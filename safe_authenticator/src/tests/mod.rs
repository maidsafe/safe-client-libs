// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod revocation;
mod serialisation;
mod share_mdata;
mod utils;

use crate::access_container as access_container_tools;
use crate::config::{self, KEY_APPS};
use crate::errors::{AuthError, ERR_INVALID_MSG, ERR_OPERATION_FORBIDDEN, ERR_UNKNOWN_APP};
use crate::ffi::apps::*;
use crate::ffi::ipc::{
    auth_revoke_app, encode_auth_resp, encode_containers_resp, encode_unregistered_resp,
};
use crate::safe_core::ffi::ipc::req::AppExchangeInfo as FfiAppExchangeInfo;
use crate::safe_core::ipc::{
    self, AuthReq, BootstrapConfig, ContainersReq, IpcError, IpcMsg, IpcReq, IpcResp, Permission,
};
use crate::std_dirs::{DEFAULT_PRIVATE_DIRS, DEFAULT_PUBLIC_DIRS};
use crate::test_utils::{self, ChannelType};
use crate::{app_container, run};
use ffi_utils::test_utils::{call_1, call_vec, sender_as_user_data};
use ffi_utils::{from_c_str, ErrorCode, ReprC, StringError};
use futures::{future, Future};
use safe_core::{app_container_name, mdata_info, AuthActions, Client};
use safe_nd::PublicKey;
use std::collections::HashMap;
use std::ffi::CString;
use std::sync::mpsc;
use std::time::Duration;
use tiny_keccak::sha3_256;

#[cfg(feature = "mock-network")]
mod mock_routing {
    use super::utils;
    use crate::access_container as access_container_tools;
    use crate::errors::AuthError;
    use crate::run;
    use crate::std_dirs::{DEFAULT_PRIVATE_DIRS, DEFAULT_PUBLIC_DIRS};
    use crate::{test_utils, Authenticator};
    use futures::Future;
    use safe_core::ipc::AuthReq;
    use safe_core::nfs::NfsError;
    use safe_core::utils::generate_random_string;
    use safe_core::{
        app_container_name, test_create_balance, Client, ConnectionManager, CoreError,
    };
    use safe_nd::{Coins, Error as SndError, PublicKey};
    use std::str::FromStr;

    // Test operation recovery for std dirs creation.
    // 1. Try to create a new user's account using `safe_authenticator::Authenticator::create_acc`
    // 2. Simulate a network disconnection [1] for a randomly selected `PutMData` operation
    //    with a type_tag == `safe_core::DIR_TAG` (in the range from 3rd request to
    //    `safe_core::nfs::DEFAULT_PRIVATE_DIRS.len()`). This will meddle with creation of
    //    default directories.
    // 3. Try to log in using the same credentials that have been provided for `create_acc`.
    //    The log in operation should be successful.
    // 4. Check that after logging in the remaining default directories have been created
    //    (= operation recovery worked after log in)
    // 5. Check the access container entry in the user's config root - it must be accessible
    #[test]
    #[ignore]
    fn std_dirs_recovery() {
        // use safe_core::DIR_TAG;

        // Add a request hook to forbid root dir modification. In this case
        // account creation operation will be failed, but login still should
        // be possible afterwards.
        let locator = unwrap!(generate_random_string(10));
        let password = unwrap!(generate_random_string(10));
        let balance_sk = threshold_crypto::SecretKey::random();
        unwrap!(test_create_balance(
            &balance_sk,
            unwrap!(Coins::from_str("10"))
        ));

        {
            let cm_hook = move |mut cm: ConnectionManager| -> ConnectionManager {
                let mut _put_mdata_counter = 0;

                cm.set_request_hook(move |_req| {
                    // FIXME
                    // match *req {
                    //     Request::PutMData {
                    //         ref data, msg_id, ..
                    //     } if data.tag() == DIR_TAG => {
                    //         put_mdata_counter += 1;

                    //         if put_mdata_counter > 4 {
                    //             Some(Response::PutMData {
                    //                 msg_id,
                    //                 res: Err(SndError::InsufficientBalance),
                    //             })
                    //         } else {
                    //             None
                    //         }
                    //     }
                    //     // Pass-through
                    //     _ => None,
                    // }
                    None
                });
                cm
            };

            let authenticator = Authenticator::create_acc_with_hook(
                locator.clone(),
                password.clone(),
                balance_sk,
                || (),
                cm_hook,
            );

            // This operation should fail
            match authenticator {
                Err(AuthError::AccountContainersCreation(_)) => (),
                Err(x) => panic!("Unexpected error {:?}", x),
                Ok(_) => panic!("Unexpected success"),
            }
        }

        // Log in using the same credentials
        let authenticator = unwrap!(Authenticator::login(locator, password, || ()));

        // Make sure that all default directories have been created after log in.
        let std_dir_names: Vec<_> = DEFAULT_PRIVATE_DIRS
            .iter()
            .cloned()
            .chain(DEFAULT_PUBLIC_DIRS.iter().cloned())
            .collect();

        // Verify that the access container has been created and
        // fetch the entries of the root authenticator entry.
        let (_entry_version, entries) = unwrap!(run(&authenticator, |client| {
            access_container_tools::fetch_authenticator_entry(client).map_err(AuthError::from)
        }));

        // Verify that all the std dirs are there.
        for name in std_dir_names {
            assert!(entries.contains_key(name));
        }
    }

    // Ensure that users can log in with low account balance.
    #[test]
    fn login_with_low_balance() {
        // Register a hook prohibiting mutations and login
        let cm_hook = move |mut cm: ConnectionManager| -> ConnectionManager {
            cm.set_request_hook(move |_req| {
                None
                // FIXME
                // match *req {
                //     Request::PutIData { msg_id, .. } => Some(Response::PutIData {
                //         res: Err(SndError::InsufficientBalance),
                //         msg_id,
                //     }),
                //     Request::PutMData { msg_id, .. } => Some(Response::PutMData {
                //         res: Err(SndError::InsufficientBalance),
                //         msg_id,
                //     }),
                //     Request::MutateMDataEntries { msg_id, .. } => {
                //         Some(Response::MutateMDataEntries {
                //             res: Err(SndError::InsufficientBalance),
                //             msg_id,
                //         })
                //     }
                //     Request::SetMDataUserPermissions { msg_id, .. } => {
                //         Some(Response::SetMDataUserPermissions {
                //             res: Err(SndError::InsufficientBalance),
                //             msg_id,
                //         })
                //     }
                //     Request::DelMDataUserPermissions { msg_id, .. } => {
                //         Some(Response::DelMDataUserPermissions {
                //             res: Err(SndError::InsufficientBalance),
                //             msg_id,
                //         })
                //     }
                //     Request::ChangeMDataOwner { msg_id, .. } => Some(Response::ChangeMDataOwner {
                //         res: Err(SndError::InsufficientBalance),
                //         msg_id,
                //     }),
                //     // Pass-through
                //     _ => None,
                // }
            });
            cm
        };

        // Make sure we can log in
        let _authenticator = test_utils::create_account_and_login_with_hook(cm_hook);
    }

    // Test operation recovery for app authentication.
    //
    // 1. Create a test app and try to authenticate it (with `app_container` set to true).
    //
    // 2. Simulate a network failure after the `mutate_mdata_entries` operation (relating to the
    //    addition of the app to the user's config dir) - it should leave the app in the
    //    `Revoked` state (as it is listen in the config root, but not in the access
    //    container)
    // 3. Try to authenticate the app again, it should continue without errors
    //
    // 4. Simulate a network failure after the `ins_auth_key` operation.
    //    The authentication op should fail.
    // 5. Try to authenticate the app again, it should continue without errors
    //
    // 6. Simulate a network failure for the `set_mdata_user_permissions` operation
    //    (relating to the app's container - so that it will be created successfuly, but fail
    //    at the permissions set stage).
    // 7. Try to authenticate the app again, it should continue without errors.
    //
    // 8. Simulate a network failure for the `mutate_mdata_entries` operation
    //    (relating to update of the access container).
    // 9. Try to authenticate the app again, it should succeed now.
    //
    // 10. Check that the app's container has been created.
    // 11. Check that the app's container has required permissions.
    // 12. Check that the app's container is listed in the access container entry for
    //     the app.
    #[ignore]
    #[test]
    fn app_authentication_recovery() {
        let locator = unwrap!(generate_random_string(10));
        let password = unwrap!(generate_random_string(10));
        let balance_sk = threshold_crypto::SecretKey::random();
        unwrap!(test_create_balance(
            &balance_sk,
            unwrap!(Coins::from_str("10"))
        ));

        let cm_hook = move |mut cm: ConnectionManager| -> ConnectionManager {
            cm.set_request_hook(move |req| {
                match *req {
                    // Simulate a network failure after
                    // the `mutate_mdata_entries` operation (relating to
                    // the addition of the app to the user's config dir)

                    // TODO: fix this test
                    // Request::InsAuthKey { msg_id, .. } => Some(Response::InsAuthKey {
                    //     res: Err(SndError::InsufficientBalance),
                    //     msg_id,
                    // }),

                    // Pass-through
                    _ => None,
                }
            });
            cm
        };
        let auth = unwrap!(Authenticator::create_acc_with_hook(
            locator.clone(),
            password.clone(),
            balance_sk,
            || (),
            cm_hook,
        ));

        // Create a test app and try to authenticate it (with `app_container` set to true).
        let auth_req = AuthReq {
            app: test_utils::rand_app(),
            app_container: true,
            app_permissions: Default::default(),
            containers: utils::create_containers_req(),
        };
        let app_id = auth_req.app.id.clone();

        // App authentication request should fail and leave the app in the
        // `Revoked` state (as it is listed in the config root, but not in the access
        // container)
        match test_utils::register_app(&auth, &auth_req) {
            Err(AuthError::CoreError(CoreError::DataError(SndError::InsufficientBalance))) => (),
            x => panic!("Unexpected {:?}", x),
        }

        // Simulate a network failure for the `update_container_perms` step -
        // it should fail at the second container (`_videos`)
        let cm_hook = move |mut cm: ConnectionManager| -> ConnectionManager {
            let mut _reqs_counter = 0;

            cm.set_request_hook(move |req| {
                // FIXME

                match *req {
                    // Request::SetMDataUserPermissions { msg_id, .. } => {
                    //     reqs_counter += 1;

                    //     if reqs_counter == 2 {
                    //         Some(Response::SetMDataUserPermissions {
                    //             res: Err(SndError::InsufficientBalance),
                    //             msg_id,
                    //         })
                    //     } else {
                    //         None
                    //     }
                    // }
                    // Pass-through
                    _ => None,
                }
            });
            cm
        };
        let auth = unwrap!(Authenticator::login_with_hook(
            locator.clone(),
            password.clone(),
            || (),
            cm_hook,
        ));
        match test_utils::register_app(&auth, &auth_req) {
            Err(AuthError::CoreError(CoreError::DataError(SndError::InsufficientBalance))) => (),
            x => panic!("Unexpected {:?}", x),
        }

        // Simulate a network failure for the `app_container` setup step -
        // it should fail at the third request for `SetMDataPermissions` (after
        // setting permissions for 2 requested containers, `_video` and `_documents`)
        let cm_hook = move |mut cm: ConnectionManager| -> ConnectionManager {
            cm.set_request_hook(move |req| {
                // FIXME
                match *req {
                    // Request::PutMData { msg_id, .. } => Some(Response::PutMData {
                    //     res: Err(SndError::InsufficientBalance),
                    //     msg_id,
                    // }),

                    // Pass-through
                    _ => None,
                }
            });
            cm
        };
        let auth = unwrap!(Authenticator::login_with_hook(
            locator.clone(),
            password.clone(),
            || (),
            cm_hook,
        ));
        match test_utils::register_app(&auth, &auth_req) {
            Err(AuthError::NfsError(NfsError::CoreError(CoreError::DataError(
                SndError::InsufficientBalance,
            )))) => (),
            x => panic!("Unexpected {:?}", x),
        }

        // Simulate a network failure for the `MutateMDataEntries` request, which
        // is supposed to setup the access container entry for the app
        let cm_hook = move |mut cm: ConnectionManager| -> ConnectionManager {
            cm.set_request_hook(move |req| {
                // FIXME
                match *req {
                    // Request::MutateMDataEntries { msg_id, .. } => {
                    //     // None
                    //     Some(Response::SetMDataUserPermissions {
                    //         res: Err(SndError::InsufficientBalance),
                    //         msg_id,
                    //     })
                    // }

                    // Pass-through
                    _ => None,
                }
            });
            cm
        };
        let auth = unwrap!(Authenticator::login_with_hook(
            locator.clone(),
            password.clone(),
            || (),
            cm_hook,
        ));
        match test_utils::register_app(&auth, &auth_req) {
            Err(AuthError::CoreError(CoreError::DataError(SndError::InsufficientBalance))) => (),
            x => panic!("Unexpected {:?}", x),
        }

        // Now try to authenticate the app without network failure simulation -
        // it should succeed.
        let auth = unwrap!(Authenticator::login(
            locator.clone(),
            password.clone(),
            || (),
        ));
        let auth_granted = match test_utils::register_app(&auth, &auth_req) {
            Ok(auth_granted) => auth_granted,
            x => panic!("Unexpected {:?}", x),
        };

        // Check that the app's container has been created and that the access container
        // contains info about all of the requested containers.
        let mut ac_entries =
            test_utils::access_container(&auth, app_id.clone(), auth_granted.clone());
        let (_videos_md, _) = unwrap!(ac_entries.remove("_videos"));
        let (_documents_md, _) = unwrap!(ac_entries.remove("_documents"));
        let (app_container, _) = unwrap!(ac_entries.remove(&app_container_name(&app_id)));

        let app_pk = PublicKey::from(auth_granted.app_keys.bls_pk);

        unwrap!(run(&auth, move |client| {
            let c2 = client.clone();

            client
                .get_mdata_version(*app_container.address())
                .then(move |res| {
                    let version = unwrap!(res);
                    assert_eq!(version, 0);

                    // Check that the app's container has required permissions.
                    c2.list_mdata_permissions(*app_container.address())
                })
                .then(move |res| {
                    let perms = unwrap!(res);
                    assert!(perms.contains_key(&app_pk));
                    assert_eq!(perms.len(), 1);

                    Ok(())
                })
        }));
    }
}

// Test creation and content of std dirs after account creation.
#[test]
fn test_access_container() {
    let authenticator = test_utils::create_account_and_login();
    let std_dir_names: Vec<_> = DEFAULT_PRIVATE_DIRS
        .iter()
        .chain(DEFAULT_PUBLIC_DIRS.iter())
        .collect();

    // Fetch the entries of the access container.
    let entries = unwrap!(run(&authenticator, |client| {
        access_container_tools::fetch_authenticator_entry(client).map(|(_version, entries)| entries)
    }));

    // Verify that all the std dirs are there.
    for name in &std_dir_names {
        assert!(entries.contains_key(**name));
    }

    // Fetch all the dirs under user root dir and verify they are empty.
    let dirs = unwrap!(run(&authenticator, move |client| {
        let fs: Vec<_> = entries
            .into_iter()
            .map(|(_, dir)| {
                let f1 = client.list_seq_mdata_entries(dir.name(), dir.type_tag());
                let f2 = client.list_mdata_permissions(*dir.address());

                f1.join(f2).map_err(AuthError::from)
            })
            .collect();

        future::join_all(fs)
    }));

    assert_eq!(dirs.len(), std_dir_names.len());

    for (entries, permissions) in dirs {
        assert!(entries.is_empty());
        assert!(permissions.is_empty());
    }
}

// Test creation and content of config dir after account creation.
#[test]
fn config_root_dir() {
    let authenticator = test_utils::create_account_and_login();

    // Fetch the entries of the config root dir.
    let (dir, entries) = unwrap!(run(&authenticator, |client| {
        let dir = client.config_root_dir();
        client
            .list_seq_mdata_entries(dir.name(), dir.type_tag())
            .map(move |entries| (dir, entries))
            .map_err(AuthError::from)
    }));

    let entries = unwrap!(mdata_info::decrypt_entries(&dir, &entries));

    // Verify it contains the required entries.
    let config = unwrap!(entries.get(KEY_APPS));
    assert!(config.data.is_empty());
}

// Test app authentication.
#[test]
fn app_authentication() {
    let authenticator = test_utils::create_account_and_login();

    // Try to send IpcResp::Auth - it should fail
    let msg = IpcMsg::Revoked {
        app_id: "hello".to_string(),
    };
    let encoded_msg = unwrap!(ipc::encode_msg(&msg));
    match test_utils::auth_decode_ipc_msg_helper(&authenticator, &encoded_msg) {
        Err((ERR_INVALID_MSG, None)) => (),
        x => panic!("Unexpected {:?}", x),
    }

    // Try to send IpcReq::Auth - it should pass
    let req_id = ipc::gen_req_id();
    let app_exchange_info = test_utils::rand_app();
    let app_id = app_exchange_info.id.clone();

    let containers = utils::create_containers_req();
    let auth_req = AuthReq {
        app: app_exchange_info.clone(),
        app_container: true,
        app_permissions: Default::default(),
        containers,
    };

    let msg = IpcMsg::Req {
        req_id,
        req: IpcReq::Auth(auth_req.clone()),
    };

    let encoded_msg = unwrap!(ipc::encode_msg(&msg));

    let (received_req_id, received_auth_req) = match unwrap!(
        test_utils::auth_decode_ipc_msg_helper(&authenticator, &encoded_msg)
    ) {
        (
            IpcMsg::Req {
                req_id,
                req: IpcReq::Auth(req),
            },
            _,
        ) => (req_id, req),
        x => panic!("Unexpected {:?}", x),
    };

    assert_eq!(received_req_id, req_id);
    assert_eq!(received_auth_req, auth_req);

    let encoded_auth_resp: String = unsafe {
        unwrap!(call_1(|ud, cb| {
            let auth_req = unwrap!(auth_req.into_repr_c());
            encode_auth_resp(
                &authenticator,
                &auth_req,
                req_id,
                true, // is_granted
                ud,
                cb,
            )
        }))
    };

    let auth_granted = match unwrap!(ipc::decode_msg(&encoded_auth_resp)) {
        IpcMsg::Resp {
            req_id: received_req_id,
            resp: IpcResp::Auth(Ok(auth_granted)),
        } => {
            assert_eq!(received_req_id, req_id);
            auth_granted
        }
        x => panic!("Unexpected {:?}", x),
    };

    let mut expected = utils::create_containers_req();
    let _ = expected.insert(
        app_container_name(&app_id),
        btree_set![
            Permission::Read,
            Permission::Insert,
            Permission::Update,
            Permission::Delete,
            Permission::ManagePermissions,
        ],
    );
    for (container, permissions) in expected.clone() {
        let perms = unwrap!(auth_granted.access_container_entry.get(&container));
        assert_eq!((*perms).1, permissions);
    }

    let mut access_container =
        test_utils::access_container(&authenticator, app_id.clone(), auth_granted.clone());
    assert_eq!(access_container.len(), 3);

    let app_keys = auth_granted.app_keys;
    let app_sign_pk = PublicKey::from(app_keys.bls_pk);

    test_utils::compare_access_container_entries(
        &authenticator,
        app_sign_pk,
        access_container.clone(),
        expected,
    );

    let (app_dir_info, _) = unwrap!(access_container.remove(&app_container_name(&app_id)));

    // Check the app info is present in the config file.
    let apps = unwrap!(run(&authenticator, |client| {
        config::list_apps(client).map(|(_, apps)| apps)
    }));

    let app_config_key = sha3_256(app_id.as_bytes());
    let app_info = unwrap!(apps.get(&app_config_key));

    assert_eq!(app_info.info, app_exchange_info);
    assert_eq!(app_info.keys, app_keys);

    // Check the app dir is present in the access container's authenticator entry.
    let received_app_dir_info = unwrap!(run(&authenticator, move |client| {
        app_container::fetch(client, &app_id).and_then(move |app_dir| match app_dir {
            Some(app_dir) => Ok(app_dir),
            None => panic!("App directory not present"),
        })
    }));

    assert_eq!(received_app_dir_info, app_dir_info);

    // Check the app is authorised.
    let auth_keys = unwrap!(run(&authenticator, |client| {
        client
            .list_auth_keys_and_version()
            .map(|(keys, _)| keys)
            .map_err(AuthError::from)
    }));

    assert!(auth_keys.contains_key(&app_sign_pk));
}

// Try to authenticate with invalid container names.
#[test]
fn invalid_container_authentication() {
    let authenticator = test_utils::create_account_and_login();
    let req_id = ipc::gen_req_id();
    let app_exchange_info = test_utils::rand_app();

    // Permissions for invalid container name
    let mut containers = HashMap::new();
    let _ = containers.insert(
        "_app".to_owned(),
        btree_set![
            Permission::Read,
            Permission::Insert,
            Permission::Update,
            Permission::Delete,
            Permission::ManagePermissions,
        ],
    );

    let auth_req = AuthReq {
        app: app_exchange_info.clone(),
        app_container: true,
        app_permissions: Default::default(),
        containers,
    };

    // Try to send IpcReq::Auth - it should fail
    let result: Result<String, i32> = unsafe {
        call_1(|ud, cb| {
            let auth_req = unwrap!(auth_req.into_repr_c());
            encode_auth_resp(
                &authenticator,
                &auth_req,
                req_id,
                true, // is_granted
                ud,
                cb,
            )
        })
    };
    match result {
        Err(error) if error == AuthError::NoSuchContainer("_app".into()).error_code() => (),
        x => panic!("Unexpected {:?}", x),
    };
}

// Test unregistered client authentication.
// First, try to send a full auth request - it must fail with "Forbidden".
// Then try to send a request for IpcReq::Unregistered, which must pass.
// Next we invoke encode_unregistered_resp and it must return the network
// configuration.
// Try the same thing again when logged in - it must pass.
#[test]
fn unregistered_authentication() {
    // Try to send IpcReq::Auth - it should fail
    let msg = IpcMsg::Req {
        req_id: ipc::gen_req_id(),
        req: IpcReq::Auth(AuthReq {
            app: test_utils::rand_app(),
            app_container: true,
            app_permissions: Default::default(),
            containers: utils::create_containers_req(),
        }),
    };
    let encoded_msg = unwrap!(ipc::encode_msg(&msg));

    match unregistered_decode_ipc_msg(&encoded_msg) {
        Err((ERR_OPERATION_FORBIDDEN, None)) => (),
        x => panic!("Unexpected {:?}", x),
    }

    // Try to send IpcReq::Unregistered - it should pass
    let test_data = vec![0u8; 10];
    let req_id = ipc::gen_req_id();
    let msg = IpcMsg::Req {
        req_id,
        req: IpcReq::Unregistered(test_data.clone()),
    };
    let encoded_msg = unwrap!(ipc::encode_msg(&msg));

    let (received_req_id, received_data) = match unwrap!(unregistered_decode_ipc_msg(&encoded_msg))
    {
        (
            IpcMsg::Req {
                req_id,
                req: IpcReq::Unregistered(extra_data),
            },
            _,
        ) => (req_id, extra_data),
        x => panic!("Unexpected {:?}", x),
    };

    assert_eq!(received_req_id, req_id);
    assert_eq!(received_data, test_data);

    let encoded_resp: String = unsafe {
        unwrap!(call_1(|ud, cb| {
            encode_unregistered_resp(
                req_id, true, // is_granted
                ud, cb,
            )
        }))
    };

    let bootstrap_cfg = match unwrap!(ipc::decode_msg(&encoded_resp)) {
        IpcMsg::Resp {
            req_id: received_req_id,
            resp: IpcResp::Unregistered(Ok(bootstrap_cfg)),
        } => {
            assert_eq!(received_req_id, req_id);
            bootstrap_cfg
        }
        x => panic!("Unexpected {:?}", x),
    };

    assert_eq!(bootstrap_cfg, BootstrapConfig::default());

    // Try to send IpcReq::Unregistered to logged in authenticator
    let authenticator = test_utils::create_account_and_login();

    let (received_req_id, received_data) = match unwrap!(test_utils::auth_decode_ipc_msg_helper(
        &authenticator,
        &encoded_msg
    )) {
        (
            IpcMsg::Req {
                req_id,
                req: IpcReq::Unregistered(extra_data),
            },
            _,
        ) => (req_id, extra_data),
        x => panic!("Unexpected {:?}", x),
    };

    assert_eq!(received_req_id, req_id);
    assert_eq!(received_data, test_data);
}

// Authenticate an app - it must pass.
// Authenticate the same app again - it must return the correct response
// with the same app details.
#[test]
fn authenticated_app_can_be_authenticated_again() {
    let authenticator = test_utils::create_account_and_login();

    let auth_req = AuthReq {
        app: test_utils::rand_app(),
        app_container: false,
        app_permissions: Default::default(),
        containers: Default::default(),
    };

    let req_id = ipc::gen_req_id();
    let msg = IpcMsg::Req {
        req_id,
        req: IpcReq::Auth(auth_req.clone()),
    };
    let encoded_msg = unwrap!(ipc::encode_msg(&msg));

    match unwrap!(test_utils::auth_decode_ipc_msg_helper(
        &authenticator,
        &encoded_msg
    )) {
        (
            IpcMsg::Req {
                req: IpcReq::Auth(_),
                ..
            },
            _,
        ) => (),
        x => panic!("Unexpected {:?}", x),
    };

    let _resp: String = unsafe {
        unwrap!(call_1(|ud, cb| {
            let auth_req = unwrap!(auth_req.clone().into_repr_c());
            encode_auth_resp(
                &authenticator,
                &auth_req,
                req_id,
                true, // is_granted
                ud,
                cb,
            )
        }))
    };

    // Second authentication should also return the correct result.
    let req_id = ipc::gen_req_id();
    let msg = IpcMsg::Req {
        req_id,
        req: IpcReq::Auth(auth_req),
    };
    let encoded_msg = unwrap!(ipc::encode_msg(&msg));

    match unwrap!(test_utils::auth_decode_ipc_msg_helper(
        &authenticator,
        &encoded_msg
    )) {
        (
            IpcMsg::Req {
                req: IpcReq::Auth(_),
                ..
            },
            _,
        ) => (),
        x => panic!("Unexpected {:?}", x),
    };
}

// Create and serialize a containers request for a random app, make sure we get an error.
#[test]
fn containers_unknown_app() {
    let authenticator = test_utils::create_account_and_login();

    // Create IpcMsg::Req { req: IpcReq::Containers } for a random App (random id, name, vendor etc)
    let req_id = ipc::gen_req_id();
    let msg = IpcMsg::Req {
        req_id,
        req: IpcReq::Containers(ContainersReq {
            app: test_utils::rand_app(),
            containers: utils::create_containers_req(),
        }),
    };

    // Serialise the request as base64 payload in "safe-auth:payload"
    let encoded_msg = unwrap!(ipc::encode_msg(&msg));

    // Invoke Authenticator's decode_ipc_msg and expect to get Failure back via
    // callback with error code for IpcError::UnknownApp
    // Check that the returned string is "safe_<app-id-base64>:payload" where payload is
    // IpcMsg::Resp(IpcResp::Auth(Err(UnknownApp)))"
    match test_utils::auth_decode_ipc_msg_helper(&authenticator, &encoded_msg) {
        Err((
            code,
            Some(IpcMsg::Resp {
                resp: IpcResp::Auth(Err(IpcError::UnknownApp)),
                ..
            }),
        )) if code == ERR_UNKNOWN_APP => (),
        x => panic!("Unexpected {:?}", x),
    };
}

// Test making a containers access request.
#[test]
fn containers_access_request() {
    let authenticator = test_utils::create_account_and_login();

    // Create IpcMsg::AuthReq for a random App (random id, name, vendor etc), ask for app_container
    // and containers "documents with permission to insert", "videos with all the permissions
    // possible",
    let auth_req = AuthReq {
        app: test_utils::rand_app(),
        app_container: true,
        app_permissions: Default::default(),
        containers: utils::create_containers_req(),
    };
    let app_id = auth_req.app.id.clone();

    let auth_granted = unwrap!(test_utils::register_app(&authenticator, &auth_req));

    // Give one Containers request to authenticator for the same app asking for "downloads with
    // permission to update only"
    let req_id = ipc::gen_req_id();
    let cont_req = ContainersReq {
        app: auth_req.app.clone(),
        containers: {
            let mut containers = HashMap::new();
            let _ = containers.insert("_downloads".to_string(), btree_set![Permission::Update]);
            containers
        },
    };

    // The callback should be invoked
    let encoded_containers_resp: String = unsafe {
        // Call `encode_auth_resp` with is_granted = true
        unwrap!(call_1(|ud, cb| {
            let cont_req = unwrap!(cont_req.into_repr_c());
            encode_containers_resp(
                &authenticator,
                &cont_req,
                req_id,
                true, // is_granted
                ud,
                cb,
            )
        }))
    };

    match ipc::decode_msg(&encoded_containers_resp) {
        Ok(IpcMsg::Resp {
            resp: IpcResp::Containers(Ok(())),
            ..
        }) => (),
        x => panic!("Unexpected {:?}", x),
    }

    // Using the access container from AuthGranted check if "app-id", "documents", "videos",
    // "downloads" are all mentioned and using MDataInfo for each check the permissions are
    // what had been asked for.
    let mut expected = utils::create_containers_req();
    let _ = expected.insert("_downloads".to_owned(), btree_set![Permission::Update]);

    let app_sign_pk = PublicKey::from(auth_granted.app_keys.bls_pk);
    let access_container = test_utils::access_container(&authenticator, app_id, auth_granted);
    test_utils::compare_access_container_entries(
        &authenticator,
        app_sign_pk,
        access_container,
        expected,
    );
}

struct RegisteredAppId(String);
impl ReprC for RegisteredAppId {
    type C = *const RegisteredApp;
    type Error = StringError;

    unsafe fn clone_from_repr_c(repr_c: Self::C) -> Result<Self, Self::Error> {
        Ok(RegisteredAppId(from_c_str((*repr_c).app_info.id)?))
    }
}

struct RevokedAppId(String);
impl ReprC for RevokedAppId {
    type C = *const FfiAppExchangeInfo;
    type Error = StringError;

    unsafe fn clone_from_repr_c(repr_c: Self::C) -> Result<Self, Self::Error> {
        Ok(RevokedAppId(from_c_str((*repr_c).id)?))
    }
}

// Test app registration and revocation.
// 1. Initially there should be no registerd or revoked apps.
// 2. Register two apps. There should be two registered apps, but no revoked apps.
// 3. Revoke the first app. There should be one registered and one revoked app.
// 4. Re-register the first app. There should be two registered apps again.
#[test]
fn lists_of_registered_and_revoked_apps() {
    let authenticator = test_utils::create_account_and_login();

    // Initially, there are no registered or revoked apps.
    let registered: Vec<RegisteredAppId> = unsafe {
        unwrap!(call_vec(|ud, cb| auth_registered_apps(
            &authenticator,
            ud,
            cb
        ),))
    };

    let revoked: Vec<RevokedAppId> =
        unsafe { unwrap!(call_vec(|ud, cb| auth_revoked_apps(&authenticator, ud, cb))) };

    assert!(registered.is_empty());
    assert!(revoked.is_empty());

    // Register two apps.
    let auth_req1 = AuthReq {
        app: test_utils::rand_app(),
        app_container: false,
        app_permissions: Default::default(),
        containers: Default::default(),
    };

    let auth_req2 = AuthReq {
        app: test_utils::rand_app(),
        app_container: false,
        app_permissions: Default::default(),
        containers: Default::default(),
    };

    let _ = unwrap!(test_utils::register_app(&authenticator, &auth_req1));
    let _ = unwrap!(test_utils::register_app(&authenticator, &auth_req2));

    // There are now two registered apps, but no revoked apps.
    let registered: Vec<RegisteredAppId> = unsafe {
        unwrap!(call_vec(|ud, cb| auth_registered_apps(
            &authenticator,
            ud,
            cb
        ),))
    };

    let revoked: Vec<RevokedAppId> =
        unsafe { unwrap!(call_vec(|ud, cb| auth_revoked_apps(&authenticator, ud, cb))) };

    assert_eq!(registered.len(), 2);
    assert!(revoked.is_empty());

    // Revoke the first app.
    let id_str = unwrap!(CString::new(auth_req1.app.id.clone()));
    let _: String = unsafe {
        unwrap!(call_1(|ud, cb| auth_revoke_app(
            &authenticator,
            id_str.as_ptr(),
            ud,
            cb
        )))
    };

    // There is now one registered and one revoked app.
    let registered: Vec<RegisteredAppId> = unsafe {
        unwrap!(call_vec(|ud, cb| auth_registered_apps(
            &authenticator,
            ud,
            cb
        ),))
    };

    let revoked: Vec<RevokedAppId> =
        unsafe { unwrap!(call_vec(|ud, cb| auth_revoked_apps(&authenticator, ud, cb))) };

    assert_eq!(registered.len(), 1);
    assert_eq!(revoked.len(), 1);

    // Re-register the first app - now there must be 2 registered apps again
    let _ = unwrap!(test_utils::register_app(&authenticator, &auth_req1));

    let registered: Vec<RegisteredAppId> = unsafe {
        unwrap!(call_vec(|ud, cb| auth_registered_apps(
            &authenticator,
            ud,
            cb
        ),))
    };
    let revoked: Vec<RevokedAppId> =
        unsafe { unwrap!(call_vec(|ud, cb| auth_revoked_apps(&authenticator, ud, cb))) };

    assert_eq!(registered.len(), 2);
    assert_eq!(revoked.len(), 0);
}

fn unregistered_decode_ipc_msg(msg: &str) -> ChannelType {
    let (tx, rx) = mpsc::channel::<ChannelType>();

    let ffi_msg = unwrap!(CString::new(msg));
    let mut ud = Default::default();

    unsafe {
        use crate::ffi::ipc::auth_unregistered_decode_ipc_msg;
        auth_unregistered_decode_ipc_msg(
            ffi_msg.as_ptr(),
            sender_as_user_data(&tx, &mut ud),
            test_utils::unregistered_cb,
            test_utils::err_cb,
        );
    };

    match rx.recv_timeout(Duration::from_secs(15)) {
        Ok(r) => r,
        Err(_) => Err((-1, None)),
    }
}
