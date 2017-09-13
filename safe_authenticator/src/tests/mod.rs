// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement.  This, along with the Licenses can be
// found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

mod revocation;
mod share_mdata;
mod utils;

use self::utils::{ChannelType, create_containers_req, decode_ipc_msg, err_cb, unregistered_cb};
use access_container as access_container_tools;
use app_container;
use config::{self, KEY_APPS};
use errors::{AuthError, ERR_INVALID_MSG, ERR_OPERATION_FORBIDDEN, ERR_UNKNOWN_APP};
use ffi::apps::*;
use ffi_utils::{ReprC, StringError, base64_encode, from_c_str};
use ffi_utils::test_utils::{call_1, call_vec, sender_as_user_data};
use futures::{Future, future};
use ipc::{auth_revoke_app, encode_auth_resp, encode_containers_resp, encode_unregistered_resp};
use safe_core::ipc::{self, AuthReq, BootstrapConfig, ContainersReq, IpcError, IpcMsg, IpcReq,
                     IpcResp, Permission};
use safe_core::ipc::req::ffi::AppExchangeInfo as FfiAppExchangeInfo;
use safe_core::mdata_info;
use std::collections::HashMap;
use std::ffi::CString;
use std::sync::mpsc;
use std::time::Duration;
use std_dirs::{DEFAULT_PRIVATE_DIRS, DEFAULT_PUBLIC_DIRS};
use test_utils::{access_container, compare_access_container_entries, create_account_and_login,
                 rand_app, register_app, run};
use tiny_keccak::sha3_256;

#[cfg(feature = "use-mock-routing")]
mod mock_routing {
    use super::utils::create_containers_req;
    use Authenticator;
    use access_container as access_container_tools;
    use errors::AuthError;
    use futures::Future;
    use routing::{ClientError, Request, Response, User};
    use safe_core::CoreError;
    use safe_core::MockRouting;
    use safe_core::ipc::AuthReq;
    use safe_core::nfs::NfsError;
    use safe_core::utils::generate_random_string;
    use std_dirs::{DEFAULT_PRIVATE_DIRS, DEFAULT_PUBLIC_DIRS};
    use test_utils::{access_container, create_account_and_login_with_hook, rand_app, register_app,
                     run};

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
    #[cfg(feature = "use-mock-routing")]
    #[test]
    fn std_dirs_recovery() {
        use safe_core::DIR_TAG;

        // Add a request hook to forbid root dir modification. In this case
        // account creation operation will be failed, but login still should
        // be possible afterwards.
        let locator = unwrap!(generate_random_string(10));
        let password = unwrap!(generate_random_string(10));
        let invitation = unwrap!(generate_random_string(10));

        {
            let routing_hook = move |mut routing: MockRouting| -> MockRouting {
                let mut put_mdata_counter = 0;

                routing.set_request_hook(move |req| {
                    match *req {
                        Request::PutMData { ref data, msg_id, .. } if data.tag() == DIR_TAG => {
                            put_mdata_counter += 1;

                            if put_mdata_counter > 4 {
                                Some(Response::PutMData {
                                    msg_id,
                                    res: Err(ClientError::LowBalance),
                                })
                            } else {
                                None
                            }
                        }
                        // Pass-through
                        _ => None,
                    }
                });
                routing
            };

            let authenticator = Authenticator::create_acc_with_hook(
                locator.clone(),
                password.clone(),
                invitation,
                |_| (),
                routing_hook,
            );

            // This operation should fail
            match authenticator {
                Err(AuthError::NfsError(NfsError::CoreError(CoreError::RoutingClientError(
                    ClientError::LowBalance)))) => (),
                Err(x) => panic!("Unexpected error {:?}", x),
                Ok(_) => panic!("Expected an error"),
            }
        }

        // Log in using the same credentials
        let authenticator = unwrap!(Authenticator::login(locator, password, |_| ()));

        // Make sure that all default directories have been created after log in.
        let std_dir_names: Vec<_> = DEFAULT_PRIVATE_DIRS
            .iter()
            .cloned()
            .chain(DEFAULT_PUBLIC_DIRS.iter().cloned())
            .collect();

        // Verify that the access container has been created and
        // fetch the entries of the root authenticator entry.
        let (_entry_version, entries) = run(&authenticator, |client| {
            access_container_tools::fetch_authenticator_entry(client).map_err(AuthError::from)
        });

        // Verify that all the std dirs are there.
        for name in std_dir_names {
            assert!(entries.contains_key(name));
        }
    }

    // Ensure that users can log in with low account balance.
    #[cfg(feature = "use-mock-routing")]
    #[test]
    fn login_with_low_balance() {
        // Register a hook prohibiting mutations and login
        let routing_hook = move |mut routing: MockRouting| -> MockRouting {
            routing.set_request_hook(move |req| {
                match *req {
                    Request::PutIData { msg_id, .. } => {
                        Some(Response::PutIData {
                            res: Err(ClientError::LowBalance),
                            msg_id,
                        })
                    }
                    Request::PutMData { msg_id, .. } => {
                        Some(Response::PutMData {
                            res: Err(ClientError::LowBalance),
                            msg_id,
                        })
                    }
                    Request::MutateMDataEntries { msg_id, .. } => {
                        Some(Response::MutateMDataEntries {
                            res: Err(ClientError::LowBalance),
                            msg_id,
                        })
                    }
                    Request::SetMDataUserPermissions { msg_id, .. } => {
                        Some(Response::SetMDataUserPermissions {
                            res: Err(ClientError::LowBalance),
                            msg_id,
                        })
                    }
                    Request::DelMDataUserPermissions { msg_id, .. } => {
                        Some(Response::DelMDataUserPermissions {
                            res: Err(ClientError::LowBalance),
                            msg_id,
                        })
                    }
                    Request::ChangeMDataOwner { msg_id, .. } => {
                        Some(Response::ChangeMDataOwner {
                            res: Err(ClientError::LowBalance),
                            msg_id,
                        })
                    }
                    Request::InsAuthKey { msg_id, .. } => {
                        Some(Response::InsAuthKey {
                            res: Err(ClientError::LowBalance),
                            msg_id,
                        })
                    }
                    Request::DelAuthKey { msg_id, .. } => {
                        Some(Response::DelAuthKey {
                            res: Err(ClientError::LowBalance),
                            msg_id,
                        })
                    }
                    // Pass-through
                    _ => None,
                }
            });
            routing
        };

        // Make sure we can log in
        let _authenticator = create_account_and_login_with_hook(routing_hook);
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
    #[cfg(feature = "use-mock-routing")]
    #[test]
    fn app_authentication_recovery() {
        let locator = unwrap!(generate_random_string(10));
        let password = unwrap!(generate_random_string(10));
        let invitation = unwrap!(generate_random_string(10));

        let routing_hook = move |mut routing: MockRouting| -> MockRouting {
            routing.set_request_hook(move |req| {
                match *req {
                    // Simulate a network failure after
                    // the `mutate_mdata_entries` operation (relating to
                    // the addition of the app to the user's config dir)
                    Request::InsAuthKey { msg_id, .. } => {
                        Some(Response::InsAuthKey {
                            res: Err(ClientError::LowBalance),
                            msg_id,
                        })
                    }
                    // Pass-through
                    _ => None,
                }
            });
            routing
        };
        let auth = unwrap!(Authenticator::create_acc_with_hook(
            locator.clone(),
            password.clone(),
            invitation,
            |_| (),
            routing_hook,
        ));

        // Create a test app and try to authenticate it (with `app_container` set to true).
        let auth_req = AuthReq {
            app: rand_app(),
            app_container: true,
            containers: create_containers_req(),
        };
        let app_id = auth_req.app.id.clone();

        // App authentication request should fail and leave the app in the
        // `Revoked` state (as it is listed in the config root, but not in the access
        // container)
        match register_app(&auth, &auth_req) {
            Err(AuthError::CoreError(CoreError::RoutingClientError(ClientError::LowBalance))) => (),
            x => panic!("Unexpected {:?}", x),
        }

        // Simulate a network failure for the `update_container_perms` step -
        // it should fail at the second container (`_videos`)
        let routing_hook = move |mut routing: MockRouting| -> MockRouting {
            let mut reqs_counter = 0;

            routing.set_request_hook(move |req| {
                match *req {
                    Request::SetMDataUserPermissions { msg_id, .. } => {
                        reqs_counter += 1;

                        if reqs_counter == 2 {
                            Some(Response::SetMDataUserPermissions {
                                res: Err(ClientError::LowBalance),
                                msg_id,
                            })
                        } else {
                            None
                        }
                    }
                    // Pass-through
                    _ => None,
                }
            });
            routing
        };
        let auth = unwrap!(Authenticator::login_with_hook(
            locator.clone(),
            password.clone(),
            |_| (),
            routing_hook,
        ));
        match register_app(&auth, &auth_req) {
            Err(AuthError::CoreError(CoreError::RoutingClientError(ClientError::LowBalance))) => (),
            x => panic!("Unexpected {:?}", x),
        }

        // Simulate a network failure for the `app_container` setup step -
        // it should fail at the third request for `SetMDataPermissions` (after
        // setting permissions for 2 requested containers, `_video` and `_documents`)
        let routing_hook = move |mut routing: MockRouting| -> MockRouting {
            routing.set_request_hook(move |req| {
                match *req {
                    Request::PutMData { msg_id, .. } => {
                        Some(Response::PutMData {
                            res: Err(ClientError::LowBalance),
                            msg_id,
                        })
                    }
                    // Pass-through
                    _ => None,
                }
            });
            routing
        };
        let auth = unwrap!(Authenticator::login_with_hook(
            locator.clone(),
            password.clone(),
            |_| (),
            routing_hook,
        ));
        match register_app(&auth, &auth_req) {
            Err(AuthError::NfsError(NfsError::CoreError(
                CoreError::RoutingClientError(ClientError::LowBalance)))) => (),
            x => panic!("Unexpected {:?}", x),
        }

        // Simulate a network failure for the `MutateMDataEntries` request, which
        // is supposed to setup the access container entry for the app
        let routing_hook = move |mut routing: MockRouting| -> MockRouting {
            routing.set_request_hook(move |req| {
                match *req {
                    Request::MutateMDataEntries { msg_id, .. } => {
                        // None
                        Some(Response::SetMDataUserPermissions {
                            res: Err(ClientError::LowBalance),
                            msg_id,
                        })

                    }
                    // Pass-through
                    _ => None,
                }
            });
            routing
        };
        let auth = unwrap!(Authenticator::login_with_hook(
            locator.clone(),
            password.clone(),
            |_| (),
            routing_hook,
        ));
        match register_app(&auth, &auth_req) {
            Err(AuthError::CoreError(CoreError::RoutingClientError(ClientError::LowBalance))) => (),
            x => panic!("Unexpected {:?}", x),
        }

        // Now try to authenticate the app without network failure simulation -
        // it should succeed.
        let auth = unwrap!(Authenticator::login(
            locator.clone(),
            password.clone(),
            |_| (),
        ));
        let auth_granted = match register_app(&auth, &auth_req) {
            Ok(auth_granted) => auth_granted,
            x => panic!("Unexpected {:?}", x),
        };

        // Check that the app's container has been created and that the access container
        // contains info about all of the requested containers.
        let mut ac_entries = access_container(&auth, app_id.clone(), auth_granted.clone());
        let (_videos_md, _) = unwrap!(ac_entries.remove("_videos"));
        let (_documents_md, _) = unwrap!(ac_entries.remove("_documents"));
        let (app_container_md, _) = unwrap!(ac_entries.remove(&format!("apps/{}", app_id.clone())));

        let app_pk = auth_granted.app_keys.sign_pk;

        run(&auth, move |client| {
            let c2 = client.clone();

            client
                .get_mdata_version(app_container_md.name, app_container_md.type_tag)
                .then(move |res| {
                    let version = unwrap!(res);
                    assert_eq!(version, 0);

                    // Check that the app's container has required permissions.
                    c2.list_mdata_permissions(app_container_md.name, app_container_md.type_tag)
                })
                .then(move |res| {
                    let perms = unwrap!(res);
                    assert!(perms.contains_key(&User::Key(app_pk)));
                    assert_eq!(perms.len(), 1);

                    Ok(())
                })
        });
    }
}

// Test creation and content of std dirs after account creation.
#[test]
fn test_access_container() {
    let authenticator = create_account_and_login();
    let std_dir_names: Vec<_> = DEFAULT_PRIVATE_DIRS
        .iter()
        .chain(DEFAULT_PUBLIC_DIRS.iter())
        .collect();

    // Fetch the entries of the access container.
    let entries = run(&authenticator, |client| {
        access_container_tools::fetch_authenticator_entry(client).map(|(_version, entries)| entries)
    });

    // Verify that all the std dirs are there.
    for name in &std_dir_names {
        assert!(entries.contains_key(**name));
    }

    // Fetch all the dirs under user root dir and verify they are empty.
    let dirs = run(&authenticator, move |client| {
        let fs: Vec<_> = entries
            .into_iter()
            .map(|(_, dir)| {
                let f1 = client.list_mdata_entries(dir.name, dir.type_tag);
                let f2 = client.list_mdata_permissions(dir.name, dir.type_tag);

                f1.join(f2).map_err(AuthError::from)
            })
            .collect();

        future::join_all(fs)
    });

    assert_eq!(dirs.len(), std_dir_names.len());

    for (entries, permissions) in dirs {
        assert!(entries.is_empty());
        assert!(permissions.is_empty());
    }
}

// Test creation and content of config dir after account creation.
#[test]
fn config_root_dir() {
    let authenticator = create_account_and_login();

    // Fetch the entries of the config root dir.
    let (dir, entries) = run(&authenticator, |client| {
        let dir = unwrap!(client.config_root_dir());
        client
            .list_mdata_entries(dir.name, dir.type_tag)
            .map(move |entries| (dir, entries))
            .map_err(AuthError::from)
    });

    let entries = unwrap!(mdata_info::decrypt_entries(&dir, &entries));

    // Verify it contains the required entries.
    let config = unwrap!(entries.get(KEY_APPS));
    assert!(config.content.is_empty());
}

// Test app authentication.
#[test]
fn app_authentication() {
    let authenticator = create_account_and_login();

    // Try to send IpcResp::Auth - it should fail
    let msg = IpcMsg::Revoked { app_id: "hello".to_string() };
    let encoded_msg = unwrap!(ipc::encode_msg(&msg, "safe-auth"));
    match decode_ipc_msg(&authenticator, &encoded_msg) {
        Err((ERR_INVALID_MSG, None)) => (),
        x => panic!("Unexpected {:?}", x),
    }

    // Try to send IpcReq::Auth - it should pass
    let req_id = ipc::gen_req_id();
    let app_exchange_info = rand_app();
    let app_id = app_exchange_info.id.clone();

    let auth_req = AuthReq {
        app: app_exchange_info.clone(),
        app_container: true,
        containers: create_containers_req(),
    };

    let msg = IpcMsg::Req {
        req_id: req_id,
        req: IpcReq::Auth(auth_req.clone()),
    };

    let encoded_msg = unwrap!(ipc::encode_msg(&msg, "safe-auth"));

    let (received_req_id, received_auth_req) =
        match unwrap!(decode_ipc_msg(&authenticator, &encoded_msg)) {
            (IpcMsg::Req {
                 req_id,
                 req: IpcReq::Auth(req),
             },
             _) => (req_id, req),
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

    let base64_app_id = base64_encode(app_id.as_bytes());
    assert!(encoded_auth_resp.starts_with(
        &format!("safe-{}", base64_app_id),
    ));

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

    let mut expected = create_containers_req();
    let _ = expected.insert(
        format!("apps/{}", app_id),
        btree_set![
            Permission::Read,
            Permission::Insert,
            Permission::Update,
            Permission::Delete,
            Permission::ManagePermissions,
        ],
    );

    let mut access_container =
        access_container(&authenticator, app_id.clone(), auth_granted.clone());
    assert_eq!(access_container.len(), 3);

    let app_keys = auth_granted.app_keys;
    let app_sign_pk = app_keys.sign_pk;

    compare_access_container_entries(
        &authenticator,
        app_sign_pk,
        access_container.clone(),
        expected,
    );

    let (app_dir_info, _) = unwrap!(access_container.remove(&format!("apps/{}", app_id)));

    // Check the app info is present in the config file.
    let apps = run(&authenticator, |client| {
        config::list_apps(client).map(|(_, apps)| apps)
    });

    let app_config_key = sha3_256(app_id.as_bytes());
    let app_info = unwrap!(apps.get(&app_config_key));

    assert_eq!(app_info.info, app_exchange_info);
    assert_eq!(app_info.keys, app_keys);

    // Check the app dir is present in the access container's authenticator entry.
    let received_app_dir_info = run(&authenticator, move |client| {
        app_container::fetch(client, &app_id).and_then(move |app_dir| match app_dir {
            Some(app_dir) => Ok(app_dir),
            None => panic!("App directory not present"),
        })
    });

    assert_eq!(received_app_dir_info, app_dir_info);

    // Check the app is authorised.
    let auth_keys = run(&authenticator, |client| {
        client
            .list_auth_keys_and_version()
            .map(|(keys, _)| keys)
            .map_err(AuthError::from)
    });

    assert!(auth_keys.contains(&app_sign_pk));
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
            app: rand_app(),
            app_container: true,
            containers: create_containers_req(),
        }),
    };
    let encoded_msg = unwrap!(ipc::encode_msg(&msg, "safe-auth"));

    match unregistered_decode_ipc_msg(&encoded_msg) {
        Err((ERR_OPERATION_FORBIDDEN, None)) => (),
        x => panic!("Unexpected {:?}", x),
    }

    // Try to send IpcReq::Unregistered - it should pass
    let req_id = ipc::gen_req_id();
    let msg = IpcMsg::Req {
        req_id: req_id,
        req: IpcReq::Unregistered,
    };
    let encoded_msg = unwrap!(ipc::encode_msg(&msg, "safe-auth"));

    let received_req_id = match unwrap!(unregistered_decode_ipc_msg(&encoded_msg)) {
        (IpcMsg::Req {
             req_id,
             req: IpcReq::Unregistered,
         },
         _) => req_id,
        x => panic!("Unexpected {:?}", x),
    };

    assert_eq!(received_req_id, req_id);

    let encoded_resp: String = unsafe {
        unwrap!(call_1(|ud, cb| {
            encode_unregistered_resp(req_id,
                                     true, // is_granted
                                     ud,
                                     cb)
        }))
    };
    let base64_app_id = base64_encode(b"unregistered");
    assert!(encoded_resp.starts_with(&format!("safe-{}", base64_app_id)));

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
    let authenticator = create_account_and_login();

    let received_req_id = match unwrap!(decode_ipc_msg(&authenticator, &encoded_msg)) {
        (IpcMsg::Req {
             req_id,
             req: IpcReq::Unregistered,
         },
         _) => req_id,
        x => panic!("Unexpected {:?}", x),
    };

    assert_eq!(received_req_id, req_id);
}

// Authenticate an app - it must pass.
// Authenticate the same app again - it must return the correct response
// with the same app details.
#[test]
fn authenticated_app_can_be_authenticated_again() {
    let authenticator = create_account_and_login();

    let auth_req = AuthReq {
        app: rand_app(),
        app_container: false,
        containers: Default::default(),
    };

    let req_id = ipc::gen_req_id();
    let msg = IpcMsg::Req {
        req_id: req_id,
        req: IpcReq::Auth(auth_req.clone()),
    };
    let encoded_msg = unwrap!(ipc::encode_msg(&msg, "safe-auth"));

    match unwrap!(decode_ipc_msg(&authenticator, &encoded_msg)) {
        (IpcMsg::Req { req: IpcReq::Auth(_), .. }, _) => (),
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
        req_id: req_id,
        req: IpcReq::Auth(auth_req),
    };
    let encoded_msg = unwrap!(ipc::encode_msg(&msg, "safe-auth"));

    match unwrap!(decode_ipc_msg(&authenticator, &encoded_msg)) {
        (IpcMsg::Req { req: IpcReq::Auth(_), .. }, _) => (),
        x => panic!("Unexpected {:?}", x),
    };
}

// Create and serialize a containers request for a random app, make sure we get an error.
#[test]
fn containers_unknown_app() {
    let authenticator = create_account_and_login();

    // Create IpcMsg::Req { req: IpcReq::Containers } for a random App (random id, name, vendor etc)
    let req_id = ipc::gen_req_id();
    let msg = IpcMsg::Req {
        req_id: req_id,
        req: IpcReq::Containers(ContainersReq {
            app: rand_app(),
            containers: create_containers_req(),
        }),
    };

    // Serialise the request as base64 payload in "safe-auth:payload"
    let encoded_msg = unwrap!(ipc::encode_msg(&msg, "safe-auth"));

    // Invoke Authenticator's decode_ipc_msg and expect to get Failure back via
    // callback with error code for IpcError::UnknownApp
    // Check that the returned string is "safe_<app-id-base64>:payload" where payload is
    // IpcMsg::Resp(IpcResp::Auth(Err(UnknownApp)))"
    match decode_ipc_msg(&authenticator, &encoded_msg) {
        Err((code, Some(IpcMsg::Resp { resp: IpcResp::Auth(Err(IpcError::UnknownApp)), .. })))
            if code == ERR_UNKNOWN_APP => (),
        x => panic!("Unexpected {:?}", x),
    };
}

// Test making a containers access request.
#[test]
fn containers_access_request() {
    let authenticator = create_account_and_login();

    // Create IpcMsg::AuthReq for a random App (random id, name, vendor etc), ask for app_container
    // and containers "documents with permission to insert", "videos with all the permissions
    // possible",
    let auth_req = AuthReq {
        app: rand_app(),
        app_container: true,
        containers: create_containers_req(),
    };
    let app_id = auth_req.app.id.clone();
    let base64_app_id = base64_encode(app_id.as_bytes());

    let auth_granted = unwrap!(register_app(&authenticator, &auth_req));

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

    // Check the string to contain "safe-<app-id-base64>:payload" where payload is
    // IpcMsg::Resp(IpcResp::Auth(Containers(Ok())))".
    assert!(encoded_containers_resp.starts_with(
        &format!("safe-{}", base64_app_id),
    ));

    match ipc::decode_msg(&encoded_containers_resp) {
        Ok(IpcMsg::Resp { resp: IpcResp::Containers(Ok(())), .. }) => (),
        x => panic!("Unexpected {:?}", x),
    }

    // Using the access container from AuthGranted check if "app-id", "documents", "videos",
    // "downloads" are all mentioned and using MDataInfo for each check the permissions are
    // what had been asked for.
    let mut expected = create_containers_req();
    let _ = expected.insert("_downloads".to_owned(), btree_set![Permission::Update]);

    let app_sign_pk = auth_granted.app_keys.sign_pk;
    let access_container = access_container(&authenticator, app_id, auth_granted);
    compare_access_container_entries(&authenticator, app_sign_pk, access_container, expected);
}

struct RegisteredAppId(String);
impl ReprC for RegisteredAppId {
    type C = *const RegisteredApp;
    type Error = StringError;

    unsafe fn clone_from_repr_c(ffi: *const RegisteredApp) -> Result<RegisteredAppId, StringError> {
        Ok(RegisteredAppId(from_c_str((*ffi).app_info.id)?))
    }
}

struct RevokedAppId(String);
impl ReprC for RevokedAppId {
    type C = *const FfiAppExchangeInfo;
    type Error = StringError;

    unsafe fn clone_from_repr_c(
        app_info: *const FfiAppExchangeInfo,
    ) -> Result<RevokedAppId, StringError> {
        Ok(RevokedAppId(from_c_str((*app_info).id)?))
    }
}

// Test app registration and revocation.
// 1. Initially there should be no registerd or revoked apps.
// 2. Register two apps. There should be two registered apps, but no revoked apps.
// 3. Revoke the first app. There should be one registered and one revoked app.
// 4. Re-register the first app. There should be two registered apps again.
#[test]
fn lists_of_registered_and_revoked_apps() {
    let authenticator = create_account_and_login();

    // Initially, there are no registered or revoked apps.
    let registered: Vec<RegisteredAppId> = unsafe {
        unwrap!(call_vec(
            |ud, cb| auth_registered_apps(&authenticator, ud, cb),
        ))
    };

    let revoked: Vec<RevokedAppId> =
        unsafe { unwrap!(call_vec(|ud, cb| auth_revoked_apps(&authenticator, ud, cb))) };

    assert!(registered.is_empty());
    assert!(revoked.is_empty());

    // Register two apps.
    let auth_req1 = AuthReq {
        app: rand_app(),
        app_container: false,
        containers: Default::default(),
    };

    let auth_req2 = AuthReq {
        app: rand_app(),
        app_container: false,
        containers: Default::default(),
    };

    let _ = unwrap!(register_app(&authenticator, &auth_req1));
    let _ = unwrap!(register_app(&authenticator, &auth_req2));

    // There are now two registered apps, but no revoked apps.
    let registered: Vec<RegisteredAppId> = unsafe {
        unwrap!(call_vec(
            |ud, cb| auth_registered_apps(&authenticator, ud, cb),
        ))
    };

    let revoked: Vec<RevokedAppId> =
        unsafe { unwrap!(call_vec(|ud, cb| auth_revoked_apps(&authenticator, ud, cb))) };

    assert_eq!(registered.len(), 2);
    assert!(revoked.is_empty());

    // Revoke the first app.
    let id_str = unwrap!(CString::new(auth_req1.app.id.clone()));
    let _: String = unsafe {
        unwrap!(call_1(|ud, cb| {
            auth_revoke_app(&authenticator, id_str.as_ptr(), ud, cb)
        }))
    };

    // There is now one registered and one revoked app.
    let registered: Vec<RegisteredAppId> = unsafe {
        unwrap!(call_vec(
            |ud, cb| auth_registered_apps(&authenticator, ud, cb),
        ))
    };

    let revoked: Vec<RevokedAppId> =
        unsafe { unwrap!(call_vec(|ud, cb| auth_revoked_apps(&authenticator, ud, cb))) };

    assert_eq!(registered.len(), 1);
    assert_eq!(revoked.len(), 1);

    // Re-register the first app - now there must be 2 registered apps again
    let _ = unwrap!(register_app(&authenticator, &auth_req1));

    let registered: Vec<RegisteredAppId> = unsafe {
        unwrap!(call_vec(
            |ud, cb| auth_registered_apps(&authenticator, ud, cb),
        ))
    };
    let revoked: Vec<RevokedAppId> =
        unsafe { unwrap!(call_vec(|ud, cb| auth_revoked_apps(&authenticator, ud, cb))) };

    assert_eq!(registered.len(), 2);
    assert_eq!(revoked.len(), 0);
}

fn unregistered_decode_ipc_msg(msg: &str) -> ChannelType {
    let (tx, rx) = mpsc::channel::<ChannelType>();

    let ffi_msg = unwrap!(CString::new(msg));

    unsafe {
        use ipc::auth_unregistered_decode_ipc_msg;
        auth_unregistered_decode_ipc_msg(
            ffi_msg.as_ptr(),
            sender_as_user_data(&tx),
            unregistered_cb,
            err_cb,
        );
    };

    match rx.recv_timeout(Duration::from_secs(15)) {
        Ok(r) => r,
        Err(_) => Err((-1, None)),
    }
}
