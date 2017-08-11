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

use Authenticator;
use access_container as access_container_tools;
use app_auth::{self, AppState};
use config::{self, KEY_ACCESS_CONTAINER, KEY_APPS};
use errors::{AuthError, ERR_INVALID_MSG, ERR_INVALID_OWNER, ERR_OPERATION_FORBIDDEN,
             ERR_SHARE_MDATA_DENIED, ERR_UNKNOWN_APP};
use ffi::apps::*;
use ffi_utils::{FfiResult, ReprC, StringError, base64_encode, from_c_str};
use ffi_utils::test_utils::{self, call_1, call_vec};
use futures::{Future, future};
use ipc::{encode_auth_resp, encode_containers_resp, encode_share_mdata_resp,
          encode_unregistered_resp};
use maidsafe_utilities::serialisation::deserialise;
use rand::{self, Rng};
use revocation;
#[cfg(feature = "use-mock-routing")]
use routing::{Action, ClientError, MutableData, PermissionSet, Request, Response, User, Value};
use rust_sodium::crypto::sign;
use safe_core::{CoreError, MDataInfo, mdata_info};
#[cfg(feature = "use-mock-routing")]
use safe_core::{MockRouting, utils};
use safe_core::ipc::{self, AuthReq, BootstrapConfig, ContainersReq, IpcError, IpcMsg, IpcReq,
                     IpcResp, Permission, ShareMData, ShareMDataReq};
use safe_core::ipc::req::ffi::AppExchangeInfo as FfiAppExchangeInfo;
use safe_core::ipc::req::ffi::AuthReq as FfiAuthReq;
use safe_core::ipc::req::ffi::ContainersReq as FfiContainersReq;
use safe_core::ipc::req::ffi::ShareMDataReq as FfiShareMDataReq;
use safe_core::ipc::resp::ffi::MDataMeta as FfiMDataMeta;
use safe_core::nfs::{DEFAULT_PRIVATE_DIRS, DEFAULT_PUBLIC_DIRS, File, Mode, NfsError, file_helper};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ffi::{CStr, CString};
use std::iter;
use std::os::raw::{c_char, c_void};
use std::slice;
use std::sync::mpsc;
use std::sync::mpsc::Sender;
use std::time::Duration;
use test_utils::{access_container, compare_access_container_entries, create_account_and_login,
                 create_account_and_login_with_hook, rand_app, register_app, run,
                 try_access_container, try_run};
#[cfg(feature = "use-mock-routing")]
use test_utils::get_container_from_root;
use tiny_keccak::sha3_256;

// Test creation and content of std dirs after account creation.
#[test]
fn user_root_dir() {
    let authenticator = create_account_and_login();
    let std_dir_names: Vec<_> = DEFAULT_PRIVATE_DIRS
        .iter()
        .chain(DEFAULT_PUBLIC_DIRS.iter())
        .collect();

    // Fetch the entries of the user root dir.
    let (dir, entries) = run(&authenticator, |client| {
        let dir = unwrap!(client.user_root_dir());
        client
            .list_mdata_entries(dir.name, dir.type_tag)
            .map(move |entries| (dir, entries))
            .map_err(AuthError::from)
    });

    let entries = unwrap!(mdata_info::decrypt_entries(&dir, &entries));

    // Verify that all the std dirs are there.
    for name in &std_dir_names {
        assert!(entries.contains_key(name.as_bytes()));
    }

    // Fetch all the dirs under user root dir and verify they are empty.
    let dirs: Vec<_> = entries
        .into_iter()
        .map(|(_, value)| {
            unwrap!(deserialise::<MDataInfo>(&value.content))
        })
        .collect();

    let dirs = run(&authenticator, move |client| {
        let fs: Vec<_> = dirs.into_iter()
            .map(|dir| {
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

    let ac = unwrap!(entries.get(KEY_ACCESS_CONTAINER));
    let ac: MDataInfo = unwrap!(deserialise(&ac.content));

    // Fetch access container and verify it's empty.
    let (entries, permissions) = run(&authenticator, move |client| {
        let f1 = client.list_mdata_entries(ac.name, ac.type_tag);
        let f2 = client.list_mdata_permissions(ac.name, ac.type_tag);

        f1.join(f2).map_err(AuthError::from)
    });

    assert!(entries.is_empty());
    assert!(permissions.is_empty());
}

// Test operation recovery for std dirs creation
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
    let locator = unwrap!(utils::generate_random_string(10));
    let password = unwrap!(utils::generate_random_string(10));
    let invitation = unwrap!(utils::generate_random_string(10));

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
        .chain(DEFAULT_PUBLIC_DIRS.iter())
        .collect();

    // Fetch the entries of the user root dir.
    let (dir, entries) = run(&authenticator, |client| {
        let dir = unwrap!(client.user_root_dir());
        client
            .list_mdata_entries(dir.name, dir.type_tag)
            .map(move |entries| (dir, entries))
            .map_err(AuthError::from)
    });
    let entries = unwrap!(mdata_info::decrypt_entries(&dir, &entries));

    // Verify that all the std dirs are there.
    for name in &std_dir_names {
        assert!(entries.contains_key(name.as_bytes()));
    }

    // Verify that accesss container has been created too
    let _version = run(&authenticator, |client| {
        let c2 = client.clone();

        access_container_tools::access_container(client).and_then(move |ac_info| {
            c2.get_mdata_version(ac_info.name, ac_info.type_tag)
                .map_err(AuthError::from)
        })
    });
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
    let app_exchange_info = unwrap!(rand_app());
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

    // Check there app dir is present in the user root.
    let received_app_dir_info = run(&authenticator, move |client| {
        let user_root_dir = unwrap!(client.user_root_dir());

        let app_dir_key = format!("apps/{}", app_id).into_bytes();
        let app_dir_key = unwrap!(user_root_dir.enc_entry_key(&app_dir_key));

        client
            .get_mdata_value(user_root_dir.name, user_root_dir.type_tag, app_dir_key)
            .and_then(move |value| {
                let encoded = user_root_dir.decrypt(&value.content)?;
                let decoded = deserialise::<MDataInfo>(&encoded)?;
                Ok(decoded)
            })
            .map_err(AuthError::from)
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
            app: unwrap!(rand_app()),
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
        app: unwrap!(rand_app()),
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

#[test]
fn containers_unknown_app() {
    let authenticator = create_account_and_login();

    // Create IpcMsg::Req { req: IpcReq::Containers } for a random App (random id, name, vendor etc)
    let req_id = ipc::gen_req_id();
    let msg = IpcMsg::Req {
        req_id: req_id,
        req: IpcReq::Containers(ContainersReq {
            app: unwrap!(rand_app()),
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

#[test]
fn containers_access_request() {
    let authenticator = create_account_and_login();

    // Create IpcMsg::AuthReq for a random App (random id, name, vendor etc), ask for app_container
    // and containers "documents with permission to insert", "videos with all the permissions
    // possible",
    let auth_req = AuthReq {
        app: unwrap!(rand_app()),
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

// The app revocation and re-authorization workflow.
#[test]
fn app_revocation() {
    let authenticator = create_account_and_login();

    // Create and authorise two apps.
    let auth_req1 = AuthReq {
        app: unwrap!(rand_app()),
        app_container: false,
        containers: create_containers_req(),
    };
    let app_id1 = auth_req1.app.id.clone();
    let auth_granted1 = unwrap!(register_app(&authenticator, &auth_req1));

    let auth_req2 = AuthReq {
        app: unwrap!(rand_app()),
        app_container: true,
        containers: create_containers_req(),
    };
    let app_id2 = auth_req2.app.id.clone();
    let auth_granted2 = unwrap!(register_app(&authenticator, &auth_req2));

    // Put one file by each app into a shared container.
    let mut ac_entries = access_container(&authenticator, app_id1.clone(), auth_granted1.clone());
    let (videos_md1, _) = unwrap!(ac_entries.remove("_videos"));
    unwrap!(create_file(
        &authenticator,
        videos_md1.clone(),
        "1.mp4",
        vec![1; 10],
    ));

    let mut ac_entries = access_container(&authenticator, app_id2.clone(), auth_granted2.clone());
    let (videos_md2, _) = unwrap!(ac_entries.remove("_videos"));
    unwrap!(create_file(
        &authenticator,
        videos_md2.clone(),
        "2.mp4",
        vec![1; 10],
    ));

    let app_container_name = format!("apps/{}", app_id2.clone());
    let (app_container_md, _) = unwrap!(ac_entries.remove(&app_container_name));
    unwrap!(create_file(
        &authenticator,
        app_container_md.clone(),
        "3.mp4",
        vec![1; 10],
    ));

    // There should be 2 entries.
    assert_eq!(count_mdata_entries(&authenticator, videos_md1.clone()), 2);

    // Both apps can access both files.
    let _ = unwrap!(fetch_file(&authenticator, videos_md1.clone(), "1.mp4"));
    let _ = unwrap!(fetch_file(&authenticator, videos_md1.clone(), "2.mp4"));

    let _ = unwrap!(fetch_file(&authenticator, videos_md2.clone(), "1.mp4"));
    let _ = unwrap!(fetch_file(&authenticator, videos_md2.clone(), "2.mp4"));

    // Revoke the first app.
    revoke(&authenticator, &app_id1);

    // There should now be 4 entries - 2 deleted previous entries, 2 new,
    // reencrypted entries.
    assert_eq!(count_mdata_entries(&authenticator, videos_md1.clone()), 4);

    // The first app is no longer be in the access container.
    let ac = try_access_container(&authenticator, app_id1.clone(), auth_granted1.clone());
    assert!(ac.is_none());

    // Container permissions includes only the second app.
    let (name, tag) = (videos_md2.name, videos_md2.type_tag);
    let perms = run(&authenticator, move |client| {
        client.list_mdata_permissions(name, tag).map_err(From::from)
    });
    assert!(!perms.contains_key(
        &User::Key(auth_granted1.app_keys.sign_pk),
    ));
    assert!(perms.contains_key(
        &User::Key(auth_granted2.app_keys.sign_pk),
    ));

    // The first app can no longer access the files.
    match fetch_file(&authenticator, videos_md1.clone(), "1.mp4") {
        Err(AuthError::NfsError(NfsError::CoreError(CoreError::EncodeDecodeError(..)))) => (),
        x => panic!("Unexpected {:?}", x),
    }

    match fetch_file(&authenticator, videos_md1.clone(), "2.mp4") {
        Err(AuthError::NfsError(NfsError::CoreError(CoreError::EncodeDecodeError(..)))) => (),
        x => panic!("Unexpected {:?}", x),
    }

    // The second app can still access both files after re-fetching the access container.
    let mut ac_entries = access_container(&authenticator, app_id2.clone(), auth_granted2.clone());
    let (videos_md2, _) = unwrap!(ac_entries.remove("_videos"));

    let _ = unwrap!(fetch_file(&authenticator, videos_md2.clone(), "1.mp4"));
    let _ = unwrap!(fetch_file(&authenticator, videos_md2.clone(), "2.mp4"));

    // Re-authorize the first app.
    let auth_granted1 = unwrap!(register_app(&authenticator, &auth_req1));
    let mut ac_entries = access_container(&authenticator, app_id1.clone(), auth_granted1.clone());
    let (videos_md1, _) = unwrap!(ac_entries.remove("_videos"));

    // The first app can access the files again.
    let _ = unwrap!(fetch_file(&authenticator, videos_md1.clone(), "1.mp4"));
    let _ = unwrap!(fetch_file(&authenticator, videos_md1.clone(), "2.mp4"));

    // The second app as well.
    let _ = unwrap!(fetch_file(&authenticator, videos_md2.clone(), "1.mp4"));
    let _ = unwrap!(fetch_file(&authenticator, videos_md2.clone(), "2.mp4"));

    // Revoke the first app again. Only the second app can access the files.
    revoke(&authenticator, &app_id1);

    // There should now be 6 entries (4 deleted, 2 new).
    assert_eq!(count_mdata_entries(&authenticator, videos_md1.clone()), 6);

    match fetch_file(&authenticator, videos_md1.clone(), "1.mp4") {
        Err(AuthError::NfsError(NfsError::CoreError(CoreError::EncodeDecodeError(..)))) => (),
        x => panic!("Unexpected {:?}", x),
    }

    match fetch_file(&authenticator, videos_md1.clone(), "2.mp4") {
        Err(AuthError::NfsError(NfsError::CoreError(CoreError::EncodeDecodeError(..)))) => (),
        x => panic!("Unexpected {:?}", x),
    }

    let mut ac_entries = access_container(&authenticator, app_id2.clone(), auth_granted2.clone());
    let (videos_md2, _) = unwrap!(ac_entries.remove("_videos"));
    let _ = unwrap!(fetch_file(&authenticator, videos_md2.clone(), "1.mp4"));
    let _ = unwrap!(fetch_file(&authenticator, videos_md2.clone(), "2.mp4"));

    // Revoke the second app that has created its own app container.
    revoke(&authenticator, &app_id2);

    match fetch_file(&authenticator, videos_md2.clone(), "1.mp4") {
        Err(AuthError::NfsError(NfsError::CoreError(CoreError::EncodeDecodeError(..)))) => (),
        x => panic!("Unexpected {:?}", x),
    }

    // Try to reauthorise and revoke the second app again - as it should have reused its
    // app container, the subsequent reauthorisation + revocation should work correctly too.
    let auth_granted2 = unwrap!(register_app(&authenticator, &auth_req2));

    // The second app should be able to access data from its own container,
    let mut ac_entries = access_container(&authenticator, app_id2.clone(), auth_granted2.clone());
    let (app_container_md, _) = unwrap!(ac_entries.remove(&app_container_name));

    assert_eq!(
        count_mdata_entries(&authenticator, app_container_md.clone()),
        2
    );
    let _ = unwrap!(fetch_file(
        &authenticator,
        app_container_md.clone(),
        "3.mp4",
    ));

    revoke(&authenticator, &app_id2);
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
        app: unwrap!(rand_app()),
        app_container: false,
        containers: Default::default(),
    };

    let auth_req2 = AuthReq {
        app: unwrap!(rand_app()),
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
    revoke(&authenticator, &auth_req1.app.id);

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

// Test operation recovery for app revocation
//
// 1. Create a test app and authenticate it.
// 2. Grant access to some of the default containers (e.g. `_video`, `_documents`).
// 3. Put several files with a known content in both containers (e.g. `_video/test.txt` and
//    `_documents/test2.txt`).
// 4. Revoke the app access from the authenticator.
// 5. After re-encryption of the `_document` container is done, simulate a network failure
//    for the `_video` container encryption step.
// 6. Verify that the `_videos` container is still accessible using the previous encryption key.
// 7. Verify that the `_documents` container is not accessible using the current key, but is
//    accessible using the new key.
// 8. Check that the app's key is not listed in MaidManagers.
// 9. Repeat step 1.4 (restart the revoke operation for the app) and don't interfere with the
//    re-encryption process this time. It should pass.
// 10. Verify that both the second and first containers aren't accessible using previous keys.
// 11. Verify that both the second and first containers are accesible using the new keys.
#[cfg(feature = "use-mock-routing")]
#[test]
fn app_revocation_recovery() {
    let locator = unwrap!(utils::generate_random_string(10));
    let password = unwrap!(utils::generate_random_string(10));
    let invitation = unwrap!(utils::generate_random_string(10));

    let auth = unwrap!(Authenticator::create_acc(
        locator.clone(),
        password.clone(),
        invitation,
        |_| (),
    ));

    // Create a test app and authenticate it.
    // Grant access to some of the default containers (e.g. `_video`, `_documents`).
    let auth_req = AuthReq {
        app: unwrap!(rand_app()),
        app_container: false,
        containers: create_containers_req(),
    };
    let app_id = auth_req.app.id.clone();
    let auth_granted = unwrap!(register_app(&auth, &auth_req));

    // Put several files with a known content in both containers
    let mut ac_entries = access_container(&auth, app_id.clone(), auth_granted.clone());
    let (videos_md, _) = unwrap!(ac_entries.remove("_videos"));
    let (docs_md, _) = unwrap!(ac_entries.remove("_documents"));

    unwrap!(create_file(
        &auth,
        videos_md.clone(),
        "video.mp4",
        vec![1; 10],
    ));
    unwrap!(create_file(&auth, docs_md.clone(), "test.doc", vec![2; 10]));

    // After re-encryption of the first container (`_video`) is done, simulate a network failure
    let docs_name = docs_md.name;

    let user_root_md = run(&auth, move |client| {
        client.user_root_dir().map_err(AuthError::from)
    });
    let user_root_name = user_root_md.name;

    let routing_hook = move |mut routing: MockRouting| -> MockRouting {
        let mut fail_user_root_update = false;

        routing.set_request_hook(move |req| {
            match *req {
                // Simulate a network failure for a second request to re-encrypt containers
                // so that the _videos container should remain untouched
                Request::MutateMDataEntries { name, msg_id, .. }
                    if name == docs_name || (name == user_root_name && fail_user_root_update) => {
                    fail_user_root_update = true;

                    Some(Response::MutateMDataEntries {
                        msg_id,
                        res: Err(ClientError::LowBalance),
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

    // Revoke the app.
    match try_revoke(&auth, &app_id) {
        Err(AuthError::CoreError(CoreError::RoutingClientError(ClientError::LowBalance))) => (),
        x => panic!("Unexpected {:?}", x),
    }

    // Verify that the `_documents` container is still accessible using the previous key.
    let _ = unwrap!(fetch_file(&auth, docs_md.clone(), "test.doc"));

    // Verify that the `_videos` container is not accessible using the previous key,
    // but is accessible using the new key.
    match fetch_file(&auth, videos_md.clone(), "video.mp4") {
        Err(AuthError::NfsError(NfsError::CoreError(CoreError::EncodeDecodeError(..)))) => (),
        x => panic!("Unexpected {:?}", x),
    }

    // We'd need to get that new key from the root container though, as the access container
    // entry for the app hasn't been updated at this point.
    let mut reencrypted_videos_md = unwrap!(get_container_from_root(&auth, "_videos"));

    // The container has been reencrypted now, swap the old enc info
    reencrypted_videos_md.commit_new_enc_info();
    let _ = unwrap!(fetch_file(
        &auth,
        reencrypted_videos_md.clone(),
        "video.mp4",
    ));

    // Ensure that the app's key has been removed from MaidManagers
    let auth_keys = run(&auth, move |client| {
        client
            .list_auth_keys_and_version()
            .map(move |(auth_keys, _version)| auth_keys)
            .map_err(AuthError::from)
    });
    assert!(!auth_keys.contains(&auth_granted.app_keys.sign_pk));

    // Login and try to revoke the app again, now without interfering with responses
    let auth = unwrap!(Authenticator::login(
        locator.clone(),
        password.clone(),
        |_| (),
    ));

    // App revocation should succeed
    revoke(&auth, &app_id);

    // Try to access both files using previous keys - they shouldn't be accessible
    match fetch_file(&auth, docs_md.clone(), "test.doc") {
        Err(AuthError::NfsError(NfsError::CoreError(CoreError::EncodeDecodeError(..)))) => (),
        x => panic!("Unexpected {:?}", x),
    }
    match fetch_file(&auth, videos_md.clone(), "video.mp4") {
        Err(AuthError::NfsError(NfsError::CoreError(CoreError::EncodeDecodeError(..)))) => (),
        x => panic!("Unexpected {:?}", x),
    }

    // Get the new encryption info from the user's root dir (as the access container has been
    // removed now). Both containers should be accessible with the new keys without any extra
    // effort
    let ac_entries = try_access_container(&auth, app_id.clone(), auth_granted.clone());
    assert!(ac_entries.is_none());

    let reencrypted_docs_md = unwrap!(get_container_from_root(&auth, "_documents"));
    let reencrypted_videos_md = unwrap!(get_container_from_root(&auth, "_videos"));

    let _ = unwrap!(fetch_file(&auth, reencrypted_docs_md.clone(), "test.doc"));
    let _ = unwrap!(fetch_file(
        &auth,
        reencrypted_videos_md.clone(),
        "video.mp4",
    ));
}

// Test operation recovery for app authentication
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
    let locator = unwrap!(utils::generate_random_string(10));
    let password = unwrap!(utils::generate_random_string(10));
    let invitation = unwrap!(utils::generate_random_string(10));

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
        app: unwrap!(rand_app()),
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
        let mut reqs_counter = 0;

        routing.set_request_hook(move |req| {
            match *req {
                Request::SetMDataUserPermissions { msg_id, .. } => {
                    reqs_counter += 1;

                    if reqs_counter == 3 {
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
                assert!(version > 0);

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

// Test app cannot be (re)authenticated while it's being revoked.
//
// 1. Create an app.
// 2. Initiate a revocation of the app, but simulate a network failure to prevent it
//    from finishing.
// 3. Try to re-authenticate the app and assert that it fails (as the app is in the
//    middle of its revocation process)
// 4. Re-try the revocation with no simulated failures to let it finish successfuly.
// 5. Try to re-authenticate the app again. This time it will succeed.
#[test]
fn app_authentication_during_pending_revocation() {
    // Create account.
    let locator = unwrap!(utils::generate_random_string(10));
    let password = unwrap!(utils::generate_random_string(10));
    let invitation = unwrap!(utils::generate_random_string(10));

    let auth = unwrap!(Authenticator::create_acc(
        locator.clone(),
        password.clone(),
        invitation,
        |_| (),
    ));

    // Authenticate the app.
    let auth_req = AuthReq {
        app: unwrap!(rand_app()),
        app_container: false,
        containers: create_containers_req(),
    };

    let app_id = auth_req.app.id.clone();
    let _ = unwrap!(register_app(&auth, &auth_req));

    // Attempt to revoke it which fails due to simulated network failure.
    simulate_revocation_failure(&locator, &password, iter::once(&app_id));

    // Attempt to re-authenticate the app fails, because revocation is pending.
    match register_app(&auth, &auth_req) {
        Err(_) => (), // TODO: assert expected error variant
        x => panic!("Unexpected {:?}", x),
    }

    // Retry the app revocation. This time it succeeds.
    revoke(&auth, &app_id);

    // Re-authentication now succeeds.
    let _ = unwrap!(register_app(&auth, &auth_req));
}

// Test flushing the app revocation queue.
//
// 1. Create two apps
// 2. Revoke both of them, but simulate network failure so both revocations would
//    fail.
// 3. Log in again and flush the revocation queue with no simulated failures.
// 4. Verify both apps are successfuly revoked.
#[test]
fn flushing_app_revocation_queue() {
    // Create account.
    let locator = unwrap!(utils::generate_random_string(10));
    let password = unwrap!(utils::generate_random_string(10));
    let invitation = unwrap!(utils::generate_random_string(10));

    let auth = unwrap!(Authenticator::create_acc(
        locator.clone(),
        password.clone(),
        invitation,
        |_| (),
    ));

    // Authenticate the first app.
    let auth_req = AuthReq {
        app: unwrap!(rand_app()),
        app_container: false,
        containers: create_containers_req(),
    };

    let _ = unwrap!(register_app(&auth, &auth_req));
    let app_id_0 = auth_req.app.id.clone();

    // Authenticate the second app.
    let auth_req = AuthReq {
        app: unwrap!(rand_app()),
        app_container: false,
        containers: create_containers_req(),
    };

    let _ = unwrap!(register_app(&auth, &auth_req));
    let app_id_1 = auth_req.app.id.clone();

    // Simulate failed revocations of both apps.
    simulate_revocation_failure(&locator, &password, &[&app_id_0, &app_id_1]);

    // Verify the apps are not revoked yet.
    {
        let app_id_0 = app_id_0.clone();
        let app_id_1 = app_id_1.clone();

        run(&auth, |client| {
            let client = client.clone();

            config::list_apps(&client)
                .then(move |res| {
                    let (_, apps) = unwrap!(res);
                    let f_0 = app_auth::app_state(&client, &apps, app_id_0);
                    let f_1 = app_auth::app_state(&client, &apps, app_id_1);

                    f_0.join(f_1)
                })
                .then(|res| {
                    let (state_0, state_1) = unwrap!(res);
                    assert_eq!(state_0, AppState::Authenticated);
                    assert_eq!(state_1, AppState::Authenticated);

                    Ok(())
                })
        })
    }

    // Login again without simulated failures.
    let auth = unwrap!(Authenticator::login(locator, password, |_| ()));

    // Flush the revocation queue and verify both apps get revoked.
    run(&auth, |client| {
        let c2 = client.clone();
        let c3 = client.clone();

        revocation::flush_app_revocation_queue(client)
            .then(move |res| {
                unwrap!(res);
                config::list_apps(&c2)
            })
            .then(move |res| {
                let (_, apps) = unwrap!(res);
                let f_0 = app_auth::app_state(&c3, &apps, app_id_0);
                let f_1 = app_auth::app_state(&c3, &apps, app_id_1);

                f_0.join(f_1)
            })
            .then(move |res| {
                let (state_0, state_1) = unwrap!(res);
                assert_eq!(state_0, AppState::Revoked);
                assert_eq!(state_1, AppState::Revoked);

                Ok(())
            })
    })
}

#[test]
fn share_zero_mdatas() {
    let authenticator = create_account_and_login();

    let msg = IpcMsg::Req {
        req_id: ipc::gen_req_id(),
        req: IpcReq::ShareMData(ShareMDataReq {
            app: unwrap!(rand_app()),
            mdata: vec![],
        }),
    };
    let encoded_msg = unwrap!(ipc::encode_msg(&msg, "safe-auth"));

    let decoded = unwrap!(decode_ipc_msg(&authenticator, &encoded_msg));
    match decoded {
        (IpcMsg::Req { req: IpcReq::ShareMData(ShareMDataReq { mdata, .. }), .. },
         Some(metadatas)) => {
            assert_eq!(mdata.len(), 0);
            assert_eq!(metadatas.len(), 0);
        }
        _ => panic!("Unexpected: {:?}", decoded),
    };
}

#[test]
fn share_some_mdatas() {
    let authenticator = create_account_and_login();

    let user = run(&authenticator, move |client| {
        client.public_signing_key().map_err(AuthError::CoreError)
    });

    const NUM_MDATAS: usize = 3;

    let mut mdatas = Vec::new();
    for _ in 0..NUM_MDATAS {
        let name = rand::random();
        let mdata = {
            let owners = btree_set![user];
            unwrap!(MutableData::new(
                name,
                0,
                BTreeMap::new(),
                BTreeMap::new(),
                owners,
            ))
        };

        run(&authenticator, move |client| {
            client.put_mdata(mdata).map_err(AuthError::CoreError)
        });

        mdatas.push(ShareMData {
            type_tag: 0,
            name: name,
            metadata_key: None,
            perms: PermissionSet::new(),
        });
    }

    let msg = IpcMsg::Req {
        req_id: ipc::gen_req_id(),
        req: IpcReq::ShareMData(ShareMDataReq {
            app: unwrap!(rand_app()),
            mdata: mdatas.clone(),
        }),
    };
    let encoded_msg = unwrap!(ipc::encode_msg(&msg, "safe-auth"));

    let decoded = unwrap!(decode_ipc_msg(&authenticator, &encoded_msg));
    match decoded {
        (IpcMsg::Req { req: IpcReq::ShareMData(ShareMDataReq { mdata, .. }), .. },
         Some(metadatas)) => {
            assert_eq!(mdata, mdatas);
            assert_eq!(
                metadatas,
                iter::repeat(Vec::<u8>::new())
                    .take(NUM_MDATAS)
                    .collect::<Vec<_>>()
            );
        }
        _ => panic!("Unexpected: {:?}", decoded),
    };
}

#[test]
fn share_some_mdatas_with_metadata() {
    let authenticator = create_account_and_login();

    let app_id = unwrap!(rand_app());
    let auth_req = AuthReq {
        app: app_id.clone(),
        app_container: false,
        containers: Default::default(),
    };

    let app_auth = unwrap!(register_app(&authenticator, &auth_req));
    let app_key = app_auth.app_keys.sign_pk;

    let user = run(&authenticator, move |client| {
        client.public_signing_key().map_err(AuthError::CoreError)
    });

    const NUM_MDATAS: usize = 3;

    let perms = PermissionSet::new().allow(Action::Insert);
    let mut mdatas = Vec::new();
    let mut metadatas = Vec::new();
    for _ in 0..NUM_MDATAS {
        let metadata: Vec<u8> = rand::thread_rng().gen_iter().take(1024).collect();
        let name = rand::random();
        let mdata = {
            let value = Value {
                content: metadata.clone(),
                entry_version: 0,
            };
            let owners = btree_set![user];
            let mut data = BTreeMap::new();
            let _ = data.insert(b"metadata"[..].to_owned(), value);
            unwrap!(MutableData::new(name, 0, BTreeMap::new(), data, owners))
        };

        run(&authenticator, move |client| {
            client.put_mdata(mdata).map_err(AuthError::CoreError)
        });

        mdatas.push(ShareMData {
            type_tag: 0,
            name: name,
            metadata_key: Some(String::from("metadata")),
            perms: perms,
        });
        metadatas.push(metadata);
    }

    let req_id = ipc::gen_req_id();
    let req = ShareMDataReq {
        app: app_id,
        mdata: mdatas.clone(),
    };
    let msg = IpcMsg::Req {
        req_id: req_id,
        req: IpcReq::ShareMData(req.clone()),
    };
    let encoded_msg = unwrap!(ipc::encode_msg(&msg, "safe-auth"));

    let decoded = unwrap!(decode_ipc_msg(&authenticator, &encoded_msg));
    match decoded {
        (IpcMsg::Req { req: IpcReq::ShareMData(ShareMDataReq { mdata, .. }), .. },
         Some(received_metadatas)) => {
            assert_eq!(mdata, mdatas);
            assert_eq!(received_metadatas, metadatas);
        }
        _ => panic!("Unexpected: {:?}", decoded),
    };

    let (tx, rx) = mpsc::channel::<Result<(), (i32, String)>>();
    let (req_c, req_c_data) = unwrap!(req.into_repr_c());
    unsafe {
        encode_share_mdata_resp(
            &authenticator,
            &req_c,
            req_id,
            true,
            test_utils::sender_as_user_data::<Result<(), (i32, String)>>(&tx),
            encode_share_mdata_cb,
        );
    }

    unwrap!(unwrap!(rx.recv_timeout(Duration::from_secs(15))));

    for share_mdata in &mdatas {
        let name = share_mdata.name;
        let type_tag = share_mdata.type_tag;
        let mdata = run(&authenticator, move |client| {
            client.get_mdata(name, type_tag).map_err(
                AuthError::CoreError,
            )
        });
        let permissions = unwrap!(mdata.user_permissions(&User::Key(app_key)));
        assert_eq!(permissions, &perms);
    }

    drop(tx);
    drop(req_c_data);
}

#[test]
fn share_some_mdatas_with_ownership_error() {
    let authenticator = create_account_and_login();

    let user = run(&authenticator, move |client| {
        client.public_signing_key().map_err(AuthError::CoreError)
    });

    let (someone_else, _) = sign::gen_keypair();

    let ownerss = vec![
        btree_set![user /* , someone_else */], // currently can't handle having multiple owners
        btree_set![someone_else],
        btree_set![user],
        btree_set![],
    ];

    let mut mdatas = Vec::new();
    for owners in ownerss {
        let name = rand::random();
        let mdata = {
            unwrap!(MutableData::new(
                name,
                0,
                BTreeMap::new(),
                BTreeMap::new(),
                owners,
            ))
        };

        run(&authenticator, move |client| {
            client.put_mdata(mdata).map_err(AuthError::CoreError)
        });

        mdatas.push(ShareMData {
            type_tag: 0,
            name: name,
            metadata_key: None,
            perms: PermissionSet::new(),
        });
    }

    let req_id = ipc::gen_req_id();
    let req = ShareMDataReq {
        app: unwrap!(rand_app()),
        mdata: mdatas.clone(),
    };
    let msg = IpcMsg::Req {
        req_id: req_id,
        req: IpcReq::ShareMData(req.clone()),
    };
    let encoded_msg = unwrap!(ipc::encode_msg(&msg, "safe-auth"));

    match decode_ipc_msg(&authenticator, &encoded_msg) {
        Ok(..) => (),
        Err(err) => {
            assert_eq!(err, (ERR_INVALID_OWNER, None));
        }
    };

    let (tx, rx) = mpsc::channel::<Result<(), (i32, String)>>();
    let (req_c, req_c_data) = unwrap!(req.into_repr_c());
    unsafe {
        encode_share_mdata_resp(
            &authenticator,
            &req_c,
            req_id,
            false,
            test_utils::sender_as_user_data::<Result<(), (i32, String)>>(&tx),
            encode_share_mdata_cb,
        );
    }

    match unwrap!(rx.recv_timeout(Duration::from_secs(15))) {
        Ok(()) => panic!("unexpected success"),
        Err((ERR_SHARE_MDATA_DENIED, _)) => (),
        Err((code, description)) => panic!("Unexpected error ({}): {}", code, description),
    };
    drop(tx);
    drop(req_c_data);
}

// Create file in the given container, with the given name and content.
fn create_file<T: Into<String>>(
    authenticator: &Authenticator,
    container_info: MDataInfo,
    name: T,
    content: Vec<u8>,
) -> Result<(), AuthError> {
    let name = name.into();
    try_run(authenticator, |client| {
        let c2 = client.clone();

        file_helper::write(
            client.clone(),
            File::new(vec![]),
            Mode::Overwrite,
            container_info.enc_key().cloned(),
        ).then(move |res| {
            let writer = unwrap!(res);
            writer.write(&content).and_then(move |_| writer.close())
        })
            .then(move |file| {
                file_helper::insert(c2, container_info, name, &unwrap!(file))
            })
            .map_err(From::from)
    })
}

fn fetch_file<T: Into<String>>(
    authenticator: &Authenticator,
    container_info: MDataInfo,
    name: T,
) -> Result<File, AuthError> {
    let name = name.into();
    try_run(authenticator, |client| {
        file_helper::fetch(client.clone(), container_info, name)
            .map(|(_, file)| file)
            .map_err(From::from)
    })
}

fn count_mdata_entries(authenticator: &Authenticator, info: MDataInfo) -> usize {
    run(authenticator, move |client| {
        client
            .list_mdata_entries(info.name, info.type_tag)
            .map(|entries| entries.len())
            .map_err(From::from)
    })
}

fn try_revoke(authenticator: &Authenticator, app_id: &str) -> Result<(), AuthError> {
    let app_id = app_id.to_string();

    try_run(authenticator, move |client| {
        revocation::revoke_app(client, &app_id)
    })
}

fn revoke(authenticator: &Authenticator, app_id: &str) {
    match try_revoke(authenticator, app_id) {
        Ok(_) => (),
        x => panic!("Unexpected {:?}", x),
    }
}

// Try to revoke apps with the given ids, but simulate network failure so they
// would be initiated but not finished.
fn simulate_revocation_failure<T, S>(locator: &str, password: &str, app_ids: T)
where
    T: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    // First, log in normally to obtain the access contained info.
    let auth = unwrap!(Authenticator::login(locator, password, |_| ()));
    let ac_info = run(&auth, |client| {
        access_container_tools::access_container(client)
    });

    // Then, log in with a request hook that makes mutation of the access container
    // fail.
    let auth = unwrap!(Authenticator::login_with_hook(
        locator,
        password,
        |_| (),
        move |mut routing| {
            let ac_info = ac_info.clone();

            routing.set_request_hook(move |request| match *request {
                Request::MutateMDataEntries { name, tag, msg_id, .. } => {
                    if name == ac_info.name && tag == ac_info.type_tag {
                        Some(Response::MutateMDataEntries {
                            res: Err(ClientError::LowBalance),
                            msg_id,
                        })
                    } else {
                        None
                    }
                }
                _ => None,
            });

            routing
        },
    ));

    // Then attempt to revoke each app from the iterator.
    for app_id in app_ids {
        match try_revoke(&auth, app_id.as_ref()) {
            Err(_) => (),
            x => panic!("Unexpected {:?}", x),
        }
    }
}

// Creates a containers request asking for "documents with permission to
// insert", and "videos with all the permissions possible",
fn create_containers_req() -> HashMap<String, BTreeSet<Permission>> {
    let mut containers = HashMap::new();
    let _ = containers.insert("_documents".to_owned(), btree_set![Permission::Insert]);
    let _ = containers.insert(
        "_videos".to_owned(),
        btree_set![
            Permission::Read,
            Permission::Insert,
            Permission::Update,
            Permission::Delete,
            Permission::ManagePermissions,
        ],
    );
    containers
}

// Helper to decode IpcMsg.
// TODO: there should be a public function with a signature like this, and the
//       FFI function `ipc::decode_ipc_msg` should be only wrapper over it.
fn decode_ipc_msg(authenticator: &Authenticator, msg: &str) -> ChannelType {
    let (tx, rx) = mpsc::channel::<ChannelType>();

    extern "C" fn auth_cb(user_data: *mut c_void, req_id: u32, req: *const FfiAuthReq) {
        unsafe {
            let req = match AuthReq::clone_from_repr_c(req) {
                Ok(req) => req,
                Err(_) => return send_via_user_data(user_data, Err((-2, None))),
            };

            let msg = IpcMsg::Req {
                req_id: req_id,
                req: IpcReq::Auth(req),
            };

            send_via_user_data(user_data, Ok((msg, None)))
        }
    }

    extern "C" fn containers_cb(user_data: *mut c_void, req_id: u32, req: *const FfiContainersReq) {
        unsafe {
            let req = match ContainersReq::clone_from_repr_c(req) {
                Ok(req) => req,
                Err(_) => return send_via_user_data(user_data, Err((-2, None))),
            };

            let msg = IpcMsg::Req {
                req_id: req_id,
                req: IpcReq::Containers(req),
            };

            send_via_user_data(user_data, Ok((msg, None)))
        }
    }

    extern "C" fn share_mdata_cb(
        user_data: *mut c_void,
        req_id: u32,
        req: *const FfiShareMDataReq,
        mdata_metas: *const FfiMDataMeta,
    ) {
        unsafe {
            let req = match ShareMDataReq::clone_from_repr_c(req) {
                Ok(req) => req,
                Err(_) => return send_via_user_data(user_data, Err((-2, None))),
            };

            let mut mdatas = Vec::with_capacity(req.mdata.len());
            let mdatas_raw = slice::from_raw_parts(mdata_metas, req.mdata.len());
            for mdata_raw in mdatas_raw {
                let data_raw = slice::from_raw_parts(mdata_raw.data, mdata_raw.len);
                let data = data_raw.to_owned();
                mdatas.push(data);
            }

            let msg = IpcMsg::Req {
                req_id: req_id,
                req: IpcReq::ShareMData(req),
            };

            send_via_user_data(user_data, Ok((msg, Some(mdatas))))
        }
    }

    let ffi_msg = unwrap!(CString::new(msg));

    unsafe {
        use ipc::auth_decode_ipc_msg;
        auth_decode_ipc_msg(
            authenticator,
            ffi_msg.as_ptr(),
            sender_as_user_data(&tx),
            auth_cb,
            containers_cb,
            unregistered_cb,
            share_mdata_cb,
            err_cb,
        );
    };

    let ret = match rx.recv_timeout(Duration::from_secs(15)) {
        Ok(r) => r,
        Err(_) => Err((-1, None)),
    };
    drop(tx);
    ret
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

extern "C" fn unregistered_cb(user_data: *mut c_void, req_id: u32) {
    unsafe {
        let msg = IpcMsg::Req {
            req_id: req_id,
            req: IpcReq::Unregistered,
        };

        send_via_user_data(user_data, Ok((msg, None)))
    }
}

extern "C" fn err_cb(user_data: *mut c_void, res: FfiResult, response: *const c_char) {
    unsafe {
        let ipc_resp = if response.is_null() {
            None
        } else {
            let response = CStr::from_ptr(response);
            match ipc::decode_msg(unwrap!(response.to_str())) {
                Ok(ipc_resp) => Some(ipc_resp),
                Err(_) => None,
            }
        };

        send_via_user_data(user_data, Err((res.error_code, ipc_resp)))
    }
}

extern "C" fn encode_share_mdata_cb(
    user_data: *mut c_void,
    result: FfiResult,
    _msg: *const c_char,
) {
    let ret = if result.error_code == 0 {
        Ok(())
    } else {
        let c_str = unsafe { CStr::from_ptr(result.description) };
        let msg = match c_str.to_str() {
            Ok(s) => s.to_owned(),
            Err(e) => {
                format!(
                    "utf8-error in error string: {} {:?}",
                    e,
                    c_str.to_string_lossy()
                )
            }
        };
        Err((result.error_code, msg))
    };
    unsafe {
        test_utils::send_via_user_data::<Result<(), (i32, String)>>(user_data, ret);
    }
}

type ChannelType = Result<(IpcMsg, Option<Vec<Vec<u8>>>), (i32, Option<IpcMsg>)>;

fn sender_as_user_data(tx: &Sender<ChannelType>) -> *mut c_void {
    test_utils::sender_as_user_data(tx)
}

unsafe fn send_via_user_data(userdata: *mut c_void, value: ChannelType) {
    test_utils::send_via_user_data(userdata, value)
}
