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
use errors::{AuthError, ERR_UNKNOWN_APP};
use ffi::apps::*;
use ffi_utils::{FfiResult, ReprC, StringError, base64_encode, from_c_str};
use ffi_utils::test_utils::{call_1, call_vec, send_via_user_data, sender_as_user_data};
use futures::{Future, future};
use ipc::{authenticator_revoke_app, encode_auth_resp, encode_containers_resp,
          encode_unregistered_resp, get_config};
use maidsafe_utilities::serialisation::deserialise;
use routing::User;
use safe_core::{CoreError, MDataInfo, mdata_info};
use safe_core::ipc::{self, AuthReq, BootstrapConfig, ContainersReq, IpcError, IpcMsg, IpcReq,
                     IpcResp, Permission};
use safe_core::ipc::req::ffi::AppExchangeInfo as FfiAppExchangeInfo;
use safe_core::ipc::req::ffi::AuthReq as FfiAuthReq;
use safe_core::ipc::req::ffi::ContainersReq as FfiContainersReq;
use safe_core::nfs::{DEFAULT_PRIVATE_DIRS, DEFAULT_PUBLIC_DIRS, File, NfsError, file_helper};
use std::collections::{BTreeSet, HashMap};
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_void};
use std::sync::mpsc;
use std::time::Duration;
use test_utils::{access_container, compare_access_container_entries, create_account_and_login,
                 rand_app, register_app, run, try_access_container, try_run};
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
        .map(|(_, value)| unwrap!(deserialise::<MDataInfo>(&value.content)))
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
    let config = unwrap!(entries.get(&b"authenticator-config"[..]));
    assert!(config.content.is_empty());

    let ac = unwrap!(entries.get(&b"access-container"[..]));
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

// Test app authentication.
#[test]
fn app_authentication() {
    let authenticator = create_account_and_login();

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

    let (received_req_id, received_auth_req) = match unwrap!(decode_ipc_msg(&authenticator,
                                                                            &encoded_msg)) {
        IpcMsg::Req {
            req_id,
            req: IpcReq::Auth(req),
        } => (req_id, req),
        x => panic!("Unexpected {:?}", x),
    };

    assert_eq!(received_req_id, req_id);
    assert_eq!(received_auth_req, auth_req);

    let encoded_auth_resp: String = unsafe {
        unwrap!(call_1(|ud, cb| {
            let auth_req = unwrap!(auth_req.into_repr_c());
            encode_auth_resp(&authenticator,
                             &auth_req,
                             req_id,
                             true, // is_granted
                             ud,
                             cb)
        }))
    };

    let base64_app_id = base64_encode(app_id.as_bytes());
    assert!(encoded_auth_resp.starts_with(&format!("safe-{}", base64_app_id)));

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
    let _ = expected.insert(format!("apps/{}", app_id),
                            btree_set![Permission::Read,
                                       Permission::Insert,
                                       Permission::Update,
                                       Permission::Delete,
                                       Permission::ManagePermissions]);

    let mut access_container =
        access_container(&authenticator, app_id.clone(), auth_granted.clone());
    assert_eq!(access_container.len(), 3);

    let app_keys = auth_granted.app_keys;
    let app_sign_pk = app_keys.sign_pk;

    compare_access_container_entries(&authenticator,
                                     app_sign_pk,
                                     access_container.clone(),
                                     expected);

    let (app_dir_info, _) = unwrap!(access_container.remove(&format!("apps/{}", app_id)));

    // Check the app info is present in the config file.
    let config = run(&authenticator,
                     |client| get_config(client).map(|(_, config)| config));

    let app_config_key = sha3_256(app_id.as_bytes());
    let app_info = unwrap!(config.get(&app_config_key));

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
#[test]
fn unregistered_authentication() {
    let authenticator = create_account_and_login();

    let req_id = ipc::gen_req_id();
    let msg = IpcMsg::Req {
        req_id: req_id,
        req: IpcReq::Unregistered,
    };
    let encoded_msg = unwrap!(ipc::encode_msg(&msg, "safe-auth"));

    let received_req_id = match unwrap!(decode_ipc_msg(&authenticator, &encoded_msg)) {
        IpcMsg::Req {
            req_id,
            req: IpcReq::Unregistered,
        } => req_id,
        x => panic!("Unexpected {:?}", x),
    };

    assert_eq!(received_req_id, req_id);

    let encoded_resp: String = unsafe {
        unwrap!(call_1(|ud, cb| {
                           encode_unregistered_resp(&authenticator,
                                                    req_id,
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
}

#[test]
fn authenticated_app_cannot_be_authenticated_again() {
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
        IpcMsg::Req { req: IpcReq::Auth(_), .. } => (),
        x => panic!("Unexpected {:?}", x),
    };

    let _resp: String = unsafe {
        unwrap!(call_1(|ud, cb| {
            let auth_req = unwrap!(auth_req.clone().into_repr_c());
            encode_auth_resp(&authenticator,
                             &auth_req,
                             req_id,
                             true, // is_granted
                             ud,
                             cb)
        }))
    };

    // Second authentication should also return the correct result.
    let req_id = ipc::gen_req_id();
    let msg = IpcMsg::Req {
        req_id: req_id,
        req: IpcReq::Auth(auth_req),
    };
    let encoded_msg = unwrap!(ipc::encode_msg(&msg, "safe-auth"));

    match decode_ipc_msg(&authenticator, &encoded_msg) {
        Ok(IpcMsg::Req { req: IpcReq::Auth(_), .. }) => (),
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
            encode_containers_resp(&authenticator,
                                   &cont_req,
                                   req_id,
                                   true, // is_granted
                                   ud,
                                   cb)
        }))
    };

    // Check the string to contain "safe-<app-id-base64>:payload" where payload is
    // IpcMsg::Resp(IpcResp::Auth(Containers(Ok())))".
    assert!(encoded_containers_resp.starts_with(&format!("safe-{}", base64_app_id)));

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
    unwrap!(create_file(&authenticator, videos_md1.clone(), "1.mp4", vec![1; 10]));

    let mut ac_entries = access_container(&authenticator, app_id2.clone(), auth_granted2.clone());
    let (videos_md2, _) = unwrap!(ac_entries.remove("_videos"));
    unwrap!(create_file(&authenticator, videos_md2.clone(), "2.mp4", vec![1; 10]));

    let app_container_name = format!("apps/{}", app_id2.clone());
    let (app_container_md, _) = unwrap!(ac_entries.remove(&app_container_name));
    unwrap!(create_file(&authenticator,
                        app_container_md.clone(),
                        "3.mp4",
                        vec![1; 10]));

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
        client
            .list_mdata_permissions(name, tag)
            .map_err(From::from)
    });
    assert!(!perms.contains_key(&User::Key(auth_granted1.app_keys.sign_pk)));
    assert!(perms.contains_key(&User::Key(auth_granted2.app_keys.sign_pk)));

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

    assert_eq!(count_mdata_entries(&authenticator, app_container_md.clone()),
               2);
    let _ = unwrap!(fetch_file(&authenticator, app_container_md.clone(), "3.mp4"));

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

    unsafe fn clone_from_repr_c(app_info: *const FfiAppExchangeInfo)
                                -> Result<RevokedAppId, StringError> {
        Ok(RevokedAppId(from_c_str((*app_info).id)?))
    }
}

#[test]
fn lists_of_registered_and_revoked_apps() {
    let authenticator = create_account_and_login();

    // Initially, there are no registered or revoked apps.
    let registered: Vec<RegisteredAppId> = unsafe {
        unwrap!(call_vec(|ud, cb| authenticator_registered_apps(&authenticator, ud, cb)))
    };

    let revoked: Vec<RevokedAppId> =
        unsafe { unwrap!(call_vec(|ud, cb| authenticator_revoked_apps(&authenticator, ud, cb))) };

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
        unwrap!(call_vec(|ud, cb| authenticator_registered_apps(&authenticator, ud, cb)))
    };

    let revoked: Vec<RevokedAppId> =
        unsafe { unwrap!(call_vec(|ud, cb| authenticator_revoked_apps(&authenticator, ud, cb))) };

    assert_eq!(registered.len(), 2);
    assert!(revoked.is_empty());

    // Revoke the first app.
    revoke(&authenticator, &auth_req1.app.id);

    // There is now one registered and one revoked app.
    let registered: Vec<RegisteredAppId> = unsafe {
        unwrap!(call_vec(|ud, cb| authenticator_registered_apps(&authenticator, ud, cb)))
    };

    let revoked: Vec<RevokedAppId> =
        unsafe { unwrap!(call_vec(|ud, cb| authenticator_revoked_apps(&authenticator, ud, cb))) };

    assert_eq!(registered.len(), 1);
    assert_eq!(revoked.len(), 1);

    // Re-register the first app - now there must be 2 registered apps again
    let _ = unwrap!(register_app(&authenticator, &auth_req1));

    let registered: Vec<RegisteredAppId> = unsafe {
        unwrap!(call_vec(|ud, cb| authenticator_registered_apps(&authenticator, ud, cb)))
    };
    let revoked: Vec<RevokedAppId> =
        unsafe { unwrap!(call_vec(|ud, cb| authenticator_revoked_apps(&authenticator, ud, cb))) };

    assert_eq!(registered.len(), 2);
    assert_eq!(revoked.len(), 0);
}

// Create file in the given container, with the given name and content.
fn create_file<T: Into<String>>(authenticator: &Authenticator,
                                container_info: MDataInfo,
                                name: T,
                                content: Vec<u8>)
                                -> Result<(), AuthError> {
    let name = name.into();
    try_run(authenticator, |client| {
        file_helper::create(client.clone(), container_info, name, vec![])
            .and_then(move |writer| {
                          writer
                              .write(&content)
                              .and_then(move |_| writer.close())
                              .map(|_| ())
                      })
            .map_err(From::from)
    })
}

fn fetch_file<T: Into<String>>(authenticator: &Authenticator,
                               container_info: MDataInfo,
                               name: T)
                               -> Result<File, AuthError> {
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

fn revoke(authenticator: &Authenticator, app_id: &str) {
    let base64_app_id = base64_encode(app_id.as_bytes());

    let revoke_resp: String = unsafe {
        let app_id = unwrap!(CString::new(app_id));
        unwrap!(call_1(|ud, cb| authenticator_revoke_app(authenticator, app_id.as_ptr(), ud, cb)))
    };

    // Assert the callback is called with error-code 0 and FfiString contains
    // "safe_<app-id-b64>:payload" where payload is b64 encoded IpcMsg::Revoked.
    assert!(revoke_resp.starts_with(&format!("safe-{}", base64_app_id)));

    match ipc::decode_msg(&revoke_resp) {
        Ok(IpcMsg::Revoked { .. }) => (),
        x => panic!("Unexpected {:?}", x),
    };
}

// Creates a containers request asking for "documents with permission to
// insert", and "videos with all the permissions possible",
fn create_containers_req() -> HashMap<String, BTreeSet<Permission>> {
    let mut containers = HashMap::new();
    let _ = containers.insert("_documents".to_owned(), btree_set![Permission::Insert]);
    let _ = containers.insert("_videos".to_owned(),
                              btree_set![Permission::Read,
                                         Permission::Insert,
                                         Permission::Update,
                                         Permission::Delete,
                                         Permission::ManagePermissions]);
    containers
}

// Helper to decode IpcMsg.
// TODO: there should be a public function with a signature like this, and the
//       FFI function `ipc::decode_ipc_msg` should be only wrapper over it.
fn decode_ipc_msg(authenticator: &Authenticator,
                  msg: &str)
                  -> Result<IpcMsg, (i32, Option<IpcMsg>)> {
    let (tx, rx) = mpsc::channel::<Result<IpcMsg, (i32, Option<IpcMsg>)>>();

    extern "C" fn auth_cb(user_data: *mut c_void, req_id: u32, req: *const FfiAuthReq) {
        unsafe {
            let req = match AuthReq::clone_from_repr_c(req) {
                Ok(req) => req,
                Err(_) => {
                    return send_via_user_data(user_data,
                                              Err::<IpcMsg, (i32, Option<IpcMsg>)>((-2, None)))
                }
            };

            let msg = IpcMsg::Req {
                req_id: req_id,
                req: IpcReq::Auth(req),
            };

            send_via_user_data(user_data, Ok::<_, (i32, Option<IpcMsg>)>(msg))
        }
    }

    extern "C" fn containers_cb(user_data: *mut c_void,
                                req_id: u32,
                                req: *const FfiContainersReq) {
        unsafe {
            let req = match ContainersReq::clone_from_repr_c(req) {
                Ok(req) => req,
                Err(_) => {
                    return send_via_user_data(user_data,
                                              Err::<IpcMsg, (i32, Option<IpcMsg>)>((-2, None)))
                }
            };

            let msg = IpcMsg::Req {
                req_id: req_id,
                req: IpcReq::Containers(req),
            };

            send_via_user_data(user_data, Ok::<_, (i32, Option<IpcMsg>)>(msg))
        }
    }

    extern "C" fn unregistered_cb(user_data: *mut c_void, req_id: u32) {
        unsafe {
            let msg = IpcMsg::Req {
                req_id: req_id,
                req: IpcReq::Unregistered,
            };

            send_via_user_data(user_data, Ok::<_, (i32, Option<IpcMsg>)>(msg))
        }
    }

    #[cfg_attr(feature="cargo-clippy", allow(needless_pass_by_value))]
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

            send_via_user_data(user_data, Err::<IpcMsg, _>((res.error_code, ipc_resp)))
        }
    }

    let ffi_msg = unwrap!(CString::new(msg));

    unsafe {
        use ipc::auth_decode_ipc_msg;
        auth_decode_ipc_msg(authenticator,
                            ffi_msg.as_ptr(),
                            sender_as_user_data(&tx),
                            auth_cb,
                            unregistered_cb,
                            containers_cb,
                            err_cb);
    };

    match rx.recv_timeout(Duration::from_secs(15)) {
        Ok(r) => r,
        Err(_) => Err((-1, None)),
    }
}
