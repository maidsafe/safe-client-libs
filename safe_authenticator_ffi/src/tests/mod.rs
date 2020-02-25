// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

#![allow(unsafe_code)]

mod revocation;
mod share_mdata;

use crate::ffi::apps::AppPermissions as FfiAppPermissions;
use crate::ffi::apps::*;
use crate::ffi::errors::{ERR_INVALID_MSG, ERR_OPERATION_FORBIDDEN, ERR_UNKNOWN_APP};
use crate::ffi::ipc::{
    auth_revoke_app, encode_auth_resp, encode_containers_resp, encode_unregistered_resp,
};
use crate::test_utils::{auth_decode_ipc_msg_helper, err_cb, unregistered_cb};
use ffi_utils::test_utils::{call_1, call_vec, sender_as_user_data};
use ffi_utils::{ReprC, StringError};
use futures::Future;
use safe_authenticator::config;
use safe_authenticator::errors::AuthError;
use safe_authenticator::std_dirs::{DEFAULT_PRIVATE_DIRS, DEFAULT_PUBLIC_DIRS};
use safe_authenticator::test_utils::{
    self, create_account_and_login, rand_app, register_app, ChannelType,
};
use safe_authenticator::{app_container, run};
use safe_core::btree_set;
use safe_core::config_handler::Config;
use safe_core::ffi::error_codes::ERR_NO_SUCH_CONTAINER;
use safe_core::ffi::ipc::req::AppExchangeInfo as FfiAppExchangeInfo;
use safe_core::ipc::{self, AuthReq, ContainersReq, IpcError, IpcMsg, IpcReq, IpcResp, Permission};
use safe_core::{app_container_name, AuthActions};
use safe_nd::AppPermissions;
use std::collections::HashMap;
use std::ffi::CString;
use std::sync::mpsc;
use std::time::Duration;
use tiny_keccak::sha3_256;
use unwrap::unwrap;

// Test app authentication.
#[test]
fn app_authentication() {
    let authenticator = create_account_and_login();

    // Try to send IpcResp::Auth - it should fail
    let msg = IpcMsg::Revoked {
        app_id: "hello".to_string(),
    };
    let encoded_msg = unwrap!(ipc::encode_msg(&msg));
    match auth_decode_ipc_msg_helper(&authenticator, &encoded_msg) {
        Err((ERR_INVALID_MSG, None)) => (),
        x => panic!("Unexpected {:?}", x),
    }

    // Try to send IpcReq::Auth - it should pass
    let req_id = ipc::gen_req_id();
    let app_exchange_info = rand_app();
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
        request: IpcReq::Auth(auth_req.clone()),
    };

    let encoded_msg = unwrap!(ipc::encode_msg(&msg));

    let (received_req_id, received_auth_req) =
        match unwrap!(auth_decode_ipc_msg_helper(&authenticator, &encoded_msg)) {
            (
                IpcMsg::Req {
                    req_id,
                    request: IpcReq::Auth(req),
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
            response: IpcResp::Auth(Ok(auth_granted)),
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
    let app_pk = app_keys.public_key();

    test_utils::compare_access_container_entries(
        &authenticator,
        app_pk,
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

    assert!(auth_keys.contains_key(&app_pk));
}

// Try to authenticate with invalid container names.
#[test]
fn invalid_container_authentication() {
    let authenticator = create_account_and_login();
    let req_id = ipc::gen_req_id();
    let app_exchange_info = rand_app();

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
        app: app_exchange_info,
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
        Err(error) if error == ERR_NO_SUCH_CONTAINER => (),
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
        request: IpcReq::Auth(AuthReq {
            app: rand_app(),
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
        request: IpcReq::Unregistered(test_data.clone()),
    };
    let encoded_msg = unwrap!(ipc::encode_msg(&msg));

    let (received_req_id, received_data) = match unwrap!(unregistered_decode_ipc_msg(&encoded_msg))
    {
        (
            IpcMsg::Req {
                req_id,
                request: IpcReq::Unregistered(extra_data),
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
            response: IpcResp::Unregistered(Ok(bootstrap_cfg)),
        } => {
            assert_eq!(received_req_id, req_id);
            bootstrap_cfg
        }
        x => panic!("Unexpected {:?}", x),
    };

    assert_eq!(bootstrap_cfg, Config::new().quic_p2p.hard_coded_contacts);

    // Try to send IpcReq::Unregistered to logged in authenticator
    let authenticator = create_account_and_login();

    let (received_req_id, received_data) =
        match unwrap!(auth_decode_ipc_msg_helper(&authenticator, &encoded_msg)) {
            (
                IpcMsg::Req {
                    req_id,
                    request: IpcReq::Unregistered(extra_data),
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
    let authenticator = create_account_and_login();

    let auth_req = AuthReq {
        app: rand_app(),
        app_container: false,
        app_permissions: Default::default(),
        containers: Default::default(),
    };

    let req_id = ipc::gen_req_id();
    let msg = IpcMsg::Req {
        req_id,
        request: IpcReq::Auth(auth_req.clone()),
    };
    let encoded_msg = unwrap!(ipc::encode_msg(&msg));

    match unwrap!(auth_decode_ipc_msg_helper(&authenticator, &encoded_msg)) {
        (
            IpcMsg::Req {
                request: IpcReq::Auth(_),
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
        request: IpcReq::Auth(auth_req),
    };
    let encoded_msg = unwrap!(ipc::encode_msg(&msg));

    match unwrap!(auth_decode_ipc_msg_helper(&authenticator, &encoded_msg)) {
        (
            IpcMsg::Req {
                request: IpcReq::Auth(_),
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
    let authenticator = create_account_and_login();

    // Create IpcMsg::Req { req: IpcReq::Containers } for a random App (random id, name, vendor etc)
    let req_id = ipc::gen_req_id();
    let msg = IpcMsg::Req {
        req_id,
        request: IpcReq::Containers(ContainersReq {
            app: rand_app(),
            containers: utils::create_containers_req(),
        }),
    };

    // Serialise the request as base64 payload in "safe-auth:payload"
    let encoded_msg = unwrap!(ipc::encode_msg(&msg));

    // Invoke Authenticator's decode_ipc_msg and expect to get Failure back via
    // callback with error code for IpcError::UnknownApp
    // Check that the returned string is "safe_<app-id-base64>:payload" where payload is
    // IpcMsg::Resp(IpcResp::Auth(Err(UnknownApp)))"
    match auth_decode_ipc_msg_helper(&authenticator, &encoded_msg) {
        Err((
            code,
            Some(IpcMsg::Resp {
                response: IpcResp::Auth(Err(IpcError::UnknownApp)),
                ..
            }),
        )) if code == ERR_UNKNOWN_APP => (),
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
        app_permissions: Default::default(),
        containers: utils::create_containers_req(),
    };
    let app_id = auth_req.app.id.clone();

    let auth_granted = unwrap!(register_app(&authenticator, &auth_req));

    // Give one Containers request to authenticator for the same app asking for "downloads with
    // permission to update only"
    let req_id = ipc::gen_req_id();
    let cont_req = ContainersReq {
        app: auth_req.app,
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
            response: IpcResp::Containers(Ok(())),
            ..
        }) => (),
        x => panic!("Unexpected {:?}", x),
    }

    // Using the access container from AuthGranted check if "app-id", "documents", "videos",
    // "downloads" are all mentioned and using MDataInfo for each check the permissions are
    // what had been asked for.
    let mut expected = utils::create_containers_req();
    let _ = expected.insert("_downloads".to_owned(), btree_set![Permission::Update]);

    let app_pk = auth_granted.app_keys.public_key();
    let access_container = test_utils::access_container(&authenticator, app_id, auth_granted);
    test_utils::compare_access_container_entries(
        &authenticator,
        app_pk,
        access_container,
        expected,
    );
}

struct RegisteredAppId {
    id: String,
    perms: FfiAppPermissions,
}

impl ReprC for RegisteredAppId {
    type C = *const RegisteredApp;
    type Error = StringError;

    unsafe fn clone_from_repr_c(repr_c: Self::C) -> Result<Self, Self::Error> {
        Ok(RegisteredAppId {
            id: String::clone_from_repr_c((*repr_c).app_info.id)?,
            perms: (*repr_c).app_permissions,
        })
    }
}

struct RevokedAppId(String);
impl ReprC for RevokedAppId {
    type C = *const FfiAppExchangeInfo;
    type Error = StringError;

    unsafe fn clone_from_repr_c(repr_c: Self::C) -> Result<Self, Self::Error> {
        Ok(RevokedAppId(String::clone_from_repr_c((*repr_c).id)?))
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
        app: rand_app(),
        app_container: false,
        app_permissions: Default::default(),
        containers: Default::default(),
    };

    let auth_req2 = AuthReq {
        app: rand_app(),
        app_container: false,
        app_permissions: Default::default(),
        containers: Default::default(),
    };

    let _ = unwrap!(register_app(&authenticator, &auth_req1));
    let _ = unwrap!(register_app(&authenticator, &auth_req2));

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
    let _ = unwrap!(register_app(&authenticator, &auth_req1));

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

// Test fetching of authenticated and registered apps.
#[test]
fn test_registered_apps() {
    let authenticator = create_account_and_login();

    // Permissions for App1
    let app1 = rand_app();
    let app1_id = app1.clone().id;
    let app1_perms = AppPermissions {
        transfer_coins: true,
        perform_mutations: false,
        get_balance: true,
    };

    let auth_req1 = AuthReq {
        app: app1,
        app_container: false,
        app_permissions: app1_perms,
        containers: Default::default(),
    };

    // Permissions for App2
    let app2_perms = AppPermissions {
        transfer_coins: false,
        perform_mutations: true,
        get_balance: false,
    };

    let auth_req2 = AuthReq {
        app: rand_app(),
        app_container: false,
        app_permissions: app2_perms,
        containers: Default::default(),
    };

    // Register both the apps.
    let _ = unwrap!(register_app(&authenticator, &auth_req1));
    let _ = unwrap!(register_app(&authenticator, &auth_req2));

    // There are now two registered apps.
    let registered: Vec<RegisteredAppId> = unsafe {
        unwrap!(call_vec(|ud, cb| auth_registered_apps(
            &authenticator,
            ud,
            cb
        ),))
    };
    assert_eq!(registered.len(), 2);

    for app in registered {
        if app1_id == app.id {
            // Assert App1's Permissions
            assert_eq!(app.perms.transfer_coins, app1_perms.transfer_coins);
            assert_eq!(app.perms.get_balance, app1_perms.get_balance);
            assert_eq!(app.perms.perform_mutations, app1_perms.perform_mutations);
        } else {
            // Assert App2's Permissions
            assert_eq!(app.perms.transfer_coins, app2_perms.transfer_coins);
            assert_eq!(app.perms.get_balance, app2_perms.get_balance);
            assert_eq!(app.perms.perform_mutations, app2_perms.perform_mutations);
        }
    }
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
            unregistered_cb,
            err_cb,
        );
    };

    match rx.recv_timeout(Duration::from_secs(15)) {
        Ok(r) => r,
        Err(_) => Err((-1, None)),
    }
}
