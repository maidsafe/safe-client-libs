// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

mod nfs;

use super::*;
use crate::ffi::app_is_mock;
use crate::ffi::ipc::decode_ipc_msg;
use crate::test_utils::create_app;
use crate::test_utils::gen_app_exchange_info;
use ffi_utils::test_utils::call_1;
use routing::ImmutableData;
use safe_authenticator::ffi::ipc::encode_auth_resp;
use safe_authenticator::test_utils;
use safe_core::ffi::ipc::resp::AuthGranted as FfiAuthGranted;
use safe_core::ffi::AccountInfo;
use safe_core::ipc::req::{AuthReq, ContainerPermissions};
use safe_core::ipc::{gen_req_id, AuthGranted, Permission};
use safe_core::Client;
use std::collections::HashMap;
use App;

// Creates a containers request asking for "documents with permission to
// insert", and "videos with all the permissions possible".
fn create_containers_req() -> HashMap<String, ContainerPermissions> {
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
// Test mock detection when compiled against mock-routing.
#[test]
#[cfg(feature = "mock-network")]
fn test_mock_build() {
    assert_eq!(app_is_mock(), true);
}

// Test mock detection when not compiled against mock-routing.
#[test]
#[cfg(not(feature = "mock-network"))]
fn test_not_mock_build() {
    assert_eq!(app_is_mock(), false);
}

// Test account usage statistics before and after a mutation.
#[test]
fn account_info() {
    let app = create_app();
    let app = Box::into_raw(Box::new(app));

    let orig_stats: AccountInfo =
        unsafe { unwrap!(call_1(|ud, cb| app_account_info(app, ud, cb))) };
    assert!(orig_stats.mutations_available > 0);

    unsafe {
        unwrap!((*app).send(move |client, _| client
            .put_idata(ImmutableData::new(vec![1, 2, 3]))
            .map_err(move |_| ())
            .into_box()
            .into()));
    }

    let stats: AccountInfo = unsafe { unwrap!(call_1(|ud, cb| app_account_info(app, ud, cb))) };
    assert_eq!(stats.mutations_done, orig_stats.mutations_done + 1);
    assert_eq!(
        stats.mutations_available,
        orig_stats.mutations_available - 1
    );

    unsafe { app_free(app) };
}

// Test disconnection and reconnection with apps.
#[cfg(all(test, feature = "mock-network"))]
#[test]
fn network_status_callback() {
    use ffi_utils::test_utils::{call_0, call_1_with_custom, send_via_user_data_custom, UserData};
    use maidsafe_utilities::serialisation::serialise;
    use safe_core::ipc::BootstrapConfig;
    use std::os::raw::c_void;
    use std::sync::mpsc;
    use std::sync::mpsc::{Receiver, Sender};
    use std::time::Duration;

    {
        let (tx, rx): (Sender<()>, Receiver<()>) = mpsc::channel();

        let bootstrap_cfg = unwrap!(serialise(&BootstrapConfig::default()));
        let mut custom_ud: UserData = Default::default();
        let ptr: *const _ = &tx;
        custom_ud.custom = ptr as *mut c_void;

        let app: *mut App = unsafe {
            unwrap!(call_1_with_custom(&mut custom_ud, |ud, cb| {
                app_unregistered(
                    bootstrap_cfg.as_ptr(),
                    bootstrap_cfg.len(),
                    ud,
                    disconnect_cb,
                    cb,
                )
            }))
        };

        unsafe {
            unwrap!((*app).send(move |client, _| {
                client.simulate_network_disconnect();
                None
            }));
        }

        // disconnect_cb should be called.
        unwrap!(rx.recv_timeout(Duration::from_secs(15)));

        // Reconnect with the network
        unsafe { unwrap!(call_0(|ud, cb| app_reconnect(app, ud, cb))) };

        // This should time out.
        let result = rx.recv_timeout(Duration::from_secs(1));
        match result {
            Err(_) => (),
            _ => panic!("Disconnect callback was called"),
        }

        // The reconnection should be fine if we're already connected.
        unsafe { unwrap!(call_0(|ud, cb| app_reconnect(app, ud, cb))) };

        // disconnect_cb should be called.
        unwrap!(rx.recv_timeout(Duration::from_secs(15)));

        // This should time out.
        let result = rx.recv_timeout(Duration::from_secs(1));
        match result {
            Err(_) => (),
            _ => panic!("Disconnect callback was called"),
        }

        unsafe { app_free(app) };
    }

    extern "C" fn disconnect_cb(user_data: *mut c_void) {
        unsafe {
            send_via_user_data_custom(user_data, ());
        }
    }
}

// Test getting the app's container name.
#[test]
fn test_app_container_name() {
    use safe_core;
    use std::ffi::CString;

    let auth = test_utils::create_account_and_login();

    let app_info = gen_app_exchange_info();
    let app_id = app_info.id.clone();

    let auth_granted = unwrap!(test_utils::register_app(
        &auth,
        &AuthReq {
            app: app_info,
            app_container: true,
            containers: HashMap::new(),
        },
    ));

    let _app = unwrap!(App::registered(app_id.clone(), auth_granted, || ()));

    let name: String = unsafe {
        unwrap!(call_1(|ud, cb| app_container_name(
            unwrap!(CString::new(app_id.clone())).as_ptr(),
            ud,
            cb
        )))
    };
    assert_eq!(name, safe_core::app_container_name(&app_id));
}

// Test app authentication using only FFI.
#[test]
fn app_authentication() {
    let auth = test_utils::create_account_and_login();

    let app_exchange_info = test_utils::rand_app();
    let app_id = app_exchange_info.id.clone();

    let containers = create_containers_req();
    let auth_req = AuthReq {
        app: app_exchange_info.clone(),
        app_container: true,
        containers,
    };
    let auth_req = unwrap!(auth_req.into_repr_c());

    let req_id = gen_req_id();
    let encoded: String = unsafe {
        unwrap!(call_1(|ud, cb| encode_auth_resp(
            &auth, &auth_req, req_id, true, ud, cb
        )))
    };
    let encoded = unwrap!(CString::new(encoded));

    let mut context = Context {
        unexpected_cb: false,
        req_id: 0,
        auth_granted: None,
    };

    let context = unsafe {
        extern "C" fn auth_cb(ctx: *mut c_void, req_id: u32, auth_granted: *const FfiAuthGranted) {
            unsafe {
                let auth_granted = unwrap!(AuthGranted::clone_from_repr_c(auth_granted));

                let ctx = ctx as *mut Context;
                (*ctx).req_id = req_id;
                (*ctx).auth_granted = Some(auth_granted);
            }
        }

        extern "C" fn containers_cb(ctx: *mut c_void, _req_id: u32) {
            unsafe {
                let ctx = ctx as *mut Context;
                (*ctx).unexpected_cb = true;
            }
        }

        extern "C" fn share_mdata_cb(ctx: *mut c_void, _req_id: u32) {
            unsafe {
                let ctx = ctx as *mut Context;
                (*ctx).unexpected_cb = true;
            }
        }

        extern "C" fn revoked_cb(ctx: *mut c_void) {
            unsafe {
                let ctx = ctx as *mut Context;
                (*ctx).unexpected_cb = true;
            }
        }

        extern "C" fn unregistered_cb(
            ctx: *mut c_void,
            _req_id: u32,
            _bootstrap_cfg: *const u8,
            _bootstrap_cfg_len: usize,
        ) {
            unsafe {
                let ctx = ctx as *mut Context;
                (*ctx).unexpected_cb = true;
            }
        }

        let context_ptr: *mut Context = &mut context;

        decode_ipc_msg(
            encoded.as_ptr(),
            context_ptr as *mut c_void,
            auth_cb,
            unregistered_cb,
            containers_cb,
            share_mdata_cb,
            revoked_cb,
            err_cb,
        );

        context
    };

    assert!(!context.unexpected_cb);

    let auth_granted = unwrap!(context.auth_granted);

    let mut expected = create_containers_req();
    let _ = expected.insert(
        safe_core::app_container_name(&app_id),
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
}

struct Context {
    unexpected_cb: bool,
    req_id: u32,
    auth_granted: Option<AuthGranted>,
}

extern "C" fn err_cb(ctx: *mut c_void, _res: *const FfiResult, _req_id: u32) {
    unsafe {
        let ctx = ctx as *mut Context;
        (*ctx).unexpected_cb = true;
    }
}
