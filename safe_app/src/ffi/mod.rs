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

//! FFI

#![allow(unsafe_code)]

use super::App;
use super::errors::AppError;
use ffi_utils::{FFI_RESULT_OK, FfiResult, OpaqueCtx, ReprC, catch_unwind_cb, from_c_str};
use futures::Future;
use maidsafe_utilities::serialisation::deserialise;
use safe_core::{FutureExt, NetworkEvent};
use safe_core::ffi::AccountInfo as FfiAccountInfo;
use safe_core::ffi::ipc::resp::AuthGranted as FfiAuthGranted;
use safe_core::ipc::{AuthGranted, BootstrapConfig};
use std::os::raw::{c_char, c_void};
use std::slice;

/// Access container
pub mod access_container;
/// Cipher Options
pub mod cipher_opt;
/// Low level manipulation of `ImmutableData`
pub mod immutable_data;
/// IPC utilities
pub mod ipc;
/// Logging operations
pub mod logging;
/// `MDataInfo` operations
pub mod mdata_info;
/// Crypto-related routines
pub mod crypto;
/// Low level manipulation of `MutableData`
pub mod mutable_data;
/// NFS API
pub mod nfs;

mod helper;

/// Create unregistered app.
/// The `user_data` parameter corresponds to the first parameter of the
/// `o_cb` callback, while `network_cb_user_data` corresponds to the
/// first parameter of `o_network_observer_cb`.
#[no_mangle]
pub unsafe extern "C" fn app_unregistered(
    bootstrap_config_ptr: *const u8,
    bootstrap_config_len: usize,
    network_cb_user_data: *mut c_void,
    user_data: *mut c_void,
    o_network_observer_cb: extern "C" fn(*mut c_void, FfiResult, i32),
    o_cb: extern "C" fn(*mut c_void, FfiResult, *mut App),
) {
    catch_unwind_cb(user_data, o_cb, || -> Result<_, AppError> {
        let user_data = OpaqueCtx(user_data);
        let network_cb_user_data = OpaqueCtx(network_cb_user_data);

        let config = if bootstrap_config_len == 0 || bootstrap_config_ptr.is_null() {
            None
        } else {
            let config_serialised =
                slice::from_raw_parts(bootstrap_config_ptr, bootstrap_config_len);
            Some(deserialise::<BootstrapConfig>(config_serialised)?)
        };

        let app = App::unregistered(
            move |event| {
                call_network_observer(event, network_cb_user_data.0, o_network_observer_cb)
            },
            config,
        )?;

        o_cb(user_data.0, FFI_RESULT_OK, Box::into_raw(Box::new(app)));

        Ok(())
    })
}

/// Create a registered app.
/// The `user_data` parameter corresponds to the first parameter of the
/// `o_cb` callback, while `network_cb_user_data` corresponds to the
/// first parameter of `o_network_observer_cb`.
#[no_mangle]
pub unsafe extern "C" fn app_registered(
    app_id: *const c_char,
    auth_granted: *const FfiAuthGranted,
    network_cb_user_data: *mut c_void,
    user_data: *mut c_void,
    o_network_observer_cb: extern "C" fn(*mut c_void, FfiResult, i32),
    o_cb: extern "C" fn(*mut c_void, FfiResult, *mut App),
) {
    catch_unwind_cb(user_data, o_cb, || -> Result<_, AppError> {
        let user_data = OpaqueCtx(user_data);
        let network_cb_user_data = OpaqueCtx(network_cb_user_data);
        let app_id = from_c_str(app_id)?;
        let auth_granted = AuthGranted::clone_from_repr_c(auth_granted)?;

        let app = App::registered(app_id, auth_granted, move |event| {
            call_network_observer(event, network_cb_user_data.0, o_network_observer_cb)
        })?;

        o_cb(user_data.0, FFI_RESULT_OK, Box::into_raw(Box::new(app)));

        Ok(())
    })
}

/// Try to restore a failed connection with the network.
#[no_mangle]
pub unsafe extern "C" fn app_reconnect(
    app: *mut App,
    user_data: *mut c_void,
    o_cb: extern "C" fn(*mut c_void, FfiResult),
) {
    let user_data = OpaqueCtx(user_data);
    let res = (*app).send(move |client, _| {
        try_cb!(
            client.restart_routing().map_err(AppError::from),
            user_data.0,
            o_cb
        );
        o_cb(user_data.0, FFI_RESULT_OK);
        None
    });
    if let Err(..) = res {
        call_result_cb!(res, user_data, o_cb);
    }
}

/// Get the account usage statistics.
#[no_mangle]
pub unsafe extern "C" fn app_account_info(
    app: *mut App,
    user_data: *mut c_void,
    o_cb: extern "C" fn(*mut c_void, FfiResult, *const FfiAccountInfo),
) {
    let user_data = OpaqueCtx(user_data);
    let res = (*app).send(move |client, _| {
        client
            .get_account_info()
            .map(move |acc_info| {
                let ffi_acc = FfiAccountInfo {
                    mutations_done: acc_info.mutations_done,
                    mutations_available: acc_info.mutations_available,
                };
                o_cb(user_data.0, FFI_RESULT_OK, &ffi_acc);
            })
            .map_err(move |e| {
                call_result_cb!(Err::<(), _>(AppError::from(e)), user_data, o_cb);
            })
            .into_box()
            .into()
    });
    if let Err(..) = res {
        call_result_cb!(res, user_data, o_cb);
    }
}

/// Discard and clean up the previously allocated app instance.
/// Use this only if the app is obtained from one of the auth
/// functions in this crate. Using `app` after a call to this
/// function is undefined behaviour.
#[no_mangle]
pub unsafe extern "C" fn app_free(app: *mut App) {
    let _ = Box::from_raw(app);
}

unsafe fn call_network_observer(
    event: Result<NetworkEvent, AppError>,
    user_data: *mut c_void,
    o_cb: unsafe extern "C" fn(*mut c_void, FfiResult, i32),
) {
    match event {
        Ok(event) => o_cb(user_data, FFI_RESULT_OK, event.into()),
        res @ Err(..) => {
            call_result_cb!(res, user_data, o_cb);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ffi_utils::test_utils::call_1;
    use routing::ImmutableData;
    use safe_core::ffi::AccountInfo;
    use test_utils::create_app;

    #[test]
    fn account_info() {
        let app = create_app();
        let app = Box::into_raw(Box::new(app));

        let orig_stats: AccountInfo =
            unsafe { unwrap!(call_1(|ud, cb| app_account_info(app, ud, cb))) };
        assert!(orig_stats.mutations_available > 0);

        unsafe {
            unwrap!((*app).send(move |client, _| {
                client
                    .put_idata(ImmutableData::new(vec![1, 2, 3]))
                    .map_err(move |_| ())
                    .into_box()
                    .into()
            }));
        }

        let stats: AccountInfo = unsafe { unwrap!(call_1(|ud, cb| app_account_info(app, ud, cb))) };
        assert_eq!(stats.mutations_done, orig_stats.mutations_done + 1);
        assert_eq!(
            stats.mutations_available,
            orig_stats.mutations_available - 1
        );

        unsafe { app_free(app) };
    }

    #[cfg(all(test, feature = "use-mock-routing"))]
    #[test]
    fn network_status_callback() {
        use App;
        use ffi_utils::test_utils::{call_0, send_via_user_data, sender_as_user_data};
        use maidsafe_utilities::serialisation::serialise;
        use safe_core::NetworkEvent;
        use safe_core::ipc::BootstrapConfig;
        use std::os::raw::c_void;
        use std::sync::mpsc;
        use std::time::Duration;

        {
            let (tx, rx) = mpsc::channel();

            let bootstrap_cfg = unwrap!(serialise(&BootstrapConfig::default()));

            let app: *mut App = unsafe {
                unwrap!(call_1(|ud, cb| {
                    app_unregistered(
                        bootstrap_cfg.as_ptr(),
                        bootstrap_cfg.len(),
                        sender_as_user_data(&tx),
                        ud,
                        net_event_cb,
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

            let (error_code, event): (i32, i32) = unwrap!(rx.recv_timeout(Duration::from_secs(10)));
            assert_eq!(error_code, 0);

            let disconnected: i32 = NetworkEvent::Disconnected.into();
            assert_eq!(event, disconnected);

            // Reconnect with the network
            unsafe { unwrap!(call_0(|ud, cb| app_reconnect(app, ud, cb))) };

            let (err_code, event): (i32, i32) = unwrap!(rx.recv_timeout(Duration::from_secs(10)));
            assert_eq!(err_code, 0);

            let connected: i32 = NetworkEvent::Connected.into();
            assert_eq!(event, connected);

            // The reconnection should be fine if we're already connected.
            unsafe { unwrap!(call_0(|ud, cb| app_reconnect(app, ud, cb))) };

            let (err_code, event): (i32, i32) = unwrap!(rx.recv_timeout(Duration::from_secs(10)));
            assert_eq!(err_code, 0);
            assert_eq!(event, disconnected);

            let (err_code, event): (i32, i32) = unwrap!(rx.recv_timeout(Duration::from_secs(10)));
            assert_eq!(err_code, 0);
            assert_eq!(event, connected);

            unsafe { app_free(app) };
        }

        extern "C" fn net_event_cb(user_data: *mut c_void, res: FfiResult, event: i32) {
            unsafe {
                send_via_user_data(user_data, (res.error_code, event));
            }
        }
    }
}
