// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

//! FFI

#![allow(unsafe_code)]

/// Access container.
pub mod access_container;
/// Cipher options operations.
pub mod cipher_opt;
/// Crypto-related routines.
pub mod crypto;
/// Errors
pub mod errors;
/// Low level manipulation of `ImmutableData`.
pub mod immutable_data;
/// IPC utilities.
pub mod ipc;
/// Logging operations.
pub mod logging;
/// `MDataInfo` operations.
pub mod mdata_info;
/// Low level manipulation of `MutableData`.
pub mod mutable_data;
/// NFS API.
pub mod nfs;
/// `ObjectCache` handles.
pub mod object_cache;
/// Testing utilities.
#[cfg(any(test, feature = "testing"))]
pub mod test_utils;

mod helper;
#[cfg(test)]
mod tests;

use super::ffi::errors::{Error, Result};
use super::App;
use bincode::deserialize;
use ffi_utils::{catch_unwind_cb, FfiResult, OpaqueCtx, ReprC, FFI_RESULT_OK};
use safe_core::ffi::ipc::resp::AuthGranted;
use safe_core::ipc::{AuthGranted as NativeAuthGranted, BootstrapConfig};
use safe_core::{self, config_handler, Client};
use std::ffi::{CStr, CString, OsStr};
use std::os::raw::{c_char, c_void};
use std::slice;

/// Create unregistered app.
/// The `user_data` parameter corresponds to the first parameter of the
/// `o_cb` and `o_disconnect_notifier_cb` callbacks.
#[no_mangle]
pub unsafe extern "C" fn app_unregistered(
    bootstrap_config: *const u8,
    bootstrap_config_len: usize,
    user_data: *mut c_void,
    o_disconnect_notifier_cb: extern "C" fn(user_data: *mut c_void),
    o_cb: extern "C" fn(user_data: *mut c_void, result: *const FfiResult, app: *mut App),
) {
    catch_unwind_cb(user_data, o_cb, || -> Result<_> {
        let user_data = OpaqueCtx(user_data);

        let config = if bootstrap_config_len == 0 || bootstrap_config.is_null() {
            None
        } else {
            let config_serialised = slice::from_raw_parts(bootstrap_config, bootstrap_config_len);
            Some(deserialize::<BootstrapConfig>(config_serialised)?)
        };

        let app = App::unregistered(move || o_disconnect_notifier_cb(user_data.0), config)?;

        o_cb(user_data.0, FFI_RESULT_OK, Box::into_raw(Box::new(app)));

        Ok(())
    })
}

/// Create a registered app.
/// The `user_data` parameter corresponds to the first parameter of the
/// `o_cb` and `o_disconnect_notifier_cb` callbacks.
#[no_mangle]
pub unsafe extern "C" fn app_registered(
    app_id: *const c_char,
    auth_granted: *const AuthGranted,
    user_data: *mut c_void,
    o_disconnect_notifier_cb: extern "C" fn(user_data: *mut c_void),
    o_cb: extern "C" fn(user_data: *mut c_void, result: *const FfiResult, app: *mut App),
) {
    catch_unwind_cb(user_data, o_cb, || -> Result<_> {
        let user_data = OpaqueCtx(user_data);
        let app_id = String::clone_from_repr_c(app_id)?;
        let auth_granted = NativeAuthGranted::clone_from_repr_c(auth_granted)?;

        let app = App::registered(app_id, auth_granted, move || {
            o_disconnect_notifier_cb(user_data.0)
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
    o_cb: extern "C" fn(user_data: *mut c_void, result: *const FfiResult),
) {
    catch_unwind_cb(user_data, o_cb, || -> Result<_> {
        let user_data = OpaqueCtx(user_data);
        (*app)
            .send(move |client, _| {
                try_cb!(
                    client.restart_network().map_err(Error::from),
                    user_data.0,
                    o_cb
                );
                o_cb(user_data.0, FFI_RESULT_OK);
                None
            })
            .map_err(Error::from)
    })
}

/// Sets the path from which the `safe_core.config` file will be read.
#[no_mangle]
pub unsafe extern "C" fn app_set_config_dir_path(
    new_path: *const c_char,
    user_data: *mut c_void,
    o_cb: extern "C" fn(user_data: *mut c_void, result: *const FfiResult),
) {
    catch_unwind_cb(user_data, o_cb, || -> Result<_> {
        let new_path = CStr::from_ptr(new_path).to_str()?;
        config_handler::set_config_dir_path(OsStr::new(new_path));
        o_cb(user_data, FFI_RESULT_OK);
        Ok(())
    });
}

/// Discard and clean up the previously allocated app instance.
/// Use this only if the app is obtained from one of the auth
/// functions in this crate. Using `app` after a call to this
/// function is undefined behaviour.
#[no_mangle]
pub unsafe extern "C" fn app_free(app: *mut App) {
    let _ = Box::from_raw(app);
}

/// Resets the object cache. Removes all objects currently in the object cache
/// and invalidates all existing object handles.
#[no_mangle]
pub unsafe extern "C" fn app_reset_object_cache(
    app: *mut App,
    user_data: *mut c_void,
    o_cb: extern "C" fn(user_data: *mut c_void, result: *const FfiResult),
) {
    catch_unwind_cb(user_data, o_cb, || -> Result<_> {
        let user_data = OpaqueCtx(user_data);
        (*app)
            .send(move |_, context| {
                context.object_cache().reset();
                o_cb(user_data.0, FFI_RESULT_OK);
                None
            })
            .map_err(Error::from)
    })
}

/// Returns the name of the app's container.
#[no_mangle]
pub unsafe extern "C" fn app_container_name(
    app_id: *const c_char,
    user_data: *mut c_void,
    o_cb: extern "C" fn(
        user_data: *mut c_void,
        result: *const FfiResult,
        container_name: *const c_char,
    ),
) {
    catch_unwind_cb(user_data, o_cb, || -> Result<_> {
        let name = CString::new(safe_core::app_container_name(
            CStr::from_ptr(app_id).to_str()?,
        ))?;
        o_cb(user_data, FFI_RESULT_OK, name.as_ptr());
        Ok(())
    })
}

/// Returns true if this crate was compiled against mock-routing.
#[no_mangle]
pub extern "C" fn app_is_mock() -> bool {
    cfg!(feature = "mock-network")
}
