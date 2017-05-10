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
use ffi_utils::{FFI_RESULT_OK, FfiResult, OpaqueCtx, ReprC, catch_unwind_error_code, from_c_str};
use safe_core::NetworkEvent;
use safe_core::ipc::AuthGranted;
use safe_core::ipc::resp::ffi::AuthGranted as FfiAuthGranted;
use std::os::raw::{c_char, c_void};

/// Access container
pub mod access_container;
/// Cipher Options
pub mod cipher_opt;
/// Low level manipulation of `ImmutableData`
pub mod immutable_data;
/// IPC utilities
pub mod ipc;
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
#[no_mangle]
pub unsafe extern "C" fn app_unregistered(user_data: *mut c_void,
                                          network_observer_cb: unsafe extern "C" fn(*mut c_void,
                                                                                    FfiResult,
                                                                                    i32),
                                          o_app: *mut *mut App)
                                          -> i32 {
    catch_unwind_error_code(|| -> Result<_, AppError> {
        let user_data = OpaqueCtx(user_data);

        let app =
            App::unregistered(move |event| {
                                  call_network_observer(event, user_data.0, network_observer_cb)
                              })?;

        *o_app = Box::into_raw(Box::new(app));

        Ok(())
    })
}

/// Create registered app.
#[no_mangle]
pub unsafe extern "C" fn app_registered(app_id: *const c_char,
                                        auth_granted: *const FfiAuthGranted,
                                        user_data: *mut c_void,
                                        network_observer_cb: unsafe extern "C" fn(*mut c_void,
                                                                                  FfiResult,
                                                                                  i32),
                                        o_app: *mut *mut App)
                                        -> i32 {
    catch_unwind_error_code(|| -> Result<_, AppError> {
        let user_data = OpaqueCtx(user_data);
        let app_id = from_c_str(app_id)?;
        let auth_granted = AuthGranted::clone_from_repr_c(auth_granted)?;

        let app = App::registered(app_id, auth_granted, move |event| {
            call_network_observer(event, user_data.0, network_observer_cb)
        })?;

        *o_app = Box::into_raw(Box::new(app));

        Ok(())
    })
}

/// Discard and clean up the previously allocated app instance.
/// Use this only if the app is obtained from one of the auth
/// functions in this crate. Using `app` after a call to this
/// function is undefined behaviour.
#[no_mangle]
pub unsafe extern "C" fn app_free(app: *mut App) {
    let _ = Box::from_raw(app);
}

unsafe fn call_network_observer(event: Result<NetworkEvent, AppError>,
                                user_data: *mut c_void,
                                o_cb: unsafe extern "C" fn(*mut c_void, FfiResult, i32)) {
    match event {
        Ok(event) => o_cb(user_data, FFI_RESULT_OK, event.into()),
        Err(err) => {
            let (error_code, description) = ffi_error!(err);
            o_cb(user_data,
                 FfiResult {
                     error_code,
                     description: description.as_ptr(),
                 },
                 0)
        }
    }
}
