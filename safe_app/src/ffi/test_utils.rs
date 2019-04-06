// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

#![allow(unsafe_code)]

use crate::errors::AppError;
use ffi_utils::{catch_unwind_cb, from_c_str, FfiResult, ReprC, FFI_RESULT_OK};
use safe_core::ffi::ipc::req::AuthReq;
use safe_core::ipc::req::AuthReq as NativeAuthReq;
use std::os::raw::{c_char, c_void};
use crate::test_utils::{create_app_by_req, create_auth_req};
use crate::App;

/// Creates a random app instance for testing.
#[no_mangle]
pub unsafe extern "C" fn test_create_app(
    app_id: *const c_char,
    user_data: *mut c_void,
    o_cb: extern "C" fn(user_data: *mut c_void, result: *const FfiResult, app: *mut App),
) {
    catch_unwind_cb(user_data, o_cb, || -> Result<(), AppError> {
        let app_id = from_c_str(app_id)?;
        let auth_req = create_auth_req(Some(app_id), None);
        match create_app_by_req(&auth_req) {
            Ok(app) => {
                o_cb(user_data, FFI_RESULT_OK, Box::into_raw(Box::new(app)));
            }
            res @ Err(..) => {
                call_result_cb!(res, user_data, o_cb);
            }
        }
        Ok(())
    })
}

/// Create a random app instance for testing, with access to containers.
#[no_mangle]
pub unsafe extern "C" fn test_create_app_with_access(
    auth_req: *const AuthReq,
    user_data: *mut c_void,
    o_cb: extern "C" fn(user_data: *mut c_void, result: *const FfiResult, o_app: *mut App),
) {
    catch_unwind_cb(user_data, o_cb, || -> Result<(), AppError> {
        let auth_req = NativeAuthReq::clone_from_repr_c(auth_req)?;
        match create_app_by_req(&auth_req) {
            Ok(app) => {
                o_cb(user_data, FFI_RESULT_OK, Box::into_raw(Box::new(app)));
            }
            res @ Err(..) => {
                call_result_cb!(res, user_data, o_cb);
            }
        }
        Ok(())
    })
}

/// Simulate a network disconnect when testing.
#[cfg(feature = "use-mock-routing")]
#[no_mangle]
pub unsafe extern "C" fn test_simulate_network_disconnect(
    app: *mut App,
    user_data: *mut c_void,
    o_cb: extern "C" fn(user_data: *mut c_void, result: *const FfiResult),
) {
    use ffi::helper::send_sync;
    use safe_core::Client;

    catch_unwind_cb(user_data, o_cb, || {
        send_sync(app, user_data, o_cb, |client, _| {
            client.simulate_network_disconnect();
            Ok(())
        })
    })
}

#[cfg(test)]
mod tests {
    use super::test_create_app_with_access;
    use ffi_utils::test_utils::call_1;
    use ffi_utils::ErrorCode;
    use safe_authenticator::test_utils::rand_app;
    use safe_core::ipc::req::AuthReq;
    use safe_core::ipc::Permission;
    use std::collections::HashMap;
    use crate::{App, AppError};

    #[test]
    fn create_app_with_invalid_access() {
        let mut containers = HashMap::new();
        let _ = containers.insert("_app".to_owned(), btree_set![Permission::Insert]);

        let auth_req = AuthReq {
            app: rand_app(),
            app_container: false,
            containers,
        };
        let auth_req = unwrap!(auth_req.into_repr_c());

        let result: Result<*mut App, i32> =
            unsafe { call_1(|ud, cb| test_create_app_with_access(&auth_req, ud, cb)) };
        match result {
            Err(error) if error == AppError::NoSuchContainer("_app".into()).error_code() => (),
            x => panic!("Unexpected {:?}", x),
        }
    }

    // Test simulating network disconnects.
    #[cfg(feature = "use-mock-routing")]
    #[test]
    fn simulate_network_disconnect() {
        use super::test_simulate_network_disconnect;
        use ffi_utils::test_utils::call_0;
        use safe_authenticator::test_utils as authenticator;
        use safe_core::utils;
        use std::sync::mpsc;
        use std::time::Duration;
        use test_utils::create_auth_req;

        let app_id = unwrap!(utils::generate_random_string(10));
        let auth_req = create_auth_req(Some(app_id), None);
        let auth = authenticator::create_account_and_login();
        let auth_granted = unwrap!(authenticator::register_app(&auth, &auth_req));

        // Use `sync_channel` as `App::registered` requires `Send`.
        let (tx, rx) = mpsc::sync_channel::<()>(0);

        let mut app = unwrap!(App::registered(
            auth_req.app.id.clone(),
            auth_granted,
            move || {
                unwrap!(tx.send(()));
            },
        ));

        unsafe {
            unwrap!(call_0(|ud, cb| test_simulate_network_disconnect(
                &mut app, ud, cb
            ),));
        }

        unwrap!(rx.recv_timeout(Duration::from_secs(10)));
    }
}
