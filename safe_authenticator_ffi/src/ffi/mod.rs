// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! FFI routines.

/// Apps management
pub mod apps;
/// Errors
pub mod errors;
/// FFI helpers
pub mod helpers;
/// Authenticator communication with apps
pub mod ipc;
/// Logging utilities
pub mod logging;

use crate::ffi::errors::{Error, Result};
use ffi_utils::try_cb;
use ffi_utils::{catch_unwind_cb, FfiResult, OpaqueCtx, ReprC, FFI_RESULT_OK};
use log::trace;
use rand::thread_rng;
use safe_authenticator::{AuthResult, Authenticator};
use safe_core::{config_handler, test_create_balance, Client};
use safe_nd::{ClientFullId, Money};
use std::ffi::{CStr, OsStr};
use std::os::raw::{c_char, c_void};
use std::str::FromStr;
use unwrap::unwrap;

/// Create a registered client. This or any one of the other companion
/// functions to get an authenticator instance must be called before initiating any
/// operation allowed by this module. The `user_data` parameter corresponds to the
/// first parameter of the `o_cb` and `o_disconnect_notifier_cb` callbacks.
#[no_mangle]
pub unsafe extern "C" fn create_acc(
    account_locator: *const c_char,
    account_password: *const c_char,
    user_data: *mut c_void,
    o_disconnect_notifier_cb: extern "C" fn(user_data: *mut c_void),
    o_cb: extern "C" fn(
        user_data: *mut c_void,
        result: *const FfiResult,
        authenticator: *mut Authenticator,
    ),
) {
    let user_data = OpaqueCtx(user_data);

    catch_unwind_cb(user_data, o_cb, || -> Result<_> {
        trace!("Authenticator - create a client account.");

        let acc_locator = String::clone_from_repr_c(account_locator)?;
        let acc_password = String::clone_from_repr_c(account_password)?;
        // FIXME: Send client id via FFI API too
        let client_id = ClientFullId::new_bls(&mut thread_rng());
        unwrap!(test_create_balance(
            &client_id,
            unwrap!(Money::from_str("10"))
        ));

        let authenticator =
            Authenticator::create_acc(acc_locator, acc_password, client_id, move || {
                o_disconnect_notifier_cb(user_data.0)
            })?;

        o_cb(
            user_data.0,
            FFI_RESULT_OK,
            Box::into_raw(Box::new(authenticator)),
        );
        Ok(())
    })
}

/// Log into a registered account. This or any one of the other companion
/// functions to get an authenticator instance must be called before initiating
/// any operation allowed for authenticator. The `user_data` parameter corresponds to the
/// first parameter of the `o_cb` and `o_disconnect_notifier_cb` callbacks.
#[no_mangle]
pub unsafe extern "C" fn login(
    account_locator: *const c_char,
    account_password: *const c_char,
    user_data: *mut c_void,
    o_disconnect_notifier_cb: unsafe extern "C" fn(user_data: *mut c_void),
    o_cb: extern "C" fn(
        user_data: *mut c_void,
        result: *const FfiResult,
        authenticaor: *mut Authenticator,
    ),
) {
    let user_data = OpaqueCtx(user_data);

    catch_unwind_cb(user_data, o_cb, || -> Result<_> {
        trace!("Authenticator - log in a registered client.");

        let acc_locator = String::clone_from_repr_c(account_locator)?;
        let acc_password = String::clone_from_repr_c(account_password)?;

        let authenticator = Authenticator::login(acc_locator, acc_password, move || {
            o_disconnect_notifier_cb(user_data.0)
        })?;

        o_cb(
            user_data.0,
            FFI_RESULT_OK,
            Box::into_raw(Box::new(authenticator)),
        );

        Ok(())
    })
}

/// Try to restore a failed connection with the network.
#[no_mangle]
pub unsafe extern "C" fn auth_reconnect(
    auth: *mut Authenticator,
    user_data: *mut c_void,
    o_cb: extern "C" fn(user_data: *mut c_void, result: *const FfiResult),
) {
    catch_unwind_cb(user_data, o_cb, || -> AuthResult<_> {
        let user_data = OpaqueCtx(user_data);
        (*auth).send(move |client| {
            try_cb!(
                client.restart_network().map_err(Error::from),
                user_data.0,
                o_cb
            );
            o_cb(user_data.0, FFI_RESULT_OK);
            None
        })
    })
}

/// Sets the path from which the `safe_core.config` file will be read.
#[no_mangle]
pub unsafe extern "C" fn auth_set_config_dir_path(
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

/// Discard and clean up the previously allocated authenticator instance.
/// Use this only if the authenticator is obtained from one of the auth
/// functions in this crate (`create_acc` or `login`).
/// Using `auth` after a call to this function is undefined behaviour.
#[no_mangle]
pub unsafe extern "C" fn auth_free(auth: *mut Authenticator) {
    let _ = Box::from_raw(auth);
}

/// Returns true if this crate was compiled against mock-routing.
#[no_mangle]
pub extern "C" fn auth_is_mock() -> bool {
    cfg!(feature = "mock-network")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ffi::auth_is_mock;
    use ffi_utils::test_utils::call_1;
    use futures::Future;
    use safe_authenticator::run;
    use safe_authenticator::AuthError;
    use safe_core::{client::COST_OF_PUT, utils, FutureExt};
    use safe_nd::PubImmutableData;
    use std::ffi::CString;
    use std::os::raw::c_void;

    // Test mock detection when compiled against mock-routing.
    #[test]
    #[cfg(feature = "mock-network")]
    fn test_mock_build() {
        assert_eq!(auth_is_mock(), true);
    }

    // Test mock detection when not compiled against mock-routing.
    #[test]
    #[cfg(not(feature = "mock-network"))]
    fn test_not_mock_build() {
        assert_eq!(auth_is_mock(), false);
    }

    // Test creating an account and logging in.
    #[test]
    fn create_account_and_login() {
        let acc_locator = unwrap!(CString::new(unwrap!(utils::generate_random_string(10))));
        let acc_password = unwrap!(CString::new(unwrap!(utils::generate_random_string(10))));

        {
            let auth_h: *mut Authenticator = unsafe {
                unwrap!(call_1(|ud, cb| create_acc(
                    acc_locator.as_ptr(),
                    acc_password.as_ptr(),
                    ud,
                    disconnect_cb,
                    cb,
                )))
            };
            assert!(!auth_h.is_null());
            unsafe { auth_free(auth_h) };
        }

        {
            let auth_h: *mut Authenticator = unsafe {
                unwrap!(call_1(|ud, cb| login(
                    acc_locator.as_ptr(),
                    acc_password.as_ptr(),
                    ud,
                    disconnect_cb,
                    cb,
                )))
            };
            assert!(!auth_h.is_null());
            unsafe { auth_free(auth_h) };
        }

        extern "C" fn disconnect_cb(_user_data: *mut c_void) {
            // FIXME: for stage 1 vaults disconnects are natural; so instead of
            // panicking we just log them.
            trace!("Disconnect occurred")
        }
    }

    // Test disconnection and reconnection with the authenticator.
    #[cfg(all(test, feature = "mock-network"))]
    #[ignore] // FIXME: ignoring this test for now until we figure out the disconnection semantics for Phase 1
    #[test]
    fn network_status_callback() {
        use ffi_utils::test_utils::{
            call_0, call_1_with_custom, send_via_user_data_custom, UserData,
        };
        use std::sync::mpsc::{self, Receiver, Sender};
        use std::time::Duration;

        safe_authenticator::test_utils::init_log();

        let acc_locator = unwrap!(CString::new(unwrap!(utils::generate_random_string(10))));
        let acc_password = unwrap!(CString::new(unwrap!(utils::generate_random_string(10))));

        {
            let (tx, rx): (Sender<()>, Receiver<()>) = mpsc::channel();

            let mut custom_ud: UserData = Default::default();
            let ptr: *const _ = &tx;
            custom_ud.custom = ptr as *mut c_void;

            let auth: *mut Authenticator = unsafe {
                unwrap!(call_1_with_custom(&mut custom_ud, |ud, cb| create_acc(
                    acc_locator.as_ptr(),
                    acc_password.as_ptr(),
                    ud,
                    disconnect_cb,
                    cb,
                )))
            };

            unsafe {
                unwrap!((*auth).send(move |client| {
                    client.simulate_network_disconnect();
                    None
                }));
            }

            // disconnect_cb should be Called.
            unwrap!(rx.recv_timeout(Duration::from_secs(15)));

            // Reconnect with the network
            unsafe { unwrap!(call_0(|ud, cb| auth_reconnect(auth, ud, cb))) };

            // This should time out.
            let result = rx.recv_timeout(Duration::from_secs(1));
            match result {
                Err(_) => (),
                _ => panic!("Disconnect callback was called"),
            }

            // The reconnection should be fine if we're already connected.
            unsafe { unwrap!(call_0(|ud, cb| auth_reconnect(auth, ud, cb))) };

            // disconnect_cb should be called.
            unwrap!(rx.recv_timeout(Duration::from_secs(15)));

            // This should time out.
            let result = rx.recv_timeout(Duration::from_secs(1));
            match result {
                Err(_) => (),
                _ => panic!("Disconnect callback was called"),
            }

            unsafe { auth_free(auth) };
        }

        extern "C" fn disconnect_cb(user_data: *mut c_void) {
            unsafe {
                send_via_user_data_custom(user_data, ());
            }
        }
    }

    // Test account usage statistics before and after a mutation.
    #[test]
    fn account_info() {
        let acc_locator = unwrap!(CString::new(unwrap!(utils::generate_random_string(10))));
        let acc_password = unwrap!(CString::new(unwrap!(utils::generate_random_string(10))));

        let auth: *mut Authenticator = unsafe {
            unwrap!(call_1(|ud, cb| create_acc(
                acc_locator.as_ptr(),
                acc_password.as_ptr(),
                ud,
                disconnect_cb,
                cb,
            )))
        };

        let orig_balance: Money = unwrap!(run(unsafe { &*auth }, |client| {
            client
                .get_balance(client.public_id().name(), None)
                .map_err(AuthError::from)
        }));

        unsafe {
            unwrap!((*auth).send(move |client| client
                .put_idata(PubImmutableData::new(vec![1, 2, 3]))
                .map_err(move |_| ())
                .into_box()
                .into()));
        }

        let new_balance: Money = unwrap!(run(unsafe { &*auth }, |client| {
            client
                .get_balance(client.public_id().name(), None)
                .map_err(AuthError::from)
        }));
        assert_eq!(new_balance, unwrap!(orig_balance.checked_sub(COST_OF_PUT)));

        unsafe { auth_free(auth) };
    }

    extern "C" fn disconnect_cb(_user_data: *mut c_void) {
        // FIXME: for stage 1 vaults disconnects are natural; so instead of
        // panicking we just log them.
        trace!("Disconnect occurred")
    }
}
