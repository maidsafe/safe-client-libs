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

/// Apps management
pub mod apps;
/// Logging utilities
pub mod logging;
/// Authenticator communication with apps
pub mod ipc;

use Authenticator;
use config_file_handler;
use errors::AuthError;
use ffi_utils::{FFI_RESULT_OK, FfiResult, OpaqueCtx, catch_unwind_cb, from_c_str};
use futures::Future;
use safe_core::FutureExt;
use safe_core::ffi::AccountInfo;
use std::ffi::{CStr, CString, OsStr};
use std::os::raw::{c_char, c_void};

/// Create a registered client. This or any one of the other companion
/// functions to get an authenticator instance must be called before initiating any
/// operation allowed by this module. The `user_data` parameter corresponds to the
/// first parameter of the `o_cb` and `o_disconnect_notifier_cb` callbacks.
///
/// Callback parameters: user data, error code, authenticator
#[no_mangle]
pub unsafe extern "C" fn create_acc(
    account_locator: *const c_char,
    account_password: *const c_char,
    invitation: *const c_char,
    user_data: *mut c_void,
    o_disconnect_notifier_cb: extern "C" fn(user_data: *mut c_void),
    o_cb: extern "C" fn(user_data: *mut c_void,
                        result: *const FfiResult,
                        authenticator: *mut Authenticator),
) {
    let user_data = OpaqueCtx(user_data);

    catch_unwind_cb(user_data, o_cb, || -> Result<_, AuthError> {
        trace!("Authenticator - create a client account.");

        let acc_locator = from_c_str(account_locator)?;
        let acc_password = from_c_str(account_password)?;
        let invitation = from_c_str(invitation)?;

        let authenticator =
            Authenticator::create_acc(acc_locator, acc_password, invitation, move || {
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
///
/// Callback parameters: user data, error code, authenticator
#[no_mangle]
pub unsafe extern "C" fn login(
    account_locator: *const c_char,
    account_password: *const c_char,
    user_data: *mut c_void,
    o_disconnect_notifier_cb: unsafe extern "C" fn(user_data: *mut c_void),
    o_cb: extern "C" fn(user_data: *mut c_void,
                        result: *const FfiResult,
                        authenticaor: *mut Authenticator),
) {
    let user_data = OpaqueCtx(user_data);

    catch_unwind_cb(user_data, o_cb, || -> Result<_, AuthError> {
        trace!("Authenticator - log in a registered client.");

        let acc_locator = from_c_str(account_locator)?;
        let acc_password = from_c_str(account_password)?;

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
///
/// Callback parameters: user data, error code
#[no_mangle]
pub unsafe extern "C" fn auth_reconnect(
    auth: *mut Authenticator,
    user_data: *mut c_void,
    o_cb: extern "C" fn(user_data: *mut c_void, result: *const FfiResult),
) {
    catch_unwind_cb(user_data, o_cb, || -> Result<_, AuthError> {
        let user_data = OpaqueCtx(user_data);
        (*auth).send(move |client| {
            try_cb!(
                client.restart_routing().map_err(AuthError::from),
                user_data.0,
                o_cb
            );
            o_cb(user_data.0, FFI_RESULT_OK);
            None
        })
    })
}

/// Get the account usage statistics.
///
/// Callback parameters: user data, error code, account info
#[no_mangle]
pub unsafe extern "C" fn auth_account_info(
    auth: *mut Authenticator,
    user_data: *mut c_void,
    o_cb: extern "C" fn(user_data: *mut c_void,
                        result: *const FfiResult,
                        account_info: *const AccountInfo),
) {
    catch_unwind_cb(user_data, o_cb, || -> Result<_, AuthError> {
        let user_data = OpaqueCtx(user_data);
        (*auth).send(move |client| {
            client
                .get_account_info()
                .map(move |acc_info| {
                    let ffi_acc = AccountInfo {
                        mutations_done: acc_info.mutations_done,
                        mutations_available: acc_info.mutations_available,
                    };
                    o_cb(user_data.0, FFI_RESULT_OK, &ffi_acc);
                })
                .map_err(move |e| {
                    call_result_cb!(Err::<(), _>(AuthError::from(e)), user_data, o_cb);
                })
                .into_box()
                .into()
        })
    })
}

/// Returns the expected name for the application executable without an extension
#[no_mangle]
pub unsafe extern "C" fn auth_exe_file_stem(
    user_data: *mut c_void,
    o_cb: extern "C" fn(user_data: *mut c_void,
                        result: *const FfiResult,
                        filename: *const c_char),
) {

    catch_unwind_cb(user_data, o_cb, || -> Result<_, AuthError> {
        if let Ok(path) = config_file_handler::exe_file_stem()?.into_string() {
            let path_c_str = CString::new(path)?;
            o_cb(user_data, FFI_RESULT_OK, path_c_str.as_ptr());
        } else {
            call_result_cb!(
                Err::<(), _>(AuthError::from(
                    "config_file_handler returned invalid string",
                )),
                user_data,
                o_cb
            );
        }
        Ok(())
    });
}

/// Sets the additional path in `config_file_handler` to search for files.
#[no_mangle]
pub unsafe extern "C" fn auth_set_additional_search_path(
    new_path: *const c_char,
    user_data: *mut c_void,
    o_cb: extern "C" fn(user_data: *mut c_void, result: *const FfiResult),
) {
    catch_unwind_cb(user_data, o_cb, || -> Result<_, AuthError> {
        let new_path = CStr::from_ptr(new_path).to_str()?;
        config_file_handler::set_additional_search_path(OsStr::new(new_path));
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

#[cfg(test)]
mod tests {
    use super::*;
    use Authenticator;
    use ffi_utils::test_utils::call_1;
    use routing::ImmutableData;
    use safe_core::ffi::AccountInfo;
    use safe_core::utils;
    use std::ffi::CString;
    use std::os::raw::c_void;

    // Test creating an account and logging in.
    #[test]
    fn create_account_and_login() {
        let acc_locator = unwrap!(CString::new(unwrap!(utils::generate_random_string(10))));
        let acc_password = unwrap!(CString::new(unwrap!(utils::generate_random_string(10))));
        let invitation = unwrap!(CString::new(unwrap!(utils::generate_random_string(10))));

        {
            let auth_h: *mut Authenticator = unsafe {
                unwrap!(call_1(|ud, cb| {
                    create_acc(
                        acc_locator.as_ptr(),
                        acc_password.as_ptr(),
                        invitation.as_ptr(),
                        ud,
                        disconnect_cb,
                        cb,
                    )
                }))
            };
            assert!(!auth_h.is_null());
            unsafe { auth_free(auth_h) };
        }

        {
            let auth_h: *mut Authenticator = unsafe {
                unwrap!(call_1(|ud, cb| {
                    login(
                        acc_locator.as_ptr(),
                        acc_password.as_ptr(),
                        ud,
                        disconnect_cb,
                        cb,
                    )
                }))
            };
            assert!(!auth_h.is_null());
            unsafe { auth_free(auth_h) };
        }

        extern "C" fn disconnect_cb(_user_data: *mut c_void) {
            panic!("Disconnect occurred")
        }
    }

    // Test disconnection and reconnection with the authenticator.
    #[cfg(all(test, feature = "use-mock-routing"))]
    #[test]
    fn network_status_callback() {
        use ffi_utils::test_utils::{UserData, call_0, call_1_with_custom,
                                    send_via_user_data_custom};
        use std::time::Duration;
        use std::sync::mpsc::{self, Receiver, Sender};

        let acc_locator = unwrap!(CString::new(unwrap!(utils::generate_random_string(10))));
        let acc_password = unwrap!(CString::new(unwrap!(utils::generate_random_string(10))));
        let invitation = unwrap!(CString::new(unwrap!(utils::generate_random_string(10))));

        {
            let (tx, rx): (Sender<()>, Receiver<()>) = mpsc::channel();

            let mut custom_ud: UserData = Default::default();
            let ptr: *const _ = &tx;
            custom_ud.custom = ptr as *mut c_void;

            let auth: *mut Authenticator = unsafe {
                unwrap!(call_1_with_custom(&mut custom_ud, |ud, cb| {
                    create_acc(
                        acc_locator.as_ptr(),
                        acc_password.as_ptr(),
                        invitation.as_ptr(),
                        ud,
                        disconnect_cb,
                        cb,
                    )
                }))
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
        let invitation = unwrap!(CString::new(unwrap!(utils::generate_random_string(10))));

        let auth: *mut Authenticator = unsafe {
            unwrap!(call_1(|ud, cb| {
                create_acc(
                    acc_locator.as_ptr(),
                    acc_password.as_ptr(),
                    invitation.as_ptr(),
                    ud,
                    disconnect_cb,
                    cb,
                )
            }))
        };

        let orig_stats: AccountInfo =
            unsafe { unwrap!(call_1(|ud, cb| auth_account_info(auth, ud, cb))) };
        assert!(orig_stats.mutations_available > 0);

        unsafe {
            unwrap!((*auth).send(move |client| {
                client
                    .put_idata(ImmutableData::new(vec![1, 2, 3]))
                    .map_err(move |_| ())
                    .into_box()
                    .into()
            }));
        }

        let stats: AccountInfo =
            unsafe { unwrap!(call_1(|ud, cb| auth_account_info(auth, ud, cb))) };
        assert_eq!(stats.mutations_done, orig_stats.mutations_done + 1);
        assert_eq!(
            stats.mutations_available,
            orig_stats.mutations_available - 1
        );

        unsafe { auth_free(auth) };
    }

    extern "C" fn disconnect_cb(_user_data: *mut c_void) {
        panic!("Disconnect occurred")
    }
}
