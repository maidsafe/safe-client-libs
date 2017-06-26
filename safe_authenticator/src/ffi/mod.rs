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

/// Public ID routines.
pub mod public_id;
/// Apps management.
pub mod apps;
/// Logging utilities
pub mod logging;

use Authenticator;
use errors::AuthError;
use ffi_utils::{FFI_RESULT_OK, FfiResult, OpaqueCtx, catch_unwind_cb, from_c_str};
use std::os::raw::{c_char, c_void};

/// Create a registered client. This or any one of the other companion
/// functions to get an authenticator instance must be called before initiating any
/// operation allowed by this module. The `user_data` parameter corresponds to the
/// first parameter of the `o_cb` callback, while `network_cb_user_data` corresponds
/// to the first parameter of the network events observer callback (`o_network_obs_cb`).
#[no_mangle]
pub unsafe extern "C" fn create_acc(account_locator: *const c_char,
                                    account_password: *const c_char,
                                    invitation: *const c_char,
                                    network_cb_user_data: *mut c_void,
                                    user_data: *mut c_void,
                                    o_network_obs_cb: unsafe extern "C" fn(*mut c_void, i32, i32),
                                    o_cb: extern "C" fn(*mut c_void,
                                                        FfiResult,
                                                        *mut Authenticator)) {
    let user_data = OpaqueCtx(user_data);
    let network_cb_user_data = OpaqueCtx(network_cb_user_data);

    catch_unwind_cb(user_data, o_cb, || -> Result<_, AuthError> {
        trace!("Authenticator - create a client account.");

        let acc_locator = from_c_str(account_locator)?;
        let acc_password = from_c_str(account_password)?;
        let invitation = from_c_str(invitation)?;

        let authenticator =
            Authenticator::create_acc(acc_locator, acc_password, invitation, move |net_event| {
                let ud = network_cb_user_data.0;
                match net_event {
                    Ok(event) => o_network_obs_cb(ud, 0, event.into()),
                    Err(()) => o_network_obs_cb(ud, -1, 0),
                }
            })?;

        o_cb(user_data.0,
             FFI_RESULT_OK,
             Box::into_raw(Box::new(authenticator)));

        Ok(())
    })
}

/// Log into a registered account. This or any one of the other companion
/// functions to get an authenticator instance must be called before initiating
/// any operation allowed for authenticator. The `user_data` parameter corresponds to the
/// first parameter of the `o_cb` callback, while `network_cb_user_data` corresponds
/// to the first parameter of the network events observer callback (`o_network_obs_cb`).
#[no_mangle]
pub unsafe extern "C" fn login(account_locator: *const c_char,
                               account_password: *const c_char,
                               user_data: *mut c_void,
                               network_cb_user_data: *mut c_void,
                               o_network_obs_cb: unsafe extern "C" fn(*mut c_void, i32, i32),
                               o_cb: extern "C" fn(*mut c_void, FfiResult, *mut Authenticator)) {
    let user_data = OpaqueCtx(user_data);
    let network_cb_user_data = OpaqueCtx(network_cb_user_data);

    catch_unwind_cb(user_data, o_cb, || -> Result<_, AuthError> {
        trace!("Authenticator - log in a registererd client.");

        let acc_locator = from_c_str(account_locator)?;
        let acc_password = from_c_str(account_password)?;

        let authenticator =
            Authenticator::login(acc_locator,
                                 acc_password,
                                 move |net_event| match net_event {
                                     Ok(event) => {
                                         o_network_obs_cb(network_cb_user_data.0, 0, event.into())
                                     }
                                     Err(()) => o_network_obs_cb(network_cb_user_data.0, -1, 0),
                                 })?;

        o_cb(user_data.0,
             FFI_RESULT_OK,
             Box::into_raw(Box::new(authenticator)));

        Ok(())
    })
}

/// Discard and clean up the previously allocated authenticator instance.
/// Use this only if the authenticator is obtained from one of the auth
/// functions in this crate (`create_acc`, `login`, `create_unregistered`).
/// Using `auth` after a call to this function is undefined behaviour.
#[no_mangle]
pub unsafe extern "C" fn authenticator_free(auth: *mut Authenticator) {
    let _ = Box::from_raw(auth);
}

#[cfg(test)]
mod tests {
    use super::*;
    use Authenticator;
    use ffi_utils::test_utils::call_1;
    use safe_core::utils;
    use std::ffi::CString;
    use std::os::raw::c_void;

    #[test]
    fn create_account_and_login() {
        let acc_locator = unwrap!(CString::new(unwrap!(utils::generate_random_string(10))));
        let acc_password = unwrap!(CString::new(unwrap!(utils::generate_random_string(10))));
        let invitation = unwrap!(CString::new(unwrap!(utils::generate_random_string(10))));

        {
            let auth_h: *mut Authenticator = unsafe {
                unwrap!(call_1(|ud, cb| {
                    create_acc(acc_locator.as_ptr(),
                               acc_password.as_ptr(),
                               invitation.as_ptr(),
                               ud,
                               ud,
                               net_event_cb,
                               cb)
                }))
            };
            assert!(!auth_h.is_null());
            unsafe { authenticator_free(auth_h) };
        }

        {
            let auth_h: *mut Authenticator = unsafe {
                unwrap!(call_1(|ud, cb| {
                                   login(acc_locator.as_ptr(),
                                         acc_password.as_ptr(),
                                         ud,
                                         ud,
                                         net_event_cb,
                                         cb)
                               }))
            };
            assert!(!auth_h.is_null());
            unsafe { authenticator_free(auth_h) };
        }

        unsafe extern "C" fn net_event_cb(_user_data: *mut c_void, err_code: i32, _event: i32) {
            assert_eq!(err_code, 0);
        }
    }

    #[cfg(all(test, feature = "use-mock-routing"))]
    #[test]
    fn network_status_callback() {
        use ffi_utils::test_utils::{send_via_user_data, sender_as_user_data};
        use safe_core::NetworkEvent;
        use std::time::Duration;
        use std::sync::mpsc;

        let acc_locator = unwrap!(CString::new(unwrap!(utils::generate_random_string(10))));
        let acc_password = unwrap!(CString::new(unwrap!(utils::generate_random_string(10))));
        let invitation = unwrap!(CString::new(unwrap!(utils::generate_random_string(10))));

        {
            let (tx, rx) = mpsc::channel();

            let auth: *mut Authenticator = unsafe {
                unwrap!(call_1(|ud, cb| {
                    create_acc(acc_locator.as_ptr(),
                               acc_password.as_ptr(),
                               invitation.as_ptr(),
                               sender_as_user_data(&tx),
                               ud,
                               net_event_cb,
                               cb)
                }))
            };

            unsafe {
                unwrap!((*auth).send(move |client| {
                                         client.simulate_network_disconnect();
                                         None
                                     }));
            }

            let (err_code, event): (i32, i32) = unwrap!(rx.recv_timeout(Duration::from_secs(10)));
            assert_eq!(err_code, 0);

            let disconnected: i32 = NetworkEvent::Disconnected.into();
            assert_eq!(event, disconnected);

            unsafe { authenticator_free(auth) };
        }

        unsafe extern "C" fn net_event_cb(user_data: *mut c_void, err_code: i32, event: i32) {
            send_via_user_data(user_data, (err_code, event));
        }
    }
}
