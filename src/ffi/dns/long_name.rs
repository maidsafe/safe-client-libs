// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net
// Commercial License, version 1.0 or later, or (2) The General Public License
// (GPL), version 3, depending on which licence you accepted on initial access
// to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project
// generally, you agree to be bound by the terms of the MaidSafe Contributor
// Agreement, version 1.0.
// This, along with the Licenses can be found in the root directory of this
// project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network
// Software distributed under the GPL Licence is distributed on an "AS IS"
// BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
//
// Please review the Licences for the specific language governing permissions
// and limitations relating to use of the SAFE Network Software.

//! DNS Long name operations

use core::futures::FutureExt;
use dns::operations;
use ffi::{FfiError, OpaqueCtx, Session};
use ffi::helper;
use ffi::string_list::{self, StringList};
use futures::Future;
use rust_sodium::crypto::box_;
use std::os::raw::c_void;
use std::ptr;

/// Register DNS long name.
#[no_mangle]
pub unsafe extern "C" fn dns_register_long_name(session: *const Session,
                                                long_name: *const u8,
                                                long_name_len: usize,
                                                user_data: *mut c_void,
                                                o_cb: extern "C" fn(*mut c_void, i32)) {
    helper::catch_unwind_cb(user_data, o_cb, || {
        let long_name = helper::c_utf8_to_string(long_name, long_name_len)?;

        trace!("FFI register public-id with name: {}. This means to register dns without a \
                given service.",
               long_name);

        let user_data = OpaqueCtx(user_data);
        let (msg_pk, msg_sk) = box_::gen_keypair();

        (*session).send(move |client, _| {
            let (sign_pk, sign_sk) = try_cb!(client.signing_keypair(), user_data, o_cb);

            let fut = operations::register_dns(client,
                                               long_name,
                                               msg_pk,
                                               msg_sk,
                                               &vec![],
                                               vec![sign_pk],
                                               sign_sk,
                                               None)
                .map(move |_| o_cb(user_data.0, 0))
                .map_err(move |err| o_cb(user_data.0, ffi_error_code!(err)))
                .into_box();

            Some(fut)
        })
    })
}

/// Delete DNS.
#[no_mangle]
pub unsafe extern "C" fn dns_delete_long_name(session: *const Session,
                                              long_name: *const u8,
                                              long_name_len: usize,
                                              user_data: *mut c_void,
                                              o_cb: extern "C" fn(*mut c_void, i32)) {
    helper::catch_unwind_cb(user_data, o_cb, || {
        trace!("FFI delete DNS.");
        let long_name = helper::c_utf8_to_string(long_name, long_name_len)?;
        let user_data = OpaqueCtx(user_data);

        (*session).send(move |client, _| {
            let sign_sk = try_cb!(client.secret_signing_key(), user_data, o_cb);

            let fut = operations::delete_dns(client, long_name, sign_sk)
                .map(move |_| o_cb(user_data.0, 0))
                .map_err(move |err| o_cb(user_data.0, ffi_error_code!(err)))
                .into_box();

            Some(fut)
        })
    })
}

/// Get all registered long names.
#[no_mangle]
pub unsafe extern "C" fn dns_get_long_names(session: *const Session,
                                            user_data: *mut c_void,
                                            o_cb: extern "C" fn(*mut c_void,
                                                                i32,
                                                                *mut StringList)) {
    helper::catch_unwind_cb(user_data, o_cb, || {
        trace!("FFI Get all dns long names.");
        let user_data = OpaqueCtx(user_data);

        (*session).send(move |client, _| {
            let fut = operations::get_all_registered_names(client)
                .map_err(FfiError::from)
                .and_then(|names| string_list::from_vec(names))
                .map(move |list| o_cb(user_data.0, 0, list))
                .map_err(move |err| o_cb(user_data.0, ffi_error_code!(err), ptr::null_mut()))
                .into_box();

            Some(fut)
        })
    })
}

#[cfg(test)]
mod tests {
    use core::utility;
    use dns::DnsError;
    use ffi::string_list::*;
    use ffi::test_utils;
    use std::os::raw::c_void;
    use std::sync::mpsc;
    use super::*;

    #[test]
    fn register_long_name() {
        let long_name = unwrap!(utility::generate_random_string(10));
        let long_name = test_utils::as_raw_parts(&long_name);

        let (tx, rx) = mpsc::channel::<()>();

        // Register
        {
            let session = test_utils::create_session();

            extern "C" fn register_cb(user_data: *mut c_void, error: i32) {
                assert_eq!(error, 0);
                unsafe { test_utils::send_via_user_data(user_data, ()) }
            }

            extern "C" fn get_cb(user_data: *mut c_void, error: i32, list: *mut StringList) {
                assert_eq!(error, 0);

                unsafe {
                    assert_eq!(string_list_len(list), 1);
                    string_list_free(list);
                    test_utils::send_via_user_data(user_data, ())
                }
            }

            unsafe {
                dns_register_long_name(&session,
                                       long_name.ptr,
                                       long_name.len,
                                       test_utils::sender_as_user_data(&tx),
                                       register_cb);
            }

            unwrap!(rx.recv());

            unsafe {
                dns_get_long_names(&session, test_utils::sender_as_user_data(&tx), get_cb);
            }

            unwrap!(rx.recv());
        }

        // Reregister is not allowed
        {
            let session = test_utils::create_session();

            extern "C" fn callback(user_data: *mut c_void, error: i32) {
                assert_eq!(error, DnsError::DnsNameAlreadyRegistered.into());
                unsafe { test_utils::send_via_user_data(user_data, ()) }
            }

            unsafe {
                dns_register_long_name(&session,
                                       long_name.ptr,
                                       long_name.len,
                                       test_utils::sender_as_user_data(&tx),
                                       callback);
            }

            unwrap!(rx.recv());
        }
    }
}
