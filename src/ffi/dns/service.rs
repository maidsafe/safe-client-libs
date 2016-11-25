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

//! DNS service operations

use core::futures::FutureExt;
use dns::operations;
use ffi::{AppHandle, FfiError, OpaqueCtx, Session, helper};
use ffi::dir_details::DirDetails;
use ffi::string_list::{self, StringList};
use futures::Future;
use nfs::helper::dir_helper;
use std::os::raw::c_void;
use std::ptr;

/// Add service.
#[no_mangle]
pub unsafe extern "C" fn dns_add_service(session: *const Session,
                                         app_handle: AppHandle,
                                         long_name: *const u8,
                                         long_name_len: usize,
                                         service_name: *const u8,
                                         service_name_len: usize,
                                         service_home_dir_path: *const u8,
                                         service_home_dir_path_len: usize,
                                         is_path_shared: bool,
                                         user_data: *mut c_void,
                                         o_cb: extern "C" fn(*mut c_void, i32)) {
    helper::catch_unwind_cb(user_data, o_cb, || {
        trace!("FFI add service.");

        let long_name = helper::c_utf8_to_string(long_name, long_name_len)?;
        let service_name = helper::c_utf8_to_string(service_name, service_name_len)?;
        let service_home_dir_path = helper::c_utf8_to_string(service_home_dir_path,
                                                             service_home_dir_path_len)?;

        let user_data = OpaqueCtx(user_data);

        (*session).send(move |client, object_cache| {
            let client2 = client.clone();
            let sign_sk = try_cb!(client.secret_signing_key(), user_data, o_cb);

            match object_cache.get_app(app_handle) {
                Ok(app) => {
                    let fut = helper::dir(client, &*app, service_home_dir_path, is_path_shared)
                        .and_then(move |(_, dir_metadata)| {
                            operations::add_service(&client2,
                                                    long_name,
                                                    (service_name, dir_metadata.id()),
                                                    sign_sk,
                                                    None)
                                .map_err(FfiError::from)
                        })
                        .map(move |_| o_cb(user_data.0, 0))
                        .map_err(move |err| o_cb(user_data.0, ffi_error_code!(err)))
                        .into_box();

                    Some(fut)
                }
                Err(err) => {
                    o_cb(user_data.0, ffi_error_code!(err));
                    None
                }
            }
        })
    })
}

/// Delete DNS service.
#[no_mangle]
pub unsafe extern "C" fn dns_delete_service(session: *const Session,
                                            long_name: *const u8,
                                            long_name_len: usize,
                                            service_name: *const u8,
                                            service_name_len: usize,
                                            user_data: *mut c_void,
                                            o_cb: extern "C" fn(*mut c_void, i32)) {
    helper::catch_unwind_cb(user_data, o_cb, || {
        trace!("FFI delete service.");

        let long_name = helper::c_utf8_to_string(long_name, long_name_len)?;
        let service_name = helper::c_utf8_to_string(service_name, service_name_len)?;
        let user_data = OpaqueCtx(user_data);

        (*session).send(move |client, _| {
            let sign_sk = try_cb!(client.secret_signing_key(), user_data, o_cb);

            let fut = operations::remove_service(client, long_name, service_name, sign_sk, None)
                .map(move |_| o_cb(user_data.0, 0))
                .map_err(move |err| o_cb(user_data.0, ffi_error_code!(err)))
                .into_box();

            Some(fut)
        })
    })
}

/// Get all registered long names.
#[no_mangle]
pub unsafe extern "C" fn dns_get_services(session: *const Session,
                                          long_name: *const u8,
                                          long_name_len: usize,
                                          user_data: *mut c_void,
                                          o_cb: extern "C" fn(*mut c_void, i32, *mut StringList)) {
    helper::catch_unwind_cb(user_data, o_cb, || {
        let long_name = helper::c_utf8_to_string(long_name, long_name_len)?;

        trace!("FFI Get all services for dns with name: {}", long_name);

        let user_data = OpaqueCtx(user_data);

        (*session).send(move |client, _| {
            let fut = operations::get_all_services(client, long_name, None)
                .map_err(FfiError::from)
                .and_then(|services| string_list::from_vec(services))
                .map(move |list| {
                    o_cb(user_data.0, 0, list);
                })
                .map_err(move |err| {
                    o_cb(user_data.0, ffi_error_code!(err), ptr::null_mut());
                })
                .into_box();

            Some(fut)
        })
    })
}

/// Get home directory of the given service.
#[no_mangle]
pub unsafe extern "C" fn dns_get_service_dir(session: *const Session,
                                             long_name: *const u8,
                                             long_name_len: usize,
                                             service_name: *const u8,
                                             service_name_len: usize,
                                             user_data: *mut c_void,
                                             o_cb: extern "C" fn(*mut c_void,
                                                                 i32,
                                                                 *mut DirDetails)) {
    helper::catch_unwind_cb(user_data, o_cb, || {
        let long_name = helper::c_utf8_to_string(long_name, long_name_len)?;
        let service_name = helper::c_utf8_to_string(service_name, service_name_len)?;

        trace!("FFI Get service home directory for \"//{}.{}\".",
               service_name,
               long_name);

        let user_data = OpaqueCtx(user_data);

        (*session).send(move |client, _| {
            let client2 = client.clone();

            let fut = operations::get_service_home_dir_id(client, long_name, service_name, None)
                .map_err(FfiError::from)
                .and_then(move |dir_id| {
                    dir_helper::get(client2, &dir_id).map_err(FfiError::from)
                })
                .and_then(|dir| DirDetails::from_dir(dir))
                .map(move |details| {
                    let details = Box::into_raw(Box::new(details));
                    o_cb(user_data.0, 0, details);
                })
                .map_err(move |err| {
                    o_cb(user_data.0, ffi_error_code!(err), ptr::null_mut());
                })
                .into_box();

            Some(fut)
        })
    })
}

#[cfg(test)]
mod tests {
    use core::{Client, utility};
    use core::futures::FutureExt;
    use dns::operations;
    use ffi::{App, FfiError, FfiFuture, helper, test_utils};
    use ffi::dir_details::DirDetails;
    use futures::Future;
    use nfs::DirId;
    use nfs::helper::dir_helper;
    use rust_sodium::crypto::box_;
    use std::os::raw::c_void;
    use std::sync::mpsc;
    use super::*;

    #[test]
    fn add_service() {
        let session = test_utils::create_session();
        let app = test_utils::create_app(&session, false);

        let long_name = unwrap!(utility::generate_random_string(10));
        let long_name2 = long_name.clone();

        // Register the DNS long name and create the home directory for the new
        // service.
        let app_h = test_utils::run(&session, move |client, object_cache| {
            let fut1 = create_dir(client, &app, "www-dir");
            let fut2 = register_dns(client, long_name, &[]);
            let app_h = object_cache.insert_app(app);

            fut1.join(fut2).map(move |_| app_h)
        });

        let (tx, rx) = mpsc::channel::<()>();

        let long_name = test_utils::as_raw_parts(&long_name2);
        let service_name = test_utils::as_raw_parts("www");
        let service_home_dir_path = test_utils::as_raw_parts("www-dir");

        extern "C" fn callback(user_data: *mut c_void, error: i32) {
            assert_eq!(error, 0);
            unsafe { test_utils::send_via_user_data(user_data, ()) }
        }

        unsafe {
            dns_add_service(&session,
                            app_h,
                            long_name.ptr,
                            long_name.len,
                            service_name.ptr,
                            service_name.len,
                            service_home_dir_path.ptr,
                            service_home_dir_path.len,
                            false,
                            test_utils::sender_as_user_data(&tx),
                            callback);
        }

        unwrap!(rx.recv());
    }


    #[test]
    fn get_service_dir() {
        let session1 = test_utils::create_session();
        let app = test_utils::create_app(&session1, false);

        let long_name = unwrap!(utility::generate_random_string(10));
        let long_name2 = long_name.clone();

        test_utils::run(&session1, move |client, _| {
            let client2 = client.clone();

            create_dir(client, &app, "www-dir").then(move |result| {
                let dir_id = unwrap!(result);
                let service = ("www".to_string(), dir_id);
                register_dns(&client2, long_name, &[service])
            })
        });

        let session2 = test_utils::create_unregistered_session();

        let (tx, rx) = mpsc::channel::<()>();

        let long_name = test_utils::as_raw_parts(&long_name2);
        let service_name = test_utils::as_raw_parts("www");

        extern "C" fn callback(user_data: *mut c_void, error: i32, dir_details: *mut DirDetails) {
            assert_eq!(error, 0);
            assert!(!dir_details.is_null());
            unsafe { test_utils::send_via_user_data(user_data, ()) }
        }

        unsafe {
            dns_get_service_dir(&session2,
                                long_name.ptr,
                                long_name.len,
                                service_name.ptr,
                                service_name.len,
                                test_utils::sender_as_user_data(&tx),
                                callback);
        }

        unwrap!(rx.recv());
    }

    fn create_dir<S: Into<String>>(client: &Client, app: &App, name: S) -> Box<FfiFuture<DirId>> {
        let client2 = client.clone();
        let name = name.into();

        helper::dir(client, app, "/", false)
            .then(move |result| {
                let (root_dir, root_dir_meta) = unwrap!(result);
                dir_helper::create_sub_dir(client2,
                                           name,
                                           None,
                                           vec![],
                                           &root_dir,
                                           &root_dir_meta.id())
                    .map(|(_, _, meta)| meta.id())
                    .map_err(FfiError::from)
            })
            .into_box()
    }

    fn register_dns<S: Into<String>>(client: &Client,
                                     long_name: S,
                                     services: &[(String, DirId)])
                                     -> Box<FfiFuture<()>> {
        let (sign_pk, sign_sk) = unwrap!(client.signing_keypair());
        let (msg_pk, msg_sk) = box_::gen_keypair();

        operations::register_dns(client,
                                 long_name,
                                 msg_pk,
                                 msg_sk,
                                 services,
                                 vec![sign_pk],
                                 sign_sk,
                                 None)
            .map_err(FfiError::from)
            .into_box()
    }
}
