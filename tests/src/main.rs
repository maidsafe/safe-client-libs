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

//! SAFE Core Integration Tests

#![doc(html_logo_url =
           "https://raw.githubusercontent.com/maidsafe/QA/master/Images/maidsafe_logo.png",
       html_favicon_url = "http://maidsafe.net/img/favicon.ico",
       html_root_url = "http://maidsafe.github.io/safe_app")]

// For explanation of lint checks, run `rustc -W help` or see
// https://github.com/maidsafe/QA/blob/master/Documentation/Rust%20Lint%20Checks.md
#![forbid(exceeding_bitshifts, mutable_transmutes, no_mangle_const_items,
          unknown_crate_types, warnings)]
#![deny(bad_style, deprecated, improper_ctypes, missing_docs,
        non_shorthand_field_patterns, overflowing_literals, plugin_as_library,
        private_no_mangle_fns, private_no_mangle_statics, stable_features,
        unconditional_recursion, unknown_lints, unused,
        unused_allocation, unused_attributes, unused_comparisons, unused_features,
        unused_parens, while_true)]
#![warn(trivial_casts, trivial_numeric_casts, unused_extern_crates, unused_import_braces,
        unused_qualifications, unused_results)]
#![allow(box_pointers, fat_ptr_transmutes, missing_copy_implementations,
         missing_debug_implementations, variant_size_differences)]

#![cfg_attr(feature="cargo-clippy", deny(clippy, unicode_not_nfc, wrong_pub_self_convention,
                                         option_unwrap_used))]
#![cfg_attr(feature="cargo-clippy", allow(use_debug, too_many_arguments))]

extern crate safe_core;
extern crate safe_authenticator;
extern crate safe_app;
extern crate ffi_utils;
#[macro_use]
extern crate unwrap;

use ffi_utils::{FfiString, ffi_string_free};
use ffi_utils::test_utils::{call_0, call_1, send_via_user_data, sender_as_user_data};
use safe_app::{App, ERR_ACCESS_DENIED};
use safe_app::ffi::{app_free, app_registered};
use safe_app::ffi::access_container::access_container_get_container_mdata_info;
use safe_app::ffi::ipc as app_ipc;
use safe_app::ffi::mutable_data::entry_actions::{mdata_entry_actions_free,
                                                 mdata_entry_actions_insert,
                                                 mdata_entry_actions_new,
                                                 mdata_entry_actions_update};
use safe_app::ffi::mutable_data::mdata_mutate_entries;
use safe_authenticator::Authenticator;
use safe_authenticator::ffi::{authenticator_free, create_acc};
use safe_authenticator::ipc::{auth_decode_ipc_msg, encode_auth_resp, encode_containers_resp};
use safe_core::ipc::req::ffi::{AppExchangeInfo, AuthReq, ContainerPermissions,
                               ContainerPermissionsArray, ContainersReq, Permission,
                               PermissionArray};
use safe_core::ipc::resp::ffi::AuthGranted;
use safe_core::utils;
use std::{mem, ptr};
use std::os::raw::c_void;
use std::sync::mpsc;

struct SendWrapper<T>(T);
unsafe impl<T> Send for SendWrapper<T> {}

// Main integration test for safe_client_libs.
#[test]
fn test() {
    let app_id = unwrap!(utils::generate_random_string(10));

    let mut perms = vec![Permission::Insert];

    let mut containers = Vec::new();
    containers.push(ContainerPermissions {
                        cont_name: FfiString::from_string("_videos"),
                        access: PermissionArray {
                            ptr: perms.as_mut_ptr(),
                            len: perms.len(),
                            cap: perms.capacity(),
                        },
                    });
    mem::forget(perms);

    let req = AuthReq {
        app: AppExchangeInfo {
            id: FfiString::from_string(app_id.clone()),
            scope: ptr::null_mut(),
            scope_len: 0,
            scope_cap: 0,
            name: FfiString::from_string("safe-core-integration-test"),
            vendor: FfiString::from_string("maidsafe"),
        },
        containers: ContainerPermissionsArray {
            ptr: containers.as_mut_ptr(),
            len: containers.len(),
            cap: containers.capacity(),
        },
        app_container: true,
    };
    mem::forget(containers);

    let mut req_id = 0;
    let mut encoded_auth_req = FfiString::default();

    unsafe {
        assert_eq!(app_ipc::encode_auth_req(req, &mut req_id, &mut encoded_auth_req),
                   0);
    }

    let authenticator = create_authenticator();

    let (tx, rx) = mpsc::channel::<Result<SendWrapper<AuthReq>, i32>>();

    unsafe {
        auth_decode_ipc_msg(authenticator,
                            encoded_auth_req,
                            sender_as_user_data(&tx),
                            auth_req_cb,
                            container_req_cb,
                            err_cb::<AuthReq>);

        ffi_string_free(encoded_auth_req);
    }

    let auth_req = unwrap!(unwrap!(rx.recv())).0;

    let result_str = unsafe {
        unwrap!(call_1(|ud, cb| encode_auth_resp(authenticator, auth_req, req_id, true, ud, cb)))
    };

    // Get AuthGranted from app
    let (tx, rx) = mpsc::channel::<Result<SendWrapper<AuthGranted>, i32>>();

    unsafe {
        app_ipc::decode_ipc_msg(result_str,
                                sender_as_user_data(&tx),
                                auth_granted_cb,
                                app_container_req_cb,
                                revoked_cb,
                                app_err_cb::<AuthGranted>);

        ffi_string_free(result_str);
    }

    let auth_granted = unwrap!(unwrap!(rx.recv())).0;

    let mut app: *mut App = ptr::null_mut();

    unsafe {
        assert_eq!(app_registered(FfiString::from_string(app_id.clone()),
                                  auth_granted,
                                  ptr::null_mut(),
                                  network_cb,
                                  &mut app),
                   0);
    }

    // Try to retrieve MDataInfo for _videos from the access container
    let md_info_h = unsafe {
        unwrap!(call_1(|ud, cb| {
                           let cont_name = FfiString::from_string("_videos");
                           access_container_get_container_mdata_info(app, cont_name, ud, cb)
                       }))
    };

    // Insert an entry into the retrieved MDataInfo
    let actions_h = unsafe { unwrap!(call_1(|ud, cb| mdata_entry_actions_new(app, ud, cb))) };

    unsafe {
        unwrap!(call_0(|ud, cb| {
            mdata_entry_actions_insert(app,
                                       actions_h,
                                       "hello".as_ptr(),
                                       5,
                                       "world".as_ptr(),
                                       5,
                                       ud,
                                       cb)
        }))
    }

    unsafe { unwrap!(call_0(|ud, cb| mdata_mutate_entries(app, md_info_h, actions_h, ud, cb))) }
    unsafe { unwrap!(call_0(|ud, cb| mdata_entry_actions_free(app, actions_h, ud, cb))) }

    // Try to update an entry without having corresponding permissions
    let upd_actions_h = unsafe { unwrap!(call_1(|ud, cb| mdata_entry_actions_new(app, ud, cb))) };

    unsafe {
        unwrap!(call_0(|ud, cb| {
            mdata_entry_actions_update(app,
                                       upd_actions_h,
                                       "hello".as_ptr(),
                                       5,
                                       "howdy".as_ptr(),
                                       5,
                                       1,
                                       ud,
                                       cb)
        }))
    }

    let res =
        unsafe { call_0(|ud, cb| mdata_mutate_entries(app, md_info_h, upd_actions_h, ud, cb)) };

    match res {
        // We should get AccessDenied as a result
        Err(ERR_ACCESS_DENIED) => (),
        Err(x) => panic!("Unexpected {:?}", x),
        Ok(()) => panic!("Unexpected successfull mutation"),
    }

    // Ask for update permissions on the _videos container
    let mut perms = vec![Permission::Insert, Permission::Update];

    let mut containers = Vec::new();
    containers.push(ContainerPermissions {
                        cont_name: FfiString::from_string("_videos"),
                        access: PermissionArray {
                            ptr: perms.as_mut_ptr(),
                            len: perms.len(),
                            cap: perms.capacity(),
                        },
                    });
    mem::forget(perms);

    let cont_req = ContainersReq {
        app: AppExchangeInfo {
            id: FfiString::from_string(app_id.clone()),
            scope: ptr::null_mut(),
            scope_len: 0,
            scope_cap: 0,
            name: FfiString::from_string("safe-core-integration-test"),
            vendor: FfiString::from_string("maidsafe"),
        },
        containers: ContainerPermissionsArray {
            ptr: containers.as_mut_ptr(),
            len: containers.len(),
            cap: containers.capacity(),
        },
    };
    mem::forget(containers);

    let mut req_id = 0;
    let mut encoded_cont_req = FfiString::default();

    unsafe {
        assert_eq!(app_ipc::encode_containers_req(cont_req, &mut req_id, &mut encoded_cont_req),
                   0)
    };

    let (tx, rx) = mpsc::channel::<Result<SendWrapper<ContainersReq>, i32>>();

    unsafe {
        auth_decode_ipc_msg(authenticator,
                            encoded_cont_req,
                            sender_as_user_data(&tx),
                            auth_req_cb,
                            container_req_cb,
                            err_cb::<ContainersReq>);

        ffi_string_free(encoded_cont_req);
    }

    let cont_req = unwrap!(unwrap!(rx.recv())).0;

    let result_str = unsafe {
        unwrap!(call_1(|ud, cb| {
                           encode_containers_resp(authenticator, cont_req, req_id, true, ud, cb)
                       }))
    };

    let (tx, rx) = mpsc::channel::<Result<(), i32>>();

    unsafe {
        app_ipc::decode_ipc_msg(result_str,
                                sender_as_user_data(&tx),
                                auth_granted_cb,
                                app_container_req_cb,
                                revoked_cb,
                                app_err_cb::<()>);

        ffi_string_free(result_str);
    }

    // We should get Ok(()) as a result
    unwrap!(unwrap!(rx.recv()));

    // Try to update an entry again, now that the app has
    // required permissions
    let res =
        unsafe { call_0(|ud, cb| mdata_mutate_entries(app, md_info_h, upd_actions_h, ud, cb)) };
    unsafe { unwrap!(call_0(|ud, cb| mdata_entry_actions_free(app, upd_actions_h, ud, cb))) }

    match res {
        Ok(()) => (),
        Err(x) => panic!("Unexpected {:?}", x),
    }

    unsafe {
        authenticator_free(authenticator);
        app_free(app);
    }
}

extern "C" fn auth_req_cb(user_data: *mut c_void, _req_id: u32, req: AuthReq) {
    unsafe {
        send_via_user_data(user_data, Ok::<SendWrapper<AuthReq>, i32>(SendWrapper(req)));
    }
}

extern "C" fn auth_granted_cb(user_data: *mut c_void, _req_id: u32, auth_granted: AuthGranted) {
    unsafe {
        send_via_user_data(user_data,
                           Ok::<SendWrapper<AuthGranted>, i32>(SendWrapper(auth_granted)));
    }
}

extern "C" fn revoked_cb(_user_data: *mut c_void) {}

extern "C" fn container_req_cb(user_data: *mut c_void, _req_id: u32, cont_req: ContainersReq) {
    unsafe {
        send_via_user_data(user_data,
                           Ok::<SendWrapper<ContainersReq>, i32>(SendWrapper(cont_req)));
    }
}

extern "C" fn app_container_req_cb(user_data: *mut c_void, _req_id: u32) {
    unsafe { send_via_user_data(user_data, Ok::<(), i32>(())) }
}

extern "C" fn err_cb<T>(user_data: *mut c_void, err_code: i32, _err: FfiString) {
    unsafe {
        send_via_user_data(user_data, Err::<SendWrapper<T>, i32>(err_code));
    }
}

extern "C" fn app_err_cb<T>(user_data: *mut c_void, err_code: i32, _req_id: u32) {
    unsafe {
        send_via_user_data(user_data, Err::<SendWrapper<T>, i32>(err_code));
    }
}

unsafe extern "C" fn network_cb(_user_data: *mut c_void, _err_code: i32, _event: i32) {}

fn create_authenticator() -> *mut Authenticator {
    let locator = FfiString::from_string(unwrap!(utils::generate_random_string(10)));
    let password = FfiString::from_string(unwrap!(utils::generate_random_string(10)));
    let mut handle: *mut Authenticator = ptr::null_mut();

    unsafe {
        assert_eq!(create_acc(locator, password, &mut handle, ptr::null_mut(), network_cb),
                   0);
    }

    handle
}
