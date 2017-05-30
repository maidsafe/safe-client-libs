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

use App;
use ffi_utils::{FFI_RESULT_OK, FfiResult, OpaqueCtx, SafePtr, catch_unwind_cb, from_c_str};
use futures::Future;
use object_cache::MDataInfoHandle;
use safe_core::FutureExt;
use safe_core::ipc::req::ffi::Permission;
use std::ffi::CString;
use std::os::raw::{c_char, c_void};
use std::ptr;

/// Fetch access info from the network.
#[no_mangle]
pub unsafe extern "C" fn access_container_refresh_access_info(app: *const App,
                                                              user_data: *mut c_void,
                                                              o_cb: extern "C" fn(*mut c_void,
                                                                                  FfiResult)) {
    catch_unwind_cb(user_data, o_cb, || {
        let user_data = OpaqueCtx(user_data);

        (*app).send(move |client, context| {
            context
                .refresh_access_info(client)
                .then(move |res| {
                    let (error_code, description) = ffi_result!(res);
                    o_cb(user_data.0,
                         FfiResult {
                             error_code,
                             description: description.as_ptr(),
                         });
                    Ok(())
                })
                .into_box()
                .into()
        })
    })
}

/// Retrieve a list of container names that an app has access to.
#[no_mangle]
pub unsafe extern "C" fn access_container_get_names(app: *const App,
                                                    user_data: *mut c_void,
                                                    o_cb: extern "C" fn(*mut c_void,
                                                                        FfiResult,
                                                                        *const *const c_char,
                                                                        u32)) {
    catch_unwind_cb(user_data, o_cb, || {
        let user_data = OpaqueCtx(user_data);

        (*app).send(move |client, context| {
            context
                .get_container_names(client)
                .and_then(move |names| {
                              let mut c_str_vec = Vec::new();
                              for name in names {
                                  c_str_vec.push(CString::new(name)?);
                              }
                              Ok(c_str_vec)
                          })
                .map(move |c_str_vec| {
                         let ptr_vec: Vec<*const c_char> =
                             c_str_vec.iter().map(|c_string| c_string.as_ptr()).collect();
                         o_cb(user_data.0,
                              FFI_RESULT_OK,
                              ptr_vec.as_safe_ptr(),
                              c_str_vec.len() as u32);
                     })
                .map_err(move |e| {
                    let (error_code, description) = ffi_error!(e);
                    o_cb(user_data.0,
                         FfiResult {
                             error_code,
                             description: description.as_ptr(),
                         },
                         ptr::null(),
                         0);
                })
                .into_box()
                .into()
        })
    })
}

/// Retrieve `MDataInfo` for the given container name from the access container.
#[no_mangle]
pub unsafe extern "C"
fn access_container_get_container_mdata_info(app: *const App,
                                             name: *const c_char,
                                             user_data: *mut c_void,
                                             o_cb: extern "C" fn(*mut c_void,
                                                                 FfiResult,
MDataInfoHandle)){
    catch_unwind_cb(user_data, o_cb, || {
        let user_data = OpaqueCtx(user_data);
        let name = from_c_str(name)?;

        (*app).send(move |client, context| {
            let context = context.clone();

            context
                .get_container_mdata_info(client, name)
                .map(move |info| {
                         let handle = context.object_cache().insert_mdata_info(info);
                         o_cb(user_data.0, FFI_RESULT_OK, handle);
                     })
                .map_err(move |err| {
                    let (error_code, description) = ffi_error!(err);
                    o_cb(user_data.0,
                         FfiResult {
                             error_code,
                             description: description.as_ptr(),
                         },
                         0)
                })
                .into_box()
                .into()
        })
    })
}

/// Check whether the app has the given permission for the given container.
#[no_mangle]
pub unsafe extern "C" fn access_container_is_permitted(app: *const App,
                                                       name: *const c_char,
                                                       permission: Permission,
                                                       user_data: *mut c_void,
                                                       o_cb: extern "C" fn(*mut c_void,
                                                                           FfiResult,
                                                                           bool)) {
    catch_unwind_cb(user_data, o_cb, || {
        let user_data = OpaqueCtx(user_data);
        let name = from_c_str(name)?;

        (*app).send(move |client, context| {
            context
                .is_permitted(client, name, permission)
                .map(move |answer| o_cb(user_data.0, FFI_RESULT_OK, answer))
                .map_err(move |err| {
                    let (error_code, description) = ffi_error!(err);
                    o_cb(user_data.0,
                         FfiResult {
                             error_code,
                             description: description.as_ptr(),
                         },
                         false)
                })
                .into_box()
                .into()
        })
    })
}
