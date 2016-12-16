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

use ::App;
use ffi_utils::{FfiString, OpaqueCtx, catch_unwind_cb};
use futures::Future;
use object_cache::MDataInfoHandle;
use safe_core::FutureExt;
use safe_core::ipc::req::ffi::Permission;
use std::os::raw::c_void;

/// Fetch access info from the network.
#[no_mangle]
pub unsafe extern "C" fn access_container_refresh_access_info(app: *const App,
                                                              user_data: *mut c_void,
                                                              o_cb: extern "C" fn(*mut c_void,
                                                                                  i32)) {
    catch_unwind_cb(user_data, o_cb, || {
        let user_data = OpaqueCtx(user_data);

        (*app).send(move |client, context| {
            context.refresh_access_info(client)
                .then(move |res| {
                    o_cb(user_data.0, ffi_result_code!(res));
                    Ok(())
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
                                             name: FfiString,
                                             user_data: *mut c_void,
                                             o_cb: extern "C" fn(*mut c_void,
                                                                 i32,
                                                                 MDataInfoHandle)) {
    catch_unwind_cb(user_data, o_cb, || {
        let user_data = OpaqueCtx(user_data);
        let name = name.to_string()?;

        (*app).send(move |client, context| {
            let context = context.clone();

            context.get_container_mdata_info(client, name)
                .map(move |info| {
                    let handle = context.object_cache().insert_mdata_info(info);
                    o_cb(user_data.0, 0, handle);
                })
                .map_err(move |err| o_cb(user_data.0, ffi_error_code!(err), 0))
                .into_box()
                .into()
        })
    })
}

/// Check whether the app has the given permission for the given container.
#[no_mangle]
pub unsafe extern "C" fn access_container_is_permitted(app: *const App,
                                                       name: FfiString,
                                                       permission: Permission,
                                                       user_data: *mut c_void,
                                                       o_cb: extern "C" fn(*mut c_void,
                                                                           i32,
                                                                           bool)) {
    catch_unwind_cb(user_data, o_cb, || {
        let user_data = OpaqueCtx(user_data);
        let name = name.to_string()?;

        (*app).send(move |client, context| {
            context.is_permitted(client, name, permission)
                .map(move |answer| o_cb(user_data.0, 0, answer))
                .map_err(move |err| o_cb(user_data.0, ffi_error_code!(err), false))
                .into_box()
                .into()
        })
    })
}
