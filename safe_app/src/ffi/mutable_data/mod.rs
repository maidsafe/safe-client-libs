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

pub mod entry_actions;
pub mod entries;
pub mod permissions;
mod helper;
#[cfg(test)]
mod tests;

use App;
use errors::AppError;
use ffi::helper::send_with_mdata_info;
use ffi_utils::{FFI_RESULT_OK, FfiResult, OpaqueCtx, SafePtr, catch_unwind_cb,
                vec_clone_from_raw_parts};
use futures::Future;
use object_cache::{MDataEntriesHandle, MDataEntryActionsHandle, MDataInfoHandle, MDataKeysHandle,
                   MDataPermissionSetHandle, MDataPermissionsHandle, MDataValuesHandle,
                   SignKeyHandle};
use routing::MutableData;
use safe_core::{CoreError, FutureExt};
use std::os::raw::c_void;
use std::ptr;

/// Special value that represents an empty permission set.
#[no_mangle]
pub static PERMISSIONS_EMPTY: u64 = 0;

/// Special value that represents an empty entry set.
#[no_mangle]
pub static ENTRIES_EMPTY: u64 = 0;

/// Create new mutable data and put it on the network.
///
/// `permissions_h` is a handle to permissions to be set on the mutable data.
/// If `PERMISSIONS_EMPTY`, the permissions will be empty.
///
/// `entries_h` is a handle to entries for the mutable data.
/// If `ENTRIES_EMPTY`, the entries will be empty.
#[no_mangle]
pub unsafe extern "C" fn mdata_put(app: *const App,
                                   info_h: MDataInfoHandle,
                                   permissions_h: MDataPermissionsHandle,
                                   entries_h: MDataEntriesHandle,
                                   user_data: *mut c_void,
                                   o_cb: extern "C" fn(*mut c_void, FfiResult)) {
    catch_unwind_cb(user_data, o_cb, || {
        let user_data = OpaqueCtx(user_data);

        (*app).send(move |client, context| {
            let info = try_cb!(context.object_cache().get_mdata_info(info_h),
                               user_data,
                               o_cb);
            let owner_key = try_cb!(client.owner_key().map_err(AppError::from), user_data, o_cb);

            let permissions = if permissions_h != 0 {
                try_cb!(helper::get_permissions(context.object_cache(), permissions_h),
                        user_data,
                        o_cb)
            } else {
                Default::default()
            };

            let entries = if entries_h != 0 {
                try_cb!(context.object_cache().get_mdata_entries(entries_h),
                        user_data,
                        o_cb)
                        .clone()
            } else {
                Default::default()
            };

            let data = try_cb!(MutableData::new(info.name,
                                                info.type_tag,
                                                permissions,
                                                entries,
                                                btree_set![owner_key])
                                       .map_err(CoreError::from)
                                       .map_err(AppError::from),
                               user_data,
                               o_cb);

            client
                .put_mdata(data)
                .map_err(AppError::from)
                .then(move |result| {
                    let (error_code, description) = ffi_result!(result);
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

/// Get version of the mutable data.
#[no_mangle]
pub unsafe extern "C" fn mdata_get_version(app: *const App,
                                           info_h: MDataInfoHandle,
                                           user_data: *mut c_void,
                                           o_cb: extern "C" fn(*mut c_void, FfiResult, u64)) {
    catch_unwind_cb(user_data, o_cb, || {
        send_with_mdata_info(app,
                             info_h,
                             user_data,
                             o_cb,
                             |client, _, info| client.get_mdata_version(info.name, info.type_tag))
    })
}

/// Get size of serialised mutable data.
#[no_mangle]
pub unsafe extern "C" fn mdata_serialised_size(app: *const App,
                                               info_h: MDataInfoHandle,
                                               user_data: *mut c_void,
                                               o_cb: extern "C" fn(*mut c_void, FfiResult, u64)) {
    catch_unwind_cb(user_data, o_cb, || {
        send_with_mdata_info(app, info_h, user_data, o_cb, |client, _, info| {
            client
                .get_mdata(info.name, info.type_tag)
                .map_err(AppError::from)
                .and_then(move |mdata| Ok(mdata.serialised_size()))
        })
    })
}

/// Get value at the given key from the mutable data.
/// The arguments to the callback are:
///     1. user data
///     2. error code
///     3. pointer to content
///     4. content length
///     5. entry version
///
/// Please notice that if a value is fetched from a private `MutableData`,
/// it's not automatically decrypted.
#[no_mangle]
pub unsafe extern "C" fn mdata_get_value(app: *const App,
                                         info_h: MDataInfoHandle,
                                         key_ptr: *const u8,
                                         key_len: usize,
                                         user_data: *mut c_void,
                                         o_cb: extern "C" fn(*mut c_void,
                                                             FfiResult,
                                                             *const u8,
                                                             usize,
                                                             u64)) {
    catch_unwind_cb(user_data, o_cb, || {
        let user_data = OpaqueCtx(user_data);
        let key = vec_clone_from_raw_parts(key_ptr, key_len);

        (*app).send(move |client, context| {
            let info = try_cb!(context.object_cache().get_mdata_info(info_h),
                               user_data,
                               o_cb);
            let info = info.clone();

            client
                .get_mdata_value(info.name, info.type_tag, key)
                .and_then(move |value| Ok((value.content, value.entry_version)))
                .map(move |(content, version)| {
                         o_cb(user_data.0,
                              FFI_RESULT_OK,
                              content.as_safe_ptr(),
                              content.len(),
                              version);
                     })
                .map_err(AppError::from)
                .map_err(move |err| {
                    let (error_code, description) = ffi_error!(err);
                    o_cb(user_data.0,
                         FfiResult {
                             error_code,
                             description: description.as_ptr(),
                         },
                         ptr::null(),
                         0,
                         0)
                })
                .into_box()
                .into()
        })
    })
}

/// Get complete list of entries in the mutable data.
#[no_mangle]
pub unsafe extern "C" fn mdata_list_entries(app: *const App,
                                            info_h: MDataInfoHandle,
                                            user_data: *mut c_void,
                                            o_cb: extern "C" fn(*mut c_void,
                                                                FfiResult,
                                                                MDataEntriesHandle)) {
    catch_unwind_cb(user_data, o_cb, || {
        send_with_mdata_info(app, info_h, user_data, o_cb, move |client, context, info| {
            let context = context.clone();
            let info = info.clone();

            client
                .list_mdata_entries(info.name, info.type_tag)
                .map_err(AppError::from)
                .and_then(move |entries| Ok(context.object_cache().insert_mdata_entries(entries)))
        })
    })
}

/// Get list of keys in the mutable data.
#[no_mangle]
pub unsafe extern "C" fn mdata_list_keys(app: *const App,
                                         info_h: MDataInfoHandle,
                                         user_data: *mut c_void,
                                         o_cb: extern "C" fn(*mut c_void,
                                                             FfiResult,
                                                             MDataKeysHandle)) {
    catch_unwind_cb(user_data, o_cb, || {
        send_with_mdata_info(app, info_h, user_data, o_cb, move |client, context, info| {
            let context = context.clone();
            let info = info.clone();

            client
                .list_mdata_keys(info.name, info.type_tag)
                .map_err(AppError::from)
                .and_then(move |keys| Ok(context.object_cache().insert_mdata_keys(keys)))
        })
    })
}

/// Get list of values in the mutable data.
#[no_mangle]
pub unsafe extern "C" fn mdata_list_values(app: *const App,
                                           info_h: MDataInfoHandle,
                                           user_data: *mut c_void,
                                           o_cb: extern "C" fn(*mut c_void,
                                                               FfiResult,
                                                               MDataValuesHandle)) {
    catch_unwind_cb(user_data, o_cb, || {
        send_with_mdata_info(app, info_h, user_data, o_cb, move |client, context, info| {
            let context = context.clone();
            let info = info.clone();

            client
                .list_mdata_values(info.name, info.type_tag)
                .map_err(AppError::from)
                .and_then(move |values| Ok(context.object_cache().insert_mdata_values(values)))
        })
    })
}

/// Mutate entries of the mutable data.
#[no_mangle]
pub unsafe fn mdata_mutate_entries(app: *const App,
                                   info_h: MDataInfoHandle,
                                   actions_h: MDataEntryActionsHandle,
                                   user_data: *mut c_void,
                                   o_cb: extern "C" fn(*mut c_void, FfiResult)) {
    catch_unwind_cb(user_data, o_cb, || {
        let user_data = OpaqueCtx(user_data);

        (*app).send(move |client, context| {
            let info = try_cb!(context.object_cache().get_mdata_info(info_h),
                               user_data,
                               o_cb);
            let actions = try_cb!(context.object_cache().get_mdata_entry_actions(actions_h),
                                  user_data,
                                  o_cb);
            client
                .mutate_mdata_entries(info.name, info.type_tag, actions.clone())
                .map_err(AppError::from)
                .then(move |result| {
                    let (error_code, description) = ffi_result!(result);
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

/// Get list of all permissions set on the mutable data
#[no_mangle]
pub unsafe fn mdata_list_permissions(app: *const App,
                                     info_h: MDataInfoHandle,
                                     user_data: *mut c_void,
                                     o_cb: extern "C" fn(*mut c_void,
                                                         FfiResult,
                                                         MDataPermissionsHandle)) {
    catch_unwind_cb(user_data, o_cb, || {
        send_with_mdata_info(app, info_h, user_data, o_cb, move |client, context, info| {
            let context = context.clone();
            client
                .list_mdata_permissions(info.name, info.type_tag)
                .map(move |perms| helper::insert_permissions(context.object_cache(), perms))
        })
    })
}

/// Get list of permissions set on the mutable data for the given user.
///
/// User is either handle to a signing key or `USER_ANYONE`.
#[no_mangle]
pub unsafe fn mdata_list_user_permissions(app: *const App,
                                          info_h: MDataInfoHandle,
                                          user_h: SignKeyHandle,
                                          user_data: *mut c_void,
                                          o_cb: extern "C" fn(*mut c_void,
                                                              FfiResult,
                                                              MDataPermissionSetHandle)) {
    catch_unwind_cb(user_data, o_cb, || {
        let user_data = OpaqueCtx(user_data);

        (*app).send(move |client, context| {
            let info = try_cb!(context.object_cache().get_mdata_info(info_h),
                               user_data,
                               o_cb);
            let user = try_cb!(helper::get_user(context.object_cache(), user_h),
                               user_data,
                               o_cb);

            let context = context.clone();

            client
                .list_mdata_user_permissions(info.name, info.type_tag, user)
                .map(move |set| {
                         let handle = context.object_cache().insert_mdata_permission_set(set);
                         o_cb(user_data.0, FFI_RESULT_OK, handle);
                     })
                .map_err(AppError::from)
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

/// Set permissions set on the mutable data for the given user.
///
/// User is either handle to a signing key or `USER_ANYONE`.
#[no_mangle]
pub unsafe fn mdata_set_user_permissions(app: *const App,
                                         info_h: MDataInfoHandle,
                                         user_h: SignKeyHandle,
                                         permission_set_h: MDataPermissionSetHandle,
                                         version: u64,
                                         user_data: *mut c_void,
                                         o_cb: extern "C" fn(*mut c_void, FfiResult)) {
    catch_unwind_cb(user_data, o_cb, || {
        let user_data = OpaqueCtx(user_data);

        (*app).send(move |client, context| {
            let info = try_cb!(context.object_cache().get_mdata_info(info_h),
                               user_data,
                               o_cb);
            let user = try_cb!(helper::get_user(context.object_cache(), user_h),
                               user_data,
                               o_cb);
            let permission_set = *try_cb!(context
                                              .object_cache()
                                              .get_mdata_permission_set(permission_set_h),
                                          user_data,
                                          o_cb);

            client
                .set_mdata_user_permissions(info.name, info.type_tag, user, permission_set, version)
                .map_err(AppError::from)
                .then(move |result| {
                    let (error_code, description) = ffi_result!(result);
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

/// Delete permissions set on the mutable data for the given user.
///
/// User is either handle to a signing key or `USER_ANYONE`.
#[no_mangle]
pub unsafe fn mdata_del_user_permissions(app: *const App,
                                         info_h: MDataInfoHandle,
                                         user_h: SignKeyHandle,
                                         version: u64,
                                         user_data: *mut c_void,
                                         o_cb: extern "C" fn(*mut c_void, FfiResult)) {
    catch_unwind_cb(user_data, o_cb, || {
        let user_data = OpaqueCtx(user_data);

        (*app).send(move |client, context| {
            let info = try_cb!(context.object_cache().get_mdata_info(info_h),
                               user_data,
                               o_cb);
            let user = try_cb!(helper::get_user(context.object_cache(), user_h),
                               user_data,
                               o_cb);

            client
                .del_mdata_user_permissions(info.name, info.type_tag, user, version)
                .map_err(AppError::from)
                .then(move |result| {
                    let (error_code, description) = ffi_result!(result);
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

/// Change owner of the mutable data.
#[no_mangle]
pub unsafe extern "C" fn mdata_change_owner(app: *const App,
                                            info_h: MDataInfoHandle,
                                            new_owner_h: SignKeyHandle,
                                            version: u64,
                                            user_data: *mut c_void,
                                            o_cb: extern "C" fn(*mut c_void, FfiResult)) {
    catch_unwind_cb(user_data, o_cb, || {
        let user_data = OpaqueCtx(user_data);

        (*app).send(move |client, context| {
            let info = try_cb!(context.object_cache().get_mdata_info(info_h),
                               user_data,
                               o_cb);
            let new_owner = *try_cb!(context.object_cache().get_sign_key(new_owner_h),
                                     user_data,
                                     o_cb);

            client
                .change_mdata_owner(info.name, info.type_tag, new_owner, version)
                .map_err(AppError::from)
                .then(move |result| {
                    let (error_code, description) = ffi_result!(result);
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
