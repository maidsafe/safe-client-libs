// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

//! FFI for mutable data permissions and permission sets.

use errors::AppError;
use ffi::helper::send_sync;
use ffi::mutable_data::helper;
use ffi::object_cache::{MDataPermissionsHandle, SignPubKeyHandle, NULL_OBJECT_HANDLE};
use ffi_utils::{catch_unwind_cb, FfiResult, OpaqueCtx, SafePtr, FFI_RESULT_OK};
use permissions;
use routing::User;
use safe_core::ffi::ipc::req::PermissionSet;
use safe_core::ipc::req::{permission_set_clone_from_repr_c, permission_set_into_repr_c};
use std::os::raw::c_void;
use App;

/// Special value that represents `User::Anyone` in permission sets.
#[no_mangle]
pub static USER_ANYONE: SignPubKeyHandle = NULL_OBJECT_HANDLE;

/// FFI object representing a (User, Permission Set) pair.
#[repr(C)]
pub struct UserPermissionSet {
    /// User's sign key handle.
    pub user_h: SignPubKeyHandle,
    /// User's permission set.
    pub perm_set: PermissionSet,
}

/// Create new permissions.
#[no_mangle]
pub unsafe extern "C" fn mdata_permissions_new(
    app: *const App,
    user_data: *mut c_void,
    o_cb: extern "C" fn(
        user_data: *mut c_void,
        result: *const FfiResult,
        perm_h: MDataPermissionsHandle,
    ),
) {
    catch_unwind_cb(user_data, o_cb, || {
        send_sync(app, user_data, o_cb, |_, context| {
            Ok(context
                .object_cache()
                .insert_mdata_permissions(Default::default()))
        })
    })
}

/// Get the number of entries in the permissions.
#[no_mangle]
pub unsafe extern "C" fn mdata_permissions_len(
    app: *const App,
    permissions_h: MDataPermissionsHandle,
    user_data: *mut c_void,
    o_cb: extern "C" fn(user_data: *mut c_void, result: *const FfiResult, size: usize),
) {
    catch_unwind_cb(user_data, o_cb, || {
        send_sync(app, user_data, o_cb, move |_, context| {
            let permissions = context
                .object_cache()
                .get_mdata_permissions(permissions_h)?;
            Ok(permissions.len())
        })
    })
}

/// Get the permission set corresponding to the given user.
///
/// User is either handle to a signing key or `USER_ANYONE`.
#[no_mangle]
pub unsafe extern "C" fn mdata_permissions_get(
    app: *const App,
    permissions_h: MDataPermissionsHandle,
    user_h: SignPubKeyHandle,
    user_data: *mut c_void,
    o_cb: extern "C" fn(
        user_data: *mut c_void,
        result: *const FfiResult,
        perm_set: *const PermissionSet,
    ),
) {
    catch_unwind_cb(user_data, o_cb, || {
        let user_data = OpaqueCtx(user_data);

        (*app).send(move |_, context| {
            let permissions = try_cb!(
                context.object_cache().get_mdata_permissions(permissions_h),
                user_data,
                o_cb
            );
            let user = try_cb!(
                helper::get_user(context.object_cache(), user_h),
                user_data,
                o_cb
            );

            let permission_set = *try_cb!(
                permissions
                    .get(&user,)
                    .ok_or(AppError::InvalidSignPubKeyHandle,),
                user_data,
                o_cb
            );
            let permission_set = permission_set_into_repr_c(permission_set);

            o_cb(user_data.0, FFI_RESULT_OK, &permission_set);
            None
        })
    })
}

/// Return each (user, permission set) pair in the permissions.
#[no_mangle]
pub unsafe extern "C" fn mdata_list_permission_sets(
    app: *const App,
    permissions_h: MDataPermissionsHandle,
    user_data: *mut c_void,
    o_cb: extern "C" fn(
        user_data: *mut c_void,
        result: *const FfiResult,
        user_perm_sets: *const UserPermissionSet,
        user_perm_sets_len: usize,
    ),
) {
    let user_data = OpaqueCtx(user_data);

    catch_unwind_cb(user_data, o_cb, || {
        (*app).send(move |_, context| {
            let permissions = try_cb!(
                context.object_cache().get_mdata_permissions(permissions_h),
                user_data,
                o_cb
            );
            let user_perm_sets: Vec<UserPermissionSet> = permissions
                .iter()
                .map(|(user_key, permission_set)| {
                    let user_h = match *user_key {
                        User::Key(key) => context.object_cache().insert_pub_sign_key(key),
                        User::Anyone => USER_ANYONE,
                    };
                    permissions::UserPermissionSet {
                        user_h,
                        perm_set: *permission_set,
                    }.into_repr_c()
                }).collect();

            o_cb(
                user_data.0,
                FFI_RESULT_OK,
                user_perm_sets.as_safe_ptr(),
                user_perm_sets.len(),
            );

            None
        })
    })
}

/// Insert permission set for the given user to the permissions.
///
/// User is either handle to a signing key or `USER_ANYONE`.
#[no_mangle]
pub unsafe extern "C" fn mdata_permissions_insert(
    app: *const App,
    permissions_h: MDataPermissionsHandle,
    user_h: SignPubKeyHandle,
    permission_set: *const PermissionSet,
    user_data: *mut c_void,
    o_cb: extern "C" fn(user_data: *mut c_void, result: *const FfiResult),
) {
    catch_unwind_cb(user_data, o_cb, || {
        let permission_set = *permission_set;

        send_sync(app, user_data, o_cb, move |_, context| {
            let mut permissions = context
                .object_cache()
                .get_mdata_permissions(permissions_h)?;
            let _ = permissions.insert(
                helper::get_user(context.object_cache(), user_h)?,
                permission_set_clone_from_repr_c(permission_set)?,
            );

            Ok(())
        })
    })
}

/// Free the permissions from memory.
#[no_mangle]
pub unsafe extern "C" fn mdata_permissions_free(
    app: *const App,
    permissions_h: MDataPermissionsHandle,
    user_data: *mut c_void,
    o_cb: extern "C" fn(user_data: *mut c_void, result: *const FfiResult),
) {
    catch_unwind_cb(user_data, o_cb, || {
        send_sync(app, user_data, o_cb, move |_, context| {
            let _ = context
                .object_cache()
                .remove_mdata_permissions(permissions_h)?;
            Ok(())
        })
    })
}
