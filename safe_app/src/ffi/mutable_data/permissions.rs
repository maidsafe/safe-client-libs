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

//! FFI for mutable data permissions and permission sets.

use App;
use errors::AppError;
use ffi::helper::send_sync;
use ffi::mutable_data::helper;
use ffi_utils::{FFI_RESULT_OK, FfiResult, OpaqueCtx, SafePtr, catch_unwind_cb};
use object_cache::{MDataPermissionsHandle, NULL_OBJECT_HANDLE, SignKeyHandle};
use permissions;
use routing::{Action, User};
use safe_core::ffi::ipc::req::PermissionSet as FfiPermissionSet;
use safe_core::ipc::req::{permission_set_clone_from_repr_c, permission_set_into_repr_c};
use std::os::raw::c_void;

/// Special value that represents `User::Anyone` in permission sets.
#[no_mangle]
pub static USER_ANYONE: u64 = NULL_OBJECT_HANDLE;

/// Permission actions.
#[repr(C)]
pub enum MDataAction {
    /// Permission to insert new entries.
    Insert,
    /// Permission to update existing entries.
    Update,
    /// Permission to delete existing entries.
    Delete,
    /// Permission to manage permissions.
    ManagePermissions,
}

impl Into<Action> for MDataAction {
    fn into(self) -> Action {
        match self {
            MDataAction::Insert => Action::Insert,
            MDataAction::Update => Action::Update,
            MDataAction::Delete => Action::Delete,
            MDataAction::ManagePermissions => Action::ManagePermissions,
        }
    }
}

/// FFI object representing a (User, Permission Set) pair.
#[repr(C)]
pub struct UserPermissionSet {
    /// User's sign key handle.
    pub user_h: SignKeyHandle,
    /// User's permission set.
    pub perm_set: FfiPermissionSet,
}

/// Create new permissions.
///
/// Callback parameters: user data, error code, permissions handle
#[no_mangle]
pub unsafe extern "C" fn mdata_permissions_new(
    app: *const App,
    user_data: *mut c_void,
    o_cb: extern "C" fn(user_data: *mut c_void,
                        result: FfiResult,
                        perm_h: MDataPermissionsHandle),
) {
    catch_unwind_cb(user_data, o_cb, || {
        send_sync(app, user_data, o_cb, |_, context| {
            Ok(context.object_cache().insert_mdata_permissions(
                Default::default(),
            ))
        })
    })
}

/// Get the number of entries in the permissions.
///
/// Callback parameters: user data, error code, size
#[no_mangle]
pub unsafe extern "C" fn mdata_permissions_len(
    app: *const App,
    permissions_h: MDataPermissionsHandle,
    user_data: *mut c_void,
    o_cb: extern "C" fn(user_data: *mut c_void, result: FfiResult, size: usize),
) {
    catch_unwind_cb(user_data, o_cb, || {
        send_sync(app, user_data, o_cb, move |_, context| {
            let permissions = context.object_cache().get_mdata_permissions(permissions_h)?;
            Ok(permissions.len())
        })
    })
}

/// Get the permission set corresponding to the given user.
/// Use a constant `USER_ANYONE` for anyone.
///
/// Callback parameters: user data, error code, permission set handle
#[no_mangle]
pub unsafe extern "C" fn mdata_permissions_get(
    app: *const App,
    permissions_h: MDataPermissionsHandle,
    user_h: SignKeyHandle,
    user_data: *mut c_void,
    o_cb: extern "C" fn(user_data: *mut c_void,
                        result: FfiResult,
                        perm_set: FfiPermissionSet),
) {
    catch_unwind_cb(user_data, o_cb, || {
        send_sync(app, user_data, o_cb, move |_, context| {
            let permissions = context.object_cache().get_mdata_permissions(permissions_h)?;
            let permission_set = *permissions
                .get(&helper::get_user(context.object_cache(), user_h)?)
                .ok_or(AppError::InvalidSignKeyHandle)?;

            Ok(permission_set_into_repr_c(permission_set))
        })
    })
}

/// Return each (user, permission set) pair in the permissions.
///
/// Callback parameters: user data, error code, vector of user/permission set objects, vector size
#[no_mangle]
pub unsafe extern "C" fn mdata_list_permission_sets(
    app: *const App,
    permissions_h: MDataPermissionsHandle,
    user_data: *mut c_void,
    o_cb: extern "C" fn(user_data: *mut c_void,
                        result: FfiResult,
                        user_perm_sets: *const UserPermissionSet,
                        len: usize),
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
                        User::Key(key) => context.object_cache().insert_sign_key(key),
                        User::Anyone => USER_ANYONE,
                    };
                    permissions::UserPermissionSet {
                        user_h: user_h,
                        perm_set: *permission_set,
                    }.into_repr_c()
                })
                .collect();

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
/// To insert permissions for "Anyone", pass `USER_ANYONE` as the user handle.
///
/// Callback parameters: user data, error code
#[no_mangle]
pub unsafe extern "C" fn mdata_permissions_insert(
    app: *const App,
    permissions_h: MDataPermissionsHandle,
    user_h: SignKeyHandle,
    permission_set: FfiPermissionSet,
    user_data: *mut c_void,
    o_cb: extern "C" fn(user_data: *mut c_void, result: FfiResult),
) {
    catch_unwind_cb(user_data, o_cb, || {
        send_sync(app, user_data, o_cb, move |_, context| {
            let mut permissions = context.object_cache().get_mdata_permissions(permissions_h)?;
            let _ = permissions.insert(
                helper::get_user(context.object_cache(), user_h)?,
                permission_set_clone_from_repr_c(&permission_set)?,
            );

            Ok(())
        })
    })
}

/// Free the permissions from memory.
///
/// Callback parameters: user data, error code
#[no_mangle]
pub unsafe extern "C" fn mdata_permissions_free(
    app: *const App,
    permissions_h: MDataPermissionsHandle,
    user_data: *mut c_void,
    o_cb: extern "C" fn(user_data: *mut c_void, result: FfiResult),
) {
    catch_unwind_cb(user_data, o_cb, || {
        send_sync(app, user_data, o_cb, move |_, context| {
            let _ = context.object_cache().remove_mdata_permissions(
                permissions_h,
            )?;
            Ok(())
        })
    })
}
