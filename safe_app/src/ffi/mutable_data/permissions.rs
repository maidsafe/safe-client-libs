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
use ffi_utils::{FfiResult, OpaqueCtx, ReprC, catch_unwind_cb};
use ffi_utils::callback::CallbackArgs;
use object_cache::{MDataPermissionSetHandle, MDataPermissionsHandle, SignKeyHandle};
use routing::{Action, PermissionSet, User};
use std::os::raw::c_void;

/// Special value that represents `User::Anyone` in permission sets.
#[no_mangle]
pub static USER_ANYONE: u64 = 0;

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

/// State of action in the permission set
#[derive(PartialEq, Debug, Copy, Clone)]
#[repr(C)]
pub enum PermissionValue {
    /// Explicit permission is not set
    NotSet,
    /// Permission is allowed
    Allowed,
    /// Permission is denied
    Denied,
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

/// Create new permission set.
#[no_mangle]
pub unsafe extern "C" fn mdata_permission_set_new(
    app: *const App,
    user_data: *mut c_void,
    o_cb: extern "C" fn(*mut c_void, FfiResult, MDataPermissionSetHandle),
) {
    catch_unwind_cb(user_data, o_cb, || {
        send_sync(app, user_data, o_cb, |_, context| {
            Ok(context.object_cache().insert_mdata_permission_set(
                PermissionSet::new(),
            ))
        })
    })
}

/// Allow the action in the permission set.
#[no_mangle]
pub unsafe extern "C" fn mdata_permissions_set_allow(
    app: *const App,
    set_h: MDataPermissionSetHandle,
    action: MDataAction,
    user_data: *mut c_void,
    o_cb: extern "C" fn(*mut c_void, FfiResult),
) {
    catch_unwind_cb(user_data, o_cb, || {
        send_sync(app, user_data, o_cb, move |_, context| {
            let mut set = context.object_cache().get_mdata_permission_set(set_h)?;
            *set = set.allow(action.into());
            Ok(())
        })
    })
}

/// Deny the action in the permission set.
#[no_mangle]
pub unsafe extern "C" fn mdata_permissions_set_deny(
    app: *const App,
    set_h: MDataPermissionSetHandle,
    action: MDataAction,
    user_data: *mut c_void,
    o_cb: extern "C" fn(*mut c_void, FfiResult),
) {
    catch_unwind_cb(user_data, o_cb, || {
        send_sync(app, user_data, o_cb, move |_, context| {
            let mut set = context.object_cache().get_mdata_permission_set(set_h)?;
            *set = set.deny(action.into());
            Ok(())
        })
    })
}

/// Clear the actions in the permission set.
#[no_mangle]
pub unsafe extern "C" fn mdata_permissions_set_clear(
    app: *const App,
    set_h: MDataPermissionSetHandle,
    action: MDataAction,
    user_data: *mut c_void,
    o_cb: extern "C" fn(*mut c_void, FfiResult),
) {
    catch_unwind_cb(user_data, o_cb, || {
        send_sync(app, user_data, o_cb, move |_, context| {
            let mut set = context.object_cache().get_mdata_permission_set(set_h)?;
            *set = set.clear(action.into());
            Ok(())
        })
    })
}

/// Read the permission set.
#[no_mangle]
pub unsafe extern "C" fn mdata_permissions_set_is_allowed(
    app: *const App,
    set_h: MDataPermissionSetHandle,
    action: MDataAction,
    user_data: *mut c_void,
    o_cb: extern "C" fn(*mut c_void, FfiResult, PermissionValue),
) {
    catch_unwind_cb(user_data, o_cb, || {
        send_sync(app, user_data, o_cb, move |_, context| {
            let set = context.object_cache().get_mdata_permission_set(set_h)?;
            let perm = match action {
                MDataAction::Insert => set.is_allowed(Action::Insert),
                MDataAction::Update => set.is_allowed(Action::Update),
                MDataAction::Delete => set.is_allowed(Action::Delete),
                MDataAction::ManagePermissions => set.is_allowed(Action::ManagePermissions),
            };
            Ok(permission_set_into_permission_value(&perm))
        })
    })
}

/// Free the permission set from memory.
#[no_mangle]
pub unsafe extern "C" fn mdata_permissions_set_free(
    app: *const App,
    set_h: MDataPermissionSetHandle,
    user_data: *mut c_void,
    o_cb: extern "C" fn(*mut c_void, FfiResult),
) {
    catch_unwind_cb(user_data, o_cb, || {
        send_sync(app, user_data, o_cb, move |_, context| {
            let _ = context.object_cache().remove_mdata_permission_set(set_h)?;
            Ok(())
        })
    })
}

/// Create new permissions.
#[no_mangle]
pub unsafe extern "C" fn mdata_permissions_new(
    app: *const App,
    user_data: *mut c_void,
    o_cb: extern "C" fn(*mut c_void, FfiResult, MDataPermissionsHandle),
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
#[no_mangle]
pub unsafe extern "C" fn mdata_permissions_len(
    app: *const App,
    permissions_h: MDataPermissionsHandle,
    user_data: *mut c_void,
    o_cb: extern "C" fn(*mut c_void, FfiResult, usize),
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
#[no_mangle]
pub unsafe extern "C" fn mdata_permissions_get(
    app: *const App,
    permissions_h: MDataPermissionsHandle,
    user_h: SignKeyHandle,
    user_data: *mut c_void,
    o_cb: extern "C" fn(*mut c_void, FfiResult, MDataPermissionSetHandle),
) {
    catch_unwind_cb(user_data, o_cb, || {
        send_sync(app, user_data, o_cb, move |_, context| {
            let permissions = context.object_cache().get_mdata_permissions(permissions_h)?;
            let handle = *permissions
                .get(&helper::get_user(context.object_cache(), user_h)?)
                .ok_or(AppError::InvalidSignKeyHandle)?;

            Ok(handle)
        })
    })
}

/// Iterate over the permissions.
/// The `each_cb` is called for each (user, permission set) pair in the permissions.
/// The `done_cb` is called after the iterations is over, or in case of error.
#[no_mangle]
pub unsafe extern "C" fn mdata_permissions_for_each(
    app: *const App,
    permissions_h: MDataPermissionsHandle,
    each_cb: extern "C" fn(*mut c_void, SignKeyHandle, MDataPermissionSetHandle),
    user_data: *mut c_void,
    done_cb: extern "C" fn(*mut c_void, FfiResult),
) {
    catch_unwind_cb(user_data, done_cb, || {
        let user_data = OpaqueCtx(user_data);

        send_sync(app, user_data.0, done_cb, move |_, context| {
            let permissions = context.object_cache().get_mdata_permissions(permissions_h)?;
            for (user_key, permission_set_h) in &*permissions {
                let user_h = match *user_key {
                    User::Key(key) => context.object_cache().insert_sign_key(key),
                    User::Anyone => USER_ANYONE,
                };
                each_cb(user_data.0, user_h, *permission_set_h);
            }

            Ok(())
        })
    })
}

/// Insert permission set for the given user to the permissions.
///
/// To insert permissions for "Anyone", pass `USER_ANYONE` as the user handle.
#[no_mangle]
pub unsafe extern "C" fn mdata_permissions_insert(
    app: *const App,
    permissions_h: MDataPermissionsHandle,
    user_h: SignKeyHandle,
    permission_set_h: MDataPermissionSetHandle,
    user_data: *mut c_void,
    o_cb: extern "C" fn(*mut c_void, FfiResult),
) {
    catch_unwind_cb(user_data, o_cb, || {
        send_sync(app, user_data, o_cb, move |_, context| {
            let mut permissions = context.object_cache().get_mdata_permissions(permissions_h)?;
            let _ = permissions.insert(
                helper::get_user(context.object_cache(), user_h)?,
                permission_set_h,
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
    o_cb: extern "C" fn(*mut c_void, FfiResult),
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

/// Converts the permission set state into a `PermissionValue` variant
fn permission_set_into_permission_value(val: &Option<bool>) -> PermissionValue {
    match *val {
        Some(true) => PermissionValue::Allowed,
        Some(false) => PermissionValue::Denied,
        None => PermissionValue::NotSet,
    }
}

/// Returns default `PermissionValue` in an error case
impl CallbackArgs for PermissionValue {
    fn default() -> Self {
        PermissionValue::NotSet
    }
}

impl ReprC for PermissionValue {
    type C = PermissionValue;
    type Error = ();

    unsafe fn clone_from_repr_c(c_repr: PermissionValue) -> Result<PermissionValue, ()> {
        Ok(c_repr)
    }
}
