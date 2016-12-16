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

//! FFI for mutable data permissions and permission sets.

use App;
use errors::AppError;
use ffi::helper::send_sync;
use ffi_utils::{OpaqueCtx, catch_unwind_cb};
use object_cache::{MDataPermissionSetHandle, MDataPermissionsHandle, SignKeyHandle};
use routing::{Action, PermissionSet};
use std::os::raw::c_void;

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

/// Create new permission set.
#[no_mangle]
pub unsafe extern "C" fn mdata_permission_set_new(app: *const App,
                                                  user_data: *mut c_void,
                                                  o_cb: extern "C" fn(*mut c_void,
                                                                      i32,
                                                                      MDataPermissionSetHandle)) {
    catch_unwind_cb(user_data, o_cb, || {
        send_sync(app, user_data, o_cb, |context| {
            Ok(context.object_cache().insert_mdata_permission_set(PermissionSet::new()))
        })
    })
}

/// Allow the action in the permission set.
#[no_mangle]
pub unsafe extern "C" fn mdata_permissions_set_allow(app: *const App,
                                                     set_h: MDataPermissionSetHandle,
                                                     action: MDataAction,
                                                     user_data: *mut c_void,
                                                     o_cb: extern "C" fn(*mut c_void, i32)) {
    catch_unwind_cb(user_data, o_cb, || {
        send_sync(app, user_data, o_cb, move |context| {
            let mut set = context.object_cache().get_mdata_permission_set(set_h)?;
            let _ = set.allow(action.into());
            Ok(())
        })
    })
}

/// Deny the action in the permission set.
#[no_mangle]
pub unsafe extern "C" fn mdata_permissions_set_deny(app: *const App,
                                                    set_h: MDataPermissionSetHandle,
                                                    action: MDataAction,
                                                    user_data: *mut c_void,
                                                    o_cb: extern "C" fn(*mut c_void, i32)) {
    catch_unwind_cb(user_data, o_cb, || {
        send_sync(app, user_data, o_cb, move |context| {
            let mut set = context.object_cache().get_mdata_permission_set(set_h)?;
            let _ = set.deny(action.into());
            Ok(())
        })
    })
}

/// Clear the actions in the permission set.
#[no_mangle]
pub unsafe extern "C" fn mdata_permissions_set_clear(app: *const App,
                                                     set_h: MDataPermissionSetHandle,
                                                     action: MDataAction,
                                                     user_data: *mut c_void,
                                                     o_cb: extern "C" fn(*mut c_void, i32)) {
    catch_unwind_cb(user_data, o_cb, || {
        send_sync(app, user_data, o_cb, move |context| {
            let mut set = context.object_cache().get_mdata_permission_set(set_h)?;
            let _ = set.clear(action.into());
            Ok(())
        })
    })
}

/// Free the permission set from memory.
#[no_mangle]
pub unsafe extern "C" fn mdata_permissions_set_free(app: *const App,
                                                    set_h: MDataPermissionSetHandle,
                                                    user_data: *mut c_void,
                                                    o_cb: extern "C" fn(*mut c_void, i32)) {
    catch_unwind_cb(user_data, o_cb, || {
        send_sync(app, user_data, o_cb, move |context| {
            let _ = context.object_cache().remove_mdata_permission_set(set_h)?;
            Ok(())
        })
    })
}

/// Create new permissions.
#[no_mangle]
pub unsafe extern "C" fn mdata_permissions_new(app: *const App,
                                               user_data: *mut c_void,
                                               o_cb: extern "C" fn(*mut c_void,
                                                                   i32,
                                                                   MDataPermissionsHandle)) {
    catch_unwind_cb(user_data, o_cb, || {
        send_sync(app,
                  user_data,
                  o_cb,
                  |context| Ok(context.object_cache().insert_mdata_permissions(Default::default())))
    })
}

/// Get the number of entries in the permissions.
#[no_mangle]
pub unsafe extern "C" fn mdata_permissions_len(app: *const App,
                                               permissions_h: MDataPermissionsHandle,
                                               user_data: *mut c_void,
                                               o_cb: extern "C" fn(*mut c_void, i32, usize)) {
    catch_unwind_cb(user_data, o_cb, || {
        send_sync(app, user_data, o_cb, move |context| {
            let permissions = context.object_cache().get_mdata_permissions(permissions_h)?;
            Ok(permissions.len())
        })
    })
}

/// Get the permission set corresponding to the given user (0 means anyone).
#[no_mangle]
pub unsafe extern "C" fn mdata_permissions_get(app: *const App,
                                               permissions_h: MDataPermissionsHandle,
                                               user_h: SignKeyHandle,
                                               user_data: *mut c_void,
                                               o_cb: extern "C" fn(*mut c_void,
                                                                   i32,
                                                                   MDataPermissionSetHandle)) {
    catch_unwind_cb(user_data, o_cb, || {
        send_sync(app, user_data, o_cb, move |context| {
            let permissions = context.object_cache().get_mdata_permissions(permissions_h)?;
            let handle = *permissions.get(&user_h).ok_or(AppError::InvalidSignKeyHandle)?;

            Ok(handle)
        })
    })
}

/// Iterate over the permissions.
/// The `each_cb` is called for each (user, permission set) pair in the permissions.
/// The `done_cb` is called after the iterations is over, or in case of error.
#[no_mangle]
pub unsafe extern "C"
fn mdata_permissions_for_each(app: *const App,
                              permissions_h: MDataPermissionsHandle,
                              each_cb: extern "C" fn(*mut c_void,
                                                            SignKeyHandle,
                                                            MDataPermissionSetHandle),
                              user_data: *mut c_void,
                              done_cb: extern "C" fn(*mut c_void, i32)) {
    catch_unwind_cb(user_data, done_cb, || {
        let user_data = OpaqueCtx(user_data);

        send_sync(app, user_data.0, done_cb, move |context| {
            let permissions = context.object_cache().get_mdata_permissions(permissions_h)?;
            for (user_h, permission_set_h) in &*permissions {
                each_cb(user_data.0, *user_h, *permission_set_h);
            }

            Ok(())
        })
    })
}

/// Insert permission set for the given user to the permissions.
///
/// To insert permissions for "Anyone", pass 0 as the user handle.
#[no_mangle]
pub unsafe extern "C" fn mdata_permissions_insert(app: *const App,
                                                  permissions_h: MDataPermissionsHandle,
                                                  user_h: SignKeyHandle,
                                                  permission_set_h: MDataPermissionSetHandle,
                                                  user_data: *mut c_void,
                                                  o_cb: extern "C" fn(*mut c_void, i32)) {
    catch_unwind_cb(user_data, o_cb, || {
        send_sync(app, user_data, o_cb, move |context| {
            let mut permissions = context.object_cache().get_mdata_permissions(permissions_h)?;
            let _ = permissions.insert(user_h, permission_set_h);

            Ok(())
        })
    })
}

/// Free the permissions from memory.
#[no_mangle]
pub unsafe extern "C" fn mdata_permissions_free(app: *const App,
                                                permissions_h: MDataPermissionsHandle,
                                                user_data: *mut c_void,
                                                o_cb: extern "C" fn(*mut c_void, i32)) {
    catch_unwind_cb(user_data, o_cb, || {
        send_sync(app, user_data, o_cb, move |context| {
            let _ = context.object_cache().remove_mdata_permissions(permissions_h)?;
            Ok(())
        })
    })
}
