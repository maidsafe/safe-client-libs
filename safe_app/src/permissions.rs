// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

//! Permissions utilities

use ffi::mutable_data::permissions::UserPermissionSet as FfiUserPermissionSet;
use ffi::object_cache::SignPubKeyHandle;
use ffi_utils::ReprC;
use routing::PermissionSet;
use safe_core::ipc::req::{permission_set_clone_from_repr_c, permission_set_into_repr_c};
use safe_core::ipc::IpcError;

/// Object representing a (User, Permission Set) pair.
#[derive(Copy, Clone, Default, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct UserPermissionSet {
    /// User's sign key handle.
    pub user_h: SignPubKeyHandle,
    /// User's permission set.
    pub perm_set: PermissionSet,
}

impl UserPermissionSet {
    /// Construct FFI wrapper for the native Rust object, consuming self.
    pub fn into_repr_c(self) -> FfiUserPermissionSet {
        FfiUserPermissionSet {
            user_h: self.user_h,
            perm_set: permission_set_into_repr_c(self.perm_set),
        }
    }
}

impl ReprC for UserPermissionSet {
    type C = *const FfiUserPermissionSet;
    type Error = IpcError;

    #[allow(unsafe_code)]
    unsafe fn clone_from_repr_c(repr_c: Self::C) -> Result<Self, Self::Error> {
        let FfiUserPermissionSet { user_h, perm_set } = *repr_c;

        Ok(Self {
            user_h,
            perm_set: permission_set_clone_from_repr_c(perm_set)?,
        })
    }
}
