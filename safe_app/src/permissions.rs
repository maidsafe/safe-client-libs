// Copyright 2017 MaidSafe.net limited.
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

//! Permissions utilities

use ffi::mutable_data::permissions::UserPermissionSet as FfiUserPermissionSet;
use ffi::object_cache::SignPubKeyHandle;
use ffi_utils::ReprC;
use routing::PermissionSet;
use safe_core::ipc::IpcError;
use safe_core::ipc::req::{permission_set_clone_from_repr_c, permission_set_into_repr_c};

/// Object representing a (User, Permission Set) pair.
#[derive(Copy, Clone, Default, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct UserPermissionSet {
    /// User's sign key handle.
    pub user_h: SignPubKeyHandle,
    /// User's permission set.
    pub perm_set: PermissionSet,
}

impl UserPermissionSet {
    /// Consumes the object and returns the FFI counterpart.
    ///
    /// You're now responsible for freeing the object's memory once you're done.
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
    unsafe fn clone_from_repr_c(c_repr: Self::C) -> Result<Self, Self::Error> {
        let FfiUserPermissionSet { user_h, perm_set } = *c_repr;

        Ok(UserPermissionSet {
            user_h: user_h,
            perm_set: permission_set_clone_from_repr_c(&perm_set)?,
        })
    }
}
