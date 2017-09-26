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

use ffi_utils::ReprC;
use ffi_utils::callback::CallbackArgs;
use ipc::req::permission_set_into_repr_c;
use routing;
use routing::XorName;
use std::ffi::CString;
use std::os::raw::c_char;

/// Represents a requested set of changes to the permissions of a mutable data.
#[repr(C)]
#[derive(Copy, Clone, Default, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct PermissionSet {
    /// How to modify the read permission.
    pub read: bool,
    /// How to modify the insert permission.
    pub insert: bool,
    /// How to modify the update permission.
    pub update: bool,
    /// How to modify the delete permission.
    pub delete: bool,
    /// How to modify the manage permissions permission.
    pub manage_permissions: bool,
}

impl ReprC for PermissionSet {
    type C = PermissionSet;
    type Error = ();

    /// Constructs the object from a raw pointer.
    ///
    /// After calling this function, the raw pointer is owned by the resulting
    /// object.
    unsafe fn clone_from_repr_c(raw: PermissionSet) -> Result<Self, Self::Error> {
        Ok(raw)
    }
}

impl CallbackArgs for PermissionSet {
    fn default() -> Self {
        permission_set_into_repr_c(routing::PermissionSet::new())
    }
}

/// Represents an authorization request
#[repr(C)]
pub struct AuthReq {
    /// The application identifier for this request
    pub app: AppExchangeInfo,
    /// `true` if the app wants dedicated container for itself. `false`
    /// otherwise.
    pub app_container: bool,

    /// Array of `ContainerPermissions`
    pub containers: *const ContainerPermissions,

    /// Size of container permissions array
    pub containers_len: usize,

    /// Capacity of container permissions array. Internal field
    /// required for the Rust allocator.
    pub containers_cap: usize,
}

impl Drop for AuthReq {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        unsafe {
            let _ = Vec::from_raw_parts(
                self.containers as *mut ContainerPermissions,
                self.containers_len,
                self.containers_cap,
            );
        }
    }
}

/// Containers request
#[repr(C)]
pub struct ContainersReq {
    /// Exchange info
    pub app: AppExchangeInfo,
    /// Requested containers
    pub containers: *const ContainerPermissions,
    /// Size of requested containers array
    pub containers_len: usize,
    /// Capacity of requested containers array. Internal field
    /// required for the Rust allocator.
    pub containers_cap: usize,
}

impl Drop for ContainersReq {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        unsafe {
            let _ = Vec::from_raw_parts(
                self.containers as *mut ContainerPermissions,
                self.containers_len,
                self.containers_cap,
            );
        }
    }
}

/// Represents an application ID in the process of asking permissions
#[repr(C)]
pub struct AppExchangeInfo {
    /// UTF-8 encoded id
    pub id: *const c_char,

    /// Reserved by the frontend
    ///
    /// null if not present
    pub scope: *const c_char,

    /// UTF-8 encoded application friendly-name.
    pub name: *const c_char,

    /// UTF-8 encoded application provider/vendor (e.g. MaidSafe)
    pub vendor: *const c_char,
}

impl Drop for AppExchangeInfo {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        unsafe {
            let _ = CString::from_raw(self.id as *mut _);
            if !self.scope.is_null() {
                let _ = CString::from_raw(self.scope as *mut _);
            }
            let _ = CString::from_raw(self.name as *mut _);
            let _ = CString::from_raw(self.vendor as *mut _);
        }
    }
}

/// Represents the set of permissions for a given container
#[repr(C)]
pub struct ContainerPermissions {
    /// The UTF-8 encoded id
    pub cont_name: *const c_char,
    /// The requested permission set
    pub access: PermissionSet,
}

impl Drop for ContainerPermissions {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        unsafe {
            let _ = CString::from_raw(self.cont_name as *mut _);
        }
    }
}

#[repr(C)]
/// Represents a request to share mutable data
pub struct ShareMDataReq {
    /// Info about the app requesting shared access
    pub app: AppExchangeInfo,
    /// List of MD names & type tags and permissions that need to be shared
    pub mdata: *const ShareMData,
    /// Length of the mdata array
    pub mdata_len: usize,
    /// Capacity of the mdata vec - internal implementation detail
    pub mdata_cap: usize,
}

impl Drop for ShareMDataReq {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        unsafe {
            let _ = Vec::from_raw_parts(
                self.mdata as *mut ShareMData,
                self.mdata_len,
                self.mdata_cap,
            );
        }
    }
}

#[repr(C)]
/// For use in `ShareMDataReq`. Represents a specific `MutableData` that is being shared.
pub struct ShareMData {
    /// The mutable data type.
    pub type_tag: u64,
    /// The mutable data name.
    pub name: XorName,
    /// The permissions being requested.
    pub perms: PermissionSet,
}
