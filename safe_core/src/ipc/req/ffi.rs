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

use ffi_utils::{FfiString, ffi_string_free};
use std::mem;

/// Permission action
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, RustcEncodable, RustcDecodable)]
pub enum Permission {
    /// Read
    Read,
    /// Insert
    Insert,
    /// Update
    Update,
    /// Delete
    Delete,
    /// Modify permissions
    ManagePermissions,
}

/// Represents an authorization request
#[repr(C)]
#[derive(Clone, Copy)]
pub struct AuthReq {
    /// The application identifier for this request
    pub app: AppExchangeInfo,
    /// `true` if the app wants dedicated container for itself. `false`
    /// otherwise.
    pub app_container: bool,

    /// Array of `ContainerPermissions`
    pub containers: ContainerPermissionsArray,
}

/// Free memory from the subobjects
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn auth_request_drop(a: AuthReq) {
    let _ = super::AuthReq::from_repr_c(a);
}

/// Containers request
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ContainersReq {
    /// Exchange info
    pub app: AppExchangeInfo,
    /// Requested containers
    pub containers: ContainerPermissionsArray,
}

/// Free memory from the subobjects
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn containers_req_drop(c: ContainersReq) {
    let _ = super::ContainersReq::from_repr_c(c);
}

/// Represents an application ID in the process of asking permissions
#[repr(C)]
#[derive(Clone, Copy)]
pub struct AppExchangeInfo {
    /// UTF-8 encoded id
    pub id: FfiString,

    /// Reserved by the frontend
    ///
    /// null if not present
    pub scope: *const u8,
    /// `scope`'s length.
    ///
    /// 0 if `scope` is null
    pub scope_len: usize,
    /// Used by the Rust memory allocator.
    ///
    /// 0 if `scope` is null
    pub scope_cap: usize,

    /// UTF-8 encoded application friendly-name.
    pub name: FfiString,

    /// UTF-8 encoded application provider/vendor (e.g. MaidSafe)
    pub vendor: FfiString,
}

/// Free memory
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn app_exchange_info_drop(a: AppExchangeInfo) {
    let _ = super::AppExchangeInfo::from_repr_c(a);
}

/// Represents the set of permissions for a given container
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ContainerPermissions {
    /// The UTF-8 encoded id
    pub cont_name: FfiString,

    /// The `Permission` array
    pub access: PermissionArray,
}

/// Free memory
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn container_permissions_drop(cp: ContainerPermissions) {
    ffi_string_free(cp.cont_name);
    permission_array_free(cp.access);
}

/// Wrapper for `ContainerPermissions` arrays to be passed across FFI boundary.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ContainerPermissionsArray {
    /// Pointer to first byte
    pub ptr: *mut ContainerPermissions,
    /// Number of elements
    pub len: usize,
    /// Reserved by Rust allocator
    pub cap: usize,
}

impl ContainerPermissionsArray {
    /// Construct owning `ContainerPermissionsArray` from `Vec`. It has to be
    /// deallocated manually by calling `container_permissions_array_free`
    pub fn from_vec(mut v: Vec<ContainerPermissions>) -> Self {
        let p = v.as_mut_ptr();
        let len = v.len();
        let cap = v.capacity();
        mem::forget(v);

        ContainerPermissionsArray {
            ptr: p,
            len: len,
            cap: cap,
        }
    }

    /// Consumes this `ContainerPermissionsArray` into a `Vec`
    #[allow(unsafe_code)]
    pub unsafe fn into_vec(self) -> Vec<ContainerPermissions> {
        Vec::from_raw_parts(self.ptr, self.len, self.cap)
    }
}

/// Free the array from memory.
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn container_permissions_array_free(s: ContainerPermissionsArray) {
    let _ = s.into_vec();
}

/// Wrapper for `Permission` arrays to be passed across FFI boundary.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PermissionArray {
    /// Pointer to first byte
    pub ptr: *mut Permission,
    /// Number of elements
    pub len: usize,
    /// Reserved by Rust allocator
    pub cap: usize,
}

impl PermissionArray {
    /// Construct owning `PermissionArray` from `Vec`. It has to be
    /// deallocated manually by calling `permission_array_free`
    pub fn from_vec(mut v: Vec<Permission>) -> Self {
        let ptr = v.as_mut_ptr();
        let len = v.len();
        let cap = v.capacity();
        mem::forget(v);

        PermissionArray {
            ptr: ptr,
            len: len,
            cap: cap,
        }
    }

    /// Consumes this `PermissionArray` into a `Vec`
    #[allow(unsafe_code)]
    pub unsafe fn into_vec(self) -> Vec<Permission> {
        Vec::from_raw_parts(self.ptr, self.len, self.cap)
    }
}

/// Free the array from memory.
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn permission_array_free(s: PermissionArray) {
    let _ = s.into_vec();
}
