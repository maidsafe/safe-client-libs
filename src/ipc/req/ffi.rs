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

use std::mem;
use util::ffi::FfiString;

/// The permission type
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, RustcEncodable, RustcDecodable)]
pub enum PermissionAccess {
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

    /// Array of `ContainerPermission`
    pub containers: ContainerPermissionArray,
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
    pub containers: ContainerPermissionArray,
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
pub struct ContainerPermission {
    /// The UTF-8 encoded id
    pub container_key: FfiString,

    /// The `PermissionAccess` array
    pub access: PermissionAccessArray,
}

/// Free memory
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn container_permission_drop(cp: ContainerPermission) {
    let _ = super::ContainerPermission::from_repr_c(cp);
}

/// Wrapper for ContainerPermission arrays to be passed across FFI boundary.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ContainerPermissionArray {
    /// Pointer to first byte
    pub ptr: *mut ContainerPermission,
    /// Number of elements
    pub len: usize,
    /// Reserved by Rust allocator
    pub cap: usize,
}

impl ContainerPermissionArray {
    /// Construct owning `ContainerPermissionArray` from `Vec`. It has to be
    /// deallocated manually by calling `container_permission_array_free`
    pub fn from_vec(mut v: Vec<ContainerPermission>) -> Self {
        let p = v.as_mut_ptr();
        let len = v.len();
        let cap = v.capacity();
        mem::forget(v);

        ContainerPermissionArray {
            ptr: p,
            len: len,
            cap: cap,
        }
    }

    /// Consumes this `ContainerPermissionArray` into a `Vec`
    #[allow(unsafe_code)]
    pub unsafe fn into_vec(&self) -> Vec<ContainerPermission> {
        Vec::from_raw_parts(self.ptr, self.len, self.cap)
    }
}

/// Free the array from memory.
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn container_permission_array_free(s: ContainerPermissionArray) {
    let _ = s.into_vec();
}

/// Wrapper for PermissionAccess arrays to be passed across FFI boundary.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PermissionAccessArray {
    /// Pointer to first byte
    pub ptr: *mut PermissionAccess,
    /// Number of elements
    pub len: usize,
    /// Reserved by Rust allocator
    pub cap: usize,
}

impl PermissionAccessArray {
    /// Construct owning `PermissionAccessArray` from `Vec`. It has to be
    /// deallocated manually by calling `container_permission_array_free`
    pub fn from_vec(mut v: Vec<PermissionAccess>) -> Self {
        let p = v.as_mut_ptr();
        let len = v.len();
        let cap = v.capacity();
        mem::forget(v);

        PermissionAccessArray {
            ptr: p,
            len: len,
            cap: cap,
        }
    }

    /// Consumes this `PermissionAccessArray` into a `Vec`
    #[allow(unsafe_code)]
    pub unsafe fn into_vec(&self) -> Vec<PermissionAccess> {
        Vec::from_raw_parts(self.ptr, self.len, self.cap)
    }
}

/// Free the array from memory.
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn permission_access_array_free(s: PermissionAccessArray) {
    let _ = s.into_vec();
}
