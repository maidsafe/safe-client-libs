// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::ffi::arrays::*;
use crate::ffi::ipc::req::PermissionSet;
use crate::ffi::MDataInfo;
use std::ffi::CString;
use std::os::raw::c_char;
use std::ptr;

/// Represents the needed keys to work with the data.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct AppKeys {
    /// Owner signing public key
    pub owner_key: BlsPublicKey,
    /// Data symmetric encryption key
    pub enc_key: SymSecretKey,
    /// Asymmetric sign public key.
    ///
    /// This is the identity of the App in the Network.
    pub sign_pk: SignPublicKey,
    /// Asymmetric sign private key.
    pub sign_sk: SignSecretKey,
    /// Asymmetric enc public key.
    pub enc_pk: AsymPublicKey,
    /// Asymmetric enc private key.
    pub enc_sk: AsymSecretKey,
}

/// Access container info.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct AccessContInfo {
    /// ID
    pub id: XorNameArray,
    /// Type tag
    pub tag: u64,
    /// Nonce
    pub nonce: SymNonce,
}

/// Information about a container (name, `MDataInfo` and permissions)
#[repr(C)]
pub struct ContainerInfo {
    /// Container name as UTF-8 encoded null-terminated string.
    pub name: *const c_char,
    /// Container's `MDataInfo`
    pub mdata_info: MDataInfo,
    /// App's permissions in the container.
    pub permissions: PermissionSet,
}

impl Drop for ContainerInfo {
    fn drop(&mut self) {
        unsafe {
            let _ = CString::from_raw(self.name as *mut _);
        }
    }
}

/// Access container entry for a single app.
#[repr(C)]
pub struct AccessContainerEntry {
    /// Pointer to the array of `ContainerInfo`.
    pub containers: *const ContainerInfo,
    /// Size of the array.
    pub containers_len: usize,
    /// Internal field used by rust memory allocator.
    pub containers_cap: usize,
}

impl Drop for AccessContainerEntry {
    fn drop(&mut self) {
        unsafe {
            let _ = Vec::from_raw_parts(
                self.containers as *mut ContainerInfo,
                self.containers_len,
                self.containers_cap,
            );
        }
    }
}

/// Represents the authentication response.
#[repr(C)]
pub struct AuthGranted {
    /// The access keys.
    pub app_keys: AppKeys,
    /// Access container info.
    pub access_container_info: AccessContInfo,
    /// Access container entry.
    pub access_container_entry: AccessContainerEntry,

    /// QuicP2P bootstrap config.
    pub bootstrap_config: *const u8,
    /// `bootstrap_config`'s length.
    pub bootstrap_config_len: usize,
    /// Used by Rust memory allocator.
    pub bootstrap_config_cap: usize,
}

impl Drop for AuthGranted {
    fn drop(&mut self) {
        unsafe {
            let _ = Vec::from_raw_parts(
                self.bootstrap_config as *mut u8,
                self.bootstrap_config_len,
                self.bootstrap_config_cap,
            );
        }
    }
}

/// Information about an application that has access to an MD through `sign_key`.
#[repr(C)]
pub struct AppAccess {
    /// App's or user's public key.
    pub sign_key: BlsPublicKey,
    /// A list of permissions.
    pub permissions: PermissionSet,
    /// App's user-facing name.
    ///
    /// null if not present.
    pub name: *const c_char,
    /// App id.
    ///
    /// null if not present.
    pub app_id: *const c_char,
}

impl Drop for AppAccess {
    fn drop(&mut self) {
        unsafe {
            if !self.name.is_null() {
                let _ = CString::from_raw(self.name as *mut _);
            }

            if !self.app_id.is_null() {
                let _ = CString::from_raw(self.app_id as *mut _);
            }
        }
    }
}

/// User metadata for mutable data.
#[repr(C)]
pub struct MetadataResponse {
    /// Name or purpose of this mutable data.
    ///
    /// null if not present.
    pub name: *const c_char,
    /// Description of how this mutable data should or should not be shared.
    ///
    /// null if not present.
    pub description: *const c_char,
    /// Xor name of this struct's corresponding MData object.
    pub xor_name: XorNameArray,
    /// Type tag of this struct's corresponding MData object.
    pub type_tag: u64,
}

impl MetadataResponse {
    /// Create invalid metadata.
    pub fn invalid() -> Self {
        MetadataResponse {
            name: ptr::null(),
            description: ptr::null(),
            xor_name: Default::default(),
            type_tag: 0,
        }
    }
}

impl Drop for MetadataResponse {
    fn drop(&mut self) {
        unsafe {
            if !self.name.is_null() {
                let _ = CString::from_raw(self.name as *mut _);
            }

            if !self.description.is_null() {
                let _ = CString::from_raw(self.description as *mut _);
            }
        }
    }
}

/// Represents an FFI-safe mutable data key.
#[repr(C)]
#[derive(Debug)]
pub struct MDataKey {
    /// Pointer to the key.
    pub key: *const u8,
    /// Size of the key.
    pub key_len: usize,
    /// Capacity of the key. Internal field required for the Rust allocator.
    pub key_cap: usize,
}

impl Drop for MDataKey {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        let _ = unsafe { Vec::from_raw_parts(self.key as *mut u8, self.key_len, self.key_cap) };
    }
}

/// Represents the FFI-safe mutable data value.
#[repr(C)]
#[derive(Debug)]
pub struct MDataValue {
    /// Pointer to the content.
    pub content: *const u8,
    /// Size of the content.
    pub content_len: usize,
    /// Capacity of the content. Internal field required for the Rust allocator.
    pub content_cap: usize,

    /// Entry version.
    pub entry_version: u64,
}

impl Drop for MDataValue {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        let _ = unsafe {
            Vec::from_raw_parts(self.content as *mut u8, self.content_len, self.content_cap)
        };
    }
}

/// Represents an FFI-safe mutable data (key, value) entry.
#[repr(C)]
#[derive(Debug)]
pub struct MDataEntry {
    /// Mutable data key.
    pub key: MDataKey,
    /// Mutable data value.
    pub value: MDataValue,
}
