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

#![allow(unsafe_code)]

use arrays::*;
use ffi::ipc::req::PermissionSet as FfiPermissionSet;
use rust_sodium::crypto::sign;
use std::ffi::CString;
use std::os::raw::c_char;
use std::ptr;

/// Represents the authentication response.
#[repr(C)]
#[derive(Clone)]
pub struct AuthGranted {
    /// The access keys.
    pub app_keys: AppKeys,
    /// Access container
    pub access_container: AccessContInfo,

    /// Crust's bootstrap config
    pub bootstrap_config_ptr: *mut u8,
    /// `bootstrap_config`'s length
    pub bootstrap_config_len: usize,
    /// Used by Rust memory allocator
    pub bootstrap_config_cap: usize,
}

impl Drop for AuthGranted {
    fn drop(&mut self) {
        unsafe {
            let _ = Vec::from_raw_parts(
                self.bootstrap_config_ptr,
                self.bootstrap_config_len,
                self.bootstrap_config_cap,
            );
        }
    }
}

/// Represents the needed keys to work with the data.
#[repr(C)]
#[derive(Copy)]
pub struct AppKeys {
    /// Owner signing public key
    pub owner_key: SignPublicKey,
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

impl Clone for AppKeys {
    // Implemented manually because:
    //
    // error[E0277]: the trait bound `[u8; 64]: std::clone::Clone` is not satisfied
    //
    // There is a default implementation only until size 32
    fn clone(&self) -> Self {
        let mut sign_pk = [0; sign::PUBLICKEYBYTES];
        let mut sign_sk = [0; sign::SECRETKEYBYTES];

        sign_pk.copy_from_slice(&self.sign_pk);
        sign_sk.copy_from_slice(&self.sign_sk);

        AppKeys {
            owner_key: self.owner_key,
            enc_key: self.enc_key,
            sign_pk: sign_pk,
            sign_sk: sign_sk,
            enc_pk: self.enc_pk,
            enc_sk: self.enc_sk,
        }
    }
}

/// Access container
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

/// Information about an application that has access to an MD through `sign_key`
#[repr(C)]
pub struct AppAccess {
    /// App's or user's public key
    pub sign_key: SignPublicKey,
    /// A list of permissions
    pub permissions: FfiPermissionSet,
    /// App's user-facing name
    pub name: *const c_char,
    /// App id.
    /// This is u8, as the app-id can contain non-printable characters.
    pub app_id: *const c_char,
}

/// User metadata for mutable data
#[repr(C)]
pub struct MetadataResponse {
    /// Name or purpose of this mutable data.
    pub name: *const c_char,
    /// Description of how this mutable data should or should not be shared.
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
