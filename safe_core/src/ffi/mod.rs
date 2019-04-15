// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! FFI.

#![allow(unsafe_code)]

/// Type definitions for arrays that are FFI input params.
pub mod arrays;
/// IPC utilities.
pub mod ipc;
/// NFS API.
pub mod nfs;

use self::arrays::*;
use errors::CoreError;
use ffi_utils::ReprC;

/// Represents the FFI-safe account info.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct AccountInfo {
    /// Number of used mutations.
    pub mutations_done: u64,
    /// Number of available mutations.
    pub mutations_available: u64,
}

impl ReprC for AccountInfo {
    type C = *const AccountInfo;
    type Error = CoreError;

    /// Constructs the object from a raw pointer.
    ///
    /// After calling this function, the raw pointer is owned by the resulting object.
    unsafe fn clone_from_repr_c(repr_c: Self::C) -> Result<Self, Self::Error> {
        Ok(*repr_c)
    }
}

/// FFI wrapper for `MDataInfo`.
#[repr(C)]
#[derive(Clone)]
pub struct MDataInfo {
    /// Name of the mutable data.
    pub name: XorNameArray,
    /// Type tag of the mutable data.
    pub type_tag: u64,

    /// Flag indicating whether the encryption info (`enc_key` and `enc_nonce`).
    /// is set.
    pub has_enc_info: bool,
    /// Encryption key. Meaningful only if `has_enc_info` is `true`.
    pub enc_key: SymSecretKey,
    /// Encryption nonce. Meaningful only if `has_enc_info` is `true`.
    pub enc_nonce: SymNonce,

    /// Flag indicating whether the new encryption info is set.
    pub has_new_enc_info: bool,
    /// New encryption key (used for two-phase reencryption). Meaningful only if
    /// `has_new_enc_info` is `true`.
    pub new_enc_key: SymSecretKey,
    /// New encryption nonce (used for two-phase reencryption). Meaningful only if
    /// `has_new_enc_info` is `true`.
    pub new_enc_nonce: SymNonce,
}
