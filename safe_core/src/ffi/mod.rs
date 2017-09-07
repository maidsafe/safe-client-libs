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

//! FFI

#![allow(unsafe_code)]

/// IPC utilities
pub mod ipc;
/// NFS API
pub mod nfs;

use errors::CoreError;
use ffi_utils::ReprC;

/// Represents the FFI-safe account info
#[repr(C)]
#[derive(Clone, Copy)]
pub struct AccountInfo {
    /// Number of used mutations
    pub mutations_done: u64,
    /// Number of available mutations
    pub mutations_available: u64,
}

impl ReprC for AccountInfo {
    type C = *const AccountInfo;
    type Error = CoreError;

    unsafe fn clone_from_repr_c(repr_c: Self::C) -> Result<Self, Self::Error> {
        Ok(*repr_c)
    }
}
