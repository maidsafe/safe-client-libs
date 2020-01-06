// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

#![allow(unsafe_code)]

use crate::client::{MDataInfo, SafeKey};
use crate::crypto::{shared_box, shared_secretbox};
use crate::ffi::ipc::resp as ffi;
use crate::ipc::req::{
    container_perms_from_repr_c, container_perms_into_repr_c, permission_set_clone_from_repr_c,
    permission_set_into_repr_c, ContainerPermissions,
};
use crate::core_structs::{AppKeys, AccessContInfo, AccessContainerEntry, access_container_entry_into_repr_c, access_container_entry_clone_from_repr_c};
use crate::ipc::{BootstrapConfig, IpcError};
use crate::utils::{symmetric_encrypt, SymEncKey, SymEncNonce, SYM_ENC_NONCE_LEN};
use crate::CoreError;
use bincode::{deserialize, serialize};
use ffi_utils::{vec_clone_from_raw_parts, vec_into_raw_parts, ReprC, StringError};
use rand::thread_rng;

use safe_nd::{
    AppFullId, ClientPublicId, MDataAddress, MDataPermissionSet, MDataSeqValue, PublicKey, XorName,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::convert::TryInto;
use std::ffi::{CString, NulError};
use std::ptr;
use std::slice;
use tiny_keccak::sha3_256;
use unwrap::unwrap;

/// Entry key under which the metadata are stored.
#[no_mangle]
pub static METADATA_KEY: &[u8] = b"_metadata";
/// Length of the metadata key.
// IMPORTANT: make sure this value stays in sync with the actual length of `METADATA_KEY`!
// TODO: Replace with `METADATA_KEY.len()` once `len` is stable as a const fn.
#[no_mangle]
pub static METADATA_KEY_LEN: usize = 9;

/// IPC response.
// TODO: `TransOwnership` variant
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum IpcResp {
    /// Authentication.
    Auth(Result<AuthGranted, IpcError>),
    /// Containers.
    Containers(Result<(), IpcError>),
    /// Unregistered client.
    Unregistered(Result<BootstrapConfig, IpcError>),
    /// Share mutable data.
    ShareMData(Result<(), IpcError>),
}

/// It represents the authentication response.
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct AuthGranted {
    /// The access keys.
    pub app_keys: AppKeys,

    /// The crust config.
    /// Useful to reuse bootstrap nodes and speed up access.
    pub bootstrap_config: BootstrapConfig,

    /// Access container info.
    pub access_container_info: AccessContInfo,
    /// Access container entry.
    pub access_container_entry: AccessContainerEntry,
}

impl AuthGranted {
    /// Construct FFI wrapper for the native Rust object, consuming self.
    pub fn into_repr_c(self) -> Result<ffi::AuthGranted, IpcError> {
        let Self {
            app_keys,
            bootstrap_config,
            access_container_info,
            access_container_entry,
        } = self;
        let bootstrap_config = serialize(&bootstrap_config)?;
        let (ptr, len) = vec_into_raw_parts(bootstrap_config);

        Ok(ffi::AuthGranted {
            app_keys: app_keys.into_repr_c()?,
            access_container_info: access_container_info.into_repr_c(),
            access_container_entry: access_container_entry_into_repr_c(access_container_entry)?,
            bootstrap_config: ptr,
            bootstrap_config_len: len,
        })
    }
}

impl ReprC for AuthGranted {
    type C = *const ffi::AuthGranted;
    type Error = IpcError;

    unsafe fn clone_from_repr_c(repr_c: Self::C) -> Result<Self, Self::Error> {
        let ffi::AuthGranted {
            ref app_keys,
            bootstrap_config,
            bootstrap_config_len,
            access_container_info,
            ref access_container_entry,
            ..
        } = *repr_c;
        let bootstrap_config = slice::from_raw_parts(bootstrap_config, bootstrap_config_len);
        let bootstrap_config = deserialize(bootstrap_config)?;

        Ok(Self {
            app_keys: AppKeys::clone_from_repr_c(app_keys)?,
            bootstrap_config,
            access_container_info: AccessContInfo::clone_from_repr_c(access_container_info)?,
            access_container_entry: access_container_entry_clone_from_repr_c(
                access_container_entry,
            )?,
        })
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils;
    use crate::utils::test_utils::gen_client_id;
    use ffi_utils::ReprC;
    use safe_nd::{XorName, XOR_NAME_LEN};

    // Test converting an `AuthGranted` object to its FFI representation and then back again.
    #[test]
    fn auth_granted() {
        let client_id = gen_client_id();
        let ak = AppKeys::new(client_id.public_id().clone());
        let ac = AccessContInfo {
            id: XorName([2; XOR_NAME_LEN]),
            tag: 681,
            nonce: utils::generate_nonce(),
        };
        let ag = AuthGranted {
            app_keys: ak,
            bootstrap_config: BootstrapConfig::default(),
            access_container_info: ac,
            access_container_entry: AccessContainerEntry::default(),
        };

        let ffi = unwrap!(ag.into_repr_c());

        assert_eq!(ffi.access_container_info.tag, 681);

        let ag = unsafe { unwrap!(AuthGranted::clone_from_repr_c(&ffi)) };

        assert_eq!(ag.access_container_info.tag, 681);
    }

}
