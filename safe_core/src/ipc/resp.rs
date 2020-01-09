// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

#![allow(unsafe_code)]

use crate::core_structs::{
    access_container_entry_clone_from_repr_c, access_container_entry_into_repr_c, AccessContInfo,
    AccessContainerEntry, AppKeys,
};
use crate::ffi::ipc::resp as ffi;

use crate::ipc::{BootstrapConfig, IpcError};
use bincode::{deserialize, serialize};
use ffi_utils::{vec_into_raw_parts, ReprC};

use serde::{Deserialize, Serialize};
use std::slice;

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
    use safe_nd::{XorName, XOR_NAME_LEN};
    use unwrap::unwrap;

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
