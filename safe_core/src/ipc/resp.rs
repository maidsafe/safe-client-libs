// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

#![allow(unsafe_code)]

use crate::client::{MDataInfo, SafeKey};
use crate::crypto::{shared_box, shared_secretbox, shared_sign};
use crate::ffi::ipc::resp as ffi;
use crate::ipc::req::{
    container_perms_from_repr_c, container_perms_into_repr_c, permission_set_clone_from_repr_c,
    permission_set_into_repr_c, ContainerPermissions,
};
use crate::ipc::{BootstrapConfig, IpcError};
use bincode::{deserialize, serialize};
use ffi_utils::{vec_clone_from_raw_parts, vec_into_raw_parts, ReprC, StringError};
use rand::thread_rng;
use rust_sodium::crypto::sign;
use rust_sodium::crypto::{box_, secretbox};
use safe_nd::{
    AppFullId, ClientFullId, ClientPublicId, MDataAddress, MDataPermissionSet, MDataSeqValue,
    PublicKey, XorName,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::ffi::{CString, NulError};
use std::ptr;
use std::slice;
use tiny_keccak::sha3_256;

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
        let AuthGranted {
            app_keys,
            bootstrap_config,
            access_container_info,
            access_container_entry,
        } = self;
        let bootstrap_config = serialize(&bootstrap_config)?;
        let (ptr, len) = vec_into_raw_parts(bootstrap_config);

        Ok(ffi::AuthGranted {
            app_keys: app_keys.into_repr_c(),
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
            app_keys,
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

/// Represents the needed keys to work with the data.
#[derive(Clone, Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct AppKeys {
    /// This is the identity of the App in the Network.
    pub app_full_id: AppFullId,
    /// Data symmetric encryption key.
    pub enc_key: shared_secretbox::Key,
    /// Asymmetric sign public key.
    pub sign_pk: sign::PublicKey,
    /// Asymmetric sign private key.
    pub sign_sk: shared_sign::SecretKey,
    /// Asymmetric enc public key.
    pub enc_pk: box_::PublicKey,
    /// Asymmetric enc private key.
    pub enc_sk: shared_box::SecretKey,
}

impl AppKeys {
    /// Generates random keys for the provided client.
    pub fn new(client_public_id: ClientPublicId) -> AppKeys {
        let (enc_pk, enc_sk) = shared_box::gen_keypair();
        let (sign_pk, sign_sk) = shared_sign::gen_keypair();
        // TODO: Instead of using `thread_rng`, generate based on a provided seed or rng.
        let app_full_id = AppFullId::new_bls(&mut thread_rng(), client_public_id);

        AppKeys {
            app_full_id,
            enc_key: shared_secretbox::gen_key(),
            sign_pk,
            sign_sk,
            enc_pk,
            enc_sk,
        }
    }

    /// Converts `AppKeys` into an App `SafeKey`.
    pub fn app_safe_key(&self) -> SafeKey {
        SafeKey::app(self.app_full_id.clone())
    }

    /// Returns the associated public key.
    pub fn public_key(&self) -> PublicKey {
        *self.app_full_id.public_id().public_key()
    }

    /// Constructs FFI wrapper for the native Rust object, consuming self.
    pub fn into_repr_c(self) -> ffi::AppKeys {
        let AppKeys {
            app_full_id,
            enc_key,
            sign_pk,
            sign_sk,
            enc_pk,
            enc_sk,
        } = self;

        // TODO: Handle the full app ID.
        let bls_pk = match app_full_id.public_id().public_key() {
            PublicKey::Bls(pk) => pk.to_bytes(),
            // TODO and FIXME: use proper ReprC for PublicKey
            _ => panic!("unexpected owner key type"),
        };

        ffi::AppKeys {
            bls_pk,
            enc_key: enc_key.0,
            sign_pk: sign_pk.0,
            sign_sk: sign_sk.0,
            enc_pk: enc_pk.0,
            enc_sk: enc_sk.0,
        }
    }
}

impl ReprC for AppKeys {
    type C = ffi::AppKeys;
    type Error = IpcError;

    unsafe fn clone_from_repr_c(repr_c: Self::C) -> Result<Self, Self::Error> {
        // TODO: handle this properly.
        let mut rng = thread_rng();
        let client_id = ClientFullId::new_bls(&mut rng);
        let app_full_id = AppFullId::new_bls(&mut rng, client_id.public_id().clone());

        Ok(Self {
            app_full_id,
            enc_key: shared_secretbox::Key::from_raw(&repr_c.enc_key),
            sign_pk: sign::PublicKey(repr_c.sign_pk),
            sign_sk: shared_sign::SecretKey::from_raw(&repr_c.sign_sk),
            enc_pk: box_::PublicKey(repr_c.enc_pk),
            enc_sk: shared_box::SecretKey::from_raw(&repr_c.enc_sk),
        })
    }
}

/// Represents an entry for a single app in the access container
pub type AccessContainerEntry = HashMap<String, (MDataInfo, ContainerPermissions)>;

/// Convert `AccessContainerEntry` to FFI representation.
pub fn access_container_entry_into_repr_c(
    entry: AccessContainerEntry,
) -> Result<ffi::AccessContainerEntry, NulError> {
    let mut vec = Vec::with_capacity(entry.len());

    for (name, (mdata_info, permissions)) in entry {
        vec.push(ffi::ContainerInfo {
            name: CString::new(name)?.into_raw(),
            mdata_info: mdata_info.into_repr_c(),
            permissions: container_perms_into_repr_c(&permissions),
        })
    }

    let (containers, containers_len) = vec_into_raw_parts(vec);

    Ok(ffi::AccessContainerEntry {
        containers,
        containers_len,
    })
}

/// Convert FFI representation of `AccessContainerEntry` to native rust representation by cloning.
///
/// # Safety
///
/// This function dereferences the provided raw pointer, which must be valid.
///
/// This function also assumes the provided `ffi::AccessContainerEntry` is valid, i.e. it was
/// constructed by calling `access_container_into_repr_c`.
pub unsafe fn access_container_entry_clone_from_repr_c(
    entry: *const ffi::AccessContainerEntry,
) -> Result<AccessContainerEntry, IpcError> {
    let input = slice::from_raw_parts((*entry).containers, (*entry).containers_len);
    let mut output = AccessContainerEntry::with_capacity(input.len());

    for container in input {
        let name = String::clone_from_repr_c(container.name)?;
        let mdata_info = MDataInfo::clone_from_repr_c(&container.mdata_info)?;
        let permissions = container_perms_from_repr_c(container.permissions)?;

        let _ = output.insert(name, (mdata_info, permissions));
    }

    Ok(output)
}

/// Access container
#[derive(Clone, Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct AccessContInfo {
    /// ID
    pub id: XorName,
    /// Type tag
    pub tag: u64,
    /// Nonce
    pub nonce: secretbox::Nonce,
}

impl AccessContInfo {
    /// Construct FFI wrapper for the native Rust object, consuming self.
    pub fn into_repr_c(self) -> ffi::AccessContInfo {
        let Self { id, tag, nonce } = self;

        ffi::AccessContInfo {
            id: id.0,
            tag,
            nonce: nonce.0,
        }
    }

    /// Creates `MDataInfo` from this `AccessContInfo`
    pub fn into_mdata_info(self, enc_key: shared_secretbox::Key) -> MDataInfo {
        MDataInfo::new_private(
            MDataAddress::Seq {
                name: self.id,
                tag: self.tag,
            },
            (enc_key, self.nonce),
        )
    }

    /// Creates an `AccessContInfo` from a given `MDataInfo`
    pub fn from_mdata_info(md: &MDataInfo) -> Result<Self, IpcError> {
        if let Some((_, nonce)) = md.enc_info {
            Ok(Self {
                id: md.name(),
                tag: md.type_tag(),
                nonce,
            })
        } else {
            Err(IpcError::Unexpected(
                "MDataInfo doesn't contain nonce".to_owned(),
            ))
        }
    }
}

impl ReprC for AccessContInfo {
    type C = ffi::AccessContInfo;
    type Error = IpcError;

    unsafe fn clone_from_repr_c(repr_c: Self::C) -> Result<Self, Self::Error> {
        Ok(Self {
            id: XorName(repr_c.id),
            tag: repr_c.tag,
            nonce: secretbox::Nonce(repr_c.nonce),
        })
    }
}

/// Encrypts and serialises an access container key using given app ID and app key.
pub fn access_container_enc_key(
    app_id: &str,
    app_enc_key: &secretbox::Key,
    access_container_nonce: &secretbox::Nonce,
) -> Result<Vec<u8>, IpcError> {
    let key = app_id.as_bytes();
    let mut key_pt = key.to_vec();
    key_pt.extend_from_slice(&access_container_nonce[..]);

    let key_nonce = secretbox::Nonce::from_slice(&sha3_256(&key_pt)[..secretbox::NONCEBYTES])
        .ok_or(IpcError::EncodeDecodeError)?;

    Ok(secretbox::seal(key, &key_nonce, app_enc_key))
}

/// Information about an app that has access to an MD through `sign_key`.
#[derive(Debug)]
pub struct AppAccess {
    /// App's or user's public key
    pub sign_key: PublicKey,
    /// A list of permissions
    pub permissions: MDataPermissionSet,
    /// App's user-facing name
    pub name: Option<String>,
    /// App id
    pub app_id: Option<String>,
}

impl AppAccess {
    /// Construct FFI wrapper for the native Rust object, consuming self.
    pub fn into_repr_c(self) -> Result<ffi::AppAccess, IpcError> {
        let AppAccess {
            sign_key,
            permissions,
            name,
            app_id,
        } = self;

        let name = match name {
            Some(name) => CString::new(name).map_err(StringError::from)?.into_raw(),
            None => ptr::null(),
        };

        let app_id = match app_id {
            Some(app_id) => CString::new(app_id).map_err(StringError::from)?.into_raw(),
            None => ptr::null(),
        };

        let sign_key = match sign_key {
            PublicKey::Bls(sec_key) => sec_key.to_bytes(),
            // TODO: FFI repr for PublicKey
            _ => return Err(IpcError::from("Unsupported key type")),
        };

        Ok(ffi::AppAccess {
            sign_key,
            permissions: permission_set_into_repr_c(permissions),
            name,
            app_id,
        })
    }
}

impl ReprC for AppAccess {
    type C = *const ffi::AppAccess;
    type Error = IpcError;

    unsafe fn clone_from_repr_c(repr_c: Self::C) -> Result<Self, Self::Error> {
        let ffi::AppAccess {
            sign_key,
            permissions,
            name,
            app_id,
        } = *repr_c;

        Ok(Self {
            sign_key: PublicKey::from(
                threshold_crypto::PublicKey::from_bytes(sign_key)
                    .map_err(|_| IpcError::EncodeDecodeError)?,
            ),
            permissions: permission_set_clone_from_repr_c(permissions)?,
            name: if name.is_null() {
                None
            } else {
                Some(String::clone_from_repr_c(name)?)
            },
            app_id: if name.is_null() {
                None
            } else {
                Some(String::clone_from_repr_c(app_id)?)
            },
        })
    }
}

/// Metadata for `MutableData`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct UserMetadata {
    /// Name or purpose of this mutable data.
    pub name: Option<String>,
    /// Description of how this mutable data should or should not be shared.
    pub description: Option<String>,
}

impl UserMetadata {
    /// Converts this object into an FFI representation with more information.
    pub fn into_md_response(
        self,
        xor_name: XorName,
        type_tag: u64,
    ) -> Result<ffi::MetadataResponse, NulError> {
        Ok(ffi::MetadataResponse {
            name: match self.name {
                Some(name) => CString::new(name)?.into_raw(),
                None => ptr::null(),
            },
            description: match self.description {
                Some(description) => CString::new(description)?.into_raw(),
                None => ptr::null(),
            },
            xor_name: xor_name.0,
            type_tag,
        })
    }
}

impl ReprC for UserMetadata {
    type C = *const ffi::MetadataResponse;
    type Error = IpcError;

    unsafe fn clone_from_repr_c(repr_c: Self::C) -> Result<Self, Self::Error> {
        let ffi::MetadataResponse {
            name, description, ..
        } = *repr_c;

        Ok(Self {
            name: if name.is_null() {
                None
            } else {
                Some(String::clone_from_repr_c(name)?)
            },
            description: if description.is_null() {
                None
            } else {
                Some(String::clone_from_repr_c(description)?)
            },
        })
    }
}

/// Mutable data key.
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize, Debug)]
// TODO: Move to safe-nd, or remove this and use Vec<u8> directly.
pub struct MDataKey(
    /// Key value.
    pub Vec<u8>,
);

impl MDataKey {
    /// Create the key from bytes.
    pub fn from_bytes(key: &[u8]) -> Self {
        MDataKey(key.into())
    }

    /// Construct FFI wrapper for the native Rust object, consuming self.
    pub fn into_repr_c(self) -> ffi::MDataKey {
        let (key, key_len) = vec_into_raw_parts(self.0);

        ffi::MDataKey { key, key_len }
    }
}

impl ReprC for MDataKey {
    type C = *const ffi::MDataKey;
    type Error = ();

    unsafe fn clone_from_repr_c(repr_c: Self::C) -> Result<Self, Self::Error> {
        let ffi::MDataKey { key, key_len, .. } = *repr_c;
        let key = vec_clone_from_raw_parts(key, key_len);

        Ok(MDataKey(key))
    }
}

/// Redefine the Value from safe-nd so that we can `impl ReprC`.
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize, Debug)]
pub struct MDataValue {
    /// Content of the entry.
    pub content: Vec<u8>,
    /// Version of the entry.
    pub entry_version: u64,
}

// TODO: Remove this and use SeqMDataValue in safe-nd instead.
impl MDataValue {
    /// Convert routing representation to `MDataValue`.
    pub fn from_routing(value: MDataSeqValue) -> Self {
        Self {
            content: value.data,
            entry_version: value.version,
        }
    }

    /// Returns FFI counterpart without consuming the object.
    pub fn into_repr_c(self) -> ffi::MDataValue {
        let (content, content_len) = vec_into_raw_parts(self.content);

        ffi::MDataValue {
            content,
            content_len,
            entry_version: self.entry_version,
        }
    }
}

impl ReprC for MDataValue {
    type C = *const ffi::MDataValue;
    type Error = ();

    unsafe fn clone_from_repr_c(repr_c: Self::C) -> Result<Self, Self::Error> {
        let ffi::MDataValue {
            content,
            content_len,
            entry_version,
            ..
        } = *repr_c;
        let content = vec_clone_from_raw_parts(content, content_len);

        Ok(Self {
            content,
            entry_version,
        })
    }
}

/// Mutable data entry.
// TODO: Remove this and use SeqMDataEntry in safe-nd instead.
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize, Debug)]
pub struct MDataEntry {
    /// Key.
    pub key: MDataKey,
    /// Value.
    pub value: MDataValue,
}

impl MDataEntry {
    /// Construct FFI wrapper for the native Rust object, consuming self.
    pub fn into_repr_c(self) -> ffi::MDataEntry {
        ffi::MDataEntry {
            key: self.key.into_repr_c(),
            value: self.value.into_repr_c(),
        }
    }
}

impl ReprC for MDataEntry {
    type C = *const ffi::MDataEntry;
    type Error = ();

    unsafe fn clone_from_repr_c(repr_c: Self::C) -> Result<Self, Self::Error> {
        let ffi::MDataEntry { ref key, ref value } = *repr_c;

        Ok(Self {
            key: MDataKey::clone_from_repr_c(key)?,
            value: MDataValue::clone_from_repr_c(value)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::gen_client_id;
    use ffi_utils::ReprC;
    use rust_sodium::crypto::secretbox;
    use safe_nd::{XorName, XOR_NAME_LEN};

    // Test converting an `AuthGranted` object to its FFI representation and then back again.
    #[test]
    fn auth_granted() {
        let client_id = gen_client_id();
        let ak = AppKeys::new(client_id.public_id().clone());
        let ac = AccessContInfo {
            id: XorName([2; XOR_NAME_LEN]),
            tag: 681,
            nonce: secretbox::gen_nonce(),
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

    // Testing converting an `AppKeys` object to its FFI representation and back again.
    #[test]
    fn app_keys() {
        let client_id = gen_client_id();
        let ak = AppKeys::new(client_id.public_id().clone());

        let AppKeys {
            enc_key,
            sign_pk,
            sign_sk,
            enc_pk,
            enc_sk,
            // TODO: check app_id also.
            ..
        } = ak.clone();

        let ffi_ak = ak.into_repr_c();

        assert_eq!(
            ffi_ak.enc_key.iter().collect::<Vec<_>>(),
            enc_key.0.iter().collect::<Vec<_>>()
        );
        assert_eq!(
            ffi_ak.sign_pk.iter().collect::<Vec<_>>(),
            sign_pk.0.iter().collect::<Vec<_>>()
        );
        assert_eq!(
            ffi_ak.sign_sk.iter().collect::<Vec<_>>(),
            sign_sk.0.iter().collect::<Vec<_>>()
        );
        assert_eq!(
            ffi_ak.enc_pk.iter().collect::<Vec<_>>(),
            enc_pk.0.iter().collect::<Vec<_>>()
        );
        assert_eq!(
            ffi_ak.enc_sk.iter().collect::<Vec<_>>(),
            enc_sk.0.iter().collect::<Vec<_>>()
        );

        let ak = unsafe { unwrap!(AppKeys::clone_from_repr_c(ffi_ak)) };

        assert_eq!(ak.enc_key, enc_key);
        assert_eq!(ak.sign_pk, sign_pk);
        assert_eq!(ak.sign_sk, sign_sk);
        assert_eq!(ak.enc_pk, enc_pk);
        assert_eq!(ak.enc_sk, enc_sk);
    }

    // Test converting an `AccessContInfo` to `MDataInfo` and back again.
    #[test]
    fn access_container_mdata_info() {
        let (key, nonce) = (shared_secretbox::gen_key(), secretbox::gen_nonce());
        let a = AccessContInfo {
            id: XorName([2; XOR_NAME_LEN]),
            tag: 681,
            nonce,
        };

        let md = a.clone().into_mdata_info(key.clone());

        let a2 = AccessContInfo::from_mdata_info(&md).unwrap();
        assert_eq!(a, a2);

        let md2 = a.into_mdata_info(key);
        assert_eq!(md, md2);
    }

    // Test converting an `AccessContInfo` to its FFI representation and back again.
    #[test]
    fn access_container_ffi() {
        let nonce = secretbox::gen_nonce();
        let a = AccessContInfo {
            id: XorName([2; XOR_NAME_LEN]),
            tag: 681,
            nonce,
        };

        let ffi = a.into_repr_c();

        assert_eq!(ffi.id.iter().sum::<u8>() as usize, 2 * XOR_NAME_LEN);
        assert_eq!(ffi.tag, 681);
        assert_eq!(
            ffi.nonce.iter().collect::<Vec<_>>(),
            nonce.0.iter().collect::<Vec<_>>()
        );

        let a = unsafe { unwrap!(AccessContInfo::clone_from_repr_c(ffi)) };

        assert_eq!(a.id.0.iter().sum::<u8>() as usize, 2 * XOR_NAME_LEN);
        assert_eq!(a.tag, 681);
        assert_eq!(a.nonce, nonce);
    }
}
