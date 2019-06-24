// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

#![allow(unsafe_code)]

use crate::client::MDataInfo;
use crate::crypto::{shared_box, shared_secretbox, shared_sign};
use crate::ffi::ipc::resp as ffi;
use crate::ipc::req::{
    container_perms_from_repr_c, container_perms_into_repr_c, permission_set_clone_from_repr_c,
    permission_set_into_repr_c, ContainerPermissions,
};
use crate::ipc::IpcError;
use ffi_utils::{vec_into_raw_parts, ReprC, StringError};
use maidsafe_utilities::serialisation::{deserialise, serialise};
use routing::PermissionSet;
use routing::Value;
use routing::{BootstrapConfig, XorName};
use rust_sodium::crypto::sign;
use rust_sodium::crypto::{box_, secretbox};
use safe_nd::{AppFullId, PublicKey};
use serde::ser::{Serialize, SerializeStruct, Serializer};
use std::collections::HashMap;
use std::ffi::{CString, NulError};
use std::ptr;
use std::slice;
use threshold_crypto::serde_impl::SerdeSecret;
use tiny_keccak::sha3_256;

/// Entry key under which the metadata are stored.
#[no_mangle]
pub static METADATA_KEY: &'static [u8] = b"_metadata";
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
        let bootstrap_config = serialise(&bootstrap_config)?;
        let (ptr, len, cap) = vec_into_raw_parts(bootstrap_config);

        Ok(ffi::AuthGranted {
            app_keys: app_keys.into_repr_c(),
            access_container_info: access_container_info.into_repr_c(),
            access_container_entry: access_container_entry_into_repr_c(access_container_entry)?,
            bootstrap_config: ptr,
            bootstrap_config_len: len,
            bootstrap_config_cap: cap,
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
        let bootstrap_config = deserialise(bootstrap_config)?;

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
#[derive(Clone, Deserialize, Debug, Eq, PartialEq)]
pub struct AppKeys {
    /// Owner public key.
    pub owner_key: PublicKey,
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
    /// BLS secret key
    pub bls_sk: threshold_crypto::SecretKey,
    /// BLS public key
    /// This is the identity of the App in the Network.
    pub bls_pk: threshold_crypto::PublicKey,
}

// threshold_crypto::SecretKey cannot be serialised directly,
// hence this trait is implemented
impl Serialize for AppKeys {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("AppKeys", 8)?;
        state.serialize_field("owner_key", &self.owner_key)?;
        state.serialize_field("enc_key", &self.enc_key)?;
        state.serialize_field("sign_pk", &self.sign_pk)?;
        state.serialize_field("sign_sk", &self.sign_sk)?;
        state.serialize_field("enc_pk", &self.enc_pk)?;
        state.serialize_field("enc_sk", &self.enc_sk)?;
        state.serialize_field("bls_sk", &SerdeSecret(&self.bls_sk))?;
        state.serialize_field("bls_pk", &self.bls_pk)?;
        state.end()
    }
}

impl AppKeys {
    /// Generate random keys
    pub fn random(owner_key: PublicKey) -> AppKeys {
        let (enc_pk, enc_sk) = shared_box::gen_keypair();
        let (sign_pk, sign_sk) = shared_sign::gen_keypair();
        let bls_sk = threshold_crypto::SecretKey::random();

        AppKeys {
            owner_key,
            enc_key: shared_secretbox::gen_key(),
            sign_pk,
            sign_sk,
            enc_pk,
            enc_sk,
            bls_sk: bls_sk.clone(),
            bls_pk: bls_sk.public_key(),
        }
    }

    /// Construct FFI wrapper for the native Rust object, consuming self.
    pub fn into_repr_c(self) -> ffi::AppKeys {
        let AppKeys {
            owner_key,
            enc_key,
            sign_pk,
            sign_sk,
            enc_pk,
            enc_sk,
            ..
        } = self;

        let owner_pk = match owner_key {
            PublicKey::Bls(pk) => pk.to_bytes(),
            _ => panic!("unexpected owner key type"), // TODO and FIXME: use proper ReprC for PublicKey
        };

        ffi::AppKeys {
            owner_key: owner_pk,
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
        let bls_sk = threshold_crypto::SecretKey::random();
        Ok(Self {
            owner_key: PublicKey::from(
                threshold_crypto::PublicKey::from_bytes(repr_c.owner_key)
                    .map_err(|_| IpcError::EncodeDecodeError)?,
            ),
            enc_key: shared_secretbox::Key::from_raw(&repr_c.enc_key),
            sign_pk: sign::PublicKey(repr_c.sign_pk),
            sign_sk: shared_sign::SecretKey::from_raw(&repr_c.sign_sk),
            enc_pk: box_::PublicKey(repr_c.enc_pk),
            enc_sk: shared_box::SecretKey::from_raw(&repr_c.enc_sk),
            bls_sk: bls_sk.clone(),
            bls_pk: bls_sk.public_key(),
        })
    }
}

impl Into<AppFullId> for AppKeys {
    fn into(self) -> AppFullId {
        let bls_sk = self.bls_sk.clone();
        AppFullId::with_keys(bls_sk, self.owner_key)
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

    let (containers, containers_len, containers_cap) = vec_into_raw_parts(vec);
    Ok(ffi::AccessContainerEntry {
        containers,
        containers_len,
        containers_cap,
    })
}

/// Convert FFI representation of `AccessContainerEntry` to native rust representation by cloning.
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
        let AccessContInfo { id, tag, nonce } = self;
        ffi::AccessContInfo {
            id: id.0,
            tag,
            nonce: nonce.0,
        }
    }

    /// Creates `MDataInfo` from this `AccessContInfo`
    pub fn into_mdata_info(self, enc_key: shared_secretbox::Key) -> MDataInfo {
        MDataInfo::new_private(self.id, self.tag, (enc_key, self.nonce))
    }

    /// Creates an `AccessContInfo` from a given `MDataInfo`
    pub fn from_mdata_info(md: &MDataInfo) -> Result<AccessContInfo, IpcError> {
        if let Some((_, nonce)) = md.enc_info {
            Ok(AccessContInfo {
                id: md.name,
                tag: md.type_tag,
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

/// Encrypts and serialises an access container key using given app ID and app key
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

/// Information about an app that has access to an MD through `sign_key`
#[derive(Debug)]
pub struct AppAccess {
    /// App's or user's public key
    pub sign_key: PublicKey,
    /// A list of permissions
    pub permissions: PermissionSet,
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

        let key = match sign_key {
            PublicKey::Bls(bls_key) => bls_key.to_bytes(),
            _ => return Err(IpcError::from("Unsupported key type")), // TODO: FFI repr for PublicKey
        };

        Ok(ffi::AppAccess {
            sign_key: key,
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

/// Redefine the Value from routing so that we can `impl ReprC`.
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize, Debug)]
pub struct MDataValue {
    /// Content of the entry.
    pub content: Vec<u8>,
    /// Version of the entry.
    pub entry_version: u64,
}

impl MDataValue {
    /// Convert routing representation to `MDataValue`.
    pub fn from_routing(value: Value) -> Self {
        MDataValue {
            content: value.content,
            entry_version: value.entry_version,
        }
    }

    /// Returns FFI counterpart without consuming the object.
    pub fn as_repr_c(&self) -> ffi::MDataValue {
        ffi::MDataValue {
            content: self.content.as_ptr(),
            content_len: self.content.len(),
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
        } = *repr_c;

        Ok(Self {
            content: slice::from_raw_parts(content, content_len).to_vec(),
            entry_version,
        })
    }
}

/// Mutable data key.
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize, Debug)]
pub struct MDataKey(
    /// Key value.
    pub Vec<u8>,
);

impl MDataKey {
    /// Convert routing representation to `MDataKey`.
    pub fn from_routing(key: Vec<u8>) -> Self {
        MDataKey(key)
    }

    /// Returns FFI counterpart without consuming the object.
    pub fn as_repr_c(&self) -> ffi::MDataKey {
        ffi::MDataKey {
            key: self.0.as_ptr(),
            key_len: self.0.len(),
        }
    }
}

impl ReprC for MDataKey {
    type C = *const ffi::MDataKey;
    type Error = ();

    unsafe fn clone_from_repr_c(repr_c: Self::C) -> Result<Self, Self::Error> {
        let ffi::MDataKey { key, key_len } = *repr_c;

        Ok(MDataKey(slice::from_raw_parts(key, key_len).to_vec()))
    }
}

/// Mutable data entry.
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize, Debug)]
pub struct MDataEntry {
    /// Key.
    pub key: MDataKey,
    /// Value.
    pub value: MDataValue,
}

impl MDataEntry {
    /// Returns FFI counterpart without consuming the object.
    pub fn as_repr_c(&self) -> ffi::MDataEntry {
        ffi::MDataEntry {
            key: self.key.as_repr_c(),
            value: self.value.as_repr_c(),
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
#[allow(unsafe_code)]
mod tests {
    use super::*;
    // use crate::ipc::BootstrapConfig;
    use ffi_utils::ReprC;
    use routing::{XorName, XOR_NAME_LEN};
    use rust_sodium::crypto::secretbox;

    // // Test converting an `AuthGranted` object to its FFI representation and then back again.
    // #[test]
    // fn auth_granted() {
    //     let (ok, _) = shared_sign::gen_keypair();
    //     let (pk, sk) = shared_sign::gen_keypair();
    //     let key = shared_secretbox::gen_key();
    //     let (ourpk, oursk) = shared_box::gen_keypair();
    //     let ak = AppKeys {
    //         owner_key: ok,
    //         enc_key: key,
    //         sign_pk: pk,
    //         sign_sk: sk,
    //         enc_pk: ourpk,
    //         enc_sk: oursk,
    //     };
    //     let ac = AccessContInfo {
    //         id: XorName([2; XOR_NAME_LEN]),
    //         tag: 681,
    //         nonce: secretbox::gen_nonce(),
    //     };
    //     let ag = AuthGranted {
    //         app_keys: ak,
    //         bootstrap_config: BootstrapConfig::default(),
    //         access_container_info: ac,
    //         access_container_entry: AccessContainerEntry::default(),
    //     };

    //     let ffi = unwrap!(ag.into_repr_c());

    //     assert_eq!(ffi.access_container_info.tag, 681);

    //     let ag = unsafe { unwrap!(AuthGranted::clone_from_repr_c(&ffi)) };

    //     assert_eq!(ag.access_container_info.tag, 681);
    // }

    // // Testing converting an `AppKeys` object to its FFI representation and back again.
    // #[test]
    // fn app_keys() {
    //     let (ok, _) = shared_sign::gen_keypair();
    //     let (pk, sk) = shared_sign::gen_keypair();
    //     let key = shared_secretbox::gen_key();
    //     let (ourpk, oursk) = shared_box::gen_keypair();
    //     let ak = AppKeys {
    //         owner_key: ok,
    //         enc_key: key.clone(),
    //         sign_pk: pk,
    //         sign_sk: sk.clone(),
    //         enc_pk: ourpk,
    //         enc_sk: oursk.clone(),
    //     };

    //     let ffi_ak = ak.into_repr_c();

    //     assert_eq!(
    //         ffi_ak.owner_key.iter().collect::<Vec<_>>(),
    //         ok.0.iter().collect::<Vec<_>>()
    //     );
    //     assert_eq!(
    //         ffi_ak.enc_key.iter().collect::<Vec<_>>(),
    //         key.0.iter().collect::<Vec<_>>()
    //     );
    //     assert_eq!(
    //         ffi_ak.sign_pk.iter().collect::<Vec<_>>(),
    //         pk.0.iter().collect::<Vec<_>>()
    //     );
    //     assert_eq!(
    //         ffi_ak.sign_sk.iter().collect::<Vec<_>>(),
    //         sk.0.iter().collect::<Vec<_>>()
    //     );
    //     assert_eq!(
    //         ffi_ak.enc_pk.iter().collect::<Vec<_>>(),
    //         ourpk.0.iter().collect::<Vec<_>>()
    //     );
    //     assert_eq!(
    //         ffi_ak.enc_sk.iter().collect::<Vec<_>>(),
    //         oursk.0.iter().collect::<Vec<_>>()
    //     );

    //     let ak = unsafe { unwrap!(AppKeys::clone_from_repr_c(ffi_ak)) };

    //     assert_eq!(ak.owner_key, ok);
    //     assert_eq!(ak.enc_key, key);
    //     assert_eq!(ak.sign_pk, pk);
    //     assert_eq!(ak.sign_sk, sk);
    //     assert_eq!(ak.enc_pk, ourpk);
    //     assert_eq!(ak.enc_sk, oursk);
    // }

    // Test converting an `AccessContInfo` struct to its FFI representation and back again.
    #[test]
    fn access_container() {
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
