// Copyright 2016 MaidSafe.net limited.
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

/// Ffi module
pub mod ffi;

use client::MDataInfo;
use crypto::{shared_box, shared_secretbox, shared_sign};
use ffi_utils::{ReprC, StringError, vec_into_raw_parts};
use ipc::IpcError;
use ipc::req::{permission_set_clone_from_repr_c, permission_set_into_repr_c};
use maidsafe_utilities::serialisation::{SerialisationError, deserialise, serialise};
use routing::{BootstrapConfig, XorName};
use routing::PermissionSet;
use rust_sodium::crypto::{box_, secretbox};
use rust_sodium::crypto::sign::PublicKey;
use std::ffi::{CString, NulError};
use std::ptr;
use std::slice;
use tiny_keccak::sha3_256;

/// Entry key under which the metadata are stored.
#[no_mangle]
pub static METADATA_KEY: &'static [u8] = b"_metadata";
/// Length of the metadata key.
// IMPORTANT: make sure this value stays in sync with the actual length of `METADATA_KEY`!
#[no_mangle]
pub static METADATA_KEY_LEN: usize = 9;

/// IPC response
// TODO: `TransOwnership` variant
#[cfg_attr(feature = "cargo-clippy", allow(large_enum_variant))]
#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum IpcResp {
    /// Authentication
    Auth(Result<AuthGranted, IpcError>),
    /// Containers
    Containers(Result<(), IpcError>),
    /// Unregistered client
    Unregistered(Result<BootstrapConfig, IpcError>),
    /// Share mutable data
    ShareMData(Result<(), IpcError>),
}

/// It represents the authentication response.
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct AuthGranted {
    /// The access keys.
    pub app_keys: AppKeys,
    /// The crust config.
    ///
    /// Useful to reuse bootstrap nodes and speed up access.
    pub bootstrap_config: BootstrapConfig,
    /// Access container
    pub access_container: AccessContInfo,
}

impl AuthGranted {
    /// Consumes the object and returns the wrapped raw pointer
    ///
    /// You're now responsible for freeing this memory once you're done.
    pub fn into_repr_c(self) -> Result<ffi::AuthGranted, SerialisationError> {
        let AuthGranted {
            app_keys,
            bootstrap_config,
            access_container,
        } = self;
        let bootstrap_config = serialise(&bootstrap_config)?;
        let (ptr, len, cap) = vec_into_raw_parts(bootstrap_config);
        Ok(ffi::AuthGranted {
            app_keys: app_keys.into_repr_c(),
            access_container: access_container.into_repr_c(),
            bootstrap_config_ptr: ptr,
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
            access_container,
            bootstrap_config_ptr,
            bootstrap_config_len,
            ..
        } = *repr_c;
        let bootstrap_config = slice::from_raw_parts(bootstrap_config_ptr, bootstrap_config_len);
        let bootstrap_config = deserialise(bootstrap_config)?;
        Ok(AuthGranted {
            app_keys: AppKeys::clone_from_repr_c(app_keys)?,
            bootstrap_config: bootstrap_config,
            access_container: AccessContInfo::clone_from_repr_c(access_container)?,
        })
    }
}

/// Represents the needed keys to work with the data
#[derive(Clone, Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct AppKeys {
    /// Owner signing public key.
    pub owner_key: PublicKey,
    /// Data symmetric encryption key
    pub enc_key: shared_secretbox::Key,
    /// Asymmetric sign public key.
    ///
    /// This is the identity of the App in the Network.
    pub sign_pk: PublicKey,
    /// Asymmetric sign private key.
    pub sign_sk: shared_sign::SecretKey,
    /// Asymmetric enc public key.
    pub enc_pk: box_::PublicKey,
    /// Asymmetric enc private key.
    pub enc_sk: shared_box::SecretKey,
}

impl AppKeys {
    /// Generate random keys
    pub fn random(owner_key: PublicKey) -> AppKeys {
        let (enc_pk, enc_sk) = shared_box::gen_keypair();
        let (sign_pk, sign_sk) = shared_sign::gen_keypair();

        AppKeys {
            owner_key: owner_key,
            enc_key: shared_secretbox::gen_key(),
            sign_pk: sign_pk,
            sign_sk: sign_sk,
            enc_pk: enc_pk,
            enc_sk: enc_sk,
        }
    }

    /// Consumes the object and returns the wrapped raw pointer
    ///
    /// You're now responsible for freeing this memory once you're done.
    pub fn into_repr_c(self) -> ffi::AppKeys {
        let AppKeys {
            owner_key,
            enc_key,
            sign_pk,
            sign_sk,
            enc_pk,
            enc_sk,
        } = self;
        ffi::AppKeys {
            owner_key: owner_key.0,
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

    unsafe fn clone_from_repr_c(raw: Self::C) -> Result<Self, Self::Error> {
        Ok(AppKeys {
            owner_key: PublicKey(raw.owner_key),
            enc_key: shared_secretbox::Key::from_raw(&raw.enc_key),
            sign_pk: PublicKey(raw.sign_pk),
            sign_sk: shared_sign::SecretKey::from_raw(&raw.sign_sk),
            enc_pk: box_::PublicKey(raw.enc_pk),
            enc_sk: shared_box::SecretKey::from_raw(&raw.enc_sk),
        })
    }
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
    /// Consumes the object and returns the wrapped raw pointer
    ///
    /// You're now responsible for freeing this memory once you're done.
    pub fn into_repr_c(self) -> ffi::AccessContInfo {
        let AccessContInfo { id, tag, nonce } = self;
        ffi::AccessContInfo {
            id: id.0,
            tag: tag,
            nonce: nonce.0,
        }
    }

    /// Creates `MDataInfo` from this `AccessContInfo`
    pub fn into_mdata_info(self, enc_key: shared_secretbox::Key) -> MDataInfo {
        MDataInfo::new_private(self.id, self.tag, (enc_key, self.nonce))
    }

    /// Creates an `AccessContInfo` from a given `MDataInfo`
    pub fn from_mdata_info(md: MDataInfo) -> Result<AccessContInfo, IpcError> {
        if let Some((_, nonce)) = md.enc_info {
            Ok(AccessContInfo {
                id: md.name,
                tag: md.type_tag,
                nonce: nonce,
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
        Ok(AccessContInfo {
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
    /// Consumes the object and returns the wrapped raw pointer.
    ///
    /// You're now responsible for freeing this memory once you're done.
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

        Ok(ffi::AppAccess {
            sign_key: sign_key.0,
            permissions: permission_set_into_repr_c(permissions),
            name: name,
            app_id: app_id,
        })
    }
}

impl ReprC for AppAccess {
    type C = *const ffi::AppAccess;
    type Error = IpcError;

    unsafe fn clone_from_repr_c(repr_c: Self::C) -> Result<Self, Self::Error> {
        Ok(AppAccess {
            sign_key: PublicKey((*repr_c).sign_key),
            permissions: permission_set_clone_from_repr_c(&(*repr_c).permissions)?,
            name: Some(String::clone_from_repr_c((*repr_c).name)?),
            app_id: Some(String::clone_from_repr_c((*repr_c).app_id)?),
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
            type_tag: type_tag,
        })
    }
}

impl ReprC for UserMetadata {
    type C = *const ffi::MetadataResponse;
    type Error = IpcError;

    unsafe fn clone_from_repr_c(repr_c: Self::C) -> Result<Self, Self::Error> {
        Ok(UserMetadata {
            name: if (*repr_c).name.is_null() {
                None
            } else {
                Some(String::clone_from_repr_c((*repr_c).name)?)
            },
            description: if (*repr_c).description.is_null() {
                None
            } else {
                Some(String::clone_from_repr_c((*repr_c).description)?)
            },
        })
    }
}

#[cfg(test)]
#[allow(unsafe_code)]
mod tests {
    use super::*;
    use ffi_utils::ReprC;
    use ipc::BootstrapConfig;
    use routing::{XOR_NAME_LEN, XorName};
    use rust_sodium::crypto::secretbox;

    #[test]
    fn auth_granted() {
        let (ok, _) = shared_sign::gen_keypair();
        let (pk, sk) = shared_sign::gen_keypair();
        let key = shared_secretbox::gen_key();
        let (ourpk, oursk) = shared_box::gen_keypair();
        let ak = AppKeys {
            owner_key: ok,
            enc_key: key,
            sign_pk: pk,
            sign_sk: sk,
            enc_pk: ourpk,
            enc_sk: oursk,
        };
        let ac = AccessContInfo {
            id: XorName([2; XOR_NAME_LEN]),
            tag: 681,
            nonce: secretbox::gen_nonce(),
        };
        let ag = AuthGranted {
            app_keys: ak,
            bootstrap_config: BootstrapConfig::default(),
            access_container: ac,
        };

        let ffi = unwrap!(ag.into_repr_c());

        assert_eq!(ffi.access_container.tag, 681);

        let ag = unsafe { unwrap!(AuthGranted::clone_from_repr_c(&ffi)) };

        assert_eq!(ag.access_container.tag, 681);
    }

    #[test]
    fn app_keys() {
        let (ok, _) = shared_sign::gen_keypair();
        let (pk, sk) = shared_sign::gen_keypair();
        let key = shared_secretbox::gen_key();
        let (ourpk, oursk) = shared_box::gen_keypair();
        let ak = AppKeys {
            owner_key: ok,
            enc_key: key.clone(),
            sign_pk: pk,
            sign_sk: sk.clone(),
            enc_pk: ourpk,
            enc_sk: oursk.clone(),
        };

        let ffi_ak = ak.into_repr_c();

        assert_eq!(
            ffi_ak.owner_key.iter().collect::<Vec<_>>(),
            ok.0.iter().collect::<Vec<_>>()
        );
        assert_eq!(
            ffi_ak.enc_key.iter().collect::<Vec<_>>(),
            key.0.iter().collect::<Vec<_>>()
        );
        assert_eq!(
            ffi_ak.sign_pk.iter().collect::<Vec<_>>(),
            pk.0.iter().collect::<Vec<_>>()
        );
        assert_eq!(
            ffi_ak.sign_sk.iter().collect::<Vec<_>>(),
            sk.0.iter().collect::<Vec<_>>()
        );
        assert_eq!(
            ffi_ak.enc_pk.iter().collect::<Vec<_>>(),
            ourpk.0.iter().collect::<Vec<_>>()
        );
        assert_eq!(
            ffi_ak.enc_sk.iter().collect::<Vec<_>>(),
            oursk.0.iter().collect::<Vec<_>>()
        );

        let ak = unsafe { unwrap!(AppKeys::clone_from_repr_c(ffi_ak)) };

        assert_eq!(ak.owner_key, ok);
        assert_eq!(ak.enc_key, key);
        assert_eq!(ak.sign_pk, pk);
        assert_eq!(ak.sign_sk, sk);
        assert_eq!(ak.enc_pk, ourpk);
        assert_eq!(ak.enc_sk, oursk);
    }

    #[test]
    fn access_container() {
        let nonce = secretbox::gen_nonce();
        let a = AccessContInfo {
            id: XorName([2; XOR_NAME_LEN]),
            tag: 681,
            nonce: nonce,
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
