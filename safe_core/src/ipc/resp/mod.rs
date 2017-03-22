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

#![allow(unsafe_code)]

/// Ffi module
pub mod ffi;

use client::MDataInfo;
use ffi_utils::{ReprC, vec_into_raw_parts};
use ipc::IpcError;
use maidsafe_utilities::serialisation::{SerialisationError, deserialise, serialise};
use routing::{BootstrapConfig, XorName};
use rust_sodium::crypto::{box_, hash, secretbox, sign};
use std::slice;

/// IPC response
// TODO: `TransOwnership` variant
#[cfg_attr(feature="cargo-clippy", allow(large_enum_variant))]
#[derive(Debug, Eq, PartialEq, RustcEncodable, RustcDecodable)]
pub enum IpcResp {
    /// Authentication
    Auth(Result<AuthGranted, IpcError>),
    /// Containers
    Containers(Result<(), IpcError>),
}

/// It represents the authentication response.
#[derive(Clone, RustcEncodable, RustcDecodable, Debug, PartialEq, Eq)]
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
        let AuthGranted { app_keys, bootstrap_config, access_container } = self;
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
        let ffi::AuthGranted { app_keys,
                               access_container,
                               bootstrap_config_ptr,
                               bootstrap_config_len,
                               .. } = *repr_c;
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
#[derive(Clone, RustcEncodable, RustcDecodable, Debug, Eq, PartialEq)]
pub struct AppKeys {
    /// Owner signing public key.
    pub owner_key: sign::PublicKey,
    /// Data symmetric encryption key
    pub enc_key: secretbox::Key,
    /// Asymmetric sign public key.
    ///
    /// This is the identity of the App in the Network.
    pub sign_pk: sign::PublicKey,
    /// Asymmetric sign private key.
    pub sign_sk: sign::SecretKey,
    /// Asymmetric enc public key.
    pub enc_pk: box_::PublicKey,
    /// Asymmetric enc private key.
    pub enc_sk: box_::SecretKey,
}

impl AppKeys {
    /// Generate random keys
    pub fn random(owner_key: sign::PublicKey) -> AppKeys {
        let (enc_pk, enc_sk) = box_::gen_keypair();
        let (sign_pk, sign_sk) = sign::gen_keypair();

        AppKeys {
            owner_key: owner_key,
            enc_key: secretbox::gen_key(),
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
        let AppKeys { owner_key, enc_key, sign_pk, sign_sk, enc_pk, enc_sk } = self;
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
               owner_key: sign::PublicKey(raw.owner_key),
               enc_key: secretbox::Key(raw.enc_key),
               sign_pk: sign::PublicKey(raw.sign_pk),
               sign_sk: sign::SecretKey(raw.sign_sk),
               enc_pk: box_::PublicKey(raw.enc_pk),
               enc_sk: box_::SecretKey(raw.enc_sk),
           })
    }
}

/// Access container
#[derive(Clone, RustcEncodable, RustcDecodable, Debug, Eq, PartialEq)]
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
    pub fn into_mdata_info(self, enc_key: secretbox::Key) -> MDataInfo {
        MDataInfo {
            name: self.id,
            type_tag: self.tag,
            enc_info: Some((enc_key, Some(self.nonce))),
        }
    }

    /// Creates an `AccessContInfo` from a given `MDataInfo`
    pub fn from_mdata_info(md: MDataInfo) -> Result<AccessContInfo, IpcError> {
        if let Some((_, Some(nonce))) = md.enc_info {
            Ok(AccessContInfo {
                   id: md.name,
                   tag: md.type_tag,
                   nonce: nonce,
               })
        } else {
            Err(IpcError::Unexpected("MDataInfo doesn't contain nonce".to_owned()))
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
pub fn access_container_enc_key(app_id: &str,
                                app_enc_key: &secretbox::Key,
                                access_container_nonce: &secretbox::Nonce)
                                -> Result<Vec<u8>, IpcError> {
    let key = app_id.as_bytes();
    let mut key_pt = key.to_vec();
    key_pt.extend_from_slice(&access_container_nonce[..]);

    let key_nonce =
        secretbox::Nonce::from_slice(&hash::sha256::hash(&key_pt)[..secretbox::NONCEBYTES])
            .ok_or(IpcError::EncodeDecodeError)?;

    Ok(secretbox::seal(key, &key_nonce, app_enc_key))
}

#[cfg(test)]
#[allow(unsafe_code)]
mod tests {
    use super::*;
    use ffi_utils::ReprC;
    use ipc::BootstrapConfig;
    use routing::{XOR_NAME_LEN, XorName};
    use rust_sodium::crypto::{box_, secretbox, sign};

    #[test]
    fn auth_granted() {
        let (ok, _) = sign::gen_keypair();
        let (pk, sk) = sign::gen_keypair();
        let key = secretbox::gen_key();
        let (ourpk, oursk) = box_::gen_keypair();
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
        let (ok, _) = sign::gen_keypair();
        let (pk, sk) = sign::gen_keypair();
        let key = secretbox::gen_key();
        let (ourpk, oursk) = box_::gen_keypair();
        let ak = AppKeys {
            owner_key: ok,
            enc_key: key.clone(),
            sign_pk: pk,
            sign_sk: sk.clone(),
            enc_pk: ourpk,
            enc_sk: oursk.clone(),
        };

        let ffi_ak = ak.into_repr_c();

        assert_eq!(ffi_ak.owner_key.iter().collect::<Vec<_>>(),
                   ok.0.iter().collect::<Vec<_>>());
        assert_eq!(ffi_ak.enc_key.iter().collect::<Vec<_>>(),
                   key.0.iter().collect::<Vec<_>>());
        assert_eq!(ffi_ak.sign_pk.iter().collect::<Vec<_>>(),
                   pk.0.iter().collect::<Vec<_>>());
        assert_eq!(ffi_ak.sign_sk.iter().collect::<Vec<_>>(),
                   sk.0.iter().collect::<Vec<_>>());
        assert_eq!(ffi_ak.enc_pk.iter().collect::<Vec<_>>(),
                   ourpk.0.iter().collect::<Vec<_>>());
        assert_eq!(ffi_ak.enc_sk.iter().collect::<Vec<_>>(),
                   oursk.0.iter().collect::<Vec<_>>());

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
        assert_eq!(ffi.nonce.iter().collect::<Vec<_>>(),
                   nonce.0.iter().collect::<Vec<_>>());

        let a = unsafe { unwrap!(AccessContInfo::clone_from_repr_c(ffi)) };

        assert_eq!(a.id
                       .0
                       .iter()
                       .sum::<u8>() as usize,
                   2 * XOR_NAME_LEN);
        assert_eq!(a.tag, 681);
        assert_eq!(a.nonce, nonce);
    }
}
