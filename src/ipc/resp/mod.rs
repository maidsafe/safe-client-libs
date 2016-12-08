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

/// Ffi module
pub mod ffi;

use ipc::{Config, IpcError};
use routing::XorName;
use rust_sodium::crypto::{box_, secretbox, sign};

/// IPC response
// TODO: `TransOwnership` variant
#[derive(Debug, Eq, PartialEq, RustcEncodable, RustcDecodable)]
pub enum IpcResp {
    /// Authentication
    Auth(Result<AuthGranted, IpcError>),
    /// Containers
    Containers,
}

/// It represents the authentication response.
#[derive(RustcEncodable, RustcDecodable, Debug, PartialEq, Eq)]
pub struct AuthGranted {
    /// The access keys.
    pub app_keys: AppKeys,
    /// The crust config.
    ///
    /// Useful to reuse bootstrap nodes and speed up access.
    pub bootstrap_config: Config,
    /// Access container
    pub access_container: AccessContainer,
}

impl AuthGranted {
    /// Consumes the object and returns the wrapped raw pointer
    ///
    /// You're now responsible for freeing this memory once you're done.
    pub fn into_repr_c(self) -> ffi::AuthGranted {
        let AuthGranted { app_keys, access_container, .. } = self;
        ffi::AuthGranted {
            app_keys: app_keys.into_repr_c(),
            access_container: access_container.into_repr_c(),
        }
    }

    /// Constructs the object from a raw pointer.
    ///
    /// After calling this function, the raw pointer is owned by the resulting
    /// object.
    #[allow(unsafe_code)]
    pub unsafe fn from_repr_c(repr_c: ffi::AuthGranted) -> Self {
        let ffi::AuthGranted { app_keys, access_container } = repr_c;
        AuthGranted {
            app_keys: AppKeys::from_repr_c(app_keys),
            bootstrap_config: Config,
            access_container: AccessContainer::from_repr_c(access_container),
        }
    }
}

/// Represents the needed keys to work with the data
#[derive(RustcEncodable, RustcDecodable, Debug, Eq, PartialEq)]
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

    /// Constructs the object from a raw pointer.
    ///
    /// After calling this function, the raw pointer is owned by the resulting
    /// object.
    #[allow(unsafe_code)]
    pub unsafe fn from_repr_c(raw: ffi::AppKeys) -> Self {
        AppKeys {
            owner_key: sign::PublicKey(raw.owner_key),
            enc_key: secretbox::Key(raw.enc_key),
            sign_pk: sign::PublicKey(raw.sign_pk),
            sign_sk: sign::SecretKey(raw.sign_sk),
            enc_pk: box_::PublicKey(raw.enc_pk),
            enc_sk: box_::SecretKey(raw.enc_sk),
        }
    }
}

/// Access container
#[derive(RustcEncodable, RustcDecodable, Debug, Eq, PartialEq)]
pub struct AccessContainer {
    /// ID
    pub id: XorName,
    /// Type tag
    pub tag: u64,
    /// Nonce
    pub nonce: secretbox::Nonce,
}

impl AccessContainer {
    /// Consumes the object and returns the wrapped raw pointer
    ///
    /// You're now responsible for freeing this memory once you're done.
    pub fn into_repr_c(self) -> ffi::AccessContainer {
        let AccessContainer { id, tag, nonce } = self;
        ffi::AccessContainer {
            id: id.0,
            tag: tag,
            nonce: nonce.0,
        }
    }

    /// Constructs the object from a raw pointer.
    ///
    /// After calling this function, the raw pointer is owned by the resulting
    /// object.
    #[allow(unsafe_code)]
    pub unsafe fn from_repr_c(repr_c: ffi::AccessContainer) -> Self {
        AccessContainer {
            id: XorName(repr_c.id),
            tag: repr_c.tag,
            nonce: secretbox::Nonce(repr_c.nonce),
        }
    }
}

#[cfg(test)]
#[allow(unsafe_code)]
mod tests {
    use rust_sodium::crypto::{box_, secretbox, sign};
    use super::*;

    #[test]
    fn app_keys() {
        let (ok, _) = sign::gen_keypair();
        let (pk, sk) = sign::gen_keypair();
        let key = secretbox::gen_key();
        let (ourpk, oursk) = box_::gen_keypair();
        let ak = AppKeys {
            owner_key: ok.clone(),
            enc_key: key.clone(),
            sign_pk: pk.clone(),
            sign_sk: sk.clone(),
            enc_pk: ourpk.clone(),
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

        let ak = unsafe { AppKeys::from_repr_c(ffi_ak) };

        assert_eq!(ak.owner_key, ok);
        assert_eq!(ak.enc_key, key);
        assert_eq!(ak.sign_pk, pk);
        assert_eq!(ak.sign_sk, sk);
        assert_eq!(ak.enc_pk, ourpk);
        assert_eq!(ak.enc_sk, oursk);

        // If test runs under special mode (e.g. Valgrind) we can detect memory
        // leaks
        unsafe {
            ffi::app_keys_drop(ak.into_repr_c());
        }
    }
}
