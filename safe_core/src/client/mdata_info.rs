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

use errors::CoreError;
use rand::{OsRng, Rng};
use routing::XorName;
use rust_sodium::crypto::hash::sha256;
use rust_sodium::crypto::secretbox;
use utils::{symmetric_decrypt, symmetric_encrypt};

/// Information allowing to locate and access mutable data on the network.
#[derive(Clone, Debug, PartialEq, RustcDecodable, RustcEncodable)]
pub struct MDataInfo {
    /// Name of the data where the directory is stored.
    pub name: XorName,
    /// Type tag of the data where the directory is stored.
    pub type_tag: u64,
    /// Key to encrypt/decrypt the directory content.
    /// and the nonce to be used for keys
    pub enc_info: Option<(secretbox::Key, Option<secretbox::Nonce>)>,
}

impl MDataInfo {
    /// Generate random `MDataInfo` for private (encrypted) mutable data.
    pub fn random_private(type_tag: u64) -> Result<Self, CoreError> {
        let mut rng = os_rng()?;
        let enc_info = Some((secretbox::gen_key(), Some(secretbox::gen_nonce())));

        Ok(MDataInfo {
            name: rng.gen(),
            type_tag: type_tag,
            enc_info: enc_info,
        })
    }
    /// Generate random `MDataInfo` for public mutable data.
    pub fn random_public(type_tag: u64) -> Result<Self, CoreError> {
        let mut rng = os_rng()?;

        Ok(MDataInfo {
            name: rng.gen(),
            type_tag: type_tag,
            enc_info: None,
        })
    }

    /// encrypt the the key for the mdata entry accordingly
    pub fn enc_entry_key(&self, plain_text: &[u8]) -> Result<Vec<u8>, CoreError> {
        if let Some((ref key, seed)) = self.enc_info {
            let nonce = match seed {
                Some(secretbox::Nonce(ref dir_nonce)) => {
                    let mut pt = plain_text.to_vec();
                    pt.extend_from_slice(&dir_nonce[..]);
                    unwrap!(secretbox::Nonce::from_slice(
                        &sha256::hash(&pt)[..secretbox::NONCEBYTES]))
                }
                None => secretbox::gen_nonce(),
            };
            symmetric_encrypt(plain_text, key, Some(&nonce))
        } else {
            Ok(plain_text.to_vec())
        }
    }

    /// encrypt the value for this mdata entry accordingly
    pub fn enc_entry_value(&self, plain_text: &[u8]) -> Result<Vec<u8>, CoreError> {
        if let Some((ref key, _)) = self.enc_info {
            symmetric_encrypt(plain_text, key, None)
        } else {
            Ok(plain_text.to_vec())
        }
    }

    /// decrypt key or value of this mdata entry
    pub fn decrypt(&self, cipher: &[u8]) -> Result<Vec<u8>, CoreError> {
        if let Some((ref key, _)) = self.enc_info {
            symmetric_decrypt(cipher, key)
        } else {
            Ok(cipher.to_vec())
        }
    }
}

fn os_rng() -> Result<OsRng, CoreError> {
    OsRng::new().map_err(|_| CoreError::RandomDataGenerationFailure)
}

#[cfg(test)]
mod tests {
    use rand;
    use rust_sodium::crypto::secretbox;
    use super::*;

    #[test]
    fn private_mdata_info_encrypts() {
        let info = unwrap!(MDataInfo::random_private(0));
        let key = Vec::from("str of key");
        let val = Vec::from("other is value");
        let enc_key = unwrap!(info.enc_entry_key(&key));
        let enc_val = unwrap!(info.enc_entry_value(&val));
        assert_ne!(enc_key, key);
        assert_ne!(enc_val, val);
        assert_eq!(unwrap!(info.decrypt(&enc_key)), key);
        assert_eq!(unwrap!(info.decrypt(&enc_val)), val);
    }

    #[test]
    fn public_mdata_info_doesnt_encrypt() {
        let info = unwrap!(MDataInfo::random_public(0));
        let key = Vec::from("str of key");
        let val = Vec::from("other is value");
        assert_eq!(unwrap!(info.enc_entry_key(&key)), key);
        assert_eq!(unwrap!(info.enc_entry_value(&val)), val);
        assert_eq!(unwrap!(info.decrypt(&val)), val);
    }

    #[test]
    fn no_nonce_means_random_nonce() {
        let info = MDataInfo {
            name: rand::random(),
            type_tag: 0,
            enc_info: Some((secretbox::gen_key(), None)),
        };
        let key = Vec::from("str of key");
        let enc_key = unwrap!(info.enc_entry_key(&key));
        assert_ne!(enc_key, key);
        // encrypted is different on every run
        assert_ne!(unwrap!(info.enc_entry_key(&key)), key);
    }
}
