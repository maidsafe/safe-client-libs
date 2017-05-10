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

use errors::CoreError;
use rand::{OsRng, Rng};
use routing::{EntryAction, Value, XorName};
use rust_sodium::crypto::hash::sha256;
use rust_sodium::crypto::secretbox;
use std::collections::{BTreeMap, BTreeSet};
use utils::{symmetric_decrypt, symmetric_encrypt};

/// Information allowing to locate and access mutable data on the network.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
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
    /// Construct `MDataInfo` for private (encrypted) data with a
    /// provided private key.
    pub fn new_private(name: XorName,
                       type_tag: u64,
                       enc_info: (secretbox::Key, Option<secretbox::Nonce>))
                       -> Self {
        MDataInfo {
            name,
            type_tag,
            enc_info: Some(enc_info),
        }
    }

    /// Construct `MDataInfo` for private (encrypted) data with a
    /// randomly generated private key.
    pub fn gen_private(name: XorName, type_tag: u64) -> Self {
        let enc_info = Some((secretbox::gen_key(), Some(secretbox::gen_nonce())));

        MDataInfo {
            name,
            type_tag,
            enc_info,
        }
    }

    /// Construct `MDataInfo` for public data.
    pub fn new_public(name: XorName, type_tag: u64) -> Self {
        MDataInfo {
            name,
            type_tag,
            enc_info: None,
        }
    }

    /// Generate random `MDataInfo` for private (encrypted) mutable data.
    pub fn random_private(type_tag: u64) -> Result<Self, CoreError> {
        let mut rng = os_rng()?;
        Ok(Self::gen_private(rng.gen(), type_tag))
    }
    /// Generate random `MDataInfo` for public mutable data.
    pub fn random_public(type_tag: u64) -> Result<Self, CoreError> {
        let mut rng = os_rng()?;
        Ok(Self::new_public(rng.gen(), type_tag))
    }

    /// encrypt the the key for the mdata entry accordingly
    pub fn enc_entry_key(&self, plain_text: &[u8]) -> Result<Vec<u8>, CoreError> {
        if let Some((ref key, seed)) = self.enc_info {
            let nonce = match seed {
                Some(secretbox::Nonce(ref dir_nonce)) => {
                    let mut pt = plain_text.to_vec();
                    pt.extend_from_slice(&dir_nonce[..]);
                    unwrap!(secretbox::Nonce::from_slice(&sha256::hash(&pt)
                                                              [..secretbox::NONCEBYTES]))
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

/// Encrypt the entries (both keys and values) using the `MDataInfo`.
pub fn encrypt_entries(info: &MDataInfo,
                       entries: &BTreeMap<Vec<u8>, Value>)
                       -> Result<BTreeMap<Vec<u8>, Value>, CoreError> {
    let mut output = BTreeMap::new();

    for (key, value) in entries {
        let encrypted_key = info.enc_entry_key(key)?;
        let encrypted_value = encrypt_value(info, value)?;
        let _ = output.insert(encrypted_key, encrypted_value);
    }

    Ok(output)
}

/// Encrypt entry actions using the `MDataInfo`. The effect of this is that the entries
/// mutated by the encrypted actions will end up encrypted using the `MDataInfo`.
pub fn encrypt_entry_actions(info: &MDataInfo,
                             actions: &BTreeMap<Vec<u8>, EntryAction>)
                             -> Result<BTreeMap<Vec<u8>, EntryAction>, CoreError> {
    let mut output = BTreeMap::new();

    for (key, action) in actions {
        let encrypted_key = info.enc_entry_key(key)?;
        let encrypted_action = match *action {
            EntryAction::Ins(ref value) => EntryAction::Ins(encrypt_value(info, value)?),
            EntryAction::Update(ref value) => EntryAction::Update(encrypt_value(info, value)?),
            EntryAction::Del(version) => EntryAction::Del(version),
        };

        let _ = output.insert(encrypted_key, encrypted_action);
    }

    Ok(output)
}

/// Decrypt entries using the `MDataInfo`.
pub fn decrypt_entries(info: &MDataInfo,
                       entries: &BTreeMap<Vec<u8>, Value>)
                       -> Result<BTreeMap<Vec<u8>, Value>, CoreError> {
    let mut output = BTreeMap::new();

    for (key, value) in entries {
        let decrypted_key = info.decrypt(key)?;
        let decrypted_value = decrypt_value(info, value)?;

        let _ = output.insert(decrypted_key, decrypted_value);
    }

    Ok(output)
}

/// Decrypt all keys using the `MDataInfo`.
pub fn decrypt_keys(info: &MDataInfo,
                    keys: &BTreeSet<Vec<u8>>)
                    -> Result<BTreeSet<Vec<u8>>, CoreError> {
    let mut output = BTreeSet::new();

    for key in keys {
        let _ = output.insert(info.decrypt(key)?);
    }

    Ok(output)
}

/// Decrypt all values using the `MDataInfo`.
pub fn decrypt_values(info: &MDataInfo, values: &[Value]) -> Result<Vec<Value>, CoreError> {
    let mut output = Vec::with_capacity(values.len());

    for value in values {
        output.push(decrypt_value(info, value)?);
    }

    Ok(output)
}

fn encrypt_value(info: &MDataInfo, value: &Value) -> Result<Value, CoreError> {
    Ok(Value {
           content: info.enc_entry_value(&value.content)?,
           entry_version: value.entry_version,
       })
}

fn decrypt_value(info: &MDataInfo, value: &Value) -> Result<Value, CoreError> {
    Ok(Value {
           content: info.decrypt(&value.content)?,
           entry_version: value.entry_version,
       })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand;
    use rust_sodium::crypto::secretbox;

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
