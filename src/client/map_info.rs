// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::crypto::shared_secretbox;
use crate::errors::Error;
use crate::utils::{
    self, symmetric_decrypt, symmetric_encrypt, SymEncKey, SymEncNonce, SYM_ENC_NONCE_LEN,
};
use serde::{Deserialize, Serialize};
use sn_data_types::{MapAddress, MapKind, MapSeqEntries, MapSeqEntryAction, MapSeqValue};
use std::collections::{BTreeMap, BTreeSet};
use std::convert::TryInto;
use tiny_keccak::sha3_256;
use unwrap::unwrap;
use xor_name::XorName;

/// Information allowing to locate and access mutable data on the network.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct MapInfo {
    /// Address of the mutable data, containing its name, type tag, and whether it is sequenced.
    pub address: MapAddress,
    /// Key to encrypt/decrypt the directory content and the nonce to be used for keys
    pub enc_info: Option<(shared_secretbox::Key, SymEncNonce)>,

    /// Future encryption info, used for two-phase data reencryption.
    pub new_enc_info: Option<(shared_secretbox::Key, SymEncNonce)>,
}

impl MapInfo {
    /// Construct `MapInfo` for private (encrypted) data with a provided private key.
    pub fn new_private(
        address: MapAddress,
        enc_info: (shared_secretbox::Key, SymEncNonce),
    ) -> Self {
        Self {
            address,
            enc_info: Some(enc_info),
            new_enc_info: None,
        }
    }

    /// Construct `MapInfo` for public data.
    pub fn new_public(address: MapAddress) -> Self {
        Self {
            address,
            enc_info: None,
            new_enc_info: None,
        }
    }

    /// Generate random `MapInfo` for private (encrypted) mutable data.
    pub fn random_private(kind: MapKind, type_tag: u64) -> Result<Self, Error> {
        let address = MapAddress::from_kind(kind, rand::random(), type_tag);
        let enc_info = (shared_secretbox::gen_key(), utils::generate_nonce());

        Ok(Self::new_private(address, enc_info))
    }

    /// Generate random `MapInfo` for public mutable data.
    pub fn random_public(kind: MapKind, type_tag: u64) -> Result<Self, Error> {
        let address = MapAddress::from_kind(kind, rand::random(), type_tag);

        Ok(Self::new_public(address))
    }

    /// Returns the name.
    pub fn name(&self) -> XorName {
        *self.address.name()
    }

    /// Returns the type tag.
    pub fn type_tag(&self) -> u64 {
        self.address.tag()
    }

    /// Returns the address of the data.
    pub fn address(&self) -> &MapAddress {
        &self.address
    }

    /// Returns the kind.
    pub fn kind(&self) -> MapKind {
        self.address.kind()
    }

    /// Returns the encryption key, if any.
    pub fn enc_key(&self) -> Option<&shared_secretbox::Key> {
        self.enc_info.as_ref().map(|&(ref key, _)| key)
    }

    /// Returns the nonce, if any.
    pub fn nonce(&self) -> Option<&SymEncNonce> {
        self.enc_info.as_ref().map(|&(_, ref nonce)| nonce)
    }

    /// Encrypt the key for the map entry accordingly.
    pub fn enc_entry_key(&self, plain_text: &[u8]) -> Result<Vec<u8>, Error> {
        if let Some((ref key, seed)) = self.new_enc_info {
            enc_entry_key(plain_text, key, seed)
        } else if let Some((ref key, seed)) = self.enc_info {
            enc_entry_key(plain_text, key, seed)
        } else {
            Ok(plain_text.to_vec())
        }
    }

    /// Encrypt the value for this map entry accordingly.
    pub fn enc_entry_value(&self, plain_text: &[u8]) -> Result<Vec<u8>, Error> {
        if let Some((ref key, _)) = self.new_enc_info {
            symmetric_encrypt(plain_text, key, None)
        } else if let Some((ref key, _)) = self.enc_info {
            symmetric_encrypt(plain_text, key, None)
        } else {
            Ok(plain_text.to_vec())
        }
    }

    /// Decrypt key or value of this map entry.
    pub fn decrypt(&self, cipher: &[u8]) -> Result<Vec<u8>, Error> {
        if let Some((ref key, _)) = self.new_enc_info {
            if let Ok(plain) = symmetric_decrypt(cipher, key) {
                return Ok(plain);
            }
        }

        if let Some((ref key, _)) = self.enc_info {
            symmetric_decrypt(cipher, key)
        } else {
            Ok(cipher.to_vec())
        }
    }

    /// Start the encryption info re-generation by populating the `new_enc_info`
    /// field with random keys, unless it's already populated.
    pub fn start_new_enc_info(&mut self) {
        if self.enc_info.is_some() && self.new_enc_info.is_none() {
            self.new_enc_info = Some((shared_secretbox::gen_key(), utils::generate_nonce()));
        }
    }

    /// Commit the encryption info re-generation by replacing the current encryption info
    /// with `new_enc_info` (if any).
    pub fn commit_new_enc_info(&mut self) {
        if let Some(new_enc_info) = self.new_enc_info.take() {
            self.enc_info = Some(new_enc_info);
        }
    }
}

/// Encrypt the entries (both keys and values) using the `MapInfo`.
pub fn encrypt_entries(info: &MapInfo, entries: &MapSeqEntries) -> Result<MapSeqEntries, Error> {
    let mut output = BTreeMap::new();

    for (key, value) in entries {
        let encrypted_key = info.enc_entry_key(key)?;
        let encrypted_value = encrypt_value(info, value)?;
        let _ = output.insert(encrypted_key, encrypted_value);
    }

    Ok(output)
}

/// Encrypt entry actions using the `MapInfo`. The effect of this is that the entries
/// mutated by the encrypted actions will end up encrypted using the `MapInfo`.
pub fn encrypt_entry_actions(
    info: &MapInfo,
    actions: &BTreeMap<Vec<u8>, MapSeqEntryAction>,
) -> Result<BTreeMap<Vec<u8>, MapSeqEntryAction>, Error> {
    let mut output = BTreeMap::new();

    for (key, action) in actions {
        let encrypted_key = info.enc_entry_key(key)?;
        let encrypted_action = match *action {
            MapSeqEntryAction::Ins(ref value) => {
                MapSeqEntryAction::Ins(encrypt_value(info, value)?)
            }
            MapSeqEntryAction::Update(ref value) => {
                MapSeqEntryAction::Update(encrypt_value(info, value)?)
            }
            MapSeqEntryAction::Del(version) => MapSeqEntryAction::Del(version),
        };

        let _ = output.insert(encrypted_key, encrypted_action);
    }

    Ok(output)
}

/// Decrypt entries using the `MapInfo`.
pub fn decrypt_entries(info: &MapInfo, entries: &MapSeqEntries) -> Result<MapSeqEntries, Error> {
    let mut output = BTreeMap::new();

    for (key, value) in entries {
        let decrypted_key = info.decrypt(key)?;
        let decrypted_value = decrypt_value(info, value)?;

        let _ = output.insert(decrypted_key, decrypted_value);
    }

    Ok(output)
}

/// Decrypt all keys using the `MapInfo`.
pub fn decrypt_keys(info: &MapInfo, keys: &BTreeSet<Vec<u8>>) -> Result<BTreeSet<Vec<u8>>, Error> {
    let mut output = BTreeSet::new();

    for key in keys {
        let _ = output.insert(info.decrypt(key)?);
    }

    Ok(output)
}

/// Decrypt all values using the `MapInfo`.
pub fn decrypt_values(info: &MapInfo, values: &[MapSeqValue]) -> Result<Vec<MapSeqValue>, Error> {
    let mut output = Vec::with_capacity(values.len());

    for value in values {
        output.push(decrypt_value(info, value)?);
    }

    Ok(output)
}

fn encrypt_value(info: &MapInfo, value: &MapSeqValue) -> Result<MapSeqValue, Error> {
    Ok(MapSeqValue {
        data: info.enc_entry_value(&value.data)?,
        version: value.version,
    })
}

fn decrypt_value(info: &MapInfo, value: &MapSeqValue) -> Result<MapSeqValue, Error> {
    Ok(MapSeqValue {
        data: info.decrypt(&value.data)?,
        version: value.version,
    })
}

fn enc_entry_key(plain_text: &[u8], key: &SymEncKey, seed: SymEncNonce) -> Result<Vec<u8>, Error> {
    let nonce: SymEncNonce = {
        let mut pt = plain_text.to_vec();
        pt.extend_from_slice(&seed[..]);
        // safe to unwrap as hash length is 256
        unwrap!(sha3_256(&pt)[..SYM_ENC_NONCE_LEN].try_into())
    };
    symmetric_encrypt(plain_text, key, Some(&nonce))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Ensure that a private map info is encrypted.
    #[test]
    fn private_map_info_encrypts() {
        let info = unwrap!(MapInfo::random_private(MapKind::Seq, 0));
        let key = Vec::from("str of key");
        let val = Vec::from("other is value");
        let enc_key = unwrap!(info.enc_entry_key(&key));
        let enc_val = unwrap!(info.enc_entry_value(&val));
        assert_ne!(enc_key, key);
        assert_ne!(enc_val, val);
        assert_eq!(unwrap!(info.decrypt(&enc_key)), key);
        assert_eq!(unwrap!(info.decrypt(&enc_val)), val);
    }

    // Ensure that a public map info is not encrypted.
    #[test]
    fn public_map_info_doesnt_encrypt() {
        let info = unwrap!(MapInfo::random_public(MapKind::Seq, 0));
        let key = Vec::from("str of key");
        let val = Vec::from("other is value");
        assert_eq!(unwrap!(info.enc_entry_key(&key)), key);
        assert_eq!(unwrap!(info.enc_entry_value(&val)), val);
        assert_eq!(unwrap!(info.decrypt(&val)), val);
    }

    // Test creating and committing new encryption info.
    #[test]
    fn decrypt() {
        let mut info = unwrap!(MapInfo::random_private(MapKind::Seq, 0));

        let plain = Vec::from("plaintext");
        let old_cipher = unwrap!(info.enc_entry_value(&plain));
        info.start_new_enc_info();
        let new_cipher = unwrap!(info.enc_entry_value(&plain));

        // After start, both encryption infos work.
        assert_eq!(unwrap!(info.decrypt(&old_cipher)), plain);
        assert_eq!(unwrap!(info.decrypt(&new_cipher)), plain);

        // After commit, only the new encryption info works.
        info.commit_new_enc_info();
        match info.decrypt(&old_cipher) {
            Err(Error::SymmetricDecipherFailure) => (),
            x => panic!("Unexpected {:?}", x),
        }
        assert_eq!(unwrap!(info.decrypt(&new_cipher)), plain);
    }
}
