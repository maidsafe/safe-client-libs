// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use errors::CoreError;
use ffi::arrays::{NonceArray, SymmetricKeyArray};
use ffi::MDataInfo as FfiMDataInfo;
use ffi_utils::ReprC;
use ipc::IpcError;
use rand::{OsRng, Rng};
use routing::{EntryAction, Value, XorName};
use safe_crypto::{self, Nonce, SymmetricKey, NONCE_BYTES};
use std::collections::{BTreeMap, BTreeSet};

/// Information allowing to locate and access mutable data on the network.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct MDataInfo {
    /// Name of the data where the directory is stored.
    pub name: XorName,
    /// Type tag of the data where the directory is stored.
    pub type_tag: u64,
    /// Key to encrypt/decrypt the directory content.
    /// and the nonce to be used for keys.
    pub enc_info: Option<(SymmetricKey, Nonce)>,

    /// Future encryption info, used for two-phase data reencryption.
    pub new_enc_info: Option<(SymmetricKey, Nonce)>,
}

impl MDataInfo {
    /// Construct `MDataInfo` for private (encrypted) data with a
    /// provided private key.
    pub fn new_private(name: XorName, type_tag: u64, enc_info: (SymmetricKey, Nonce)) -> Self {
        MDataInfo {
            name,
            type_tag,
            enc_info: Some(enc_info),
            new_enc_info: None,
        }
    }

    /// Construct `MDataInfo` for public data.
    pub fn new_public(name: XorName, type_tag: u64) -> Self {
        MDataInfo {
            name,
            type_tag,
            enc_info: None,
            new_enc_info: None,
        }
    }

    /// Generate random `MDataInfo` for private (encrypted) mutable data.
    pub fn random_private(type_tag: u64) -> Result<Self, CoreError> {
        let mut rng = os_rng()?;
        let enc_info = (SymmetricKey::new(), Nonce::new());
        Ok(Self::new_private(rng.gen(), type_tag, enc_info))
    }

    /// Generate random `MDataInfo` for public mutable data.
    pub fn random_public(type_tag: u64) -> Result<Self, CoreError> {
        let mut rng = os_rng()?;
        Ok(Self::new_public(rng.gen(), type_tag))
    }

    /// Returns the encryption key, if any.
    pub fn enc_key(&self) -> Option<&SymmetricKey> {
        self.enc_info.as_ref().map(|&(ref key, _)| key)
    }

    /// Returns the nonce, if any.
    pub fn nonce(&self) -> Option<&Nonce> {
        self.enc_info.as_ref().map(|&(_, ref nonce)| nonce)
    }

    /// Encrypt the key for the mdata entry accordingly.
    pub fn enc_entry_key(&self, plain_text: &[u8]) -> Result<Vec<u8>, CoreError> {
        let result = if let Some((ref key, ref seed)) = self.new_enc_info {
            enc_entry_key(plain_text, &key, seed.clone())?
        } else if let Some((ref key, ref seed)) = self.enc_info {
            enc_entry_key(plain_text, &key, seed.clone())?
        } else {
            plain_text.to_vec()
        };

        Ok(result)
    }

    /// Encrypt the value for this mdata entry accordingly.
    pub fn enc_entry_value(&self, plain_text: &[u8]) -> Result<Vec<u8>, CoreError> {
        let result = if let Some((ref key, _)) = self.new_enc_info {
            key.encrypt_bytes(plain_text)?
        } else if let Some((ref key, _)) = self.enc_info {
            key.encrypt_bytes(plain_text)?
        } else {
            plain_text.to_vec()
        };

        Ok(result)
    }

    /// Decrypt key or value of this mdata entry.
    pub fn decrypt(&self, cipher: &[u8]) -> Result<Vec<u8>, CoreError> {
        if let Some((ref key, _)) = self.new_enc_info {
            if let Ok(plain) = key.decrypt_bytes(cipher) {
                return Ok(plain);
            }
        }

        let result = if let Some((ref key, _)) = self.enc_info {
            key.decrypt_bytes(cipher).map_err(CoreError::from)?
        } else {
            cipher.to_vec()
        };

        Ok(result)
    }

    /// Start the encryption info re-generation by populating the `new_enc_info`
    /// field with random keys, unless it's already populated.
    pub fn start_new_enc_info(&mut self) {
        if self.enc_info.is_some() && self.new_enc_info.is_none() {
            self.new_enc_info = Some((SymmetricKey::new(), Nonce::new()));
        }
    }

    /// Commit the encryption info re-generation by replacing the current encryption info
    /// with `new_enc_info` (if any).
    pub fn commit_new_enc_info(&mut self) {
        if let Some(new_enc_info) = self.new_enc_info.take() {
            self.enc_info = Some(new_enc_info);
        }
    }

    /// Convert into C-representation.
    pub fn into_repr_c(self) -> FfiMDataInfo {
        let (has_enc_info, enc_key, enc_nonce) = enc_info_into_repr_c(self.enc_info);
        let (has_new_enc_info, new_enc_key, new_enc_nonce) =
            enc_info_into_repr_c(self.new_enc_info);

        FfiMDataInfo {
            name: self.name.0,
            type_tag: self.type_tag,
            has_enc_info,
            enc_key,
            enc_nonce,
            has_new_enc_info,
            new_enc_key,
            new_enc_nonce,
        }
    }
}

fn os_rng() -> Result<OsRng, CoreError> {
    OsRng::new().map_err(|_| CoreError::RandomDataGenerationFailure)
}

/// Encrypt the entries (both keys and values) using the `MDataInfo`.
pub fn encrypt_entries(
    info: &MDataInfo,
    entries: &BTreeMap<Vec<u8>, Value>,
) -> Result<BTreeMap<Vec<u8>, Value>, CoreError> {
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
pub fn encrypt_entry_actions(
    info: &MDataInfo,
    actions: &BTreeMap<Vec<u8>, EntryAction>,
) -> Result<BTreeMap<Vec<u8>, EntryAction>, CoreError> {
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
pub fn decrypt_entries(
    info: &MDataInfo,
    entries: &BTreeMap<Vec<u8>, Value>,
) -> Result<BTreeMap<Vec<u8>, Value>, CoreError> {
    let mut output = BTreeMap::new();

    for (key, value) in entries {
        let decrypted_key = info.decrypt(key)?;
        let decrypted_value = decrypt_value(info, value)?;

        let _ = output.insert(decrypted_key, decrypted_value);
    }

    Ok(output)
}

/// Decrypt all keys using the `MDataInfo`.
pub fn decrypt_keys(
    info: &MDataInfo,
    keys: &BTreeSet<Vec<u8>>,
) -> Result<BTreeSet<Vec<u8>>, CoreError> {
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

fn enc_entry_key(plain_text: &[u8], key: &SymmetricKey, seed: Nonce) -> Result<Vec<u8>, CoreError> {
    let nonce = {
        let mut pt = plain_text.to_vec();
        pt.extend_from_slice(&seed.into_bytes());

        let mut nonce_bytes: [u8; NONCE_BYTES] = Default::default();
        nonce_bytes.copy_from_slice(&safe_crypto::hash(&pt)[..NONCE_BYTES]);
        Nonce::from_bytes(nonce_bytes)
    };
    Ok(key.encrypt_bytes_with_nonce(plain_text, &nonce)?)
}

impl ReprC for MDataInfo {
    type C = *const FfiMDataInfo;
    type Error = IpcError;

    #[allow(unsafe_code)]
    unsafe fn clone_from_repr_c(c: Self::C) -> Result<Self, Self::Error> {
        let c = &*c;

        Ok(MDataInfo {
            name: XorName(c.name),
            type_tag: c.type_tag,
            enc_info: enc_info_from_repr_c(c.has_enc_info, c.enc_key, c.enc_nonce),
            new_enc_info: enc_info_from_repr_c(c.has_new_enc_info, c.new_enc_key, c.new_enc_nonce),
        })
    }
}

fn enc_info_into_repr_c(
    info: Option<(SymmetricKey, Nonce)>,
) -> (bool, SymmetricKeyArray, NonceArray) {
    if let Some((key, nonce)) = info {
        (true, key.into_bytes(), nonce.into_bytes())
    } else {
        (false, Default::default(), Default::default())
    }
}

fn enc_info_from_repr_c(
    is_set: bool,
    key: SymmetricKeyArray,
    nonce: NonceArray,
) -> Option<(SymmetricKey, Nonce)> {
    if is_set {
        Some((SymmetricKey::from_bytes(key), Nonce::from_bytes(nonce)))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use safe_crypto;

    // Ensure that a private mdata info is encrypted.
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

    // Ensure that a public mdata info is not encrypted.
    #[test]
    fn public_mdata_info_doesnt_encrypt() {
        let info = unwrap!(MDataInfo::random_public(0));
        let key = Vec::from("str of key");
        let val = Vec::from("other is value");
        assert_eq!(unwrap!(info.enc_entry_key(&key)), key);
        assert_eq!(unwrap!(info.enc_entry_value(&val)), val);
        assert_eq!(unwrap!(info.decrypt(&val)), val);
    }

    // Test creating and committing new encryption info.
    #[test]
    fn decrypt() {
        let mut info = unwrap!(MDataInfo::random_private(0));

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
            Err(CoreError::CryptoError(safe_crypto::Error::DecryptVerify(_))) => (),
            x => panic!("Unexpected {:?}", x),
        }
        assert_eq!(unwrap!(info.decrypt(&new_cipher)), plain);
    }
}
