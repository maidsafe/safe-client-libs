// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::crypto::shared_secretbox;
use crate::errors::CoreError;
use crate::ffi::arrays::{SymNonce, SymSecretKey};
use crate::ffi::{md_kind_clone_from_repr_c, md_kind_into_repr_c, MDataInfo as FfiMDataInfo};
use crate::ipc::IpcError;
use crate::utils::{symmetric_decrypt, symmetric_encrypt};
use ffi_utils::ReprC;
use rust_sodium::crypto::secretbox;
use safe_nd::{
    MDataAddress, MDataKind, MDataSeqEntries, MDataSeqEntryAction, MDataSeqValue, XorName,
};
use std::collections::{BTreeMap, BTreeSet};
use tiny_keccak::sha3_256;

/// Information allowing to locate and access mutable data on the network.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct MDataInfo {
    /// Address of the mutable data, containing its name, type tag, and whether it is sequenced.
    pub address: MDataAddress,
    /// Key to encrypt/decrypt the directory content and the nonce to be used for keys
    pub enc_info: Option<(shared_secretbox::Key, secretbox::Nonce)>,

    /// Future encryption info, used for two-phase data reencryption.
    pub new_enc_info: Option<(shared_secretbox::Key, secretbox::Nonce)>,
}

impl MDataInfo {
    /// Construct `MDataInfo` for private (encrypted) data with a provided private key.
    pub fn new_private(
        address: MDataAddress,
        enc_info: (shared_secretbox::Key, secretbox::Nonce),
    ) -> Self {
        MDataInfo {
            address,
            enc_info: Some(enc_info),
            new_enc_info: None,
        }
    }

    /// Construct `MDataInfo` for public data.
    pub fn new_public(address: MDataAddress) -> Self {
        MDataInfo {
            address,
            enc_info: None,
            new_enc_info: None,
        }
    }

    /// Generate random `MDataInfo` for private (encrypted) mutable data.
    pub fn random_private(kind: MDataKind, type_tag: u64) -> Result<Self, CoreError> {
        let address = MDataAddress::from_kind(kind, new_rand::random(), type_tag);
        let enc_info = (shared_secretbox::gen_key(), secretbox::gen_nonce());

        Ok(Self::new_private(address, enc_info))
    }

    /// Generate random `MDataInfo` for public mutable data.
    pub fn random_public(kind: MDataKind, type_tag: u64) -> Result<Self, CoreError> {
        let address = MDataAddress::from_kind(kind, new_rand::random(), type_tag);

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
    pub fn address(&self) -> &MDataAddress {
        &self.address
    }

    /// Returns the kind.
    pub fn kind(&self) -> MDataKind {
        self.address.kind()
    }

    /// Returns the encryption key, if any.
    pub fn enc_key(&self) -> Option<&shared_secretbox::Key> {
        self.enc_info.as_ref().map(|&(ref key, _)| key)
    }

    /// Returns the nonce, if any.
    pub fn nonce(&self) -> Option<&secretbox::Nonce> {
        self.enc_info.as_ref().map(|&(_, ref nonce)| nonce)
    }

    /// Encrypt the key for the mdata entry accordingly.
    pub fn enc_entry_key(&self, plain_text: &[u8]) -> Result<Vec<u8>, CoreError> {
        if let Some((ref key, seed)) = self.new_enc_info {
            enc_entry_key(plain_text, key, seed)
        } else if let Some((ref key, seed)) = self.enc_info {
            enc_entry_key(plain_text, key, seed)
        } else {
            Ok(plain_text.to_vec())
        }
    }

    /// Encrypt the value for this mdata entry accordingly.
    pub fn enc_entry_value(&self, plain_text: &[u8]) -> Result<Vec<u8>, CoreError> {
        if let Some((ref key, _)) = self.new_enc_info {
            symmetric_encrypt(plain_text, key, None)
        } else if let Some((ref key, _)) = self.enc_info {
            symmetric_encrypt(plain_text, key, None)
        } else {
            Ok(plain_text.to_vec())
        }
    }

    /// Decrypt key or value of this mdata entry.
    pub fn decrypt(&self, cipher: &[u8]) -> Result<Vec<u8>, CoreError> {
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
            self.new_enc_info = Some((shared_secretbox::gen_key(), secretbox::gen_nonce()));
        }
    }

    /// Commit the encryption info re-generation by replacing the current encryption info
    /// with `new_enc_info` (if any).
    pub fn commit_new_enc_info(&mut self) {
        if let Some(new_enc_info) = self.new_enc_info.take() {
            self.enc_info = Some(new_enc_info);
        }
    }

    /// Construct FFI wrapper for the native Rust object, consuming self.
    pub fn into_repr_c(self) -> FfiMDataInfo {
        let (name, type_tag, kind) = (self.name().0, self.type_tag(), self.kind());
        let kind = md_kind_into_repr_c(kind);

        let (has_enc_info, enc_key, enc_nonce) = enc_info_into_repr_c(self.enc_info);
        let (has_new_enc_info, new_enc_key, new_enc_nonce) =
            enc_info_into_repr_c(self.new_enc_info);

        FfiMDataInfo {
            name,
            type_tag,
            kind,

            has_enc_info,
            enc_key,
            enc_nonce,

            has_new_enc_info,
            new_enc_key,
            new_enc_nonce,
        }
    }
}

/// Encrypt the entries (both keys and values) using the `MDataInfo`.
pub fn encrypt_entries(
    info: &MDataInfo,
    entries: &MDataSeqEntries,
) -> Result<MDataSeqEntries, CoreError> {
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
    actions: &BTreeMap<Vec<u8>, MDataSeqEntryAction>,
) -> Result<BTreeMap<Vec<u8>, MDataSeqEntryAction>, CoreError> {
    let mut output = BTreeMap::new();

    for (key, action) in actions {
        let encrypted_key = info.enc_entry_key(key)?;
        let encrypted_action = match *action {
            MDataSeqEntryAction::Ins(ref value) => {
                MDataSeqEntryAction::Ins(encrypt_value(info, value)?)
            }
            MDataSeqEntryAction::Update(ref value) => {
                MDataSeqEntryAction::Update(encrypt_value(info, value)?)
            }
            MDataSeqEntryAction::Del(version) => MDataSeqEntryAction::Del(version),
        };

        let _ = output.insert(encrypted_key, encrypted_action);
    }

    Ok(output)
}

/// Decrypt entries using the `MDataInfo`.
pub fn decrypt_entries(
    info: &MDataInfo,
    entries: &MDataSeqEntries,
) -> Result<MDataSeqEntries, CoreError> {
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
pub fn decrypt_values(
    info: &MDataInfo,
    values: &[MDataSeqValue],
) -> Result<Vec<MDataSeqValue>, CoreError> {
    let mut output = Vec::with_capacity(values.len());

    for value in values {
        output.push(decrypt_value(info, value)?);
    }

    Ok(output)
}

fn encrypt_value(info: &MDataInfo, value: &MDataSeqValue) -> Result<MDataSeqValue, CoreError> {
    Ok(MDataSeqValue {
        data: info.enc_entry_value(&value.data)?,
        version: value.version,
    })
}

fn decrypt_value(info: &MDataInfo, value: &MDataSeqValue) -> Result<MDataSeqValue, CoreError> {
    Ok(MDataSeqValue {
        data: info.decrypt(&value.data)?,
        version: value.version,
    })
}

fn enc_entry_key(
    plain_text: &[u8],
    key: &secretbox::Key,
    seed: secretbox::Nonce,
) -> Result<Vec<u8>, CoreError> {
    let nonce = {
        let secretbox::Nonce(ref nonce) = seed;
        let mut pt = plain_text.to_vec();
        pt.extend_from_slice(&nonce[..]);
        unwrap!(secretbox::Nonce::from_slice(
            &sha3_256(&pt)[..secretbox::NONCEBYTES],
        ))
    };
    symmetric_encrypt(plain_text, key, Some(&nonce))
}

impl ReprC for MDataInfo {
    type C = *const FfiMDataInfo;
    type Error = IpcError;

    #[allow(unsafe_code)]
    unsafe fn clone_from_repr_c(repr_c: Self::C) -> Result<Self, Self::Error> {
        let FfiMDataInfo {
            name,
            type_tag,
            kind,

            has_enc_info,
            enc_key,
            enc_nonce,

            has_new_enc_info,
            new_enc_key,
            new_enc_nonce,
        } = *repr_c;

        let name = XorName(name);
        let kind = md_kind_clone_from_repr_c(kind);

        Ok(Self {
            address: MDataAddress::from_kind(kind, name, type_tag),
            enc_info: enc_info_from_repr_c(has_enc_info, enc_key, enc_nonce),
            new_enc_info: enc_info_from_repr_c(has_new_enc_info, new_enc_key, new_enc_nonce),
        })
    }
}

// Helper function for converting to FFI representation.
fn enc_info_into_repr_c(
    info: Option<(shared_secretbox::Key, secretbox::Nonce)>,
) -> (bool, SymSecretKey, SymNonce) {
    if let Some((key, nonce)) = info {
        (true, key.0, nonce.0)
    } else {
        (false, Default::default(), Default::default())
    }
}

// Helper function for converting from FFI representation.
fn enc_info_from_repr_c(
    is_set: bool,
    key: SymSecretKey,
    nonce: SymNonce,
) -> Option<(shared_secretbox::Key, secretbox::Nonce)> {
    if is_set {
        Some((
            shared_secretbox::Key::from_raw(&key),
            secretbox::Nonce(nonce),
        ))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Ensure that a private mdata info is encrypted.
    #[test]
    fn private_mdata_info_encrypts() {
        let info = unwrap!(MDataInfo::random_private(MDataKind::Seq, 0));
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
        let info = unwrap!(MDataInfo::random_public(MDataKind::Seq, 0));
        let key = Vec::from("str of key");
        let val = Vec::from("other is value");
        assert_eq!(unwrap!(info.enc_entry_key(&key)), key);
        assert_eq!(unwrap!(info.enc_entry_value(&val)), val);
        assert_eq!(unwrap!(info.decrypt(&val)), val);
    }

    // Test creating and committing new encryption info.
    #[test]
    fn decrypt() {
        let mut info = unwrap!(MDataInfo::random_private(MDataKind::Seq, 0));

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
            Err(CoreError::SymmetricDecipherFailure) => (),
            x => panic!("Unexpected {:?}", x),
        }
        assert_eq!(unwrap!(info.decrypt(&new_cipher)), plain);
    }
}
