// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use client::MDataInfo;
use errors::CoreError;
use maidsafe_utilities::serialisation::{deserialise, serialise};
use routing::{FullId, XorName, XOR_NAME_LEN};
use safe_crypto::{
    self, Nonce, PublicEncryptKey, PublicSignKey, SecretEncryptKey, SecretSignKey, Seed,
    SymmetricKey, NONCE_BYTES, SYMMETRIC_KEY_BYTES,
};
use DIR_TAG;

/// Representing the User Account information on the network.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct Account {
    /// The User Account Keys.
    pub maid_keys: ClientKeys,
    /// The user's access container.
    pub access_container: MDataInfo,
    /// The user's configuration directory.
    pub config_root: MDataInfo,
    /// Set to `true` when all root and standard containers have been created successfully. `false`
    /// signifies that previous attempt might have failed - check on login.
    pub root_dirs_created: bool,
}

impl Account {
    /// Create new Account with a provided set of keys.
    pub fn new(maid_keys: ClientKeys) -> Result<Self, CoreError> {
        Ok(Account {
            maid_keys,
            access_container: MDataInfo::random_private(DIR_TAG)?,
            config_root: MDataInfo::random_private(DIR_TAG)?,
            root_dirs_created: false,
        })
    }

    /// Symmetric encryption of Account using User's credentials. Credentials are passed through
    /// key-derivation-function first.
    pub fn encrypt(&self, password: &[u8], pin: &[u8]) -> Result<Vec<u8>, CoreError> {
        let serialised_self = serialise(self)?;
        let (key, nonce) = Self::generate_crypto_keys(password, pin)?;

        Ok(key.encrypt_bytes_with_nonce(&serialised_self, &nonce)?)
    }

    /// Symmetric decryption of Account using User's credentials. Credentials are passed through
    /// key-derivation-function first.
    pub fn decrypt(encrypted_self: &[u8], password: &[u8], pin: &[u8]) -> Result<Self, CoreError> {
        // `encrypt_bytes_with_nonce` already inserted the nonce in the cipher text, so all we need
        // here is to reproduce the key and decrypt.
        let (key, _) = Self::generate_crypto_keys(password, pin)?;
        let decrypted_self = key.decrypt_bytes(encrypted_self)?;

        Ok(deserialise(&decrypted_self)?)
    }

    /// Generate User's Identity for the network using supplied credentials in
    /// a deterministic way.  This is similar to the username in various places.
    pub fn generate_network_id(keyword: &[u8], pin: &[u8]) -> Result<XorName, CoreError> {
        let mut id = XorName([0; XOR_NAME_LEN]);
        safe_crypto::derive_bytes(keyword, pin, &mut id.0)?;

        Ok(id)
    }

    fn generate_crypto_keys(
        password: &[u8],
        pin: &[u8],
    ) -> Result<(SymmetricKey, Nonce), CoreError> {
        let mut output = [0; SYMMETRIC_KEY_BYTES + NONCE_BYTES];
        safe_crypto::derive_bytes(password, pin, &mut output)?;

        let mut key_bytes = [0; SYMMETRIC_KEY_BYTES];
        key_bytes.copy_from_slice(&output[..SYMMETRIC_KEY_BYTES]);
        let key = SymmetricKey::from_bytes(key_bytes);
        let mut nonce_bytes = [0; NONCE_BYTES];
        nonce_bytes.copy_from_slice(&output[SYMMETRIC_KEY_BYTES..]);
        let nonce = Nonce::from_bytes(nonce_bytes);

        Ok((key, nonce))
    }
}

/// Client signing and encryption keypairs.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct ClientKeys {
    /// Signing public key.
    pub sign_pk: PublicSignKey,
    /// Signing secret key.
    pub sign_sk: SecretSignKey,
    /// Encryption public key.
    pub enc_pk: PublicEncryptKey,
    /// Encryption private key.
    pub enc_sk: SecretEncryptKey,
    /// Symmetric encryption key.
    pub enc_key: SymmetricKey,
}

impl ClientKeys {
    /// Construct new `ClientKeys`.
    pub fn new(seed: Option<&Seed>) -> Self {
        let (sign_pk, sign_sk) = match seed {
            Some(s) => safe_crypto::gen_sign_keypair_from_seed(s),
            None => safe_crypto::gen_sign_keypair(),
        };
        let (enc_pk, enc_sk) = safe_crypto::gen_encrypt_keypair();
        let enc_key = SymmetricKey::new();

        ClientKeys {
            sign_pk,
            sign_sk,
            enc_pk,
            enc_sk,
            enc_key,
        }
    }
}

impl Default for ClientKeys {
    fn default() -> Self {
        Self::new(None)
    }
}

impl Into<FullId> for ClientKeys {
    fn into(self) -> FullId {
        let enc_sk = self.enc_sk.clone();
        let sign_sk = self.sign_sk.clone();

        FullId::with_keys((self.enc_pk, enc_sk), (self.sign_pk, sign_sk))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use maidsafe_utilities::serialisation::{deserialise, serialise};
    use std::u32;

    // Test deterministically generating User's Identity for the network using supplied credentials.
    #[test]
    fn generate_network_id() {
        let keyword1 = b"user1";

        let user1_id1 = unwrap!(Account::generate_network_id(keyword1, b"0"));
        let user1_id2 = unwrap!(Account::generate_network_id(keyword1, b"1234"));
        let user1_id3 = unwrap!(Account::generate_network_id(
            keyword1,
            u32::MAX.to_string().as_bytes(),
        ));

        assert_ne!(user1_id1, user1_id2);
        assert_ne!(user1_id1, user1_id3);
        assert_ne!(user1_id2, user1_id3);

        assert_eq!(
            user1_id1,
            unwrap!(Account::generate_network_id(keyword1, b"0"))
        );
        assert_eq!(
            user1_id2,
            unwrap!(Account::generate_network_id(keyword1, b"1234"))
        );
        assert_eq!(
            user1_id3,
            unwrap!(Account::generate_network_id(
                keyword1,
                u32::MAX.to_string().as_bytes(),
            ))
        );

        let keyword2 = b"user2";
        let user1_id = unwrap!(Account::generate_network_id(keyword1, b"248"));
        let user2_id = unwrap!(Account::generate_network_id(keyword2, b"248"));

        assert_ne!(user1_id, user2_id);
    }

    // Test deterministically generating cryptographic keys.
    #[test]
    fn generate_crypto_keys() {
        let password1 = b"super great password";
        let password2 = b"even better password";

        let keys1 = unwrap!(Account::generate_crypto_keys(password1, b"0"));
        let keys2 = unwrap!(Account::generate_crypto_keys(password1, b"1234"));
        let keys3 = unwrap!(Account::generate_crypto_keys(
            password1,
            u32::MAX.to_string().as_bytes(),
        ));
        assert_ne!(keys1, keys2);
        assert_ne!(keys1, keys3);
        assert_ne!(keys2, keys3);

        let keys1 = unwrap!(Account::generate_crypto_keys(password1, b"0"));
        let keys2 = unwrap!(Account::generate_crypto_keys(password2, b"0"));
        assert_ne!(keys1, keys2);

        let keys1 = unwrap!(Account::generate_crypto_keys(password1, b"0"));
        let keys2 = unwrap!(Account::generate_crypto_keys(password1, b"0"));
        assert_eq!(keys1, keys2);
    }

    // Test serialising and deserialising accounts.
    #[test]
    fn serialisation() {
        let account = unwrap!(Account::new(ClientKeys::new(None)));
        let encoded = unwrap!(serialise(&account));
        let decoded: Account = unwrap!(deserialise(&encoded));

        assert_eq!(decoded, account);
    }

    // Test encryption and decryption of accounts.
    #[test]
    fn encryption() {
        let account = unwrap!(Account::new(ClientKeys::new(None)));

        let password = b"impossible to guess";
        let pin = b"1000";

        let encrypted = unwrap!(account.encrypt(password, pin));
        let encoded = unwrap!(serialise(&account));
        assert!(!encrypted.is_empty());
        assert_ne!(encrypted, encoded);

        let decrypted = unwrap!(Account::decrypt(&encrypted, password, pin));
        assert_eq!(account, decrypted);
    }
}
