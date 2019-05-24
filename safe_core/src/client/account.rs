// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::client::MDataInfo;
use crate::crypto::{shared_box, shared_secretbox, shared_sign};
use crate::errors::CoreError;
use crate::DIR_TAG;
use maidsafe_utilities::serialisation::{deserialise, serialise};
use routing::{FullId, XorName, XOR_NAME_LEN};
use rust_sodium::crypto::sign::Seed;
use rust_sodium::crypto::{box_, pwhash, secretbox, sign};
use serde::ser::{Serialize, SerializeStruct, Serializer};
use threshold_crypto::serde_impl::SerdeSecret;
use tiny_keccak::sha3_256;

/// Representing the User Account information on the network.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct Account {
    /// The User Account Keys.
    pub maid_keys: ClientKeys,
    /// The user's access container.
    pub access_container: MDataInfo,
    /// The user's configuration directory.
    pub config_root: MDataInfo,
    /// Set to `true` when all root and standard containers
    /// have been created successfully. `false` signifies that
    /// previous attempt might have failed - check on login.
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

    /// Symmetric encryption of Account using User's credentials.
    /// Credentials are passed through key-derivation-function first
    pub fn encrypt(&self, password: &[u8], pin: &[u8]) -> Result<Vec<u8>, CoreError> {
        let serialised_self = serialise(self)?;
        let (key, nonce) = Self::generate_crypto_keys(password, pin)?;

        Ok(secretbox::seal(&serialised_self, &nonce, &key))
    }

    /// Symmetric decryption of Account using User's credentials.
    /// Credentials are passed through key-derivation-function first
    pub fn decrypt(encrypted_self: &[u8], password: &[u8], pin: &[u8]) -> Result<Self, CoreError> {
        let (key, nonce) = Self::generate_crypto_keys(password, pin)?;
        let decrypted_self = secretbox::open(encrypted_self, &nonce, &key)
            .map_err(|_| CoreError::SymmetricDecipherFailure)?;

        Ok(deserialise(&decrypted_self)?)
    }

    /// Generate User's Identity for the network using supplied credentials in
    /// a deterministic way.  This is similar to the username in various places.
    pub fn generate_network_id(keyword: &[u8], pin: &[u8]) -> Result<XorName, CoreError> {
        let mut id = XorName([0; XOR_NAME_LEN]);
        Self::derive_key(&mut id.0[..], keyword, pin)?;

        Ok(id)
    }

    fn generate_crypto_keys(
        password: &[u8],
        pin: &[u8],
    ) -> Result<(secretbox::Key, secretbox::Nonce), CoreError> {
        let mut output = [0; secretbox::KEYBYTES + secretbox::NONCEBYTES];
        Self::derive_key(&mut output[..], password, pin)?;

        // OK to unwrap here, as we guaranteed the slices have the correct length.
        let key = unwrap!(secretbox::Key::from_slice(&output[..secretbox::KEYBYTES]));
        let nonce = unwrap!(secretbox::Nonce::from_slice(&output[secretbox::KEYBYTES..]));

        Ok((key, nonce))
    }

    fn derive_key(output: &mut [u8], input: &[u8], user_salt: &[u8]) -> Result<(), CoreError> {
        let mut salt = pwhash::Salt([0; pwhash::SALTBYTES]);
        {
            let pwhash::Salt(ref mut salt_bytes) = salt;
            if salt_bytes.len() == 32 {
                let hashed_pin = sha3_256(user_salt);
                for it in salt_bytes.iter_mut().enumerate() {
                    *it.1 = hashed_pin[it.0];
                }
            } else {
                return Err(CoreError::UnsupportedSaltSizeForPwHash);
            }
        }

        pwhash::derive_key(
            output,
            input,
            &salt,
            pwhash::OPSLIMIT_INTERACTIVE,
            pwhash::MEMLIMIT_INTERACTIVE,
        )
        .map(|_| ())
        .map_err(|_| CoreError::UnsuccessfulPwHash)
    }
}

/// Client signing and encryption keypairs
#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct ClientKeys {
    /// Signing public key
    pub sign_pk: sign::PublicKey,
    /// Signing secret key
    pub sign_sk: shared_sign::SecretKey,
    /// Encryption public key
    pub enc_pk: box_::PublicKey,
    /// Encryption private key
    pub enc_sk: shared_box::SecretKey,
    /// Symmetric encryption key
    pub enc_key: shared_secretbox::Key,
    /// BLS public key
    pub bls_pk: threshold_crypto::PublicKey,
    /// BLS private key
    pub bls_sk: threshold_crypto::SecretKey,
}

impl Serialize for ClientKeys {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("ClientKeys", 7)?;
        state.serialize_field("sign_pk", &self.sign_pk)?;
        state.serialize_field("sign_sk", &self.sign_sk)?;
        state.serialize_field("enc_pk", &self.enc_pk)?;
        state.serialize_field("enc_sk", &self.enc_sk)?;
        state.serialize_field("enc_key", &self.enc_key)?;
        state.serialize_field("bls_pk", &self.bls_pk)?;
        state.serialize_field("bls_sk", &SerdeSecret(&self.bls_sk))?;
        state.end()
    }
}

impl ClientKeys {
    /// Construct new `ClientKeys`
    pub fn new(seed: Option<&Seed>) -> Self {
        let sign = match seed {
            Some(s) => shared_sign::keypair_from_seed(s),
            None => shared_sign::gen_keypair(),
        };
        let enc = shared_box::gen_keypair();
        let enc_key = shared_secretbox::gen_key();
        let bls_sk = threshold_crypto::SecretKey::random();

        ClientKeys {
            sign_pk: sign.0,
            sign_sk: sign.1,
            enc_pk: enc.0,
            enc_sk: enc.1,
            enc_key,
            bls_pk: bls_sk.public_key(),
            bls_sk,
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
        let enc_sk = (*self.enc_sk).clone();
        let sign_sk = (*self.sign_sk).clone();

        FullId::with_keys((self.enc_pk, enc_sk), (self.sign_pk, sign_sk), self.bls_sk)
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
