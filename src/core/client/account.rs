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

use core::errors::CoreError;
use maidsafe_utilities::serialisation::{deserialise, serialise};
use rand;
use routing::{XOR_NAME_LEN, XorName};
use rust_sodium::crypto::{box_, pwhash, secretbox, sign};
use rust_sodium::crypto::hash::sha256;

// TODO: remove allow(unused)
#[allow(unused)]
#[derive(Debug, PartialEq, RustcDecodable, RustcEncodable)]
pub struct Account {
    pub maid_keys: ClientKeys,
    pub user_root: Dir,
    pub config_root: Dir,
}

// TODO: remove allow(unused)
#[allow(unused)]
impl Account {
    /// Create new Account with randomly generated maid keys.
    pub fn new(user_root: Dir, config_root: Dir) -> Self {
        Account {
            maid_keys: ClientKeys::new(),
            user_root: user_root,
            config_root: config_root,
        }
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
        let decrypted_self = try!(secretbox::open(encrypted_self, &nonce, &key)
            .map_err(|_| CoreError::SymmetricDecipherFailure));

        Ok(deserialise(&decrypted_self)?)
    }

    /// Generate User's Identity for the network using supplied credentials in
    /// a deterministic way.  This is similar to the username in various places.
    pub fn generate_network_id(keyword: &[u8], pin: &[u8]) -> Result<XorName, CoreError> {
        let mut id = XorName([0; XOR_NAME_LEN]);
        Self::derive_key(&mut id.0[..], keyword, pin)?;

        Ok(id)
    }

    fn generate_crypto_keys(password: &[u8],
                            pin: &[u8])
                            -> Result<(secretbox::Key, secretbox::Nonce), CoreError> {
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
            if salt_bytes.len() == sha256::DIGESTBYTES {
                let hashed_pin = sha256::hash(user_salt);
                for it in salt_bytes.iter_mut().enumerate() {
                    *it.1 = hashed_pin.0[it.0];
                }
            } else {
                return Err(CoreError::UnsupportedSaltSizeForPwHash);
            }
        }

        pwhash::derive_key(output,
                           input,
                           &salt,
                           pwhash::OPSLIMIT_INTERACTIVE,
                           pwhash::MEMLIMIT_INTERACTIVE)
            .map(|_| ())
            .map_err(|_| CoreError::UnsuccessfulPwHash)
    }
}

/// Information about a directory associated with an account.
#[derive(Debug, PartialEq, RustcDecodable, RustcEncodable)]
pub struct Dir {
    /// Name of the data where the directory is stored.
    pub name: XorName,
    /// Type tag of the data where the directory is stored.
    pub type_tag: u64,
    /// Key to encrypt/decrypt the directory content.
    pub enc_key: secretbox::Key,
}

impl Dir {
    /// Generate random `Dir` with the given type tag.
    pub fn random(type_tag: u64) -> Self {
        Dir {
            name: rand::random(),
            type_tag: type_tag,
            enc_key: secretbox::gen_key(),
        }
    }
}

/// Client signing and encryption keypairs
#[derive(Debug, PartialEq, RustcDecodable, RustcEncodable)]
pub struct ClientKeys {
    /// Signing public key
    pub sign_pk: sign::PublicKey,
    /// Signing secret key
    pub sign_sk: sign::SecretKey,
    /// Encryption public key
    pub enc_pk: box_::PublicKey,
    /// Encryption private key
    pub enc_sk: box_::SecretKey,
}

impl ClientKeys {
    /// Construct new `ClientKeys`
    pub fn new() -> Self {
        let sign = sign::gen_keypair();
        let enc = box_::gen_keypair();

        ClientKeys {
            sign_pk: sign.0,
            sign_sk: sign.1,
            enc_pk: enc.0,
            enc_sk: enc.1,
        }
    }
}

impl Default for ClientKeys {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use maidsafe_utilities::serialisation::{deserialise, serialise};
    use std::u32;
    use super::*;

    #[test]
    fn generate_network_id() {
        let keyword1 = b"user1";

        let user1_id1 = unwrap!(Account::generate_network_id(keyword1, b"0"));
        let user1_id2 = unwrap!(Account::generate_network_id(keyword1, b"1234"));
        let user1_id3 = unwrap!(Account::generate_network_id(keyword1,
                                                             u32::MAX.to_string().as_bytes()));

        assert!(user1_id1 != user1_id2);
        assert!(user1_id1 != user1_id3);
        assert!(user1_id2 != user1_id3);

        assert_eq!(user1_id1,
                   unwrap!(Account::generate_network_id(keyword1, b"0")));
        assert_eq!(user1_id2,
                   unwrap!(Account::generate_network_id(keyword1, b"1234")));
        assert_eq!(user1_id3,
                   unwrap!(Account::generate_network_id(keyword1,
                                                        u32::MAX.to_string().as_bytes())));

        let keyword2 = b"user2";
        let user1_id = unwrap!(Account::generate_network_id(keyword1, b"248"));
        let user2_id = unwrap!(Account::generate_network_id(keyword2, b"248"));

        assert!(user1_id != user2_id);
    }

    #[test]
    fn generate_crypto_keys() {
        let password1 = b"super great password";
        let password2 = b"even better password";

        let keys1 = unwrap!(Account::generate_crypto_keys(password1, b"0"));
        let keys2 = unwrap!(Account::generate_crypto_keys(password1, b"1234"));
        let keys3 = unwrap!(Account::generate_crypto_keys(password1,
                                                          u32::MAX.to_string().as_bytes()));
        assert!(keys1 != keys2);
        assert!(keys1 != keys3);
        assert!(keys2 != keys3);

        let keys1 = unwrap!(Account::generate_crypto_keys(password1, b"0"));
        let keys2 = unwrap!(Account::generate_crypto_keys(password2, b"0"));
        assert!(keys1 != keys2);

        let keys1 = unwrap!(Account::generate_crypto_keys(password1, b"0"));
        let keys2 = unwrap!(Account::generate_crypto_keys(password1, b"0"));
        assert_eq!(keys1, keys2);
    }

    #[test]
    fn serialisation() {
        let account = create_account();
        let encoded = unwrap!(serialise(&account));
        let decoded: Account = unwrap!(deserialise(&encoded));

        assert_eq!(decoded, account);
    }

    #[test]
    fn encryption() {
        let account = create_account();

        let password = b"impossible to guess";
        let pin = b"1000";

        let encrypted = unwrap!(account.encrypt(password, pin));
        let encoded = unwrap!(serialise(&account));
        assert!(encrypted.len() > 0);
        assert!(encrypted != encoded);

        let decrypted = unwrap!(Account::decrypt(&encrypted, password, pin));
        assert_eq!(account, decrypted);
    }

    fn create_account() -> Account {
        let user_root = Dir::random(0);
        let config_root = Dir::random(0);

        Account::new(user_root, config_root)
    }
}
