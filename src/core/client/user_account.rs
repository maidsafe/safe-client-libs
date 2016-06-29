// Copyright 2015 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use core::errors::CoreError;
use core::id::{IdType, MaidTypeTags, MpidTypeTags, PublicIdType, RevocationIdType};
use maidsafe_utilities::serialisation::{deserialise, serialise};
use routing::{XOR_NAME_LEN, XorName};
use sodiumoxide::crypto::hash::sha256;
use sodiumoxide::crypto::{pwhash, secretbox};

/// Represents a Session Packet for the user. It is necessary to fetch and decode this via user
/// supplied credentials to retrieve all the Maid/Mpid etc keys of the user and also their Root
/// Directory ID if they have put data onto the network.
#[derive(Clone, PartialEq, Debug, RustcEncodable, RustcDecodable)]
pub struct Account {
    an_maid: RevocationIdType,
    maid: IdType,
    public_maid: PublicIdType,

    an_mpid: RevocationIdType,
    mpid: IdType,
    public_mpid: PublicIdType,

    user_root_dir_id: Option<XorName>,
    maidsafe_config_root_dir_id: Option<XorName>,
}

#[allow(dead_code)]
impl Account {
    /// Create a new Session Packet with Randomly generated Maid keys for the user
    pub fn new(user_root_dir_id: Option<XorName>,
               maidsafe_config_root_dir_id: Option<XorName>)
               -> Account {
        let an_maid = RevocationIdType::new::<MaidTypeTags>();
        let maid = IdType::new(&an_maid);
        let public_maid = PublicIdType::new(&maid, &an_maid);

        let an_mpid = RevocationIdType::new::<MpidTypeTags>();
        let mpid = IdType::new(&an_mpid);
        let public_mpid = PublicIdType::new(&mpid, &an_mpid);

        Account {
            an_maid: an_maid,
            maid: maid,
            public_maid: public_maid,
            an_mpid: an_mpid,
            mpid: mpid,
            public_mpid: public_mpid,
            user_root_dir_id: user_root_dir_id,
            maidsafe_config_root_dir_id: maidsafe_config_root_dir_id,
        }
    }

    /// Generate User's Identity for the network using supplied credentials in a deterministic way.
    /// This is similar to the username in various places.
    pub fn generate_network_id(keyword: &[u8], pin: &[u8]) -> Result<XorName, CoreError> {
        let mut id = XorName([0; XOR_NAME_LEN]);
        try!(Account::derive_key(&mut id.0[..], keyword, pin));

        Ok(id)
    }

    /// Get user's AnMAID
    pub fn get_an_maid(&self) -> &RevocationIdType {
        &self.an_maid
    }

    /// Get user's MAID
    pub fn get_maid(&self) -> &IdType {
        &self.maid
    }

    /// Get user's Public-MAID
    pub fn get_public_maid(&self) -> &PublicIdType {
        &self.public_maid
    }

    /// Get user's AnMPID
    pub fn get_an_mpid(&self) -> &RevocationIdType {
        &self.an_mpid
    }

    /// Get user's MPID
    pub fn get_mpid(&self) -> &IdType {
        &self.mpid
    }

    /// Get user's Public-MPID
    pub fn get_public_mpid(&self) -> &PublicIdType {
        &self.public_mpid
    }

    /// Get user's root directory ID
    pub fn get_user_root_dir_id(&self) -> Option<&XorName> {
        match self.user_root_dir_id {
            Some(ref dir_id) => Some(dir_id),
            None => None,
        }
    }

    /// Set user's root directory ID
    pub fn set_user_root_dir_id(&mut self, user_root_dir_id: XorName) -> bool {
        match self.user_root_dir_id {
            Some(_) => false,
            None => {
                self.user_root_dir_id = Some(user_root_dir_id);
                true
            }
        }
    }

    /// Get maidsafe configuration specific root directory ID
    pub fn get_maidsafe_config_root_dir_id(&self) -> Option<&XorName> {
        match self.maidsafe_config_root_dir_id {
            Some(ref dir_id) => Some(dir_id),
            None => None,
        }
    }

    /// Set maidsafe configuration specific root directory ID
    pub fn set_maidsafe_config_root_dir_id(&mut self,
                                           maidsafe_config_root_dir_id: XorName)
                                           -> bool {
        match self.maidsafe_config_root_dir_id {
            Some(_) => false,
            None => {
                self.maidsafe_config_root_dir_id = Some(maidsafe_config_root_dir_id);
                true
            }
        }
    }

    /// Symmetric encryption of Session Packet using User's credentials. Credentials are passed
    /// through key-derivation-function first
    pub fn encrypt(&self, password: &[u8], pin: &[u8]) -> Result<Vec<u8>, CoreError> {
        let serialised_self = try!(serialise(self));
        let (key, nonce) = try!(Account::generate_crypto_keys(password, pin));

        Ok(secretbox::seal(&serialised_self, &nonce, &key))
    }

    /// Symmetric decryption of Session Packet using User's credentials. Credentials are passed
    /// through key-derivation-function first
    pub fn decrypt(encrypted_self: &[u8],
                   password: &[u8],
                   pin: &[u8])
                   -> Result<Account, CoreError> {
        let (key, nonce) = try!(Account::generate_crypto_keys(password, pin));
        let decrypted_self = try!(secretbox::open(encrypted_self, &nonce, &key)
            .map_err(|_| CoreError::SymmetricDecipherFailure));

        Ok(try!(deserialise(&decrypted_self)))
    }

    fn generate_crypto_keys(password: &[u8],
                            pin: &[u8])
                            -> Result<(secretbox::Key, secretbox::Nonce), CoreError> {
        let mut output = [0; secretbox::KEYBYTES + secretbox::NONCEBYTES];
        try!(Account::derive_key(&mut output[..], password, pin));

        let mut key = secretbox::Key([0; secretbox::KEYBYTES]);
        let mut nonce = secretbox::Nonce([0; secretbox::NONCEBYTES]);

        for it in output.iter().take(secretbox::KEYBYTES).enumerate() {
            key.0[it.0] = *it.1;
        }
        for it in output.iter().skip(secretbox::KEYBYTES).enumerate() {
            nonce.0[it.0] = *it.1;
        }

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

        try!(pwhash::derive_key(output,
                                input,
                                &salt,
                                pwhash::OPSLIMIT_INTERACTIVE,
                                pwhash::MEMLIMIT_INTERACTIVE)
            .map_err(|_| CoreError::UnsuccessfulPwHash)
            .map(|_| Ok(())))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use maidsafe_utilities::serialisation::{deserialise, serialise};

    #[test]
    fn generating_new_account() {
        let account1 = Account::new(None, None);
        let account2 = Account::new(None, None);
        assert!(account1 != account2);
    }

    #[test]
    fn generating_network_id() {
        let keyword1 = "user1".to_owned();

        let user1_id1 = unwrap_result!(Account::generate_network_id(keyword1.as_bytes(),
                                                                    0.to_string().as_bytes()));
        let user1_id2 = unwrap_result!(Account::generate_network_id(keyword1.as_bytes(),
                                                                    1234.to_string().as_bytes()));
        let user1_id3 = unwrap_result!(Account::generate_network_id(keyword1.as_bytes(),
                                                                    ::std::u32::MAX.to_string()
                                                                        .as_bytes()));

        assert!(user1_id1 != user1_id2);
        assert!(user1_id1 != user1_id3);
        assert!(user1_id2 != user1_id3);
        assert_eq!(user1_id1,
                   unwrap_result!(Account::generate_network_id(keyword1.as_bytes(),
                                                               0.to_string().as_bytes())));
        assert_eq!(user1_id2,
                   unwrap_result!(Account::generate_network_id(keyword1.as_bytes(),
                                                               1234.to_string().as_bytes())));
        assert_eq!(user1_id3,
                   unwrap_result!(Account::generate_network_id(keyword1.as_bytes(),
                                                               ::std::u32::MAX.to_string()
                                                                   .as_bytes())));

        let keyword2 = "user2".to_owned();
        let gen_id_res1 = Account::generate_network_id(keyword1.as_bytes(), 248.to_string().as_bytes());
        let gen_id_res2 = Account::generate_network_id(keyword2.as_bytes(), 248.to_string().as_bytes());
        let gen_id1 = unwrap_result!(gen_id_res1);
        let gen_id2 = unwrap_result!(gen_id_res2);
        assert!(gen_id1 != gen_id2);
    }

    #[test]
    fn generating_crypto_keys() {
        let password1 = "super great password".to_owned();
        let password2 = "even better password".to_owned();
        {
            let keys1 = unwrap_result!(Account::generate_crypto_keys(password1.as_bytes(),
                                                                     0.to_string().as_bytes()));
            let keys2 = unwrap_result!(Account::generate_crypto_keys(password1.as_bytes(),
                                                                     1234.to_string().as_bytes()));
            let keys3 = unwrap_result!(Account::generate_crypto_keys(password1.as_bytes(),
                                                                     ::std::u32::MAX.to_string()
                                                                         .as_bytes()));

            assert!(keys1 != keys2);
            assert!(keys1 != keys3);
            assert!(keys2 != keys3);
        }
        {
            let keys1 = unwrap_result!(Account::generate_crypto_keys(password1.as_bytes(),
                                                                     0.to_string().as_bytes()));
            let keys2 = unwrap_result!(Account::generate_crypto_keys(password2.as_bytes(),
                                                                     0.to_string().as_bytes()));

            assert!(keys1 != keys2);
            assert!(keys1 != keys2);
        }
        {
            let keys = unwrap_result!(Account::generate_crypto_keys(password1.as_bytes(),
                                                                    0.to_string().as_bytes()));
            let again = unwrap_result!(Account::generate_crypto_keys(password1.as_bytes(),
                                                                     0.to_string().as_bytes()));
            assert_eq!(keys, again);
            assert_eq!(keys, again);
        }
    }

    #[test]
    fn serialisation() {
        let account = Account::new(None, None);
        let deserialised_account =
            unwrap_result!(deserialise(&unwrap_result!(serialise(&account))));
        assert_eq!(account, deserialised_account);
    }

    #[test]
    fn encryption() {
        let account = Account::new(None, None);

        let password = "impossible to guess".to_owned();
        let pin = 1000u16;

        let encrypted_account =
            unwrap_result!(account.encrypt(password.as_bytes(), pin.to_string().as_bytes()));
        let serialised_account = unwrap_result!(serialise(&account));
        assert!(encrypted_account.len() > 0);
        assert!(encrypted_account != serialised_account);

        let decrypted_account = unwrap_result!(Account::decrypt(&encrypted_account,
                                                                password.as_bytes(),
                                                                pin.to_string().as_bytes()));
        assert_eq!(account, decrypted_account);
    }
}
