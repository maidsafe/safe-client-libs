// Copyright 2015 MaidSafe.net limited.
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

use core::errors::CoreError;
use core::id::{IdType, MaidTypeTags, MpidTypeTags, PublicIdType, RevocationIdType};
use maidsafe_utilities::serialisation::{deserialise, serialise};
use routing::{XOR_NAME_LEN, XorName};
use rust_sodium::crypto::{pwhash, secretbox};
use rust_sodium::crypto::hash::sha256;
use rust_sodium::crypto::sign::Seed;

/// Represents a Session Packet for the user. It is necessary to fetch and decode this via user
/// supplied credentials to retrieve all the Maid/Mpid etc keys of the user and also their Root
/// Directory ID if they have put data onto the network.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
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
               maidsafe_config_root_dir_id: Option<XorName>,
               id_seed: Option<&Seed>,
               revocation_seed: Option<&Seed>)
               -> Account {
        let an_maid = RevocationIdType::new::<MaidTypeTags>(revocation_seed);
        let maid = IdType::new(&an_maid, id_seed);
        let public_maid = PublicIdType::new(&maid, &an_maid);

        let an_mpid = RevocationIdType::new::<MpidTypeTags>(None);
        let mpid = IdType::new(&an_mpid, None);
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
        Account::derive_key(&mut id.0[..], keyword, pin)?;

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
        let serialised_self = serialise(self)?;
        let (key, nonce) = Account::generate_crypto_keys(password, pin)?;

        Ok(secretbox::seal(&serialised_self, &nonce, &key))
    }

    /// Symmetric decryption of Session Packet using User's credentials. Credentials are passed
    /// through key-derivation-function first
    pub fn decrypt(encrypted_self: &[u8],
                   password: &[u8],
                   pin: &[u8])
                   -> Result<Account, CoreError> {
        let (key, nonce) = Account::generate_crypto_keys(password, pin)?;
        let decrypted_self = secretbox::open(encrypted_self, &nonce, &key)
            .map_err(|_| CoreError::SymmetricDecipherFailure)?;

        Ok(deserialise(&decrypted_self)?)
    }

    fn generate_crypto_keys(password: &[u8],
                            pin: &[u8])
                            -> Result<(secretbox::Key, secretbox::Nonce), CoreError> {
        let mut output = [0; secretbox::KEYBYTES + secretbox::NONCEBYTES];
        Account::derive_key(&mut output[..], password, pin)?;

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

        pwhash::derive_key(output,
                           input,
                           &salt,
                           pwhash::OPSLIMIT_INTERACTIVE,
                           pwhash::MEMLIMIT_INTERACTIVE)
                .map_err(|_| CoreError::UnsuccessfulPwHash)
                .map(|_| Ok(()))?
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use core::utility;
    use maidsafe_utilities::serialisation::{deserialise, serialise};
    use rust_sodium::crypto::sign::Seed;

    #[test]
    fn generating_new_account() {
        let account1 = Account::new(None, None, None, None);
        let account2 = Account::new(None, None, None, None);
        assert!(account1 != account2);
    }

    #[test]
    fn generating_network_id() {
        let keyword1 = "user1".to_owned();

        let user1_id1 = unwrap!(Account::generate_network_id(keyword1.as_bytes(),
                                                             0.to_string().as_bytes()));
        let user1_id2 = unwrap!(Account::generate_network_id(keyword1.as_bytes(),
                                                             1234.to_string().as_bytes()));
        let user1_id3 =
            unwrap!(Account::generate_network_id(keyword1.as_bytes(),
                                                 ::std::u32::MAX.to_string().as_bytes()));

        assert!(user1_id1 != user1_id2);
        assert!(user1_id1 != user1_id3);
        assert!(user1_id2 != user1_id3);
        assert_eq!(user1_id1,
                   unwrap!(Account::generate_network_id(keyword1.as_bytes(),
                                                        0.to_string().as_bytes())));
        assert_eq!(user1_id2,
                   unwrap!(Account::generate_network_id(keyword1.as_bytes(),
                                                        1234.to_string().as_bytes())));
        assert_eq!(user1_id3,
                   unwrap!(Account::generate_network_id(keyword1.as_bytes(),
                                                        ::std::u32::MAX.to_string().as_bytes())));

        let keyword2 = "user2".to_owned();
        let gen_id_res1 = Account::generate_network_id(keyword1.as_bytes(),
                                                       248.to_string().as_bytes());
        let gen_id_res2 = Account::generate_network_id(keyword2.as_bytes(),
                                                       248.to_string().as_bytes());
        let gen_id1 = unwrap!(gen_id_res1);
        let gen_id2 = unwrap!(gen_id_res2);
        assert!(gen_id1 != gen_id2);
    }

    #[test]
    fn generating_crypto_keys() {
        let password1 = "super great password".to_owned();
        let password2 = "even better password".to_owned();
        {
            let keys1 = unwrap!(Account::generate_crypto_keys(password1.as_bytes(),
                                                              0.to_string().as_bytes()));
            let keys2 = unwrap!(Account::generate_crypto_keys(password1.as_bytes(),
                                                              1234.to_string().as_bytes()));
            let keys3 =
                unwrap!(Account::generate_crypto_keys(password1.as_bytes(),
                                                      ::std::u32::MAX.to_string().as_bytes()));

            assert!(keys1 != keys2);
            assert!(keys1 != keys3);
            assert!(keys2 != keys3);
        }
        {
            let keys1 = unwrap!(Account::generate_crypto_keys(password1.as_bytes(),
                                                              0.to_string().as_bytes()));
            let keys2 = unwrap!(Account::generate_crypto_keys(password2.as_bytes(),
                                                              0.to_string().as_bytes()));

            assert!(keys1 != keys2);
            assert!(keys1 != keys2);
        }
        {
            let keys = unwrap!(Account::generate_crypto_keys(password1.as_bytes(),
                                                             0.to_string().as_bytes()));
            let again = unwrap!(Account::generate_crypto_keys(password1.as_bytes(),
                                                              0.to_string().as_bytes()));
            assert_eq!(keys, again);
            assert_eq!(keys, again);
        }
    }

    #[test]
    fn serialisation() {
        let account = Account::new(None, None, None, None);
        let deserialised_account = unwrap!(deserialise(&unwrap!(serialise(&account))));
        assert_eq!(account, deserialised_account);
    }

    #[test]
    fn encryption() {
        let account = Account::new(None, None, None, None);

        let password = "impossible to guess".to_owned();
        let pin = 1000u16;

        let encrypted_account = unwrap!(account.encrypt(password.as_bytes(),
                                                        pin.to_string().as_bytes()));
        let serialised_account = unwrap!(serialise(&account));
        assert!(encrypted_account.len() > 0);
        assert!(encrypted_account != serialised_account);

        let decrypted_account = unwrap!(Account::decrypt(&encrypted_account,
                                                         password.as_bytes(),
                                                         pin.to_string().as_bytes()));
        assert_eq!(account, decrypted_account);
    }

    #[test]
    fn seeded_account() {
        let id_seed_0 = Seed(sha256::hash(&unwrap!(utility::generate_random_vector(10))).0);
        let revocation_seed_0 = Seed(sha256::hash(&unwrap!(utility::generate_random_vector(10))).0);

        let id_seed_1 = Seed(sha256::hash(&unwrap!(utility::generate_random_vector(10))).0);
        let revocation_seed_1 = Seed(sha256::hash(&unwrap!(utility::generate_random_vector(10))).0);

        let acc_default = Account::new(None, None, None, None);
        let acc_default_again = Account::new(None, None, None, None);

        let acc_0 = Account::new(None, None, Some(&id_seed_0), Some(&revocation_seed_0));
        let acc_1 = Account::new(None, None, Some(&id_seed_1), Some(&revocation_seed_1));

        let acc_0_again = Account::new(None, None, Some(&id_seed_0), Some(&revocation_seed_0));
        let acc_1_again = Account::new(None, None, Some(&id_seed_1), Some(&revocation_seed_1));

        let acc_mixed_0 = Account::new(None, None, Some(&id_seed_0), Some(&revocation_seed_1));
        let acc_mixed_1 = Account::new(None, None, Some(&id_seed_1), Some(&revocation_seed_0));

        assert_ne!(acc_default.get_maid().public_keys().0,
                   acc_default_again.get_maid().public_keys().0);
        assert_ne!(acc_default.get_maid().public_keys().0,
                   acc_0.get_maid().public_keys().0);
        assert_ne!(acc_default.get_maid().public_keys().0,
                   acc_1.get_maid().public_keys().0);

        // box_ keys should be unaffected by presence of seed
        assert_ne!(acc_0.get_maid().public_keys().1,
                   acc_0_again.get_maid().public_keys().1);
        assert_ne!(acc_1.get_maid().public_keys().1,
                   acc_1_again.get_maid().public_keys().1);

        assert_eq!(acc_0.get_maid().public_keys().0,
                   acc_0_again.get_maid().public_keys().0);
        assert_eq!(acc_1.get_maid().public_keys().0,
                   acc_1_again.get_maid().public_keys().0);

        assert_ne!(acc_0.get_maid().public_keys().0,
                   acc_1.get_maid().public_keys().0);

        // Diferent revocation_seed will have no effect on sign keys but different id_seed will
        assert_eq!(acc_0.get_maid().public_keys().0,
                   acc_mixed_0.get_maid().public_keys().0);
        assert_ne!(acc_0.get_maid().public_keys().0,
                   acc_mixed_1.get_maid().public_keys().0);

        // Diferent revocation_seed will have no effect on sign keys but different id_seed will
        assert_ne!(acc_1.get_maid().public_keys().0,
                   acc_mixed_0.get_maid().public_keys().0);
        assert_eq!(acc_1.get_maid().public_keys().0,
                   acc_mixed_1.get_maid().public_keys().0);
    }
}
