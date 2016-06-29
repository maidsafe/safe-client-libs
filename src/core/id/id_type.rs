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
use core::id::revocation_id_type::RevocationIdType;
use routing::XorName;
use sodiumoxide::crypto::{box_, sign};
use sodiumoxide::crypto::hash::sha256;

/// IdType
///
/// #Examples
///
/// ```
/// use ::safe_core::core::id::{IdType, RevocationIdType, MaidTypeTags};
/// // Creating new IdType
/// let _maid  = IdType::new(&RevocationIdType::new::<MaidTypeTags>());
///
/// ```
#[derive(Clone, Debug, Eq, PartialEq, RustcEncodable, RustcDecodable)]
pub struct IdType {
    type_tag: u64,
    public_keys: (sign::PublicKey, box_::PublicKey),
    secret_keys: (sign::SecretKey, box_::SecretKey),
}

impl IdType {
    /// Invoked to create an instance of IdType
    pub fn new(revocation_id: &RevocationIdType) -> IdType {
        let asym_keys = box_::gen_keypair();
        let signing_keys = sign::gen_keypair();

        IdType {
            type_tag: revocation_id.type_tags().1,
            public_keys: (signing_keys.0, asym_keys.0),
            secret_keys: (signing_keys.1, asym_keys.1),
        }
    }

    /// Returns name
    pub fn name(&self) -> XorName {
        let combined_iter = (&self.public_keys.0)
            .0
            .into_iter()
            .chain((&self.public_keys.1).0.into_iter());
        let mut combined = Vec::new();
        for iter in combined_iter {
            combined.push(*iter);
        }
        for i in self.type_tag.to_string().into_bytes().into_iter() {
            combined.push(i);
        }
        XorName(sha256::hash(&combined).0)
    }

    /// Returns the PublicKeys
    pub fn public_keys(&self) -> &(sign::PublicKey, box_::PublicKey) {
        &self.public_keys
    }

    /// Returns the PublicKeys
    pub fn secret_keys(&self) -> &(sign::SecretKey, box_::SecretKey) {
        &self.secret_keys
    }

    /// Signs the data with the SecretKey and returns the Signed data
    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        sign::sign(data, &self.secret_keys.0)
    }

    /// Encrypts and authenticates data. It returns a ciphertext and the Nonce.
    pub fn seal(&self, data: &[u8], to: &box_::PublicKey) -> (Vec<u8>, box_::Nonce) {
        let nonce = box_::gen_nonce();
        let sealed = box_::seal(data, &nonce, to, &self.secret_keys.1);
        (sealed, nonce)
    }

    /// Verifies and decrypts the data
    pub fn open(&self,
                data: &[u8],
                nonce: &box_::Nonce,
                from: &box_::PublicKey)
                -> Result<Vec<u8>, CoreError> {
        box_::open(data, nonce, from, &self.secret_keys.1)
            .map_err(|_| CoreError::AsymmetricDecipherFailure)
    }
}

#[cfg(test)]
mod test {
    extern crate rand;

    use core::id::Random;
    use self::rand::Rng;
    use sodiumoxide::crypto::{box_, sign};
    use maidsafe_utilities::serialisation::{serialise, deserialise};
    use core::id::{IdType, RevocationIdType, MaidTypeTags};

    impl Random for IdType {
        fn generate_random() -> IdType {
            IdType::new(&RevocationIdType::new::<MaidTypeTags>())
        }
    }

    #[test]
    fn serialisation_maid() {
        let obj_before = IdType::generate_random();

        let serialised_obj = unwrap!(serialise(&obj_before));

        let obj_after: IdType = unwrap!(deserialise(&serialised_obj));

        let &(sign::PublicKey(pub_sign_arr_before), box_::PublicKey(pub_asym_arr_before)) =
            obj_before.public_keys();
        let &(sign::PublicKey(pub_sign_arr_after), box_::PublicKey(pub_asym_arr_after)) =
            obj_after.public_keys();
        let &(sign::SecretKey(sec_sign_arr_before), box_::SecretKey(sec_asym_arr_before)) =
            &obj_before.secret_keys;
        let &(sign::SecretKey(sec_sign_arr_after), box_::SecretKey(sec_asym_arr_after)) =
            &obj_after.secret_keys;

        assert_eq!(pub_sign_arr_before, pub_sign_arr_after);
        assert_eq!(pub_asym_arr_before, pub_asym_arr_after);
        assert!(&sec_sign_arr_before[..] == &sec_sign_arr_after[..]);
        assert_eq!(sec_asym_arr_before, sec_asym_arr_after);
    }

    #[test]
    fn generation() {
        let maid1 = IdType::generate_random();
        let maid2 = IdType::generate_random();
        let maid2_clone = maid2.clone();

        assert_eq!(maid2, maid2_clone);
        assert!(!(maid2 != maid2_clone));
        assert!(maid1 != maid2);

        let random_bytes = rand::thread_rng().gen_iter::<u8>().take(100).collect::<Vec<u8>>();
        {
            let sign1 = maid1.sign(&random_bytes);
            let sign2 = maid2.sign(&random_bytes);
            assert!(sign1 != sign2);

            assert!(sign::verify(&sign1, &maid1.public_keys().0).is_ok());
            assert!(sign::verify(&sign2, &maid1.public_keys().0).is_err());

            assert!(sign::verify(&sign2, &maid2.public_keys().0).is_ok());
            assert!(sign::verify(&sign2, &maid1.public_keys().0).is_err());
        }
        {
            let maid3 = IdType::generate_random();

            let encrypt1 = maid1.seal(&random_bytes, &maid3.public_keys().1);
            let encrypt2 = maid2.seal(&random_bytes, &maid3.public_keys().1);
            assert!(encrypt1.0 != encrypt2.0);

            assert!(maid3.open(&encrypt1.0, &encrypt1.1, &maid1.public_keys().1).is_ok());
            assert!(maid3.open(&encrypt1.0, &encrypt1.1, &maid2.public_keys().1).is_err());

            assert!(maid3.open(&encrypt2.0, &encrypt2.1, &maid2.public_keys().1).is_ok());
            assert!(maid3.open(&encrypt2.0, &encrypt2.1, &maid1.public_keys().1).is_err());
        }
    }
}
