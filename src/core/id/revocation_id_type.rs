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

use core::id::IdTypeTags;
use routing::XorName;
use rust_sodium::crypto::hash::sha256;
use rust_sodium::crypto::sign;

/// `RevocationIdType`
///
/// #Examples
///
/// ```
/// // Generating public and secret keys using rust_sodium
/// // Create RevocationIdType
/// use safe_core::core::id;
/// let _an_maid = id::RevocationIdType::new::<id::MaidTypeTags>();
/// ```
#[derive(Clone, Debug, Eq, PartialEq, RustcEncodable, RustcDecodable)]
pub struct RevocationIdType {
    type_tags: (u64, u64, u64), // type tags for revocation, id and public ids
    public_key: sign::PublicKey,
    secret_key: sign::SecretKey,
}

#[cfg_attr(feature="clippy", allow(new_without_default))]
impl RevocationIdType {
    /// An instance of RevocationIdType can be created by invoking the new()
    /// Default contructed RevocationIdType instance is returned
    #[allow(unsafe_code)]
    pub fn new<TypeTags>() -> RevocationIdType
        where TypeTags: IdTypeTags
    {
        let (pub_sign_key, sec_sign_key) = sign::gen_keypair();
        let type_tags: TypeTags = unsafe { ::std::mem::uninitialized() };
        RevocationIdType {
            type_tags: (type_tags.revocation_id_type_tag(),
                        type_tags.id_type_tag(),
                        type_tags.public_id_type_tag()),
            public_key: pub_sign_key,
            secret_key: sec_sign_key,
        }
    }

    /// Returns name
    pub fn name(&self) -> XorName {
        let combined_iter = self.public_key.0.into_iter();
        let mut combined: Vec<u8> = Vec::new();
        for iter in combined_iter {
            combined.push(*iter);
        }
        for i in self.type_tags.0.to_string().into_bytes() {
            combined.push(i);
        }
        XorName(sha256::hash(&combined).0)
    }

    /// Returns type tags
    pub fn type_tags(&self) -> &(u64, u64, u64) {
        &self.type_tags
    }

    /// Returns type tag
    pub fn type_tag(&self) -> u64 {
        self.type_tags.0
    }

    /// Returns the SecretKey of the RevocationIdType
    pub fn secret_key(&self) -> &sign::SecretKey {
        &self.secret_key
    }

    /// Returns the PublicKey of the AnMaid
    pub fn public_key(&self) -> &sign::PublicKey {
        &self.public_key
    }

    /// Signs the data with the SecretKey of the AnMaid and recturns the Signed
    /// Data
    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        sign::sign(data, &self.secret_key)
    }
}

#[cfg(test)]
mod tests {
    use core::id::{MaidTypeTags, MpidTypeTags, Random};
    use maidsafe_utilities::serialisation::{deserialise, serialise};
    use rand;
    use rand::Rng;
    use rust_sodium::crypto::sign;
    use super::*;


    impl Random for RevocationIdType {
        fn generate_random() -> RevocationIdType {
            RevocationIdType::new::<MaidTypeTags>()
        }
    }

    #[test]
    fn create_an_mpid() {
        let _ = RevocationIdType::new::<MpidTypeTags>();
    }

    #[test]
    fn serialisation_an_maid() {
        let obj_before = RevocationIdType::generate_random();

        let serialised_obj = unwrap!(serialise(&obj_before));
        let obj_after = unwrap!(deserialise(&serialised_obj));
        assert_eq!(obj_before, obj_after);
    }

    #[test]
    fn equality_assertion_an_maid() {
        let first_obj = RevocationIdType::generate_random();
        let second_obj = RevocationIdType::generate_random();
        let cloned_obj = second_obj.clone();

        assert!(first_obj != second_obj);
        assert!(second_obj == cloned_obj);
    }

    #[test]
    fn generation() {
        let maid1 = RevocationIdType::generate_random();
        let maid2 = RevocationIdType::generate_random();
        let maid2_clone = maid2.clone();

        assert_eq!(maid2, maid2_clone);
        assert!(!(maid2 != maid2_clone));
        assert!(maid1 != maid2);

        let random_bytes = rand::thread_rng().gen_iter::<u8>().take(100).collect::<Vec<u8>>();
        {
            let sign1 = maid1.sign(&random_bytes);
            let sign2 = maid2.sign(&random_bytes);
            assert!(sign1 != sign2);

            assert!(sign::verify(&sign1, &maid1.public_key()).is_ok());
            assert!(sign::verify(&sign2, &maid1.public_key()).is_err());

            assert!(sign::verify(&sign2, &maid2.public_key()).is_ok());
            assert!(sign::verify(&sign2, &maid1.public_key()).is_err());
        }
    }
}
