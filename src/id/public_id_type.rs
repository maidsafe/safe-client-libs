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

/// PublicIdType
///
/// #Examples
///
/// ```
/// use ::safe_core::id::{IdType, RevocationIdType, MaidTypeTags, PublicIdType};
///
/// let revocation_maid = RevocationIdType::new::<MaidTypeTags>();
/// let maid = IdType::new(&revocation_maid);
/// let _public_maid  = PublicIdType::new(&maid, &revocation_maid);
/// ```
#[derive(Clone, Debug, Eq, PartialEq, RustcEncodable, RustcDecodable)]
#[allow(unused_results)] 
pub struct PublicIdType {
    type_tag: u64,
    public_keys: (::sodiumoxide::crypto::sign::PublicKey, ::sodiumoxide::crypto::box_::PublicKey),
    revocation_public_key: ::sodiumoxide::crypto::sign::PublicKey,
    signature: ::sodiumoxide::crypto::sign::Signature,
}

impl PublicIdType {
    /// An instanstance of the PublicIdType can be created using the new()
    pub fn new(id_type: &::id::IdType, revocation_id: &::id::RevocationIdType) -> PublicIdType {
        let type_tag = revocation_id.type_tags().2;
        let public_keys = id_type.public_keys().clone();
        let revocation_public_key = revocation_id.public_key();
        let combined_iter = (public_keys.0).0.into_iter().chain((public_keys.1).0.into_iter().chain(revocation_public_key.0.into_iter()));
        let mut combined: Vec<u8> = Vec::new();
        for iter in combined_iter {
            combined.push(*iter);
        }
        for i in type_tag.to_string().into_bytes().into_iter() {
            combined.push(i);
        }
        let message_length = combined.len();

        let signature = revocation_id.sign(&combined).into_iter().skip(message_length).collect::<Vec<_>>();
        let mut signature_arr = [0; ::sodiumoxide::crypto::sign::SIGNATUREBYTES];

        for it in signature.into_iter().take(::sodiumoxide::crypto::sign::SIGNATUREBYTES).enumerate() {
            signature_arr[it.0] = it.1;
        }

        PublicIdType { type_tag: type_tag, public_keys: public_keys,
             revocation_public_key: revocation_id.public_key().clone(),
             signature: ::sodiumoxide::crypto::sign::Signature(signature_arr) }
    }

    /// Returns the name
    pub fn name(&self) -> ::routing::NameType {
        let combined_iter = (self.public_keys.0).0.into_iter().chain((self.public_keys.1).0.into_iter());
        let mut combined: Vec<u8> = Vec::new();
        for iter in combined_iter {
            combined.push(*iter);
        }
        for i in self.type_tag.to_string().into_bytes().into_iter() {
            combined.push(i);
        }
        for i in 0..::sodiumoxide::crypto::sign::SIGNATUREBYTES {
            combined.push(self.signature.0[i]);
        }
        ::routing::NameType(::sodiumoxide::crypto::hash::sha512::hash(&combined).0)
    }

    /// Returns the PublicKeys
    pub fn public_keys(&self) -> &(::sodiumoxide::crypto::sign::PublicKey, ::sodiumoxide::crypto::box_::PublicKey) {
        &self.public_keys
    }

    /// Returns revocation public key
    pub fn revocation_public_key(&self) -> &::sodiumoxide::crypto::sign::PublicKey {
        &self.revocation_public_key
    }

    /// Returns the Signature of PublicIdType
    pub fn signature(&self) -> &::sodiumoxide::crypto::sign::Signature {
        &self.signature
    }
}

#[cfg(test)]
mod test {
    use super::PublicIdType;
    use ::id::Random;

    impl Random for PublicIdType {
        fn generate_random() -> PublicIdType {
            let revocation_maid = ::id::RevocationIdType::new::<::id::MaidTypeTags>();
            let maid = ::id::IdType::new(&revocation_maid);
            PublicIdType::new(&maid, &revocation_maid)
        }
    }

    #[test]
    fn create_public_mpid() {
        let revocation_mpid = ::id::RevocationIdType::new::<::id::MpidTypeTags>();
        let mpid = ::id::IdType::new(&revocation_mpid);
        let _ = PublicIdType::new(&mpid, &revocation_mpid);
    }

    #[test]
    fn serialisation_public_maid() {
        let obj_before: PublicIdType = ::id::Random::generate_random();

        let serialised_obj = eval_result!(::utility::serialise(&obj_before));
        let obj_after: PublicIdType = eval_result!(::utility::deserialise(&serialised_obj));

        assert_eq!(obj_before, obj_after);
    }

    #[test]
    fn equality_assertion_public_maid() {
        let public_maid_first = PublicIdType::generate_random();
        let public_maid_second = public_maid_first.clone();
        let public_maid_third = PublicIdType::generate_random();
        assert_eq!(public_maid_first, public_maid_second);
        assert!(public_maid_first != public_maid_third);
    }

    #[test]
    fn invariant_check() {
        let revocation_maid = ::id::RevocationIdType::new::<::id::MaidTypeTags>();
        let maid = ::id::IdType::new(&revocation_maid);
        let public_maid = PublicIdType::new(&maid, &revocation_maid);
        let type_tag = public_maid.type_tag;
        let public_id_keys = public_maid.public_keys;
        let public_revocation_key = public_maid.revocation_public_key;
        let combined_keys = (public_id_keys.0).0.into_iter().chain((public_id_keys.1).0
                                                .into_iter().chain(public_revocation_key.0
                                                .into_iter()));
        let mut combined = Vec::new();

        for iter in combined_keys {
            combined.push(*iter);
        }
        for i in type_tag.to_string().into_bytes().into_iter() {
            combined.push(i);
        }

        let message_length = combined.len();
        let signature_vec = revocation_maid.sign(&combined).into_iter().skip(message_length).collect::<Vec<_>>();

        assert_eq!(signature_vec.len(), ::sodiumoxide::crypto::sign::SIGNATUREBYTES);

        let mut signature_arr = [0; ::sodiumoxide::crypto::sign::SIGNATUREBYTES];

        for it in signature_vec.into_iter().take(::sodiumoxide::crypto::sign::SIGNATUREBYTES).enumerate() {
            signature_arr[it.0] = it.1;
        }

        let signature = ::sodiumoxide::crypto::sign::Signature(signature_arr);
        assert!(::utility::slice_equal(&signature.0, &public_maid.signature().0));
    }
}
