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
/// use ::safe_client::id::{IdType, RevocationIdType, MaidTypeTags, PublicIdType};
///
///  let revocation_maid = RevocationIdType::new::<::safe_client::id::MaidTypeTags>();
///  let maid = IdType::new(&revocation_maid);
///  let public_maid  = PublicIdType::new(&maid, &revocation_maid);
/// ```

#[derive(Clone)]
pub struct PublicIdType {
    type_tag: u64,
    public_keys: (::sodiumoxide::crypto::sign::PublicKey, ::sodiumoxide::crypto::box_::PublicKey),
    revocation_public_key: ::sodiumoxide::crypto::sign::PublicKey,
    signature: ::sodiumoxide::crypto::sign::Signature,
}

impl PartialEq for PublicIdType {

    fn eq(&self, other: &PublicIdType) -> bool {
        &self.type_tag == &other.type_tag &&
        ::utility::slice_equal(&self.public_keys.0 .0, &other.public_keys.0 .0) &&
        ::utility::slice_equal(&self.public_keys.1 .0, &other.public_keys.1 .0) &&
        ::utility::slice_equal(&self.revocation_public_key.0, &other.revocation_public_key.0) &&
        ::utility::slice_equal(&self.signature.0, &other.signature.0)
    }

}

impl ::std::fmt::Debug for PublicIdType {

    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "PublicIdType {{ type_tag:{}, public_keys:({:?}, {:?}), revocation_public_key:{:?}, signature:{:?}}}",
            self.type_tag, self.public_keys.0 .0.to_vec(), self.public_keys.1 .0.to_vec(), self.revocation_public_key.0.to_vec(),
            self.signature.0.to_vec())
    }

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
        let signature_arr = convert_to_array!(signature, ::sodiumoxide::crypto::sign::SIGNATUREBYTES);
        PublicIdType { type_tag: type_tag, public_keys: public_keys,
             revocation_public_key: revocation_id.public_key().clone(),
             signature: ::sodiumoxide::crypto::sign::Signature(signature_arr.unwrap()) }
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

impl ::rustc_serialize::Encodable for PublicIdType {

    fn encode<E: ::rustc_serialize::Encoder>(&self, e: &mut E) -> Result<(), E::Error> {
        let (::sodiumoxide::crypto::sign::PublicKey(ref pub_sign_vec), ::sodiumoxide::crypto::box_::PublicKey(pub_asym_vec)) = self.public_keys;
        let ::sodiumoxide::crypto::sign::PublicKey(ref revocation_public_key_vec) = self.revocation_public_key;
        let ::sodiumoxide::crypto::sign::Signature(ref signature) = self.signature;
        let type_vec = self.type_tag.to_string().into_bytes();
        ::cbor::CborTagEncode::new(self.type_tag, &(type_vec,
                                                    pub_sign_vec.as_ref(),
                                                    pub_asym_vec.as_ref(),
                                                    revocation_public_key_vec.as_ref(),
                                                    signature.as_ref())).encode(e)
    }

}

impl ::rustc_serialize::Decodable for PublicIdType {

    fn decode<D: ::rustc_serialize::Decoder>(d: &mut D) -> Result<PublicIdType, D::Error> {
        let _ = try!(d.read_u64());
        let (tag_type_vec, pub_sign_vec, pub_asym_vec, revocation_public_key_vec, signature_vec):
            (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) = try!(::rustc_serialize::Decodable::decode(d));
        let pub_sign_arr = convert_to_array!(pub_sign_vec, ::sodiumoxide::crypto::sign::PUBLICKEYBYTES);
        let pub_asym_arr = convert_to_array!(pub_asym_vec, ::sodiumoxide::crypto::box_::PUBLICKEYBYTES);
        let revocation_public_key_arr = convert_to_array!(revocation_public_key_vec, ::sodiumoxide::crypto::box_::PUBLICKEYBYTES);
        let signature_arr = convert_to_array!(signature_vec, ::sodiumoxide::crypto::sign::SIGNATUREBYTES);

        if pub_sign_arr.is_none() || pub_asym_arr.is_none() || revocation_public_key_arr.is_none()
            || signature_arr.is_none() {
                 return Err(d.error("Bad PublicIdType size"));
        }

        let type_tag: u64 = match String::from_utf8(tag_type_vec) {
            Ok(string) =>  {
                match string.parse::<u64>() {
                    Ok(type_tag) => type_tag,
                    Err(_) => return Err(d.error("Bad Tag Type")),
                }
            },
            Err(_) => return Err(d.error("Bad Tag Type")),
        };

        Ok(PublicIdType {
                type_tag: type_tag,
                public_keys: (::sodiumoxide::crypto::sign::PublicKey(pub_sign_arr.unwrap()), ::sodiumoxide::crypto::box_::PublicKey(pub_asym_arr.unwrap())),
                revocation_public_key: ::sodiumoxide::crypto::sign::PublicKey(revocation_public_key_arr.unwrap()),
                signature: ::sodiumoxide::crypto::sign::Signature(signature_arr.unwrap()),
            })
    }

}

#[cfg(test)]
mod test {
    use super::PublicIdType;
    use routing::types::array_as_vector;
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
        PublicIdType::new(&mpid, &revocation_mpid);
    }

    #[test]
    fn serialisation_public_maid() {
        let obj_before: PublicIdType = ::id::Random::generate_random();

        let mut e = ::cbor::Encoder::from_memory();
        e.encode(&[&obj_before]).unwrap();

        let mut d = ::cbor::Decoder::from_bytes(e.as_bytes());

        let obj_after: PublicIdType = d.decode().next().unwrap().unwrap();

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
        let signature = revocation_maid.sign(&combined).into_iter().skip(message_length).collect::<Vec<_>>();
        let signature_array = convert_to_array!(signature, ::sodiumoxide::crypto::sign::SIGNATUREBYTES);
        let signature = ::sodiumoxide::crypto::sign::Signature(signature_array.unwrap());

        assert_eq!(array_as_vector(&signature.0), array_as_vector(&public_maid.signature().0));
    }
}
