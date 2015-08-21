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

/// IdType
///
/// #Examples
/// ```
/// use ::safe_client::id::{IdType, RevocationIdType, MaidTypeTags};
/// // Creating new IdType
/// let maid  = IdType::new(&RevocationIdType::new::<MaidTypeTags>());
///
/// ```

#[derive(Clone)]
pub struct IdType {
    type_tag: u64,
    public_keys: (::sodiumoxide::crypto::sign::PublicKey, ::sodiumoxide::crypto::box_::PublicKey),
    secret_keys: (::sodiumoxide::crypto::sign::SecretKey, ::sodiumoxide::crypto::box_::SecretKey),
}

impl IdType {

    /// Invoked to create an instance of IdType
    pub fn new(revocation_id: &::id::RevocationIdType) -> IdType {
        let asym_keys = ::sodiumoxide::crypto::box_::gen_keypair();
        let signing_keys = ::sodiumoxide::crypto::sign::gen_keypair();

        IdType {
            type_tag: revocation_id.type_tags().1,
            public_keys: (signing_keys.0, asym_keys.0),
            secret_keys: (signing_keys.1, asym_keys.1),
        }

    }
    /// Returns name
    pub fn name(&self) -> ::routing::NameType {
        let combined_iter = (&self.public_keys.0).0.into_iter().chain((&self.public_keys.1).0.into_iter());
        let mut combined: Vec<u8> = Vec::new();
        for iter in combined_iter {
            combined.push(*iter);
        }
        for i in self.type_tag.to_string().into_bytes().into_iter() {
            combined.push(i);
        }
        ::routing::NameType(::sodiumoxide::crypto::hash::sha512::hash(&combined).0)
    }

    /// Returns the PublicKeys
    pub fn public_keys(&self) -> &(::sodiumoxide::crypto::sign::PublicKey, ::sodiumoxide::crypto::box_::PublicKey) {
        &self.public_keys
    }

    /// Returns the PublicKeys
    pub fn secret_keys(&self) -> &(::sodiumoxide::crypto::sign::SecretKey, ::sodiumoxide::crypto::box_::SecretKey) {
        &self.secret_keys
    }

    /// Signs the data with the SecretKey and returns the Signed data
    pub fn sign(&self, data : &[u8]) -> Vec<u8> {
        return ::sodiumoxide::crypto::sign::sign(&data, &self.secret_keys.0)
    }

    /// Encrypts and authenticates data. It returns a ciphertext and the Nonce.
    pub fn seal(&self, data : &[u8], to : &::sodiumoxide::crypto::box_::PublicKey) -> (Vec<u8>, ::sodiumoxide::crypto::box_::Nonce) {
        let nonce = ::sodiumoxide::crypto::box_::gen_nonce();
        let sealed = ::sodiumoxide::crypto::box_::seal(data, &nonce, &to, &self.secret_keys.1);
        return (sealed, nonce);
    }

    /// Verifies and decrypts the data
    pub fn open(&self,
                data : &[u8],
                nonce : &::sodiumoxide::crypto::box_::Nonce,
                from : &::sodiumoxide::crypto::box_::PublicKey) -> Result<Vec<u8>, ::errors::ClientError> {
        ::sodiumoxide::crypto::box_::open(&data, &nonce, &from, &self.secret_keys.1).map_err(|_| ::errors::ClientError::AsymmetricDecipherFailure)
    }

}

impl PartialEq for IdType {

    fn eq(&self, other: &IdType) -> bool {
        // Private keys are mathematically linked, so just check public keys
        &self.type_tag == &other.type_tag &&
        ::utility::slice_equal(&self.public_keys.0 .0, &other.public_keys.0 .0) &&
        ::utility::slice_equal(&self.public_keys.1 .0, &other.public_keys.1 .0)
    }

}

impl ::std::fmt::Debug for IdType {

    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "IdType {{ type_tag:{}, public_keys: ({:?}, {:?}) }}", self.type_tag, self.public_keys.0 .0.to_vec(), self.public_keys.1 .0.to_vec())
    }

}

impl ::rustc_serialize::Encodable for IdType {

    fn encode<E: ::rustc_serialize::Encoder>(&self, e: &mut E) -> Result<(), E::Error> {
        let (::sodiumoxide::crypto::sign::PublicKey(pub_sign_vec), ::sodiumoxide::crypto::box_::PublicKey(pub_asym_vec)) = self.public_keys;
        let (::sodiumoxide::crypto::sign::SecretKey(sec_sign_vec), ::sodiumoxide::crypto::box_::SecretKey(sec_asym_vec)) = self.secret_keys;
        let type_vec = self.type_tag.to_string().into_bytes();

        ::cbor::CborTagEncode::new(self.type_tag, &(type_vec,
                                                    pub_sign_vec.as_ref(),
                                                    pub_asym_vec.as_ref(),
                                                    sec_sign_vec.as_ref(),
                                                    sec_asym_vec.as_ref())).encode(e)
    }

}

impl ::rustc_serialize::Decodable for IdType {

    fn decode<D: ::rustc_serialize::Decoder>(d: &mut D) -> Result<IdType, D::Error> {
        let _ = try!(d.read_u64());
        let (tag_type_vec, pub_sign_vec, pub_asym_vec, sec_sign_vec, sec_asym_vec) :
            (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) = try!(::rustc_serialize::Decodable::decode(d));
        let pub_sign_arr = convert_to_array!(pub_sign_vec, ::sodiumoxide::crypto::sign::PUBLICKEYBYTES);
        let pub_asym_arr = convert_to_array!(pub_asym_vec, ::sodiumoxide::crypto::box_::PUBLICKEYBYTES);
        let sec_sign_arr = convert_to_array!(sec_sign_vec, ::sodiumoxide::crypto::sign::SECRETKEYBYTES);
        let sec_asym_arr = convert_to_array!(sec_asym_vec, ::sodiumoxide::crypto::box_::SECRETKEYBYTES);

        if pub_sign_arr.is_none() || pub_asym_arr.is_none() || sec_sign_arr.is_none() || sec_asym_arr.is_none() {
            return Err(d.error("Bad IdType size"));
        }

        let type_tag: u64 = match String::from_utf8(tag_type_vec) {
            Ok(string) =>  {
                match string.parse::<u64>() {
                    Ok(type_tag) => type_tag,
                    Err(_) => return Err(d.error("Bad Tag Type"))
                }
            },
            Err(_) => return Err(d.error("Bad Tag Type"))
        };

        Ok(IdType {
                type_tag: type_tag,
                public_keys:(::sodiumoxide::crypto::sign::PublicKey(pub_sign_arr.unwrap()), ::sodiumoxide::crypto::box_::PublicKey(pub_asym_arr.unwrap())),
                secret_keys: (::sodiumoxide::crypto::sign::SecretKey(sec_sign_arr.unwrap()), ::sodiumoxide::crypto::box_::SecretKey(sec_asym_arr.unwrap()))
            })
    }

}

#[cfg(test)]
mod test {
    extern crate rand;

    use self::rand::Rng;
    use ::id::Random;

    impl Random for ::id::IdType {

        fn generate_random() -> ::id::IdType {
            ::id::IdType::new(&::id::RevocationIdType::new::<::id::MaidTypeTags>())
        }

    }

#[test]
    fn serialisation_maid() {
        let obj_before = ::id::IdType::generate_random();

        let mut e = ::cbor::Encoder::from_memory();
        e.encode(&[&obj_before]).unwrap();

        let mut d = ::cbor::Decoder::from_bytes(e.as_bytes());
        let obj_after: ::id::IdType = d.decode().next().unwrap().unwrap();
        let &(::sodiumoxide::crypto::sign::PublicKey(pub_sign_arr_before), ::sodiumoxide::crypto::box_::PublicKey(pub_asym_arr_before)) = obj_before.public_keys();
        let &(::sodiumoxide::crypto::sign::PublicKey(pub_sign_arr_after), ::sodiumoxide::crypto::box_::PublicKey(pub_asym_arr_after)) = obj_after.public_keys();
        let &(::sodiumoxide::crypto::sign::SecretKey(sec_sign_arr_before), ::sodiumoxide::crypto::box_::SecretKey(sec_asym_arr_before)) = &obj_before.secret_keys;
        let &(::sodiumoxide::crypto::sign::SecretKey(sec_sign_arr_after), ::sodiumoxide::crypto::box_::SecretKey(sec_asym_arr_after)) = &obj_after.secret_keys;

        assert_eq!(pub_sign_arr_before, pub_sign_arr_after);
        assert_eq!(pub_asym_arr_before, pub_asym_arr_after);
        assert!(::utility::slice_equal(&sec_sign_arr_before, &sec_sign_arr_after));
        assert_eq!(sec_asym_arr_before, sec_asym_arr_after);
    }

#[test]
    fn generation() {
        let maid1 = ::id::IdType::generate_random();
        let maid2 = ::id::IdType::generate_random();
        let maid2_clone = maid2.clone();

        assert_eq!(maid2, maid2_clone);
        assert!(!(maid2 != maid2_clone));
        assert!(maid1 != maid2);

        let random_bytes = rand::thread_rng().gen_iter::<u8>().take(100).collect::<Vec<u8>>();
        {
            let sign1 = maid1.sign(&random_bytes);
            let sign2 = maid2.sign(&random_bytes);
            assert!(sign1 != sign2);

            assert!(::sodiumoxide::crypto::sign::verify(&sign1, &maid1.public_keys().0).is_ok());
            assert!(::sodiumoxide::crypto::sign::verify(&sign2, &maid1.public_keys().0).is_err());

            assert!(::sodiumoxide::crypto::sign::verify(&sign2, &maid2.public_keys().0).is_ok());
            assert!(::sodiumoxide::crypto::sign::verify(&sign2, &maid1.public_keys().0).is_err());
        }
        {
            let maid3 = ::id::IdType::generate_random();

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
