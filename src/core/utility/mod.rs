// Copyright 2015 MaidSafe.net limited.
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

/// Common utility functions for writting test cases
#[cfg(test)]
pub mod test_utils;

use core::errors::CoreError;
use maidsafe_utilities::serialisation::{deserialise, serialise};
use rand::Rng;
use rust_sodium::crypto::{box_, secretbox};
use rust_sodium::crypto::hash::sha512::{self, DIGESTBYTES, Digest};

/// Combined Asymmetric and Symmetric encryption. The data is encrypted using random Key and
/// IV with Xsalsa-symmetric encryption. Random IV ensures that same plain text produces different
/// cipher-texts for each fresh symmetric encryption. The Key and IV are then asymmetrically
/// enrypted using Public-MAID and the whole thing is then serialised into a single Vec<u8>.
pub fn hybrid_encrypt(plain_text: &[u8],
                      asym_nonce: &box_::Nonce,
                      asym_public_key: &box_::PublicKey,
                      asym_secret_key: &box_::SecretKey)
                      -> Result<Vec<u8>, CoreError> {
    let sym_key = secretbox::gen_key();
    let sym_nonce = secretbox::gen_nonce();

    let mut asym_plain_text = [0u8; secretbox::KEYBYTES + secretbox::NONCEBYTES];
    for it in sym_key.0.iter().chain(sym_nonce.0.iter()).enumerate() {
        asym_plain_text[it.0] = *it.1;
    }

    let sym_cipher_text = secretbox::seal(plain_text, &sym_nonce, &sym_key);
    let asym_cipher_text = box_::seal(&asym_plain_text,
                                      asym_nonce,
                                      asym_public_key,
                                      asym_secret_key);

    Ok(try!(serialise(&(asym_cipher_text, sym_cipher_text))))
}

/// Reverse of hybrid_encrypt. Refer hybrid_encrypt.
pub fn hybrid_decrypt(cipher_text: &[u8],
                      asym_nonce: &box_::Nonce,
                      asym_public_key: &box_::PublicKey,
                      asym_secret_key: &box_::SecretKey)
                      -> Result<Vec<u8>, CoreError> {
    let (asym_cipher_text, sym_cipher_text): (Vec<u8>, Vec<u8>) = try!(deserialise(cipher_text));

    let asym_plain_text = try!(box_::open(&asym_cipher_text,
                                          asym_nonce,
                                          asym_public_key,
                                          asym_secret_key)
        .map_err(|_| CoreError::AsymmetricDecipherFailure));

    if asym_plain_text.len() != secretbox::KEYBYTES + secretbox::NONCEBYTES {
        Err(CoreError::AsymmetricDecipherFailure)
    } else {
        let mut sym_key = secretbox::Key([0u8; secretbox::KEYBYTES]);
        let mut sym_nonce = secretbox::Nonce([0u8; secretbox::NONCEBYTES]);

        for it in asym_plain_text.iter().take(secretbox::KEYBYTES).enumerate() {
            sym_key.0[it.0] = *it.1;
        }
        for it in asym_plain_text.iter().skip(secretbox::KEYBYTES).enumerate() {
            sym_nonce.0[it.0] = *it.1;
        }

        secretbox::open(&sym_cipher_text, &sym_nonce, &sym_key)
            .map_err(|()| CoreError::SymmetricDecipherFailure)
    }
}

/// Generates a random string for specified size
pub fn generate_random_string(length: usize) -> Result<String, CoreError> {
    let mut os_rng = try!(::rand::OsRng::new().map_err(|error| {
        error!("{:?}", error);
        CoreError::RandomDataGenerationFailure
    }));
    Ok((0..length).map(|_| os_rng.gen::<char>()).collect())
}

/// Generate a random vector of given length
pub fn generate_random_vector<T>(length: usize) -> Result<Vec<T>, CoreError>
    where T: ::rand::Rand
{
    let mut os_rng = try!(::rand::OsRng::new().map_err(|error| {
        error!("{:?}", error);
        CoreError::RandomDataGenerationFailure
    }));
    Ok((0..length).map(|_| os_rng.gen()).collect())
}

/// Derive Password, Keyword and PIN (in order)
pub fn derive_secrets(acc_locator: &str, acc_password: &str) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let Digest(locator_hash) = sha512::hash(acc_locator.as_bytes());

    let pin = sha512::hash(&locator_hash[DIGESTBYTES / 2..]).0.to_owned();
    let keyword = locator_hash.to_owned();
    let password = sha512::hash(acc_password.as_bytes()).0.to_owned();

    (password, keyword, pin)
}

#[cfg(test)]
mod test {
    use rust_sodium::crypto::box_;
    use super::*;

    const SIZE: usize = 10;

    #[test]
    fn hybrid_encrypt_decrypt() {
        // Identical Plain Texts
        let plain_text_0 = vec![123u8; 1000];
        let plain_text_1 = plain_text_0.clone();

        let nonce = box_::gen_nonce();
        let (public_key, secret_key) = box_::gen_keypair();

        // Encrypt
        let cipher_text_0 =
            unwrap!(hybrid_encrypt(&plain_text_0[..], &nonce, &public_key, &secret_key));
        let cipher_text_1 =
            unwrap!(hybrid_encrypt(&plain_text_1[..], &nonce, &public_key, &secret_key));

        // Same Plain Texts
        assert_eq!(plain_text_0, plain_text_1);

        // Different Results because of random "iv"
        assert!(cipher_text_0 != cipher_text_1);

        // Decrypt
        let deciphered_plain_text_0 =
            unwrap!(hybrid_decrypt(&cipher_text_0, &nonce, &public_key, &secret_key));
        let deciphered_plain_text_1 =
            unwrap!(hybrid_decrypt(&cipher_text_1, &nonce, &public_key, &secret_key));

        // Should have decrypted to the same Plain Texts
        assert_eq!(plain_text_0, deciphered_plain_text_0);
        assert_eq!(plain_text_1, deciphered_plain_text_1);
    }

    #[test]
    fn random_string() {
        let str0 = unwrap!(generate_random_string(SIZE));
        let str1 = unwrap!(generate_random_string(SIZE));
        let str2 = unwrap!(generate_random_string(SIZE));

        assert!(str0 != str1);
        assert!(str0 != str2);
        assert!(str1 != str2);
    }

    #[test]
    fn random_vector() {
        let vec0 = unwrap!(generate_random_vector::<u8>(SIZE));
        let vec1 = unwrap!(generate_random_vector::<u8>(SIZE));
        let vec2 = unwrap!(generate_random_vector::<u8>(SIZE));

        assert!(vec0 != vec1);
        assert!(vec0 != vec2);
        assert!(vec1 != vec2);
    }

    #[test]
    fn secrets_derivation() {
        // Random pass-phrase
        {
            let secret_0 = unwrap!(generate_random_string(SIZE));
            let secret_1 = unwrap!(generate_random_string(SIZE));
            let (password, keyword, pin) = derive_secrets(&secret_0, &secret_1);
            assert!(pin != keyword);
            assert!(password != pin);
            assert!(password != keyword);
        }

        // Nullary pass-phrase
        {
            let secret_0 = String::new();
            let secret_1 = String::new();
            let (password, keyword, pin) = derive_secrets(&secret_0, &secret_1);
            assert!(pin != keyword);
            assert!(password != pin);
            assert!(password == keyword);
        }
    }
}
