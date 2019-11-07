// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

#[macro_use]
mod futures;

/// Seed utilities.
pub mod seed;

/// Logging utilities.
pub mod logging;

/// Common utility functions for writing test cases.
#[cfg(any(test, feature = "testing"))]
pub mod test_utils;

pub use self::futures::FutureExt;
use crate::errors::CoreError;
use bincode::{deserialize, serialize};
use rand::Rng;
use rust_sodium::crypto::hash::sha512::{self, Digest, DIGESTBYTES};
use rust_sodium::crypto::secretbox;
use serde::{Deserialize, Serialize};

/// Easily create a BTreeSet.
#[macro_export]
macro_rules! btree_set {
    ($($item:expr),*) => {{
        let mut _set = ::std::collections::BTreeSet::new();
        $(
            let _ = _set.insert($item);
        )*
        _set
    }};

    ($($item:expr),*,) => {
        btree_set![$($item),*]
    };
}

/// Easily create a BTreeMap with the key => value syntax.
#[macro_export]
macro_rules! btree_map {
    () => ({
        ::std::collections::BTreeMap::new()
    });

    ($($key:expr => $value:expr),*) => {{
        let mut _map = ::std::collections::BTreeMap::new();
        $(
            let _ = _map.insert($key, $value);
        )*
        _map
    }};

    ($($key:expr => $value:expr),*,) => {
        btree_map![$($key => $value),*]
    };
}

#[derive(Serialize, Deserialize)]
struct SymmetricEnc {
    nonce: [u8; secretbox::NONCEBYTES],
    cipher_text: Vec<u8>,
}

/// Symmetric encryption.
/// If `nonce` is `None`, then it will be generated randomly.
pub fn symmetric_encrypt(
    plain_text: &[u8],
    secret_key: &secretbox::Key,
    nonce: Option<&secretbox::Nonce>,
) -> Result<Vec<u8>, CoreError> {
    let nonce = match nonce {
        Some(nonce) => *nonce,
        None => secretbox::gen_nonce(),
    };

    let cipher_text = secretbox::seal(plain_text, &nonce, secret_key);

    Ok(serialize(&SymmetricEnc {
        nonce: nonce.0,
        cipher_text,
    })?)
}

/// Symmetric decryption.
pub fn symmetric_decrypt(
    cipher_text: &[u8],
    secret_key: &secretbox::Key,
) -> Result<Vec<u8>, CoreError> {
    let SymmetricEnc { nonce, cipher_text } = deserialize::<SymmetricEnc>(cipher_text)?;
    secretbox::open(&cipher_text, &secretbox::Nonce(nonce), secret_key)
        .map_err(|_| CoreError::SymmetricDecipherFailure)
}

/// Generates a `String` from `length` random UTF-8 `char`s.  Note that the NULL character will be
/// excluded to allow conversion to a `CString` if required, and that the actual `len()` of the
/// returned `String` will likely be around `4 * length` as most of the randomly-generated `char`s
/// will consume 4 elements of the `String`.
pub fn generate_random_string(length: usize) -> Result<String, CoreError> {
    let mut os_rng = ::rand::OsRng::new().map_err(|error| {
        error!("{:?}", error);
        CoreError::RandomDataGenerationFailure
    })?;
    Ok(os_rng
        .gen_iter::<char>()
        .filter(|c| *c != '\u{0}')
        .take(length)
        .collect())
}

/// Generates a readable `String` using only ASCII characters.
pub fn generate_readable_string(length: usize) -> Result<String, CoreError> {
    let mut os_rng = ::rand::OsRng::new().map_err(|error| {
        error!("{:?}", error);
        CoreError::RandomDataGenerationFailure
    })?;
    Ok(os_rng.gen_ascii_chars().take(length).collect())
}

/// Generate a random vector of given length.
pub fn generate_random_vector<T>(length: usize) -> Result<Vec<T>, CoreError>
where
    T: ::rand::Rand,
{
    let mut os_rng = ::rand::OsRng::new().map_err(|error| {
        error!("{:?}", error);
        CoreError::RandomDataGenerationFailure
    })?;
    Ok(os_rng.gen_iter().take(length).collect())
}

/// Derive Password, Keyword and PIN (in order).
pub fn derive_secrets(acc_locator: &[u8], acc_password: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let Digest(locator_hash) = sha512::hash(acc_locator);

    let pin = sha512::hash(&locator_hash[DIGESTBYTES / 2..]).0.to_vec();
    let keyword = locator_hash.to_vec();
    let password = sha512::hash(acc_password).0.to_vec();

    (password, keyword, pin)
}

/// Convert binary data to a diplay-able format
#[inline]
pub fn bin_data_format(data: &[u8]) -> String {
    let len = data.len();
    if len < 8 {
        return format!("[ {:?} ]", data);
    }

    format!(
        "[ {:02x} {:02x} {:02x} {:02x}..{:02x} {:02x} {:02x} {:02x} ]",
        data[0],
        data[1],
        data[2],
        data[3],
        data[len - 4],
        data[len - 3],
        data[len - 2],
        data[len - 1]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIZE: usize = 10;

    // Test `generate_random_string` and that the results are not repeated.
    #[test]
    fn random_string() {
        let str0 = unwrap!(generate_random_string(SIZE));
        let str1 = unwrap!(generate_random_string(SIZE));
        let str2 = unwrap!(generate_random_string(SIZE));

        assert_ne!(str0, str1);
        assert_ne!(str0, str2);
        assert_ne!(str1, str2);

        assert_eq!(str0.chars().count(), SIZE);
        assert_eq!(str1.chars().count(), SIZE);
        assert_eq!(str2.chars().count(), SIZE);
    }

    // Test `generate_random_vector` and that the results are not repeated.
    #[test]
    fn random_vector() {
        let vec0 = unwrap!(generate_random_vector::<u8>(SIZE));
        let vec1 = unwrap!(generate_random_vector::<u8>(SIZE));
        let vec2 = unwrap!(generate_random_vector::<u8>(SIZE));

        assert_ne!(vec0, vec1);
        assert_ne!(vec0, vec2);
        assert_ne!(vec1, vec2);

        assert_eq!(vec0.len(), SIZE);
        assert_eq!(vec1.len(), SIZE);
        assert_eq!(vec2.len(), SIZE);
    }

    // Test derivation of distinct password, keyword, and pin secrets.
    #[test]
    fn secrets_derivation() {
        // Random pass-phrase
        {
            let secret_0 = unwrap!(generate_random_string(SIZE));
            let secret_1 = unwrap!(generate_random_string(SIZE));
            let (password, keyword, pin) = derive_secrets(secret_0.as_bytes(), secret_1.as_bytes());
            assert_ne!(pin, keyword);
            assert_ne!(password, pin);
            assert_ne!(password, keyword);
        }

        // Nullary pass-phrase
        {
            let secret_0 = String::new();
            let secret_1 = String::new();
            let (password, keyword, pin) = derive_secrets(secret_0.as_bytes(), secret_1.as_bytes());
            assert_ne!(pin, keyword);
            assert_ne!(password, pin);
            assert_eq!(password, keyword);
        }
    }
}
