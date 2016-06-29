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

use core::client::Client;
use core::errors::CoreError;
use core::utility;
use sodiumoxide::crypto::sign;

/// Generates a random mock client for testing
pub fn get_client() -> Result<Client, CoreError> {
    let pin = try!(utility::generate_random_string(10));
    let keyword = try!(utility::generate_random_string(10));
    let password = try!(utility::generate_random_string(10));

    Client::create_account(keyword, pin, password)
}

/// Generates random public keys
pub fn generate_public_keys(len: usize) -> Vec<sign::PublicKey> {
    (0..len).map(|_| sign::gen_keypair().0).collect()
}

/// Generates random secret keys
pub fn generate_secret_keys(len: usize) -> Vec<sign::SecretKey> {
    (0..len).map(|_| sign::gen_keypair().1).collect()
}

/// Generates public keys of maximum size
pub fn get_max_sized_public_keys(len: usize) -> Vec<sign::PublicKey> {
    ::std::iter::repeat(sign::PublicKey([::std::u8::MAX; sign::PUBLICKEYBYTES])).take(len).collect()
}

/// Generates secret keys of maximum size
pub fn get_max_sized_secret_keys(len: usize) -> Vec<sign::SecretKey> {
    ::std::iter::repeat(sign::SecretKey([::std::u8::MAX; sign::SECRETKEYBYTES])).take(len).collect()
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn random_client() {
        let client_0 = unwrap!(get_client());
        let client_1 = unwrap!(get_client());

        let sign_key_0 = unwrap!(client_0.get_public_signing_key());
        let sign_key_1 = unwrap!(client_1.get_public_signing_key());
        let pub_key_0 = unwrap!(client_0.get_public_encryption_key());
        let pub_key_1 = unwrap!(client_1.get_public_encryption_key());

        assert!(sign_key_0 != sign_key_1);
        assert!(pub_key_0 != pub_key_1);
    }
}
