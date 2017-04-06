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

use core::{SelfEncryptionStorage, utility};

use core::client::Client;
use core::errors::CoreError;
use maidsafe_utilities::serialisation::{deserialise, serialise};
use routing::{Data, DataIdentifier, ImmutableData, XorName};
use rust_sodium::crypto::box_::{Nonce, PublicKey, SecretKey};
use self_encryption::{DataMap, SelfEncryptor};
use std::sync::{Arc, Mutex};

// TODO(Spandan) Ask Routing to define this constant and use it from there
const MAX_IMMUT_DATA_SIZE_IN_BYTES: usize = 1024 * 1024;

#[derive(Serialize, Deserialize)]
enum DataTypeEncoding {
    Serialised(Vec<u8>),
    DataMap(DataMap),
}

/// Create and obtain immutable data out of the given raw data. The API will encrypt the right
/// content if the keys are provided and will ensure the maximum immutable data chunk size is
/// respected.
pub fn create(client: Arc<Mutex<Client>>,
              data: Vec<u8>,
              encryption_keys: Option<(&PublicKey, &SecretKey, &Nonce)>)
              -> Result<ImmutableData, CoreError> {
    trace!("Creating conformant ImmutableData.");

    let mut storage = SelfEncryptionStorage::new(client.clone());
    let mut self_encryptor = SelfEncryptor::new(&mut storage, DataMap::None)?;
    self_encryptor.write(&data, 0)?;
    let mut data_map = self_encryptor.close()?;

    let mut serialised_data_map = serialise(&data_map)?;
    let mut immut_data = if let Some((public_key, secret_key, nonce)) = encryption_keys {
        let cipher_text =
            utility::hybrid_encrypt(&serialised_data_map, nonce, public_key, secret_key)?;
        let encoded_cipher_text = serialise(&DataTypeEncoding::Serialised(cipher_text))?;
        ImmutableData::new(encoded_cipher_text)
    } else {
        let encoded_plain_text = serialise(&DataTypeEncoding::Serialised(serialised_data_map))?;
        ImmutableData::new(encoded_plain_text)
    };

    let mut serialised_data = serialise(&immut_data)?;
    while serialised_data.len() > MAX_IMMUT_DATA_SIZE_IN_BYTES {
        let mut storage = SelfEncryptionStorage::new(client.clone());
        let mut self_encryptor = SelfEncryptor::new(&mut storage, DataMap::None)?;
        self_encryptor.write(&serialised_data, 0)?;
        data_map = self_encryptor.close()?;
        serialised_data_map = serialise(&DataTypeEncoding::DataMap(data_map))?;
        immut_data = ImmutableData::new(serialised_data_map);
        serialised_data = serialise(&immut_data)?;
    }

    Ok(immut_data)
}

/// Get actual data from `ImmutableData` created via create() function in this module.
pub fn get_data(client: Arc<Mutex<Client>>,
                immut_data_name: XorName,
                decryption_keys: Option<(&PublicKey, &SecretKey, &Nonce)>)
                -> Result<Vec<u8>, CoreError> {
    trace!("Getting data after fetching a conformant ImmutableData.");

    let data_identifier = DataIdentifier::Immutable(immut_data_name);
    let response_getter = unwrap!(client.lock(), "Couldn't lock")
        .get(data_identifier, None)?;

    match response_getter.get()? {
        Data::Immutable(immut_data) => {
            get_data_from_immut_data(client, immut_data, decryption_keys)
        }
        _ => Err(CoreError::ReceivedUnexpectedData),
    }
}

/// Get actual data from `ImmutableData` created via create() function in this module.
/// Call this if you already have the `ImmutableData` with you.
pub fn get_data_from_immut_data(client: Arc<Mutex<Client>>,
                                mut immut_data: ImmutableData,
                                decryption_keys: Option<(&PublicKey, &SecretKey, &Nonce)>)
                                -> Result<Vec<u8>, CoreError> {
    let mut storage = SelfEncryptionStorage::new(client.clone());
    while let Ok(DataTypeEncoding::DataMap(data_map)) = deserialise(immut_data.value()) {
        let mut self_encryptor = SelfEncryptor::new(&mut storage, data_map)?;
        let length = self_encryptor.len();
        immut_data = deserialise(&self_encryptor.read(0, length)?)?;
    }

    match deserialise(immut_data.value())? {
        DataTypeEncoding::Serialised(serialised_data_map) => {
            let data_map = if let Some((public_key, secret_key, nonce)) = decryption_keys {
                let plain_text =
                    utility::hybrid_decrypt(&serialised_data_map, nonce, public_key, secret_key)?;
                deserialise(&plain_text)?
            } else {
                deserialise(&serialised_data_map)?
            };

            let mut self_encryptor = SelfEncryptor::new(&mut storage, data_map)?;
            let length = self_encryptor.len();
            Ok(self_encryptor.read(0, length)?)
        }
        _ => Err(CoreError::ReceivedUnexpectedData),
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use core::utility;
    use core::utility::test_utils;

    use routing::Data;
    use rust_sodium::crypto::box_;

    use std::sync::{Arc, Mutex};

    // TODO It takes a very long time in debug mode - it is due to S.E crate.
    #[test]
    fn immut_data_create_retrieve_10_mb() {
        // 10 MB of data
        let data_to_put = unwrap!(utility::generate_random_vector(1024 * 1024 * 10));

        // Unencrypted
        {
            let client = Arc::new(Mutex::new(unwrap!(test_utils::get_client())));

            let immut_data_before = unwrap!(create(client.clone(), data_to_put.clone(), None));
            let data_name = *immut_data_before.name();
            let resp_getter = unwrap!(unwrap!(client.lock())
                                          .put(Data::Immutable(immut_data_before), None));
            unwrap!(resp_getter.get());

            let data_got = unwrap!(get_data(client.clone(), data_name, None));

            assert_eq!(data_to_put, data_got);
        }

        // Encrypted
        {
            let client = Arc::new(Mutex::new(unwrap!(test_utils::get_client())));
            let (pk, sk) = box_::gen_keypair();
            let nonce = box_::gen_nonce();

            let immut_data_before = unwrap!(create(client.clone(),
                                                   data_to_put.clone(),
                                                   Some((&pk, &sk, &nonce))));
            let data_name = *immut_data_before.name();
            let resp_getter = unwrap!(unwrap!(client.lock())
                                          .put(Data::Immutable(immut_data_before), None));
            unwrap!(resp_getter.get());

            let data_got = unwrap!(get_data(client.clone(), data_name, Some((&pk, &sk, &nonce))));

            assert_eq!(data_to_put, data_got);
        }

        // Put unencrypted Retrieve encrypted - Should fail
        {
            let client = Arc::new(Mutex::new(unwrap!(test_utils::get_client())));
            let (pk, sk) = box_::gen_keypair();
            let nonce = box_::gen_nonce();

            let immut_data_before = unwrap!(create(client.clone(), data_to_put.clone(), None));
            let data_name = *immut_data_before.name();
            let resp_getter = unwrap!(unwrap!(client.lock())
                                          .put(Data::Immutable(immut_data_before), None));
            unwrap!(resp_getter.get());

            assert!(get_data(client.clone(), data_name, Some((&pk, &sk, &nonce))).is_err());
        }

        // Put encrypted Retrieve unencrypted - Should fail
        {
            let client = Arc::new(Mutex::new(unwrap!(test_utils::get_client())));
            let (pk, sk) = box_::gen_keypair();
            let nonce = box_::gen_nonce();

            let immut_data_before = unwrap!(create(client.clone(),
                                                   data_to_put.clone(),
                                                   Some((&pk, &sk, &nonce))));
            let data_name = *immut_data_before.name();
            let resp_getter = unwrap!(unwrap!(client.lock())
                                          .put(Data::Immutable(immut_data_before), None));
            unwrap!(resp_getter.get());

            assert!(get_data(client.clone(), data_name, None).is_err());
        }
    }
}
