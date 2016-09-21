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

use core::SelfEncryptionStorage;

use core::client::Client;
use core::errors::CoreError;
use core::structured_data_operations::{self, DataFitResult};
use core::utility;
use maidsafe_utilities::serialisation::{deserialise, serialise};
use routing::{Data, DataIdentifier, ImmutableData, StructuredData, XorName};
use rust_sodium::crypto::{secretbox, sign};
use self_encryption::{DataMap, SelfEncryptor};
use std::sync::{Arc, Mutex};

#[allow(variant_size_differences)]
#[derive(Clone, RustcEncodable, RustcDecodable, PartialEq)]
enum DataTypeEncoding {
    Data(Vec<u8>),
    Map(DataMap),
    MapName(XorName),
}

/// Create StructuredData in accordance with data-encoding rules abstracted from user. For
/// StructuredData created with create, data must be obtained using the complementary function
/// defined in this module to get_data()
#[cfg_attr(feature="clippy", allow(too_many_arguments))]
pub fn create(client: Arc<Mutex<Client>>,
              type_tag: u64,
              id: XorName,
              version: u64,
              data: Vec<u8>,
              owner_keys: Vec<sign::PublicKey>,
              prev_owner_keys: Vec<sign::PublicKey>,
              private_signing_key: &sign::SecretKey,
              encryption_key: Option<&secretbox::Key>)
              -> Result<StructuredData, CoreError> {
    trace!("Creating unversioned StructuredData.");

    let data_to_store = try!(get_encoded_data_to_store(DataTypeEncoding::Data(data.clone()),
                                                       encryption_key));

    match try!(structured_data_operations::check_if_data_can_fit_in_structured_data(
            &data_to_store,
            owner_keys.clone(),
            prev_owner_keys.clone())) {
        DataFitResult::DataFits => {
            trace!("Data fits in the StructuredData.");

            Ok(try!(StructuredData::new(type_tag,
                                        id,
                                        version,
                                        data_to_store,
                                        owner_keys,
                                        prev_owner_keys,
                                        Some(private_signing_key))))
        }
        DataFitResult::DataDoesNotFit => {
            trace!("Data does not fit in the StructuredData. Self-Encrypting data...");

            let mut storage = SelfEncryptionStorage::new(client.clone());
            let mut self_encryptor = try!(SelfEncryptor::new(&mut storage, DataMap::None));
            try!(self_encryptor.write(&data, 0));
            let data_map = try!(self_encryptor.close());

            let data_to_store =
                try!(get_encoded_data_to_store(DataTypeEncoding::Map(data_map.clone()),
                                               encryption_key));
            match try!(structured_data_operations::check_if_data_can_fit_in_structured_data(
                    &data_to_store,
                    owner_keys.clone(),
                    prev_owner_keys.clone())) {
                DataFitResult::DataFits => {
                    trace!("DataMap (encrypted: {}) fits in the StructuredData.",
                           encryption_key.is_some());

                    Ok(try!(StructuredData::new(type_tag,
                                                id,
                                                version,
                                                data_to_store,
                                                owner_keys,
                                                prev_owner_keys,
                                                Some(private_signing_key))))
                }
                DataFitResult::DataDoesNotFit => {
                    trace!("DataMap (encrypted: {}) does not fit in the StructuredData. Putting \
                            it out as ImmutableData.",
                           encryption_key.is_some());

                    let immutable_data = ImmutableData::new(data_to_store);
                    let name = *immutable_data.name();
                    let data = Data::Immutable(immutable_data);
                    try!(Client::put_recover(client, data, None));

                    let data_to_store = try!(get_encoded_data_to_store(
                        DataTypeEncoding::MapName(name), encryption_key));

                    match try!(structured_data_operations::
                               check_if_data_can_fit_in_structured_data(&data_to_store,
                                                                        owner_keys.clone(),
                                                                        prev_owner_keys.clone())) {
                        DataFitResult::DataFits => {
                            trace!("ImmutableData name fits in StructuredData");
                            Ok(try!(StructuredData::new(type_tag,
                                                        id,
                                                        version,
                                                        data_to_store,
                                                        owner_keys,
                                                        prev_owner_keys,
                                                        Some(private_signing_key))))
                        }
                        _ => {
                            trace!("Even name of ImmutableData does not fit in StructuredData.");
                            Err(CoreError::StructuredDataHeaderSizeProhibitive)
                        }
                    }
                }
                DataFitResult::NoDataCanFit => Err(CoreError::StructuredDataHeaderSizeProhibitive),
            }
        }
        DataFitResult::NoDataCanFit => Err(CoreError::StructuredDataHeaderSizeProhibitive),
    }
}

/// Get Actual Data From StructuredData created via create() function in this module.
pub fn get_data(client: Arc<Mutex<Client>>,
                struct_data: &StructuredData,
                decryption_key: Option<&secretbox::Key>)
                -> Result<Vec<u8>, CoreError> {
    trace!("Getting unversioned StructuredData");

    match try!(get_decoded_stored_data(&struct_data.get_data(), decryption_key)) {
        DataTypeEncoding::Data(data) => Ok(data),
        DataTypeEncoding::Map(data_map) => {
            let mut storage = SelfEncryptionStorage::new(client);
            let mut self_encryptor = try!(SelfEncryptor::new(&mut storage, data_map));
            let length = self_encryptor.len();
            Ok(try!(self_encryptor.read(0, length)))
        }
        DataTypeEncoding::MapName(data_map_name) => {
            let request = DataIdentifier::Immutable(data_map_name);
            let response_getter = try!(unwrap!(client.lock()).get(request, None));
            match try!(response_getter.get()) {
                Data::Immutable(immutable_data) => {
                    match try!(get_decoded_stored_data(&immutable_data.value(),
                                                       decryption_key)) {
                        DataTypeEncoding::Map(data_map) => {
                            let mut storage = SelfEncryptionStorage::new(client);
                            let mut self_encryptor = try!(SelfEncryptor::new(&mut storage,
                                                                             data_map));
                            let length = self_encryptor.len();
                            Ok(try!(self_encryptor.read(0, length)))
                        }
                        _ => Err(CoreError::ReceivedUnexpectedData),
                    }
                }
                _ => Err(CoreError::ReceivedUnexpectedData),
            }
        }
    }
}

fn get_encoded_data_to_store(data: DataTypeEncoding,
                             encryption_key: Option<&secretbox::Key>)
                             -> Result<Vec<u8>, CoreError> {
    let encoded = try!(serialise(&data));

    if let Some(secret_key) = encryption_key {
        utility::symmetric_encrypt(&encoded, secret_key)
    } else {
        Ok(encoded)
    }
}

fn get_decoded_stored_data(raw_data: &[u8],
                           decryption_key: Option<&secretbox::Key>)
                           -> Result<DataTypeEncoding, CoreError> {
    if let Some(secret_key) = decryption_key {
        let decrypted = try!(utility::symmetric_decrypt(raw_data, secret_key));
        Ok(try!(deserialise(&decrypted)))
    } else {
        Ok(try!(deserialise(raw_data)))
    }
}

#[cfg(test)]
mod test {
    use core::utility;
    use rand;
    use routing::XorName;
    use rust_sodium::crypto::secretbox;
    use std::sync::{Arc, Mutex};
    use super::*;

    const TAG_ID: u64 = ::core::MAIDSAFE_TAG + 1000;

    #[test]
    fn create_and_get_unversioned_structured_data() {
        let secret_key = secretbox::gen_key();
        let client = Arc::new(Mutex::new(unwrap!(utility::test_utils::get_client())));
        // Empty Data
        {
            let id: XorName = rand::random();
            let data = Vec::new();
            let owners = utility::test_utils::get_max_sized_public_keys(1);
            let prev_owners = Vec::new();
            let sign_key = &utility::test_utils::get_max_sized_secret_keys(1)[0];
            let result = create(client.clone(),
                                TAG_ID,
                                id,
                                0,
                                data.clone(),
                                owners.clone(),
                                prev_owners.clone(),
                                sign_key,
                                None);
            match get_data(client.clone(), &unwrap!(result), None) {
                Ok(fetched_data) => assert_eq!(fetched_data, data),
                Err(_) => panic!("Failed to fetch"),
            }
        }
        // Empty Data- with decryption_keys
        {
            let id: XorName = rand::random();
            let data = Vec::new();
            let owners = utility::test_utils::get_max_sized_public_keys(1);
            let prev_owners = Vec::new();
            let sign_key = &utility::test_utils::get_max_sized_secret_keys(1)[0];
            let result = create(client.clone(),
                                TAG_ID,
                                id,
                                0,
                                data.clone(),
                                owners.clone(),
                                prev_owners.clone(),
                                sign_key,
                                Some(&secret_key));
            match get_data(client.clone(), &unwrap!(result), Some(&secret_key)) {
                Ok(fetched_data) => assert_eq!(fetched_data, data),
                Err(_) => panic!("Failed to fetch"),
            }
        }
        // Data of size 75 KB
        {
            let id: XorName = rand::random();
            let data = vec![99u8; 1024 * 75];
            let owners = utility::test_utils::get_max_sized_public_keys(1);
            let prev_owners = Vec::new();
            let sign_key = &utility::test_utils::get_max_sized_secret_keys(1)[0];
            let result = create(client.clone(),
                                TAG_ID,
                                id,
                                0,
                                data.clone(),
                                owners.clone(),
                                prev_owners.clone(),
                                sign_key,
                                None);
            match get_data(client.clone(), &unwrap!(result), None) {
                Ok(fetched_data) => assert_eq!(data.len(), fetched_data.len()),
                Err(_) => panic!("Failed to fetch"),
            }
        }
        // Data of size 75 KB with 200 owners
        {
            let id: XorName = rand::random();
            let data = vec![99u8; 1024 * 75];
            let owners = utility::test_utils::get_max_sized_public_keys(200);
            let prev_owners = Vec::new();
            let sign_key = &utility::test_utils::get_max_sized_secret_keys(1)[0];
            let result = create(client.clone(),
                                TAG_ID,
                                id,
                                0,
                                data.clone(),
                                owners.clone(),
                                prev_owners.clone(),
                                sign_key,
                                None);
            match get_data(client.clone(), &unwrap!(result), None) {
                Ok(fetched_data) => assert_eq!(fetched_data, data),
                Err(_) => panic!("Failed to fetch"),
            }
        }
        // Data of size 75 KB with MAX owners
        {
            let id: XorName = rand::random();
            let data = vec![99u8; 1024 * 75];
            let owners = utility::test_utils::get_max_sized_public_keys(903);
            let prev_owners = Vec::new();
            let sign_key = &utility::test_utils::get_max_sized_secret_keys(1)[0];
            let result = create(client.clone(),
                                TAG_ID,
                                id,
                                0,
                                data.clone(),
                                owners.clone(),
                                prev_owners.clone(),
                                sign_key,
                                None);
            match get_data(client.clone(), &unwrap!(result), None) {
                Ok(fetched_data) => assert_eq!(fetched_data, data),
                Err(_) => panic!("Failed to fetch"),
            }
        }
        // Data of size 75 KB with MAX owners - with decryption_keys
        {
            let id: XorName = rand::random();
            let data = vec![99u8; 1024 * 75];
            let owners = utility::test_utils::get_max_sized_public_keys(900);
            let prev_owners = Vec::new();
            let sign_key = &utility::test_utils::get_max_sized_secret_keys(1)[0];
            let result = create(client.clone(),
                                TAG_ID,
                                id,
                                0,
                                data.clone(),
                                owners.clone(),
                                prev_owners.clone(),
                                sign_key,
                                Some(&secret_key));
            match get_data(client.clone(), &unwrap!(result), Some(&secret_key)) {
                Ok(fetched_data) => assert_eq!(fetched_data, data),
                Err(_) => panic!("Failed to fetch"),
            }
        }
        // Data of size 80 KB with MAX + 1 - No Data could be fit - Should result in error
        {
            let id: XorName = rand::random();
            let data = vec![99u8; 1024 * 80];
            let owners = utility::test_utils::get_max_sized_public_keys(905);
            let prev_owners = Vec::new();
            let sign_key = &utility::test_utils::get_max_sized_secret_keys(1)[0];
            let result = create(client.clone(),
                                TAG_ID,
                                id,
                                0,
                                data.clone(),
                                owners.clone(),
                                prev_owners.clone(),
                                sign_key,
                                None);
            assert!(result.is_err());
        }
        // Data of size 100 KB
        {
            let id: XorName = rand::random();
            let data = vec![99u8; 102400];
            let owners = utility::test_utils::get_max_sized_public_keys(1);
            let prev_owners = Vec::new();
            let sign_key = &utility::test_utils::get_max_sized_secret_keys(1)[0];
            let result = create(client.clone(),
                                TAG_ID,
                                id,
                                0,
                                data.clone(),
                                owners.clone(),
                                prev_owners.clone(),
                                sign_key,
                                None);
            match get_data(client.clone(), &unwrap!(result), None) {
                Ok(fetched_data) => assert_eq!(fetched_data, data),
                Err(_) => panic!("Failed to fetch"),
            }
        }
        // Data of size 200 KB
        {
            let id: XorName = rand::random();
            let data = vec![99u8; 204801];
            let owners = utility::test_utils::get_max_sized_public_keys(1);
            let prev_owners = Vec::new();
            let sign_key = &utility::test_utils::get_max_sized_secret_keys(1)[0];
            let result = create(client.clone(),
                                TAG_ID,
                                id,
                                0,
                                data.clone(),
                                owners.clone(),
                                prev_owners.clone(),
                                sign_key,
                                None);
            match get_data(client.clone(), &unwrap!(result), None) {
                Ok(fetched_data) => assert_eq!(fetched_data, data),
                Err(_) => panic!("Failed to fetch"),
            }
        }
    }
}
