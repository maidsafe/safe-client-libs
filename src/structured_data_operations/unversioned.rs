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

use client::Client;
use xor_name::XorName;
use errors::CoreError;
use std::sync::{Arc, Mutex};
use self_encryption::datamap;
use sodiumoxide::crypto::{box_, sign};
use maidsafe_utilities::serialisation::{serialise, deserialise};
use routing::{StructuredData, ImmutableData, ImmutableDataType, Data, DataRequest};

#[allow(variant_size_differences)]
#[derive(Clone, RustcEncodable, RustcDecodable, PartialEq)]
enum DataTypeEncoding {
    ContainsData(Vec<u8>),
    ContainsDataMap(datamap::DataMap),
    ContainsDataMapName(XorName),
}

/// Create StructuredData in accordance with data-encoding rules abstracted from user. For
/// StructuredData created with create, data must be obtained using the complementary function
/// defined in this module to get_data()
pub fn create(client: ::std::sync::Arc<::std::sync::Mutex<::client::Client>>,
              tag_type: u64,
              id: XorName,
              version: u64,
              data: Vec<u8>,
              owner_keys: Vec<sign::PublicKey>,
              prev_owner_keys: Vec<sign::PublicKey>,
              private_signing_key: &sign::SecretKey,
              data_encryption_keys: Option<(&box_::PublicKey, &box_::SecretKey, &box_::Nonce)>)
              -> Result<StructuredData, CoreError> {
    let data_to_store = try!(get_encoded_data_to_store(DataTypeEncoding::ContainsData(data.clone()),
                                                       data_encryption_keys));

    match try!(::structured_data_operations::check_if_data_can_fit_in_structured_data(&data_to_store,
                                                                                      owner_keys.clone(),
                                                                                      prev_owner_keys.clone())) {
        ::structured_data_operations::DataFitResult::DataFits => {
            Ok(try!(StructuredData::new(tag_type,
                                        id,
                                        version,
                                        data_to_store,
                                        owner_keys,
                                        prev_owner_keys,
                                        Some(private_signing_key))))

        },
        ::structured_data_operations::DataFitResult::DataDoesNotFit => {
            let mut se = ::self_encryption::SelfEncryptor::new(::SelfEncryptionStorage::new(client.clone()),
                                                                                            datamap::DataMap::None);
            se.write(&data, 0);
            let data_map = se.close();

            let data_to_store = try!(get_encoded_data_to_store(DataTypeEncoding::ContainsDataMap(data_map.clone()),
                                                                                                 data_encryption_keys));
            match try!(::structured_data_operations::check_if_data_can_fit_in_structured_data(&data_to_store,
                                                                                              owner_keys.clone(),
                                                                                              prev_owner_keys.clone())) {
                ::structured_data_operations::DataFitResult::DataFits => {
                    Ok(try!(StructuredData::new(tag_type,
                                                id,
                                                version,
                                                data_to_store,
                                                owner_keys,
                                                prev_owner_keys,
                                                Some(private_signing_key))))

                },
                ::structured_data_operations::DataFitResult::DataDoesNotFit => {
                    let immutable_data = ImmutableData::new(ImmutableDataType::Normal, data_to_store);
                    let name = immutable_data.name();
                    let data = Data::Immutable(immutable_data);
                    try!(unwrap_result!(client.lock()).put(data, None));

                    let data_to_store = try!(get_encoded_data_to_store(DataTypeEncoding::ContainsDataMapName(name),
                                                                       data_encryption_keys));

                    match try!(::structured_data_operations::check_if_data_can_fit_in_structured_data(&data_to_store,
                                                                                                      owner_keys.clone(),
                                                                                                      prev_owner_keys.clone())) {
                        ::structured_data_operations::DataFitResult::DataFits => {
                            Ok(try!(StructuredData::new(tag_type,
                                                        id,
                                                        version,
                                                        data_to_store,
                                                        owner_keys,
                                                        prev_owner_keys,
                                                        Some(private_signing_key))))
                        },
                        _ => Err(::errors::CoreError::StructuredDataHeaderSizeProhibitive),
                    }
                },
                ::structured_data_operations::DataFitResult::NoDataCanFit => Err(CoreError::StructuredDataHeaderSizeProhibitive),
            }
        },
        ::structured_data_operations::DataFitResult::NoDataCanFit => Err(CoreError::StructuredDataHeaderSizeProhibitive),
    }
}

/// Get Actual Data From StructuredData created via create() function in this module.
pub fn get_data(client: Arc<Mutex<Client>>,
                struct_data: &StructuredData,
                data_decryption_keys: Option<(&box_::PublicKey, &box_::SecretKey, &box_::Nonce)>)
                -> Result<Vec<u8>, CoreError> {
    match try!(get_decoded_stored_data(&struct_data.get_data(), data_decryption_keys)) {
        DataTypeEncoding::ContainsData(data) => Ok(data),
        DataTypeEncoding::ContainsDataMap(data_map) => {
            let mut se =
                ::self_encryption::SelfEncryptor::new(::SelfEncryptionStorage::new(client),
                                                      data_map);
            let length = se.len();
            Ok(se.read(0, length))
        }
        DataTypeEncoding::ContainsDataMapName(data_map_name) => {
            let request = DataRequest::Immutable(data_map_name, ImmutableDataType::Normal);
            let response_getter = try!(unwrap_result!(client.lock()).get(request, None));
            match try!(response_getter.get()) {
                Data::Immutable(immutable_data) => {
                    match try!(get_decoded_stored_data(&immutable_data.value(),
                                                       data_decryption_keys)) {
                        DataTypeEncoding::ContainsDataMap(data_map) => {
                            let mut se = ::self_encryption::SelfEncryptor::new(::SelfEncryptionStorage::new(client.clone()), data_map);
                            let length = se.len();
                            Ok(se.read(0, length))
                        }
                        _ => Err(::errors::CoreError::ReceivedUnexpectedData),
                    }
                }
                _ => Err(::errors::CoreError::ReceivedUnexpectedData),
            }
        }
    }
}

fn get_encoded_data_to_store(data: DataTypeEncoding,
                             data_encryption_keys: Option<(&box_::PublicKey,
                                                           &box_::SecretKey,
                                                           &box_::Nonce)>)
                             -> Result<Vec<u8>, CoreError> {
    let serialised_data = try!(serialise(&data));
    if let Some((public_encryp_key, secret_encryp_key, nonce)) = data_encryption_keys {
        ::utility::hybrid_encrypt(&serialised_data,
                                  nonce,
                                  public_encryp_key,
                                  secret_encryp_key)
    } else {
        Ok(serialised_data)
    }
}

fn get_decoded_stored_data(raw_data: &Vec<u8>,
                           data_decryption_keys: Option<(&box_::PublicKey,
                                                         &box_::SecretKey,
                                                         &box_::Nonce)>)
                           -> Result<DataTypeEncoding, CoreError> {
    let data: _;
    let data_to_deserialise = if let Some((public_encryp_key, secret_encryp_key, nonce)) =
                                     data_decryption_keys {
        data = try!(::utility::hybrid_decrypt(&raw_data,
                                              nonce,
                                              public_encryp_key,
                                              secret_encryp_key));
        &data
    } else {
        raw_data
    };

    Ok(try!(deserialise(data_to_deserialise)))
}

#[cfg(test)]
mod test {
    use super::*;
    use xor_name::XorName;
    use std::sync::{Arc, Mutex};
    use sodiumoxide::crypto::box_;

    const TAG_ID: u64 = ::MAIDSAFE_TAG + 1000;

    #[test]
    fn create_and_get_unversionsed_structured_data() {
        let keys = box_::gen_keypair();
        let data_decryption_keys = (&keys.0, &keys.1, &box_::gen_nonce());
        let client = Arc::new(Mutex::new(unwrap_result!(::utility::test_utils::get_client())));
        // Empty Data
        {
            let id = XorName::new(unwrap_result!(::utility::generate_random_array_u8_64()));
            let data = Vec::new();
            let owners = ::utility::test_utils::get_max_sized_public_keys(1);
            let prev_owners = Vec::new();
            let ref secret_key = ::utility::test_utils::get_max_sized_secret_keys(1)[0];
            let result = create(client.clone(),
                                TAG_ID,
                                id,
                                0,
                                data.clone(),
                                owners.clone(),
                                prev_owners.clone(),
                                secret_key,
                                None);
            match get_data(client.clone(), &unwrap_result!(result), None) {
                Ok(fetched_data) => assert_eq!(fetched_data, data),
                Err(_) => panic!("Failed to fetch"),
            }
        }
        // Empty Data- with decryption_keys
        {
            let id = XorName::new(unwrap_result!(::utility::generate_random_array_u8_64()));
            let data = Vec::new();
            let owners = ::utility::test_utils::get_max_sized_public_keys(1);
            let prev_owners = Vec::new();
            let ref secret_key = ::utility::test_utils::get_max_sized_secret_keys(1)[0];
            let result = create(client.clone(),
                                TAG_ID,
                                id,
                                0,
                                data.clone(),
                                owners.clone(),
                                prev_owners.clone(),
                                secret_key,
                                Some(data_decryption_keys));
            match get_data(client.clone(),
                           &unwrap_result!(result),
                           Some(data_decryption_keys)) {
                Ok(fetched_data) => assert_eq!(fetched_data, data),
                Err(_) => panic!("Failed to fetch"),
            }
        }
        // Data of size 75 KB
        {
            let id = XorName::new(unwrap_result!(::utility::generate_random_array_u8_64()));
            let data = vec![99u8; 1024 * 75];
            let owners = ::utility::test_utils::get_max_sized_public_keys(1);
            let prev_owners = Vec::new();
            let ref secret_key = ::utility::test_utils::get_max_sized_secret_keys(1)[0];
            let result = create(client.clone(),
                                TAG_ID,
                                id,
                                0,
                                data.clone(),
                                owners.clone(),
                                prev_owners.clone(),
                                secret_key,
                                None);
            match get_data(client.clone(), &unwrap_result!(result), None) {
                Ok(fetched_data) => assert_eq!(data.len(), fetched_data.len()),
                Err(_) => panic!("Failed to fetch"),
            }
        }
        // Data of size 75 KB with 200 owners
        {
            let id = XorName::new(unwrap_result!(::utility::generate_random_array_u8_64()));
            let data = vec![99u8; 1024 * 75];
            let owners = ::utility::test_utils::get_max_sized_public_keys(200);
            let prev_owners = Vec::new();
            let ref secret_key = ::utility::test_utils::get_max_sized_secret_keys(1)[0];
            let result = create(client.clone(),
                                TAG_ID,
                                id,
                                0,
                                data.clone(),
                                owners.clone(),
                                prev_owners.clone(),
                                secret_key,
                                None);
            match get_data(client.clone(), &unwrap_result!(result), None) {
                Ok(fetched_data) => assert_eq!(fetched_data, data),
                Err(_) => panic!("Failed to fetch"),
            }
        }
        // Data of size 75 KB with MAX owners
        {
            let id = XorName::new(unwrap_result!(::utility::generate_random_array_u8_64()));
            let data = vec![99u8; 1024 * 75];
            let owners = ::utility::test_utils::get_max_sized_public_keys(515);
            let prev_owners = Vec::new();
            let ref secret_key = ::utility::test_utils::get_max_sized_secret_keys(1)[0];
            let result = create(client.clone(),
                                TAG_ID,
                                id,
                                0,
                                data.clone(),
                                owners.clone(),
                                prev_owners.clone(),
                                secret_key,
                                None);
            match get_data(client.clone(), &unwrap_result!(result), None) {
                Ok(fetched_data) => assert_eq!(fetched_data, data),
                Err(_) => panic!("Failed to fetch"),
            }
        }
        // Data of size 75 KB with MAX owners - with decryption_keys
        {
            let id = XorName::new(unwrap_result!(::utility::generate_random_array_u8_64()));
            let data = vec![99u8; 1024 * 75];
            let owners = ::utility::test_utils::get_max_sized_public_keys(510);
            let prev_owners = Vec::new();
            let ref secret_key = ::utility::test_utils::get_max_sized_secret_keys(1)[0];
            let result = create(client.clone(),
                                TAG_ID,
                                id,
                                0,
                                data.clone(),
                                owners.clone(),
                                prev_owners.clone(),
                                secret_key,
                                Some(data_decryption_keys));
            match get_data(client.clone(),
                           &unwrap_result!(result),
                           Some(data_decryption_keys)) {
                Ok(fetched_data) => assert_eq!(fetched_data, data),
                Err(_) => panic!("Failed to fetch"),
            }
        }
        // Data of size 80 KB with MAX + 1 - No Data could be fit - Should result in error
        {
            let id = XorName::new(unwrap_result!(::utility::generate_random_array_u8_64()));
            let data = vec![99u8; 1024 * 80];
            let owners = ::utility::test_utils::get_max_sized_public_keys(517);
            let prev_owners = Vec::new();
            let ref secret_key = ::utility::test_utils::get_max_sized_secret_keys(1)[0];
            let result = create(client.clone(),
                                TAG_ID,
                                id,
                                0,
                                data.clone(),
                                owners.clone(),
                                prev_owners.clone(),
                                secret_key,
                                None);
            assert!(result.is_err());
        }
        // Data of size 100 KB
        {
            let id = XorName::new(unwrap_result!(::utility::generate_random_array_u8_64()));
            let data = vec![99u8; 102400];
            let owners = ::utility::test_utils::get_max_sized_public_keys(1);
            let prev_owners = Vec::new();
            let ref secret_key = ::utility::test_utils::get_max_sized_secret_keys(1)[0];
            let result = create(client.clone(),
                                TAG_ID,
                                id,
                                0,
                                data.clone(),
                                owners.clone(),
                                prev_owners.clone(),
                                secret_key,
                                None);
            match get_data(client.clone(), &unwrap_result!(result), None) {
                Ok(fetched_data) => assert_eq!(fetched_data, data),
                Err(_) => panic!("Failed to fetch"),
            }
        }
        // Data of size 200 KB
        {
            let id = XorName::new(unwrap_result!(::utility::generate_random_array_u8_64()));
            let data = vec![99u8; 204801];
            let owners = ::utility::test_utils::get_max_sized_public_keys(1);
            let prev_owners = Vec::new();
            let ref secret_key = ::utility::test_utils::get_max_sized_secret_keys(1)[0];
            let result = create(client.clone(),
                                TAG_ID,
                                id,
                                0,
                                data.clone(),
                                owners.clone(),
                                prev_owners.clone(),
                                secret_key,
                                None);
            match get_data(client.clone(), &unwrap_result!(result), None) {
                Ok(fetched_data) => assert_eq!(fetched_data, data),
                Err(_) => panic!("Failed to fetch"),
            }
        }
    }
}
