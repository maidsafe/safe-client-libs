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

use core::{Client, CoreError, CoreFuture, SelfEncryptionStorage, immutable_data, utility};
use core::futures::FutureExt;
use futures::{Future, IntoFuture};
use maidsafe_utilities::serialisation::{deserialise, serialise};
use routing::{Data, ImmutableData, StructuredData, XorName};
use rust_sodium::crypto::{secretbox, sign};
use self_encryption::{DataMap, SelfEncryptor};
use super::DataFitResult;

#[derive(RustcEncodable, RustcDecodable)]
enum DataTypeEncoding {
    Data(Vec<u8>),
    Map(DataMap),
    MapName(XorName),
}

/// Create StructuredData in accordance with data-encoding rules abstracted
/// from user.
pub fn create(client: &Client,
              type_tag: u64,
              id: XorName,
              version: u64,
              value: Vec<u8>,
              curr_owner_keys: Vec<sign::PublicKey>,
              prev_owner_keys: Vec<sign::PublicKey>,
              sign_sk: sign::SecretKey,
              encryption_key: Option<secretbox::Key>)
              -> Box<CoreFuture<StructuredData>> {
    trace!("Creating unversioned StructuredData.");

    let encoded_value = fry!(encode(DataTypeEncoding::Data(value.clone()),
                                    encryption_key.as_ref()));

    match fry!(super::can_data_fit(&encoded_value,
                                   curr_owner_keys.clone(),
                                   prev_owner_keys.clone())) {
        DataFitResult::DataFits => {
            trace!("Data fits in the StructuredData.");
            StructuredData::new(type_tag,
                                id,
                                version,
                                encoded_value,
                                curr_owner_keys,
                                prev_owner_keys,
                                Some(&sign_sk))
                .map_err(From::from)
                .into_future()
                .into_box()
        }

        DataFitResult::DataDoesNotFit => {
            trace!("Data does not fit in the StructuredData. Self-Encrypting data...");
            create_with_data_map(client.clone(),
                                 type_tag,
                                 id,
                                 version,
                                 value,
                                 curr_owner_keys,
                                 prev_owner_keys,
                                 sign_sk,
                                 encryption_key)
        }
        DataFitResult::NoDataCanFit => err!(CoreError::StructuredDataHeaderSizeProhibitive),
    }
}

/// Update structured data with new value and POST it to the network.
pub fn update(client: &Client,
              data: StructuredData,
              new_value: Vec<u8>,
              sign_sk: sign::SecretKey,
              encryption_key: Option<secretbox::Key>)
              -> Box<CoreFuture<()>> {
    let client2 = client.clone();

    create(client,
           data.get_type_tag(),
           *data.name(),
           data.get_version() + 1,
           new_value,
           data.get_owner_keys().clone(),
           data.get_previous_owner_keys().clone(),
           sign_sk,
           encryption_key)
        .and_then(move |data| client2.post(Data::Structured(data), None))
        .into_box()
}

/// Get the raw bytes from StructuredData created via `create()` function in
/// this module.
pub fn extract_value(client: &Client,
                     data: &StructuredData,
                     decryption_key: Option<secretbox::Key>)
                     -> Box<CoreFuture<Vec<u8>>> {
    if data.is_deleted() {
        return ok!(Vec::new());
    }

    match fry!(decode(data.get_data(), decryption_key.as_ref())) {
        DataTypeEncoding::Data(data) => ok!(data),
        DataTypeEncoding::Map(data_map) => {
            let storage = SelfEncryptionStorage::new(client.clone());
            let self_encryptor = fry!(SelfEncryptor::new(storage, data_map));
            let length = self_encryptor.len();
            self_encryptor.read(0, length).map_err(From::from).into_box()
        }
        DataTypeEncoding::MapName(data_map_name) => {
            let client2 = client.clone();

            immutable_data::get(client, &data_map_name)
                .and_then(move |immutable_data| {
                    match fry!(decode(immutable_data.value(), decryption_key.as_ref())) {
                        DataTypeEncoding::Map(data_map) => {
                            let storage = SelfEncryptionStorage::new(client2);
                            let self_encryptor = fry!(SelfEncryptor::new(storage, data_map));
                            let length = self_encryptor.len();
                            self_encryptor.read(0, length)
                                .map_err(From::from)
                                .into_box()
                        }
                        _ => err!(CoreError::ReceivedUnexpectedData),
                    }
                })
                .into_box()
        }
    }
}

/// Get structured data from the network and extract its value, decrypting it
/// in the process (if keys provided).  This is a convenience function
/// combining `get` and `extract_value` into one function.
pub fn get_value(client: &Client,
                 type_tag: u64,
                 id: &XorName,
                 decryption_key: Option<secretbox::Key>)
                 -> Box<CoreFuture<Vec<u8>>> {
    let client2 = client.clone();
    super::get(client, type_tag, id)
        .and_then(move |data| extract_value(&client2, &data, decryption_key))
        .into_box()
}

// Create structured data containing a data map of the given value.
fn create_with_data_map(client: Client,
                        type_tag: u64,
                        id: XorName,
                        version: u64,
                        value: Vec<u8>,
                        curr_owner_keys: Vec<sign::PublicKey>,
                        prev_owner_keys: Vec<sign::PublicKey>,
                        sign_sk: sign::SecretKey,
                        encryption_key: Option<secretbox::Key>)
                        -> Box<CoreFuture<StructuredData>> {

    let storage = SelfEncryptionStorage::new(client.clone());
    let self_encryptor = fry!(SelfEncryptor::new(storage, DataMap::None));

    self_encryptor.write(&value, 0)
        .and_then(move |_| self_encryptor.close())
        .map_err(From::from)
        .and_then(move |(data_map, _)| {
            let encoded_data_map = fry!(encode(DataTypeEncoding::Map(data_map.clone()),
                                               encryption_key.as_ref()));

            match fry!(super::can_data_fit(&encoded_data_map,
                                           curr_owner_keys.clone(),
                                           prev_owner_keys.clone())) {
                DataFitResult::DataFits => {
                    trace!("DataMap (encrypted: {}) fits in the StructuredData.",
                           encryption_key.is_some());

                    StructuredData::new(type_tag,
                                        id,
                                        version,
                                        encoded_data_map,
                                        curr_owner_keys,
                                        prev_owner_keys,
                                        Some(&sign_sk))
                        .map_err(From::from)
                        .into_future()
                        .into_box()
                }
                DataFitResult::DataDoesNotFit => {
                    trace!("DataMap (encrypted: {}) does not fit in the StructuredData. Putting \
                            it out as ImmutableData.",
                           encryption_key.is_some());
                    create_with_immutable_data(client.clone(),
                                               type_tag,
                                               id,
                                               version,
                                               encoded_data_map,
                                               curr_owner_keys,
                                               prev_owner_keys,
                                               sign_sk,
                                               encryption_key)
                }
                DataFitResult::NoDataCanFit => err!(CoreError::StructuredDataHeaderSizeProhibitive),
            }
        })
        .into_box()
}

// Create strucutred data contaning the name of the immutable data contianing
// the given value.
fn create_with_immutable_data(client: Client,
                              type_tag: u64,
                              id: XorName,
                              version: u64,
                              value: Vec<u8>,
                              curr_owner_keys: Vec<sign::PublicKey>,
                              prev_owner_keys: Vec<sign::PublicKey>,
                              sign_sk: sign::SecretKey,
                              encryption_key: Option<secretbox::Key>)
                              -> Box<CoreFuture<StructuredData>> {
    let immutable_data = ImmutableData::new(value);
    let name = *immutable_data.name();

    client.put_recover(Data::Immutable(immutable_data), None, sign_sk.clone())
        .and_then(move |_| {
            let encoded_name = encode(DataTypeEncoding::MapName(name), encryption_key.as_ref())?;
            match super::can_data_fit(&encoded_name,
                                      curr_owner_keys.clone(),
                                      prev_owner_keys.clone())? {
                DataFitResult::DataFits => {
                    trace!("ImmutableData name fits in StructuredData");
                    Ok(StructuredData::new(type_tag,
                                           id,
                                           version,
                                           encoded_name,
                                           curr_owner_keys,
                                           prev_owner_keys,
                                           Some(&sign_sk))?)
                }
                _ => {
                    trace!("Even name of ImmutableData does not fit in \
                            StructuredData.");
                    Err(CoreError::StructuredDataHeaderSizeProhibitive)
                }
            }
        })
        .into_box()
}

fn encode(data: DataTypeEncoding,
          encryption_key: Option<&secretbox::Key>)
          -> Result<Vec<u8>, CoreError> {
    let serialised = serialise(&data)?;
    if let Some(key) = encryption_key {
        utility::symmetric_encrypt(&serialised, key)
    } else {
        Ok(serialised)
    }
}

fn decode(raw_data: &[u8],
          decryption_key: Option<&secretbox::Key>)
          -> Result<DataTypeEncoding, CoreError> {
    if let Some(key) = decryption_key {
        let decrypted = utility::symmetric_decrypt(raw_data, key)?;
        Ok(deserialise(&decrypted)?)
    } else {
        Ok(deserialise(raw_data)?)
    }
}

#[cfg(test)]
mod tests {
    use core::MAIDSAFE_TAG;
    use core::utility;
    use core::utility::test_utils::{self, finish, random_client};
    use futures::Future;
    use rand;
    use rust_sodium::crypto::secretbox;
    use super::*;

    const TAG: u64 = MAIDSAFE_TAG + 1000;

    #[test]
    fn create_and_retrieve_empty_unencrypted() {
        create_and_retrieve(0, 1, None);
    }

    #[test]
    fn create_and_retrieve_empty_encrypted() {
        let key = secretbox::gen_key();
        create_and_retrieve(0, 1, Some(key));
    }

    #[test]
    fn create_and_retrieve_75kb() {
        create_and_retrieve(75 * 1024, 1, None);
    }

    #[test]
    fn create_and_retrieve_75kb_200_owners() {
        create_and_retrieve(75 * 1024, 200, None);
    }

    #[test]
    fn create_and_retrieve_75kb_max_owners() {
        // TODO (adam): where is the number 903 coming from?
        create_and_retrieve(75 * 1024, 903, None);
    }

    #[test]
    fn create_and_retrieve_75kb_max_owners_encrypted() {
        // TODO (adam): where is the number 900 coming from?
        let key = secretbox::gen_key();
        create_and_retrieve(75 * 1024, 900, Some(key));
    }

    #[test]
    fn create_and_retrieve_80kb_max_plus_1_owners() {
        let id = rand::random();
        let value = unwrap!(utility::generate_random_vector(80 * 1024));
        // TODO (adam): where is the number 905 coming from?
        let curr_owners = test_utils::get_max_sized_public_keys(905);
        let prev_owners = Vec::new();
        let sign_key = test_utils::get_max_sized_secret_keys(1).remove(0);

        random_client(move |client| {
            create(client,
                   TAG,
                   id,
                   0,
                   value.clone(),
                   curr_owners.clone(),
                   prev_owners.clone(),
                   sign_key,
                   None)
                .then(|res| {
                    assert!(res.is_err());
                    finish()
                })
        });
    }

    #[test]
    fn create_and_retrieve_100kb() {
        create_and_retrieve(100 * 1024, 1, None);
    }

    #[test]
    fn create_and_retrieve_200kb() {
        create_and_retrieve(200 * 1024, 1, None);
    }

    fn create_and_retrieve(value_size: usize, num_owners: usize, key: Option<secretbox::Key>) {
        let id = rand::random();
        let value = unwrap!(utility::generate_random_vector(value_size));
        let curr_owners = test_utils::get_max_sized_public_keys(num_owners);
        let prev_owners = Vec::new();
        let sign_key = test_utils::get_max_sized_secret_keys(1).remove(0);

        random_client(move |client| {
            let client2 = client.clone();

            create(client,
                   TAG,
                   id,
                   0,
                   value.clone(),
                   curr_owners.clone(),
                   prev_owners.clone(),
                   sign_key,
                   key.clone())
                .then(move |res| {
                    let data = unwrap!(res);
                    extract_value(&client2, &data, key)
                })
                .then(move |res| {
                    let value_after = unwrap!(res);
                    assert_eq!(value_after, value);
                    finish()
                })
        });
    }
}
