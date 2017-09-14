// Copyright 2016 MaidSafe.net limited.
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

use client::Client;
use crypto::shared_secretbox;
use event_loop::CoreFuture;
use futures::Future;
use maidsafe_utilities::serialisation::{deserialise, serialise};
use routing::{ImmutableData, XorName};
use self_encryption::{DataMap, SelfEncryptor};
use self_encryption_storage::SelfEncryptionStorage;
use utils::{self, FutureExt};

#[derive(Serialize, Deserialize)]
enum DataTypeEncoding {
    Serialised(Vec<u8>),
    DataMap(DataMap),
}

/// Create and obtain immutable data out of the given raw bytes. The API will
/// encrypt the right content if the keys are provided and will ensure the
/// maximum immutable data chunk size is respected.
pub fn create<T: 'static>(
    client: &Client<T>,
    value: &[u8],
    encryption_key: Option<shared_secretbox::Key>,
) -> Box<CoreFuture<ImmutableData>> {
    trace!("Creating conformant ImmutableData.");

    let client = client.clone();
    let storage = SelfEncryptionStorage::new(client.clone());
    let self_encryptor = fry!(SelfEncryptor::new(storage, DataMap::None));

    self_encryptor
        .write(value, 0)
        .and_then(move |_| self_encryptor.close())
        .map_err(From::from)
        .and_then(move |(data_map, _)| {
            let serialised_data_map = fry!(serialise(&data_map));

            let value = if let Some(key) = encryption_key {
                let cipher_text = fry!(utils::symmetric_encrypt(&serialised_data_map, &key, None));
                fry!(serialise(&DataTypeEncoding::Serialised(cipher_text)))
            } else {
                fry!(serialise(
                    &DataTypeEncoding::Serialised(serialised_data_map),
                ))
            };

            pack(client, value)
        })
        .into_box()
}

/// Get the raw bytes from `ImmutableData` created via `create()` function in
/// this module.
pub fn extract_value<T: 'static>(
    client: &Client<T>,
    data: &ImmutableData,
    decryption_key: Option<shared_secretbox::Key>,
) -> Box<CoreFuture<Vec<u8>>> {
    let client = client.clone();

    unpack(client.clone(), data)
        .and_then(move |value| {
            let data_map = if let Some(key) = decryption_key {
                let plain_text = utils::symmetric_decrypt(&value, &key)?;
                deserialise(&plain_text)?
            } else {
                deserialise(&value)?
            };

            let storage = SelfEncryptionStorage::new(client);
            Ok(SelfEncryptor::new(storage, data_map)?)
        })
        .and_then(|self_encryptor| {
            let length = self_encryptor.len();
            self_encryptor.read(0, length).map_err(From::from)
        })
        .into_box()
}

/// Get immutable data from the network and extract its value, decrypting it in
/// the process (if keys provided).  This is a convenience function combining
/// `get` and `extract_value` into one function.
pub fn get_value<T: 'static>(
    client: &Client<T>,
    name: &XorName,
    decryption_key: Option<shared_secretbox::Key>,
) -> Box<CoreFuture<Vec<u8>>> {
    let client2 = client.clone();
    client
        .get_idata(*name)
        .and_then(move |data| extract_value(&client2, &data, decryption_key))
        .into_box()
}

// TODO: consider rewriting these two function to not use recursion.

fn pack<T: 'static>(client: Client<T>, value: Vec<u8>) -> Box<CoreFuture<ImmutableData>> {
    let data = ImmutableData::new(value);
    let serialised_data = fry!(serialise(&data));

    if !data.validate_size() {
        let storage = SelfEncryptionStorage::new(client.clone());
        let self_encryptor = fry!(SelfEncryptor::new(storage, DataMap::None));
        self_encryptor
            .write(&serialised_data, 0)
            .and_then(move |_| self_encryptor.close())
            .map_err(From::from)
            .and_then(move |(data_map, _)| {
                let value = fry!(serialise(&DataTypeEncoding::DataMap(data_map)));
                pack(client, value)
            })
            .into_box()
    } else {
        ok!(data)
    }
}

fn unpack<T: 'static>(client: Client<T>, data: &ImmutableData) -> Box<CoreFuture<Vec<u8>>> {
    match fry!(deserialise(data.value())) {
        DataTypeEncoding::Serialised(value) => ok!(value),
        DataTypeEncoding::DataMap(data_map) => {
            let storage = SelfEncryptionStorage::new(client.clone());
            let self_encryptor = fry!(SelfEncryptor::new(storage, data_map));
            let length = self_encryptor.len();
            self_encryptor
                .read(0, length)
                .map_err(From::from)
                .and_then(move |serialised_data| {
                    let data = fry!(deserialise(&serialised_data));
                    unpack(client, &data)
                })
                .into_box()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::Future;
    use utils;
    use utils::test_utils::{finish, random_client};

    #[test]
    fn create_and_retrieve_1kb() {
        create_and_retrieve(1024)
    }

    #[test]
    fn create_and_retrieve_1mb() {
        create_and_retrieve(1024 * 1024)
    }

    #[test]
    fn create_and_retrieve_2mb() {
        create_and_retrieve(2 * 1024 * 1024)
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn create_and_retrieve_10mb() {
        create_and_retrieve(10 * 1024 * 1024)
    }

    fn create_and_retrieve(size: usize) {
        let value = unwrap!(utils::generate_random_vector(size));

        // Unencrypted
        {
            let value_before = value.clone();

            random_client(move |client| {
                let client2 = client.clone();
                let client3 = client.clone();

                create(client, &value_before.clone(), None)
                    .then(move |res| {
                        let data_before = unwrap!(res);
                        let data_name = *data_before.name();
                        client2.put_idata(data_before).map(move |_| data_name)
                    })
                    .then(move |res| {
                        let data_name = unwrap!(res);
                        get_value(&client3, &data_name, None)
                    })
                    .then(move |res| {
                        let value_after = unwrap!(res);
                        assert_eq!(value_after, value_before);
                        finish()
                    })
            })
        }

        // Encrypted
        {
            let value_before = value.clone();
            let key = shared_secretbox::gen_key();

            random_client(move |client| {
                let client2 = client.clone();
                let client3 = client.clone();

                create(client, &value_before.clone(), Some(key.clone()))
                    .then(move |res| {
                        let data_before = unwrap!(res);
                        let data_name = *data_before.name();
                        client2.put_idata(data_before).map(move |_| data_name)
                    })
                    .then(move |res| {
                        let data_name = unwrap!(res);
                        get_value(&client3, &data_name, Some(key))
                    })
                    .then(move |res| {
                        let value_after = unwrap!(res);
                        assert_eq!(value_after, value_before);
                        finish()
                    })
            })
        }

        // Put unencrypted Retrieve encrypted - Should fail
        {
            let value = value.clone();
            let key = shared_secretbox::gen_key();

            random_client(move |client| {
                let client2 = client.clone();
                let client3 = client.clone();

                create(client, &value, None)
                    .then(move |res| {
                        let data = unwrap!(res);
                        let data_name = *data.name();
                        client2.put_idata(data).map(move |_| data_name)
                    })
                    .then(move |res| {
                        let data_name = unwrap!(res);
                        get_value(&client3, &data_name, Some(key))
                    })
                    .then(|res| {
                        assert!(res.is_err());
                        finish()
                    })
            })
        }

        // Put encrypted Retrieve unencrypted - Should fail
        {
            let value = value.clone();
            let key = shared_secretbox::gen_key();

            random_client(move |client| {
                let client2 = client.clone();
                let client3 = client.clone();

                create(client, &value, Some(key))
                    .then(move |res| {
                        let data = unwrap!(res);
                        let data_name = *data.name();
                        client2.put_idata(data).map(move |_| data_name)
                    })
                    .then(move |res| {
                        let data_name = unwrap!(res);
                        get_value(&client3, &data_name, None)
                    })
                    .then(|res| {
                        assert!(res.is_err());
                        finish()
                    })

            })
        }
    }
}
