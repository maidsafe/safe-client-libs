// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::client::Client;
use crate::crypto::shared_secretbox;
use crate::self_encryption_storage::{
    SEStorageError, SelfEncryptionStorage, SelfEncryptionStorageDryRun,
};
use crate::utils;
// use crate::{fry, ok};
use crate::{CoreError};

use bincode::{deserialize, serialize};
use futures::Future;
use log::trace;
use std::sync::Arc;
use safe_nd::{IData, IDataAddress, PubImmutableData, UnpubImmutableData};
use self_encryption::{DataMap, SelfEncryptor, Storage};
use serde::{Deserialize, Serialize};
use async_recursion::async_recursion;

use futures::future::{BoxFuture, FutureExt};

#[derive(Serialize, Deserialize)]
enum DataTypeEncoding {
    Serialised(Vec<u8>),
    DataMap(DataMap),
}

/// Create and obtain immutable data out of the given raw bytes. This will encrypt the right content
/// if the keys are provided and will ensure the maximum immutable data chunk size is respected.
pub async fn create(
    client: &(impl Client + Sync + Send),
    value: &[u8],
    published: bool,
    encryption_key: Option<shared_secretbox::Key>,
) -> Result<IData, CoreError> {
    trace!("Creating conformant ImmutableData.");
    let client = client.clone();
    let se_storage = SelfEncryptionStorage::new(client.clone(), published);
    write_with_self_encryptor(se_storage, &client, value, published, encryption_key).await
}

/// Create and obtain immutable data out of the given raw bytes. This will encrypt the right content
/// if the keys are provided and will ensure the maximum immutable data chunk size is respected.
/// The DataMap is generated but the chunks are not uploaded to the network.
pub async fn gen_data_map(
    client: &(impl Client + Sync + Send),
    value: &[u8],
    published: bool,
    encryption_key: Option<shared_secretbox::Key>,
) -> Result<IData, CoreError> {
    trace!("Creating conformant ImmutableData data map.");
    let client = client.clone();
    let se_storage = SelfEncryptionStorageDryRun::new(client.clone(), published);
    write_with_self_encryptor(se_storage, &client, value, published, encryption_key).await
}

/// Get the raw bytes from `ImmutableData` created via the `create` function in this module.
pub async fn extract_value(
    client: &(impl Client + Sync + Send),
    data: IData,
    position: Option<u64>,
    len: Option<u64>,
    decryption_key: Option<shared_secretbox::Key>,
) -> Result<Vec<u8>, CoreError> {
    let published = data.is_pub();
    let se_storage = SelfEncryptionStorage::new(client.clone(), published);
    let value = unpack(se_storage.clone(), &client.clone(), data).await?;

        // .and_then(move |value| {
            let data_map = if let Some(key) = decryption_key {
                let plain_text = utils::symmetric_decrypt(&value, &key)?;
                deserialize(&plain_text)?
            } else {
                deserialize(&value)?
            };

        let self_encryptor = SelfEncryptor::new(se_storage, data_map)?;
        // })
        // .and_then(move |self_encryptor| {
            let length = match len {
                None => self_encryptor.len(),
                Some(request_length) => request_length,
            };

            let read_position = match position {
                None => 0,
                Some(pos) => pos,
            };
            match self_encryptor
                .read(read_position, length).await {
                    Ok(data) => Ok(data), 
                    Err(error) => Err(CoreError::from(error))
                }
                // .map_err(From::from)
        // })
        // .into_box()
}

/// Get immutable data from the network and extract its value, decrypting it in the process (if keys
/// provided). This combines `get_idata` in `Client` and `extract_value` in this module into one
/// function.
pub async fn get_value(
    client: &(impl Client + Sync + Send),
    address: IDataAddress,
    position: Option<u64>,
    len: Option<u64>,
    decryption_key: Option<shared_secretbox::Key>,
) -> Result<Vec<u8>, CoreError> {
    let client2 = client.clone();
    let data = client
        .get_idata(address).await?;
    extract_value(&client2, data, position, len, decryption_key).await
}

async fn write_with_self_encryptor<S>(
    se_storage: S,
    client: &(impl Client + Sync + Send),
    value: &[u8],
    published: bool,
    encryption_key: Option<shared_secretbox::Key>,
) -> Result<IData, CoreError>
where
    S: Storage<Error = SEStorageError> + Clone + Send + Sync + 'static,
{
    let self_encryptor = SelfEncryptor::new(se_storage.clone(), DataMap::None)?;
    self_encryptor
        .write(value, 0).await?;

        let ( data_map, _ ) = self_encryptor.close().await?;

        // .and_then(move |_| self_encryptor.close())
        // .map_err(From::from)
        // .and_then(move |(data_map, _)| {
        let serialised_data_map = serialize(&data_map)?;

        let value = if let Some(key) = encryption_key {
            let cipher_text = utils::symmetric_encrypt(&serialised_data_map, &key, None)?;
            serialize(&DataTypeEncoding::Serialised(cipher_text))?
        } else {
            serialize(&DataTypeEncoding::Serialised(
                serialised_data_map
            ),)?
        };

        // let arc
        //  = 
         pack(se_storage, client, value, published).await
        // Arc::into_raw( arc)


        // })
        // .into_box()
}

// TODO: consider rewriting these two function to not use recursion.

#[async_recursion]
async fn pack<S>(
    se_storage: S,
    client: &(impl Client + Sync + Send),
    value: Vec<u8>,
    published: bool,
) -> Result<IData, CoreError>
where
    S: Storage<Error = SEStorageError> + Clone + 'static + Sync + Send,
{
    let data: IData = if published {
        PubImmutableData::new(value).into()
    } else {
        UnpubImmutableData::new(value, client.public_key()).into()
    };
    let serialised_data = match serialize(&data) {
        Ok(the_data) => the_data, 
        Err(error) => {
            // return async move{

            //     Arc::new(Err(CoreError::from(error) ))
            // }.await
            return Err(CoreError::from(error) ) 
            // error.await
        }
            // return Box::new(error)
    };

    if data.validate_size() {

           Ok(data)

    } else {
            let self_encryptor = SelfEncryptor::new(se_storage.clone(), DataMap::None)?;
            
            // TODO make read/write properly x-thread compatible in self_encrypt
            let _ = self_encryptor
                .write(&serialised_data, 0).await?;

            let ( data_map, _ ) = self_encryptor.close().await?;
    
                // .and_then(move |_| self_encryptor.close())
                // .map_err(From::from)
                // .and_then(move |(data_map, _)| {
                let value = serialize(&DataTypeEncoding::DataMap(data_map))?;

                // this is an Arc
                pack(se_storage, client, value, published).await
                // })
                // .into_box()

        // .boxed()
    }
}


#[async_recursion]
async fn unpack<S>(se_storage: S, client: &(impl Client + Sync + Send)
, data: IData) -> Result<Vec<u8>, CoreError>
where
    S: Storage<Error = SEStorageError> + Clone + 'static + Send + Sync,
{
    match deserialize(data.value())? {
        DataTypeEncoding::Serialised(value) => Ok(value) ,
        DataTypeEncoding::DataMap(data_map) => {
            let self_encryptor = SelfEncryptor::new(se_storage.clone(), data_map)?;
            let length = self_encryptor.len();
           
            let serialised_data = self_encryptor
                    .read(0, length).await?;

            //     // .map_err(From::from)
            //     // .and_then(move |&serialised_data| {
                    let data = deserialize(&serialised_data)?;
                    unpack(se_storage, client, data).await
                // let vec = Vec::new();

                // Ok(vec)
                // })
                // .into_box()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::CoreError;
    use futures::Future;
    use safe_nd::Error as SndError;
    use unwrap::unwrap;
    use utils;
    use utils::test_utils::{finish, random_client};

    // Test creating and retrieving a 1kb idata.
    #[test]
    fn create_and_retrieve_1kb() {
        create_and_retrieve(1024)
    }

    // Test creating and retrieving a 1mb idata.
    #[test]
    fn create_and_retrieve_1mb() {
        create_and_retrieve(1024 * 1024)
    }

    #[test]
    fn create_and_retrieve_index_based() {
        create_and_index_based_retrieve(1024);
    }

    // Test creating and retrieving a 2mb idata.
    #[test]
    fn create_and_retrieve_2mb() {
        create_and_retrieve(2 * 1024 * 1024)
    }

    // Test creating and retrieving a 10mb idata.
    #[cfg(not(debug_assertions))]
    #[test]
    fn create_and_retrieve_10mb() {
        create_and_retrieve(10 * 1024 * 1024)
    }

    fn create_and_index_based_retrieve(size: usize) {
        let value = unwrap!(utils::generate_random_vector(size));
        {
            // Read first half
            random_client(move |client| {
                let client2 = client.clone();
                let client3 = client.clone();
                create(client, &value, true, None)
                    .then(move |res| {
                        let data = unwrap!(res);
                        let address = *data.address();
                        client2.put_idata(data).map(move |_| address)
                    })
                    .then(move |res| {
                        let address = unwrap!(res);
                        get_value(&client3, address, None, Some(size as u64 / 2), None)
                    })
                    .then(move |res| {
                        let fetched_value = unwrap!(res);
                        assert_eq!(fetched_value, value[0..size / 2].to_vec());
                        finish()
                    })
            });
        }

        let value2 = unwrap!(utils::generate_random_vector(size));
        {
            // Read Second half
            random_client(move |client| {
                let client2 = client.clone();
                let client3 = client.clone();
                create(client, &value2, true, None)
                    .then(move |res| {
                        let data = unwrap!(res);
                        let address = *data.address();
                        client2.put_idata(data).map(move |_| address)
                    })
                    .then(move |res| {
                        let address = unwrap!(res);
                        get_value(
                            &client3,
                            address,
                            Some(size as u64 / 2),
                            Some(size as u64 / 2),
                            None,
                        )
                    })
                    .then(move |res| {
                        let fetched_value = unwrap!(res);
                        assert_eq!(fetched_value, value2[size / 2..size].to_vec());
                        finish()
                    })
            })
        }
    }

    fn create_and_retrieve(size: usize) {
        // Published and unencrypted
        gen_data_then_map_create_and_retrieve(size, true, None);

        // Unpublished and unencrypted
        gen_data_then_map_create_and_retrieve(size, false, None);

        // Published and encrypted
        {
            let key = shared_secretbox::gen_key();
            gen_data_then_map_create_and_retrieve(size, true, Some(key));
        }

        // Unpublished and encrypted
        {
            let key = shared_secretbox::gen_key();
            gen_data_then_map_create_and_retrieve(size, false, Some(key));
        }

        let value = unwrap!(utils::generate_random_vector(size));

        // Put unencrypted Retrieve encrypted - Should fail
        {
            let value = value.clone();
            let key = shared_secretbox::gen_key();

            random_client(move |client| {
                let client2 = client.clone();
                let client3 = client.clone();

                create(client, &value, true, None)
                    .then(move |res| {
                        let data = unwrap!(res);
                        let address = *data.address();
                        client2.put_idata(data).map(move |_| address)
                    })
                    .then(move |res| {
                        let address = unwrap!(res);
                        get_value(&client3, address, None, None, Some(key))
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

                create(client, &value, true, Some(key))
                    .then(move |res| {
                        let data = unwrap!(res);
                        let address = *data.address();
                        client2.put_idata(data).map(move |_| address)
                    })
                    .then(move |res| {
                        let address = unwrap!(res);
                        get_value(&client3, address, None, None, None)
                    })
                    .then(|res| {
                        assert!(res.is_err());
                        finish()
                    })
            })
        }

        // Put published Retrieve unpublished - Should fail
        {
            let value = value.clone();

            random_client(move |client| {
                let client2 = client.clone();
                let client3 = client.clone();

                create(client, &value, true, None)
                    .then(move |res| {
                        let data = unwrap!(res);
                        let data_name = *data.name();
                        client2.put_idata(data).map(move |_| data_name)
                    })
                    .then(move |res| {
                        let data_name = unwrap!(res);
                        let address = IDataAddress::Unpub(data_name);
                        get_value(&client3, address, None, None, None)
                    })
                    .then(|res| {
                        assert!(res.is_err());
                        finish()
                    })
            })
        }

        // Put unpublished Retrieve published - Should fail
        {
            random_client(move |client| {
                let client2 = client.clone();
                let client3 = client.clone();

                create(client, &value, false, None)
                    .then(move |res| {
                        let data = unwrap!(res);
                        let data_name = *data.name();
                        client2.put_idata(data).map(move |_| data_name)
                    })
                    .then(move |res| {
                        let data_name = unwrap!(res);
                        let address = IDataAddress::Pub(data_name);
                        get_value(&client3, address, None, None, None)
                    })
                    .then(|res| {
                        assert!(res.is_err());
                        finish()
                    })
            })
        }
    }

    fn gen_data_then_map_create_and_retrieve(
        size: usize,
        published: bool,
        key: Option<shared_secretbox::Key>,
    ) {
        let value = unwrap!(utils::generate_random_vector(size));
        let value_before = value.clone();
        let value_before2 = value.clone();

        random_client(move |client| {
            let client2 = client.clone();
            let client3 = client.clone();
            let client4 = client.clone();
            let client5 = client.clone();
            let key2 = key.clone();
            let key3 = key.clone();

            // gen address without putting to the network (published and unencrypted)
            gen_data_map(client, &value.clone(), published, key2.clone())
                .then(move |res| {
                    let data = unwrap!(res);
                    let address_before = *data.address();
                    // attempt to retrieve it with generated address (it should error)
                    get_value(&client2, address_before, None, None, key2.clone())
                        .then(move |res| {
                            match res {
                                Err(err) => {
                                    if let CoreError::DataError(SndError::NoSuchData) = err {
                                        // let's put it to the network (published and unencrypted)
                                        create(&client3, &value_before2.clone(), published, key3)
                                    } else {
                                        panic!("Unexpected error when ImmutableData retrieved using address generated by gen_data_map");
                                    }
                                }
                                Ok(_) => panic!("ImmutableData unexpectedly retrieved using address generated by gen_data_map"),
                            }
                        })
                        .then(move |res| {
                            let data_map_before = unwrap!(res);
                            let address_after = *data_map_before.address();
                            if key2.is_none() {
                                // the addresses generated without/with putting to the network should match
                                assert_eq!(address_after, address_before);
                            } else {
                                // in this case the addresses generated without/with putting to the network
                                // don't match since the encryption uses a random nonce
                                // which changes the address of the chunks
                                assert_ne!(address_after, address_before);
                            }
                            client4.put_idata(data_map_before).map(move |_| address_after)
                        })
                })
                .then(move |res| {
                    let address = unwrap!(res);
                    // now that it was put to the network we should be able to retrieve it
                    get_value(&client5, address, None, None, key)
                })
                .then(move |res| {
                    let value_after = unwrap!(res);
                    // then the content should be what we put
                    assert_eq!(value_after, value_before);
                    finish()
                })
        })
    }
}
