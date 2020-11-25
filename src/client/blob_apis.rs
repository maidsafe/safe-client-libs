// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::errors::ClientError;
use crate::Client;
use bincode::{deserialize, serialize};
use log::{info, trace};
use serde::{Deserialize, Serialize};

use crate::client::blob_storage::{BlobStorage, BlobStorageDryRun};

use self_encryption::{DataMap, SelfEncryptor};
use sn_data_types::{
    Blob, BlobAddress, BlobRead, BlobWrite, DataCmd, DataQuery, PrivateBlob, PublicBlob, PublicKey,
    Query, QueryResponse,
};

#[derive(Serialize, Deserialize)]
enum DataTypeEncoding {
    Serialised(Vec<u8>),
    DataMap(DataMap),
}

impl Client {
    /// Get a data blob from the network. If the data exists locally in the cache then it will be
    /// immediately returned without making an actual network request.
    ///
    /// # Examples
    ///
    /// Get data
    ///
    /// ```no_run
    /// # extern crate tokio; use sn_client::ClientError;
    /// use sn_client::Client;
    /// use sn_data_types::BlobAddress;
    /// use xor_name::XorName;
    /// # #[tokio::main] async fn main() { let _: Result<(), ClientError> = futures::executor::block_on( async {
    /// let target_blob = BlobAddress::Public(XorName::random());
    /// let mut client = Client::new(None, None).await?;
    ///
    /// // grab the random blob from the network
    /// let _blob = client.get_blob(target_blob, None, None).await?;
    /// # Ok(())} );}
    /// ```
    pub async fn get_blob(
        &mut self,
        address: BlobAddress,
        position: Option<u64>,
        len: Option<u64>,
    ) -> Result<Blob, ClientError>
    where
        Self: Sized,
    {
        trace!("Fetch Blob");

        if let Some(data) = self.blob_cache.lock().await.get_mut(&address) {
            trace!("Blob found in cache.");
            return Ok(data.clone());
        }

        let res = self
            .send_query(Query::Data(DataQuery::Blob(BlobRead::Get(address))))
            .await?;
        let data: Blob = match res {
            QueryResponse::GetBlob(res) => res.map_err(ClientError::from),
            _ => return Err(ClientError::ReceivedUnexpectedEvent),
        }?;

        // Put to cache
        let _ = self
            .blob_cache
            .lock()
            .await
            .put(*data.address(), data.clone());

        let is_published = data.is_pub();

        // parse data map and get resulting blob
        let raw_data = self.extract_blob_data(data, position, len).await?;

        let final_blob = if is_published {
            Blob::Public(PublicBlob::new(raw_data))
        } else {
            Blob::Private(PrivateBlob::new(raw_data, self.public_key().await)?)
        };

        Ok(final_blob)
    }

    /// Store a new blob object on the network.
    ///
    /// This performs self encrypt on the data itself and returns the final blob for further use,
    /// as well as all necessary payment validation and checks against the client's AT2 actor.
    ///
    /// # Examples
    ///
    /// Store data
    ///
    /// ```no_run
    /// # extern crate tokio; use sn_client::ClientError;
    /// use sn_client::Client;
    /// use sn_data_types::{Blob, Money, PublicBlob};
    /// use std::str::FromStr;
    /// # #[tokio::main] async fn main() { let _: Result<(), ClientError> = futures::executor::block_on( async {
    /// // Let's use an existing client, with a pre-existing balance to be used for write payments.
    /// let mut client = Client::new(None, None).await?;
    /// # let initial_balance = Money::from_str("100")?; client.trigger_simulated_farming_payout(initial_balance).await?;
    /// let data = b"some data".to_vec();
    /// let blob_for_storage = Blob::Public(PublicBlob::new(data));
    /// // grab the random blob from the network
    /// let blob = client.store_blob(blob_for_storage).await?;
    ///
    /// println!( "{:?}",blob.value() ); // prints "some data"
    /// # let balance_after_write = client.get_local_balance().await; assert_ne!(initial_balance, balance_after_write); Ok(()) } ); }
    /// ```
    pub async fn store_blob(&mut self, the_blob: Blob) -> Result<Blob, ClientError> {
        info!("Storing blob at given address: {:?}", the_blob.address());

        let is_pub = the_blob.is_pub();
        let pub_key = if is_pub {
            self.public_key().await
        } else {
            *the_blob
                .owner()
                .ok_or_else(|| ClientError::DataError(sn_data_types::Error::InvalidOwners))?
        };

        let data_map = self.generate_data_map(&the_blob).await?;

        let serialised_data_map = serialize(&data_map)?;
        let data_to_write_to_network =
            serialize(&DataTypeEncoding::Serialised(serialised_data_map))
                .map_err(ClientError::from)?;

        let blob_to_write = self.pack(pub_key, data_to_write_to_network, is_pub).await?;

        let cmd = DataCmd::Blob(BlobWrite::New(blob_to_write.clone()));

        self.pay_and_send_data_command(cmd).await?;

        Ok(blob_to_write)
    }

    /// Delete blob can only be performed on Private Blobs. But on those private blobs this will remove the data
    /// from the network.
    ///
    /// # Examples
    ///
    /// Remove data
    ///
    /// ```no_run
    /// # extern crate tokio; use sn_client::ClientError;
    /// use sn_client::Client;
    /// use sn_data_types::{Money, Blob, PrivateBlob};
    /// use std::str::FromStr;
    /// # #[tokio::main] async fn main() { let _: Result<(), ClientError> = futures::executor::block_on( async {
    ///
    /// // Let's use an existing client, with a pre-existing balance to be used for write payments.
    /// let mut client = Client::new(None, None).await?;
    /// # let initial_balance = Money::from_str("100")?; client.trigger_simulated_farming_payout(initial_balance).await?;
    /// let data = b"some private data".to_vec();
    /// let some_blob_for_storage = Blob::Private(PrivateBlob::new(data, client.public_key().await)?);
    /// let blob = client.store_blob(some_blob_for_storage).await?;
    ///
    /// let _ = client.delete_blob(*blob.address()).await?;
    ///
    /// // Now when we attempt to retrieve the blob, we should get an error
    ///
    /// match client.get_blob(*blob.address(), None, None).await {
    ///     Err(error) => eprintln!("Expected error getting blob {:?}", error),
    ///     _ => return Err(ClientError::from("Should not have been able to retrieve this blob"))
    /// };
    /// #  Ok(())} );}
    /// ```
    pub async fn delete_blob(&mut self, address: BlobAddress) -> Result<(), ClientError> {
        info!("Deleting blob at given address: {:?}", address);

        let cmd = DataCmd::Blob(BlobWrite::DeletePrivate(address));

        self.pay_and_send_data_command(cmd).await?;
        info!("Dropping from cache");
        let _ =
            self.blob_cache.lock().await.pop(&address).ok_or_else(|| {
                ClientError::Unexpected("Couldn't pop Blob from cache".to_string())
            })?;
        info!("Dropped from cache");
        Ok(())
    }

    /// Uses self_encryption to generated an encrypted blob serialised data map, without writing to the network
    pub async fn generate_data_map(&mut self, the_blob: &Blob) -> Result<DataMap, ClientError> {
        let blob_storage = BlobStorageDryRun::new(self.clone(), the_blob.is_pub());

        let self_encryptor = SelfEncryptor::new(blob_storage, DataMap::None)
            .map_err(|e| ClientError::from(format!("Self encryption error: {:?}", e)))?;
        self_encryptor
            .write(the_blob.value(), 0)
            .await
            .map_err(|e| ClientError::from(format!("Self encryption error: {:?}", e)))?;
        let (data_map, _) = self_encryptor
            .close()
            .await
            .map_err(|e| ClientError::from(format!("Self encryption error: {:?}", e)))?;

        Ok(data_map)
    }

    // --------------------------------------------
    // ---------- Private helpers -----------------
    // --------------------------------------------

    async fn extract_blob_data(
        &mut self,
        data: Blob,
        position: Option<u64>,
        len: Option<u64>,
    ) -> Result<Vec<u8>, ClientError> {
        let published = data.is_pub();
        let _blob_storage = BlobStorage::new(self.clone(), published);
        let value = self.unpack(data).await?;

        let data_map = deserialize(&value)?;

        let blob_storage = BlobStorage::new(self.clone(), published);
        let self_encryptor = SelfEncryptor::new(blob_storage, data_map)
            .map_err(|e| ClientError::from(format!("Self encryption error: {:?}", e)))?;

        let length = match len {
            None => self_encryptor.len().await,
            Some(request_length) => request_length,
        };

        let read_position = match position {
            None => 0,
            Some(pos) => pos,
        };

        match self_encryptor.read(read_position, length).await {
            Ok(data) => Ok(data),
            Err(error) => Err(ClientError::from(format!("{:?}", error))),
        }
    }

    /// Write Blob to the network.
    async fn pack(
        &mut self,
        public_key: PublicKey,
        mut value: Vec<u8>,
        published: bool,
    ) -> Result<Blob, ClientError> {
        // This blob storage is used to perform write operations to the network, via self encryptor
        let blob_storage = BlobStorage::new(self.clone(), published);

        loop {
            let data: Blob = if published {
                PublicBlob::new(value).into()
            } else {
                PrivateBlob::new(value, public_key)?.into()
            };

            let serialised_data = serialize(&data)?;

            if data.validate_size() {
                return Ok(data);
            }

            let self_encryptor = SelfEncryptor::new(blob_storage.clone(), DataMap::None)
                .map_err(|e| ClientError::from(format!("Self encryption error: {:?}", e)))?;

            self_encryptor
                .write(&serialised_data, 0)
                .await
                .map_err(|e| ClientError::from(format!("Self encryption error: {:?}", e)))?;

            let (data_map, _) = self_encryptor
                .close()
                .await
                .map_err(|e| ClientError::from(format!("Self encryption error: {:?}", e)))?;

            value = serialize(&DataTypeEncoding::DataMap(data_map))?;
        }
    }

    async fn unpack(&mut self, mut data: Blob) -> Result<Vec<u8>, ClientError> {
        loop {
            match deserialize(data.value())? {
                DataTypeEncoding::Serialised(value) => return Ok(value),
                DataTypeEncoding::DataMap(data_map) => {
                    let blob_storage = BlobStorage::new(self.clone(), data.is_pub());
                    let self_encryptor =
                        SelfEncryptor::new(blob_storage, data_map).map_err(|e| {
                            ClientError::from(format!("Self encryption error: {:?}", e))
                        })?;
                    let length = self_encryptor.len().await;

                    let serialised_data = self_encryptor.read(0, length).await.map_err(|e| {
                        ClientError::from(format!("Self encryption error: {:?}", e))
                    })?;

                    data = deserialize(&serialised_data)?;
                }
            }
        }
    }
}

#[allow(missing_docs)]
#[cfg(any(test, feature = "simulated-payouts"))]
pub mod exported_tests {
    use super::*;
    use crate::utils::{
        generate_random_vector,
        test_utils::{calculate_new_balance, gen_bls_keypair},
    };
    use sn_data_types::{Error as SndError, Money, PrivateBlob, PublicBlob};
    use std::str::FromStr;
    use unwrap::unwrap;

    // Test putting and getting pub blob.
    pub async fn pub_blob_test() -> Result<(), ClientError> {
        let mut client = Client::new(None, None).await?;
        // The `Client::new(None)` initializes the client with 10 money.
        let start_bal = unwrap!(Money::from_str("10"));

        let value = generate_random_vector::<u8>(10);
        let data = Blob::Public(PublicBlob::new(value.clone()));
        let address = *data.address();
        let pk = gen_bls_keypair().public_key();

        let test_data = Blob::Private(PrivateBlob::new(value, pk)?);
        let res = client
            // Get non-existent blob
            .get_blob(address, None, None)
            .await;
        match res {
            Ok(data) => panic!("Pub blob should not exist yet: {:?}", data),
            Err(ClientError::DataError(SndError::NoSuchData)) => (),
            Err(e) => panic!("Unexpected: {:?}", e),
        }
        // Put blob
        let stored_data = client.store_blob(data.clone()).await?;

        // Assert that the blob was written
        let mut fetched_data = client.get_blob(*stored_data.address(), None, None).await;
        while fetched_data.is_err() {
            fetched_data = client.get_blob(*stored_data.address(), None, None).await;
        }

        assert_eq!(*fetched_data?.address(), address);

        // Try writing a PrivateBlob with a different owner
        let res = client.store_blob(test_data.clone()).await?;
        client
            .expect_error(ClientError::DataError(SndError::InvalidOwners))
            .await;

        Ok(())
    }

    // Test putting, getting, and deleting unpub blob.
    pub async fn unpub_blob_test() -> Result<(), ClientError> {
        // The `Client::new(None)` initializes the client with 10 money.
        // let start_bal = unwrap!(Money::from_str("10"));

        let mut client = Client::new(None, None).await?;

        let pk = client.public_key().await;

        let value = generate_random_vector::<u8>(10);
        let data = Blob::Private(PrivateBlob::new(value.clone(), pk)?);
        let data2 = data.clone();
        let data3 = data.clone();
        let address = *data.address();
        assert_eq!(address, *data2.address());

        let pub_data = Blob::Public(PublicBlob::new(value));

        let res = client
            // Get nonexistent blob
            .get_blob(address, None, None)
            .await;

        match res {
            Ok(_) => panic!("Private blob should not exist yet"),
            Err(ClientError::DataError(SndError::NoSuchData)) => (),
            Err(e) => panic!("Unexpected: {:?}", e),
        }

        println!("STORING UNPUB BLOB");
        // Put blob
        let data = client.store_blob(data.clone()).await?;
        let address = *data.address();

        println!("FETCHING UNPUB BLOB TO ASSERT");
        // Assert that the blob is stored.
        let mut res = client.get_blob(address, None, None).await;
        while res.is_err() {
            println!("LOOP1");
            res = client.get_blob(address, None, None).await;
        }
        println!("STORED UNPUB BLOB");

        // Test putting unpub blob with the same value.
        // Should conflict because duplication does .await?;not apply to unpublished data.
        println!("STORING SAME UNPUB BLOB AGAIN");
        let _ = client.store_blob(data2.clone()).await;
        client
            .expect_error(ClientError::DataError(SndError::DataExists))
            .await;
        println!("GOT ERROR: DATA EXISTS");

        // let balance = client.get_balance().await?;
        // mutation_count of 3 as even our failed op counts as a mutation
        // let expected_bal = calculate_new_balance(start_bal, Some(3), None);
        // assert_eq!(balance, expected_bal);

        println!("STORING SAME as PUB BLOB");
        // Test putting published blob with the same value. Should not conflict.
        let pub_blob = client.store_blob(pub_data.clone()).await?;
        println!("FETCHING PUB BLOB TO ASSERT");

        // Fetch blob
        // Assert that the blob is stored.
        let mut fetched_data = client.get_blob(*pub_blob.address(), None, None).await;
        while fetched_data.is_err() {
            println!("Loop2");
            fetched_data = client.get_blob(*pub_blob.address(), None, None).await;
        }

        assert_eq!(*fetched_data?.address(), *pub_data.address());
        println!("DELETING UNPUB BLOB");
        // Delete blob
        client.delete_blob(address).await?;
        println!("ASSERTING DELETE UNPUB BLOB");
        // Make sure blob was deleted
        let mut fetched_data = client.get_blob(address, None, None).await;
        while fetched_data.is_ok() {
            println!("Loop3");
            fetched_data = client.get_blob(address, None, None).await;
        }

        // Test putting unpub blob with the same value again. Should not conflict.
        let _ = client.store_blob(data3.clone()).await?;
        Ok(())
    }

    pub async fn blob_deletions_should_cost_put_price() -> Result<(), ClientError> {
        let mut client = Client::new(None, None).await?;

        let blob = Blob::Private(PrivateBlob::new(
            generate_random_vector::<u8>(10),
            client.public_key().await,
        )?);
        let blob_address = *blob.address();
        let _ = client.store_blob(blob).await?;

        let balance_before_delete = client.get_balance().await?;
        client.delete_blob(blob_address).await?;
        let new_balance = client.get_balance().await?;

        // make sure we have _some_ balance
        assert_ne!(balance_before_delete, Money::from_str("0")?);
        assert_ne!(balance_before_delete, new_balance);

        Ok(())
    }

    // Test creating and retrieving a 1kb blob.
    pub async fn create_and_retrieve_1kb_pub_unencrypted() -> Result<(), ClientError> {
        let size = 1024;

        gen_data_then_create_and_retrieve(size, true).await?;

        Ok(())
    }

    pub async fn create_and_retrieve_1kb_private_unencrypted() -> Result<(), ClientError> {
        let size = 1024;

        gen_data_then_create_and_retrieve(size, false).await?;
        Ok(())
    }

    pub async fn create_and_retrieve_1kb_put_pub_retrieve_private() -> Result<(), ClientError> {
        let size = 1024;
        let value = Blob::Public(PublicBlob::new(generate_random_vector(size)));

        let mut client = Client::new(None, None).await?;
        let data = client.store_blob(value).await?;
        let data_name = *data.name();
        let _ = client.store_blob(data).await?;

        let address = BlobAddress::Private(data_name);
        let res = client.get_blob(address, None, None).await;
        assert!(res.is_err());

        Ok(())
    }

    pub async fn create_and_retrieve_1kb_put_private_retrieve_pub() -> Result<(), ClientError> {
        let size = 1024;

        let value = Blob::Public(PublicBlob::new(generate_random_vector(size)));

        let mut client = Client::new(None, None).await?;

        let data = client.store_blob(value).await?;
        let data_name = *data.name();
        let _ = client.store_blob(data).await?;

        let address = BlobAddress::Public(data_name);
        let res = client.get_blob(address, None, None).await;
        assert!(res.is_err());

        Ok(())
    }

    // ----------------------------------------------------------------
    // 10mb (ie. more than 1 chunk)
    // ----------------------------------------------------------------

    // Test creating and retrieving a 1kb blob.
    pub async fn create_and_retrieve_10mb_pub_unencrypted() -> Result<(), ClientError> {
        let size = 1024 * 1024 * 10;

        gen_data_then_create_and_retrieve(size, true).await?;

        Ok(())
    }

    pub async fn create_and_retrieve_10mb_private_unencrypted() -> Result<(), ClientError> {
        let size = 1024 * 1024 * 10;

        gen_data_then_create_and_retrieve(size, false).await?;
        Ok(())
    }

    pub async fn create_and_retrieve_10mb_private_encrypted() -> Result<(), ClientError> {
        let size = 1024 * 1024 * 10;
        gen_data_then_create_and_retrieve(size, false).await?;

        Ok(())
    }

    pub async fn create_and_retrieve_10mb_pub_encrypted() -> Result<(), ClientError> {
        let size = 1024 * 1024 * 10;
        gen_data_then_create_and_retrieve(size, true).await?;
        Ok(())
    }

    pub async fn create_and_retrieve_10mb_unencrypted_put_retrieve_encrypted(
    ) -> Result<(), ClientError> {
        let size = 1024 * 1024 * 10;
        let value = Blob::Public(PublicBlob::new(generate_random_vector(size)));

        let value = value.clone();

        let mut client = Client::new(None, None).await?;

        let data = client.store_blob(value).await?;
        let address = *data.address();
        let _ = client.store_blob(data).await?;

        let res = client.get_blob(address, None, None).await;
        assert!(res.is_err());
        Ok(())
    }

    pub async fn create_and_retrieve_10mb_encrypted_put_retrieve_unencrypted(
    ) -> Result<(), ClientError> {
        let size = 1024 * 1024 * 10;
        let value = Blob::Public(PublicBlob::new(generate_random_vector(size)));

        let value = value.clone();

        let mut client = Client::new(None, None).await?;

        let data = client.store_blob(value).await?;
        let address = *data.address();
        let _ = client.store_blob(data).await?;

        let res = client.get_blob(address, None, None).await;
        assert!(res.is_err());

        Ok(())
    }

    pub async fn create_and_retrieve_10mb_encrypted_put_pub_retrieve_private(
    ) -> Result<(), ClientError> {
        let size = 1024 * 1024 * 10;
        let value = Blob::Public(PublicBlob::new(generate_random_vector(size)));

        let mut client = Client::new(None, None).await?;

        let data = client.store_blob(value).await?;
        let data_name = *data.name();
        let _ = client.store_blob(data).await?;

        let address = BlobAddress::Private(data_name);
        let res = client.get_blob(address, None, None).await;
        assert!(res.is_err());

        Ok(())
    }

    pub async fn create_and_retrieve_10mb_encrypted_put_private_retrieve_pub(
    ) -> Result<(), ClientError> {
        let size = 1024 * 1024 * 10;

        let mut client = Client::new(None, None).await?;
        let value = Blob::Private(PrivateBlob::new(
            generate_random_vector(size),
            client.public_key().await,
        )?);

        let data = client.store_blob(value).await?;
        let data_name = *data.name();

        let address = BlobAddress::Public(data_name);
        let res = client.get_blob(address, None, None).await;
        assert!(res.is_err());

        Ok(())
    }

    pub async fn create_and_retrieve_index_based() -> Result<(), ClientError> {
        create_and_index_based_retrieve(1024).await
    }

    async fn create_and_index_based_retrieve(size: usize) -> Result<(), ClientError> {
        let blob = Blob::Public(PublicBlob::new(generate_random_vector(size)));
        {
            // Read first half
            let mut client = Client::new(None, None).await?;

            let data = client.store_blob(blob.clone()).await?;
            let address = *data.address();
            let _ = client.store_blob(data).await?;

            let fetched_blob = client
                .get_blob(address, None, Some(size as u64 / 2))
                .await?;
            assert_eq!(*fetched_blob.value(), blob.value()[0..size / 2].to_vec());
        }

        let blob2 = Blob::Public(PublicBlob::new(generate_random_vector(size)));
        {
            // Read Second half
            let mut client = Client::new(None, None).await?;

            let data = client.store_blob(blob2.clone()).await?;
            let address = *data.address();
            let _ = client.store_blob(data).await?;

            let fetched_blob = client
                .get_blob(address, Some(size as u64 / 2), Some(size as u64 / 2))
                .await?;
            assert_eq!(
                *fetched_blob.value(),
                blob2.value()[size / 2..size].to_vec()
            );
        }

        Ok(())
    }

    #[allow(clippy::match_wild_err_arm)]
    async fn gen_data_then_create_and_retrieve(
        size: usize,
        publish: bool,
    ) -> Result<(), ClientError> {
        let raw_data = generate_random_vector(size);

        let mut client = Client::new(None, None).await?;

        // gen address without putting to the network (published and unencrypted)
        let blob = if publish {
            Blob::Public(PublicBlob::new(raw_data.clone()))
        } else {
            Blob::Private(PrivateBlob::new(
                raw_data.clone(),
                client.public_key().await,
            )?)
        };

        // let data = gen_data_map(&client, &value.clone(), published, key2.clone()).await?;
        let address_before = blob.address();

        // attempt to retrieve it with generated address (it should error)
        let res = client.get_blob(*address_before, None, None).await;
        let _data_map_before = match res {
            Err(ClientError::DataError(SndError::NoSuchData)) => {
                // let's put it to the network (published)
                client.store_blob(blob.clone()).await?
            }
            Ok(_) => panic!("Blob unexpectedly retrieved using address generated by gen_data_map"),
            Err(_) => panic!(
                "Unexpected error when Blob retrieved using address generated by gen_data_map"
            ),
        };

        // now that it was put to the network we should be able to retrieve it
        let data_after = client.get_blob(*blob.address(), None, None).await?;

        // then the content should be what we put
        assert_eq!(*data_after.value(), raw_data);
        // sleep
        std::thread::sleep(std::time::Duration::from_millis(5500));

        Ok(())
    }
}

#[allow(missing_docs)]
#[cfg(all(test, feature = "simulated-payouts"))]
mod tests {
    use super::exported_tests;
    use super::ClientError;

    // Test putting and getting pub blob.
    #[tokio::test]
    async fn pub_blob_test() -> Result<(), ClientError> {
        exported_tests::pub_blob_test().await
    }
}

// Test putting, getting, and deleting unpub blob.
#[tokio::test]
async fn unpub_blob_test() -> Result<(), ClientError> {
    exported_tests::unpub_blob_test().await
}

/*
    #[tokio::test]
    async fn blob_deletions_should_cost_put_price() -> Result<(), ClientError> {
        exported_tests::blob_deletions_should_cost_put_price().await
    }

    #[tokio::test]
    async fn create_and_retrieve_1kb_pub_unencrypted() -> Result<(), ClientError> {
        exported_tests::create_and_retrieve_1kb_pub_unencrypted().await
    }

    #[tokio::test]
    async fn create_and_retrieve_1kb_private_unencrypted() -> Result<(), ClientError> {
        exported_tests::create_and_retrieve_1kb_private_unencrypted().await
    }

    #[tokio::test]
    async fn create_and_retrieve_1kb_put_pub_retrieve_private() -> Result<(), ClientError> {
        exported_tests::create_and_retrieve_1kb_put_pub_retrieve_private().await
    }

    #[tokio::test]
    async fn create_and_retrieve_1kb_put_private_retrieve_pub() -> Result<(), ClientError> {
        exported_tests::create_and_retrieve_1kb_put_private_retrieve_pub().await
    }

    #[tokio::test]
    async fn create_and_retrieve_10mb_private_encrypted() -> Result<(), ClientError> {
        exported_tests::create_and_retrieve_10mb_private_encrypted().await
    }

    #[tokio::test]
    async fn create_and_retrieve_10mb_pub_encrypted() -> Result<(), ClientError> {
        exported_tests::create_and_retrieve_10mb_pub_encrypted().await
    }

    #[tokio::test]
    async fn create_and_retrieve_10mb_private_unencrypted() -> Result<(), ClientError> {
        exported_tests::create_and_retrieve_10mb_private_unencrypted().await
    }

    #[tokio::test]
    async fn create_and_retrieve_10mb_pub_unencrypted() -> Result<(), ClientError> {
        exported_tests::create_and_retrieve_10mb_pub_unencrypted().await
    }

    #[tokio::test]
    async fn create_and_retrieve_10mb_unencrypted_put_retrieve_encrypted() -> Result<(), ClientError>
    {
        exported_tests::create_and_retrieve_10mb_unencrypted_put_retrieve_encrypted().await
    }

    #[tokio::test]
    async fn create_and_retrieve_10mb_encrypted_put_retrieve_unencrypted() -> Result<(), ClientError>
    {
        exported_tests::create_and_retrieve_10mb_encrypted_put_retrieve_unencrypted().await
    }

    #[tokio::test]
    async fn create_and_retrieve_10mb_encrypted_put_pub_retrieve_private() -> Result<(), ClientError>
    {
        exported_tests::create_and_retrieve_10mb_encrypted_put_pub_retrieve_private().await
    }

    #[tokio::test]
    async fn create_and_retrieve_10mb_encrypted_put_private_retrieve_pub() -> Result<(), ClientError>
    {
        exported_tests::create_and_retrieve_10mb_encrypted_put_private_retrieve_pub().await
    }

    #[tokio::test]
    async fn create_and_retrieve_index_based() -> Result<(), ClientError> {
        exported_tests::create_and_retrieve_index_based().await
    }
}
*/
