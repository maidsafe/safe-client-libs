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
    Blob, BlobAddress, BlobRead, BlobWrite, DataCmd, DataQuery, PrivateBlob, PublicBlob,
    Query, QueryResponse,
};

#[derive(Serialize, Deserialize)]
enum DataMapLevel {
    Root(DataMap),
    Child(DataMap),
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

        let data = self.fetch_blob_from_network(address).await?;
        let published = address.is_pub();
        let data_map = self.unpack(data).await?;

        let raw_data = self
            .read_using_data_map(data_map, published, position, len)
            .await?;

        let final_blob = if published {
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
    pub async fn store_blob(&mut self, the_blob: Blob) -> Result<BlobAddress, ClientError> {
        info!("Storing blob: {:?}", &the_blob);

        let published = the_blob.is_pub();
        let value = the_blob.value().clone(); // can be prevented by changing the API

        // Write the contents to the self encryptor.
        let blob_storage = BlobStorage::new(self.clone(), published);
        let self_encryptor = SelfEncryptor::new(blob_storage.clone(), DataMap::None)
            .map_err(|e| ClientError::from(format!("Self encryption error: {:?}", e)))?;

        self_encryptor
            .write(&value, 0)
            .await
            .map_err(|e| ClientError::from(format!("Self encryption error: {:?}", e)))?;

        let (data_map, _) = self_encryptor
            .close()
            .await
            .map_err(|e| ClientError::from(format!("Self encryption error: {:?}", e)))?;

        let data = serialize(&DataMapLevel::Root(data_map))?;

        let data_map_blob = self.pack(data, published).await?;
        let data_map_address = *data_map_blob.address();

        self.store_blob_on_network(data_map_blob).await?;

        Ok(data_map_address)
    }

    pub(crate) async fn fetch_blob_from_network(
        &mut self,
        address: BlobAddress,
    ) -> Result<Blob, ClientError> {
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
        // let _ = self
        //     .blob_cache
        //     .lock()
        //     .await
        //     .put(*data.address(), data.clone());
        Ok(data)
    }

    // This is a private function that actually stores the given blob on the network.
    // Self Encryption is NOT APPLIED ON the blob that is passed to this function.
    // Clients should not call this function directly.
    pub(crate) async fn store_blob_on_network(&mut self, blob: Blob) -> Result<(), ClientError> {
        let cmd = DataCmd::Blob(BlobWrite::New(blob));
        self.pay_and_send_data_command(cmd).await?;
        Ok(())
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
        let res = self.blob_cache.lock().await.pop(&address);
        info!("Dropped {:?} from cache", res);
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

    async fn read_using_data_map(
        &mut self,
        data_map: DataMap,
        published: bool,
        position: Option<u64>,
        len: Option<u64>,
    ) -> Result<Vec<u8>, ClientError> {
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

    /// This function takes the "Root data map" and returns a Blob that is acceptable by the network
    ///
    /// If the root data map blob is too big, the whole blob is self-encrypted and the child data map is used.
    /// The above step is repeated as many times as required until the blob size is valid.
    async fn pack(&mut self, mut contents: Vec<u8>, published: bool) -> Result<Blob, ClientError> {
        loop {
            let data: Blob = if published {
                PublicBlob::new(contents).into()
            } else {
                PrivateBlob::new(contents, self.public_key().await)?.into()
            };

            // If data map blob is less thatn 1MB return it so it can be directly sento to the network
            if data.validate_size() {
                return Ok(data);
            } else {
                let serialized_blob = serialize(&data)?;
                let blob_storage = BlobStorage::new(self.clone(), published);
                let self_encryptor = SelfEncryptor::new(blob_storage, DataMap::None)
                    .map_err(|e| ClientError::from(format!("Self encryption error: {:?}", e)))?;

                self_encryptor
                    .write(&serialized_blob, 0)
                    .await
                    .map_err(|e| ClientError::from(format!("Self encryption error: {:?}", e)))?;

                let (data_map, _) = self_encryptor
                    .close()
                    .await
                    .map_err(|e| ClientError::from(format!("Self encryption error: {:?}", e)))?;

                contents = serialize(&DataMapLevel::Child(data_map))?
            }
        }
    }

    /// This function takes a blob and fetches the data map from it.
    /// If the data map is not the root data map of the user's contents,
    /// the function repeats itself until it obtains the root data map.
    async fn unpack(&mut self, mut data: Blob) -> Result<DataMap, ClientError> {
        loop {
            let published = data.is_pub();
            match deserialize(data.value())? {
                DataMapLevel::Root(data_map) => {
                    return Ok(data_map);
                }
                DataMapLevel::Child(data_map) => {
                    let serialised_blob = self
                        .read_using_data_map(data_map, published, None, None)
                        .await?;
                    data = deserialize(&serialised_blob)?;
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
        test_utils::gen_bls_keypair,
    };
    use sn_data_types::{Error as SndError, Money, PrivateBlob, PublicBlob};
    use std::str::FromStr;
    use unwrap::unwrap;

    // Test putting and getting pub blob.
    pub async fn pub_blob_test() -> Result<(), ClientError> {
        let mut client = Client::new(None, None).await?;
        // The `Client::new(None)` initializes the client with 10 money.
        let _start_bal = unwrap!(Money::from_str("10"));

        let value = generate_random_vector::<u8>(10);
        let data = Blob::Public(PublicBlob::new(value.clone()));
        let address = *data.address();
        let _pk = gen_bls_keypair().public_key();

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
        let address = client.store_blob(data.clone()).await?;

        // Assert that the blob was written
        let mut fetched_data = client.get_blob(address, None, None).await;
        while fetched_data.is_err() {
            fetched_data = client.get_blob(address, None, None).await;
        }

        assert_eq!(data, fetched_data?);

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
        let address = client.store_blob(data.clone()).await?;

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
        let pub_address = client.store_blob(pub_data.clone()).await?;
        println!("FETCHING PUB BLOB TO ASSERT");

        // Fetch blob
        // Assert that the blob is stored.
        let mut fetched_data = client.get_blob(pub_address, None, None).await;
        while fetched_data.is_err() {
            println!("Loop2");
            fetched_data = client.get_blob(pub_address, None, None).await;
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
        let address = client.store_blob(value).await?;

        let res = client.get_blob(address, None, None).await;
        assert!(res.is_err());

        Ok(())
    }

    pub async fn create_and_retrieve_1kb_put_private_retrieve_pub() -> Result<(), ClientError> {
        let size = 1024;

        let value = Blob::Public(PublicBlob::new(generate_random_vector(size)));

        let mut client = Client::new(None, None).await?;

        let address = client.store_blob(value).await?;

        let res = client.get_blob(address, None, None).await;
        assert!(res.is_err());

        Ok(())
    }

    // ----------------------------------------------------------------
    // 10mb (ie. more than 1 chunk)
    // ----------------------------------------------------------------
    pub async fn create_and_retrieve_10mb_private() -> Result<(), ClientError> {
        let size = 1024 * 1024 * 10;
        gen_data_then_create_and_retrieve(size, false).await?;

        Ok(())
    }

    pub async fn create_and_retrieve_10mb_public() -> Result<(), ClientError> {
        let size = 1024 * 1024 * 10;
        gen_data_then_create_and_retrieve(size, true).await?;
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

            let address = client.store_blob(blob.clone()).await?;

            let mut fetch_res = client.get_blob(address, None, Some(size as u64 / 2)).await;
            while fetch_res.is_err() {
                fetch_res = client.get_blob(address, None, Some(size as u64 / 2)).await;
            }
            let fetched_blob = fetch_res?;
            assert_eq!(*fetched_blob.value(), blob.value()[0..size / 2].to_vec());
        }

        let blob2 = Blob::Public(PublicBlob::new(generate_random_vector(size)));
        {
            // Read Second half
            let mut client = Client::new(None, None).await?;

            let address = client.store_blob(blob2.clone()).await?;

            let mut fetch_res = client
                .get_blob(address, Some(size as u64 / 2), Some(size as u64 / 2))
                .await;
            while fetch_res.is_err() {
                fetch_res = client
                    .get_blob(address, Some(size as u64 / 2), Some(size as u64 / 2))
                    .await;
            }
            let fetched_blob = fetch_res?;
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

        let address_before = blob.address();

        // attempt to retrieve it with generated address (it should error)
        let res = client.get_blob(*address_before, None, None).await;
        match res {
            Err(ClientError::DataError(SndError::NoSuchData)) => (),
            Ok(_) => panic!("Blob unexpectedly retrieved using address generated by gen_data_map"),
            Err(_) => panic!(
                "Unexpected error when Blob retrieved using address generated by gen_data_map"
            ),
        };

        let address = client.store_blob(blob.clone()).await?;

        let mut fetch_result;
        // now that it was put to the network we should be able to retrieve it
        fetch_result = client.get_blob(address, None, None).await;

        while fetch_result.is_err() {
            dbg!("fetching data again");
            fetch_result = client.get_blob(address, None, None).await;
        }

        // then the content should be what we put
        assert_eq!(*fetch_result?.value(), raw_data);

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

    // Test putting, getting, and deleting unpub blob.
    #[tokio::test]
    async fn unpub_blob_test() -> Result<(), ClientError> {
        exported_tests::unpub_blob_test().await
    }

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
    async fn create_and_retrieve_10mb_private() -> Result<(), ClientError> {
        exported_tests::create_and_retrieve_10mb_private().await
    }

    #[tokio::test]
    async fn create_and_retrieve_10mb_public() -> Result<(), ClientError> {
        exported_tests::create_and_retrieve_10mb_public().await
    }

    #[tokio::test]
    async fn create_and_retrieve_index_based() -> Result<(), ClientError> {
        exported_tests::create_and_retrieve_index_based().await
    }
}
