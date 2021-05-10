// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::Client;
use async_trait::async_trait;
use log::trace;
use self_encryption::{SelfEncryptionError, Storage};
use sn_data_types::{Chunk, ChunkAddress, PrivateChunk, PublicChunk, PublicKey};
use xor_name::{XorName, XOR_NAME_LEN};

/// Network storage is the concrete type which self_encryption crate will use
/// to put or get data from the network.
#[derive(Clone)]
pub struct BlobStorage {
    client: Client,
    public: bool,
}

impl BlobStorage {
    /// Create a new BlobStorage instance.
    pub fn new(client: Client, public: bool) -> Self {
        Self { client, public }
    }
}

#[async_trait]
impl Storage for BlobStorage {
    async fn get(&mut self, name: &[u8]) -> Result<Vec<u8>, SelfEncryptionError> {
        if name.len() != XOR_NAME_LEN {
            return Err(SelfEncryptionError::Generic(
                "Requested `name` is incorrect size.".to_owned(),
            ));
        }

        let name = {
            let mut temp = [0_u8; XOR_NAME_LEN];
            temp.clone_from_slice(name);
            XorName(temp)
        };

        let head_chunk_address = if self.public {
            ChunkAddress::Public(name)
        } else {
            ChunkAddress::Private(name)
        };

        trace!("Self encrypt invoked GetBlob({:?})", &head_chunk_address);

        match self
            .client
            .fetch_blob_from_network(head_chunk_address)
            .await
        {
            Ok(data) => Ok(data.value().clone()),
            Err(error) => Err(SelfEncryptionError::Generic(format!("{}", error))),
        }
    }

    async fn delete(&mut self, name: &[u8]) -> Result<(), SelfEncryptionError> {
        if name.len() != XOR_NAME_LEN {
            return Err(SelfEncryptionError::Generic(
                "Requested `name` is incorrect size.".to_owned(),
            ));
        }

        let name = {
            let mut temp = [0_u8; XOR_NAME_LEN];
            temp.clone_from_slice(name);
            XorName(temp)
        };

        let head_chunk_address = if self.public {
            return Err(SelfEncryptionError::Generic(
                "Cannot delete on a public storage".to_owned(),
            ));
        } else {
            ChunkAddress::Private(name)
        };
        trace!("Self encrypt invoked DeleteBlob({:?})", &head_chunk_address);

        match self
            .client
            .delete_blob_from_network(head_chunk_address)
            .await
        {
            Ok(_) => Ok(()),
            Err(error) => Err(SelfEncryptionError::Generic(format!("{}", error))),
        }
    }

    async fn put(&mut self, _: Vec<u8>, data: Vec<u8>) -> Result<(), SelfEncryptionError> {
        let chunk: Chunk = if self.public {
            PublicChunk::new(data).into()
        } else {
            PrivateChunk::new(data, self.client.public_key().await).into()
        };
        trace!("Self encrypt invoked StoreChunk({:?})", &chunk);
        self.client
            .store_chunk_on_network(chunk)
            .await
            .map_err(|err| SelfEncryptionError::Generic(format!("{}", err)))
    }

    async fn generate_address(&self, data: &[u8]) -> Result<Vec<u8>, SelfEncryptionError> {
        let chunk: Chunk = if self.public {
            PublicChunk::new(data.to_vec()).into()
        } else {
            PrivateChunk::new(data.to_vec(), self.client.public_key().await).into()
        };
        Ok(chunk.name().0.to_vec())
    }
}

/// Network storage is the concrete type which self_encryption crate will use
/// to put or get data from the network.
#[derive(Clone)]
pub struct BlobStorageDryRun {
    privately_owned: Option<PublicKey>,
}

impl BlobStorageDryRun {
    /// Create a new BlobStorage instance.
    pub fn new(privately_owned: Option<PublicKey>) -> Self {
        Self { privately_owned }
    }
}

#[async_trait]
impl Storage for BlobStorageDryRun {
    async fn get(&mut self, _name: &[u8]) -> Result<Vec<u8>, SelfEncryptionError> {
        trace!("Self encrypt invoked GetBlob dry run.");
        Err(SelfEncryptionError::Generic(
            "Cannot get from storage since it's a dry run.".to_owned(),
        ))
    }

    async fn put(&mut self, _: Vec<u8>, _data: Vec<u8>) -> Result<(), SelfEncryptionError> {
        trace!("Self encrypt invoked PutBlob dry run.");
        // We do nothing here just return ok so self_encrpytion can finish
        // and generate chunk addresses and datamap if required
        Ok(())
    }

    async fn delete(&mut self, _name: &[u8]) -> Result<(), SelfEncryptionError> {
        trace!("Self encrypt invoked DeleteBlob dry run.");

        Ok(())
    }

    async fn generate_address(&self, data: &[u8]) -> Result<Vec<u8>, SelfEncryptionError> {
        let chunk: Chunk = if let Some(owner) = self.privately_owned {
            PrivateChunk::new(data.to_vec(), owner).into()
        } else {
            PublicChunk::new(data.to_vec()).into()
        };

        Ok(chunk.name().0.to_vec())
    }
}
