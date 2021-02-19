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
use sn_data_types::{Blob, BlobAddress, PrivateBlob, PublicBlob};
use xor_name::{XorName, XOR_NAME_LEN};

/// Network storage is the concrete type which self_encryption crate will use
/// to put or get data from the network.
#[derive(Clone)]
pub struct BlobStorage {
    client: Client,
    published: bool,
}

impl BlobStorage {
    /// Create a new BlobStorage instance.
    pub fn new(client: Client, published: bool) -> Self {
        Self { client, published }
    }
}

#[async_trait]
impl Storage for BlobStorage {
    async fn get(&mut self, name: &[u8]) -> Result<Vec<u8>, SelfEncryptionError> {
        trace!("Self encrypt invoked GetBlob.");

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

        let address = if self.published {
            BlobAddress::Public(name)
        } else {
            BlobAddress::Private(name)
        };

        match self.client.fetch_blob_from_network(address).await {
            Ok(data) => Ok(data.value().clone()),
            Err(error) => Err(SelfEncryptionError::Generic(format!("{}", error))),
        }
    }

    async fn delete(&mut self, name: &[u8]) -> Result<(), SelfEncryptionError> {
        trace!("Self encrypt invoked DeleteBlob.");

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

        let address = if self.published {
            // Should raise error though
            BlobAddress::Public(name)
        } else {
            BlobAddress::Private(name)
        };

        match self.client.delete_blob_from_network(address).await {
            Ok(_) => Ok(()),
            Err(error) => Err(SelfEncryptionError::Generic(format!("{}", error))),
        }
    }

    async fn put(&mut self, _: Vec<u8>, data: Vec<u8>) -> Result<(), SelfEncryptionError> {
        trace!("Self encrypt invoked PutBlob.");
        let blob: Blob = if self.published {
            PublicBlob::new(data).into()
        } else {
            PrivateBlob::new(data, self.client.public_key().await).into()
        };
        self.client
            .store_blob_on_network(blob)
            .await
            .map_err(|err| SelfEncryptionError::Generic(format!("{}", err)))
    }

    async fn generate_address(&self, data: &[u8]) -> Result<Vec<u8>, SelfEncryptionError> {
        let blob: Blob = if self.published {
            PublicBlob::new(data.to_vec()).into()
        } else {
            PrivateBlob::new(data.to_vec(), self.client.public_key().await).into()
        };
        Ok(blob.name().0.to_vec())
    }
}

/// Network storage is the concrete type which self_encryption crate will use
/// to put or get data from the network.
#[derive(Clone)]
pub struct BlobStorageDryRun {
    client: Client,
    published: bool,
}

impl BlobStorageDryRun {
    /// Create a new BlobStorage instance.
    pub fn new(client: Client, published: bool) -> Self {
        Self { client, published }
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
        let blob: Blob = if self.published {
            PublicBlob::new(data.to_vec()).into()
        } else {
            PrivateBlob::new(data.to_vec(), self.client.public_key().await).into()
        };
        Ok(blob.name().0.to_vec())
    }
}
