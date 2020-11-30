// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{Client, ClientError};
use async_trait::async_trait;
use log::trace;
use sn_data_types::{Blob, BlobAddress, PrivateBlob, PublicBlob};
use self_encryption::{Storage, StorageError};
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use xor_name::{XorName, XOR_NAME_LEN};

/// Network storage is the concrete type which self_encryption crate will use
/// to put or get data from the network.
// #[derive(Clone)]
pub struct SelfEncryptionStorage {
    client: &'static mut Client,
    published: bool,
}

impl SelfEncryptionStorage {
    /// Create a new SelfEncryptionStorage instance.
    pub fn new(client: &'static mut Client, published: bool) -> Self {
        Self { client, published }
    }
}

/// Errors arising from storage object being used by self_encryptors.
#[derive(Debug)]
pub struct SEStorageError(pub Box<ClientError>);

impl Display for SEStorageError {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        Display::fmt(&self.0, formatter)
    }
}

impl Error for SEStorageError {
    fn cause(&self) -> Option<&dyn Error> {
        self.0.source()
    }
}

impl From<ClientError> for SEStorageError {
    fn from(error: ClientError) -> Self {
        Self(Box::new(error))
    }
}

impl StorageError for SEStorageError {}

/// Network storage is the concrete type which self_encryption crate will use
/// to put or get data from the network.
// #[derive(Clone)]
pub struct SelfEncryptionStorageDryRun {
    client: &'static mut Client,
    published: bool,
}

impl SelfEncryptionStorageDryRun {
    /// Create a new SelfEncryptionStorage instance.
    pub fn new(client: &'static mut Client, published: bool) -> Self {
        Self { client, published }
    }
}

#[async_trait]
impl Storage for SelfEncryptionStorageDryRun {
    type Error = SEStorageError;

    async fn get(&mut self, _name: &[u8]) -> Result<Vec<u8>, Self::Error> {
        trace!("Self encrypt invoked GetBlob dry run.");
        Err(SEStorageError::from(ClientError::Unexpected(
            "Cannot get from storage since it's a dry run.".to_owned(),
        )))
    }

    async fn put(&mut self, _: Vec<u8>, _data: Vec<u8>) -> Result<(), Self::Error> {
        trace!("Self encrypt invoked PutBlob dry run.");
        // We do nothing here just return ok so self_encrpytion can finish
        // and generate chunk addresses and datamap if required
        Ok(())
    }

    async fn generate_address(&self, data: &[u8]) -> Result<Vec<u8>, Self::Error > {
        let blob: Blob = if self.published {
            PublicBlob::new(data.to_vec()).into()
        } else {
            PrivateBlob::new(data.to_vec(), self.client.public_key().await).into()
        };
        Ok(blob.name().0.to_vec())
    }
}
