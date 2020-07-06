// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{Client, CoreError};
use async_trait::async_trait;
use log::trace;
use safe_nd::{IData, IDataAddress, PubImmutableData, UnpubImmutableData};
use self_encryption::{Storage, StorageError};
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use xor_name::{XorName, XOR_NAME_LEN};

/// Network storage is the concrete type which self-encryption crate will use
/// to put or get data from the network.
#[derive(Clone)]
pub struct SelfEncryptionStorage<C: Client + Send + Sync + 'static> {
    client: C,
    published: bool,
}

impl<C: Client + Send + Sync + 'static> SelfEncryptionStorage<C> {
    /// Create a new SelfEncryptionStorage instance.
    pub fn new(client: C, published: bool) -> Self {
        Self { client, published }
    }
}

#[async_trait]
impl<C: Send + Sync + Client + 'static> Storage for SelfEncryptionStorage<C> {
    type Error = SEStorageError;

    async fn get(&self, name: &[u8]) -> Result<Vec<u8>, Self::Error> {
        trace!("Self encrypt invoked GetIData.");

        if name.len() != XOR_NAME_LEN {
            let err = CoreError::Unexpected("Requested `name` is incorrect size.".to_owned());
            let err = SEStorageError::from(err);
            return Err(err);
        }

        let name = {
            let mut temp = [0_u8; XOR_NAME_LEN];
            temp.clone_from_slice(name);
            XorName(temp)
        };

        let address = if self.published {
            IDataAddress::Pub(name)
        } else {
            IDataAddress::Unpub(name)
        };

        match self.client.get_idata(address).await {
            Ok(data) => Ok(data.value().clone()),
            Err(error) => Err(SEStorageError::from(error)),
        }
    }

    async fn put(&mut self, _: Vec<u8>, data: Vec<u8>) -> Result<(), Self::Error> {
        trace!("Self encrypt invoked PutIData.");
        let immutable_data: IData = if self.published {
            PubImmutableData::new(data).into()
        } else {
            UnpubImmutableData::new(data, self.client.public_key().await).into()
        };
        match self.client.put_idata(immutable_data).await {
            Ok(_r) => Ok(()),
            Err(error) => Err(SEStorageError::from(error)),
        }
    }

    async fn generate_address(&self, data: &[u8]) -> Vec<u8> {
        let immutable_data: IData = if self.published {
            PubImmutableData::new(data.to_vec()).into()
        } else {
            UnpubImmutableData::new(data.to_vec(), self.client.public_key().await).into()
        };
        immutable_data.name().0.to_vec()
    }
}

/// Errors arising from storage object being used by self-encryptors.
#[derive(Debug)]
pub struct SEStorageError(pub Box<CoreError>);

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

impl From<CoreError> for SEStorageError {
    fn from(error: CoreError) -> Self {
        Self(Box::new(error))
    }
}

impl StorageError for SEStorageError {}

/// Network storage is the concrete type which self-encryption crate will use
/// to put or get data from the network.
#[derive(Clone)]
pub struct SelfEncryptionStorageDryRun<C: Client + 'static> {
    client: C,
    published: bool,
}

impl<C: Client + 'static> SelfEncryptionStorageDryRun<C> {
    /// Create a new SelfEncryptionStorage instance.
    pub fn new(client: C, published: bool) -> Self {
        Self { client, published }
    }
}

#[async_trait]
impl<C: Send + Sync + Client + 'static> Storage for SelfEncryptionStorageDryRun<C> {
    type Error = SEStorageError;

    async fn get(&self, _name: &[u8]) -> Result<Vec<u8>, Self::Error> {
        trace!("Self encrypt invoked GetIData dry run.");
        Err(SEStorageError::from(CoreError::Unexpected(
            "Cannot get from storage since it's a dry run.".to_owned(),
        )))
    }

    async fn put(&mut self, _: Vec<u8>, _data: Vec<u8>) -> Result<(), Self::Error> {
        trace!("Self encrypt invoked PutIData dry run.");
        // We do nothing here just return ok so self-encrpytion can finish
        // and generate chunk addresses and datamap if required
        Ok(())
    }

    async fn generate_address(&self, data: &[u8]) -> Vec<u8> {
        let immutable_data: IData = if self.published {
            PubImmutableData::new(data.to_vec()).into()
        } else {
            UnpubImmutableData::new(data.to_vec(), self.client.public_key().await).into()
        };
        immutable_data.name().0.to_vec()
    }
}
