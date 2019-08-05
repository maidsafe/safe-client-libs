// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{Client, CoreError, FutureExt};
use futures::{self, Future};
use safe_nd::{IData, IDataAddress, PubImmutableData, UnpubImmutableData, XorName, XOR_NAME_LEN};
use self_encryption::{Storage, StorageError};
use std::error::Error;
use std::fmt::{self, Display, Formatter};

/// Network storage is the concrete type which self-encryption crate will use
/// to put or get data from the network.
pub struct SelfEncryptionStorage<C: Client> {
    client: C,
    published: bool,
}

impl<C: Client> SelfEncryptionStorage<C> {
    /// Create a new SelfEncryptionStorage instance.
    pub fn new(client: C, published: bool) -> Self {
        SelfEncryptionStorage { client, published }
    }
}

impl<C: Client> Storage for SelfEncryptionStorage<C> {
    type Error = SelfEncryptionStorageError;

    fn get(&self, name: &[u8]) -> Box<Future<Item = Vec<u8>, Error = Self::Error>> {
        trace!("Self encrypt invoked GetIData.");

        if name.len() != XOR_NAME_LEN {
            let err = CoreError::Unexpected("Requested `name` is incorrect size.".to_owned());
            let err = SelfEncryptionStorageError::from(err);
            return Box::new(futures::failed(err));
        }

        let name = {
            let mut temp = [0u8; XOR_NAME_LEN];
            temp.clone_from_slice(name);
            XorName(temp)
        };

        let address = if self.published {
            IDataAddress::Pub(name)
        } else {
            IDataAddress::Unpub(name)
        };

        self.client
            .get_idata(address)
            .map(|data| data.value().clone())
            .map_err(From::from)
            .into_box()
    }

    fn put(&mut self, _: Vec<u8>, data: Vec<u8>) -> Box<Future<Item = (), Error = Self::Error>> {
        trace!("Self encrypt invoked PutIData.");
        let idata: IData = if self.published {
            PubImmutableData::new(data).into()
        } else {
            UnpubImmutableData::new(data, unwrap!(self.client.public_bls_key()).into()).into()
        };
        self.client.put_idata(idata).map_err(From::from).into_box()
    }

    fn generate_address(&self, data: &[u8]) -> Vec<u8> {
        let idata: IData = if self.published {
            PubImmutableData::new(data.to_vec()).into()
        } else {
            UnpubImmutableData::new(data.to_vec(), unwrap!(self.client.public_bls_key()).into())
                .into()
        };
        idata.name().0.to_vec()
    }
}

/// Errors arising from storage object being used by self-encryptors.
#[derive(Debug)]
pub struct SelfEncryptionStorageError(pub Box<CoreError>);

impl Display for SelfEncryptionStorageError {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        Display::fmt(&*self.0, formatter)
    }
}

impl Error for SelfEncryptionStorageError {
    fn description(&self) -> &str {
        self.0.description()
    }

    fn cause(&self) -> Option<&Error> {
        self.0.source()
    }
}

impl From<CoreError> for SelfEncryptionStorageError {
    fn from(error: CoreError) -> SelfEncryptionStorageError {
        SelfEncryptionStorageError(Box::new(error))
    }
}

impl StorageError for SelfEncryptionStorageError {}
