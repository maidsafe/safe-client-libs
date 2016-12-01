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

use core::Client;
use core::CoreError;
use core::futures::FutureExt;
use futures::{self, Future};
use routing::{ImmutableData, XOR_NAME_LEN, XorName};
use self_encryption::{Storage, StorageError};
use std::error::Error;
use std::fmt::{self, Display, Formatter};

/// Network storage is the concrete type which self-encryption crate will use
/// to put or get data from the network
pub struct SelfEncryptionStorage {
    client: Client,
}

impl SelfEncryptionStorage {
    /// Create a new SelfEncryptionStorage instance
    pub fn new(client: Client) -> Self {
        SelfEncryptionStorage { client: client }
    }
}

impl Storage for SelfEncryptionStorage {
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

        self.client
            .get_idata(name)
            .map(|data| data.value().clone())
            .map_err(From::from)
            .into_box()
    }

    fn put(&mut self, _: Vec<u8>, data: Vec<u8>) -> Box<Future<Item = (), Error = Self::Error>> {
        trace!("Self encrypt invoked PutIData.");
        let data = ImmutableData::new(data);
        self.client.put_idata(data).map_err(From::from).into_box()
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
        self.0.cause()
    }
}

impl From<CoreError> for SelfEncryptionStorageError {
    fn from(error: CoreError) -> SelfEncryptionStorageError {
        SelfEncryptionStorageError(Box::new(error))
    }
}

impl StorageError for SelfEncryptionStorageError {}
