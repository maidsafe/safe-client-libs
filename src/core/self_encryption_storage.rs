// Copyright 2015 MaidSafe.net limited.
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

use core::client::Client;
use core::errors::CoreError;
use core::self_encryption_storage_error::SelfEncryptionStorageError;
use routing::{Data, DataIdentifier, ImmutableData, XOR_NAME_LEN, XorName};
use self_encryption::Storage;
use std::sync::{Arc, Mutex};

/// Network storage is the concrete type which self-encryption crate will use to put or get data
/// from the network
pub struct SelfEncryptionStorage {
    // TODO - No need for `client` to be mutex-protected any more since SelfEncryptor is no longer
    // multi-threaded.
    client: Arc<Mutex<Client>>,
}

impl SelfEncryptionStorage {
    /// Create a new SelfEncryptionStorage instance
    pub fn new(client: Arc<Mutex<Client>>) -> SelfEncryptionStorage {
        SelfEncryptionStorage { client: client }
    }
}

impl Storage<SelfEncryptionStorageError> for SelfEncryptionStorage {
    fn get(&self, name: &[u8]) -> Result<Vec<u8>, SelfEncryptionStorageError> {
        trace!("Self encrypt invoked GET.");

        if name.len() != XOR_NAME_LEN {
            return Err(SelfEncryptionStorageError(Box::new(CoreError::Unexpected("Requested \
                                                                                  `name` is \
                                                                                  incorrect \
                                                                                  size."
                .to_owned()))));
        }
        let mut name_id = [0u8; XOR_NAME_LEN];
        for i in 0..XOR_NAME_LEN {
            name_id[i] = name[i];
        }

        let immutable_data_request = DataIdentifier::Immutable(XorName(name_id));
        let resp_getter = unwrap!(self.client.lock())
            .get(immutable_data_request, None)?;
        match resp_getter.get()? {
            Data::Immutable(ref received_data) => Ok(received_data.value().clone()),
            _ => {
                Err(SelfEncryptionStorageError(Box::new(CoreError::Unexpected("Wrong data type \
                                                                               returned from \
                                                                               network."
                    .to_owned()))))
            }
        }
    }

    fn put(&mut self, _: Vec<u8>, data: Vec<u8>) -> Result<(), SelfEncryptionStorageError> {
        trace!("Self encrypt invoked PUT.");

        let immutable_data = ImmutableData::new(data);
        Ok(Client::put_recover(self.client.clone(), Data::Immutable(immutable_data), None)?)
    }
}
