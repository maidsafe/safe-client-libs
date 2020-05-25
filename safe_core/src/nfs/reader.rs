// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::client::Client;
use crate::crypto::shared_secretbox;
use crate::nfs::{data_map, File, NfsError};
use crate::self_encryption_storage::SelfEncryptionStorage;
use log::{debug, trace};
use self_encryption::SelfEncryptor;

/// `Reader` is used to read contents of a `File`. It can read in chunks if the `File` happens to be
/// very large.
#[allow(dead_code)]
pub struct Reader<C: Client + 'static> {
    client: C,
    self_encryptor: SelfEncryptor<SelfEncryptionStorage<C>>,
}

impl<C: Client + 'static> Reader<C> {
    /// Create a new instance of `Reader`.
    pub async fn new(
        client: C,
        storage: SelfEncryptionStorage<C>,
        file: &File,
        encryption_key: Option<shared_secretbox::Key>,
    ) -> Result<Self, NfsError> {
        let data_map = data_map::get(&client, file.data_address(), encryption_key).await?;

        let self_encryptor = SelfEncryptor::new(storage, data_map)?;

        Ok(Self {
            client,
            self_encryptor,
        })
    }

    /// Returns the total size of the file/blob.
    pub async fn size(&self) -> u64 {
        self.self_encryptor.len().await
    }

    /// Read data from file/blob.
    pub async fn read(&self, position: u64, length: u64) -> Result<Vec<u8>, NfsError> {
        trace!(
            "Reader reading from pos: {} and size: {}.",
            position,
            length
        );

        if (position + length) > self.size().await {
            Err(NfsError::InvalidRange)
        } else {
            debug!(
                "Reading {len} bytes of data from file starting at offset of {pos} bytes ...",
                len = length,
                pos = position
            );
            self.self_encryptor
                .read(position, length)
                .await
                .map_err(From::from)
        }
    }
}
