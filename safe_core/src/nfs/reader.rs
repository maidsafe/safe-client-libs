// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use client::Client;
use crypto::shared_secretbox;
use futures::Future;
use nfs::{data_map, File, NfsError, NfsFuture};
use self_encryption::SelfEncryptor;
use self_encryption_storage::SelfEncryptionStorage;
use utils::FutureExt;

/// `Reader` is used to read contents of a `File`. It can read in chunks if the `File` happens to be
/// very large.
#[allow(dead_code)]
pub struct Reader<C: Client> {
    client: C,
    self_encryptor: SelfEncryptor<SelfEncryptionStorage<C>>,
}

impl<C: Client> Reader<C> {
    /// Create a new instance of `Reader`.
    pub fn new(
        client: C,
        storage: SelfEncryptionStorage<C>,
        file: &File,
        encryption_key: Option<shared_secretbox::Key>,
    ) -> Box<NfsFuture<Self>> {
        data_map::get(&client, file.data_map_name(), encryption_key)
            .and_then(move |data_map| {
                let self_encryptor = SelfEncryptor::new(storage, data_map)?;

                Ok(Self {
                    client,
                    self_encryptor,
                })
            }).into_box()
    }

    /// Returns the total size of the file/blob.
    pub fn size(&self) -> u64 {
        self.self_encryptor.len()
    }

    /// Read data from file/blob.
    pub fn read(&self, position: u64, length: u64) -> Box<NfsFuture<Vec<u8>>> {
        trace!(
            "Reader reading from pos: {} and size: {}.",
            position,
            length
        );

        if (position + length) > self.size() {
            err!(NfsError::InvalidRange)
        } else {
            debug!(
                "Reading {len} bytes of data from file starting at offset of {pos} bytes ...",
                len = length,
                pos = position
            );
            self.self_encryptor
                .read(position, length)
                .map_err(From::from)
                .into_box()
        }
    }
}
