// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::client::Client;
use crate::crypto::shared_secretbox;
use crate::errors::CoreError;
use crate::nfs::{data_map, File, NfsError};
use crate::self_encryption_storage::SelfEncryptionStorage;
use chrono::Utc;
use log::trace;
use safe_nd::Error as SndError;
use self_encryption::{DataMap, SequentialEncryptor};

/// Mode of the writer.
#[derive(Clone, Copy, Debug)]
pub enum Mode {
    /// Will create new data.
    Overwrite,
    /// Will append content to the existing data.
    Append,
}

/// Writer is used to write contents to a File and especially in chunks if the
/// file happens to be too large.
pub struct Writer<C: Client> {
    client: C,
    file: File,
    self_encryptor: SequentialEncryptor<SelfEncryptionStorage<C>>,
    encryption_key: Option<shared_secretbox::Key>,
}

impl<C: Sync + Client> Writer<C> {
    /// Create new instance of Writer.
    pub async fn new(
        client: &C,
        storage: SelfEncryptionStorage<C>,
        file: File,
        mode: Mode,
        encryption_key: Option<shared_secretbox::Key>,
    ) -> Result<Writer<C>, NfsError> {
        let data_map = match mode {
            Mode::Append => {
                let data_map: Option<DataMap> = match data_map::get(
                    client,
                    file.data_address(),
                    encryption_key.clone(),
                )
                .await
                {
                    Ok(map) => Some(map),
                    Err(err) => {
                        if let NfsError::CoreError(CoreError::DataError(SndError::NoSuchData)) = err
                        {
                            None
                        } else {
                            return Err(NfsError::from(err));
                        }
                    }
                };
                data_map
            }
            Mode::Overwrite => None,
        };
        let client = client.clone();

        let self_encryptor = SequentialEncryptor::new(storage, data_map);

        Ok(Self {
            client,
            file,
            self_encryptor: self_encryptor.await?,
            encryption_key,
        })
    }

    /// Data of a file/blob can be written in smaller chunks.
    pub async fn write(&self, data: &[u8]) -> Result<(), NfsError> {
        trace!(
            "Writer writing file data of size {} into self-encryptor.",
            data.len()
        );
        self.self_encryptor.write(data).await.map_err(From::from)
    }

    /// close() should be invoked only after all the data is completely written. The file/blob is
    /// saved only when close() is invoked. Returns the final `File` with the data_map stored on the
    /// network.
    pub async fn close(self) -> Result<File, NfsError> {
        trace!("Writer induced self-encryptor close.");

        let mut file = self.file;
        let size = self.self_encryptor.len();
        let client = self.client;
        let encryption_key = self.encryption_key;
        let published = file.published();

        let (data_map, _storage) = self.self_encryptor.close().await?;
        let data_map_name = data_map::put(&client, &data_map, published, encryption_key).await?;

        file.set_data_map_name(data_map_name);
        file.set_modified_time(Utc::now());
        file.set_size(size);
        Ok(file)
    }
}
