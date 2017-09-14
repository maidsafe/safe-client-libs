// Copyright 2016 MaidSafe.net limited.
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

use chrono::Utc;
use client::Client;
use crypto::shared_secretbox;
use futures::Future;
use nfs::{File, NfsFuture, data_map};
use self_encryption::SequentialEncryptor;
use self_encryption_storage::SelfEncryptionStorage;
use utils::FutureExt;

/// Mode of the writer
pub enum Mode {
    /// Will create new data
    Overwrite,
    /// Will append content to the existing data
    Append,
}

/// Writer is used to write contents to a File and especially in chunks if the
/// file happens to be too large
pub struct Writer<T> {
    client: Client<T>,
    file: File,
    self_encryptor: SequentialEncryptor<SelfEncryptionStorage<T>>,
    encryption_key: Option<shared_secretbox::Key>,
}

impl<T: 'static> Writer<T> {
    /// Create new instance of Writer
    pub fn new(
        client: Client<T>,
        storage: SelfEncryptionStorage<T>,
        file: File,
        mode: Mode,
        encryption_key: Option<shared_secretbox::Key>,
    ) -> Box<NfsFuture<Writer<T>>> {
        let fut = match mode {
            Mode::Append => {
                data_map::get(&client, file.data_map_name(), encryption_key.clone())
                    .map(Some)
                    .into_box()
            }
            Mode::Overwrite => ok!(None),
        };
        let client = client.clone();
        fut.and_then(move |data_map| {
            SequentialEncryptor::new(storage, data_map).map_err(From::from)
        }).map(move |self_encryptor| {
                Writer {
                    client,
                    file,
                    self_encryptor,
                    encryption_key,
                }
            })
            .map_err(From::from)
            .into_box()
    }

    /// Data of a file/blob can be written in smaller chunks
    pub fn write(&self, data: &[u8]) -> Box<NfsFuture<()>> {
        trace!(
            "Writer writing file data of size {} into self-encryptor.",
            data.len()
        );
        self.self_encryptor
            .write(data)
            .map_err(From::from)
            .into_box()
    }

    /// close is invoked only after all the data is completely written. The
    /// file/blob is saved only when the close is invoked. Returns the final
    /// `File` with the data_map stored on the network.
    pub fn close(self) -> Box<NfsFuture<File>> {
        trace!("Writer induced self-encryptor close.");

        let mut file = self.file;
        let size = self.self_encryptor.len();
        let client = self.client;
        let encryption_key = self.encryption_key;

        self.self_encryptor
            .close()
            .map_err(From::from)
            .and_then(move |(data_map, _)| {
                data_map::put(&client, &data_map, encryption_key)
            })
            .map(move |data_map_name| {
                file.set_data_map_name(data_map_name);
                file.set_modified_time(Utc::now());
                file.set_size(size);
                file
            })
            .into_box()
    }
}
