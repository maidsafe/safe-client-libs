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
use client::{Client, MDataInfo};
use futures::{Future, future};
use maidsafe_utilities::serialisation::serialise;
use nfs::{File, NfsFuture, data_map};
use routing::EntryActions;
use self_encryption::SequentialEncryptor;
use self_encryption_storage::SelfEncryptionStorage;
use utils::FutureExt;

/// Mode of the writer
pub enum Mode {
    /// Will create new data
    Overwrite,
    /// Will modify the existing data
    Modify,
}

/// Writer is used to write contents to a File and especially in chunks if the
/// file happens to be too large
pub struct Writer {
    client: Client,
    file: File,
    parent: MDataInfo,
    file_name: String,
    self_encryptor: SequentialEncryptor<SelfEncryptionStorage>,
    version: Option<u64>,
}

impl Writer {
    /// Create new instance of Writer
    pub fn new(client: Client,
               storage: SelfEncryptionStorage,
               mode: Mode,
               parent: MDataInfo,
               file: File,
               file_name: String,
               version: Option<u64>)
               -> Box<NfsFuture<Writer>> {
        let fut = match mode {
            Mode::Modify => {
                data_map::get(&client, file.data_map_name())
                    .map(Some)
                    .into_box()
            }
            Mode::Overwrite => future::ok(None).into_box(),
        };

        let client = client.clone();
        fut.and_then(move |data_map| {
                          SequentialEncryptor::new(storage, data_map).map_err(From::from)
                      })
            .map(move |encryptor| {
                Writer {
                    client: client,
                    parent: parent,
                    file: file,
                    self_encryptor: encryptor,
                    file_name: file_name,
                    version: version,
                }
            })
            .map_err(From::from)
            .into_box()
    }

    /// Data of a file/blob can be written in smaller chunks
    pub fn write(&self, data: &[u8]) -> Box<NfsFuture<()>> {
        trace!("Writer writing file data of size {} into self-encryptor.",
               data.len());
        self.self_encryptor
            .write(data)
            .map_err(From::from)
            .into_box()
    }

    /// close is invoked only after all the data is completely written. The
    /// file/blob is saved only when the close is invoked. Returns the final
    /// `File` that was written to the network.
    pub fn close(self) -> Box<NfsFuture<File>> {
        trace!("Writer induced self-encryptor close.");

        let mut file = self.file;
        let parent = self.parent;
        let file_name = self.file_name;
        let size = self.self_encryptor.len();
        let version = self.version;

        let client = self.client;
        let client2 = client.clone();

        self.self_encryptor
            .close()
            .map_err(From::from)
            .and_then(move |(data_map, _)| data_map::put(&client, &data_map))
            .and_then(move |data_map_name| {
                file.set_data_map_name(data_map_name);
                file.set_modified_time(Utc::now());
                file.set_size(size);

                let key = fry!(parent.enc_entry_key(file_name.as_bytes()));
                let plaintext = fry!(serialise(&file));
                let ciphertext = fry!(parent.enc_entry_value(&plaintext));

                let actions = if let Some(version) = version {
                    EntryActions::new().update(key, ciphertext, version)
                } else {
                    EntryActions::new().ins(key, ciphertext, 0)
                };

                client2
                    .mutate_mdata_entries(parent.name, parent.type_tag, actions.into())
                    .map(move |_| file)
                    .map_err(From::from)
                    .into_box()
            })
            .into_box()
    }
}
