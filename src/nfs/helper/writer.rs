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

use core::{Client, FutureExt, SelfEncryptionStorage, immutable_data};
use futures::Future;
use maidsafe_utilities::serialisation::serialise;
use nfs::{File, FileMetadata, NfsFuture};
use nfs::helper::file_helper;
use routing::ImmutableData;
// use rust_sodium::crypto::secretbox;
use self_encryption::SequentialEncryptor;

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
    self_encryptor: SequentialEncryptor<SelfEncryptionStorage>,
}

impl Writer {
    /// Create new instance of Writer
    pub fn new(client: Client,
               storage: SelfEncryptionStorage,
               mode: Mode,
               file: File)
               -> Box<NfsFuture<Writer>> {
        let data_map = match mode {
            Mode::Modify => Some(file.datamap().clone()),
            Mode::Overwrite => None,
        };

        let client = client.clone();
        SequentialEncryptor::new(storage, data_map)
            .map(move |encryptor| {
                Writer {
                    client: client,
                    file: file,
                    self_encryptor: encryptor,
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
    /// `FileMetadata` referencing the `File` that was written to the network
    pub fn close(self) -> Box<NfsFuture<FileMetadata>> {
        trace!("Writer induced self-encryptor close.");

        let file = self.file;
        let size = self.self_encryptor.len();
        let client = self.client;

        self.self_encryptor
            .close()
            .map_err(From::from)
            .and_then(move |(data_map, _)| {
                match file {
                    File::Unversioned(ref metadata) => {
                        let mut metadata = metadata.clone();
                        metadata.set_datamap(data_map);
                        metadata.set_modified_time(::time::now_utc());
                        metadata.set_size(size);
                        ok!(metadata)
                    }
                    File::Versioned { ptr_versions, num_of_versions, latest_version } => {
                        // Create a new file version
                        let mut new_version = FileMetadata::new(latest_version.name()
                                                                    .to_owned(),
                                                                latest_version.user_metadata()
                                                                    .to_owned(),
                                                                data_map);
                        new_version.set_created_time(latest_version.created_time().clone());
                        new_version.set_modified_time(::time::now_utc());

                        let c2 = client.clone();
                        let c3 = client.clone();

                        let previous_versions_fut = if num_of_versions > 0 {
                            file_helper::get_versions(&client, &ptr_versions, None)
                                .map(move |mut versions| {
                                    versions.push(latest_version);
                                    versions
                                })
                                .into_box()
                        } else {
                            // ptr_versions is null, create a new list of versions
                            ok!(Vec::<FileMetadata>::new())
                        };

                        previous_versions_fut.and_then(move |versions| {
                                immutable_data::create(&c2, fry!(serialise(&versions)), None)
                                    .map_err(From::from)
                                    .into_box()
                            })
                            .and_then(move |immut_data| {
                                let immut_id = immut_data.identifier();
                                c3.put_idata(ImmutableData::from(immut_data))
                                    .map_err(From::from)
                                    .map(move |_| immut_id)
                            })
                            .and_then(move |ptr_versions| {
                                let file = File::Versioned {
                                    ptr_versions: ptr_versions,
                                    latest_version: new_version,
                                    num_of_versions: num_of_versions + 1,
                                };
                                Ok(file.metadata().clone())
                            })
                            .into_box()
                    }
                }
            })
            .into_box()
    }
}
