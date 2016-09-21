// Copyright 2015 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use core::{SelfEncryptionStorage, SelfEncryptionStorageError};

use core::client::Client;
use nfs::directory::Directory;
use nfs::errors::NfsError;
use nfs::file::File;
use nfs::helper::directory_helper::DirectoryHelper;
use self_encryption::SequentialEncryptor;
use std::sync::{Arc, Mutex};

/// Mode of the writer
pub enum Mode {
    /// Will create new data
    Overwrite,
    /// Will modify the existing data
    Modify,
}

/// Writer is used to write contents to a File and especially in chunks if the file happens to be
/// too large
pub struct Writer<'a> {
    client: Arc<Mutex<Client>>,
    file: File,
    parent_directory: Directory,
    self_encryptor: SequentialEncryptor<'a, SelfEncryptionStorageError, SelfEncryptionStorage>,
}

impl<'a> Writer<'a> {
    /// Create new instance of Writer
    pub fn new(client: Arc<Mutex<Client>>,
               storage: &'a mut SelfEncryptionStorage,
               mode: Mode,
               parent_directory: Directory,
               file: File)
               -> Result<Writer<'a>, NfsError> {
        let data_map = match mode {
            Mode::Modify => Some(file.datamap().clone()),
            Mode::Overwrite => None,
        };

        Ok(Writer {
            client: client.clone(),
            file: file,
            parent_directory: parent_directory,
            self_encryptor: try!(SequentialEncryptor::new(storage, data_map)),
        })
    }

    /// Data of a file/blob can be written in smaller chunks
    pub fn write(&mut self, data: &[u8]) -> Result<(), NfsError> {
        trace!("Writer writing file data of size {} into self-encryptor.",
               data.len());
        Ok(try!(self.self_encryptor.write(data)))
    }

    /// close is invoked only after all the data is completely written
    /// The file/blob is saved only when the close is invoked.
    /// Returns the update DirectoryListing which owns the file and also the updated
    /// DirectoryListing of the file's parent
    /// Returns (files's parent_directory, Option<file's parent_directory's parent>)
    pub fn close(mut self) -> Result<(Directory, Option<Directory>), NfsError> {
        let mut file = self.file;
        let mut directory = self.parent_directory;
        let size = self.self_encryptor.len();

        file.set_datamap(try!(self.self_encryptor.close()));
        trace!("Writer induced self-encryptor close.");

        file.metadata_mut().set_modified_time(::time::now_utc());
        file.metadata_mut().set_size(size);
        file.metadata_mut().increment_version();

        directory.upsert_file(file.clone());

        let directory_helper = DirectoryHelper::new(self.client.clone());
        if let Some(updated_grand_parent) = try!(directory_helper.update(&directory)) {
            Ok((directory, Some(updated_grand_parent)))
        } else {
            Ok((directory, None))
        }
    }
}
