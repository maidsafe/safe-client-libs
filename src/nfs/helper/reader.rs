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
use core::CPtr;
use futures::{self, Future};
use nfs::NfsFuture;
use nfs::errors::NfsError;
use nfs::file::File;
use self_encryption::SelfEncryptor;

/// Reader is used to read contents of a File. It can read in chunks if the file happens to be very
/// large
#[allow(dead_code)]
pub struct Reader {
    client: CPtr,
    self_encryptor: SelfEncryptor<SelfEncryptionStorage>,
}

impl Reader {
    /// Create a new instance of Reader
    pub fn new(client: CPtr,
               storage: SelfEncryptionStorage,
               file: &File)
               -> Result<Reader, NfsError> {
        Ok(Reader {
            client: client,
            self_encryptor: try!(SelfEncryptor::new(storage, file.datamap().clone())),
        })
    }

    /// Returns the total size of the file/blob
    pub fn size(&self) -> u64 {
        self.self_encryptor.len()
    }

    /// Read data from file/blob
    pub fn read(&self, position: u64, length: u64) -> NfsFuture<Vec<u8>> {
        trace!("Reader reading from pos: {} and size: {}.",
               position,
               length);

        if (position + length) > self.size() {
            Box::new(futures::failed(NfsError::InvalidRangeSpecified))
        } else {
            debug!("Reading {len} bytes of data from file starting at offset of {pos} bytes ...",
                   len = length,
                   pos = position);
            Box::new(self.self_encryptor.read(position, length).map_err(From::from))
        }
    }
}
