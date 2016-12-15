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

use core::{Client, FutureExt, SelfEncryptionStorage};
use futures::Future;
use nfs::{File, NfsError, NfsFuture, data_map};
use self_encryption::SelfEncryptor;

/// Reader is used to read contents of a File. It can read in chunks if the
/// file happens to be very large
#[allow(dead_code)]
pub struct Reader {
    client: Client,
    self_encryptor: SelfEncryptor<SelfEncryptionStorage>,
}

impl Reader {
    /// Create a new instance of Reader
    pub fn new(client: Client,
               storage: SelfEncryptionStorage,
               file: &File)
               -> Box<NfsFuture<Reader>> {
        data_map::get(&client, file.data_map_name())
            .and_then(move |data_map| {
                let self_encryptor = SelfEncryptor::new(storage, data_map)?;

                Ok(Reader {
                    client: client,
                    self_encryptor: self_encryptor,
                })
            })
            .into_box()
    }

    /// Returns the total size of the file/blob
    pub fn size(&self) -> u64 {
        self.self_encryptor.len()
    }

    /// Read data from file/blob
    pub fn read(&self, position: u64, length: u64) -> Box<NfsFuture<Vec<u8>>> {
        trace!("Reader reading from pos: {} and size: {}.",
               position,
               length);

        if (position + length) > self.size() {
            err!(NfsError::InvalidRangeSpecified)
        } else {
            debug!("Reading {len} bytes of data from file starting at offset of {pos} bytes ...",
                   len = length,
                   pos = position);
            self.self_encryptor.read(position, length).map_err(From::from).into_box()
        }
    }
}
