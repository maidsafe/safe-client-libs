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
use nfs;
use std::sync;
use super::network_storage::NetworkStorage;
use self_encryption;
use client;

#[allow(dead_code)]
pub struct Reader {
    file: nfs::file::File,
    self_encryptor: self_encryption::SelfEncryptor<NetworkStorage>,
    client: ::std::sync::Arc<::std::sync::Mutex<client::Client>>
}

impl Reader {

    pub fn new(file: nfs::file::File,
        client: ::std::sync::Arc<::std::sync::Mutex<client::Client>>) -> Reader {
        let storage = sync::Arc::new(NetworkStorage::new(client.clone()));
        Reader {
            file: file.clone(),
            self_encryptor: self_encryption::SelfEncryptor::new(storage.clone(), file.get_datamap().clone()),
            client: client
        }
    }

    /// Returns the total size of the file/blob
    pub fn size(&self) -> u64 {
        self.self_encryptor.len()
    }

    /// Read data from file/blob
    pub fn read(&mut self,  position: u64, length: u64) -> Result<Vec<u8>, String> {
        if (position + length) > self.size() {
            return Err("Invalid range specified".to_string());
        }
        Ok(self.self_encryptor.read(position, length))
    }

}
