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

use maidsafe_utilities::serialisation::{SerialisationError, deserialise, serialise};
use routing::{AccountInfo, ClientError, Data, XorName};
use std::collections::HashMap;

// This should ideally be replaced with
// `safe_vault::maid_manager::DEFAULT_ACCOUNT_SIZE`, but that's not exported by
// Vault currently.
pub const DEFAULT_CLIENT_ACCOUNT_SIZE: u64 = 100;

#[derive(RustcEncodable, RustcDecodable)]
pub struct Storage {
    data_store: HashMap<XorName, Vec<u8>>,
    client_accounts: HashMap<XorName, AccountInfo>,
}

impl Storage {
    pub fn new() -> Self {
        sync::load().unwrap_or_else(|| {
            Storage {
                data_store: HashMap::new(),
                client_accounts: HashMap::new(),
            }
        })
    }

    // Check if data with the given name is in the storage.
    pub fn contains_data(&self, name: &XorName) -> bool {
        self.data_store.contains_key(name)
    }

    // Load data with the given name from the storage.
    pub fn get_data(&self, name: &XorName) -> Result<Data, StorageError> {
        match self.data_store.get(name) {
            Some(data) => deserialise(data).map_err(StorageError::SerialisationError),
            None => Err(StorageError::NoSuchData),
        }
    }

    // Save the data to the storage.
    pub fn put_data(&mut self, name: XorName, data: Data) -> Result<(), StorageError> {
        serialise(&data)
            .map(|data| {
                let _ = self.data_store.insert(name, data);
            })
            .map_err(StorageError::SerialisationError)
    }

    // Get account info for the given client
    pub fn get_account_info(&self, name: &XorName) -> Option<&AccountInfo> {
        self.client_accounts.get(name)
    }

    // Get account info for the given client, or create a default one if it doesn't exist yet.
    pub fn get_or_create_account_info(&mut self, name: &XorName) -> &mut AccountInfo {
        self.client_accounts.entry(*name).or_insert_with(|| {
            AccountInfo {
                data_stored: 0,
                space_available: DEFAULT_CLIENT_ACCOUNT_SIZE,
            }
        })
    }

    // Synchronize the storage with the disk.
    pub fn sync(&self) {
        sync::save(self)
    }
}

pub enum StorageError {
    NoSuchData,
    SerialisationError(SerialisationError),
}

impl From<StorageError> for ClientError {
    fn from(error: StorageError) -> Self {
        match error {
            StorageError::NoSuchData => ClientError::NoSuchData,
            StorageError::SerialisationError(error) => {
                ClientError::NetworkOther(format!("{:?}", error))
            }
        }
    }
}

#[cfg(test)]
mod sync {
    use super::Storage;

    pub fn load() -> Option<Storage> {
        None
    }

    pub fn save(_: &Storage) {}
}

#[cfg(not(test))]
mod sync {
    use maidsafe_utilities::serialisation::{deserialise, serialise};
    use std::env;
    use std::fs::File;
    use std::io::{Read, Write};
    use std::path::PathBuf;
    use super::Storage;

    const STORAGE_FILE_NAME: &'static str = "VaultStorageSimulation";

    pub fn load() -> Option<Storage> {
        if let Ok(mut file) = File::open(path()) {
            let mut raw_disk_data = Vec::with_capacity(unwrap!(file.metadata()).len() as usize);
            if let Ok(_) = file.read_to_end(&mut raw_disk_data) {
                if !raw_disk_data.is_empty() {
                    return deserialise(&raw_disk_data).ok();
                }
            }
        }

        None
    }

    pub fn save(storage: &Storage) {
        let mut file = unwrap!(File::create(path()));
        let _ = file.write_all(&unwrap!(serialise(storage)));
        unwrap!(file.sync_all());
    }

    fn path() -> PathBuf {
        env::temp_dir().join(STORAGE_FILE_NAME)
    }
}
