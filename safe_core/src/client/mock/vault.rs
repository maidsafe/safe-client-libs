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

use super::DataId;
use routing::{AccountInfo, Authority, ClientError, ImmutableData, MutableData, XorName};
use rust_sodium::crypto::sign;
use std::collections::{BTreeSet, HashMap};
use std::time::SystemTime;
use tiny_keccak::sha3_256;

pub const DEFAULT_MAX_MUTATIONS: u64 = 500;

#[derive(Deserialize, Serialize)]
pub struct InnerVault {
    client_manager: HashMap<XorName, Account>,
    nae_manager: HashMap<DataId, Data>,
}

pub struct Vault {
    storage: InnerVault,
    #[allow(dead_code)]
    sync_time: SystemTime,
}

impl Vault {
    pub fn new() -> Self {
        let mut vault = Vault {
            storage: InnerVault {
                client_manager: HashMap::new(),
                nae_manager: HashMap::new(),
            },
            sync_time: SystemTime::now(),
        };
        let _ = vault.load();
        vault
    }

    // Get account for the client manager name.
    pub fn get_account(&self, name: &XorName) -> Option<&Account> {
        self.storage.client_manager.get(name)
    }

    // Get mutable reference to account for the client manager name.
    pub fn get_account_mut(&mut self, name: &XorName) -> Option<&mut Account> {
        self.storage.client_manager.get_mut(name)
    }

    // Create account for the given client manager name.
    pub fn insert_account(&mut self, name: XorName) {
        let _ = self.storage.client_manager.insert(name, Account::new());
    }

    // Authorise read (non-mutation) operation.
    pub fn authorise_read(&self, dst: &Authority<XorName>, data_name: &XorName) -> bool {
        match *dst {
            Authority::NaeManager(name) if name == *data_name => true,
            _ => false,
        }
    }

    // Authorise mutation operation.
    pub fn authorise_mutation(&self,
                              dst: &Authority<XorName>,
                              sign_pk: &sign::PublicKey)
                              -> Result<(), ClientError> {
        let dst_name = match *dst {
            Authority::ClientManager(name) => name,
            x => {
                println!("Unexpected authority for mutation: {:?}", x);
                return Err(ClientError::InvalidOperation);
            }
        };

        let account = match self.get_account(&dst_name) {
            Some(account) => account,
            None => {
                println!("Account not found for {:?}", dst);
                return Err(ClientError::NoSuchAccount);
            }
        };

        // Check if we are the owner or app.
        let owner_name = XorName(sha3_256(&sign_pk[..]));
        if owner_name != dst_name && !account.auth_keys.contains(sign_pk) {
            println!("Mutation not authorised");
            return Err(ClientError::AccessDenied);
        }

        if account.account_info.mutations_available == 0 {
            return Err(ClientError::LowBalance);
        }

        Ok(())
    }

    // Commit a mutation.
    pub fn commit_mutation(&mut self, dst: &Authority<XorName>) {
        {
            let account = unwrap!(self.get_account_mut(&dst.name()));
            account.increment_mutations_counter();
        }

        self.sync();
    }

    // Check if data with the given name is in the storage.
    pub fn contains_data(&self, name: &DataId) -> bool {
        self.storage.nae_manager.contains_key(name)
    }

    // Load data with the given name from the storage.
    pub fn get_data(&self, name: &DataId) -> Option<Data> {
        self.storage.nae_manager.get(name).cloned()
    }

    // Save the data to the storage.
    pub fn insert_data(&mut self, name: DataId, data: Data) {
        let _ = self.storage.nae_manager.insert(name, data);
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub enum Data {
    Immutable(ImmutableData),
    Mutable(MutableData),
}

#[derive(Deserialize, Serialize)]
pub struct Account {
    account_info: AccountInfo,
    auth_keys: BTreeSet<sign::PublicKey>,
    version: u64,
}

impl Account {
    pub fn new() -> Self {
        Account {
            account_info: AccountInfo {
                mutations_done: 0,
                mutations_available: DEFAULT_MAX_MUTATIONS,
            },
            auth_keys: Default::default(),
            version: 0,
        }
    }

    pub fn version(&self) -> u64 {
        self.version
    }

    pub fn account_info(&self) -> &AccountInfo {
        &self.account_info
    }

    // Insert new auth key and bump the version. Returns false if the given version
    // is not one more than the current version.
    pub fn ins_auth_key(&mut self, key: sign::PublicKey, version: u64) -> Result<(), ClientError> {
        self.validate_version(version)?;

        let _ = self.auth_keys.insert(key);
        self.version = version;
        Ok(())
    }

    // Remove the auth key and bump the version. Returns false if the given version
    // is not one more than the current version.
    pub fn del_auth_key(&mut self, key: &sign::PublicKey, version: u64) -> Result<(), ClientError> {
        self.validate_version(version)?;

        if self.auth_keys.remove(key) {
            self.version = version;
            Ok(())
        } else {
            Err(ClientError::NoSuchKey)
        }
    }

    pub fn auth_keys(&self) -> &BTreeSet<sign::PublicKey> {
        &self.auth_keys
    }

    pub fn increment_mutations_counter(&mut self) {
        self.account_info.mutations_done += 1;
        self.account_info.mutations_available -= 1;
        self.version += 1;
    }

    fn validate_version(&self, version: u64) -> Result<(), ClientError> {
        if version == self.version + 1 {
            Ok(())
        } else {
            Err(ClientError::InvalidSuccessor)
        }
    }
}

#[cfg(test)]
mod sync {
    use super::Vault;

    impl Vault {
        pub fn load(&mut self) -> bool {
            false
        }

        pub fn sync(&mut self) {}
    }
}

#[cfg(not(test))]
mod sync {
    use super::{InnerVault, Vault};
    use maidsafe_utilities::serialisation::{deserialise, serialise};
    use std::env;
    use std::fs::File;
    use std::io::{Read, Write};
    use std::path::PathBuf;
    use std::time::Duration;

    const FILE_NAME: &'static str = "MockVault";

    fn path() -> PathBuf {
        env::temp_dir().join(FILE_NAME)
    }

    impl Vault {
        pub fn load(&mut self) -> bool {
            if let Ok(mut file) = File::open(path()) {
                let mtime = unwrap!(unwrap!(file.metadata()).modified());
                let mtime_duration = mtime
                    .duration_since(self.sync_time)
                    .unwrap_or(Duration::from_millis(1));

                if mtime_duration.as_secs() == 0 && mtime_duration.subsec_nanos() == 0 {
                    // Don't update vault if it's already synchronised
                    return false;
                }

                let mut raw_disk_data = Vec::with_capacity(unwrap!(file.metadata()).len() as usize);
                if file.read_to_end(&mut raw_disk_data).is_ok() && !raw_disk_data.is_empty() {
                    if let Ok(storage) = deserialise::<InnerVault>(&raw_disk_data) {
                        self.storage = storage;
                        self.sync_time = mtime;
                        return true;
                    }
                }
            }

            false
        }

        pub fn sync(&mut self) {
            let mut file = unwrap!(File::create(path()));
            let _ = file.write_all(&unwrap!(serialise(&self.storage)));
            unwrap!(file.sync_all());

            let mtime = unwrap!(unwrap!(file.metadata()).modified());
            self.sync_time = mtime;
        }
    }
}
