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

use routing::{AccountInfo, Authority, ImmutableData, MutableData, XorName};
use rust_sodium::crypto::hash::sha256;
use rust_sodium::crypto::sign;
use std::collections::{HashMap, HashSet};

pub const DEFAULT_MAX_MUTATIONS: u64 = 100;

#[derive(RustcDecodable, RustcEncodable)]
pub struct Vault {
    client_manager: HashMap<XorName, Account>,
    nae_manager: HashMap<XorName, Data>,
}

impl Vault {
    pub fn new() -> Self {
        sync::load().unwrap_or_else(|| {
            Vault {
                client_manager: HashMap::new(),
                nae_manager: HashMap::new(),
            }
        })
    }

    // Get account for the client manager name.
    pub fn get_account(&self, name: &XorName) -> Option<&Account> {
        self.client_manager.get(name)
    }

    // Create account for the given client manager name.
    pub fn insert_account(&mut self, name: XorName) {
        let _ = self.client_manager.insert(name, Account::new());
    }

    // Increment the counter of mutation operations in the account under the given name.
    pub fn increment_account_mutations_counter(&mut self, name: &XorName) -> bool {
        if let Some(account) = self.client_manager.get_mut(name) {
            account.account_info.mutations_done += 1;
            account.account_info.mutations_available -= 1;

            true
        } else {
            false
        }
    }

    pub fn ins_account_auth_key(&mut self, name: &XorName, key: sign::PublicKey) -> bool {
        if let Some(account) = self.client_manager.get_mut(name) {
            account.ins_auth_key(key);
            true
        } else {
            false
        }
    }

    // Authorise read (non-mutation) operation.
    pub fn authorise_read(&self, dst: &Authority, data_name: &XorName) -> bool {
        match *dst {
            Authority::NaeManager(name) if name == *data_name => true,
            _ => false,
        }
    }

    // Authorise mutation operation.
    pub fn authorise_mutation(&self, dst: &Authority, sign_pk: &sign::PublicKey) -> bool {
        let dst_name = match *dst {
            Authority::ClientManager(name) => name,
            x => {
                println!("Unexpected authority for mutation: {:?}", x);
                return false;
            }
        };

        let account = match self.get_account(&dst_name) {
            Some(account) => account,
            None => {
                println!("Account not found for {:?}", dst);
                return false;
            }
        };

        // Check if we are the owner or app.
        let owner_name = XorName(sha256::hash(&sign_pk[..]).0);
        if owner_name == dst_name || account.auth_keys.contains(sign_pk) {
            true
        } else {
            println!("Mutation not authorised");
            false
        }
    }

    // Check if data with the given name is in the storage.
    pub fn contains_data(&self, name: &XorName) -> bool {
        self.nae_manager.contains_key(name)
    }

    // Load data with the given name from the storage.
    pub fn get_data(&self, name: &XorName) -> Option<Data> {
        self.nae_manager.get(name).cloned()
    }

    // Save the data to the storage.
    pub fn insert_data(&mut self, name: XorName, data: Data) {
        let _ = self.nae_manager.insert(name, data);
    }

    // Synchronize the storage with the disk.
    pub fn sync(&self) {
        sync::save(self)
    }
}

#[derive(Clone, RustcDecodable, RustcEncodable)]
pub enum Data {
    Immutable(ImmutableData),
    Mutable(MutableData),
}

#[derive(RustcDecodable, RustcEncodable)]
pub struct Account {
    account_info: AccountInfo,
    auth_keys: HashSet<sign::PublicKey>,
}

impl Account {
    pub fn new() -> Self {
        Account {
            account_info: AccountInfo {
                mutations_done: 0,
                mutations_available: DEFAULT_MAX_MUTATIONS,
            },
            auth_keys: HashSet::new(),
        }
    }

    pub fn account_info(&self) -> &AccountInfo {
        &self.account_info
    }

    pub fn ins_auth_key(&mut self, key: sign::PublicKey) {
        let _ = self.auth_keys.insert(key);
    }
}

#[cfg(test)]
mod sync {
    use super::Vault;

    pub fn load() -> Option<Vault> {
        None
    }

    pub fn save(_: &Vault) {}
}

#[cfg(not(test))]
mod sync {
    use maidsafe_utilities::serialisation::{deserialise, serialise};
    use std::env;
    use std::fs::File;
    use std::io::{Read, Write};
    use std::path::PathBuf;
    use super::Vault;

    const FILE_NAME: &'static str = "MockVault";

    pub fn load() -> Option<Vault> {
        if let Ok(mut file) = File::open(path()) {
            let mut raw_disk_data = Vec::with_capacity(unwrap!(file.metadata()).len() as usize);
            if file.read_to_end(&mut raw_disk_data).is_ok() && !raw_disk_data.is_empty() {
                return deserialise(&raw_disk_data).ok();
            }
        }

        None
    }

    pub fn save(vault: &Vault) {
        let mut file = unwrap!(File::create(path()));
        let _ = file.write_all(&unwrap!(serialise(vault)));
        unwrap!(file.sync_all());
    }

    fn path() -> PathBuf {
        env::temp_dir().join(FILE_NAME)
    }
}
