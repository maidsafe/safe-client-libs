// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::client::mock::routing::unlimited_muts;
use crate::config_handler::Config;
use routing::{AccountInfo, ClientError};
use rust_sodium::crypto::sign;
use std::collections::BTreeSet;

pub const DEFAULT_MAX_MUTATIONS: u64 = 1000;

#[derive(Deserialize, Serialize)]
pub struct Account {
    account_info: AccountInfo,
    auth_keys: BTreeSet<sign::PublicKey>,
    version: u64,
    config: Config,
}

impl Account {
    pub fn new(config: Config) -> Self {
        Account {
            account_info: AccountInfo {
                mutations_done: 0,
                mutations_available: DEFAULT_MAX_MUTATIONS,
            },
            auth_keys: Default::default(),
            version: 0,
            config,
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
        // Decrement mutations available, unless we're at 0 and we have unlimited mutations.
        let unlimited_muts = unlimited_muts(&self.config);
        if self.account_info.mutations_available > 0 && !unlimited_muts {
            self.account_info.mutations_available -= 1;
        }
        self.version += 1;
    }

    fn validate_version(&self, version: u64) -> Result<(), ClientError> {
        if version == self.version + 1 {
            Ok(())
        } else {
            Err(ClientError::InvalidSuccessor(self.version))
        }
    }
}
