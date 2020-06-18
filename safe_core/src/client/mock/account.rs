// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::config_handler::Config;
use safe_nd::{AppPermissions, Error, Money, PublicKey, TransferId};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};

pub const DEFAULT_MAX_CREDITS: usize = 100;
// pub const DEFAULT_COINS: &str = "100";

#[derive(Deserialize, Serialize)]
pub struct AccountBalance {
    owner: PublicKey,
    value: Money,
    credits: VecDeque<Credit>,
}

impl AccountBalance {
    pub fn new(value: Money, owner: PublicKey) -> Self {
        Self {
            owner,
            value,
            credits: VecDeque::new(),
        }
    }

    pub fn credit_balance(&mut self, amount: Money, transfer_id: TransferId) -> Result<(), Error> {
        if let Some(new_balance) = self.value.checked_add(amount) {
            self.value = new_balance;
            self.add_transfer_id(amount, transfer_id);
            Ok(())
        } else {
            Err(Error::ExcessiveValue)
        }
    }

    pub fn debit_balance(&mut self, amount: Money) -> Result<(), Error> {
        println!(
            "DEBITTTTTTTTTTTTTTTTTTTTTTT of, {:?} from {:?}",
            amount, self.value
        );
        if let Some(new_balance) = self.value.checked_sub(amount) {
            self.value = new_balance;
            Ok(())
        } else {
            Err(Error::InsufficientBalance)
        }
    }

    pub fn balance(&self) -> Money {
        self.value
    }

    fn add_transfer_id(&mut self, amount: Money, transfer_id: TransferId) {
        if self.credits.len() == DEFAULT_MAX_CREDITS {
            let _ = self.credits.pop_back();
        }
        let credit = Credit {
            amount,
            transfer_id,
        };
        self.credits.push_front(credit);
    }
}

#[derive(Deserialize, Serialize)]
pub struct Credit {
    amount: Money,
    transfer_id: TransferId, // TODO: use Uuid
}

#[derive(Deserialize, Serialize)]
pub struct Account {
    auth_keys: BTreeMap<PublicKey, AppPermissions>,
    version: u64,
    config: Config,
}

impl Account {
    pub fn new(config: Config) -> Self {
        Account {
            auth_keys: Default::default(),
            version: 0,
            config,
        }
    }

    pub fn version(&self) -> u64 {
        self.version
    }

    // Insert new auth key and bump the version. Returns false if the given version
    // is not one more than the current version.
    pub fn ins_auth_key(
        &mut self,
        key: PublicKey,
        permissions: AppPermissions,
        version: u64,
    ) -> Result<(), Error> {
        self.validate_version(version)?;

        let _ = self.auth_keys.insert(key, permissions);
        self.version = version;
        Ok(())
    }

    // Remove the auth key and bump the version. Returns false if the given version
    // is not one more than the current version.
    pub fn del_auth_key(&mut self, key: &PublicKey, version: u64) -> Result<(), Error> {
        self.validate_version(version)?;

        if self.auth_keys.remove(key).is_some() {
            self.version = version;
            Ok(())
        } else {
            Err(Error::NoSuchKey)
        }
    }

    pub fn auth_keys(&self) -> &BTreeMap<PublicKey, AppPermissions> {
        &self.auth_keys
    }

    fn validate_version(&self, version: u64) -> Result<(), Error> {
        if version == self.version + 1 {
            Ok(())
        } else {
            Err(Error::InvalidSuccessor(self.version))
        }
    }
}
