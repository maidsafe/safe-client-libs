// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod adata;
mod client;
mod coins;
mod idata;
mod login_packet;
mod mdata;
mod sdata;

use super::DataId;
use super::{Account, CoinBalance};
use crate::client::mock::connection_manager::unlimited_coins;
use crate::client::COST_OF_PUT;
use crate::config_handler::{Config, DevConfig};
use bincode::{deserialize, serialize};
use fs2::FileExt;
use futures::lock::{Mutex, MutexGuard};
use log::{debug, trace, warn};
use safe_nd::{
    verify_signature, Coins, Data, Error as SndError, LoginPacket, Message, PublicId, PublicKey,
    Request, RequestType, Result as SndResult, Transaction, XorName,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::fs::File;
#[cfg(not(test))]
use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::ops::{Deref, DerefMut};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use std::time::SystemTime;
#[cfg(test)]
use tempfile::tempfile;
use unwrap::unwrap;

const FILE_NAME: &str = "SCL-Mock";

pub struct Vault {
    cache: Cache,
    config: Config,
    store: Box<dyn Store>,
}

// Initializes mock-vault path with the following precedence:
// 1. "SAFE_MOCK_VAULT_PATH" env var
// 2. DevConfig `mock_vault_path` option
// 3. default temp dir
fn init_vault_path(devconfig: Option<&DevConfig>) -> PathBuf {
    match env::var("SAFE_MOCK_VAULT_PATH") {
        Ok(path) => PathBuf::from(path),
        Err(_) => match devconfig.and_then(|dev| dev.mock_vault_path.clone()) {
            Some(path) => PathBuf::from(path),
            None => env::temp_dir(),
        },
    }
}

// Initializes vault storage. The type of storage is chosen with the following precedence:
// 1.  "SAFE_MOCK_IN_MEMORY_STORAGE" env var => in-memory storage
// 2.  DevConfig `mock_in_memory_storage` option => in-memory storage
// 3a. Else (not test) => file storage, use path from `init_vault_path`
// 3b. Else (test) => file storage, use random temporary file
fn init_vault_store(config: &Config) -> Box<dyn Store> {
    match env::var("SAFE_MOCK_IN_MEMORY_STORAGE") {
        Ok(_) => {
            // If the env var is set, override config file option.
            trace!("Mock vault: using memory store");
            Box::new(MemoryStore)
        }
        Err(_) => match config.dev {
            Some(ref dev) if dev.mock_in_memory_storage => {
                trace!("Mock vault: using memory store");
                Box::new(MemoryStore)
            }
            Some(ref dev) => {
                trace!("Mock vault: using file store");
                Box::new(FileStore::new(&init_vault_path(Some(dev))))
            }
            #[cfg(not(test))]
            None => {
                trace!("Mock vault: using file store");
                Box::new(FileStore::new(&init_vault_path(None)))
            }
            #[cfg(test)]
            None => {
                trace!("Mock vault: using temporary file store");
                Box::new(FileStore::new_with_temp())
            }
        },
    }
}

pub(crate) enum Operation {
    TransferCoins,
    Mutation,
    GetBalance,
}

impl Vault {
    pub fn new(config: Config) -> Self {
        let store = init_vault_store(&config);

        Vault {
            cache: Cache {
                coin_balances: HashMap::new(),
                client_manager: HashMap::new(),
                login_packets: HashMap::new(),
                nae_manager: HashMap::new(),
            },
            config,
            store,
        }
    }

    // Get account for the client manager name.
    pub fn get_account(&self, name: &XorName) -> Option<&Account> {
        self.cache.client_manager.get(name)
    }

    // Get mutable reference to account for the client manager name.
    pub fn get_account_mut(&mut self, name: &XorName) -> Option<&mut Account> {
        self.cache.client_manager.get_mut(name)
    }

    // Get coin balance for the client manager name.
    pub fn get_coin_balance(&self, name: &XorName) -> Option<&CoinBalance> {
        self.cache.coin_balances.get(name)
    }

    // Get mutable reference to account for the client manager name.
    pub fn get_coin_balance_mut(&mut self, name: &XorName) -> Option<&mut CoinBalance> {
        self.cache.coin_balances.get_mut(name)
    }

    // Create account for the given client manager name.
    pub fn insert_account(&mut self, name: XorName) {
        let _ = self
            .cache
            .client_manager
            .insert(name, Account::new(self.config.clone()));
    }

    pub fn insert_login_packet(&mut self, login_packet: LoginPacket) {
        let _ = self
            .cache
            .login_packets
            .insert(*login_packet.destination(), login_packet);
    }

    pub fn get_login_packet(&self, name: &XorName) -> Option<&LoginPacket> {
        self.cache.login_packets.get(name)
    }

    /// Instantly creates new balance.
    pub fn mock_create_balance(&mut self, owner: PublicKey, amount: Coins) {
        let _ = self
            .cache
            .coin_balances
            .insert(owner.into(), CoinBalance::new(amount, owner));
    }

    /// Increment coin balance for testing
    pub fn mock_increment_balance(
        &mut self,
        coin_balance_name: &XorName,
        amount: Coins,
    ) -> SndResult<()> {
        let balance = match self.get_coin_balance_mut(coin_balance_name) {
            Some(balance) => balance,
            None => {
                debug!("Balance not found for {:?}", coin_balance_name);
                return Err(SndError::NoSuchBalance);
            }
        };
        balance.credit_balance(amount, rand::random())
    }

    pub(crate) fn get_balance(&self, coins_balance_id: &XorName) -> SndResult<Coins> {
        self.get_coin_balance(&coins_balance_id).map_or_else(
            || {
                debug!("Coin balance {:?} not found", coins_balance_id);
                Err(SndError::NoSuchBalance)
            },
            |bal| Ok(bal.balance()),
        )
    }

    // Checks if the given balance has sufficient coins for the given `amount` of Operation.
    pub(crate) fn has_sufficient_balance(&self, balance: Coins, amount: Coins) -> bool {
        unlimited_coins(&self.config) || balance.checked_sub(amount).is_some()
    }

    // Authorises coin transfers, mutations and get balance operations.
    pub(crate) fn authorise_operations(
        &self,
        operations: &[Operation],
        owner: XorName,
        requester_pk: PublicKey,
    ) -> Result<(), SndError> {
        let requester = XorName::from(requester_pk);
        let balance = self.get_balance(&owner)?;
        // Checks if the requester is the owner
        if owner == requester {
            for operation in operations {
                // Mutation operations must be checked for min COST_OF_PUT balance
                if let Operation::Mutation = operation {
                    if !self.has_sufficient_balance(balance, COST_OF_PUT) {
                        return Err(SndError::InsufficientBalance);
                    }
                }
            }
            return Ok(());
        }
        // Fetches the account of the owner
        let account = self.get_account(&owner).ok_or_else(|| {
            debug!("Account not found for {:?}", owner);
            SndError::AccessDenied
        })?;
        // Fetches permissions granted to the application
        let perms = account.auth_keys().get(&requester_pk).ok_or_else(|| {
            debug!("App not authorised");
            SndError::AccessDenied
        })?;
        // Iterates over the list of operations requested to authorise.
        // Will fail to authorise any even if one of the requested operations had been denied.
        for operation in operations {
            match operation {
                Operation::TransferCoins => {
                    if !perms.transfer_coins {
                        debug!("Transfer coins not authorised");
                        return Err(SndError::AccessDenied);
                    }
                }
                Operation::GetBalance => {
                    if !perms.get_balance {
                        debug!("Reading balance not authorised");
                        return Err(SndError::AccessDenied);
                    }
                }
                Operation::Mutation => {
                    if !perms.perform_mutations {
                        debug!("Performing mutations not authorised");
                        return Err(SndError::AccessDenied);
                    }
                    if !self.has_sufficient_balance(balance, COST_OF_PUT) {
                        return Err(SndError::InsufficientBalance);
                    }
                }
            }
        }
        Ok(())
    }

    // Commit a mutation.
    pub fn commit_mutation(&mut self, account: &XorName) {
        if !unlimited_coins(&self.config) {
            let balance = unwrap!(self.get_coin_balance_mut(account));
            // Cannot fail - Balance is checked before
            unwrap!(balance.debit_balance(COST_OF_PUT));
        }
    }

    // Check if data with the given name is in the storage.
    pub fn contains_data(&self, name: &DataId) -> bool {
        self.cache.nae_manager.contains_key(name)
    }

    // Load data with the given name from the storage.
    pub fn get_data(&self, name: &DataId) -> Option<Data> {
        self.cache.nae_manager.get(name).cloned()
    }

    // Save the data to the storage.
    pub fn insert_data(&mut self, name: DataId, data: Data) {
        let _ = self.cache.nae_manager.insert(name, data);
    }

    // Delete the data from the storage.
    pub fn delete_data(&mut self, name: DataId) {
        let _ = self.cache.nae_manager.remove(&name);
    }

    pub(crate) fn create_balance(
        &mut self,
        destination: XorName,
        owner: PublicKey,
    ) -> SndResult<()> {
        if self.get_coin_balance(&destination).is_some() {
            return Err(SndError::BalanceExists);
        }
        let _ = self
            .cache
            .coin_balances
            .insert(destination, CoinBalance::new(Coins::from_nano(0), owner));
        Ok(())
    }

    pub(crate) fn transfer_coins(
        &mut self,
        source: XorName,
        destination: XorName,
        amount: Coins,
        transaction_id: u64,
    ) -> SndResult<Transaction> {
        let unlimited = unlimited_coins(&self.config);
        match self.get_coin_balance_mut(&source) {
            Some(balance) => {
                if !unlimited {
                    balance.debit_balance(amount)?
                }
            }
            None => return Err(SndError::NoSuchBalance),
        };
        match self.get_coin_balance_mut(&destination) {
            Some(balance) => balance.credit_balance(amount, transaction_id)?,
            None => return Err(SndError::NoSuchBalance),
        };
        Ok(Transaction {
            id: transaction_id,
            amount,
        })
    }

    pub fn process_request(
        &mut self,
        requester: PublicId,
        message: &Message,
    ) -> SndResult<Message> {
        let (request, message_id, signature) = if let Message::Request {
            request,
            message_id,
            signature,
        } = message
        {
            (request, *message_id, signature)
        } else {
            return Err(SndError::from("Unexpected Message type"));
        };

        // Get the requester's public key.
        let result = match &requester {
            PublicId::App(pk) => Ok((true, *pk.public_key(), *pk.owner().public_key())),
            PublicId::Client(pk) => Ok((false, *pk.public_key(), *pk.public_key())),
            PublicId::Node(_) => Err(SndError::AccessDenied),
        }
        .and_then(|(is_app, requester_pk, owner_pk)| {
            let request_type = request.get_type();

            match request_type {
                RequestType::PrivateGet | RequestType::Mutation | RequestType::Transaction => {
                    // For apps, check if its public key is listed as an auth key.
                    if is_app {
                        let auth_keys = self
                            .get_account(&requester.name())
                            .map(|account| (account.auth_keys().clone()))
                            .unwrap_or_else(Default::default);

                        if !auth_keys.contains_key(&requester_pk) {
                            return Err(SndError::AccessDenied);
                        }
                    }

                    // Verify signature if the request is not a GET for public data.
                    match signature {
                        Some(sig) => verify_signature(&sig, &requester_pk, &request, &message_id)?,
                        None => return Err(SndError::InvalidSignature),
                    }
                }
                RequestType::PublicGet => (),
            }

            Ok((requester_pk, owner_pk))
        });

        // Return errors as a response message corresponding to the incoming request message.
        let (requester_pk, owner_pk) = match result {
            Ok(s) => s,
            Err(err) => {
                let response = request.error_response(err);
                return Ok(Message::Response {
                    response,
                    message_id,
                });
            }
        };

        let response = match request {
            Request::IData(req) => self.process_idata_req(req, requester, requester_pk, owner_pk),
            Request::MData(req) => self.process_mdata_req(req, requester, requester_pk, owner_pk),
            Request::AData(req) => self.process_adata_req(req, requester, requester_pk, owner_pk),
            Request::SData(req) => self.process_sdata_req(req, requester, requester_pk, owner_pk),
            Request::Client(req) => self.process_client_req(req, requester, requester_pk, owner_pk),
            Request::Coins(req) => self.process_coins_req(req, requester_pk, owner_pk),
            Request::LoginPacket(req) => self.process_login_packet_req(req, requester_pk, owner_pk),
        };

        Ok(Message::Response {
            response,
            message_id,
        })
    }

    pub fn put_data(
        &mut self,
        data_name: DataId,
        data: Data,
        requester: PublicId,
    ) -> SndResult<()> {
        let (name, key) = match requester.clone() {
            PublicId::Client(client_public_id) => {
                (*client_public_id.name(), *client_public_id.public_key())
            }
            PublicId::App(app_public_id) => {
                (*app_public_id.owner_name(), *app_public_id.public_key())
            }
            _ => return Err(SndError::AccessDenied),
        };
        self.authorise_operations(&[Operation::Mutation], name, key)?;
        if self.contains_data(&data_name) {
            // Published Immutable Data is de-duplicated
            if let DataId::Immutable(addr) = data_name {
                if addr.is_pub() {
                    self.commit_mutation(&requester.name());
                    return Ok(());
                }
            }
            Err(SndError::DataExists)
        } else {
            self.insert_data(data_name, data);
            self.commit_mutation(&requester.name());
            Ok(())
        }
    }
}

pub struct VaultGuard<'a>(MutexGuard<'a, Vault>);

impl<'a> Deref for VaultGuard<'a> {
    type Target = Vault;
    fn deref(&self) -> &Self::Target {
        self.0.deref()
    }
}

impl<'a> DerefMut for VaultGuard<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0.deref_mut()
    }
}

impl<'a> Drop for VaultGuard<'a> {
    fn drop(&mut self) {
        let vault = &mut *self.0;
        vault.store.save(&vault.cache)
    }
}

pub async fn lock<'a>(vault: &'a Arc<Mutex<Vault>>, writing: bool) -> VaultGuard<'a> {
    let mut inner = vault.lock().await;

    if let Some(cache) = inner.store.load(writing) {
        inner.cache = cache;
    }

    VaultGuard(inner)
}

#[derive(Deserialize, Serialize)]
struct Cache {
    coin_balances: HashMap<XorName, CoinBalance>,
    client_manager: HashMap<XorName, Account>,
    login_packets: HashMap<XorName, LoginPacket>,
    nae_manager: HashMap<DataId, Data>,
}

trait Store: Send {
    fn load(&mut self, writing: bool) -> Option<Cache>;
    fn save(&mut self, cache: &Cache);
}

struct MemoryStore;

impl Store for MemoryStore {
    fn load(&mut self, _: bool) -> Option<Cache> {
        None
    }

    fn save(&mut self, _: &Cache) {}
}

struct FileStore {
    // `bool` element indicates whether the store is being written to.
    file: Option<(File, bool)>,
    sync_time: Option<SystemTime>,
    // The path that we're provided. If we're not provided a path we're going to create a random
    // temporary file.
    path: Option<PathBuf>,
}

impl FileStore {
    fn new(path: &PathBuf) -> Self {
        Self {
            file: None,
            sync_time: None,
            path: Some(path.join(FILE_NAME)),
        }
    }

    #[cfg(test)]
    fn new_with_temp() -> Self {
        Self {
            file: None,
            sync_time: None,
            path: None,
        }
    }
}

impl FileStore {
    #[cfg(not(test))]
    fn open_file(&self) -> File {
        unwrap!(self.path.as_ref().and_then(|ref path| {
            OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(&path)
                .ok()
        }))
    }

    #[cfg(test)]
    fn open_file(&self) -> File {
        if let Some(path) = &self.path {
            // Using File::create here as it creates a new file in write mode if it doesn't exist
            // or truncates if it already exists.
            unwrap!(
                std::fs::File::create(path),
                "Error creating mock vault file"
            )
        } else {
            unwrap!(tempfile())
        }
    }
}

impl Store for FileStore {
    fn load(&mut self, writing: bool) -> Option<Cache> {
        let mut file = self.open_file();

        if writing {
            unwrap!(file.lock_exclusive());
        } else {
            unwrap!(file.lock_shared());
        };

        let metadata = unwrap!(file.metadata());
        let mtime = unwrap!(metadata.modified());
        let mtime_duration = if let Some(sync_time) = self.sync_time {
            mtime
                .duration_since(sync_time)
                .unwrap_or_else(|_| Duration::from_millis(0))
        } else {
            Duration::from_millis(1)
        };

        // Update vault only if it's not already synchronised
        let mut result = None;
        if mtime_duration > Duration::new(0, 0) {
            let mut raw_data = Vec::with_capacity(metadata.len() as usize);
            match file.read_to_end(&mut raw_data) {
                Ok(0) => (),
                Ok(_) => match deserialize::<Cache>(&raw_data) {
                    Ok(cache) => {
                        self.sync_time = Some(mtime);
                        result = Some(cache);
                    }
                    Err(e) => {
                        warn!("Can't read the mock vault: {:?}", e);
                    }
                },
                Err(e) => {
                    warn!("Can't read the mock vault: {:?}", e);
                    return None;
                }
            }
        }

        self.file = Some((file, writing));

        result
    }

    fn save(&mut self, cache: &Cache) {
        // Write the data to the storage file (if in write mode) and remove
        // the lock.
        if let Some((mut file, writing)) = self.file.take() {
            if writing {
                let raw_data = unwrap!(serialize(&cache));
                unwrap!(file.set_len(0));
                let _ = unwrap!(file.seek(SeekFrom::Start(0)));
                unwrap!(file.write_all(&raw_data));
                unwrap!(file.sync_all());

                let mtime = unwrap!(unwrap!(file.metadata()).modified());
                self.sync_time = Some(mtime);
            }

            let _ = file.unlock();
        }
    }
}

/// Path to the mock vault store file.
pub fn mock_vault_path(config: &Config) -> PathBuf {
    init_vault_path(config.dev.as_ref()).join(FILE_NAME)
}
