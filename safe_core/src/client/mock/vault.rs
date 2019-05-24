// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::Account;
use super::DataId;
use crate::client::mock::routing::unlimited_muts;
use crate::config_handler::{Config, DevConfig};
use fs2::FileExt;
use maidsafe_utilities::serialisation::{deserialise, serialise};
use routing::{Authority, ClientError, ImmutableData, MutableData, XorName};
use rust_sodium::crypto::sign;
use safe_nd::mutable_data::{MutableData as SndMutableData, MutableDataRef, Permission, User};
use safe_nd::request::Request;
use safe_nd::response::Response;
use std::collections::HashMap;
use std::env;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::ops::{Deref, DerefMut};
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;
use std::time::SystemTime;
use tiny_keccak::sha3_256;

const FILE_NAME: &str = "MockVault";

pub struct Vault {
    cache: Cache,
    config: Config,
    store: Box<Store>,
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
// 1. "SAFE_MOCK_IN_MEMORY_STORAGE" env var => in-memory storage
// 2. DevConfig `mock_in_memory_storage` option => in-memory storage
// 3. Else => file storage, use path from `init_vault_path`
fn init_vault_store(config: &Config) -> Box<Store> {
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
            None => {
                trace!("Mock vault: using file store");
                Box::new(FileStore::new(&init_vault_path(None)))
            }
        },
    }
}

impl Vault {
    pub fn new(config: Config) -> Self {
        let store = init_vault_store(&config);

        Vault {
            cache: Cache {
                client_manager: HashMap::new(),
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

    // Get the config for this vault.
    pub fn config(&self) -> Config {
        self.config.clone()
    }

    // Create account for the given client manager name.
    pub fn insert_account(&mut self, name: XorName) {
        let _ = self
            .cache
            .client_manager
            .insert(name, Account::new(self.config.clone()));
    }

    // Authorise read (non-mutation) operation.
    pub fn authorise_read(
        &self,
        dst: &Authority<XorName>,
        data_name: &XorName,
    ) -> Result<(), ClientError> {
        match *dst {
            Authority::NaeManager(name) if name == *data_name => Ok(()),
            x => {
                debug!("Unexpected authority for read: {:?}", x);
                Err(ClientError::InvalidOperation)
            }
        }
    }

    pub fn authorised_read(
        &self,
        data_name: DataId,
        requester: threshold_crypto::PublicKey,
    ) -> Result<SndMutableData, ClientError> {
        match self.get_data(&data_name) {
            Some(Data::UnpublishedMutable(data)) => {
                if data.owners() == requester {
                    Ok(data)
                } else {
                    match data.permissions().get(&User::Key(requester)) {
                        Some(permission_set) => {
                            if permission_set.contains(&Permission::Read) {
                                Ok(data)
                            } else {
                                Err(ClientError::AccessDenied)
                            }
                        }
                        None => match data.permissions().get(&User::Key(requester)) {
                            Some(permission_set) => {
                                if permission_set.contains(&Permission::Read) {
                                    Ok(data)
                                } else {
                                    Err(ClientError::AccessDenied)
                                }
                            }
                            None => Err(ClientError::AccessDenied),
                        },
                    }
                }
            }
            _ => Err(ClientError::NoSuchData),
        }
    }

    // Authorise mutation operation.
    pub fn authorise_mutation(
        &self,
        dst: &Authority<XorName>,
        sign_pk: &sign::PublicKey,
    ) -> Result<(), ClientError> {
        let dst_name = match *dst {
            Authority::ClientManager(name) => name,
            x => {
                debug!("Unexpected authority for mutation: {:?}", x);
                return Err(ClientError::InvalidOperation);
            }
        };

        let account = match self.get_account(&dst_name) {
            Some(account) => account,
            None => {
                debug!("Account not found for {:?}", dst);
                return Err(ClientError::NoSuchAccount);
            }
        };

        // Check if we are the owner or app.
        let owner_name = XorName(sha3_256(&sign_pk[..]));
        if owner_name != dst_name && !account.auth_keys().contains(sign_pk) {
            debug!("Mutation not authorised");
            return Err(ClientError::AccessDenied);
        }

        let unlimited_mut = unlimited_muts(&self.config);
        if !unlimited_mut && account.account_info().mutations_available == 0 {
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

    pub fn process_request(
        &mut self,
        _src: Authority<XorName>,
        dest: Authority<XorName>,
        payload: Vec<u8>,
    ) -> Result<(Authority<XorName>, Vec<u8>), ClientError> {
        let request = unwrap!(deserialise(&payload));
        match request {
            Request::PutUnseqMData {
                data,
                requester,
                message_id,
            } => {
                let result = self.put_unsequenced_mdata(dest, data.clone(), requester);
                let payload = unwrap!(serialise(&Response::PutUnseqMData {
                    res: result,
                    msg_id: message_id,
                }));
                Ok((Authority::NaeManager(XorName(data.name())), payload))
            }
            Request::GetUnseqMData {
                address,
                requester,
                message_id,
            } => {
                let result = self.get_unseq_mdata(dest, address.clone(), requester);
                let payload = unwrap!(serialise(&Response::GetUnseqMData {
                    res: result,
                    msg_id: message_id,
                }));
                Ok((dest, payload))
            }
            _ => {
                // Dummy return
                // other requests to be handled by their data type impls
                Ok((dest, payload))
            }
        }
    }

    pub fn get_unseq_mdata(
        &mut self,
        dst: Authority<XorName>,
        address: MutableDataRef,
        requester: threshold_crypto::PublicKey,
    ) -> Result<SndMutableData, ClientError> {
        let data_name = DataId::mutable(XorName(address.name()), address.tag());
        self.authorise_read(&dst, &XorName(address.name()))
            .and_then(|_| self.authorised_read(data_name, requester))
    }

    pub fn put_unsequenced_mdata(
        &mut self,
        dst: Authority<XorName>,
        data: SndMutableData,
        requester: sign::PublicKey,
    ) -> Result<(), ClientError> {
        // let v = self.clone();
        let data_name = DataId::mutable(XorName(data.name()), data.tag());
        self.authorise_mutation(&dst, &requester)
            // .and_then(|_| Self::verify_owner(&dst, data.owners()))
            .and_then(|_| {
                if self.contains_data(&data_name) {
                    Err(ClientError::DataExists)
                } else {
                    self.insert_data(data_name, Data::UnpublishedMutable(data));
                    Ok(())
                }
            })
            .map(|_| self.commit_mutation(&dst))
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

pub fn lock(vault: &Mutex<Vault>, writing: bool) -> VaultGuard {
    let mut inner = unwrap!(vault.lock());

    if let Some(cache) = inner.store.load(writing) {
        inner.cache = cache;
    }

    VaultGuard(inner)
}

#[derive(Deserialize, Serialize)]
struct Cache {
    client_manager: HashMap<XorName, Account>,
    nae_manager: HashMap<DataId, Data>,
}

#[derive(Clone, Deserialize, Serialize)]
pub enum Data {
    Immutable(ImmutableData),
    Mutable(MutableData),
    UnpublishedMutable(SndMutableData),
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
    path: PathBuf,
}

impl FileStore {
    fn new(path: &PathBuf) -> Self {
        FileStore {
            file: None,
            sync_time: None,
            path: path.join(FILE_NAME),
        }
    }
}

impl Store for FileStore {
    fn load(&mut self, writing: bool) -> Option<Cache> {
        // Create the file if it doesn't exist yet.
        let mut file = unwrap!(OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&self.path));

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
                Ok(_) => match deserialise::<Cache>(&raw_data) {
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
                let raw_data = unwrap!(serialise(&cache));
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
