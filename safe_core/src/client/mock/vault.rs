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
use routing::{Authority, ClientError, ImmutableData, MutableData as OldMutableData, XorName};
use rust_sodium::crypto::sign;
use safe_nd::mutable_data::{
    Action, MutableData as NewMutableData, MutableDataRef, SeqMutableData, UnseqMutableData,
};
use safe_nd::request::{Request, Requester};
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

    pub fn verify_requester(
        &self,
        data_name: DataId,
        requester: Requester,
    ) -> Result<(), ClientError> {
        // FIXME: Handle permissions properly
        let public_key_res = match requester {
            Requester::Owner(_) => Err(ClientError::AccessDenied),
            Requester::Key(key) => Ok(key),
        };
        let public_key = unwrap!(public_key_res);
        match self.get_data(&data_name) {
            Some(data_type) => match data_type {
                Data::NewMutable(data) => match data.clone() {
                    MutableDataKind::Sequenced(mdata) => {
                        if mdata.is_action_allowed(public_key, Action::Read) {
                            Ok(())
                        } else {
                            Err(ClientError::AccessDenied)
                        }
                    }
                    MutableDataKind::Unsequenced(mdata) => {
                        if mdata.is_action_allowed(public_key, Action::Read) {
                            Ok(())
                        } else {
                            Err(ClientError::AccessDenied)
                        }
                    }
                },
                // Handle other types
                _ => Err(ClientError::NoSuchData),
            },
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
        let request: Request = unwrap!(deserialise(&payload));
        dbg!(request.clone());
        match request {
            Request::PutUnseqMData {
                data,
                requester,
                message_id,
            } => {
                let result =
                    self.put_mdata(dest, MutableDataKind::Unsequenced(data.clone()), requester);
                let payload = unwrap!(serialise(&Response::PutUnseqMData {
                    res: result,
                    msg_id: message_id,
                }));
                Ok((Authority::NaeManager(XorName(*data.name())), payload))
            }
            Request::GetSeqMData {
                address,
                requester,
                message_id,
            } => {
                let result = self
                    .get_mdata(dest, address.clone(), requester)
                    .and_then(|data| match data {
                        MutableDataKind::Sequenced(data) => Ok(data),
                        _ => Err(ClientError::from("Unexpected data returned")),
                    });
                let payload = unwrap!(serialise(&Response::GetSeqMData {
                    res: result,
                    msg_id: message_id,
                }));
                Ok((dest, payload))
            }
            Request::GetUnseqMData {
                address,
                requester,
                message_id,
            } => {
                let result = self
                    .get_mdata(dest, address.clone(), requester)
                    .and_then(|data| match data {
                        MutableDataKind::Unsequenced(mdata) => Ok(mdata),
                        _ => Err(ClientError::from("Unexpected data returned")),
                    });
                let payload = unwrap!(serialise(&Response::GetUnseqMData {
                    res: result,
                    msg_id: message_id,
                }));
                Ok((dest, payload))
            }
            Request::PutSeqMData {
                data,
                requester,
                message_id,
            } => {
                let result =
                    self.put_mdata(dest, MutableDataKind::Sequenced(data.clone()), requester);
                let payload = unwrap!(serialise(&Response::PutSeqMData {
                    res: result,
                    msg_id: message_id
                }));
                Ok((Authority::NaeManager(XorName(*data.name())), payload))
            }
            Request::GetSeqMDataShell {
                address,
                requester,
                message_id,
            } => {
                let result = self
                    .get_mdata(dest, address, requester)
                    .and_then(|data| match data {
                        MutableDataKind::Sequenced(mdata) => Ok(mdata.shell()),
                        _ => Err(ClientError::from("Unexpected data returned")),
                    });
                let payload = unwrap!(serialise(&Response::GetSeqMDataShell {
                    res: result,
                    msg_id: message_id
                }));
                Ok((dest, payload))
            }
            Request::GetUnseqMDataShell {
                address,
                requester,
                message_id,
            } => {
                let result = self
                    .get_mdata(dest, address, requester)
                    .and_then(|data| match data {
                        MutableDataKind::Unsequenced(mdata) => Ok(mdata.shell()),
                        _ => Err(ClientError::from("Unexpected data returned")),
                    });
                let payload = unwrap!(serialise(&Response::GetUnseqMDataShell {
                    res: result,
                    msg_id: message_id
                }));
                Ok((dest, payload))
            }
            Request::GetMDataVersion {
                address,
                requester,
                message_id,
            } => {
                let result = self
                    .get_mdata(dest, address, requester)
                    .and_then(|data| match data {
                        MutableDataKind::Sequenced(mdata) => Ok(mdata.version()),
                        MutableDataKind::Unsequenced(mdata) => Ok(mdata.version()),
                    });
                let payload = unwrap!(serialise(&Response::GetMDataVersion {
                    res: result,
                    msg_id: message_id
                }));
                Ok((dest, payload))
            }
            Request::ListUnseqMDataEntries {
                address,
                requester,
                message_id,
            } => {
                let result = self
                    .get_mdata(dest, address.clone(), requester)
                    .and_then(|data| match data {
                        MutableDataKind::Unsequenced(mdata) => Ok(mdata.entries().clone()),
                        _ => Err(ClientError::from("Unexpected data returned")),
                    });
                let payload = unwrap!(serialise(&Response::ListUnseqMDataEntries {
                    res: result,
                    msg_id: message_id
                }));
                Ok((dest, payload))
            }
            Request::ListSeqMDataEntries {
                address,
                requester,
                message_id,
            } => {
                let result = self
                    .get_mdata(dest, address.clone(), requester)
                    .and_then(|data| match data {
                        MutableDataKind::Sequenced(mdata) => Ok(mdata.entries().clone()),
                        _ => Err(ClientError::from("Unexpected data returned")),
                    });
                let payload = unwrap!(serialise(&Response::ListSeqMDataEntries {
                    res: result,
                    msg_id: message_id
                }));
                Ok((dest, payload))
            }
            Request::ListMDataKeys {
                address,
                requester,
                message_id,
            } => {
                let result = self
                    .get_mdata(dest, address.clone(), requester)
                    .and_then(|data| match data {
                        MutableDataKind::Sequenced(mdata) => Ok(mdata.keys().clone()),
                        MutableDataKind::Unsequenced(mdata) => Ok(mdata.keys().clone()),
                    });
                let payload = unwrap!(serialise(&Response::ListMDataKeys {
                    res: result,
                    msg_id: message_id
                }));
                Ok((dest, payload))
            }
            Request::ListSeqMDataValues {
                address,
                requester,
                message_id,
            } => {
                let result = self
                    .get_mdata(dest, address.clone(), requester)
                    .and_then(|data| match data {
                        MutableDataKind::Sequenced(mdata) => Ok(mdata.values()),
                        _ => Err(ClientError::from("Unexpected data returned")),
                    });
                let payload = unwrap!(serialise(&Response::ListSeqMDataValues {
                    res: result,
                    msg_id: message_id
                }));
                Ok((dest, payload))
            }
            Request::ListUnseqMDataValues {
                address,
                requester,
                message_id,
            } => {
                let result = self
                    .get_mdata(dest, address.clone(), requester)
                    .and_then(|data| match data {
                        MutableDataKind::Unsequenced(mdata) => Ok(mdata.values()),
                        _ => Err(ClientError::from("Unexpected data returned")),
                    });
                let payload = unwrap!(serialise(&Response::ListUnseqMDataValues {
                    res: result,
                    msg_id: message_id
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

    pub fn get_mdata(
        &mut self,
        dst: Authority<XorName>,
        address: MutableDataRef,
        requester: Requester,
    ) -> Result<MutableDataKind, ClientError> {
        let data_name = DataId::mutable(XorName(address.name()), address.tag());
        self.authorise_read(&dst, &XorName(address.name()))
            .and_then(|_| self.verify_requester(data_name, requester))
            .and_then(|_| match self.get_data(&data_name) {
                Some(data_type) => match data_type {
                    Data::NewMutable(data) => Ok(data),
                    _ => Err(ClientError::NoSuchData),
                },
                None => Err(ClientError::NoSuchData),
            })
    }

    pub fn put_mdata(
        &mut self,
        dst: Authority<XorName>,
        data: MutableDataKind,
        _requester: Requester,
    ) -> Result<(), ClientError> {
        let data_name = DataId::mutable(data.name(), data.tag());
        /*
        self.authorise_mutation(&dst, &requester)
            .and_then(|_| {
                if self.contains_data(&data_name) {
                    Err(ClientError::DataExists)
                } else {
                    self.insert_data(data_name, Data::NewMutable(data));
                    Ok(())
                }
            })
            .map(|_| self.commit_mutation(&dst))
        */
        // FIXME: Put requests verify the app's public key - Usage of BLS-key TBD
        if self.contains_data(&data_name) {
            Err(ClientError::DataExists)
        } else {
            self.insert_data(data_name, Data::NewMutable(data));
            self.commit_mutation(&dst);
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
    OldMutable(OldMutableData),
    NewMutable(MutableDataKind),
}

#[derive(Clone, Deserialize, Serialize)]
pub enum MutableDataKind {
    Sequenced(SeqMutableData),
    Unsequenced(UnseqMutableData),
}

impl MutableDataKind {
    fn name(&self) -> XorName {
        match self {
            MutableDataKind::Sequenced(data) => XorName(*data.name()),
            MutableDataKind::Unsequenced(data) => XorName(*data.name()),
        }
    }
    fn tag(&self) -> u64 {
        match self {
            MutableDataKind::Sequenced(data) => data.tag(),
            MutableDataKind::Unsequenced(data) => data.tag(),
        }
    }
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
