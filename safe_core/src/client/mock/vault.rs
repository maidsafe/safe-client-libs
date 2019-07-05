// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::DataId;
use super::{Account, CoinBalance};
use crate::client::mock::routing::unlimited_muts;
use crate::config_handler::{Config, DevConfig};
use fs2::FileExt;
use maidsafe_utilities::serialisation::{deserialise, serialise};
use routing::{Authority, ClientError, MutableData as OldMutableData};
use safe_nd::{
    verify_signature, AData, ADataAddress, ADataIndex, AppendOnlyData, Coins, Error as SndError,
    IData, IDataAddress, MData, MDataAddress, MDataKind, Message, MutableData, PublicId, PublicKey,
    Request, Response, SeqAppendOnly, Transaction, UnseqAppendOnly, XorName,
};
use std::collections::HashMap;
use std::env;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::ops::{Deref, DerefMut};
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;
use std::time::SystemTime;

// TODO: Replace this with `Data` from safe-nd
#[derive(Clone, Deserialize, Serialize)]
pub enum Data {
    Immutable(IData),
    OldMutable(OldMutableData),
    NewMutable(MData),
    AppendOnly(AData),
}

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
                coin_balances: HashMap::new(),
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

    // Get coin balance for the client manager name.
    pub fn get_coin_balance(&self, name: &XorName) -> Option<&CoinBalance> {
        self.cache.coin_balances.get(name)
    }

    // Get mutable reference to account for the client manager name.
    pub fn get_coin_balance_mut(&mut self, name: &XorName) -> Option<&mut CoinBalance> {
        self.cache.coin_balances.get_mut(name)
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

    /// Instantly creates new balance.
    pub fn mock_create_balance(
        &mut self,
        coin_balance_name: &XorName,
        amount: Coins,
        owner: PublicKey,
    ) {
        let _ = self
            .cache
            .coin_balances
            .insert(*coin_balance_name, CoinBalance::new(amount, owner));
    }

    /// Increment coin balance for testing
    pub fn mock_increment_balance(
        &mut self,
        coin_balance_name: &XorName,
        amount: Coins,
    ) -> Result<(), SndError> {
        let balance = match self.get_coin_balance_mut(coin_balance_name) {
            Some(balance) => balance,
            None => {
                debug!("Account not found for {:?}", coin_balance_name);
                return Err(SndError::NoSuchAccount);
            }
        };
        balance.credit_balance(amount, new_rand::random())
    }

    // Authorise coin operation.
    pub fn authorise_coin_operation(
        &self,
        coin_balance_name: &XorName,
        requester_pk: PublicKey,
    ) -> Result<(), SndError> {
        // Check if we are the owner or app.
        let balance = match self.get_coin_balance(&coin_balance_name) {
            Some(balance) => balance,
            None => {
                debug!("Coin balance {:?} not found", coin_balance_name);
                return Err(SndError::NoSuchAccount);
            }
        };
        let owner_account = XorName::from(*balance.owner());
        if *balance.owner() == requester_pk {
            Ok(())
        } else {
            let account = match self.get_account(&owner_account) {
                Some(account) => account,
                None => {
                    debug!("Account not found for {:?}", owner_account);
                    return Err(SndError::NoSuchAccount);
                }
            };
            match account.auth_keys().get(&requester_pk) {
                Some(perms) => {
                    if !perms.transfer_coins {
                        debug!("Mutation not authorised");
                        return Err(SndError::AccessDenied);
                    }
                    Ok(())
                }
                None => {
                    debug!("App not found");
                    Err(SndError::AccessDenied)
                }
            }
        }
    }

    // Authorise mutation operation.
    pub fn authorise_mutation(
        &self,
        dst: &Authority<XorName>,
        sign_pk: &PublicKey,
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
        let owner_name = XorName::from(*sign_pk);
        if owner_name != dst_name && !account.auth_keys().contains_key(sign_pk) {
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
    pub fn commit_mutation(&mut self, account: &XorName) {
        {
            let account = unwrap!(self.get_account_mut(account));
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

    // Delete the data from the storage.
    pub fn delete_data(&mut self, name: DataId) {
        let _ = self.cache.nae_manager.remove(&name);
    }

    fn create_coin_balance(
        &mut self,
        destination: XorName,
        owner: PublicKey,
    ) -> Result<(), SndError> {
        if self.get_coin_balance(&destination).is_some() {
            return Err(SndError::AccountExists);
        }
        let _ = self
            .cache
            .coin_balances
            .insert(destination, CoinBalance::new(Coins::from_nano(0)?, owner));
        Ok(())
    }

    fn transfer_coins(
        &mut self,
        source: XorName,
        destination: XorName,
        amount: Coins,
        transaction_id: u64,
    ) -> Result<(), SndError> {
        match self.get_coin_balance_mut(&source) {
            Some(balance) => balance.debit_balance(amount)?,
            None => return Err(SndError::NoSuchAccount),
        };
        match self.get_coin_balance_mut(&destination) {
            Some(balance) => balance.credit_balance(amount, transaction_id)?,
            None => return Err(SndError::NoSuchAccount),
        };
        Ok(())
    }

    fn get_transaction(
        &self,
        coins_balance_id: &XorName,
        transaction_id: u64,
    ) -> Result<Transaction, SndError> {
        match self.get_coin_balance(coins_balance_id) {
            Some(balance) => match balance.find_transaction(transaction_id) {
                Some(amount) => Ok(Transaction::Success(amount)),
                None => Ok(Transaction::NoSuchTransaction),
            },
            None => Ok(Transaction::NoSuchCoinBalance),
        }
    }

    fn get_balance(&self, coins_balance_id: &XorName) -> Result<Coins, SndError> {
        match self.get_coin_balance(coins_balance_id) {
            Some(balance) => Ok(balance.balance()),
            None => Err(SndError::NoSuchAccount),
        }
    }

    pub fn process_request(
        &mut self,
        requester: PublicId,
        payload: Vec<u8>,
    ) -> Result<Message, SndError> {
        let (request, message_id, signature) = if let Message::Request {
            request,
            message_id,
            signature,
        } = unwrap!(deserialise(&payload))
        {
            (request, message_id, signature)
        } else {
            return Err(SndError::from("Unexpected Message type"));
        };

        // Requester's public key
        let (requester_pk, owner_pk) = match requester.clone() {
            PublicId::App(pk) => (*pk.public_key(), *pk.owner().public_key()),
            PublicId::Client(pk) => (*pk.public_key(), *pk.public_key()),
            PublicId::Node(_) => return Err(SndError::AccessDenied),
        };
        let sig = match signature {
            Some(s) => s,
            None => return Err(SndError::InvalidSignature),
        };
        verify_signature(&sig, &requester_pk, &request, &message_id)?;
        let response = match request.clone() {
            //
            // Immutable Data
            //
            Request::GetIData(address) => {
                let result = self.get_idata(address).and_then(|idata| match idata {
                    IData::Unpub(ref data) => {
                        // Check permissions for unpub idata.
                        if *data.owner() == requester_pk {
                            Ok(idata)
                        } else {
                            Err(SndError::AccessDenied)
                        }
                    }
                    IData::Pub(_) => Ok(idata),
                });

                Response::GetIData(result)
            }
            Request::PutIData(idata) => {
                let result = self.put_data(
                    DataId::Immutable(*idata.address()),
                    Data::Immutable(idata),
                    requester,
                );
                Response::Mutation(result)
            }
            Request::DeleteUnpubIData(address) => {
                let result = self.delete_idata(address, requester, requester_pk);
                Response::Mutation(result)
            }
            Request::ListAuthKeysAndVersion => {
                let name = requester.name();
                if let Some(account) = self.get_account(&name) {
                    Response::ListAuthKeysAndVersion(Ok((
                        account.auth_keys().clone(),
                        account.version(),
                    )))
                } else {
                    return Err(SndError::NoSuchAccount);
                }
            }
            Request::InsAuthKey {
                key,
                permissions,
                version,
            } => {
                let name = requester.name();
                if let Some(account) = self.get_account_mut(&name) {
                    Response::Mutation(account.ins_auth_key(key, permissions, version))
                } else {
                    return Err(SndError::NoSuchAccount);
                }
            }
            Request::DelAuthKey { key, version } => {
                let name = requester.name();
                if let Some(account) = self.get_account_mut(&name) {
                    Response::Mutation(account.del_auth_key(&key, version))
                } else {
                    return Err(SndError::NoSuchAccount);
                }
            }
            Request::TransferCoins {
                destination,
                amount,
                transaction_id,
            } => {
                let source: XorName = owner_pk.into();
                if let Err(e) = self.authorise_coin_operation(&source, requester_pk) {
                    Response::Mutation(Err(e))
                } else {
                    let res = self.transfer_coins(source, destination, amount, transaction_id);
                    Response::Mutation(res)
                }
            }
            Request::CreateBalance {
                amount,
                new_balance_owner,
                transaction_id,
            } => {
                let source = owner_pk.into();
                let destination = new_balance_owner.into();
                if let Err(e) = self.authorise_coin_operation(&source, requester_pk) {
                    Response::Mutation(Err(e))
                } else {
                    let res = self
                        .get_balance(&source)
                        .and_then(|source_balance| {
                            if source_balance.checked_sub(amount).is_none() {
                                return Err(SndError::InsufficientBalance);
                            }
                            self.create_coin_balance(destination, new_balance_owner)
                        })
                        .and_then(|_| {
                            self.transfer_coins(source, destination, amount, transaction_id)
                        });
                    Response::Mutation(res)
                }
            }
            Request::GetBalance => {
                let coin_balance_id = owner_pk.into();
                if let Err(e) = self.authorise_coin_operation(&coin_balance_id, requester_pk) {
                    Response::GetBalance(Err(e))
                } else {
                    let res = self.get_balance(&coin_balance_id);
                    Response::GetBalance(res)
                }
            }
            Request::GetTransaction {
                coins_balance_id,
                transaction_id,
            } => {
                let transaction = self.get_transaction(&coins_balance_id, transaction_id);
                Response::GetTransaction(transaction)
            }
            Request::GetMData(address) => {
                let result = self.get_mdata(address, requester_pk, request);

                match (address, result) {
                    (MDataAddress::Seq { .. }, Ok(mdata @ MData::Seq(_)))
                    | (MDataAddress::Unseq { .. }, Ok(mdata @ MData::Unseq(_))) => {
                        Response::GetMData(Ok(mdata))
                    }
                    (MDataAddress::Seq { .. }, Err(err))
                    | (MDataAddress::Unseq { .. }, Err(err)) => Response::GetMData(Err(err)),
                    (MDataAddress::Seq { .. }, Ok(MData::Unseq(_)))
                    | (MDataAddress::Unseq { .. }, Ok(MData::Seq(_))) => {
                        Response::GetMData(Err(SndError::NoSuchData))
                    }
                }
            }
            Request::PutMData(data) => {
                let address = *data.address();
                let result = self.put_data(
                    DataId::Mutable(address),
                    Data::NewMutable(data.clone()),
                    requester,
                );
                Response::Mutation(result)
            }
            Request::GetMDataValue { address, ref key } => {
                let result = self.get_mdata(address, requester_pk, request.clone());

                match (address, result) {
                    (MDataAddress::Seq { .. }, Ok(MData::Seq(mdata))) => {
                        let res = match mdata.get(&key) {
                            Some(value) => Ok(value.clone()),
                            None => Err(SndError::NoSuchEntry),
                        };
                        Response::GetSeqMDataValue(res)
                    }
                    (MDataAddress::Unseq { .. }, Ok(MData::Unseq(mdata))) => {
                        let res = match mdata.get(&key) {
                            Some(value) => Ok(value.clone()),
                            None => Err(SndError::NoSuchEntry),
                        };
                        Response::GetUnseqMDataValue(res)
                    }
                    (MDataAddress::Seq { .. }, Err(err)) => Response::GetSeqMDataValue(Err(err)),
                    (MDataAddress::Unseq { .. }, Err(err)) => {
                        Response::GetUnseqMDataValue(Err(err))
                    }
                    (MDataAddress::Seq { .. }, Ok(MData::Unseq(_)))
                    | (MDataAddress::Unseq { .. }, Ok(MData::Seq(_))) => {
                        Response::GetUnseqMDataValue(Err(SndError::NoSuchData))
                    }
                }
            }
            Request::GetMDataShell(address) => {
                let result = self.get_mdata(address, requester_pk, request);

                match (address, result) {
                    (MDataAddress::Seq { .. }, Ok(mdata @ MData::Seq(_)))
                    | (MDataAddress::Unseq { .. }, Ok(mdata @ MData::Unseq(_))) => {
                        Response::GetMDataShell(Ok(mdata.shell()))
                    }
                    (MDataAddress::Seq { .. }, Err(err))
                    | (MDataAddress::Unseq { .. }, Err(err)) => Response::GetMDataShell(Err(err)),
                    (MDataAddress::Seq { .. }, Ok(MData::Unseq(_)))
                    | (MDataAddress::Unseq { .. }, Ok(MData::Seq(_))) => {
                        Response::GetMDataShell(Err(SndError::NoSuchData))
                    }
                }
            }
            Request::GetMDataVersion(address) => {
                let result = self
                    .get_mdata(address, requester_pk, request)
                    .and_then(|data| match data {
                        MData::Seq(mdata) => Ok(mdata.version()),
                        MData::Unseq(mdata) => Ok(mdata.version()),
                    });
                Response::GetMDataVersion(result)
            }
            Request::ListMDataEntries(address) => {
                let result = self.get_mdata(address, requester_pk, request);

                match (address, result) {
                    (MDataAddress::Seq { .. }, Ok(MData::Seq(mdata))) => {
                        Response::ListSeqMDataEntries(Ok(mdata.entries().clone()))
                    }
                    (MDataAddress::Unseq { .. }, Ok(MData::Unseq(mdata))) => {
                        Response::ListUnseqMDataEntries(Ok(mdata.entries().clone()))
                    }
                    (MDataAddress::Seq { .. }, Err(err)) => Response::ListSeqMDataEntries(Err(err)),
                    (MDataAddress::Unseq { .. }, Err(err)) => {
                        Response::ListUnseqMDataEntries(Err(err))
                    }
                    (MDataAddress::Seq { .. }, Ok(MData::Unseq(_)))
                    | (MDataAddress::Unseq { .. }, Ok(MData::Seq(_))) => {
                        Response::ListUnseqMDataEntries(Err(SndError::NoSuchData))
                    }
                }
            }
            Request::ListMDataKeys(address) => {
                let result = self
                    .get_mdata(address, requester_pk, request)
                    .and_then(|data| match data {
                        MData::Seq(mdata) => Ok(mdata.keys().clone()),
                        MData::Unseq(mdata) => Ok(mdata.keys().clone()),
                    });
                Response::ListMDataKeys(result)
            }
            Request::ListMDataValues(address) => {
                let result = self.get_mdata(address, requester_pk, request);
                match (address, result) {
                    (MDataAddress::Seq { .. }, Ok(MData::Seq(mdata))) => {
                        Response::ListSeqMDataValues(Ok(mdata.values()))
                    }
                    (MDataAddress::Unseq { .. }, Ok(MData::Unseq(mdata))) => {
                        Response::ListUnseqMDataValues(Ok(mdata.values()))
                    }
                    (MDataAddress::Seq { .. }, Err(err)) => Response::ListSeqMDataValues(Err(err)),
                    (MDataAddress::Unseq { .. }, Err(err)) => {
                        Response::ListUnseqMDataValues(Err(err))
                    }
                    (MDataAddress::Seq { .. }, Ok(MData::Unseq(_)))
                    | (MDataAddress::Unseq { .. }, Ok(MData::Seq(_))) => {
                        Response::ListUnseqMDataValues(Err(SndError::NoSuchData))
                    }
                }
            }
            Request::DeleteMData(address) => {
                let res =
                    self.get_mdata(address, requester_pk, request)
                        .and_then(|data| match data {
                            MData::Seq(mdata) => {
                                if let PublicId::Client(client_id) = requester.clone() {
                                    if client_id.public_key() == mdata.owners() {
                                        let address = *mdata.address();
                                        self.delete_data(DataId::Mutable(address));
                                        self.commit_mutation(requester.name());
                                        Ok(())
                                    } else {
                                        Err(SndError::InvalidOwners)
                                    }
                                } else {
                                    Err(SndError::AccessDenied)
                                }
                            }
                            MData::Unseq(mdata) => {
                                if let PublicId::Client(client_id) = requester.clone() {
                                    if client_id.public_key() == mdata.owners() {
                                        let address = *mdata.address();
                                        self.delete_data(DataId::Mutable(address));
                                        self.commit_mutation(requester.name());
                                        Ok(())
                                    } else {
                                        Err(SndError::InvalidOwners)
                                    }
                                } else {
                                    Err(SndError::AccessDenied)
                                }
                            }
                        });
                Response::Mutation(res)
            }
            Request::SetMDataUserPermissions {
                address,
                ref user,
                ref permissions,
                version,
            } => {
                let permissions = permissions.clone();
                let user = user;

                let result = self
                    .get_mdata(address, requester_pk, request.clone())
                    .and_then(|data| {
                        let address = *data.address();
                        let data_name = DataId::Mutable(address);
                        match data.clone() {
                            MData::Unseq(mut mdata) => {
                                mdata.set_user_permissions(*user, permissions, version)?;
                                self.insert_data(data_name, Data::NewMutable(MData::Unseq(mdata)));
                                self.commit_mutation(requester.name());
                                Ok(())
                            }
                            MData::Seq(mut mdata) => {
                                mdata.set_user_permissions(*user, permissions, version)?;
                                self.insert_data(data_name, Data::NewMutable(MData::Seq(mdata)));
                                self.commit_mutation(requester.name());
                                Ok(())
                            }
                        }
                    });
                Response::Mutation(result)
            }
            Request::DelMDataUserPermissions {
                address,
                ref user,
                version,
            } => {
                let user = *user;

                let result = self
                    .get_mdata(address, requester_pk, request)
                    .and_then(|data| {
                        let address = *data.address();
                        let data_name = DataId::Mutable(address);
                        match data.clone() {
                            MData::Unseq(mut mdata) => {
                                mdata.del_user_permissions(user, version)?;
                                self.insert_data(data_name, Data::NewMutable(MData::Unseq(mdata)));
                            }
                            MData::Seq(mut mdata) => {
                                mdata.del_user_permissions(user, version)?;
                                self.insert_data(data_name, Data::NewMutable(MData::Seq(mdata)));
                            }
                        }
                        self.commit_mutation(requester.name());
                        Ok(())
                    });
                Response::Mutation(result)
            }
            Request::ListMDataUserPermissions { address, ref user } => {
                let user = *user;

                let result = self
                    .get_mdata(address, requester_pk, request)
                    .and_then(|data| match data {
                        MData::Unseq(mdata) => Ok((*unwrap!(mdata.user_permissions(user))).clone()),
                        MData::Seq(mdata) => Ok((*unwrap!(mdata.user_permissions(user))).clone()),
                    });
                Response::ListMDataUserPermissions(result)
            }
            Request::ListMDataPermissions(address) => {
                let result = self
                    .get_mdata(address, requester_pk, request)
                    .and_then(|data| match data {
                        MData::Unseq(mdata) => Ok(mdata.permissions()),
                        MData::Seq(mdata) => Ok(mdata.permissions()),
                    });
                Response::ListMDataPermissions(result)
            }
            Request::MutateSeqMDataEntries {
                address,
                ref actions,
            } => {
                let result = self
                    .get_mdata(address, requester_pk, request.clone())
                    .and_then(move |data| {
                        let address = *data.address();
                        let data_name = DataId::Mutable(address);
                        match data.clone() {
                            MData::Seq(mut mdata) => {
                                mdata.mutate_entries(actions.clone(), requester_pk)?;
                                self.insert_data(data_name, Data::NewMutable(MData::Seq(mdata)));
                                self.commit_mutation(requester.name());
                                Ok(())
                            }
                            MData::Unseq(_) => Err(SndError::NoSuchData),
                        }
                    });
                Response::Mutation(result)
            }
            Request::MutateUnseqMDataEntries {
                address,
                ref actions,
            } => {
                let request = request.clone();
                let actions = actions.clone();

                let result = self
                    .get_mdata(address, requester_pk, request)
                    .and_then(move |data| {
                        let address = *data.address();
                        let data_name = DataId::Mutable(address);
                        match data.clone() {
                            MData::Unseq(mut mdata) => {
                                mdata.mutate_entries(actions.clone(), requester_pk)?;
                                self.insert_data(data_name, Data::NewMutable(MData::Unseq(mdata)));
                                self.commit_mutation(requester.name());
                                Ok(())
                            }
                            MData::Seq(_) => Err(SndError::NoSuchData),
                        }
                    });
                Response::Mutation(result)
            }
            //
            // ===== Immutable Data =====
            //
            Request::PutAData(adata) => {
                let address = *adata.address();
                let result = self.put_data(
                    DataId::AppendOnly(address),
                    Data::AppendOnly(adata),
                    requester,
                );
                Response::Mutation(result)
            }
            Request::GetAData(address) => {
                let result = self.get_adata(address, requester_pk, request);
                Response::GetAData(result)
            }
            Request::DeleteAData(address) => {
                let id = DataId::AppendOnly(address);
                let res = self
                    .get_adata(address, requester_pk, request)
                    .and_then(move |data| match data {
                        // Cannot be deleted as it is a published data.
                        AData::PubSeq(_) | AData::PubUnseq(_) => Err(SndError::InvalidOperation),
                        AData::UnpubSeq(_) | AData::UnpubUnseq(_) => {
                            self.delete_data(id);
                            self.commit_mutation(requester.name());
                            Ok(())
                        }
                    });
                Response::Mutation(res)
            }
            Request::GetADataShell {
                address,
                data_index,
            } => {
                let res = self
                    .get_adata(address, requester_pk, request)
                    .and_then(move |data| {
                        let idx = match data_index {
                            ADataIndex::FromStart(idx) => idx,
                            ADataIndex::FromEnd(idx) => (data.permissions_index() - idx),
                        };
                        data.shell(idx)
                    });
                Response::GetADataShell(res)
            }
            Request::GetADataRange { address, range } => {
                let res = self
                    .get_adata(address, requester_pk, request)
                    .and_then(move |data| {
                        data.in_range(range.0, range.1).ok_or(SndError::NoSuchEntry)
                    });
                Response::GetADataRange(res)
            }
            Request::GetADataIndices(address) => {
                let res = self
                    .get_adata(address, requester_pk, request)
                    .and_then(move |data| data.indices());
                Response::GetADataIndices(res)
            }
            Request::GetADataLastEntry(address) => {
                let res = self
                    .get_adata(address, requester_pk, request)
                    .and_then(move |data| data.last_entry().ok_or(SndError::NoSuchEntry));
                Response::GetADataLastEntry(res)
            }
            Request::GetADataPermissions {
                // Macro cannot be used here
                address,
                permissions_index,
            } => {
                let res = self
                    .get_adata(address, requester_pk, request)
                    .and_then(move |data| {
                        let idx = match permissions_index {
                            ADataIndex::FromStart(idx) => idx as usize,
                            ADataIndex::FromEnd(idx) => (data.permissions_index() - idx) as usize,
                        };
                        match address {
                            ADataAddress::PubSeq { .. } => {
                                let res = match data {
                                    AData::PubSeq(adata) => {
                                        match adata.fetch_permissions_at_index(idx as u64) {
                                            Some(perm) => Ok(perm.clone()),
                                            None => Err(SndError::NoSuchEntry),
                                        }
                                    }
                                    _ => Err(SndError::NoSuchData),
                                };
                                Ok(Response::GetPubADataPermissionAtIndex(res))
                            }
                            ADataAddress::PubUnseq { .. } => {
                                let res = match data {
                                    AData::PubUnseq(adata) => {
                                        match adata.fetch_permissions_at_index(idx as u64) {
                                            Some(perm) => Ok(perm.clone()),
                                            None => Err(SndError::NoSuchEntry),
                                        }
                                    }
                                    _ => Err(SndError::NoSuchData),
                                };
                                Ok(Response::GetPubADataPermissionAtIndex(res))
                            }
                            ADataAddress::UnpubSeq { .. } => {
                                let res = match data {
                                    AData::UnpubSeq(adata) => {
                                        match adata.fetch_permissions_at_index(idx as u64) {
                                            Some(perm) => Ok(perm.clone()),
                                            None => Err(SndError::NoSuchEntry),
                                        }
                                    }
                                    _ => Err(SndError::NoSuchData),
                                };
                                Ok(Response::GetUnpubADataPermissionAtIndex(res))
                            }
                            ADataAddress::UnpubUnseq { .. } => {
                                let res = match data {
                                    AData::UnpubUnseq(adata) => {
                                        match adata.fetch_permissions_at_index(idx as u64) {
                                            Some(perm) => Ok(perm.clone()),
                                            None => Err(SndError::NoSuchEntry),
                                        }
                                    }
                                    _ => Err(SndError::NoSuchData),
                                };
                                Ok(Response::GetUnpubADataPermissionAtIndex(res))
                            }
                        }
                    });
                unwrap!(res)
            }
            Request::GetPubADataUserPermissions {
                address,
                permissions_index,
                user,
            } => {
                let res = self
                    .get_adata(address, requester_pk, request)
                    .and_then(move |data| {
                        let idx = match permissions_index {
                            ADataIndex::FromStart(idx) => idx as usize,
                            ADataIndex::FromEnd(idx) => (data.permissions_index() - idx) as usize,
                        };
                        data.pub_user_permissions(user, idx as u64)
                    });
                Response::GetPubADataUserPermissions(res)
            }
            Request::GetUnpubADataUserPermissions {
                address,
                permissions_index,
                public_key,
            } => {
                let res = self
                    .get_adata(address, requester_pk, request)
                    .and_then(move |data| {
                        let idx = match permissions_index {
                            ADataIndex::FromStart(idx) => idx as usize,
                            ADataIndex::FromEnd(idx) => (data.permissions_index() - idx) as usize,
                        };
                        data.unpub_user_permissions(public_key, idx as u64)
                    });
                Response::GetUnpubADataUserPermissions(res)
            }
            Request::AppendSeq { append, index } => {
                let id = DataId::AppendOnly(append.address);
                let res = self
                    .get_adata(append.address, requester_pk, request)
                    .and_then(move |data| match data {
                        AData::PubSeq(mut adata) => {
                            unwrap!(adata.append(&append.values, index));
                            self.commit_mutation(requester.name());
                            self.insert_data(id, Data::AppendOnly(AData::PubSeq(adata)));
                            Ok(())
                        }
                        AData::UnpubSeq(mut adata) => {
                            unwrap!(adata.append(&append.values, index));
                            self.commit_mutation(requester.name());
                            self.insert_data(id, Data::AppendOnly(AData::UnpubSeq(adata)));
                            Ok(())
                        }
                        _ => Err(SndError::NoSuchData),
                    });
                Response::Mutation(res)
            }
            Request::AppendUnseq(append) => {
                let id = DataId::AppendOnly(append.address);
                let res = self
                    .get_adata(append.address, requester_pk, request)
                    .and_then(move |data| match data {
                        AData::PubUnseq(mut adata) => {
                            unwrap!(adata.append(&append.values));
                            self.commit_mutation(requester.name());
                            self.insert_data(id, Data::AppendOnly(AData::PubUnseq(adata)));
                            Ok(())
                        }
                        AData::UnpubUnseq(mut adata) => {
                            unwrap!(adata.append(&append.values));
                            self.commit_mutation(requester.name());
                            self.insert_data(id, Data::AppendOnly(AData::UnpubUnseq(adata)));
                            Ok(())
                        }
                        _ => Err(SndError::NoSuchData),
                    });
                Response::Mutation(res)
            }
            Request::AddPubADataPermissions {
                address,
                permissions,
            } => {
                let id = DataId::AppendOnly(address);
                let res = self
                    .get_adata(address, requester_pk, request)
                    .and_then(move |data| match address {
                        ADataAddress::PubSeq { .. } => match data {
                            AData::PubSeq(mut adata) => {
                                unwrap!(adata.append_permissions(permissions));
                                self.commit_mutation(requester.name());
                                self.insert_data(id, Data::AppendOnly(AData::PubSeq(adata)));
                                Ok(())
                            }
                            _ => Err(SndError::NoSuchData),
                        },
                        ADataAddress::PubUnseq { .. } => match data {
                            AData::PubUnseq(mut adata) => {
                                unwrap!(adata.append_permissions(permissions));
                                self.commit_mutation(requester.name());
                                self.insert_data(id, Data::AppendOnly(AData::PubUnseq(adata)));
                                Ok(())
                            }
                            _ => Err(SndError::NoSuchData),
                        },
                        _ => Err(SndError::AccessDenied),
                    });
                Response::Mutation(res)
            }
            Request::AddUnpubADataPermissions {
                address,
                permissions,
            } => {
                let id = DataId::AppendOnly(address);
                let res = self
                    .get_adata(address, requester_pk, request)
                    .and_then(|data| match address {
                        ADataAddress::UnpubSeq { .. } => match data.clone() {
                            AData::UnpubSeq(mut adata) => {
                                unwrap!(adata.append_permissions(permissions));
                                self.commit_mutation(requester.name());
                                self.insert_data(id, Data::AppendOnly(AData::UnpubSeq(adata)));
                                Ok(())
                            }
                            _ => Err(SndError::NoSuchData),
                        },
                        ADataAddress::UnpubUnseq { .. } => match data {
                            AData::UnpubUnseq(mut adata) => {
                                unwrap!(adata.append_permissions(permissions));
                                self.commit_mutation(requester.name());
                                self.insert_data(id, Data::AppendOnly(AData::UnpubUnseq(adata)));
                                Ok(())
                            }
                            _ => Err(SndError::NoSuchData),
                        },
                        _ => Err(SndError::AccessDenied),
                    });
                Response::Mutation(res)
            }
            Request::SetADataOwner { address, owner } => {
                let id = DataId::AppendOnly(address);
                let res = self
                    .get_adata(address, requester_pk, request)
                    .and_then(move |data| match address {
                        ADataAddress::PubSeq { .. } => match data {
                            AData::PubSeq(mut adata) => {
                                unwrap!(adata.append_owner(owner));
                                self.commit_mutation(requester.name());
                                self.insert_data(id, Data::AppendOnly(AData::PubSeq(adata)));
                                Ok(())
                            }
                            _ => Err(SndError::NoSuchData),
                        },
                        ADataAddress::PubUnseq { .. } => match data {
                            AData::PubUnseq(mut adata) => {
                                unwrap!(adata.append_owner(owner));
                                self.commit_mutation(requester.name());
                                self.insert_data(id, Data::AppendOnly(AData::PubUnseq(adata)));
                                Ok(())
                            }
                            _ => Err(SndError::NoSuchData),
                        },
                        ADataAddress::UnpubSeq { .. } => match data.clone() {
                            AData::UnpubSeq(mut adata) => {
                                unwrap!(adata.append_owner(owner));
                                self.commit_mutation(requester.name());
                                self.insert_data(id, Data::AppendOnly(AData::UnpubSeq(adata)));
                                Ok(())
                            }
                            _ => Err(SndError::NoSuchData),
                        },
                        ADataAddress::UnpubUnseq { .. } => match data {
                            AData::UnpubUnseq(mut adata) => {
                                unwrap!(adata.append_owner(owner));
                                self.commit_mutation(requester.name());
                                self.insert_data(id, Data::AppendOnly(AData::UnpubUnseq(adata)));
                                Ok(())
                            }
                            _ => Err(SndError::NoSuchData),
                        },
                    });
                Response::Mutation(res)
            }
            Request::GetADataOwners {
                address,
                owners_index,
            } => {
                let res = self
                    .get_adata(address, requester_pk, request)
                    .and_then(move |data| {
                        let idx = match owners_index {
                            ADataIndex::FromStart(idx) => idx,
                            ADataIndex::FromEnd(idx) => (data.owners_index() - idx),
                        };
                        match data.get_owners(idx) {
                            Some(owner) => Ok(owner.clone()),
                            None => Err(SndError::NoSuchEntry),
                        }
                    });
                Response::GetADataOwners(res)
            }
            other => panic!("RPC not handled: {:?}", other),
        };
        Ok(Message::Response {
            response,
            message_id,
        })
    }
    //
    // ======= Append Only Data =======
    //
    pub fn get_adata(
        &mut self,
        address: ADataAddress,
        requester_pk: PublicKey,
        request: Request,
    ) -> Result<AData, SndError> {
        let data_id = DataId::AppendOnly(address);

        match self.get_data(&data_id) {
            Some(data_type) => match data_type {
                Data::AppendOnly(adata) => {
                    if adata.check_permission(&request, requester_pk).is_ok() {
                        Ok(adata)
                    } else {
                        Err(SndError::AccessDenied)
                    }
                }
                _ => Err(SndError::NoSuchData),
            },
            None => Err(SndError::NoSuchData),
        }
    }

    pub fn get_idata(&mut self, address: IDataAddress) -> Result<IData, SndError> {
        let data_name = DataId::Immutable(address);

        match self.get_data(&data_name) {
            Some(data_type) => match data_type {
                Data::Immutable(data) => Ok(data),
                _ => Err(SndError::NoSuchData),
            },
            None => Err(SndError::NoSuchData),
        }
    }

    pub fn delete_idata(
        &mut self,
        address: IDataAddress,
        requester: PublicId,
        requester_pk: PublicKey,
    ) -> Result<(), SndError> {
        let data_id = DataId::Immutable(address);

        match self.get_data(&data_id) {
            Some(idata) => {
                if let Data::Immutable(data) = idata {
                    if let IData::Unpub(unpub_idata) = data {
                        if *unpub_idata.owner() == requester_pk {
                            self.delete_data(data_id);
                            self.commit_mutation(requester.name());
                            Ok(())
                        } else {
                            Err(SndError::AccessDenied)
                        }
                    } else {
                        Err(SndError::InvalidOperation)
                    }
                } else {
                    Err(SndError::NoSuchData)
                }
            }
            None => Err(SndError::NoSuchData),
        }
    }

    pub fn get_mdata(
        &mut self,
        address: MDataAddress,
        requester_pk: PublicKey,
        request: Request,
    ) -> Result<MData, SndError> {
        let kind = address.kind();
        let data_name = DataId::Mutable(address);

        match self.get_data(&data_name) {
            Some(data_type) => match data_type {
                Data::NewMutable(data) => match data.clone() {
                    MData::Seq(mdata) => {
                        if let MDataKind::Unseq = kind {
                            Err(SndError::NoSuchData)
                        } else if mdata.check_permissions(request, requester_pk).is_err() {
                            Err(SndError::AccessDenied)
                        } else {
                            Ok(data)
                        }
                    }
                    MData::Unseq(mdata) => {
                        if let MDataKind::Seq = kind {
                            Err(SndError::NoSuchData)
                        } else if mdata.check_permissions(request, requester_pk).is_err() {
                            Err(SndError::AccessDenied)
                        } else {
                            Ok(data)
                        }
                    }
                },
                _ => Err(SndError::NoSuchData),
            },
            None => Err(SndError::NoSuchData),
        }
    }

    pub fn put_data(
        &mut self,
        data_name: DataId,
        data: Data,
        requester: PublicId,
    ) -> Result<(), SndError> {
        match requester.clone() {
            PublicId::Client(client_public_id) => {
                if self.get_account(client_public_id.name()).is_none() {
                    return Err(SndError::NoSuchAccount);
                }
            }
            PublicId::App(app_public_id) => match self.get_account(app_public_id.owner_name()) {
                None => return Err(SndError::NoSuchAccount),
                Some(account) => {
                    if !account.auth_keys().contains_key(app_public_id.public_key()) {
                        return Err(SndError::AccessDenied);
                    }
                }
            },
            _ => return Err(SndError::AccessDenied),
        }
        if self.contains_data(&data_name) {
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

pub fn lock(vault: &Mutex<Vault>, writing: bool) -> VaultGuard {
    let mut inner = unwrap!(vault.lock());

    if let Some(cache) = inner.store.load(writing) {
        inner.cache = cache;
    }

    VaultGuard(inner)
}

#[derive(Deserialize, Serialize)]
struct Cache {
    coin_balances: HashMap<XorName, CoinBalance>,
    client_manager: HashMap<XorName, Account>,
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
