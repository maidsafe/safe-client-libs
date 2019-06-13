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
use safe_nd::appendable_data::{
    Action as ADataAction, AppendOnlyData, AppendOnlyDataRef, AppendOnlyKind, Index, Indices,
    PubPermissions, SeqAppendOnly, SeqAppendOnlyData, UnpubPermissions, UnseqAppendOnly,
    UnseqAppendOnlyData,
};
use safe_nd::mutable_data::{
    MutableData as NewMutableData, MutableDataRef, SeqMutableData, UnseqMutableData,
};
use safe_nd::request::{AppendOnlyData as AData, Request, Requester};
use safe_nd::response::{Response, Transaction};
use safe_nd::{
    Coins, Error, ImmutableData, Message, MessageId, PublicKey, UnpubImmutableData, XorName,
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
        owner: threshold_crypto::PublicKey,
    ) {
        let _ = self
            .cache
            .coin_balances
            .insert(*coin_balance_name, CoinBalance::new(amount, owner));
    }

    // Authorise coin operation.
    pub fn authorise_coin_operation(
        &self,
        dst: Authority<XorName>,
        coin_balance_name: &XorName,
        req: &Request,
        msg_id: MessageId,
        requester: &Requester,
    ) -> Result<(), Error> {
        // Check if we are the owner or app.
        let balance = match self.get_coin_balance(&coin_balance_name) {
            Some(balance) => balance,
            None => {
                debug!("Account not found for {:?}", dst);
                return Err(Error::NoSuchAccount);
            }
        };
        let owner_cm = XorName::from(PublicKey::from(*balance.owner()));

        match requester {
            Requester::Owner(sig) => {
                if balance
                    .owner()
                    .verify(sig, &unwrap!(serialise(&(req, &msg_id))))
                {
                    Ok(())
                } else {
                    Err(Error::AccessDenied)
                }
            }
            Requester::Key(sign_pk) => {
                let dst_name = match dst {
                    Authority::ClientManager(name) => name,
                    x => {
                        debug!("Unexpected authority for mutation: {:?}", x);
                        return Err(Error::InvalidOperation);
                    }
                };
                if dst_name != owner_cm {
                    return Err(Error::InvalidOperation);
                }
                let account = match self.get_account(&owner_cm) {
                    Some(account) => account,
                    None => {
                        debug!("Account not found for {:?}", dst);
                        return Err(Error::NoSuchAccount);
                    }
                };
                match account.auth_keys().get(sign_pk) {
                    Some(perms) => {
                        if !perms.transfer_coins {
                            debug!("Mutation not authorised");
                            return Err(Error::AccessDenied);
                        }
                        Ok(())
                    }
                    None => {
                        debug!("App not found");
                        Err(Error::AccessDenied)
                    }
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
            return Err(ClientError::from("Error here"));
        }

        let unlimited_mut = unlimited_muts(&self.config);
        if !unlimited_mut && account.account_info().mutations_available == 0 {
            return Err(ClientError::LowBalance);
        }

        Ok(())
    }

    // Authorise mutation operation.
    pub fn authorise_mutation1(&self, dst: &Authority<XorName>) -> Result<(), Error> {
        let dst_name = match *dst {
            Authority::ClientManager(name) => name,
            x => {
                debug!("Unexpected authority for mutation: {:?}", x);
                return Err(Error::InvalidOperation);
            }
        };

        let account = match self.get_account(&dst_name) {
            Some(account) => account,
            None => {
                debug!("Account not found for {:?}", dst);
                return Err(Error::NoSuchAccount);
            }
        };
        // TODO: Check if we are the owner or app once account keys are changed to threshold_crypto

        let unlimited_mut = unlimited_muts(&self.config);
        if !unlimited_mut && account.account_info().mutations_available == 0 {
            return Err(Error::LowBalance);
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

    // Delete the data from the storage.
    pub fn delete_data(&mut self, name: DataId) {
        let _ = self.cache.nae_manager.remove(&name);
    }

    fn transfer_coins(
        &mut self,
        source: XorName,
        destination: XorName,
        amount: Coins,
        transaction_id: u64,
    ) -> Result<(), Error> {
        match self.get_coin_balance_mut(&source) {
            Some(balance) => balance.credit_balance(amount, transaction_id)?,
            None => return Err(Error::NoSuchAccount),
        };
        match self.get_coin_balance_mut(&destination) {
            Some(balance) => balance.debit_balance(amount)?,
            None => return Err(Error::NoSuchAccount),
        };
        Ok(())
    }

    fn get_transaction(
        &self,
        coins_balance_id: &XorName,
        transaction_id: u64,
    ) -> Result<Transaction, Error> {
        match self.get_coin_balance(coins_balance_id) {
            Some(balance) => match balance.find_transaction(transaction_id) {
                Some(amount) => Ok(Transaction::Success(amount)),
                None => Ok(Transaction::NoSuchTransaction),
            },
            None => Ok(Transaction::NoSuchCoinBalance),
        }
    }

    fn get_balance(&self, coins_balance_id: &XorName) -> Result<Coins, Error> {
        match self.get_coin_balance(coins_balance_id) {
            Some(balance) => Ok(balance.balance()),
            None => Err(Error::NoSuchAccount),
        }
    }

    pub fn process_request(
        &mut self,
        _src: Authority<XorName>,
        dest: Authority<XorName>,
        payload: Vec<u8>,
    ) -> Result<(Authority<XorName>, Vec<u8>), Error> {
        let (request, message_id, requester) = if let Message::Request {
            request,
            message_id,
            requester,
        } = unwrap!(deserialise(&payload))
        {
            (request, message_id, requester)
        } else {
            return Err(Error::from("Unexpected Message type"));
        };

        let response = match request {
            //
            // Immutable Data
            //
            Request::GetUnpubIData { address } => {
                let result = self
                    .get_idata(
                        dest,
                        ImmutableDataRef {
                            name: address,
                            published: false,
                        },
                        requester,
                    )
                    .and_then(|kind| match kind {
                        ImmutableDataKind::Unpublished(data) => Ok(data),
                        _ => Err(Error::from("Unexpected data returned")),
                    });
                Response::GetUnpubIData(result)
            }
            Request::PutUnpubIData { data } => {
                let result = self.put_idata(
                    dest,
                    ImmutableDataKind::Unpublished(data.clone()),
                    requester,
                );
                Response::PutUnpubIData(result)
            }
            Request::DeleteUnpubIData { address } => {
                let result = self.delete_idata(
                    dest,
                    ImmutableDataRef {
                        name: address,
                        published: false,
                    },
                    requester,
                );
                Response::DeleteUnpubIData(result)
            }
            Request::ListAuthKeysAndVersion => {
                let name = dest.name();
                if let Some(account) = self.get_account(&name) {
                    Response::ListAuthKeysAndVersion(Ok((
                        account.auth_keys().clone(),
                        account.version(),
                    )))
                } else {
                    return Err(Error::NoSuchAccount);
                }
            }
            Request::InsAuthKey {
                key,
                permissions,
                version,
            } => {
                let name = dest.name();
                if let Some(account) = self.get_account_mut(&name) {
                    Response::InsAuthKey(account.ins_auth_key(key, permissions, version))
                } else {
                    return Err(Error::NoSuchAccount);
                }
            }
            Request::DelAuthKey { key, version } => {
                let name = dest.name();
                if let Some(account) = self.get_account_mut(&name) {
                    Response::DelAuthKey(account.del_auth_key(&key, version))
                } else {
                    return Err(Error::NoSuchAccount);
                }
            }
            Request::TransferCoins {
                source,
                destination,
                amount,
                transaction_id,
            } => {
                if let Err(e) =
                    self.authorise_coin_operation(dest, &source, &request, message_id, &requester)
                {
                    Response::TransferCoins(Err(e))
                } else {
                    let res = self.transfer_coins(source, destination, amount, transaction_id);
                    Response::TransferCoins(res)
                }
            }
            Request::GetBalance { coins_balance_id } => {
                if let Err(e) = self.authorise_coin_operation(
                    dest,
                    &coins_balance_id,
                    &request,
                    message_id,
                    &requester,
                ) {
                    Response::GetBalance(Err(e))
                } else {
                    let res = self.get_balance(&coins_balance_id);
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
            Request::PutUnseqMData { data } => {
                let result =
                    self.put_mdata(dest, MutableDataKind::Unsequenced(data.clone()), requester);
                Response::PutUnseqMData(result)
            }
            Request::GetSeqMData { address } => {
                let result = self
                    .get_mdata(
                        dest,
                        address,
                        requester.clone(),
                        request,
                        message_id,
                        Some(true),
                    )
                    .and_then(|data| match data {
                        MutableDataKind::Sequenced(mdata) => Ok(mdata),
                        _ => Err(Error::from("Unexpected data")),
                    });
                Response::GetSeqMData(result)
            }
            Request::GetUnseqMData { address } => {
                let result = self
                    .get_mdata(
                        dest,
                        address,
                        requester.clone(),
                        request,
                        message_id,
                        Some(false),
                    )
                    .and_then(|data| match data {
                        MutableDataKind::Unsequenced(mdata) => Ok(mdata),
                        _ => Err(Error::from("Unexpected data")),
                    });
                Response::GetUnseqMData(result)
            }
            Request::PutSeqMData { data } => {
                let result =
                    self.put_mdata(dest, MutableDataKind::Sequenced(data.clone()), requester);
                Response::PutSeqMData(result)
            }
            Request::GetSeqMDataValue { address, ref key } => {
                let result = self
                    .get_mdata(
                        dest,
                        address,
                        requester.clone(),
                        request.clone(),
                        message_id,
                        Some(true),
                    )
                    .and_then(|data| match data {
                        MutableDataKind::Sequenced(mdata) => Ok(mdata.get(&key).unwrap().clone()),
                        _ => Err(Error::from("Unexpected data returned")),
                    });
                Response::GetSeqMDataValue(result)
            }
            Request::GetUnseqMDataValue { address, ref key } => {
                let result = self
                    .get_mdata(
                        dest,
                        address,
                        requester.clone(),
                        request.clone(),
                        message_id,
                        Some(false),
                    )
                    .and_then(|data| match data {
                        MutableDataKind::Unsequenced(mdata) => Ok(mdata.get(&key).unwrap().clone()),
                        _ => Err(Error::from("Unexpected data returned")),
                    });
                Response::GetUnseqMDataValue(result)
            }
            Request::GetSeqMDataShell { address } => {
                let result = self
                    .get_mdata(
                        dest,
                        address,
                        requester.clone(),
                        request,
                        message_id,
                        Some(true),
                    )
                    .and_then(|data| match data {
                        MutableDataKind::Sequenced(mdata) => Ok(mdata.shell()),
                        _ => Err(Error::from("Unexpected data returned")),
                    });
                Response::GetSeqMDataShell(result)
            }
            Request::GetUnseqMDataShell { address } => {
                let result = self
                    .get_mdata(
                        dest,
                        address,
                        requester.clone(),
                        request,
                        message_id,
                        Some(false),
                    )
                    .and_then(|data| match data {
                        MutableDataKind::Unsequenced(mdata) => Ok(mdata.shell()),
                        _ => Err(Error::from("Unexpected data returned")),
                    });
                Response::GetUnseqMDataShell(result)
            }
            Request::GetMDataVersion { address } => {
                let result = self
                    .get_mdata(dest, address, requester.clone(), request, message_id, None)
                    .and_then(|data| match data {
                        MutableDataKind::Sequenced(mdata) => Ok(mdata.version()),
                        MutableDataKind::Unsequenced(mdata) => Ok(mdata.version()),
                    });
                Response::GetMDataVersion(result)
            }
            Request::ListUnseqMDataEntries { address } => {
                let result = self
                    .get_mdata(
                        dest,
                        address,
                        requester.clone(),
                        request,
                        message_id,
                        Some(false),
                    )
                    .and_then(|data| match data {
                        MutableDataKind::Unsequenced(mdata) => Ok(mdata.entries().clone()),
                        _ => Err(Error::from("Unexpected data returned")),
                    });
                Response::ListUnseqMDataEntries(result)
            }
            Request::ListSeqMDataEntries { address } => {
                let result = self
                    .get_mdata(
                        dest,
                        address,
                        requester.clone(),
                        request,
                        message_id,
                        Some(true),
                    )
                    .and_then(|data| match data {
                        MutableDataKind::Sequenced(mdata) => Ok(mdata.entries().clone()),
                        _ => Err(Error::from("Unexpected data returned")),
                    });
                Response::ListSeqMDataEntries(result)
            }
            Request::ListMDataKeys { address } => {
                let result = self
                    .get_mdata(dest, address, requester.clone(), request, message_id, None)
                    .and_then(|data| match data {
                        MutableDataKind::Sequenced(mdata) => Ok(mdata.keys().clone()),
                        MutableDataKind::Unsequenced(mdata) => Ok(mdata.keys().clone()),
                    });
                Response::ListMDataKeys(result)
            }
            Request::ListSeqMDataValues { address } => {
                let result = self
                    .get_mdata(
                        dest,
                        address,
                        requester.clone(),
                        request,
                        message_id,
                        Some(true),
                    )
                    .and_then(|data| match data {
                        MutableDataKind::Sequenced(mdata) => Ok(mdata.values()),
                        _ => Err(Error::from("Unexpected data returned")),
                    });
                Response::ListSeqMDataValues(result)
            }
            Request::ListUnseqMDataValues { address } => {
                let result = self
                    .get_mdata(
                        dest,
                        address,
                        requester.clone(),
                        request,
                        message_id,
                        Some(false),
                    )
                    .and_then(|data| match data {
                        MutableDataKind::Unsequenced(mdata) => Ok(mdata.values()),
                        _ => Err(Error::from("Unexpected data returned")),
                    });
                Response::ListUnseqMDataValues(result)
            }
            Request::DeleteMData { address } => {
                let res = self.authorise_mutation1(&dest).and_then(|_| {
                    self.get_mdata(dest, address, requester.clone(), request, message_id, None)
                        .and_then(|data| match data {
                            MutableDataKind::Sequenced(mdata) => {
                                self.delete_data(DataId::mutable(*mdata.name(), mdata.tag()));
                                self.commit_mutation(&dest);
                                Ok(())
                            }
                            MutableDataKind::Unsequenced(mdata) => {
                                self.delete_data(DataId::mutable(*mdata.name(), mdata.tag()));
                                self.commit_mutation(&dest);
                                Ok(())
                            }
                        })
                });
                Response::DeleteMData(res)
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
                    .get_mdata(
                        Authority::NaeManager(address.name()),
                        address,
                        requester.clone(),
                        request.clone(),
                        message_id,
                        None,
                    )
                    .and_then(|data| {
                        let data_name = DataId::mutable(data.name(), data.tag());
                        match data.clone() {
                            MutableDataKind::Unsequenced(mut mdata) => {
                                unwrap!(mdata.set_user_permissions(*user, permissions, version));
                                self.insert_data(
                                    data_name,
                                    Data::NewMutable(MutableDataKind::Unsequenced(mdata)),
                                );
                                self.commit_mutation(&dest);
                                Ok(())
                            }
                            MutableDataKind::Sequenced(mut mdata) => {
                                unwrap!(mdata.set_user_permissions(*user, permissions, version));
                                self.insert_data(
                                    data_name,
                                    Data::NewMutable(MutableDataKind::Sequenced(mdata)),
                                );
                                self.commit_mutation(&dest);
                                Ok(())
                            }
                        }
                    });
                Response::SetMDataUserPermissions(result)
            }
            Request::DelMDataUserPermissions {
                address,
                ref user,
                version,
            } => {
                let user = *user;

                let result = self
                    .get_mdata(
                        Authority::NaeManager(address.name()),
                        address,
                        requester.clone(),
                        request,
                        message_id,
                        None,
                    )
                    .and_then(|data| {
                        let data_name = DataId::mutable(data.name(), data.tag());
                        match data.clone() {
                            MutableDataKind::Unsequenced(mut mdata) => {
                                unwrap!(mdata.del_user_permissions(user, version));
                                self.insert_data(
                                    data_name,
                                    Data::NewMutable(MutableDataKind::Unsequenced(mdata)),
                                );
                                self.commit_mutation(&dest);
                                Ok(())
                            }
                            MutableDataKind::Sequenced(mut mdata) => {
                                unwrap!(mdata.del_user_permissions(user, version));
                                self.insert_data(
                                    data_name,
                                    Data::NewMutable(MutableDataKind::Sequenced(mdata)),
                                );
                                self.commit_mutation(&dest);
                                Ok(())
                            }
                        }
                    });
                Response::DelMDataUserPermissions(result)
            }
            Request::ListMDataUserPermissions { address, ref user } => {
                let user = *user;

                let result = self
                    .get_mdata(dest, address, requester.clone(), request, message_id, None)
                    .and_then(|data| match data {
                        MutableDataKind::Unsequenced(mdata) => {
                            Ok((*unwrap!(mdata.user_permissions(user))).clone())
                        }
                        MutableDataKind::Sequenced(mdata) => {
                            Ok((*unwrap!(mdata.user_permissions(user))).clone())
                        }
                    });
                Response::ListMDataUserPermissions(result)
            }
            Request::ListMDataPermissions { address } => {
                let result = self
                    .get_mdata(dest, address, requester.clone(), request, message_id, None)
                    .and_then(|data| match data {
                        MutableDataKind::Unsequenced(mdata) => Ok(mdata.permissions()),
                        MutableDataKind::Sequenced(mdata) => Ok(mdata.permissions()),
                    });
                Response::ListMDataPermissions(result)
            }
            Request::MutateSeqMDataEntries {
                address,
                ref actions,
            } => {
                let request = request.clone();

                let result = self
                    .get_mdata(
                        Authority::NaeManager(address.name()),
                        address,
                        requester.clone(),
                        request.clone(),
                        message_id,
                        Some(true),
                    )
                    .and_then(move |data| {
                        let data_name = DataId::mutable(data.name(), data.tag());
                        match data.clone() {
                            MutableDataKind::Sequenced(mut mdata) => {
                                unwrap!(mdata.mutate_entries(
                                    actions.clone(),
                                    request,
                                    requester,
                                    message_id
                                ));
                                self.insert_data(
                                    data_name,
                                    Data::NewMutable(MutableDataKind::Sequenced(mdata)),
                                );
                                self.commit_mutation(&dest);
                                Ok(())
                            }
                            _ => Err(Error::from("Unexpected data returned")),
                        }
                    });
                Response::MutateSeqMDataEntries(result)
            }
            Request::MutateUnseqMDataEntries {
                address,
                ref actions,
            } => {
                let request = request.clone();
                let actions = actions.clone();

                let result = self
                    .get_mdata(
                        Authority::NaeManager(address.name()),
                        address,
                        requester.clone(),
                        request.clone(),
                        message_id,
                        Some(false),
                    )
                    .and_then(move |data| {
                        let data_name = DataId::mutable(data.name(), data.tag());
                        match data.clone() {
                            MutableDataKind::Unsequenced(mut mdata) => {
                                unwrap!(mdata.mutate_entries(
                                    actions.clone(),
                                    request,
                                    requester,
                                    message_id
                                ));
                                self.insert_data(
                                    data_name,
                                    Data::NewMutable(MutableDataKind::Unsequenced(mdata)),
                                );
                                self.commit_mutation(&dest);
                                Ok(())
                            }
                            _ => Err(Error::from("Unexpected data returned")),
                        }
                    });
                Response::MutateUnseqMDataEntries(result)
            }
            Request::PutAData { data } => {
                let result = self.put_adata(dest, data.clone(), requester);
                Response::PutAData(result)
            }
            Request::GetAData { address } => {
                let result = self.get_adata(dest, address, requester);
                Response::GetAData(result)
            }
            Request::GetADataRange {
                kind,
                address,
                range,
            } => {
                let res = self
                    .get_adata(dest, address, requester.clone())
                    .and_then(move |data| match kind {
                        AppendOnlyKind::PubSeq => match data {
                            AData::PubSeq(adata) => {
                                if unwrap!(
                                    adata.verify_requester(requester.clone(), ADataAction::Read)
                                ) {
                                    adata.in_range(range.0, range.1).ok_or(Error::NoSuchEntry)
                                } else {
                                    Err(Error::AccessDenied)
                                }
                            }
                            _ => Err(Error::NoSuchData),
                        },
                        AppendOnlyKind::PubUnseq => match data {
                            AData::PubUnseq(adata) => {
                                if unwrap!(adata.verify_requester(requester, ADataAction::Read)) {
                                    adata.in_range(range.0, range.1).ok_or(Error::NoSuchEntry)
                                } else {
                                    Err(Error::AccessDenied)
                                }
                            }
                            _ => Err(Error::NoSuchData),
                        },
                        AppendOnlyKind::UnpubSeq => match data {
                            AData::UnpubSeq(adata) => {
                                if unwrap!(adata.verify_requester(requester, ADataAction::Read)) {
                                    adata.in_range(range.0, range.1).ok_or(Error::NoSuchEntry)
                                } else {
                                    Err(Error::AccessDenied)
                                }
                            }
                            _ => Err(Error::NoSuchData),
                        },
                        AppendOnlyKind::UnpubUnseq => match data {
                            AData::UnpubUnseq(adata) => {
                                if unwrap!(adata.verify_requester(requester, ADataAction::Read)) {
                                    adata.in_range(range.0, range.1).ok_or(Error::NoSuchEntry)
                                } else {
                                    Err(Error::AccessDenied)
                                }
                            }
                            _ => Err(Error::NoSuchData),
                        },
                    });
                Response::GetADataRange(res)
            }
            Request::GetADataIndices { kind, address } => {
                let res = self
                    .get_adata(dest, address, requester.clone())
                    .and_then(move |data| match kind {
                        AppendOnlyKind::PubSeq => match data {
                            AData::PubSeq(adata) => {
                                if unwrap!(
                                    adata.verify_requester(requester.clone(), ADataAction::Read)
                                ) {
                                    Ok(Indices::new(
                                        adata.entry_index(),
                                        adata.owners_index(),
                                        adata.permissions_index(),
                                    ))
                                } else {
                                    Err(Error::AccessDenied)
                                }
                            }
                            _ => Err(Error::NoSuchData),
                        },
                        AppendOnlyKind::PubUnseq => match data {
                            AData::PubUnseq(adata) => {
                                if unwrap!(adata.verify_requester(requester, ADataAction::Read)) {
                                    Ok(Indices::new(
                                        adata.entry_index(),
                                        adata.owners_index(),
                                        adata.permissions_index(),
                                    ))
                                } else {
                                    Err(Error::AccessDenied)
                                }
                            }
                            _ => Err(Error::NoSuchData),
                        },
                        AppendOnlyKind::UnpubSeq => match data {
                            AData::UnpubSeq(adata) => {
                                if unwrap!(adata.verify_requester(requester, ADataAction::Read)) {
                                    Ok(Indices::new(
                                        adata.entry_index(),
                                        adata.owners_index(),
                                        adata.permissions_index(),
                                    ))
                                } else {
                                    Err(Error::AccessDenied)
                                }
                            }
                            _ => Err(Error::NoSuchData),
                        },
                        AppendOnlyKind::UnpubUnseq => match data {
                            AData::UnpubUnseq(adata) => {
                                if unwrap!(adata.verify_requester(requester, ADataAction::Read)) {
                                    Ok(Indices::new(
                                        adata.entry_index(),
                                        adata.owners_index(),
                                        adata.permissions_index(),
                                    ))
                                } else {
                                    Err(Error::AccessDenied)
                                }
                            }
                            _ => Err(Error::NoSuchData),
                        },
                    });
                Response::GetADataIndices(res)
            }
            Request::GetADataLastEntry { kind, address } => {
                let res = self
                    .get_adata(dest, address, requester.clone())
                    .and_then(move |data| match kind {
                        AppendOnlyKind::PubSeq => match data {
                            AData::PubSeq(adata) => {
                                if unwrap!(
                                    adata.verify_requester(requester.clone(), ADataAction::Read)
                                ) {
                                    adata.last().ok_or(Error::NoSuchEntry)
                                } else {
                                    Err(Error::AccessDenied)
                                }
                            }
                            _ => Err(Error::NoSuchData),
                        },
                        AppendOnlyKind::PubUnseq => match data {
                            AData::PubUnseq(adata) => {
                                if unwrap!(adata.verify_requester(requester, ADataAction::Read)) {
                                    adata.last().ok_or(Error::NoSuchEntry)
                                } else {
                                    Err(Error::AccessDenied)
                                }
                            }
                            _ => Err(Error::NoSuchData),
                        },
                        AppendOnlyKind::UnpubSeq => match data {
                            AData::UnpubSeq(adata) => {
                                if unwrap!(adata.verify_requester(requester, ADataAction::Read)) {
                                    adata.last().ok_or(Error::NoSuchEntry)
                                } else {
                                    Err(Error::AccessDenied)
                                }
                            }
                            _ => Err(Error::NoSuchData),
                        },
                        AppendOnlyKind::UnpubUnseq => match data {
                            AData::UnpubUnseq(adata) => {
                                if unwrap!(adata.verify_requester(requester, ADataAction::Read)) {
                                    adata.last().ok_or(Error::NoSuchEntry)
                                } else {
                                    Err(Error::AccessDenied)
                                }
                            }
                            _ => Err(Error::NoSuchData),
                        },
                    });
                Response::GetADataLastEntry(res)
            }
            Request::GetADataPermissions {
                kind,
                address,
                permissions_index,
            } => {
                let res = self
                    .get_adata(dest, address, requester.clone())
                    .and_then(move |data| match kind {
                        AppendOnlyKind::PubSeq => {
                            let res = match data {
                                AData::PubSeq(adata) => {
                                    if unwrap!(adata
                                        .verify_requester(requester.clone(), ADataAction::Read))
                                    {
                                        let idx = match permissions_index {
                                            Index::FromStart(idx) => idx as usize,
                                            Index::FromEnd(idx) => {
                                                (adata.permissions_index() - idx) as usize
                                            }
                                        };
                                        match adata.fetch_permissions_at_index(idx as u64) {
                                            Some(perm) => Ok(perm.clone()),
                                            None => Err(Error::NoSuchEntry),
                                        }
                                    } else {
                                        Err(Error::AccessDenied)
                                    }
                                }
                                _ => Err(Error::NoSuchData),
                            };
                            Ok(Response::GetPubADataPermissionAtIndex(res))
                        }
                        AppendOnlyKind::PubUnseq => {
                            let res = match data {
                                AData::PubUnseq(adata) => {
                                    if unwrap!(adata.verify_requester(requester, ADataAction::Read))
                                    {
                                        let idx = match permissions_index {
                                            Index::FromStart(idx) => idx as usize,
                                            Index::FromEnd(idx) => {
                                                (adata.permissions_index() - idx) as usize
                                            }
                                        };
                                        match adata.fetch_permissions_at_index(idx as u64) {
                                            Some(perm) => Ok(perm.clone()),
                                            None => Err(Error::NoSuchEntry),
                                        }
                                    } else {
                                        Err(Error::AccessDenied)
                                    }
                                }
                                _ => Err(Error::NoSuchData),
                            };
                            Ok(Response::GetPubADataPermissionAtIndex(res))
                        }
                        AppendOnlyKind::UnpubSeq => {
                            let res = match data {
                                AData::UnpubSeq(adata) => {
                                    if unwrap!(adata.verify_requester(requester, ADataAction::Read))
                                    {
                                        let idx = match permissions_index {
                                            Index::FromStart(idx) => idx as usize,
                                            Index::FromEnd(idx) => {
                                                (adata.permissions_index() - idx) as usize
                                            }
                                        };
                                        match adata.fetch_permissions_at_index(idx as u64) {
                                            Some(perm) => Ok(perm.clone()),
                                            None => Err(Error::NoSuchEntry),
                                        }
                                    } else {
                                        Err(Error::AccessDenied)
                                    }
                                }
                                _ => Err(Error::NoSuchData),
                            };
                            Ok(Response::GetUnpubADataPermissionAtIndex(res))
                        }
                        AppendOnlyKind::UnpubUnseq => {
                            let res = match data {
                                AData::UnpubUnseq(adata) => {
                                    if unwrap!(adata.verify_requester(requester, ADataAction::Read))
                                    {
                                        let idx = match permissions_index {
                                            Index::FromStart(idx) => idx as usize,
                                            Index::FromEnd(idx) => {
                                                (adata.permissions_index() - idx) as usize
                                            }
                                        };
                                        match adata.fetch_permissions_at_index(idx as u64) {
                                            Some(perm) => Ok(perm.clone()),
                                            None => Err(Error::NoSuchEntry),
                                        }
                                    } else {
                                        Err(Error::AccessDenied)
                                    }
                                }
                                _ => Err(Error::NoSuchData),
                            };
                            Ok(Response::GetUnpubADataPermissionAtIndex(res))
                        }
                    });
                unwrap!(res)
            }
            Request::GetPubADataUserPermissions {
                kind,
                address,
                permissions_index,
                user,
            } => {
                let res = self
                    .get_adata(dest, address, requester.clone())
                    .and_then(move |data| match kind {
                        AppendOnlyKind::PubSeq => {
                            let res = match data {
                                AData::PubSeq(adata) => {
                                    if unwrap!(adata
                                        .verify_requester(requester.clone(), ADataAction::Read))
                                    {
                                        let idx = match permissions_index {
                                            Index::FromStart(idx) => idx as usize,
                                            Index::FromEnd(idx) => {
                                                (adata.permissions_index() - idx) as usize
                                            }
                                        };
                                        match adata.fetch_permissions_at_index(idx as u64) {
                                            Some(perm) => {
                                                match perm.clone().permissions().get(&user) {
                                                    Some(usr) => Ok(*usr),
                                                    None => Err(Error::NoSuchEntry),
                                                }
                                            }
                                            None => Err(Error::NoSuchEntry),
                                        }
                                    } else {
                                        Err(Error::AccessDenied)
                                    }
                                }
                                _ => Err(Error::NoSuchData),
                            };
                            Ok(Response::GetPubADataUserPermissions(res))
                        }
                        AppendOnlyKind::PubUnseq => {
                            let res = match data {
                                AData::PubUnseq(adata) => {
                                    if unwrap!(adata.verify_requester(requester, ADataAction::Read))
                                    {
                                        let idx = match permissions_index {
                                            Index::FromStart(idx) => idx as usize,
                                            Index::FromEnd(idx) => {
                                                (adata.permissions_index() - idx) as usize
                                            }
                                        };
                                        match adata.fetch_permissions_at_index(idx as u64) {
                                            Some(perm) => {
                                                match perm.clone().permissions().get(&user) {
                                                    Some(usr) => Ok(*usr),
                                                    None => Err(Error::NoSuchEntry),
                                                }
                                            }
                                            None => Err(Error::NoSuchEntry),
                                        }
                                    } else {
                                        Err(Error::AccessDenied)
                                    }
                                }
                                _ => Err(Error::NoSuchData),
                            };
                            Ok(Response::GetPubADataUserPermissions(res))
                        }
                        _ => Ok(Response::GetPubADataUserPermissions(Err(Error::NoSuchData))),
                    });
                unwrap!(res)
            }
            Request::GetUnpubADataUserPermissions {
                kind,
                address,
                permissions_index,
                user,
            } => {
                let res = self
                    .get_adata(dest, address, requester.clone())
                    .and_then(move |data| match kind {
                        AppendOnlyKind::UnpubSeq => {
                            let res = match data {
                                AData::UnpubSeq(adata) => {
                                    if unwrap!(adata.verify_requester(requester, ADataAction::Read))
                                    {
                                        let idx = match permissions_index {
                                            Index::FromStart(idx) => idx as usize,
                                            Index::FromEnd(idx) => {
                                                (adata.permissions_index() - idx) as usize
                                            }
                                        };
                                        match adata.fetch_permissions_at_index(idx as u64) {
                                            Some(perm) => {
                                                match perm.clone().permissions().get(&user) {
                                                    Some(usr) => Ok(*usr),
                                                    None => Err(Error::NoSuchAccount),
                                                }
                                            }
                                            None => Err(Error::NoSuchEntry),
                                        }
                                    } else {
                                        Err(Error::AccessDenied)
                                    }
                                }
                                _ => Err(Error::NoSuchData),
                            };
                            Ok(Response::GetUnpubADataUserPermissions(res))
                        }
                        AppendOnlyKind::UnpubUnseq => {
                            let res = match data {
                                AData::UnpubUnseq(adata) => {
                                    if unwrap!(adata.verify_requester(requester, ADataAction::Read))
                                    {
                                        let idx = match permissions_index {
                                            Index::FromStart(idx) => idx as usize,
                                            Index::FromEnd(idx) => {
                                                (adata.permissions_index() - idx) as usize
                                            }
                                        };
                                        match adata.fetch_permissions_at_index(idx as u64) {
                                            Some(perm) => {
                                                match perm.clone().permissions().get(&user) {
                                                    Some(usr) => Ok(*usr),
                                                    None => Err(Error::NoSuchEntry),
                                                }
                                            }
                                            None => Err(Error::NoSuchEntry),
                                        }
                                    } else {
                                        Err(Error::AccessDenied)
                                    }
                                }
                                _ => Err(Error::NoSuchData),
                            };
                            Ok(Response::GetUnpubADataUserPermissions(res))
                        }
                        _ => Ok(Response::GetPubADataUserPermissions(Err(
                            Error::AccessDenied,
                        ))),
                    });
                unwrap!(res)
            }
            Request::AppendPubSeq { append, index } => {
                let name = append.address.name();
                let id = DataId::appendonly(name, append.address.tag());
                let res = self
                    .get_adata(dest, append.address, requester.clone())
                    .and_then(move |data| match data {
                        AData::PubSeq(mut adata) => {
                            if unwrap!(
                                adata.verify_requester(requester.clone(), ADataAction::Append)
                            ) {
                                unwrap!(adata.append(append.values.as_slice(), index));
                                self.commit_mutation(&dest);
                                self.insert_data(
                                    id,
                                    Data::AppendOnly(AppendableDataKind::PublishedSequenced(adata)),
                                );
                                Ok(())
                            } else {
                                Err(Error::AccessDenied)
                            }
                        }
                        _ => Err(Error::NoSuchData),
                    });
                Response::AppendPubSeq(res)
            }
            Request::AppendUnpubSeq { append, index } => {
                let name = append.address.name();
                let id = DataId::appendonly(name, append.address.tag());
                let res = self
                    .get_adata(dest, append.address, requester.clone())
                    .and_then(move |data| match data {
                        AData::UnpubSeq(mut adata) => {
                            if unwrap!(
                                adata.verify_requester(requester.clone(), ADataAction::Append)
                            ) {
                                unwrap!(adata.append(append.values.as_slice(), index));
                                self.commit_mutation(&dest);
                                self.insert_data(
                                    id,
                                    Data::AppendOnly(AppendableDataKind::UnpublishedSequenced(
                                        adata,
                                    )),
                                );
                                Ok(())
                            } else {
                                Err(Error::AccessDenied)
                            }
                        }
                        _ => Err(Error::NoSuchData),
                    });
                Response::AppendUnpubSeq(res)
            }
            Request::AppendPubUnseq(append) => {
                let name = append.address.name();
                let id = DataId::appendonly(name, append.address.tag());
                let res = self
                    .get_adata(dest, append.address, requester.clone())
                    .and_then(move |data| match data {
                        AData::PubUnseq(mut adata) => {
                            if unwrap!(
                                adata.verify_requester(requester.clone(), ADataAction::Append)
                            ) {
                                unwrap!(adata.append(append.values.as_slice()));
                                self.commit_mutation(&dest);
                                self.insert_data(
                                    id,
                                    Data::AppendOnly(AppendableDataKind::PublishedUnsequenced(
                                        adata,
                                    )),
                                );
                                Ok(())
                            } else {
                                Err(Error::AccessDenied)
                            }
                        }
                        _ => Err(Error::NoSuchData),
                    });
                Response::AppendPubUnseq(res)
            }
            Request::AppendUnpubUnseq(append) => {
                let name = append.address.name();
                let id = DataId::appendonly(name, append.address.tag());
                let res = self
                    .get_adata(dest, append.address, requester.clone())
                    .and_then(move |data| match data {
                        AData::UnpubUnseq(mut adata) => {
                            if unwrap!(
                                adata.verify_requester(requester.clone(), ADataAction::Append)
                            ) {
                                unwrap!(adata.append(append.values.as_slice()));
                                self.commit_mutation(&dest);
                                self.insert_data(
                                    id,
                                    Data::AppendOnly(AppendableDataKind::UnpublishedUnsequenced(
                                        adata,
                                    )),
                                );
                                Ok(())
                            } else {
                                Err(Error::AccessDenied)
                            }
                        }
                        _ => Err(Error::NoSuchData),
                    });
                Response::AppendUnpubUnseq(res)
            }
            Request::AddPubADataPermissions {
                kind,
                address,
                permissions,
            } => {
                let name = address.name();
                let id = DataId::appendonly(name, address.tag());
                let res = self
                    .get_adata(dest, address, requester.clone())
                    .and_then(move |data| match kind {
                        AppendOnlyKind::PubSeq => match data {
                            AData::PubSeq(mut adata) => {
                                if unwrap!(adata.verify_requester(
                                    requester.clone(),
                                    ADataAction::ManagePermissions
                                )) {
                                    unwrap!(adata.append_permissions(permissions));
                                    self.commit_mutation(&dest);
                                    self.insert_data(
                                        id,
                                        Data::AppendOnly(AppendableDataKind::PublishedSequenced(
                                            adata,
                                        )),
                                    );
                                    Ok(())
                                } else {
                                    Err(Error::AccessDenied)
                                }
                            }
                            _ => Err(Error::NoSuchData),
                        },
                        AppendOnlyKind::PubUnseq => match data {
                            AData::PubUnseq(mut adata) => {
                                if unwrap!(adata.verify_requester(requester, ADataAction::Read)) {
                                    unwrap!(adata.append_permissions(permissions));
                                    self.commit_mutation(&dest);
                                    self.insert_data(
                                        id,
                                        Data::AppendOnly(AppendableDataKind::PublishedUnsequenced(
                                            adata,
                                        )),
                                    );
                                    Ok(())
                                } else {
                                    Err(Error::AccessDenied)
                                }
                            }
                            _ => Err(Error::NoSuchData),
                        },
                        _ => Err(Error::AccessDenied),
                    });
                Response::AddUnpubADataPermissions(res)
            }
            Request::AddUnpubADataPermissions {
                kind,
                address,
                permissions,
            } => {
                let name = address.name();
                let id = DataId::appendonly(name, address.tag());
                let res = self
                    .get_adata(dest, address, requester.clone())
                    .and_then(|data| match kind {
                        AppendOnlyKind::UnpubSeq => match data.clone() {
                            AData::UnpubSeq(mut adata) => {
                                if unwrap!(adata.verify_requester(requester, ADataAction::Read)) {
                                    unwrap!(adata.append_permissions(permissions));
                                    self.commit_mutation(&dest);
                                    self.insert_data(
                                        id,
                                        Data::AppendOnly(AppendableDataKind::UnpublishedSequenced(
                                            adata,
                                        )),
                                    );
                                    Ok(())
                                } else {
                                    Err(Error::AccessDenied)
                                }
                            }
                            _ => Err(Error::NoSuchData),
                        },
                        AppendOnlyKind::UnpubUnseq => match data {
                            AData::UnpubUnseq(mut adata) => {
                                if unwrap!(adata.verify_requester(requester, ADataAction::Read)) {
                                    unwrap!(adata.append_permissions(permissions));
                                    self.commit_mutation(&dest);
                                    self.insert_data(
                                        id,
                                        Data::AppendOnly(
                                            AppendableDataKind::UnpublishedUnsequenced(adata),
                                        ),
                                    );
                                    Ok(())
                                } else {
                                    Err(Error::AccessDenied)
                                }
                            }
                            _ => Err(Error::NoSuchData),
                        },
                        _ => Err(Error::AccessDenied),
                    });
                Response::AddUnpubADataPermissions(res)
            }
            Request::DeleteAData(address) => {
                let name = address.name();
                let id = DataId::appendonly(name, address.tag());
                let res = self
                    .get_adata(dest, address, requester.clone())
                    .and_then(move |data| match data {
                        AData::PubSeq(_adata) => Err(Error::InvalidOperation),
                        AData::PubUnseq(_adata) => Err(Error::InvalidOperation),
                        AData::UnpubSeq(adata) => {
                            if unwrap!(adata.verify_requester(
                                requester.clone(),
                                ADataAction::ManagePermissions
                            )) {
                                self.commit_mutation(&dest);
                                self.delete_data(id);
                                Ok(())
                            } else {
                                Err(Error::AccessDenied)
                            }
                        }
                        AData::UnpubUnseq(adata) => {
                            if unwrap!(adata.verify_requester(
                                requester.clone(),
                                ADataAction::ManagePermissions
                            )) {
                                self.commit_mutation(&dest);
                                self.delete_data(id);
                                Ok(())
                            } else {
                                Err(Error::AccessDenied)
                            }
                        }
                    });
                Response::AddUnpubADataPermissions(res)
            }
            _ => {
                // Dummy return
                // other requests to be handled by their data type impls
                panic!("RPC not implemented")
            }
        };

        Ok((
            dest,
            unwrap!(serialise(&Message::Response {
                response,
                message_id,
            })),
        ))
    }

    pub fn put_adata(
        &mut self,
        dst: Authority<XorName>,
        data: AData,
        _requester: Requester,
    ) -> Result<(), Error> {
        let data_name = DataId::appendonly(data.name(), data.tag());
        if self.contains_data(&data_name) {
            Err(Error::DataExists)
        } else {
            match data {
                AData::PubSeq(adata) => {
                    self.insert_data(
                        data_name,
                        Data::AppendOnly(AppendableDataKind::PublishedSequenced(adata)),
                    );
                }
                AData::PubUnseq(adata) => {
                    self.insert_data(
                        data_name,
                        Data::AppendOnly(AppendableDataKind::PublishedUnsequenced(adata)),
                    );
                }
                AData::UnpubSeq(adata) => {
                    self.insert_data(
                        data_name,
                        Data::AppendOnly(AppendableDataKind::UnpublishedSequenced(adata)),
                    );
                }
                AData::UnpubUnseq(adata) => {
                    self.insert_data(
                        data_name,
                        Data::AppendOnly(AppendableDataKind::UnpublishedUnsequenced(adata)),
                    );
                }
            }
            self.commit_mutation(&dst);
            Ok(())
        }
    }

    pub fn get_adata(
        &mut self,
        _dst: Authority<XorName>,
        data: AppendOnlyDataRef,
        requester: Requester,
    ) -> Result<AData, Error> {
        let data_name = DataId::appendonly(data.name(), data.tag());
        match self.get_data(&data_name) {
            Some(data_type) => match data_type {
                Data::AppendOnly(kind) => match kind {
                    AppendableDataKind::PublishedSequenced(data) => {
                        if unwrap!(data.verify_requester(requester, ADataAction::Read)) {
                            Ok(AData::PubSeq(data))
                        } else {
                            Err(Error::AccessDenied)
                        }
                    }
                    AppendableDataKind::UnpublishedSequenced(data) => {
                        if unwrap!(data.verify_requester(requester, ADataAction::Read)) {
                            Ok(AData::UnpubSeq(data))
                        } else {
                            Err(Error::AccessDenied)
                        }
                    }
                    AppendableDataKind::UnpublishedUnsequenced(data) => {
                        if unwrap!(data.verify_requester(requester, ADataAction::Read)) {
                            Ok(AData::UnpubUnseq(data))
                        } else {
                            Err(Error::AccessDenied)
                        }
                    }
                    AppendableDataKind::PublishedUnsequenced(data) => {
                        if unwrap!(data.verify_requester(requester, ADataAction::Read)) {
                            Ok(AData::PubUnseq(data))
                        } else {
                            Err(Error::AccessDenied)
                        }
                    }
                },
                _ => Err(Error::NoSuchData),
            },
            None => Err(Error::NoSuchData),
        }
    }

    pub fn get_idata(
        &mut self,
        _dst: Authority<XorName>,
        address: ImmutableDataRef,
        _requester: Requester,
    ) -> Result<ImmutableDataKind, Error> {
        let name = address.name;
        let data_name = DataId::immutable(name, address.published);
        //self.new_authorise_read(&dst, &name)
        // .and_then(|_| self.verify_requester(data_name, requester))
        //.and_then(|_| match self.get_data(&data_name) {
        match self.get_data(&data_name) {
            Some(data_type) => match data_type {
                Data::Immutable(data) => Ok(data),
                _ => Err(Error::NoSuchData),
            },
            None => Err(Error::NoSuchData),
        }
    }

    pub fn put_idata(
        &mut self,
        dst: Authority<XorName>,
        data: ImmutableDataKind,
        _requester: Requester,
    ) -> Result<(), Error> {
        let data_name = DataId::immutable(data.name(), data.published());
        /*
        self.authorise_mutation(&dst, &requester)
            .and_then(|_| {
                if self.contains_data(&data_name) {
                    Err(Error::DataExists)
                } else {
                    self.insert_data(data_name, Data::NewMutable(data));
                    Ok(())
                }
            })
            .map(|_| self.commit_mutation(&dst))
        */
        // FIXME: Put requests verify the app's public key - Usage of BLS-key TBD
        if self.contains_data(&data_name) {
            Err(Error::DataExists)
        } else {
            self.insert_data(data_name, Data::Immutable(data));
            self.commit_mutation(&dst);
            Ok(())
        }
    }

    pub fn delete_idata(
        &mut self,
        dst: Authority<XorName>,
        address: ImmutableDataRef,
        _requester: Requester,
    ) -> Result<(), Error> {
        let data_name = DataId::immutable(address.name, address.published);
        self.authorise_mutation1(&dst)
            // .and_then(|_| self.authorised_delete(data_name, requester))
            .and_then(|_| {
                if !self.contains_data(&data_name) {
                    Err(Error::NoSuchData)
                } else {
                    self.delete_data(data_name);
                    Ok(())
                }
            })
            .map(|_| self.commit_mutation(&dst))
    }

    pub fn get_mdata(
        &mut self,
        _dst: Authority<XorName>,
        address: MutableDataRef,
        requester: Requester,
        request: Request,
        msg_id: MessageId,
        sequenced: Option<bool>,
    ) -> Result<MutableDataKind, Error> {
        let data_name = DataId::mutable(address.name(), address.tag());
        // self.authorise_read(&dst, &address.name())
        // .map_err(|err| Error::from(err.description()))
        // .and_then(|_| match self.get_data(&data_name) {
        dbg!(request.clone());
        match self.get_data(&data_name) {
            Some(data_type) => match data_type {
                Data::NewMutable(data) => match data.clone() {
                    MutableDataKind::Sequenced(mdata) => {
                        if sequenced.is_some() && !unwrap!(sequenced) {
                            Err(Error::from("Unexpected data returned"))
                        } else if mdata.check_permissions(request, requester, msg_id).is_err() {
                            Err(Error::AccessDenied)
                        } else {
                            Ok(data)
                        }
                    }
                    MutableDataKind::Unsequenced(mdata) => {
                        if sequenced.is_some() && unwrap!(sequenced) {
                            Err(Error::from("Unexpected data returned"))
                        } else if mdata.check_permissions(request, requester, msg_id).is_err() {
                            Err(Error::AccessDenied)
                        } else {
                            Ok(data)
                        }
                    }
                },
                _ => Err(Error::NoSuchData),
            },
            None => Err(Error::NoSuchData),
        }
        // })
    }

    pub fn put_mdata(
        &mut self,
        dst: Authority<XorName>,
        data: MutableDataKind,
        _requester: Requester,
    ) -> Result<(), Error> {
        let data_name = DataId::mutable(data.name(), data.tag());
        self.authorise_mutation1(&dst)
            .and_then(|_| {
                if self.contains_data(&data_name) {
                    Err(Error::DataExists)
                } else {
                    self.insert_data(data_name, Data::NewMutable(data));
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
    coin_balances: HashMap<XorName, CoinBalance>,
    client_manager: HashMap<XorName, Account>,
    nae_manager: HashMap<DataId, Data>,
}

#[derive(Clone, Deserialize, Serialize)]
pub enum Data {
    Immutable(ImmutableDataKind),
    OldMutable(OldMutableData),
    NewMutable(MutableDataKind),
    AppendOnly(AppendableDataKind),
}

pub struct ImmutableDataRef {
    name: XorName,
    published: bool,
}

#[derive(Clone, Deserialize, Serialize)]
pub enum ImmutableDataKind {
    Unpublished(UnpubImmutableData),
    Published(ImmutableData),
}

impl ImmutableDataKind {
    fn name(&self) -> XorName {
        match self {
            ImmutableDataKind::Unpublished(data) => *data.name(),
            ImmutableDataKind::Published(data) => *data.name(),
        }
    }

    fn published(&self) -> bool {
        match self {
            ImmutableDataKind::Unpublished(_) => false,
            ImmutableDataKind::Published(_) => true,
        }
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub enum MutableDataKind {
    Sequenced(SeqMutableData),
    Unsequenced(UnseqMutableData),
}

impl MutableDataKind {
    fn name(&self) -> XorName {
        match self {
            MutableDataKind::Sequenced(data) => *data.name(),
            MutableDataKind::Unsequenced(data) => *data.name(),
        }
    }
    fn tag(&self) -> u64 {
        match self {
            MutableDataKind::Sequenced(data) => data.tag(),
            MutableDataKind::Unsequenced(data) => data.tag(),
        }
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub enum AppendableDataKind {
    PublishedSequenced(SeqAppendOnlyData<PubPermissions>),
    PublishedUnsequenced(UnseqAppendOnlyData<PubPermissions>),
    UnpublishedSequenced(SeqAppendOnlyData<UnpubPermissions>),
    UnpublishedUnsequenced(UnseqAppendOnlyData<UnpubPermissions>),
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
