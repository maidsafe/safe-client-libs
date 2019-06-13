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
    verify_signature, Coins, Error, IDataKind, MDataAddress, Message, MessageId,
    MutableData as NewMutableData, PublicId, PublicKey, Request, Response, SeqMutableData,
    Signature, Transaction, UnseqMutableData, XorName,
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
        coin_balance_name: &XorName,
        req: &Request,
        msg_id: MessageId,
        requester_pk: PublicKey,
        signature: Option<Signature>,
    ) -> Result<(), Error> {
        let sig = match signature {
            Some(s) => s,
            None => return Err(Error::InvalidSignature),
        };
        verify_signature(&sig, &requester_pk, req, &msg_id)?;
        // Check if we are the owner or app.
        let balance = match self.get_coin_balance(&coin_balance_name) {
            Some(balance) => balance,
            None => {
                debug!("Coin balance {:?} not found", coin_balance_name);
                return Err(Error::NoSuchAccount);
            }
        };
        let owner_account = XorName::from(PublicKey::from(*balance.owner()));

        if PublicKey::from(*balance.owner()) == requester_pk {
            Ok(())
        } else {
            let account = match self.get_account(&owner_account) {
                Some(account) => account,
                None => {
                    debug!("Account not found for {:?}", owner_account);
                    return Err(Error::NoSuchAccount);
                }
            };
            match account.auth_keys().get(&requester_pk) {
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

    fn transfer_coins(
        &mut self,
        source: XorName,
        destination: XorName,
        amount: Coins,
        transaction_id: u64,
    ) -> Result<(), Error> {
        match self.get_coin_balance_mut(&source) {
            Some(balance) => balance.debit_balance(amount)?,
            None => return Err(Error::NoSuchAccount),
        };
        match self.get_coin_balance_mut(&destination) {
            Some(balance) => balance.credit_balance(amount, transaction_id)?,
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
        requester: PublicId,
        payload: Vec<u8>,
    ) -> Result<Message, Error> {
        let (request, message_id, signature) = if let Message::Request {
            request,
            message_id,
            signature,
        } = unwrap!(deserialise(&payload))
        {
            (request, message_id, signature)
        } else {
            return Err(Error::from("Unexpected Message type"));
        };

        // Requester's public key
        let requester_pk = match requester.clone() {
            PublicId::App(pk) => *pk.public_key(),
            PublicId::Client(pk) => *pk.public_key(),
            PublicId::Node(_) => return Err(Error::AccessDenied),
        };
        let response = match request.clone() {
            //
            // Immutable Data
            //
            Request::GetIData(address) => {
                let result = self
                    .get_idata(ImmutableDataRef {
                        name: *address.name(),
                        published: address.published(),
                    })
                    .and_then(|kind| match kind {
                        IDataKind::Unpub(ref data) => {
                            // Check permissions for unpub idata.
                            if PublicKey::from(*data.owners()) == requester_pk {
                                let sig = match signature {
                                    None => return Err(Error::InvalidSignature),
                                    Some(s) => s,
                                };
                                verify_signature(&sig, &requester_pk, &request, &message_id)?;
                                Ok(kind)
                            } else {
                                Err(Error::AccessDenied)
                            }
                        }
                        IDataKind::Pub(_) => Ok(kind),
                    });

                Response::GetIData(result)
            }
            Request::PutIData(kind) => {
                let result = self.put_data(
                    DataId::immutable(*kind.name(), kind.published()),
                    Data::Immutable(kind),
                    requester,
                    requester_pk,
                    request,
                    message_id,
                    signature,
                );
                Response::PutIData(result)
            }
            Request::DeleteUnpubIData(address) => {
                let result = self.delete_idata(
                    ImmutableDataRef {
                        name: *address.name(),
                        published: false,
                    },
                    requester,
                    requester_pk,
                );
                Response::DeleteUnpubIData(result)
            }
            Request::ListAuthKeysAndVersion => {
                let name = requester.name();
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
                let name = requester.name();
                if let Some(account) = self.get_account_mut(&name) {
                    Response::InsAuthKey(account.ins_auth_key(key, permissions, version))
                } else {
                    return Err(Error::NoSuchAccount);
                }
            }
            Request::DelAuthKey { key, version } => {
                let name = requester.name();
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
                if let Err(e) = self.authorise_coin_operation(
                    &source,
                    &request,
                    message_id,
                    requester_pk,
                    signature,
                ) {
                    Response::TransferCoins(Err(e))
                } else {
                    let res = self.transfer_coins(source, destination, amount, transaction_id);
                    Response::TransferCoins(res)
                }
            }
            Request::GetBalance(coins_balance_id) => {
                if let Err(e) = self.authorise_coin_operation(
                    &coins_balance_id,
                    &request,
                    message_id,
                    requester_pk,
                    signature,
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
            Request::PutUnseqMData(data) => {
                let result = self.put_data(
                    DataId::mutable(*data.name(), data.tag()),
                    Data::NewMutable(MutableDataKind::Unsequenced(data.clone())),
                    requester,
                    requester_pk,
                    request,
                    message_id,
                    signature,
                );
                Response::PutUnseqMData(result)
            }
            Request::GetMData(address) => {
                let result = self.get_mdata(address, requester_pk, request, message_id, signature);

                match (address, result) {
                    (MDataAddress::Seq { .. }, Ok(MutableDataKind::Sequenced(mdata))) => {
                        Response::GetSeqMData(Ok(mdata))
                    }
                    (MDataAddress::Unseq { .. }, Ok(MutableDataKind::Unsequenced(mdata))) => {
                        Response::GetUnseqMData(Ok(mdata))
                    }
                    (MDataAddress::Seq { .. }, Err(err)) => Response::GetSeqMData(Err(err)),
                    (MDataAddress::Unseq { .. }, Err(err)) => Response::GetUnseqMData(Err(err)),
                    (MDataAddress::Seq { .. }, Ok(MutableDataKind::Unsequenced(_))) => {
                        Response::GetSeqMData(Err(Error::from("Unexpected data returned")))
                    }
                    (MDataAddress::Unseq { .. }, Ok(MutableDataKind::Sequenced(_))) => {
                        Response::GetSeqMData(Err(Error::from("Unexpected data returned")))
                    }
                }
            }
            Request::PutSeqMData(data) => {
                let result = self.put_data(
                    DataId::mutable(*data.name(), data.tag()),
                    Data::NewMutable(MutableDataKind::Sequenced(data.clone())),
                    requester,
                    requester_pk,
                    request,
                    message_id,
                    signature,
                );
                Response::PutSeqMData(result)
            }
            Request::GetMDataValue { address, ref key } => {
                let result = self.get_mdata(
                    address,
                    requester_pk,
                    request.clone(),
                    message_id,
                    signature,
                );

                match (address, result) {
                    (MDataAddress::Seq { .. }, Ok(MutableDataKind::Sequenced(mdata))) => {
                        Response::GetSeqMDataValue(Ok(mdata.get(&key).unwrap().clone()))
                    }
                    (MDataAddress::Unseq { .. }, Ok(MutableDataKind::Unsequenced(mdata))) => {
                        Response::GetUnseqMDataValue(Ok(mdata.get(&key).unwrap().clone()))
                    }
                    (MDataAddress::Seq { .. }, Err(err)) => Response::GetSeqMDataValue(Err(err)),
                    (MDataAddress::Unseq { .. }, Err(err)) => {
                        Response::GetUnseqMDataValue(Err(err))
                    }
                    (MDataAddress::Seq { .. }, Ok(MutableDataKind::Unsequenced(_))) => {
                        Response::GetSeqMDataValue(Err(Error::from("Unexpected data returned")))
                    }
                    (MDataAddress::Unseq { .. }, Ok(MutableDataKind::Sequenced(_))) => {
                        Response::GetUnseqMDataValue(Err(Error::from("Unexpected data returned")))
                    }
                }
            }
            Request::GetMDataShell(address) => {
                let result = self.get_mdata(address, requester_pk, request, message_id, signature);

                match (address, result) {
                    (MDataAddress::Seq { .. }, Ok(MutableDataKind::Sequenced(mdata))) => {
                        Response::GetSeqMDataShell(Ok(mdata.shell()))
                    }
                    (MDataAddress::Unseq { .. }, Ok(MutableDataKind::Unsequenced(mdata))) => {
                        Response::GetUnseqMDataShell(Ok(mdata.shell()))
                    }
                    (MDataAddress::Seq { .. }, Err(err)) => Response::GetSeqMDataShell(Err(err)),
                    (MDataAddress::Unseq { .. }, Err(err)) => {
                        Response::GetUnseqMDataShell(Err(err))
                    }
                    (MDataAddress::Seq { .. }, Ok(MutableDataKind::Unsequenced(_))) => {
                        Response::GetSeqMDataShell(Err(Error::from("Unexpected data returned")))
                    }
                    (MDataAddress::Unseq { .. }, Ok(MutableDataKind::Sequenced(_))) => {
                        Response::GetUnseqMDataShell(Err(Error::from("Unexpected data returned")))
                    }
                }
            }
            Request::GetMDataVersion(address) => {
                let result = self
                    .get_mdata(address, requester_pk, request, message_id, signature)
                    .and_then(|data| match data {
                        MutableDataKind::Sequenced(mdata) => Ok(mdata.version()),
                        MutableDataKind::Unsequenced(mdata) => Ok(mdata.version()),
                    });
                Response::GetMDataVersion(result)
            }
            Request::ListMDataEntries(address) => {
                let result = self.get_mdata(address, requester_pk, request, message_id, signature);

                match (address, result) {
                    (MDataAddress::Seq { .. }, Ok(MutableDataKind::Sequenced(mdata))) => {
                        Response::ListSeqMDataEntries(Ok(mdata.entries().clone()))
                    }
                    (MDataAddress::Unseq { .. }, Ok(MutableDataKind::Unsequenced(mdata))) => {
                        Response::ListUnseqMDataEntries(Ok(mdata.entries().clone()))
                    }
                    (MDataAddress::Seq { .. }, Err(err)) => Response::ListSeqMDataEntries(Err(err)),
                    (MDataAddress::Unseq { .. }, Err(err)) => {
                        Response::ListUnseqMDataEntries(Err(err))
                    }
                    (MDataAddress::Seq { .. }, Ok(MutableDataKind::Unsequenced(_))) => {
                        Response::ListSeqMDataEntries(Err(Error::from("Unexpected data returned")))
                    }
                    (MDataAddress::Unseq { .. }, Ok(MutableDataKind::Sequenced(_))) => {
                        Response::ListUnseqMDataEntries(Err(Error::from(
                            "Unexpected data returned",
                        )))
                    }
                }
            }
            Request::ListMDataKeys(address) => {
                let result = self
                    .get_mdata(address, requester_pk, request, message_id, signature)
                    .and_then(|data| match data {
                        MutableDataKind::Sequenced(mdata) => Ok(mdata.keys().clone()),
                        MutableDataKind::Unsequenced(mdata) => Ok(mdata.keys().clone()),
                    });
                Response::ListMDataKeys(result)
            }
            Request::ListMDataValues(address) => {
                let result = self.get_mdata(address, requester_pk, request, message_id, signature);
                match (address, result) {
                    (MDataAddress::Seq { .. }, Ok(MutableDataKind::Sequenced(mdata))) => {
                        Response::ListSeqMDataValues(Ok(mdata.values()))
                    }
                    (MDataAddress::Unseq { .. }, Ok(MutableDataKind::Unsequenced(mdata))) => {
                        Response::ListUnseqMDataValues(Ok(mdata.values()))
                    }
                    (MDataAddress::Seq { .. }, Err(err)) => Response::ListSeqMDataValues(Err(err)),
                    (MDataAddress::Unseq { .. }, Err(err)) => {
                        Response::ListUnseqMDataValues(Err(err))
                    }
                    (MDataAddress::Seq { .. }, Ok(MutableDataKind::Unsequenced(_))) => {
                        Response::ListSeqMDataValues(Err(Error::from("Unexpected data returned")))
                    }
                    (MDataAddress::Unseq { .. }, Ok(MutableDataKind::Sequenced(_))) => {
                        Response::ListUnseqMDataValues(Err(Error::from("Unexpected data returned")))
                    }
                }
            }
            Request::DeleteMData(address) => {
                let res = self
                    .get_mdata(address, requester_pk, request, message_id, signature)
                    .and_then(|data| match data {
                        MutableDataKind::Sequenced(mdata) => {
                            if let PublicId::Client(client_id) = requester.clone() {
                                if client_id.public_key() == mdata.owners() {
                                    self.delete_data(DataId::mutable(*mdata.name(), mdata.tag()));
                                    self.commit_mutation(requester.name());
                                    Ok(())
                                } else {
                                    Err(Error::InvalidOwners)
                                }
                            } else {
                                Err(Error::AccessDenied)
                            }
                        }
                        MutableDataKind::Unsequenced(mdata) => {
                            if let PublicId::Client(client_id) = requester.clone() {
                                if client_id.public_key() == mdata.owners() {
                                    self.delete_data(DataId::mutable(*mdata.name(), mdata.tag()));
                                    self.commit_mutation(requester.name());
                                    Ok(())
                                } else {
                                    Err(Error::InvalidOwners)
                                }
                            } else {
                                Err(Error::AccessDenied)
                            }
                        }
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
                        address,
                        requester_pk,
                        request.clone(),
                        message_id,
                        signature,
                    )
                    .and_then(|data| {
                        let data_name = DataId::mutable(data.name(), data.tag());
                        match data.clone() {
                            MutableDataKind::Unsequenced(mut mdata) => {
                                mdata.set_user_permissions(*user, permissions, version)?;
                                self.insert_data(
                                    data_name,
                                    Data::NewMutable(MutableDataKind::Unsequenced(mdata)),
                                );
                                self.commit_mutation(requester.name());
                                Ok(())
                            }
                            MutableDataKind::Sequenced(mut mdata) => {
                                mdata.set_user_permissions(*user, permissions, version)?;
                                self.insert_data(
                                    data_name,
                                    Data::NewMutable(MutableDataKind::Sequenced(mdata)),
                                );
                                self.commit_mutation(requester.name());
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
                    .get_mdata(address, requester_pk, request, message_id, signature)
                    .and_then(|data| {
                        let data_name = DataId::mutable(data.name(), data.tag());
                        match data.clone() {
                            MutableDataKind::Unsequenced(mut mdata) => {
                                mdata.del_user_permissions(user, version)?;
                                self.insert_data(
                                    data_name,
                                    Data::NewMutable(MutableDataKind::Unsequenced(mdata)),
                                );
                            }
                            MutableDataKind::Sequenced(mut mdata) => {
                                mdata.del_user_permissions(user, version)?;
                                self.insert_data(
                                    data_name,
                                    Data::NewMutable(MutableDataKind::Sequenced(mdata)),
                                );
                            }
                        }
                        self.commit_mutation(requester.name());
                        Ok(())
                    });
                Response::DelMDataUserPermissions(result)
            }
            Request::ListMDataUserPermissions { address, ref user } => {
                let user = *user;

                let result = self
                    .get_mdata(address, requester_pk, request, message_id, signature)
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
            Request::ListMDataPermissions(address) => {
                let result = self
                    .get_mdata(address, requester_pk, request, message_id, signature)
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
                let result = self
                    .get_mdata(
                        address,
                        requester_pk,
                        request.clone(),
                        message_id,
                        signature,
                    )
                    .and_then(move |data| {
                        let data_name = DataId::mutable(data.name(), data.tag());
                        match data.clone() {
                            MutableDataKind::Sequenced(mut mdata) => {
                                mdata.mutate_entries(actions.clone(), requester_pk)?;
                                self.insert_data(
                                    data_name,
                                    Data::NewMutable(MutableDataKind::Sequenced(mdata)),
                                );
                                self.commit_mutation(requester.name());
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
                    .get_mdata(address, requester_pk, request, message_id, signature)
                    .and_then(move |data| {
                        let data_name = DataId::mutable(data.name(), data.tag());
                        match data.clone() {
                            MutableDataKind::Unsequenced(mut mdata) => {
                                mdata.mutate_entries(actions.clone(), requester_pk)?;
                                self.insert_data(
                                    data_name,
                                    Data::NewMutable(MutableDataKind::Unsequenced(mdata)),
                                );
                                self.commit_mutation(requester.name());
                                Ok(())
                            }
                            _ => Err(Error::from("Unexpected data returned")),
                        }
                    });
                Response::MutateUnseqMDataEntries(result)
            }
            _ => panic!("RPC not handled"),
        };

        Ok(Message::Response {
            response,
            message_id,
        })
    }

    pub fn get_idata(&mut self, address: ImmutableDataRef) -> Result<IDataKind, Error> {
        let name = address.name;
        let data_name = DataId::immutable(name, address.published);
        match self.get_data(&data_name) {
            Some(data_type) => match data_type {
                Data::Immutable(data) => Ok(data),
                _ => Err(Error::NoSuchData),
            },
            None => Err(Error::NoSuchData),
        }
    }

    pub fn delete_idata(
        &mut self,
        address: ImmutableDataRef,
        requester: PublicId,
        requester_pk: PublicKey,
    ) -> Result<(), Error> {
        let data_name = DataId::immutable(address.name, address.published);
        match self.get_data(&data_name) {
            Some(idata) => {
                if let Data::Immutable(kind) = idata {
                    if let IDataKind::Unpub(unpub_idata) = kind {
                        if PublicKey::from(*unpub_idata.owners()) == requester_pk {
                            self.delete_data(data_name);
                            self.commit_mutation(requester.name());
                            Ok(())
                        } else {
                            Err(Error::AccessDenied)
                        }
                    } else {
                        Err(Error::InvalidOperation)
                    }
                } else {
                    Err(Error::NoSuchData)
                }
            }
            None => Err(Error::NoSuchData),
        }
    }

    pub fn get_mdata(
        &mut self,
        address: MDataAddress,
        requester_pk: PublicKey,
        request: Request,
        msg_id: MessageId,
        signature: Option<Signature>,
    ) -> Result<MutableDataKind, Error> {
        let data_name = DataId::mutable(*address.name(), address.tag());
        let sig = match signature {
            Some(s) => s,
            None => return Err(Error::InvalidSignature),
        };
        verify_signature(&sig, &requester_pk, &request, &msg_id)?;
        match self.get_data(&data_name) {
            Some(data_type) => match data_type {
                Data::NewMutable(data) => match data.clone() {
                    MutableDataKind::Sequenced(mdata) => {
                        if address.is_unseq() {
                            Err(Error::from("Unexpected data returned"))
                        } else if mdata.check_permissions(request, requester_pk).is_err() {
                            Err(Error::AccessDenied)
                        } else {
                            Ok(data)
                        }
                    }
                    MutableDataKind::Unsequenced(mdata) => {
                        if address.is_seq() {
                            Err(Error::from("Unexpected data returned"))
                        } else if mdata.check_permissions(request, requester_pk).is_err() {
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
    }

    pub fn put_data(
        &mut self,
        data_name: DataId,
        data: Data,
        requester: PublicId,
        requester_pk: PublicKey,
        request: Request,
        msg_id: MessageId,
        signature: Option<Signature>,
    ) -> Result<(), Error> {
        let sig = match signature {
            Some(s) => s,
            None => return Err(Error::InvalidSignature),
        };
        match requester.clone() {
            PublicId::Client(client_public_id) => {
                if self.get_account(client_public_id.name()).is_none() {
                    return Err(Error::NoSuchAccount);
                }
            }
            PublicId::App(app_public_id) => match self.get_account(app_public_id.owner_name()) {
                None => return Err(Error::NoSuchAccount),
                Some(account) => {
                    if !account.auth_keys().contains_key(app_public_id.public_key()) {
                        return Err(Error::AccessDenied);
                    }
                }
            },
            _ => return Err(Error::AccessDenied),
        }
        verify_signature(&sig, &requester_pk, &request, &msg_id)?;
        if self.contains_data(&data_name) {
            Err(Error::DataExists)
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

#[derive(Clone, Deserialize, Serialize)]
pub enum Data {
    Immutable(IDataKind),
    OldMutable(OldMutableData),
    NewMutable(MutableDataKind),
}

pub struct ImmutableDataRef {
    name: XorName,
    published: bool,
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
