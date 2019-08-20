// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::DataId;
use super::{Account, CoinBalance};
use crate::client::mock::connection_manager::unlimited_muts;
use crate::client::COST_OF_PUT;
use crate::config_handler::{Config, DevConfig};
use fs2::FileExt;
use maidsafe_utilities::serialisation::{deserialise, serialise};
use routing::{Authority, ClientError};
use safe_nd::{
    verify_signature, AData, ADataAction, ADataAddress, ADataIndex, AppPermissions, AppendOnlyData,
    Coins, Error as SndError, IData, IDataAddress, LoginPacket, MData, MDataAction, MDataAddress,
    MDataKind, Message, PublicId, PublicKey, Request, Response, Result as SndResult, SeqAppendOnly,
    Transaction, UnseqAppendOnly, XorName,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
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
    Mutable(MData),
    AppendOnly(AData),
}

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
// 1. "SAFE_MOCK_IN_MEMORY_STORAGE" env var => in-memory storage
// 2. DevConfig `mock_in_memory_storage` option => in-memory storage
// 3. Else => file storage, use path from `init_vault_path`
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
            None => {
                trace!("Mock vault: using file store");
                Box::new(FileStore::new(&init_vault_path(None)))
            }
        },
    }
}

// NOTE: This most probably should be in safe-nd::AData
fn check_is_owner_adata(data: &AData, requester: PublicKey) -> SndResult<()> {
    data.owner(data.owners_index() - 1).map_or_else(
        || Err(SndError::InvalidOwners),
        move |owner| {
            if owner.public_key == requester {
                Ok(())
            } else {
                Err(SndError::AccessDenied)
            }
        },
    )
}

fn check_perms_adata(data: &AData, request: &Request, requester: PublicKey) -> SndResult<()> {
    match request {
        Request::GetAData(..)
        | Request::GetADataShell { .. }
        | Request::GetADataValue { .. }
        | Request::GetADataRange { .. }
        | Request::GetADataIndices(..)
        | Request::GetADataLastEntry(..)
        | Request::GetADataPermissions { .. }
        | Request::GetPubADataUserPermissions { .. }
        | Request::GetUnpubADataUserPermissions { .. }
        | Request::GetADataOwners { .. } => match data {
            AData::PubUnseq(_) | AData::PubSeq(_) => Ok(()),
            AData::UnpubSeq(_) | AData::UnpubUnseq(_) => data
                .check_permission(ADataAction::Read, requester)
                .map_err(|_| SndError::AccessDenied),
        },
        Request::AppendSeq { .. } | Request::AppendUnseq { .. } => data
            .check_permission(ADataAction::Append, requester)
            .map_err(|_| SndError::AccessDenied),
        Request::AddPubADataPermissions { .. } | Request::AddUnpubADataPermissions { .. } => data
            .check_permission(ADataAction::ManagePermissions, requester)
            .map_err(|_| SndError::AccessDenied),
        Request::SetADataOwner { .. } => check_is_owner_adata(data, requester),
        Request::DeleteAData(_) => match data {
            AData::PubSeq(_) | AData::PubUnseq(_) => Err(SndError::InvalidOperation),
            AData::UnpubSeq(_) | AData::UnpubUnseq(_) => check_is_owner_adata(data, requester),
        },
        _ => Err(SndError::InvalidOperation),
    }
}

fn check_perms_mdata(data: &MData, request: &Request, requester: PublicKey) -> SndResult<()> {
    match request {
        Request::GetMData { .. }
        | Request::GetMDataShell { .. }
        | Request::GetMDataVersion { .. }
        | Request::ListMDataKeys { .. }
        | Request::ListMDataEntries { .. }
        | Request::ListMDataValues { .. }
        | Request::GetMDataValue { .. }
        | Request::ListMDataPermissions { .. }
        | Request::ListMDataUserPermissions { .. } => {
            data.check_permissions(MDataAction::Read, requester)
        }

        Request::SetMDataUserPermissions { .. } | Request::DelMDataUserPermissions { .. } => {
            data.check_permissions(MDataAction::ManagePermissions, requester)
        }

        Request::MutateMDataEntries { .. } => Ok(()),

        Request::DeleteMData { .. } => data.check_is_owner(requester),

        _ => Err(SndError::InvalidOperation),
    }
}

enum RequestType {
    GetForPub,
    GetForUnpub,
    Mutation,
}

// Is the request a GET and if so, is it for pub or unpub data?
fn request_is_get(request: &Request) -> RequestType {
    match *request {
        Request::GetIData(address) => {
            if address.is_pub() {
                RequestType::GetForPub
            } else {
                RequestType::GetForUnpub
            }
        }

        Request::GetAData(address)
        | Request::GetADataShell { address, .. }
        | Request::GetADataRange { address, .. }
        | Request::GetADataValue { address, .. }
        | Request::GetADataIndices(address)
        | Request::GetADataLastEntry(address)
        | Request::GetADataPermissions { address, .. }
        | Request::GetPubADataUserPermissions { address, .. }
        | Request::GetUnpubADataUserPermissions { address, .. }
        | Request::GetADataOwners { address, .. } => {
            if address.is_pub() {
                RequestType::GetForPub
            } else {
                RequestType::GetForUnpub
            }
        }

        Request::GetMData(_)
        | Request::GetMDataValue { .. }
        | Request::GetMDataShell(_)
        | Request::GetMDataVersion(_)
        | Request::ListMDataEntries(_)
        | Request::ListMDataKeys(_)
        | Request::ListMDataValues(_)
        | Request::ListMDataPermissions(_)
        | Request::ListMDataUserPermissions { .. } => RequestType::GetForUnpub,

        _ => RequestType::Mutation,
    }
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
        balance.credit_balance(amount, new_rand::random())
    }

    // Authorise coin operation.
    pub fn authorise_coin_operation(
        &self,
        coin_balance_name: &XorName,
        requester_pk: PublicKey,
    ) -> SndResult<()> {
        // Check if we are the owner or app.
        let balance = match self.get_coin_balance(&coin_balance_name) {
            Some(balance) => balance,
            None => {
                debug!("Coin balance {:?} not found", coin_balance_name);
                return Err(SndError::NoSuchBalance);
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
                    return Err(SndError::AccessDenied);
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

        let account = self.get_account(&dst_name);

        let owner_name = XorName::from(*sign_pk);
        let balance = match self.get_balance(&dst_name) {
            Ok(coins) => coins,
            Err(_) => return Err(ClientError::AccessDenied),
        };

        match account {
            None => {
                if owner_name != dst_name {
                    debug!("No apps authorised");
                    return Err(ClientError::AccessDenied);
                }
            }
            Some(account) => {
                if owner_name != dst_name && !account.auth_keys().contains_key(sign_pk) {
                    debug!("Mutation not authorised");
                    return Err(ClientError::AccessDenied);
                }
            }
        };

        let unlimited_mut = unlimited_muts(&self.config);

        if !unlimited_mut && balance.checked_sub(*COST_OF_PUT).is_none() {
            return Err(ClientError::LowBalance);
        }
        Ok(())
    }

    // Commit a mutation.
    pub fn commit_mutation(&mut self, account: &XorName) {
        let unlimited_mut = unlimited_muts(&self.config);
        if !unlimited_mut {
            let balance = unwrap!(self.get_coin_balance_mut(account));
            unwrap!(balance.debit_balance(*COST_OF_PUT));
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

    fn create_balance(&mut self, destination: XorName, owner: PublicKey) -> SndResult<()> {
        if self.get_coin_balance(&destination).is_some() {
            return Err(SndError::BalanceExists);
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
    ) -> SndResult<Transaction> {
        match self.get_coin_balance_mut(&source) {
            Some(balance) => balance.debit_balance(amount)?,
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

    fn get_balance(&self, coins_balance_id: &XorName) -> SndResult<Coins> {
        match self.get_coin_balance(coins_balance_id) {
            Some(balance) => Ok(balance.balance()),
            None => Err(SndError::NoSuchBalance),
        }
    }

    #[allow(clippy::cognitive_complexity)]
    pub fn process_request(&mut self, requester: PublicId, payload: &[u8]) -> SndResult<Message> {
        // Deserialise the request, returning an early error on failure.
        let (request, message_id, signature) = if let Message::Request {
            request,
            message_id,
            signature,
        } =
            deserialise(payload).map_err(|_| SndError::from("Error deserialising message"))?
        {
            (request, message_id, signature)
        } else {
            return Err(SndError::from("Unexpected Message type"));
        };

        // Get the requester's public key.
        let result = match requester.clone() {
            PublicId::App(pk) => Ok((true, *pk.public_key(), *pk.owner().public_key())),
            PublicId::Client(pk) => Ok((false, *pk.public_key(), *pk.public_key())),
            PublicId::Node(_) => Err(SndError::AccessDenied),
        }
        .and_then(|(is_app, requester_pk, owner_pk)| {
            let request_type = request_is_get(&request);

            match request_type {
                RequestType::GetForUnpub | RequestType::Mutation => {
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
                RequestType::GetForPub => (),
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
                let mut errored = false;
                if let IData::Unpub(data) = idata.clone() {
                    if owner_pk != *data.owner() {
                        errored = true
                    }
                }

                let result = if errored {
                    Err(SndError::InvalidOwners)
                } else {
                    self.put_data(
                        DataId::Immutable(*idata.address()),
                        Data::Immutable(idata),
                        requester,
                    )
                };
                Response::Mutation(result)
            }
            Request::DeleteUnpubIData(address) => {
                let result = self.delete_idata(address, requester, requester_pk);
                Response::Mutation(result)
            }
            // ===== Client (Owner) to SrcElders =====
            Request::ListAuthKeysAndVersion => {
                let result = {
                    if owner_pk != requester_pk {
                        Err(SndError::AccessDenied)
                    } else {
                        Ok(self.list_auth_keys_and_version(&requester.name()))
                    }
                };
                Response::ListAuthKeysAndVersion(result)
            }
            Request::InsAuthKey {
                key,
                permissions,
                version,
            } => {
                let result = if owner_pk != requester_pk {
                    Err(SndError::AccessDenied)
                } else {
                    self.ins_auth_key(&requester.name(), key, permissions, version)
                };
                Response::Mutation(result)
            }
            Request::DelAuthKey { key, version } => {
                let result = if owner_pk != requester_pk {
                    Err(SndError::AccessDenied)
                } else {
                    self.del_auth_key(&requester.name(), key, version)
                };
                Response::Mutation(result)
            }
            // ===== Coins =====
            Request::TransferCoins {
                destination,
                amount,
                transaction_id,
            } => {
                let source: XorName = owner_pk.into();

                let result = self
                    .authorise_coin_operation(&source, requester_pk)
                    .and_then(|()| {
                        self.transfer_coins(source, destination, amount, transaction_id)
                    });
                Response::Transaction(result)
            }
            Request::CreateBalance {
                amount,
                new_balance_owner,
                transaction_id,
            } => {
                let source = owner_pk.into();
                let destination = new_balance_owner.into();

                let result = if source == destination {
                    self.mock_create_balance(new_balance_owner, amount);
                    Ok(Transaction {
                        id: transaction_id,
                        amount,
                    })
                } else {
                    self.authorise_coin_operation(&source, requester_pk)
                        .and_then(|()| {
                            self.get_balance(&source)
                                .and_then(|source_balance| {
                                    if source_balance.checked_sub(amount).is_none() {
                                        return Err(SndError::InsufficientBalance);
                                    }
                                    self.create_balance(destination, new_balance_owner)
                                })
                                .and_then(|()| {
                                    self.transfer_coins(source, destination, amount, transaction_id)
                                })
                        })
                };
                Response::Transaction(result)
            }
            Request::GetBalance => {
                let coin_balance_id = owner_pk.into();

                let result = self
                    .authorise_coin_operation(&coin_balance_id, requester_pk)
                    .and_then(|()| self.get_balance(&coin_balance_id));
                Response::GetBalance(result)
            }
            // ===== Account =====
            Request::CreateLoginPacketFor {
                new_owner,
                amount,
                transaction_id,
                new_login_packet,
            } => {
                let source = owner_pk.into();
                let new_balance_dest = new_owner.into();

                // Check if the requester is authorized to perform coin transactions.
                let result = if let Err(e) = self.authorise_coin_operation(&source, requester_pk) {
                    Err(e)
                }
                // If a login packet at the given destination exists return an error.
                else if self
                    .get_login_packet(new_login_packet.destination())
                    .is_some()
                {
                    Err(SndError::LoginPacketExists)
                } else {
                    self.get_balance(&source)
                        .and_then(|source_balance| {
                            let debit_amt = amount.checked_add(*COST_OF_PUT);
                            match debit_amt {
                                Some(amt) => {
                                    // Check if the balance has sufficient coin for the transfer and
                                    // an additional PUT operation.
                                    if source_balance.checked_sub(amt).is_none() {
                                        return Err(SndError::InsufficientBalance);
                                    }
                                }
                                None => return Err(SndError::ExcessiveValue),
                            }

                            // Debit the requester's wallet the cost of inserting a login packet
                            match self.get_coin_balance_mut(&source) {
                                Some(balance) => balance.debit_balance(*COST_OF_PUT)?,
                                None => return Err(SndError::NoSuchBalance),
                            };

                            // Create the balance and transfer the mentioned amount of coins
                            self.create_balance(new_balance_dest, new_owner)
                        })
                        .and_then(|_| {
                            self.transfer_coins(source, new_balance_dest, amount, transaction_id)
                        })
                        // Store the login packet
                        .map(|_| {
                            self.insert_login_packet(new_login_packet);

                            Transaction {
                                id: transaction_id,
                                amount,
                            }
                        })
                };
                Response::Transaction(result)
            }
            Request::CreateLoginPacket(account_data) => {
                let source = owner_pk.into();

                if let Err(e) = self.authorise_coin_operation(&source, requester_pk) {
                    Response::Mutation(Err(e))
                } else if self.get_login_packet(account_data.destination()).is_some() {
                    Response::Mutation(Err(SndError::LoginPacketExists))
                } else {
                    let result = self
                        .get_balance(&source)
                        .and_then(|source_balance| {
                            if source_balance.checked_sub(*COST_OF_PUT).is_none() {
                                return Err(SndError::InsufficientBalance);
                            }
                            match self.get_coin_balance_mut(&source) {
                                Some(balance) => balance.debit_balance(*COST_OF_PUT)?,
                                None => return Err(SndError::NoSuchBalance),
                            };
                            Ok(())
                        })
                        .map(|_| self.insert_login_packet(account_data));
                    Response::Mutation(result)
                }
            }
            Request::GetLoginPacket(location) => {
                let result = match self.get_login_packet(&location) {
                    None => Err(SndError::NoSuchLoginPacket),
                    Some(login_packet) => {
                        if *login_packet.authorised_getter() == requester_pk {
                            Ok((
                                login_packet.data().to_vec(),
                                login_packet.signature().clone(),
                            ))
                        } else {
                            Err(SndError::AccessDenied)
                        }
                    }
                };
                Response::GetLoginPacket(result)
            }
            Request::UpdateLoginPacket(new_packet) => {
                let result = {
                    match self.get_login_packet(new_packet.destination()) {
                        Some(old_packet) => {
                            if *old_packet.authorised_getter() == requester_pk {
                                self.insert_login_packet(new_packet);
                                Ok(())
                            } else {
                                Err(SndError::AccessDenied)
                            }
                        }
                        None => Err(SndError::NoSuchLoginPacket),
                    }
                };
                Response::Mutation(result)
            }
            // ===== Mutable Data =====
            Request::GetMData(address) => {
                let result = self
                    .get_mdata(address, requester_pk, request)
                    .and_then(|data| {
                        if address != *data.address() {
                            return Err(SndError::NoSuchData);
                        }

                        Ok(data)
                    });
                Response::GetMData(result)
            }
            Request::PutMData(data) => {
                let address = *data.address();

                let result = if data.owner() != owner_pk {
                    Err(SndError::InvalidOwners)
                } else {
                    self.put_data(
                        DataId::Mutable(address),
                        Data::Mutable(data.clone()),
                        requester,
                    )
                };
                Response::Mutation(result)
            }
            Request::GetMDataValue { address, ref key } => {
                let data = self.get_mdata(address, requester_pk, request.clone());

                match (address.kind(), data) {
                    (MDataKind::Seq, Ok(MData::Seq(mdata))) => {
                        let result = mdata
                            .get(&key)
                            .map(|value| value.clone().into())
                            .ok_or(SndError::NoSuchEntry);
                        Response::GetMDataValue(result)
                    }
                    (MDataKind::Unseq, Ok(MData::Unseq(mdata))) => {
                        let result = mdata
                            .get(&key)
                            .map(|value| value.clone().into())
                            .ok_or(SndError::NoSuchEntry);
                        Response::GetMDataValue(result)
                    }
                    (_, Err(err)) => Response::GetMDataValue(Err(err)),
                    (_, Ok(_)) => Response::GetMDataValue(Err(SndError::NoSuchData)),
                }
            }
            Request::GetMDataShell(address) => {
                let result = self
                    .get_mdata(address, requester_pk, request)
                    .and_then(|data| {
                        if address != *data.address() {
                            return Err(SndError::NoSuchData);
                        }

                        Ok(data.shell())
                    });
                Response::GetMDataShell(result)
            }
            Request::GetMDataVersion(address) => {
                let result = self
                    .get_mdata(address, requester_pk, request)
                    .and_then(|data| {
                        if address != *data.address() {
                            return Err(SndError::NoSuchData);
                        }

                        Ok(data.version())
                    });
                Response::GetMDataVersion(result)
            }
            Request::ListMDataEntries(address) => {
                let data = self.get_mdata(address, requester_pk, request);

                match (address.kind(), data) {
                    (MDataKind::Seq, Ok(MData::Seq(mdata))) => {
                        Response::ListMDataEntries(Ok(mdata.entries().clone().into()))
                    }
                    (MDataKind::Unseq, Ok(MData::Unseq(mdata))) => {
                        Response::ListMDataEntries(Ok(mdata.entries().clone().into()))
                    }
                    (_, Err(err)) => Response::ListMDataEntries(Err(err)),
                    (_, Ok(_)) => Response::ListMDataEntries(Err(SndError::NoSuchData)),
                }
            }
            Request::ListMDataKeys(address) => {
                let result = self
                    .get_mdata(address, requester_pk, request)
                    .and_then(|data| {
                        if address != *data.address() {
                            return Err(SndError::NoSuchData);
                        }

                        Ok(data.keys())
                    });
                Response::ListMDataKeys(result)
            }
            Request::ListMDataValues(address) => {
                let data = self.get_mdata(address, requester_pk, request);

                match (address.kind(), data) {
                    (MDataKind::Seq, Ok(MData::Seq(mdata))) => {
                        Response::ListMDataValues(Ok(mdata.values().into()))
                    }
                    (MDataKind::Unseq, Ok(MData::Unseq(mdata))) => {
                        Response::ListMDataValues(Ok(mdata.values().into()))
                    }
                    (_, Err(err)) => Response::ListMDataValues(Err(err)),
                    (_, Ok(_)) => Response::ListMDataValues(Err(SndError::NoSuchData)),
                }
            }
            Request::DeleteMData(address) => {
                let result = self
                    .get_mdata(address, requester_pk, request)
                    .and_then(|data| {
                        if address != *data.address() {
                            return Err(SndError::NoSuchData);
                        }

                        if let PublicId::Client(client_id) = requester.clone() {
                            if *client_id.public_key() == data.owner() {
                                self.delete_data(DataId::Mutable(address));
                                self.commit_mutation(requester.name());
                                Ok(())
                            } else {
                                Err(SndError::InvalidOwners)
                            }
                        } else {
                            Err(SndError::AccessDenied)
                        }
                    });
                Response::Mutation(result)
            }
            Request::SetMDataUserPermissions {
                address,
                ref user,
                ref permissions,
                version,
            } => {
                let permissions = permissions.clone();
                let user = *user;

                let result = self
                    .get_mdata(address, requester_pk, request.clone())
                    .and_then(|mut data| {
                        if address != *data.address() {
                            return Err(SndError::NoSuchData);
                        }

                        let data_name = DataId::Mutable(address);
                        data.set_user_permissions(user, permissions, version)?;
                        self.insert_data(data_name, Data::Mutable(data));
                        self.commit_mutation(requester.name());

                        Ok(())
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
                    .and_then(|mut data| {
                        if address != *data.address() {
                            return Err(SndError::NoSuchData);
                        }

                        let data_name = DataId::Mutable(address);
                        data.del_user_permissions(user, version)?;
                        self.insert_data(data_name, Data::Mutable(data));
                        self.commit_mutation(requester.name());

                        Ok(())
                    });
                Response::Mutation(result)
            }
            Request::ListMDataUserPermissions { address, ref user } => {
                let user = *user;

                let result = self
                    .get_mdata(address, requester_pk, request)
                    .and_then(|data| {
                        if address != *data.address() {
                            return Err(SndError::NoSuchData);
                        }

                        data.user_permissions(user).map(|perm| perm.clone())
                    });
                Response::ListMDataUserPermissions(result)
            }
            Request::ListMDataPermissions(address) => {
                let result = self
                    .get_mdata(address, requester_pk, request)
                    .and_then(|data| {
                        if address != *data.address() {
                            return Err(SndError::NoSuchData);
                        }

                        Ok(data.permissions())
                    });
                Response::ListMDataPermissions(result)
            }
            Request::MutateMDataEntries {
                address,
                ref actions,
            } => {
                let result =
                    self.get_mdata(address, requester_pk, request)
                        .and_then(move |mut data| {
                            if address != *data.address() {
                                return Err(SndError::NoSuchData);
                            }

                            let data_name = DataId::Mutable(address);
                            data.mutate_entries(actions.clone(), requester_pk)?;
                            self.insert_data(data_name, Data::Mutable(data));
                            self.commit_mutation(requester.name());

                            Ok(())
                        });
                Response::Mutation(result)
            }
            //
            // ===== AppendOnly Data =====
            //
            Request::PutAData(adata) => {
                let owner_index = adata.owners_index();
                let address = *adata.address();

                let result = match adata.owner(owner_index - 1) {
                    Some(key) => {
                        if key.public_key != owner_pk {
                            Err(SndError::InvalidOwners)
                        } else {
                            self.put_data(
                                DataId::AppendOnly(address),
                                Data::AppendOnly(adata),
                                requester,
                            )
                        }
                    }
                    None => Err(SndError::NoSuchEntry),
                };
                Response::Mutation(result)
            }
            Request::GetAData(address) => {
                let result = self.get_adata(address, requester_pk, request);
                Response::GetAData(result)
            }
            Request::DeleteAData(address) => {
                let id = DataId::AppendOnly(address);
                let result = self
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
                Response::Mutation(result)
            }
            Request::GetADataShell {
                address,
                data_index,
            } => {
                let result = self
                    .get_adata(address, requester_pk, request)
                    .and_then(move |data| {
                        let index = match data_index {
                            ADataIndex::FromStart(index) => index,
                            ADataIndex::FromEnd(index) => (data.permissions_index() - index),
                        };
                        data.shell(index)
                    });
                Response::GetADataShell(result)
            }
            Request::GetADataRange { address, range } => {
                let result = self
                    .get_adata(address, requester_pk, request)
                    .and_then(move |data| {
                        data.in_range(range.0, range.1).ok_or(SndError::NoSuchEntry)
                    });
                Response::GetADataRange(result)
            }
            Request::GetADataValue { address, key } => {
                let result = self
                    .get_adata(address, requester_pk, request)
                    .and_then(move |data| data.get(&key).cloned().ok_or(SndError::NoSuchEntry));
                Response::GetADataValue(result)
            }
            Request::GetADataIndices(address) => {
                let result = self
                    .get_adata(address, requester_pk, request)
                    .and_then(move |data| data.indices());
                Response::GetADataIndices(result)
            }
            Request::GetADataLastEntry(address) => {
                let result = self
                    .get_adata(address, requester_pk, request)
                    .and_then(move |data| data.last_entry().cloned().ok_or(SndError::NoSuchEntry));
                Response::GetADataLastEntry(result)
            }
            Request::GetADataPermissions {
                address,
                permissions_index,
            } => {
                let data = self.get_adata(address, requester_pk, request);

                match (address.kind(), data) {
                    (kind, Ok(ref data)) if kind.is_pub() && data.is_pub() => {
                        Response::GetADataPermissions(
                            data.pub_permissions(permissions_index)
                                .map(|perm| perm.clone().into()),
                        )
                    }
                    (kind, Ok(ref data)) if kind.is_unpub() && data.is_unpub() => {
                        Response::GetADataPermissions(
                            data.unpub_permissions(permissions_index)
                                .map(|perm| perm.clone().into()),
                        )
                    }
                    (_, Err(err)) => Response::GetADataPermissions(Err(err)),
                    (_, Ok(_)) => Response::GetADataPermissions(Err(SndError::NoSuchData)),
                }
            }
            Request::GetPubADataUserPermissions {
                address,
                permissions_index,
                user,
            } => {
                let result = self
                    .get_adata(address, requester_pk, request)
                    .and_then(move |data| data.pub_user_permissions(user, permissions_index));
                Response::GetPubADataUserPermissions(result)
            }
            Request::GetUnpubADataUserPermissions {
                address,
                permissions_index,
                public_key,
            } => {
                let result = self
                    .get_adata(address, requester_pk, request)
                    .and_then(move |data| {
                        data.unpub_user_permissions(public_key, permissions_index)
                    });
                Response::GetUnpubADataUserPermissions(result)
            }
            Request::AppendSeq { append, index } => {
                let id = DataId::AppendOnly(append.address);
                let result = self
                    .get_adata(append.address, requester_pk, request)
                    .and_then(move |data| match data {
                        AData::PubSeq(mut adata) => {
                            adata.append(append.values, index)?;
                            self.commit_mutation(requester.name());
                            self.insert_data(id, Data::AppendOnly(AData::PubSeq(adata)));
                            Ok(())
                        }
                        AData::UnpubSeq(mut adata) => {
                            adata.append(append.values, index)?;
                            self.commit_mutation(requester.name());
                            self.insert_data(id, Data::AppendOnly(AData::UnpubSeq(adata)));
                            Ok(())
                        }
                        _ => Err(SndError::NoSuchData),
                    });
                Response::Mutation(result)
            }
            Request::AppendUnseq(append) => {
                let id = DataId::AppendOnly(append.address);
                let result = self
                    .get_adata(append.address, requester_pk, request)
                    .and_then(move |data| match data {
                        AData::PubUnseq(mut adata) => {
                            adata.append(append.values)?;
                            self.commit_mutation(requester.name());
                            self.insert_data(id, Data::AppendOnly(AData::PubUnseq(adata)));
                            Ok(())
                        }
                        AData::UnpubUnseq(mut adata) => {
                            adata.append(append.values)?;
                            self.commit_mutation(requester.name());
                            self.insert_data(id, Data::AppendOnly(AData::UnpubUnseq(adata)));
                            Ok(())
                        }
                        _ => Err(SndError::NoSuchData),
                    });
                Response::Mutation(result)
            }
            Request::AddPubADataPermissions {
                address,
                permissions,
                permissions_index,
            } => {
                let id = DataId::AppendOnly(address);
                let result = self
                    .get_adata(address, requester_pk, request)
                    .and_then(move |data| match address {
                        ADataAddress::PubSeq { .. } => match data {
                            AData::PubSeq(mut adata) => {
                                adata.append_permissions(permissions, permissions_index)?;
                                self.commit_mutation(requester.name());
                                self.insert_data(id, Data::AppendOnly(AData::PubSeq(adata)));
                                Ok(())
                            }
                            _ => Err(SndError::NoSuchData),
                        },
                        ADataAddress::PubUnseq { .. } => match data {
                            AData::PubUnseq(mut adata) => {
                                adata.append_permissions(permissions, permissions_index)?;
                                self.commit_mutation(requester.name());
                                self.insert_data(id, Data::AppendOnly(AData::PubUnseq(adata)));
                                Ok(())
                            }
                            _ => Err(SndError::NoSuchData),
                        },
                        _ => Err(SndError::AccessDenied),
                    });
                Response::Mutation(result)
            }
            Request::AddUnpubADataPermissions {
                address,
                permissions,
                permissions_index,
            } => {
                let id = DataId::AppendOnly(address);
                let result = self
                    .get_adata(address, requester_pk, request)
                    .and_then(|data| match address {
                        ADataAddress::UnpubSeq { .. } => match data.clone() {
                            AData::UnpubSeq(mut adata) => {
                                adata.append_permissions(permissions, permissions_index)?;
                                self.commit_mutation(requester.name());
                                self.insert_data(id, Data::AppendOnly(AData::UnpubSeq(adata)));
                                Ok(())
                            }
                            _ => Err(SndError::NoSuchData),
                        },
                        ADataAddress::UnpubUnseq { .. } => match data {
                            AData::UnpubUnseq(mut adata) => {
                                adata.append_permissions(permissions, permissions_index)?;
                                self.commit_mutation(requester.name());
                                self.insert_data(id, Data::AppendOnly(AData::UnpubUnseq(adata)));
                                Ok(())
                            }
                            _ => Err(SndError::NoSuchData),
                        },
                        _ => Err(SndError::AccessDenied),
                    });
                Response::Mutation(result)
            }
            Request::SetADataOwner {
                address,
                owner,
                owners_index,
            } => {
                let id = DataId::AppendOnly(address);
                let result = self
                    .get_adata(address, requester_pk, request)
                    .and_then(move |data| match address {
                        ADataAddress::PubSeq { .. } => match data {
                            AData::PubSeq(mut adata) => {
                                adata.append_owner(owner, owners_index)?;
                                self.commit_mutation(requester.name());
                                self.insert_data(id, Data::AppendOnly(AData::PubSeq(adata)));
                                Ok(())
                            }
                            _ => Err(SndError::NoSuchData),
                        },
                        ADataAddress::PubUnseq { .. } => match data {
                            AData::PubUnseq(mut adata) => {
                                adata.append_owner(owner, owners_index)?;
                                self.commit_mutation(requester.name());
                                self.insert_data(id, Data::AppendOnly(AData::PubUnseq(adata)));
                                Ok(())
                            }
                            _ => Err(SndError::NoSuchData),
                        },
                        ADataAddress::UnpubSeq { .. } => match data.clone() {
                            AData::UnpubSeq(mut adata) => {
                                adata.append_owner(owner, owners_index)?;
                                self.commit_mutation(requester.name());
                                self.insert_data(id, Data::AppendOnly(AData::UnpubSeq(adata)));
                                Ok(())
                            }
                            _ => Err(SndError::NoSuchData),
                        },
                        ADataAddress::UnpubUnseq { .. } => match data {
                            AData::UnpubUnseq(mut adata) => {
                                adata.append_owner(owner, owners_index)?;
                                self.commit_mutation(requester.name());
                                self.insert_data(id, Data::AppendOnly(AData::UnpubUnseq(adata)));
                                Ok(())
                            }
                            _ => Err(SndError::NoSuchData),
                        },
                    });
                Response::Mutation(result)
            }
            Request::GetADataOwners {
                address,
                owners_index,
            } => {
                let result = self
                    .get_adata(address, requester_pk, request)
                    .and_then(move |data| {
                        let index = match owners_index {
                            ADataIndex::FromStart(index) => index,
                            ADataIndex::FromEnd(index) => (data.owners_index() - index),
                        };
                        match data.owner(index) {
                            Some(owner) => Ok(*owner),
                            None => Err(SndError::NoSuchEntry),
                        }
                    });
                Response::GetADataOwners(result)
            }
        };

        Ok(Message::Response {
            response,
            message_id,
        })
    }

    pub fn get_idata(&mut self, address: IDataAddress) -> SndResult<IData> {
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
    ) -> SndResult<()> {
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
    ) -> SndResult<MData> {
        match self.get_data(&DataId::Mutable(address)) {
            Some(data_type) => match data_type {
                Data::Mutable(data) => {
                    check_perms_mdata(&data, &request, requester_pk).map(move |_| data)
                }
                _ => Err(SndError::NoSuchData),
            },
            None => Err(SndError::NoSuchData),
        }
    }

    pub fn get_adata(
        &mut self,
        address: ADataAddress,
        requester_pk: PublicKey,
        request: Request,
    ) -> SndResult<AData> {
        let data_id = DataId::AppendOnly(address);
        match self.get_data(&data_id) {
            Some(data_type) => match data_type {
                Data::AppendOnly(data) => {
                    check_perms_adata(&data, &request, requester_pk).map(move |_| data)
                }
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
    ) -> SndResult<()> {
        match requester.clone() {
            PublicId::Client(client_public_id) => self
                .authorise_mutation(
                    &Authority::ClientManager(*client_public_id.name()),
                    client_public_id.public_key(),
                )
                .map_err(|_| SndError::AccessDenied)?,
            PublicId::App(app_public_id) => match self.get_account(app_public_id.owner_name()) {
                None => {
                    debug!("Account does not exist");
                    return Err(SndError::AccessDenied);
                }
                Some(account) => {
                    if !account.auth_keys().contains_key(app_public_id.public_key()) {
                        return Err(SndError::AccessDenied);
                    }
                }
            },
            _ => return Err(SndError::AccessDenied),
        }
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

    fn list_auth_keys_and_version(
        &mut self,
        name: &XorName,
    ) -> (BTreeMap<PublicKey, AppPermissions>, u64) {
        if self.get_account(&name).is_none() {
            self.insert_account(*name);
        }
        let account = unwrap!(self.get_account(&name));

        (account.auth_keys().clone(), account.version())
    }

    fn ins_auth_key(
        &mut self,
        name: &XorName,
        key: PublicKey,
        permissions: AppPermissions,
        version: u64,
    ) -> SndResult<()> {
        if self.get_account(&name).is_none() {
            self.insert_account(*name);
        }
        let account = unwrap!(self.get_account_mut(&name));

        account.ins_auth_key(key, permissions, version)
    }

    fn del_auth_key(&mut self, name: &XorName, key: PublicKey, version: u64) -> SndResult<()> {
        if self.get_account(&name).is_none() {
            self.insert_account(*name);
        }
        let account = unwrap!(self.get_account_mut(&name));

        account.del_auth_key(&key, version)
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
    path: PathBuf,
}

impl FileStore {
    fn new(path: &PathBuf) -> Self {
        Self {
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
