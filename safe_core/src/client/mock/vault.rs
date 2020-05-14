// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::DataId;
use super::{Account, CoinBalance};
use crate::client::mock::connection_manager::unlimited_money;
use crate::client::COST_OF_PUT;
use crate::config_handler::{Config, DevConfig};
use bincode::{deserialize, serialize};
use fs2::FileExt;
use log::{debug, trace, warn};
use safe_nd::{
    verify_signature, AData, ADataAction, ADataAddress, ADataIndex, ADataRequest, AppPermissions,
    AppendOnlyData, ClientFullId, ClientRequest, Data, Error as SndError, IData, IDataAddress,
    IDataRequest, LoginPacket, LoginPacketRequest, MData, MDataAction, MDataAddress, MDataKind,
    MDataRequest, Message, Money, TransferReceipt, MoneyRequest, PublicId, PublicKey, Request,
    RequestType, Response, Result as SndResult, SeqAppendOnly, UnseqAppendOnly, XorName,
};

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::env;
use std::fs::File;
#[cfg(not(test))]
use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::ops::{Deref, DerefMut};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::{Mutex, MutexGuard};
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
    // TODO: Use proper section type ID for this. At the mo we're just simulating the verification with a client Id
    section_identity: ClientFullId,
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

fn check_perms_adata(data: &AData, request: &Request, requester: PublicKey) -> SndResult<()> {
    match request {
        Request::AData(ADataRequest::Get(..))
        | Request::AData(ADataRequest::GetShell { .. })
        | Request::AData(ADataRequest::GetValue { .. })
        | Request::AData(ADataRequest::GetRange { .. })
        | Request::AData(ADataRequest::GetIndices(..))
        | Request::AData(ADataRequest::GetLastEntry(..))
        | Request::AData(ADataRequest::GetPermissions { .. })
        | Request::AData(ADataRequest::GetPubUserPermissions { .. })
        | Request::AData(ADataRequest::GetUnpubUserPermissions { .. })
        | Request::AData(ADataRequest::GetOwners { .. }) => match data {
            AData::PubUnseq(_) | AData::PubSeq(_) => Ok(()),
            AData::UnpubSeq(_) | AData::UnpubUnseq(_) => {
                data.check_permission(ADataAction::Read, requester)
            }
        },
        Request::AData(ADataRequest::AppendSeq { .. })
        | Request::AData(ADataRequest::AppendUnseq { .. }) => {
            data.check_permission(ADataAction::Append, requester)
        }
        Request::AData(ADataRequest::AddPubPermissions { .. })
        | Request::AData(ADataRequest::AddUnpubPermissions { .. }) => {
            data.check_permission(ADataAction::ManagePermissions, requester)
        }
        Request::AData(ADataRequest::SetOwner { .. }) => data.check_is_last_owner(requester),
        Request::AData(ADataRequest::Delete(_)) => match data {
            AData::PubSeq(_) | AData::PubUnseq(_) => Err(SndError::InvalidOperation),
            AData::UnpubSeq(_) | AData::UnpubUnseq(_) => data.check_is_last_owner(requester),
        },
        _ => Err(SndError::InvalidOperation),
    }
}

fn check_perms_mdata(data: &MData, request: &Request, requester: PublicKey) -> SndResult<()> {
    match request {
        Request::MData(MDataRequest::Get { .. })
        | Request::MData(MDataRequest::GetShell { .. })
        | Request::MData(MDataRequest::GetVersion { .. })
        | Request::MData(MDataRequest::ListKeys { .. })
        | Request::MData(MDataRequest::ListEntries { .. })
        | Request::MData(MDataRequest::ListValues { .. })
        | Request::MData(MDataRequest::GetValue { .. })
        | Request::MData(MDataRequest::ListPermissions { .. })
        | Request::MData(MDataRequest::ListUserPermissions { .. }) => {
            data.check_permissions(MDataAction::Read, requester)
        }

        Request::MData(MDataRequest::SetUserPermissions { .. })
        | Request::MData(MDataRequest::DelUserPermissions { .. }) => {
            data.check_permissions(MDataAction::ManagePermissions, requester)
        }

        Request::MData(MDataRequest::MutateEntries { .. }) => Ok(()),

        Request::MData(MDataRequest::Delete { .. }) => data.check_is_owner(requester),

        _ => Err(SndError::InvalidOperation),
    }
}

enum Operation {
    TransferMoney,
    Mutation,
    GetBalance,
}

impl Vault {
    pub fn new(config: Config) -> Self {
        let store = init_vault_store(&config);
        let mut rng = rand::thread_rng();

        let section_identity = ClientFullId::new_bls(&mut rng);
        Vault {
            cache: Cache {
                coin_balances: HashMap::new(),
                client_manager: HashMap::new(),
                login_packets: HashMap::new(),
                nae_manager: HashMap::new(),
            },
            config,
            store,
            section_identity,
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

        // TODO: update this to at2 api
        self.cache.coin_balances.get(name)
    }

    // Get mutable reference to account for the client manager name.
    pub fn get_coin_balance_mut(&mut self, name: &XorName) -> Option<&mut CoinBalance> {
        // TODO: update this to at2 api

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
    pub fn mock_create_balance(&mut self, owner: PublicKey, amount: Money) {
        let _ = self
            .cache
            .coin_balances
            .insert(XorName::from(owner), CoinBalance::new(amount, owner));
    }

    /// Increment coin balance for testing
    pub fn mock_increment_balance(
        &mut self,
        coin_balance_name: &XorName,
        amount: Money,
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

    fn get_balance(&self, money_balance_id: &XorName) -> SndResult<Money> {
        self.get_coin_balance(&money_balance_id).map_or_else(
            || {
                debug!("Coin balance {:?} not found", money_balance_id);
                Err(SndError::NoSuchBalance)
            },
            |bal| Ok(bal.balance()),
        )
    }

    // Checks if the given balance has sufficient money for the given `amount` of Operation.
    fn has_sufficient_balance(&self, balance: Money, amount: Money) -> bool {
        unlimited_money(&self.config) || balance.checked_sub(amount).is_some()
    }

    // Authorises coin transfers, mutations and get balance operations.
    fn authorise_operations(
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
                Operation::TransferMoney => {
                    if !perms.transfer_money {
                        debug!("Transfer money not authorised");
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
        if !unlimited_money(&self.config) {
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

    fn create_balance(&mut self, to: XorName, owner: PublicKey) -> SndResult<()> {
        if self.get_coin_balance(&to).is_some() {
            return Err(SndError::BalanceExists);
        }
        let _ = self
            .cache
            .coin_balances
            .insert(to, CoinBalance::new(Money::from_nano(0), owner));
        Ok(())
    }

    fn deposit_money(
        &mut self,
        _source: XorName,
        to: XorName,
        amount: Money,
        transaction_id: u64,
    ) -> SndResult<TransferReceipt> {
        match self.get_coin_balance_mut(&to) {
            Some(balance) => balance.credit_balance(amount, transaction_id)?,
            None => return Err(SndError::NoSuchBalance),
        };

        Ok(TransferReceipt {
            id: transaction_id,
            amount,
        })
    }
    fn withdraw_money(
        &mut self,
        source: XorName,
        _to: XorName,
        amount: Money,
        _transaction_id: u64,
    ) -> SndResult<()> {
        let unlimited = unlimited_money(&self.config);
        match self.get_coin_balance_mut(&source) {
            Some(balance) => {
                if !unlimited {
                    balance.debit_balance(amount)?
                }
            }
            None => return Err(SndError::NoSuchBalance),
        };

        Ok(())
    }

    #[allow(clippy::cognitive_complexity)]
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
        let request_validation = match requester.clone() {
            PublicId::App(pk) => Ok((true, *pk.public_key(), *pk.owner().public_key())),
            PublicId::Client(pk) => Ok((false, *pk.public_key(), *pk.public_key())),
            // TODO: use actual node identity lark instead of client for section
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
        let (requester_pk, owner_pk) = match request_validation {
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
            Request::IData(IDataRequest::Get(address)) => {
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
            Request::IData(IDataRequest::Put(idata)) => {
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
            Request::IData(IDataRequest::DeleteUnpub(address)) => {
                let result = self.delete_idata(address, requester_pk);
                Response::Mutation(result)
            }
            // ===== Client (Owner) to SrcElders =====
            Request::Client(ClientRequest::ListAuthKeysAndVersion) => {
                let result = {
                    if owner_pk != requester_pk {
                        Err(SndError::AccessDenied)
                    } else {
                        Ok(self.list_auth_keys_and_version(&requester.name()))
                    }
                };
                Response::ListAuthKeysAndVersion(result)
            }
            Request::Client(ClientRequest::InsAuthKey {
                key,
                permissions,
                version,
            }) => {
                let result = if owner_pk != requester_pk {
                    Err(SndError::AccessDenied)
                } else {
                    self.ins_auth_key(&requester.name(), key, permissions, version)
                };
                Response::Mutation(result)
            }
            Request::Client(ClientRequest::DelAuthKey { key, version }) => {
                let result = if owner_pk != requester_pk {
                    Err(SndError::AccessDenied)
                } else {
                    self.del_auth_key(&requester.name(), key, version)
                };
                Response::Mutation(result)
            }
            // ===== Money =====
            // Put money in target account. Triggered after Transfer/Create have subtracted from sender
            Request::Money(MoneyRequest::GetTransferValidation {
                to,
                from: _,
                amount,
                transaction_id,
                dependencies
            }) => {
                // TODO: 
                // 1. full steps of AT2 validation...
                // 2 sign
                // 3 return signed keyshare

                // setup fake share
                use threshold_crypto::{SecretKeySet};
                let threshold = 1; 
                let mut rng = rand::thread_rng();
                let sk_set = SecretKeySet::random(threshold, &mut rng);

                // this should be retrieved from Elder node
                let sk_share = sk_set.secret_key_share(0);

                match bincode::serialize(&request) {
                    Ok(vec) => {
                        let signed_message = sk_share.sign(vec);
                        Response::GetTransferValidation(Ok(vec![signed_message]))

                    },
                    Err(error) => {
                       request.error_response(safe_nd::Error::NetworkOther( format!("Error seriliasizing request: {:?}", error ) ) )
                    }
                }

            }

            Request::Money(MoneyRequest::DepositMoney {
                to,
                from: _,
                amount,
                new_account: _,
                transaction_id,
                transfer_proof: _,
            }) => {
                debug!("DepositMoney request being handled.");

                let source: XorName = owner_pk.into();

                let result = if amount.as_nano() == 0 {
                    Err(SndError::InvalidOperation)
                } else {
                    // TODO deserialise and validate proof
                    // But this is NOT the normal auth operation, as balance has been withdrawn and validated at home section
                    // we just validate PK of section...
                    // ...so what with the proof?

                    self.deposit_money(source, to, amount, transaction_id)
                };

                Response::TransferReceipt(result)
            }
            Request::Money(MoneyRequest::TransferMoney {
                to,
                from: _,
                amount,
                transaction_id,
            }) => {
                let source: XorName = owner_pk.into();
                debug!("TransferMoney request being handled.");
                let result = if amount.as_nano() == 0 {
                    Err(SndError::InvalidOperation)
                } else {
                    self.authorise_operations(&[Operation::TransferMoney], source, requester_pk)
                        .and_then(|()| self.withdraw_money(source, to, amount, transaction_id))
                        .and_then(|()| {
                            // Trigger deposit step
                            let serialised_proof = unwrap!(serialize(&message));
                            let deposit_request = Request::Money(MoneyRequest::DepositMoney {
                                from: source,
                                to,
                                amount,
                                transaction_id,
                                new_account: false,
                                transfer_proof: serialised_proof,
                            });

                            let signature = self
                                .section_identity
                                .sign(&unwrap!(serialize(&(&deposit_request, message_id))));

                            let deposit_message = Message::Request {
                                request: deposit_request,
                                message_id,
                                signature: Some(signature),
                            };

                            // We're now mocking a request to _another_ section, where the deposit would happen
                            match self.process_request(
                                PublicId::Client(self.section_identity.public_id().clone()),
                                &deposit_message,
                            )? {
                                Message::Response { response, .. } => Ok(response),
                                _ => panic!("Unexpected response to deposit Money"),
                            }
                        })
                };

                match result {
                    Ok(response) => response,
                    Err(error) => Response::TransferReceipt(Err(error)),
                }
            }
            Request::Money(MoneyRequest::CreateBalance {
                amount,
                to,
                from: _,
                transaction_id,
            }) => {
                let source = owner_pk.into();
                let recipient = to.into();

                let result = if source == recipient {
                    let real_or_random_transaction_id: u64 =
                        transaction_id.unwrap_or_else(rand::random);
                    // creating a mock balance, source is recipient so we just use that pk?
                    self.mock_create_balance(owner_pk, amount);
                    Ok(TransferReceipt {
                        id: real_or_random_transaction_id,
                        amount,
                    })
                } else {
                    let mut req_perms = vec![Operation::Mutation];
                    if amount == unwrap!(Money::from_str("0")) {
                        req_perms.push(Operation::TransferMoney);
                    }

                    let transaction_id = transaction_id.unwrap_or_else(rand::random);
                    self.authorise_operations(req_perms.as_slice(), source, requester_pk)
                        .and_then(|_| self.get_balance(&source))
                        .and_then(|source_balance| {
                            let total_amount = amount
                                .checked_add(COST_OF_PUT)
                                .ok_or(SndError::ExcessiveValue)?;
                            if !self.has_sufficient_balance(source_balance, total_amount) {
                                return Err(SndError::InsufficientBalance);
                            }

                            self.create_balance(recipient, to)
                        })
                        .and_then(|()| {
                            self.commit_mutation(&source);
                            // and also withdraw money
                            self.withdraw_money(source, recipient, amount, transaction_id)
                        })
                        .and_then(|()| {
                            // Trigger deposit step
                            let serialised_proof = unwrap!(serialize(&message));
                            let deposit_request = Request::Money(MoneyRequest::DepositMoney {
                                from: source,
                                to: recipient,
                                amount,
                                transaction_id,
                                new_account: false,
                                transfer_proof: serialised_proof,
                            });
                            let signature = self
                                .section_identity
                                .sign(&unwrap!(serialize(&(&deposit_request, message_id))));
                            let deposit_message = Message::Request {
                                request: deposit_request,
                                message_id,
                                signature: Some(signature),
                            };
                            match self.process_request(
                                PublicId::Client(self.section_identity.public_id().clone()),
                                &deposit_message,
                            )? {
                                Message::Response { response, .. } => match response {
                                    Response::TransferReceipt(res) => res,
                                    _ => panic!("Unexpected response to DepositMoney"),
                                },
                                _ => panic!("Unexpected response to DepositMoney"),
                            }
                        })
                };
                Response::TransferReceipt(result)
            }
            Request::Money(MoneyRequest::GetBalance(xorname)) => {
                let coin_balance_id = xorname;

                let result = self
                    .authorise_operations(&[Operation::GetBalance], coin_balance_id, requester_pk)
                    .and_then(move |_| self.get_balance(&coin_balance_id));
                Response::GetBalance(result)
            }

            // ===== Account =====
            Request::LoginPacket(LoginPacketRequest::CreateFor {
                new_owner,
                amount,
                transaction_id,
                new_login_packet,
            }) => {
                let source = owner_pk.into();
                let new_balance_dest = new_owner.into();

                // If a login packet at the given to exists return an error.
                let result = if let Err(e) = {
                    // Check if the requester is authorized to perform coin transactions, mutate, and read balance.
                    let mut req_perms = vec![Operation::Mutation];
                    if amount == unwrap!(Money::from_str("0")) {
                        req_perms.push(Operation::TransferMoney);
                    }
                    self.authorise_operations(req_perms.as_slice(), source, requester_pk)
                } {
                    Err(e)
                } else {
                    self.get_balance(&source)
                        .and_then(|source_balance| {
                            let debit_amt = amount
                                .checked_add(COST_OF_PUT)
                                .ok_or(SndError::ExcessiveValue)?;
                            if !self.has_sufficient_balance(source_balance, debit_amt) {
                                return Err(SndError::InsufficientBalance);
                            }

                            // Create the balance and transfer the mentioned amount of money
                            self.create_balance(new_balance_dest, new_owner)
                        })
                        .and_then(|_| {
                            // Debit the requester's wallet the cost of `CreateLoginPacketFor`
                            self.commit_mutation(&source);
                            // and also withdraw money
                            self.withdraw_money(source, new_balance_dest, amount, transaction_id)
                        })
                        .and_then(|()| {
                            // Trigger deposit step
                            let serialised_proof = unwrap!(serialize(&message));
                            let deposit_request = Request::Money(MoneyRequest::DepositMoney {
                                from: source,
                                to: new_balance_dest,
                                amount,
                                transaction_id,
                                new_account: false,
                                transfer_proof: serialised_proof,
                            });
                            let signature = self
                                .section_identity
                                .sign(&unwrap!(serialize(&(&deposit_request, message_id))));

                            let deposit_message = Message::Request {
                                request: deposit_request,
                                message_id,
                                signature: Some(signature),
                            };
                            self.process_request(
                                PublicId::Client(self.section_identity.public_id().clone()),
                                &deposit_message,
                            )
                        })
                        .and_then(|_| {
                            if self
                                .get_login_packet(new_login_packet.destination())
                                .is_some()
                            {
                                Err(SndError::LoginPacketExists)
                            } else {
                                Ok(())
                            }
                        })
                        // Store the login packet
                        .map(|_| {
                            self.insert_login_packet(new_login_packet);

                            TransferReceipt {
                                id: transaction_id,
                                amount,
                            }
                        })
                };
                Response::TransferReceipt(result)
            }
            Request::LoginPacket(LoginPacketRequest::Create(account_data)) => {
                let source = owner_pk.into();

                if let Err(e) =
                    self.authorise_operations(&[Operation::Mutation], source, requester_pk)
                {
                    Response::Mutation(Err(e))
                } else if self.get_login_packet(account_data.destination()).is_some() {
                    Response::Mutation(Err(SndError::LoginPacketExists))
                } else {
                    let result = self
                        .get_balance(&source)
                        .and_then(|source_balance| {
                            if !self.has_sufficient_balance(source_balance, COST_OF_PUT) {
                                return Err(SndError::InsufficientBalance);
                            }

                            self.commit_mutation(&source);
                            Ok(())
                        })
                        .map(|_| self.insert_login_packet(account_data));
                    Response::Mutation(result)
                }
            }
            Request::LoginPacket(LoginPacketRequest::Get(location)) => {
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
            Request::LoginPacket(LoginPacketRequest::Update(new_packet)) => {
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
            Request::MData(MDataRequest::Get(address)) => {
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
            Request::MData(MDataRequest::Put(data)) => {
                let address = *data.address();

                let result = if data.owner() != owner_pk {
                    Err(SndError::InvalidOwners)
                } else {
                    self.put_data(DataId::Mutable(address), Data::Mutable(data), requester)
                };
                Response::Mutation(result)
            }
            Request::MData(MDataRequest::GetValue { address, ref key }) => {
                let data = self.get_mdata(address, requester_pk, request);

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
            Request::MData(MDataRequest::GetShell(address)) => {
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
            Request::MData(MDataRequest::GetVersion(address)) => {
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
            Request::MData(MDataRequest::ListEntries(address)) => {
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
            Request::MData(MDataRequest::ListKeys(address)) => {
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
            Request::MData(MDataRequest::ListValues(address)) => {
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
            Request::MData(MDataRequest::Delete(address)) => {
                let result = self
                    .get_mdata(address, requester_pk, request)
                    .and_then(|data| {
                        if address != *data.address() {
                            return Err(SndError::NoSuchData);
                        }

                        if let PublicId::Client(client_id) = requester.clone() {
                            if *client_id.public_key() == data.owner() {
                                self.delete_data(DataId::Mutable(address));
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
            Request::MData(MDataRequest::SetUserPermissions {
                address,
                ref user,
                ref permissions,
                version,
            }) => {
                let permissions = permissions.clone();
                let user = *user;

                let result = self
                    .get_mdata(address, requester_pk, request)
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
            Request::MData(MDataRequest::DelUserPermissions {
                address,
                ref user,
                version,
            }) => {
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
            Request::MData(MDataRequest::ListUserPermissions { address, ref user }) => {
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
            Request::MData(MDataRequest::ListPermissions(address)) => {
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
            Request::MData(MDataRequest::MutateEntries {
                address,
                ref actions,
            }) => {
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
            Request::AData(ADataRequest::Put(adata)) => {
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
            Request::AData(ADataRequest::Get(address)) => {
                let result = self.get_adata(address, requester_pk, request);
                Response::GetAData(result)
            }
            Request::AData(ADataRequest::Delete(address)) => {
                let id = DataId::AppendOnly(address);
                let result = self
                    .get_adata(address, requester_pk, request)
                    .and_then(move |data| match data {
                        // Cannot be deleted as it is a published data.
                        AData::PubSeq(_) | AData::PubUnseq(_) => Err(SndError::InvalidOperation),
                        AData::UnpubSeq(_) | AData::UnpubUnseq(_) => {
                            self.delete_data(id);
                            Ok(())
                        }
                    });
                Response::Mutation(result)
            }
            Request::AData(ADataRequest::GetShell {
                address,
                data_index,
            }) => {
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
            Request::AData(ADataRequest::GetRange { address, range }) => {
                let result = self
                    .get_adata(address, requester_pk, request)
                    .and_then(move |data| {
                        data.in_range(range.0, range.1).ok_or(SndError::NoSuchEntry)
                    });
                Response::GetADataRange(result)
            }
            Request::AData(ADataRequest::GetValue { address, key }) => {
                let result = self
                    .get_adata(address, requester_pk, request)
                    .and_then(move |data| data.get(&key).cloned().ok_or(SndError::NoSuchEntry));
                Response::GetADataValue(result)
            }
            Request::AData(ADataRequest::GetIndices(address)) => {
                let result = self
                    .get_adata(address, requester_pk, request)
                    .and_then(move |data| data.indices());
                Response::GetADataIndices(result)
            }
            Request::AData(ADataRequest::GetLastEntry(address)) => {
                let result = self
                    .get_adata(address, requester_pk, request)
                    .and_then(move |data| data.last_entry().cloned().ok_or(SndError::NoSuchEntry));
                Response::GetADataLastEntry(result)
            }
            Request::AData(ADataRequest::GetPermissions {
                address,
                permissions_index,
            }) => {
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
            Request::AData(ADataRequest::GetPubUserPermissions {
                address,
                permissions_index,
                user,
            }) => {
                let result = self
                    .get_adata(address, requester_pk, request)
                    .and_then(move |data| data.pub_user_permissions(user, permissions_index));
                Response::GetPubADataUserPermissions(result)
            }
            Request::AData(ADataRequest::GetUnpubUserPermissions {
                address,
                permissions_index,
                public_key,
            }) => {
                let result = self
                    .get_adata(address, requester_pk, request)
                    .and_then(move |data| {
                        data.unpub_user_permissions(public_key, permissions_index)
                    });
                Response::GetUnpubADataUserPermissions(result)
            }
            Request::AData(ADataRequest::AppendSeq { append, index }) => {
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
            Request::AData(ADataRequest::AppendUnseq(append)) => {
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
            Request::AData(ADataRequest::AddPubPermissions {
                address,
                permissions,
                permissions_index,
            }) => {
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
            Request::AData(ADataRequest::AddUnpubPermissions {
                address,
                permissions,
                permissions_index,
            }) => {
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
            Request::AData(ADataRequest::SetOwner {
                address,
                owner,
                owners_index,
            }) => {
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
            Request::AData(ADataRequest::GetOwners {
                address,
                owners_index,
            }) => {
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
        requester_pk: PublicKey,
    ) -> SndResult<()> {
        let data_id = DataId::Immutable(address);

        match self.get_data(&data_id) {
            Some(idata) => {
                if let Data::Immutable(data) = idata {
                    if let IData::Unpub(unpub_idata) = data {
                        if *unpub_idata.owner() == requester_pk {
                            self.delete_data(data_id);
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
        request: &Request,
    ) -> SndResult<MData> {
        match self.get_data(&DataId::Mutable(address)) {
            Some(data_type) => match data_type {
                Data::Mutable(data) => {
                    check_perms_mdata(&data, request, requester_pk).map(move |_| data)
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
        request: &Request,
    ) -> SndResult<AData> {
        let data_id = DataId::AppendOnly(address);
        match self.get_data(&data_id) {
            Some(data_type) => match data_type {
                Data::AppendOnly(data) => {
                    check_perms_adata(&data, request, requester_pk).map(move |_| data)
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
        // println!("PUT ting data");
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
    let mut inner = match vault.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };

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
