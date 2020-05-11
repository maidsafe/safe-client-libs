// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

/// User Account information.
pub mod account;
/// Core client used for testing purposes.
#[cfg(any(test, feature = "testing"))]
pub mod core_client;
/// `MDataInfo` utilities.
pub mod mdata_info;
/// Various APIs wrapped to provide resiliance for common network operations.
pub mod recoverable_apis;
use async_trait::async_trait;
use futures::future::FutureExt;
mod id;
#[cfg(feature = "mock-network")]
mod mock;

pub use self::account::ClientKeys;
pub use self::id::SafeKey;
pub use self::mdata_info::MDataInfo;
#[cfg(feature = "mock-network")]
pub use self::mock::vault::mock_vault_path;
#[cfg(feature = "mock-network")]
pub use self::mock::ConnectionManager as MockConnectionManager;

#[cfg(feature = "mock-network")]
use self::mock::ConnectionManager;
use crate::config_handler::Config;
#[cfg(not(feature = "mock-network"))]
use crate::connection_manager::ConnectionManager;
use crate::crypto::{shared_box, shared_secretbox};
use crate::errors::CoreError;
use crate::event_loop::CoreMsgTx;
use crate::ipc::BootstrapConfig;
use crate::network_event::{NetworkEvent, NetworkTx};
use futures::channel::mpsc;
use std::sync::{Arc, Mutex};

use log::trace;
use lru_cache::LruCache;
use quic_p2p::Config as QuicP2pConfig;
use safe_nd::{
    AData, ADataAddress, ADataAppendOperation, ADataEntries, ADataEntry, ADataIndex, ADataIndices,
    ADataOwner, ADataPermissions, ADataPubPermissionSet, ADataPubPermissions,
    ADataUnpubPermissionSet, ADataUnpubPermissions, ADataUser, AppPermissions, ClientFullId, Coins,
    IData, IDataAddress, LoginPacket, MData, MDataAddress, MDataEntries, MDataEntryActions,
    MDataPermissionSet, MDataSeqEntries, MDataSeqEntryActions, MDataSeqValue,
    MDataUnseqEntryActions, MDataValue, MDataValues, Message, MessageId, PublicId, PublicKey,
    Request, RequestType, Response, SeqMutableData, Transaction, UnseqMutableData, XorName,
};

use std::collections::{BTreeMap, BTreeSet};

use std::time::Duration;
use threshold_crypto;
use tokio::runtime::*;
use unwrap::unwrap;

/// Capacity of the immutable data cache.
pub const IMMUT_DATA_CACHE_SIZE: usize = 300;

// FIXME: move to conn manager
// const CONNECTION_TIMEOUT_SECS: u64 = 40;

/// Expected cost of mutation operations.
pub const COST_OF_PUT: Coins = Coins::from_nano(1);

/// Return the `crust::Config` associated with the `crust::Service` (if any).
pub fn bootstrap_config() -> Result<BootstrapConfig, CoreError> {
    Ok(Config::new().quic_p2p.hard_coded_contacts)
}

fn send(client: &impl Client, request: Request) -> Result<Response, CoreError> {
    // `sign` should be false for GETs on published data, true otherwise.
    let sign = request.get_type() != RequestType::PublicGet;
    let request = client.compose_message(request, sign);
    let inner = client.inner();
    let cm = &mut inner.lock().unwrap().connection_manager;
    futures::executor::block_on(cm.send(&client.public_id(), &request))
}

// Sends a mutation request to a new routing.
async fn send_mutation(client: &impl Client, req: Request) -> Result<(), CoreError> {
    let response = send(client, req)?;
    match response {
        Response::Mutation(result) => {
            trace!("mutation result: {:?}", result);
            result.map_err(CoreError::from)
        }
        _ => Err(CoreError::ReceivedUnexpectedEvent),
    }
}

fn send_as_helper(
    client: &impl Client,
    request: Request,
    client_id: Option<&ClientFullId>,
) -> Result<Response, CoreError> {
    let (message, identity) = match client_id {
        Some(id) => (sign_request(request, id), SafeKey::client(id.clone())),
        None => (client.compose_message(request, true), client.full_id()),
    };

    let pub_id = identity.public_id();

    let inner = client.inner();

    let cm = &mut inner.lock().unwrap().connection_manager;
    let mut cm2 = cm.clone();

    futures::executor::block_on(async {
        let _bootstrapped = cm.bootstrap(identity).await;
        cm2.send(&pub_id, &message).await
    })
}

/// Trait providing an interface for self-authentication client implementations, so they can
/// interface all requests from high-level APIs to the actual routing layer and manage all
/// interactions with it. Clients are non-blocking, with an asynchronous API using the futures
/// abstraction from the futures-rs crate.
#[async_trait]
pub trait Client: Clone + 'static + Send + Sync {
    /// Associated message type.
    type Context;

    /// Return the client's ID.
    fn full_id(&self) -> SafeKey;

    /// Return the client's public ID.
    fn public_id(&self) -> PublicId {
        self.full_id().public_id()
    }

    /// Returns the client's public key.
    fn public_key(&self) -> PublicKey {
        self.full_id().public_key()
    }

    /// Returns the client's owner key.
    fn owner_key(&self) -> PublicKey;

    /// Return a `crust::Config` if the `Client` was initialized with one.
    fn config(&self) -> Option<BootstrapConfig>;

    /// Return an associated `ClientInner` type which is expected to contain fields associated with
    /// the implementing type.
    fn inner(&self) -> Arc<Mutex<Inner<Self, Self::Context>>>
    where
        Self: Sized;

    /// Return the public encryption key.
    fn public_encryption_key(&self) -> threshold_crypto::PublicKey;

    /// Return the secret encryption key.
    fn secret_encryption_key(&self) -> shared_box::SecretKey;

    /// Return the public and secret encryption keys.
    fn encryption_keypair(&self) -> (threshold_crypto::PublicKey, shared_box::SecretKey) {
        (self.public_encryption_key(), self.secret_encryption_key())
    }

    /// Return the symmetric encryption key.
    fn secret_symmetric_key(&self) -> shared_secretbox::Key;

    /// Create a `Message` from the given request.
    /// This function adds the requester signature and message ID.
    fn compose_message(&self, request: Request, sign: bool) -> Message {
        let message_id = MessageId::new();

        let signature = if sign {
            Some(
                self.full_id()
                    .sign(&unwrap!(bincode::serialize(&(&request, message_id)))),
            )
        } else {
            None
        };

        Message::Request {
            request,
            message_id,
            signature,
        }
    }

    /// Set request timeout.
    fn set_timeout(&self, duration: Duration) {
        let inner = self.inner();
        inner.lock().unwrap().timeout = duration;
    }

    /// Restart the client and reconnect to the network.
    fn restart_network(&self) -> Result<(), CoreError> {
        trace!("Restarting the network connection");

        let inner = self.inner();
        let mut inner = inner.lock().unwrap();

        inner.connection_manager.restart_network();

        inner
            .net_tx
            .unbounded_send(NetworkEvent::Connected)
            .map_err(|error| CoreError::from(format!("{:?}", error)))?;

        Ok(())
    }

    /// Put unsequenced mutable data to the network
    async fn put_unseq_mutable_data(&self, data: UnseqMutableData) -> Result<(), CoreError>
    where
        Self: Sized,
    {
        trace!("Put Unsequenced MData at {:?}", data.name());
        send_mutation(self, Request::PutMData(MData::Unseq(data))).await?;
        Ok(())
    }

    /// Transfer coin balance
    async fn transfer_coins(
        &self,
        client_id: Option<&ClientFullId>,
        destination: XorName,
        amount: Coins,
        transaction_id: Option<u64>,
    ) -> Result<Transaction, CoreError>
    where
        Self: Sized,
    {
        trace!("Transfer {} coins to {:?}", amount, destination);

        match send_as_helper(
            self,
            Request::TransferCoins {
                destination,
                amount,
                transaction_id: transaction_id.unwrap_or_else(rand::random),
            },
            client_id,
        ) {
            Ok(res) => match res {
                Response::Transaction(result) => match result {
                    Ok(transaction) => Ok(transaction),
                    Err(error) => Err(CoreError::from(error)),
                },
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            },
            Err(_error) => Err(CoreError::ReceivedUnexpectedEvent),
        }
    }

    /// Creates a new balance on the network.
    async fn create_balance(
        &self,
        client_id: Option<&ClientFullId>,
        new_balance_owner: PublicKey,
        amount: Coins,
        transaction_id: Option<u64>,
    ) -> Result<Transaction, CoreError>
    where
        Self: Sized,
    {
        trace!(
            "Create a new balance for {:?} with {} coins.",
            new_balance_owner,
            amount
        );

        match send_as_helper(
            self,
            Request::CreateBalance {
                new_balance_owner,
                amount,
                transaction_id: transaction_id.unwrap_or_else(rand::random),
            },
            client_id,
        ) {
            Ok(res) => match res {
                Response::Transaction(result) => match result {
                    Ok(transaction) => Ok(transaction),
                    Err(error) => Err(CoreError::from(error)),
                },
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            },

            Err(error) => Err(CoreError::from(error)),
        }
    }

    /// Insert a given login packet at the specified destination
    async fn insert_login_packet_for(
        &self,
        client_id: Option<&ClientFullId>,
        new_owner: PublicKey,
        amount: Coins,
        transaction_id: Option<u64>,
        new_login_packet: LoginPacket,
    ) -> Result<Transaction, CoreError>
    where
        Self: Sized,
    {
        trace!(
            "Insert a login packet for {:?} preloading the wallet with {} coins.",
            new_owner,
            amount
        );

        let transaction_id = transaction_id.unwrap_or_else(rand::random);

        match send_as_helper(
            self,
            Request::CreateLoginPacketFor {
                new_owner,
                amount,
                transaction_id,
                new_login_packet,
            },
            client_id,
        ) {
            Ok(res) => match res {
                Response::Transaction(result) => match result {
                    Ok(transaction) => Ok(transaction),
                    Err(error) => Err(CoreError::from(error)),
                },
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            },

            Err(error) => Err(CoreError::from(error)),
        }
    }

    /// Get the current coin balance.
    async fn get_balance(&self, client_id: Option<&ClientFullId>) -> Result<Coins, CoreError>
    where
        Self: Sized,
    {
        trace!("Get balance for {:?}", client_id);

        match send_as_helper(self, Request::GetBalance, client_id) {
            Ok(res) => match res {
                Response::GetBalance(result) => match result {
                    Ok(coins) => Ok(coins),
                    Err(error) => Err(CoreError::from(error)),
                },
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            },
            Err(error) => Err(CoreError::from(error)),
        }
    }

    /// Put immutable data to the network.
    async fn put_idata<D: Into<IData> + Send>(&self, data: D) -> Result<(), CoreError>
    where
        Self: Sized + Send,
    {
        let idata: IData = data.into();
        trace!("Put IData at {:?}", idata.name());
        send_mutation(self, Request::PutIData(idata)).await
    }

    /// Get immutable data from the network. If the data exists locally in the cache then it will be
    /// immediately returned without making an actual network request.
    async fn get_idata(&self, address: IDataAddress) -> Result<IData, CoreError>
    where
        Self: Sized,
    {
        trace!("Fetch Immutable Data");

        let inner = self.inner();
        if let Some(data) = inner.lock().unwrap().cache.get_mut(&address) {
            trace!("ImmutableData found in cache.");
            return Ok(data.clone());
        }

        let inner = Arc::downgrade(&self.inner());
        let res = send(self, Request::GetIData(address))?;
        let data = match res {
            Response::GetIData(res) => res.map_err(CoreError::from),
            _ => return Err(CoreError::ReceivedUnexpectedEvent),
        }?;

        if let Some(inner) = inner.upgrade() {
            // Put to cache
            let _ = inner
                .lock()
                .unwrap()
                .cache
                .insert(*data.address(), data.clone());
        };
        Ok(data)
    }

    /// Delete unpublished immutable data from the network.
    async fn del_unpub_idata(&self, name: XorName) -> Result<(), CoreError>
    where
        Self: Sized,
    {
        let inner = self.inner();
        if inner
            .lock()
            .unwrap()
            .cache
            .remove(&IDataAddress::Unpub(name))
            .is_some()
        {
            trace!("Deleted UnpubImmutableData from cache.");
        }

        // let inner = self.inner().clone();
        let inner = self.inner().clone();

        let _ = Arc::downgrade(&inner);
        trace!("Delete Unpublished IData at {:?}", name);
        send_mutation(self, Request::DeleteUnpubIData(IDataAddress::Unpub(name))).await
    }

    /// Put sequenced mutable data to the network
    async fn put_seq_mutable_data(&self, data: SeqMutableData) -> Result<(), CoreError>
    where
        Self: Sized,
    {
        trace!("Put Sequenced MData at {:?}", data.name());
        send_mutation(self, Request::PutMData(MData::Seq(data))).await
    }

    /// Fetch unpublished mutable data from the network
    async fn get_unseq_mdata(&self, name: XorName, tag: u64) -> Result<UnseqMutableData, CoreError>
    where
        Self: Sized,
    {
        trace!("Fetch Unsequenced Mutable Data");

        match send(self, Request::GetMData(MDataAddress::Unseq { name, tag }))? {
            Response::GetMData(res) => res.map_err(CoreError::from).and_then(|mdata| match mdata {
                MData::Unseq(data) => Ok(data),
                MData::Seq(_) => Err(CoreError::ReceivedUnexpectedData),
            }),
            _ => Err(CoreError::ReceivedUnexpectedEvent),
        }
    }

    /// Fetch the value for a given key in a sequenced mutable data
    async fn get_seq_mdata_value(
        &self,
        name: XorName,
        tag: u64,
        key: Vec<u8>,
    ) -> Result<MDataSeqValue, CoreError>
    where
        Self: Sized,
    {
        trace!("Fetch MDataValue for {:?}", name);

        match send(
            self,
            Request::GetMDataValue {
                address: MDataAddress::Seq { name, tag },
                key,
            },
        )? {
            Response::GetMDataValue(res) => {
                res.map_err(CoreError::from).and_then(|value| match value {
                    MDataValue::Seq(val) => Ok(val),
                    MDataValue::Unseq(_) => Err(CoreError::ReceivedUnexpectedData),
                })
            }
            _ => Err(CoreError::ReceivedUnexpectedEvent),
        }
    }

    /// Fetch the value for a given key in a sequenced mutable data
    async fn get_unseq_mdata_value(
        &self,
        name: XorName,
        tag: u64,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, CoreError>
    where
        Self: Sized,
    {
        trace!("Fetch MDataValue for {:?}", name);

        match send(
            self,
            Request::GetMDataValue {
                address: MDataAddress::Unseq { name, tag },
                key,
            },
        )? {
            Response::GetMDataValue(res) => {
                res.map_err(CoreError::from).and_then(|value| match value {
                    MDataValue::Unseq(val) => Ok(val),
                    MDataValue::Seq(_) => Err(CoreError::ReceivedUnexpectedData),
                })
            }
            _ => Err(CoreError::ReceivedUnexpectedEvent),
        }
    }

    /// Fetch sequenced mutable data from the network
    async fn get_seq_mdata(&self, name: XorName, tag: u64) -> Result<SeqMutableData, CoreError>
    where
        Self: Sized,
    {
        trace!("Fetch Sequenced Mutable Data");

        match send(self, Request::GetMData(MDataAddress::Seq { name, tag }))? {
            Response::GetMData(res) => res.map_err(CoreError::from).and_then(|mdata| match mdata {
                MData::Seq(data) => Ok(data),
                MData::Unseq(_) => Err(CoreError::ReceivedUnexpectedData),
            }),
            _ => Err(CoreError::ReceivedUnexpectedEvent),
        }
    }

    /// Mutates sequenced `MutableData` entries in bulk
    async fn mutate_seq_mdata_entries(
        &self,
        name: XorName,
        tag: u64,
        actions: MDataSeqEntryActions,
    ) -> Result<(), CoreError>
    where
        Self: Sized,
    {
        trace!("Mutate MData for {:?}", name);

        send_mutation(
            self,
            Request::MutateMDataEntries {
                address: MDataAddress::Seq { name, tag },
                actions: MDataEntryActions::Seq(actions),
            },
        )
        .await
    }

    /// Mutates unsequenced `MutableData` entries in bulk
    async fn mutate_unseq_mdata_entries(
        &self,
        name: XorName,
        tag: u64,
        actions: MDataUnseqEntryActions,
    ) -> Result<(), CoreError>
    where
        Self: Sized,
    {
        trace!("Mutate MData for {:?}", name);

        send_mutation(
            self,
            Request::MutateMDataEntries {
                address: MDataAddress::Unseq { name, tag },
                actions: MDataEntryActions::Unseq(actions),
            },
        )
        .await
    }

    /// Get a shell (bare bones) version of `MutableData` from the network.
    async fn get_seq_mdata_shell(
        &self,
        name: XorName,
        tag: u64,
    ) -> Result<SeqMutableData, CoreError>
    where
        Self: Sized,
    {
        trace!("GetMDataShell for {:?}", name);

        match send(
            self,
            Request::GetMDataShell(MDataAddress::Seq { name, tag }),
        )? {
            Response::GetMDataShell(res) => {
                res.map_err(CoreError::from).and_then(|mdata| match mdata {
                    MData::Seq(data) => Ok(data),
                    _ => Err(CoreError::ReceivedUnexpectedData),
                })
            }
            _ => Err(CoreError::ReceivedUnexpectedEvent),
        }
    }

    /// Get a shell (bare bones) version of `MutableData` from the network.
    async fn get_unseq_mdata_shell(
        &self,
        name: XorName,
        tag: u64,
    ) -> Result<UnseqMutableData, CoreError>
    where
        Self: Sized,
    {
        trace!("GetMDataShell for {:?}", name);

        match send(
            self,
            Request::GetMDataShell(MDataAddress::Unseq { name, tag }),
        )? {
            Response::GetMDataShell(res) => {
                res.map_err(CoreError::from).and_then(|mdata| match mdata {
                    MData::Unseq(data) => Ok(data),
                    _ => Err(CoreError::ReceivedUnexpectedData),
                })
            }
            _ => Err(CoreError::ReceivedUnexpectedEvent),
        }
    }

    /// Get a current version of `MutableData` from the network.
    async fn get_mdata_version(&self, address: MDataAddress) -> Result<u64, CoreError>
    where
        Self: Sized,
    {
        trace!("GetMDataVersion for {:?}", address);

        match send(self, Request::GetMDataVersion(address))? {
            Response::GetMDataVersion(res) => res.map_err(CoreError::from),
            _ => Err(CoreError::ReceivedUnexpectedEvent),
        }
    }

    /// Return a complete list of entries in `MutableData`.
    async fn list_unseq_mdata_entries(
        &self,
        name: XorName,
        tag: u64,
    ) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, CoreError>
    where
        Self: Sized,
    {
        trace!("ListMDataEntries for {:?}", name);

        match send(
            self,
            Request::ListMDataEntries(MDataAddress::Unseq { name, tag }),
        )? {
            Response::ListMDataEntries(res) => {
                res.map_err(CoreError::from)
                    .and_then(|entries| match entries {
                        MDataEntries::Unseq(data) => Ok(data),
                        MDataEntries::Seq(_) => Err(CoreError::ReceivedUnexpectedData),
                    })
            }
            _ => Err(CoreError::ReceivedUnexpectedEvent),
        }
    }

    /// Return a complete list of entries in `MutableData`.
    async fn list_seq_mdata_entries(
        &self,
        name: XorName,
        tag: u64,
    ) -> Result<MDataSeqEntries, CoreError>
    where
        Self: Sized,
    {
        trace!("ListSeqMDataEntries for {:?}", name);

        match send(
            self,
            Request::ListMDataEntries(MDataAddress::Seq { name, tag }),
        )? {
            Response::ListMDataEntries(res) => {
                res.map_err(CoreError::from)
                    .and_then(|entries| match entries {
                        MDataEntries::Seq(data) => Ok(data),
                        MDataEntries::Unseq(_) => Err(CoreError::ReceivedUnexpectedData),
                    })
            }
            _ => Err(CoreError::ReceivedUnexpectedEvent),
        }
    }

    /// Return a list of keys in `MutableData` stored on the network.
    async fn list_mdata_keys(&self, address: MDataAddress) -> Result<BTreeSet<Vec<u8>>, CoreError>
    where
        Self: Sized,
    {
        trace!("ListMDataKeys for {:?}", address);

        match send(self, Request::ListMDataKeys(address))? {
            Response::ListMDataKeys(res) => res.map_err(CoreError::from),
            _ => Err(CoreError::ReceivedUnexpectedEvent),
        }
    }

    /// Return a list of values in a Sequenced Mutable Data
    async fn list_seq_mdata_values(
        &self,
        name: XorName,
        tag: u64,
    ) -> Result<Vec<MDataSeqValue>, CoreError>
    where
        Self: Sized,
    {
        trace!("List MDataValues for {:?}", name);

        match send(
            self,
            Request::ListMDataValues(MDataAddress::Seq { name, tag }),
        )? {
            Response::ListMDataValues(res) => {
                res.map_err(CoreError::from)
                    .and_then(|values| match values {
                        MDataValues::Seq(data) => Ok(data),
                        MDataValues::Unseq(_) => Err(CoreError::ReceivedUnexpectedData),
                    })
            }
            _ => Err(CoreError::ReceivedUnexpectedEvent),
        }
    }

    /// Return the permissions set for a particular user
    async fn list_mdata_user_permissions(
        &self,
        address: MDataAddress,
        user: PublicKey,
    ) -> Result<MDataPermissionSet, CoreError>
    where
        Self: Sized,
    {
        trace!("GetMDataUserPermissions for {:?}", address);

        match send(self, Request::ListMDataUserPermissions { address, user })? {
            Response::ListMDataUserPermissions(res) => res.map_err(CoreError::from),
            _ => Err(CoreError::ReceivedUnexpectedEvent),
        }
    }

    /// Returns a list of values in an Unsequenced Mutable Data
    async fn list_unseq_mdata_values(
        &self,
        name: XorName,
        tag: u64,
    ) -> Result<Vec<Vec<u8>>, CoreError>
    where
        Self: Sized,
    {
        trace!("List MDataValues for {:?}", name);

        match send(
            self,
            Request::ListMDataValues(MDataAddress::Unseq { name, tag }),
        )? {
            Response::ListMDataValues(res) => {
                res.map_err(CoreError::from)
                    .and_then(|values| match values {
                        MDataValues::Unseq(data) => Ok(data),
                        MDataValues::Seq(_) => Err(CoreError::ReceivedUnexpectedData),
                    })
            }
            _ => Err(CoreError::ReceivedUnexpectedEvent),
        }
    }
    // ======= Append Only Data =======
    //
    /// Put AppendOnly Data into the Network
    async fn put_adata(&self, data: AData) -> Result<(), CoreError>
    where
        Self: Sized,
    {
        trace!("Put AppendOnly Data {:?}", data.name());
        send_mutation(self, Request::PutAData(data)).await
    }

    /// Get AppendOnly Data from the Network
    async fn get_adata(&self, address: ADataAddress) -> Result<AData, CoreError>
    where
        Self: Sized,
    {
        trace!("Get AppendOnly Data at {:?}", address.name());

        match send(self, Request::GetAData(address))? {
            Response::GetAData(res) => res.map_err(CoreError::from),
            _ => Err(CoreError::ReceivedUnexpectedEvent),
        }
    }

    /// Get AppendOnly Data Shell from the Network
    async fn get_adata_shell(
        &self,
        data_index: ADataIndex,
        address: ADataAddress,
    ) -> Result<AData, CoreError>
    where
        Self: Sized,
    {
        trace!("Get AppendOnly Data at {:?}", address.name());

        match send(
            self,
            Request::GetADataShell {
                address,
                data_index,
            },
        )? {
            Response::GetADataShell(res) => res.map_err(CoreError::from),
            _ => Err(CoreError::ReceivedUnexpectedEvent),
        }
    }

    /// Fetch Value for the provided key from AppendOnly Data at {:?}
    async fn get_adata_value(
        &self,
        address: ADataAddress,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, CoreError>
    where
        Self: Sized,
    {
        trace!(
            "Fetch Value for the provided key from AppendOnly Data at {:?}",
            address.name()
        );

        match send(self, Request::GetADataValue { address, key })? {
            Response::GetADataValue(res) => res.map_err(CoreError::from),
            _ => Err(CoreError::ReceivedUnexpectedEvent),
        }
    }

    /// Get a Set of Entries for the requested range from an AData.
    async fn get_adata_range(
        &self,
        address: ADataAddress,
        range: (ADataIndex, ADataIndex),
    ) -> Result<ADataEntries, CoreError>
    where
        Self: Sized,
    {
        trace!(
            "Get Range of entries from AppendOnly Data at {:?}",
            address.name()
        );

        match send(self, Request::GetADataRange { address, range })? {
            Response::GetADataRange(res) => res.map_err(CoreError::from),
            _ => Err(CoreError::ReceivedUnexpectedEvent),
        }
    }

    /// Get latest indices from an AppendOnly Data.
    async fn get_adata_indices(&self, address: ADataAddress) -> Result<ADataIndices, CoreError>
    where
        Self: Sized,
    {
        trace!(
            "Get latest indices from AppendOnly Data at {:?}",
            address.name()
        );

        match send(self, Request::GetADataIndices(address))? {
            Response::GetADataIndices(res) => res.map_err(CoreError::from),
            _ => Err(CoreError::ReceivedUnexpectedEvent),
        }
    }

    /// Get the last data entry from an AppendOnly Data.
    async fn get_adata_last_entry(&self, address: ADataAddress) -> Result<ADataEntry, CoreError>
    where
        Self: Sized,
    {
        trace!(
            "Get latest indices from AppendOnly Data at {:?}",
            address.name()
        );

        match send(self, Request::GetADataLastEntry(address))? {
            Response::GetADataLastEntry(res) => res.map_err(CoreError::from),
            _ => Err(CoreError::ReceivedUnexpectedEvent),
        }
    }

    /// Get permissions at the provided index.
    async fn get_unpub_adata_permissions_at_index(
        &self,
        address: ADataAddress,
        permissions_index: ADataIndex,
    ) -> Result<ADataUnpubPermissions, CoreError>
    where
        Self: Sized,
    {
        trace!(
            "Get latest indices from AppendOnly Data at {:?}",
            address.name()
        );

        match send(
            self,
            Request::GetADataPermissions {
                address,
                permissions_index,
            },
        )? {
            Response::GetADataPermissions(res) => {
                res.map_err(CoreError::from)
                    .and_then(|permissions| match permissions {
                        ADataPermissions::Unpub(data) => Ok(data),
                        ADataPermissions::Pub(_) => Err(CoreError::ReceivedUnexpectedData),
                    })
            }
            _ => Err(CoreError::ReceivedUnexpectedEvent),
        }
    }

    /// Get permissions at the provided index.
    async fn get_pub_adata_permissions_at_index(
        &self,
        address: ADataAddress,
        permissions_index: ADataIndex,
    ) -> Result<ADataPubPermissions, CoreError>
    where
        Self: Sized,
    {
        trace!(
            "Get latest indices from AppendOnly Data at {:?}",
            address.name()
        );

        match send(
            self,
            Request::GetADataPermissions {
                address,
                permissions_index,
            },
        )? {
            Response::GetADataPermissions(res) => {
                res.map_err(CoreError::from)
                    .and_then(|permissions| match permissions {
                        ADataPermissions::Pub(data) => Ok(data),
                        ADataPermissions::Unpub(_) => Err(CoreError::ReceivedUnexpectedData),
                    })
            }
            _ => Err(CoreError::ReceivedUnexpectedEvent),
        }
    }

    /// Get permissions for a specified user(s).
    async fn get_pub_adata_user_permissions(
        &self,
        address: ADataAddress,
        permissions_index: ADataIndex,
        user: ADataUser,
    ) -> Result<ADataPubPermissionSet, CoreError>
    where
        Self: Sized,
    {
        trace!(
            "Get permissions for a specified user(s) from AppendOnly Data at {:?}",
            address.name()
        );

        match send(
            self,
            Request::GetPubADataUserPermissions {
                address,
                permissions_index,
                user,
            },
        )? {
            Response::GetPubADataUserPermissions(res) => res.map_err(CoreError::from),
            _ => Err(CoreError::ReceivedUnexpectedEvent),
        }
    }

    /// Get permissions for a specified user(s).
    async fn get_unpub_adata_user_permissions(
        &self,
        address: ADataAddress,
        permissions_index: ADataIndex,
        public_key: PublicKey,
    ) -> Result<ADataUnpubPermissionSet, CoreError>
    where
        Self: Sized,
    {
        trace!(
            "Get permissions for a specified user(s) from AppendOnly Data at {:?}",
            address.name()
        );

        match send(
            self,
            Request::GetUnpubADataUserPermissions {
                address,
                permissions_index,
                public_key,
            },
        )? {
            Response::GetUnpubADataUserPermissions(res) => res.map_err(CoreError::from),
            _ => Err(CoreError::ReceivedUnexpectedEvent),
        }
    }

    /// Add AData Permissions
    async fn add_unpub_adata_permissions(
        &self,
        address: ADataAddress,
        permissions: ADataUnpubPermissions,
        permissions_index: u64,
    ) -> Result<(), CoreError>
    where
        Self: Sized,
    {
        trace!(
            "Add Permissions to UnPub AppendOnly Data {:?}",
            address.name()
        );

        send_mutation(
            self,
            Request::AddUnpubADataPermissions {
                address,
                permissions,
                permissions_index,
            },
        )
        .await
    }

    /// Add Pub AData Permissions
    async fn add_pub_adata_permissions(
        &self,
        address: ADataAddress,
        permissions: ADataPubPermissions,
        permissions_index: u64,
    ) -> Result<(), CoreError>
    where
        Self: Sized,
    {
        trace!("Add Permissions to AppendOnly Data {:?}", address.name());

        send_mutation(
            self,
            Request::AddPubADataPermissions {
                address,
                permissions,
                permissions_index,
            },
        )
        .await
    }

    /// Set new Owners to AData
    async fn set_adata_owners(
        &self,
        address: ADataAddress,
        owner: ADataOwner,
        owners_index: u64,
    ) -> Result<(), CoreError>
    where
        Self: Sized,
    {
        trace!("Set Owners to AppendOnly Data {:?}", address.name());

        send_mutation(
            self,
            Request::SetADataOwner {
                address,
                owner,
                owners_index,
            },
        )
        .await
    }

    /// Set new Owners to AData
    async fn get_adata_owners(
        &self,
        address: ADataAddress,
        owners_index: ADataIndex,
    ) -> Result<ADataOwner, CoreError>
    where
        Self: Sized,
    {
        trace!("Get Owners from AppendOnly Data at {:?}", address.name());

        match send(
            self,
            Request::GetADataOwners {
                address,
                owners_index,
            },
        )? {
            Response::GetADataOwners(res) => res.map_err(CoreError::from),
            _ => Err(CoreError::ReceivedUnexpectedEvent),
        }
    }

    /// Append to Published Seq AppendOnly Data
    async fn append_seq_adata(
        &self,
        append: ADataAppendOperation,
        index: u64,
    ) -> Result<(), CoreError>
    where
        Self: Sized,
    {
        send_mutation(self, Request::AppendSeq { append, index }).await
    }

    /// Append to Unpublished Unseq AppendOnly Data
    async fn append_unseq_adata(&self, append: ADataAppendOperation) -> Result<(), CoreError>
    where
        Self: Sized,
    {
        send_mutation(self, Request::AppendUnseq(append)).await
    }

    /// Return a list of permissions in `MutableData` stored on the network.
    async fn list_mdata_permissions(
        &self,
        address: MDataAddress,
    ) -> Result<BTreeMap<PublicKey, MDataPermissionSet>, CoreError>
    where
        Self: Sized,
    {
        trace!("List MDataPermissions for {:?}", address);

        match send(self, Request::ListMDataPermissions(address))? {
            Response::ListMDataPermissions(res) => res.map_err(CoreError::from),
            _ => Err(CoreError::ReceivedUnexpectedEvent),
        }
    }

    /// Updates or inserts a permissions set for a user
    async fn set_mdata_user_permissions(
        &self,
        address: MDataAddress,
        user: PublicKey,
        permissions: MDataPermissionSet,
        version: u64,
    ) -> Result<(), CoreError>
    where
        Self: Sized,
    {
        trace!("SetMDataUserPermissions for {:?}", address);

        send_mutation(
            self,
            Request::SetMDataUserPermissions {
                address,
                user,
                permissions,
                version,
            },
        )
        .await
    }

    /// Updates or inserts a permissions set for a user
    async fn del_mdata_user_permissions(
        &self,
        address: MDataAddress,
        user: PublicKey,
        version: u64,
    ) -> Result<(), CoreError>
    where
        Self: Sized,
    {
        trace!("DelMDataUserPermissions for {:?}", address);

        send_mutation(
            self,
            Request::DelMDataUserPermissions {
                address,
                user,
                version,
            },
        )
        .await
    }

    /// Sends an ownership transfer request.
    #[allow(unused)]
    fn change_mdata_owner(
        &self,
        name: XorName,
        tag: u64,
        new_owner: PublicKey,
        version: u64,
    ) -> Result<(), CoreError> {
        unimplemented!();
    }

    #[cfg(any(
        all(test, feature = "mock-network"),
        all(feature = "testing", feature = "mock-network")
    ))]
    #[doc(hidden)]
    fn set_network_limits(&self, max_ops_count: Option<u64>) {
        let inner = self.inner();
        inner
            .lock()
            .unwrap()
            .connection_manager
            .set_network_limits(max_ops_count);
    }

    #[cfg(any(
        all(test, feature = "mock-network"),
        all(feature = "testing", feature = "mock-network")
    ))]
    #[doc(hidden)]
    fn simulate_network_disconnect(&self) {
        let inner = self.inner();
        inner
            .lock()
            .unwrap()
            .connection_manager
            .simulate_disconnect();
    }

    #[cfg(any(
        all(test, feature = "mock-network"),
        all(feature = "testing", feature = "mock-network")
    ))]
    #[doc(hidden)]
    fn set_simulate_timeout(&self, enabled: bool) {
        let inner = self.inner();
        inner
            .lock()
            .unwrap()
            .connection_manager
            .set_simulate_timeout(enabled);
    }

    /// Set the coin balance to a specific value for testing
    #[cfg(any(test, feature = "testing"))]
    async fn test_set_balance(
        &self,
        client_id: Option<&ClientFullId>,
        amount: Coins,
    ) -> Result<Transaction, CoreError>
    where
        Self: Sized,
    {
        let new_balance_owner = client_id.map_or_else(
            || self.public_key(),
            |client_id| *client_id.public_id().public_key(),
        );
        trace!(
            "Set the coin balance of {:?} to {:?}",
            new_balance_owner,
            amount,
        );

        match send_as_helper(
            self,
            Request::CreateBalance {
                new_balance_owner,
                amount,
                transaction_id: rand::random(),
            },
            client_id,
        ) {
            Ok(res) => match res {
                Response::Transaction(result) => match result {
                    Ok(transaction) => Ok(transaction),
                    Err(error) => Err(CoreError::from(error)),
                },
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            },

            Err(error) => Err(CoreError::from(error)),
        }
    }
}

/// Creates a throw-away client to execute requests sequentially.
/// This function is blocking.
async fn temp_client<F, R>(identity: &ClientFullId, mut func: F) -> Result<R, CoreError>
where
    F: FnMut(&mut ConnectionManager, &SafeKey) -> Result<R, CoreError>,
{
    let full_id = SafeKey::client(identity.clone());
    let (net_tx, _net_rx) = mpsc::unbounded();

    let mut cm = attempt_bootstrap(&Config::new().quic_p2p, &net_tx, full_id.clone()).await?;

    let res = func(&mut cm, &full_id);

    cm.disconnect(&full_id.public_id()).await?;

    res
}

/// Create a new mock balance at an arbitrary address.
pub async fn test_create_balance(owner: &ClientFullId, amount: Coins) -> Result<(), CoreError> {
    trace!("Create test balance of {} for {:?}", amount, owner);

    temp_client(owner, move |mut cm, full_id| {
        // Create the balance for the client
        let new_balance_owner = match full_id.public_id() {
            PublicId::Client(id) => *id.public_key(),
            x => return Err(CoreError::from(format!("Unexpected ID type {:?}", x))),
        };

        let response = futures::executor::block_on(req(
            &mut cm,
            Request::CreateBalance {
                new_balance_owner,
                amount,
                transaction_id: rand::random(),
            },
            &full_id,
        ))?;

        match response {
            Response::Transaction(res) => res.map(|_| Ok(()))?,
            _ => Err(CoreError::from("Unexpected response")),
        }
    })
    .await
}

/// Get the balance at the given key's location
pub async fn wallet_get_balance(wallet_sk: &ClientFullId) -> Result<Coins, CoreError> {
    trace!("Get balance for {:?}", wallet_sk);

    temp_client(
        wallet_sk,
        move |mut cm, full_id| match futures::executor::block_on(req(
            &mut cm,
            Request::GetBalance,
            &full_id,
        ))? {
            Response::GetBalance(res) => res.map_err(CoreError::from),
            _ => Err(CoreError::from("Unexpected response")),
        },
    )
    .await
}

/// Creates a new coin balance on the network.
pub async fn wallet_create_balance(
    client_id: &ClientFullId,
    new_balance_owner: PublicKey,
    amount: Coins,
    transaction_id: Option<u64>,
) -> Result<Transaction, CoreError> {
    trace!(
        "Create a new coin balance for {:?} with {} coins.",
        new_balance_owner,
        amount
    );

    let transaction_id = transaction_id.unwrap_or_else(rand::random);

    temp_client(client_id, move |mut cm, full_id| {
        let response = futures::executor::block_on(req(
            &mut cm,
            Request::CreateBalance {
                new_balance_owner,
                amount,
                transaction_id,
            },
            &full_id,
        ))?;
        match response {
            Response::Transaction(res) => res.map_err(CoreError::from),
            _ => Err(CoreError::from("Unexpected response")),
        }
    })
    .await
}

/// Transfer coins
pub async fn wallet_transfer_coins(
    client_id: &ClientFullId,
    destination: XorName,
    amount: Coins,
    transaction_id: Option<u64>,
) -> Result<Transaction, CoreError> {
    trace!("Transfer {} coins to {:?}", amount, destination);

    let transaction_id = transaction_id.unwrap_or_else(rand::random);

    temp_client(client_id, move |mut cm, full_id| {
        let response = futures::executor::block_on(req(
            &mut cm,
            Request::TransferCoins {
                destination,
                amount,
                transaction_id,
            },
            &full_id,
        ))?;
        match response {
            Response::Transaction(res) => res.map_err(CoreError::from),
            _ => Err(CoreError::from("Unexpected response")),
        }
    })
    .await
}

/// This trait implements functions that are supposed to be called only by `CoreClient` and `AuthClient`.
/// Applications are not allowed to `DELETE MData` and get/mutate auth keys, hence `AppClient` does not implement
/// this trait.
#[async_trait]
pub trait AuthActions: Client + Clone + 'static {
    /// Fetches a list of authorised keys and version.
    async fn list_auth_keys_and_version(
        &self,
    ) -> Result<(BTreeMap<PublicKey, AppPermissions>, u64), CoreError>
    where
        Self: Sized,
    {
        trace!("ListAuthKeysAndVersion");

        match send(self, Request::ListAuthKeysAndVersion)? {
            Response::ListAuthKeysAndVersion(res) => res.map_err(CoreError::from),
            _ => Err(CoreError::ReceivedUnexpectedEvent),
        }
    }

    /// Adds a new authorised key.
    async fn ins_auth_key(
        &self,
        key: PublicKey,
        permissions: AppPermissions,
        version: u64,
    ) -> Result<(), CoreError>
    where
        Self: Sized,
    {
        trace!("InsAuthKey ({:?})", key);

        send_mutation(
            self,
            Request::InsAuthKey {
                key,
                permissions,
                version,
            },
        )
        .await
    }

    /// Removes an authorised key.
    async fn del_auth_key(&self, key: PublicKey, version: u64) -> Result<(), CoreError>
    where
        Self: Sized,
    {
        trace!("DelAuthKey ({:?})", key);

        send_mutation(self, Request::DelAuthKey { key, version }).await
    }

    /// Delete MData from network
    async fn delete_mdata(&self, address: MDataAddress) -> Result<(), CoreError>
    where
        Self: Sized,
    {
        trace!("Delete entire Mutable Data at {:?}", address);

        send_mutation(self, Request::DeleteMData(address)).await
    }

    /// Delete AData from network.
    async fn delete_adata(&self, address: ADataAddress) -> Result<(), CoreError>
    where
        Self: Sized,
    {
        trace!("Delete entire Unpublished AppendOnly Data at {:?}", address);

        send_mutation(self, Request::DeleteAData(address)).await
    }
}

fn sign_request(request: Request, client_id: &ClientFullId) -> Message {
    let message_id = MessageId::new();

    let signature = Some(client_id.sign(&unwrap!(bincode::serialize(&(&request, message_id)))));

    Message::Request {
        request,
        message_id,
        signature,
    }
}

// TODO: Consider deprecating this struct once trait fields are stable. See
// https://github.com/nikomatsakis/fields-in-traits-rfc.
/// Struct containing fields expected by the `Client` trait. Implementers of `Client` should be
/// composed around this struct.
#[allow(unused)] // FIXME
pub struct Inner<C: Client + Sync + Send, T> {
    connection_manager: ConnectionManager,
    el_handle: Handle,
    cache: LruCache<IDataAddress, IData>,
    timeout: Duration,
    core_tx: CoreMsgTx<C, T>,
    net_tx: NetworkTx,
}

impl<C: Client + Sync + Send, T> Inner<C, T> {
    /// Create a new `ClientInner` object.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        el_handle: Handle,
        connection_manager: ConnectionManager,
        cache: LruCache<IDataAddress, IData>,
        timeout: Duration,
        core_tx: CoreMsgTx<C, T>,
        net_tx: NetworkTx,
    ) -> Inner<C, T>
    where
        Self: Sized,
    {
        Self {
            el_handle,
            connection_manager,
            cache,
            timeout,
            core_tx,
            net_tx,
        }
    }

    /// Get the connection manager associated with the client
    pub fn cm(&mut self) -> &mut ConnectionManager
    where
        Self: Sized,
    {
        &mut self.connection_manager
    }
}

/// Send a request and wait for a response.
/// This function is blocking.
pub async fn req(
    cm: &mut ConnectionManager,
    request: Request,
    full_id_new: &SafeKey,
) -> Result<Response, CoreError> {
    let message_id = MessageId::new();
    let signature = full_id_new.sign(&unwrap!(bincode::serialize(&(&request, message_id))));

    cm.send(
        &full_id_new.public_id(),
        &Message::Request {
            request,
            message_id,
            signature: Some(signature),
        },
    )
    .await
}

/// Utility function that bootstraps a client to the network. If there is a failure then it retries.
/// After a maximum of three attempts if the boostrap process still fails, then an error is returned.
pub async fn attempt_bootstrap(
    qp2p_config: &QuicP2pConfig,
    net_tx: &NetworkTx,
    safe_key: SafeKey,
) -> Result<ConnectionManager, CoreError> {
    let mut attempts: u32 = 0;

    loop {
        let mut connection_manager = ConnectionManager::new(qp2p_config.clone(), &net_tx.clone())?;
        let res = connection_manager.bootstrap(safe_key.clone()).await;
        match res {
            Ok(()) => return Ok(connection_manager),
            Err(err) => {
                attempts += 1;
                if attempts < 3 {
                    trace!("Error connecting to network! Retrying... ({})", attempts);
                } else {
                    return Err(err);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::generate_random_vector;
    use crate::utils::test_utils::{
        calculate_new_balance, gen_bls_keypair, gen_client_id, random_client,
    };
    use safe_nd::{
        ADataAction, ADataEntry, ADataKind, ADataOwner, ADataUnpubPermissionSet,
        ADataUnpubPermissions, AppendOnlyData, Coins, Error as SndError, MDataAction, MDataKind,
        PubImmutableData, PubSeqAppendOnlyData, SeqAppendOnly, UnpubImmutableData,
        UnpubSeqAppendOnlyData, UnpubUnseqAppendOnlyData, UnseqAppendOnly, XorName,
    };
    use std::str::FromStr;

    // Test putting and getting pub idata.
    #[test]
    fn pub_idata_test() {
        random_client(move |client| {
            let client2 = client.clone();
            let client3 = client.clone();
            let client4 = client.clone();
            let client5 = client.clone();
            // The `random_client()` initializes the client with 10 coins.
            let start_bal = unwrap!(Coins::from_str("10"));

            let value = unwrap!(generate_random_vector::<u8>(10));
            let data = PubImmutableData::new(value.clone());
            let address = *data.address();
            let pk = gen_bls_keypair().public_key();

            let test_data = UnpubImmutableData::new(value, pk);
            client
                // Get inexistent idata
                .get_idata(address)
                .then(|res| -> Result<(), CoreError> {
                    match res {
                        Ok(data) => panic!("Pub idata should not exist yet: {:?}", data),
                        Err(CoreError::DataError(SndError::NoSuchData)) => Ok(()),
                        Err(e) => panic!("Unexpected: {:?}", e),
                    }
                })
                .and_then(move |_| {
                    // Put idata
                    client2.put_idata(data.clone())
                })
                .and_then(move |_| {
                    client3.put_idata(test_data.clone()).then(|res| match res {
                        Ok(_) => panic!("Unexpected Success: Validating owners should fail"),
                        Err(CoreError::DataError(SndError::InvalidOwners)) => Ok(()),
                        Err(e) => panic!("Unexpected: {:?}", e),
                    })
                })
                .and_then(move |_| client4.get_balance(None))
                .and_then(move |balance| {
                    let expected_bal = calculate_new_balance(start_bal, Some(2), None);
                    assert_eq!(balance, expected_bal);
                    Ok(())
                })
                .and_then(move |_| {
                    // Fetch idata
                    client5.get_idata(address).map(move |fetched_data| {
                        assert_eq!(*fetched_data.address(), address);
                    })
                })
        })
    }

    // Test putting, getting, and deleting unpub idata.
    #[test]
    fn unpub_idata_test() {
        crate::utils::test_utils::init_log();
        // The `random_client()` initializes the client with 10 coins.
        let start_bal = unwrap!(Coins::from_str("10"));

        random_client(move |client| {
            let client2 = client.clone();
            let client3 = client.clone();
            let client4 = client.clone();
            let client5 = client.clone();
            let client6 = client.clone();
            let client7 = client.clone();
            let client8 = client.clone();
            let client9 = client.clone();

            let value = unwrap!(generate_random_vector::<u8>(10));
            let data = UnpubImmutableData::new(value.clone(), client.public_key());
            let data2 = data.clone();
            let data3 = data.clone();
            let address = *data.address();
            assert_eq!(address, *data2.address());

            let pub_data = PubImmutableData::new(value);

            client
                // Get inexistent idata
                .get_idata(address)
                .then(|res| -> Result<(), CoreError> {
                    match res {
                        Ok(_) => panic!("Unpub idata should not exist yet"),
                        Err(CoreError::DataError(SndError::NoSuchData)) => Ok(()),
                        Err(e) => panic!("Unexpected: {:?}", e),
                    }
                })
                .and_then(move |_| {
                    // Put idata
                    client2.put_idata(data.clone())
                })
                .and_then(move |_| {
                    // Test putting unpub idata with the same value.
                    // Should conflict because duplication does not apply to unpublished data.
                    client3.put_idata(data2.clone())
                })
                .then(|res| -> Result<(), CoreError> {
                    match res {
                        Err(CoreError::DataError(SndError::DataExists)) => Ok(()),
                        res => panic!("Unexpected: {:?}", res),
                    }
                })
                .and_then(move |_| client4.get_balance(None))
                .and_then(move |balance| {
                    let expected_bal = calculate_new_balance(start_bal, Some(2), None);
                    assert_eq!(balance, expected_bal);
                    Ok(())
                })
                .and_then(move |_| {
                    // Test putting published idata with the same value. Should not conflict.
                    client5.put_idata(pub_data)
                })
                .and_then(move |_| {
                    // Fetch idata
                    client6.get_idata(address).map(move |fetched_data| {
                        assert_eq!(*fetched_data.address(), address);
                    })
                })
                .and_then(move |()| {
                    // Delete idata
                    client7.del_unpub_idata(*address.name())
                })
                .and_then(move |()| {
                    // Make sure idata was deleted
                    client8.get_idata(address)
                })
                .then(|res| -> Result<(), CoreError> {
                    match res {
                        Ok(_) => panic!("Unpub idata still exists after deletion"),
                        Err(CoreError::DataError(SndError::NoSuchData)) => Ok(()),
                        Err(e) => panic!("Unexpected: {:?}", e),
                    }
                })
                .and_then(move |_| {
                    // Test putting unpub idata with the same value again. Should not conflict.
                    client9.put_idata(data3.clone())
                })
        });
    }

    // 1. Create unseq. mdata with some entries and perms and put it on the network
    // 2. Fetch the shell version, entries, keys, values anv verify them
    // 3. Fetch the entire. data object and verify
    #[test]
    pub fn unseq_mdata_test() {
        let _ = random_client(move |client| {
            let client2 = client.clone();
            let client3 = client.clone();
            let client4 = client.clone();
            let client5 = client.clone();
            let client6 = client.clone();

            let name = XorName(rand::random());
            let tag = 15001;
            let mut entries: BTreeMap<Vec<u8>, Vec<u8>> = Default::default();
            let mut permissions: BTreeMap<_, _> = Default::default();
            let permission_set = MDataPermissionSet::new().allow(MDataAction::Read);
            let _ = permissions.insert(client.public_key(), permission_set);
            let _ = entries.insert(b"key".to_vec(), b"value".to_vec());
            let entries_keys = entries.keys().cloned().collect();
            let entries_values: Vec<Vec<u8>> = entries.values().cloned().collect();

            let data = UnseqMutableData::new_with_data(
                name,
                tag,
                entries.clone(),
                permissions,
                client.public_key(),
            );
            client
                .put_unseq_mutable_data(data.clone())
                .and_then(move |_| {
                    println!("Put unseq. MData successfully");

                    client3
                        .get_mdata_version(MDataAddress::Unseq { name, tag })
                        .map(move |version| assert_eq!(version, 0))
                })
                .and_then(move |_| {
                    client4
                        .list_unseq_mdata_entries(name, tag)
                        .map(move |fetched_entries| {
                            assert_eq!(fetched_entries, entries);
                        })
                })
                .and_then(move |_| {
                    client5
                        .list_mdata_keys(MDataAddress::Unseq { name, tag })
                        .map(move |keys| assert_eq!(keys, entries_keys))
                })
                .and_then(move |_| {
                    client6
                        .list_unseq_mdata_values(name, tag)
                        .map(move |values| assert_eq!(values, entries_values))
                })
                .and_then(move |_| {
                    client2
                        .get_unseq_mdata(*data.name(), data.tag())
                        .map(move |fetched_data| {
                            assert_eq!(fetched_data.name(), data.name());
                            assert_eq!(fetched_data.tag(), data.tag());
                            fetched_data
                        })
                })
                .then(|res| res)
        });
    }

    // 1. Create an put seq. mdata on the network with some entries and permissions.
    // 2. Fetch the shell version, entries, keys, values anv verify them
    // 3. Fetch the entire. data object and verify
    #[test]
    pub fn seq_mdata_test() {
        let _ = random_client(move |client| {
            let client2 = client.clone();
            let client3 = client.clone();
            let client4 = client.clone();
            let client5 = client.clone();
            let client6 = client.clone();

            let name = XorName(rand::random());
            let tag = 15001;
            let mut entries: MDataSeqEntries = Default::default();
            let _ = entries.insert(
                b"key".to_vec(),
                MDataSeqValue {
                    data: b"value".to_vec(),
                    version: 0,
                },
            );
            let entries_keys = entries.keys().cloned().collect();
            let entries_values: Vec<MDataSeqValue> = entries.values().cloned().collect();
            let mut permissions: BTreeMap<_, _> = Default::default();
            let permission_set = MDataPermissionSet::new().allow(MDataAction::Read);
            let _ = permissions.insert(client.public_key(), permission_set);
            let data = SeqMutableData::new_with_data(
                name,
                tag,
                entries.clone(),
                permissions,
                client.public_key(),
            );

            client
                .put_seq_mutable_data(data.clone())
                .and_then(move |_| {
                    println!("Put seq. MData successfully");

                    client4
                        .list_seq_mdata_entries(name, tag)
                        .map(move |fetched_entries| {
                            assert_eq!(fetched_entries, entries);
                        })
                })
                .and_then(move |_| {
                    client3
                        .get_seq_mdata_shell(name, tag)
                        .map(move |mdata_shell| {
                            assert_eq!(*mdata_shell.name(), name);
                            assert_eq!(mdata_shell.tag(), tag);
                            assert_eq!(mdata_shell.entries().len(), 0);
                        })
                })
                .and_then(move |_| {
                    client5
                        .list_mdata_keys(MDataAddress::Seq { name, tag })
                        .map(move |keys| assert_eq!(keys, entries_keys))
                })
                .and_then(move |_| {
                    client6
                        .list_seq_mdata_values(name, tag)
                        .map(move |values| assert_eq!(values, entries_values))
                })
                .and_then(move |_| {
                    client2.get_seq_mdata(name, tag).map(move |fetched_data| {
                        assert_eq!(fetched_data.name(), data.name());
                        assert_eq!(fetched_data.tag(), data.tag());
                        assert_eq!(fetched_data.entries().len(), 1);
                        fetched_data
                    })
                })
                .then(|res| res)
        });
    }

    // 1. Put seq. mdata on the network and then delete it
    // 2. Try getting the data object. It should panic
    #[test]
    pub fn del_seq_mdata_test() {
        random_client(move |client| {
            let client2 = client.clone();
            let client3 = client.clone();
            let name = XorName(rand::random());
            let tag = 15001;
            let mdataref = MDataAddress::Seq { name, tag };
            let data = SeqMutableData::new_with_data(
                name,
                tag,
                Default::default(),
                Default::default(),
                client.public_key(),
            );

            client
                .put_seq_mutable_data(data.clone())
                .and_then(move |_| {
                    client2.delete_mdata(mdataref).then(move |result| {
                        assert!(result.is_ok());
                        Ok(())
                    })
                })
                .then(move |_| {
                    client3
                        .get_unseq_mdata(*data.name(), data.tag())
                        .then(move |res| {
                            match res {
                                Err(CoreError::DataError(SndError::NoSuchData)) => (),
                                _ => panic!("Unexpected success"),
                            }
                            Ok::<_, SndError>(())
                        })
                })
        });
    }

    // 1. Put unseq. mdata on the network and then delete it
    // 2. Try getting the data object. It should panic
    #[test]
    pub fn del_unseq_mdata_test() {
        random_client(move |client| {
            let client2 = client.clone();
            let client3 = client.clone();
            let name = XorName(rand::random());
            let tag = 15001;
            let mdataref = MDataAddress::Unseq { name, tag };
            let data = UnseqMutableData::new_with_data(
                name,
                tag,
                Default::default(),
                Default::default(),
                client.public_key(),
            );

            client
                .put_unseq_mutable_data(data.clone())
                .and_then(move |_| {
                    client2.delete_mdata(mdataref).then(move |result| {
                        assert!(result.is_ok());
                        Ok(())
                    })
                })
                .then(move |_| {
                    client3
                        .get_unseq_mdata(*data.name(), data.tag())
                        .then(move |res| {
                            match res {
                                Err(CoreError::DataError(SndError::NoSuchData)) => (),
                                _ => panic!("Unexpected success"),
                            }
                            Ok::<_, SndError>(())
                        })
                })
        });
    }

    // 1. Create 2 accounts and create a wallet only for account A.
    // 2. Try to transfer coins from A to inexistent wallet. This request should fail.
    // 3. Try to request balance of wallet B. This request should fail.
    // 4. Now create a wallet for account B and transfer some coins to A. This should pass.
    // 5. Try to request transaction from wallet A using account B. This request should succeed
    // (because transactions are always open).
    #[test]
    fn coin_permissions() {
        let wallet_a_addr = random_client(move |client| {
            let wallet_a_addr: XorName = client.public_key().into();
            client
                .transfer_coins(None, rand::random(), unwrap!(Coins::from_str("5.0")), None)
                .then(move |res| {
                    match res {
                        Err(CoreError::DataError(SndError::NoSuchBalance)) => (),
                        res => panic!("Unexpected result: {:?}", res),
                    }
                    Ok::<_, SndError>(wallet_a_addr)
                })
        });

        random_client(move |client| {
            let c2 = client.clone();
            let c3 = client.clone();
            let c4 = client.clone();
            client
                .get_balance(None)
                .then(move |res| {
                    // Subtract to cover the cost of inserting the login packet
                    let expected_amt = unwrap!(Coins::from_str("10")
                        .ok()
                        .and_then(|x| x.checked_sub(COST_OF_PUT)));
                    match res {
                        Ok(fetched_amt) => assert_eq!(expected_amt, fetched_amt),
                        res => panic!("Unexpected result: {:?}", res),
                    }
                    c2.test_set_balance(None, unwrap!(Coins::from_str("50.0")))
                })
                .and_then(move |_| {
                    c3.transfer_coins(None, wallet_a_addr, unwrap!(Coins::from_str("10")), None)
                })
                .then(move |res| {
                    match res {
                        Ok(transaction) => {
                            assert_eq!(transaction.amount, unwrap!(Coins::from_str("10")))
                        }
                        res => panic!("Unexpected error: {:?}", res),
                    }
                    c4.get_balance(None)
                })
                .then(move |res| {
                    let expected_amt = unwrap!(Coins::from_str("40"));
                    match res {
                        Ok(fetched_amt) => assert_eq!(expected_amt, fetched_amt),
                        res => panic!("Unexpected result: {:?}", res),
                    }
                    Ok::<_, SndError>(())
                })
        });
    }

    // 1. Create a client with a wallet. Create an anonymous wallet preloading it from the client's wallet.
    // 2. Transfer some safecoin from the anonymous wallet to the client.
    // 3. Fetch the balances of both the wallets and verify them.
    // 5. Try to create a balance using an inexistent wallet. This should fail.
    #[test]
    fn anonymous_wallet() {
        random_client(move |client| {
            let client1 = client.clone();
            let client2 = client.clone();
            let client3 = client.clone();
            let client4 = client.clone();
            let client5 = client.clone();
            let wallet1: XorName = client.owner_key().into();
            let init_bal = unwrap!(Coins::from_str("500.0"));

            let client_id = gen_client_id();
            let bls_pk = *client_id.public_id().public_key();

            client
                .test_set_balance(None, init_bal)
                .and_then(move |_| {
                    client1.create_balance(None, bls_pk, unwrap!(Coins::from_str("100.0")), None)
                })
                .and_then(move |transaction| {
                    assert_eq!(transaction.amount, unwrap!(Coins::from_str("100")));
                    client2
                        .transfer_coins(
                            Some(&client_id.clone()),
                            wallet1,
                            unwrap!(Coins::from_str("5.0")),
                            None,
                        )
                        .map(|transaction| (transaction, client_id))
                })
                .and_then(move |(transaction, client_id)| {
                    assert_eq!(transaction.amount, unwrap!(Coins::from_str("5.0")));
                    client3.get_balance(Some(&client_id)).and_then(|balance| {
                        assert_eq!(balance, unwrap!(Coins::from_str("95.0")));
                        Ok(())
                    })
                })
                .and_then(move |_| {
                    client4.get_balance(None).and_then(move |balance| {
                        let expected = calculate_new_balance(
                            init_bal,
                            Some(1),
                            Some(unwrap!(Coins::from_str("95"))),
                        );
                        assert_eq!(balance, expected);
                        Ok(())
                    })
                })
                .and_then(move |_| {
                    let random_pk = gen_bls_keypair().public_key();
                    let random_source = gen_client_id();

                    client5
                        .create_balance(
                            Some(&random_source),
                            random_pk,
                            unwrap!(Coins::from_str("100.0")),
                            None,
                        )
                        .then(|res| {
                            match res {
                                Err(CoreError::DataError(SndError::NoSuchBalance)) => {}
                                res => panic!("Unexpected result: {:?}", res),
                            }
                            Ok(())
                        })
                })
        });
    }

    // 1. Create a client A with a wallet and allocate some test safecoin to it.
    // 2. Get the balance and verify it.
    // 3. Create another client B with a wallet holding some safecoin.
    // 4. Transfer some coins from client B to client A and verify the new balance.
    // 5. Fetch the transaction using the transaction ID and verify the amount.
    // 6. Try to do a coin transfer without enough funds, it should return `InsufficientBalance`
    // 7. Try to do a coin transfer with the amount set to 0, it should return `InvalidOperation`
    // 8. Set the client's balance to zero and try to put data. It should fail.
    #[test]
    fn coin_balance_transfer() {
        let wallet1: XorName = random_client(move |client| {
            let client1 = client.clone();
            let owner_key = client.owner_key();
            let wallet1: XorName = owner_key.into();

            client
                .test_set_balance(None, unwrap!(Coins::from_str("100.0")))
                .and_then(move |_| client1.get_balance(None))
                .and_then(move |balance| {
                    assert_eq!(balance, unwrap!(Coins::from_str("100.0")));
                    Ok(wallet1)
                })
        });

        random_client(move |client| {
            let c2 = client.clone();
            let c3 = client.clone();
            let c4 = client.clone();
            let c5 = client.clone();
            let c6 = client.clone();
            let c7 = client.clone();
            let c8 = client.clone();
            let init_bal = unwrap!(Coins::from_str("10"));
            client
                .get_balance(None)
                .and_then(move |orig_balance| {
                    c2.transfer_coins(None, wallet1, unwrap!(Coins::from_str("5.0")), None)
                        .map(move |_| orig_balance)
                })
                .and_then(move |orig_balance| {
                    c3.get_balance(None)
                        .map(move |new_balance| (new_balance, orig_balance))
                })
                .and_then(move |(new_balance, orig_balance)| {
                    assert_eq!(
                        new_balance,
                        unwrap!(orig_balance.checked_sub(unwrap!(Coins::from_str("5.0")))),
                    );
                    c4.transfer_coins(None, wallet1, unwrap!(Coins::from_str("5000")), None)
                })
                .then(move |res| {
                    match res {
                        Err(CoreError::DataError(SndError::InsufficientBalance)) => (),
                        res => panic!("Unexpected result: {:?}", res),
                    }
                    Ok(())
                })
                // Check if coins are refunded
                .and_then(move |_| c5.get_balance(None))
                .and_then(move |balance| {
                    let expected = calculate_new_balance(
                        init_bal,
                        Some(1),
                        Some(unwrap!(Coins::from_str("5"))),
                    );
                    assert_eq!(balance, expected);
                    c6.transfer_coins(None, wallet1, unwrap!(Coins::from_str("0")), None)
                })
                .then(move |res| {
                    match res {
                        Err(CoreError::DataError(SndError::InvalidOperation)) => (),
                        res => panic!("Unexpected result: {:?}", res),
                    }
                    c7.test_set_balance(None, unwrap!(Coins::from_str("0")))
                })
                .and_then(move |_| {
                    let data = PubImmutableData::new(unwrap!(generate_random_vector::<u8>(10)));
                    c8.put_idata(data)
                })
                .then(move |res| {
                    match res {
                        Err(CoreError::DataError(SndError::InsufficientBalance)) => (),
                        res => panic!("Unexpected result: {:?}", res),
                    }
                    Ok::<_, SndError>(())
                })
        });
    }

    // 1. Create a client that PUTs some mdata on the network
    // 2. Create a different client that tries to delete the data. It should panic.
    #[test]
    pub fn del_unseq_mdata_permission_test() {
        let name = XorName(rand::random());
        let tag = 15001;
        let mdataref = MDataAddress::Unseq { name, tag };

        random_client(move |client| {
            let data = UnseqMutableData::new_with_data(
                name,
                tag,
                Default::default(),
                Default::default(),
                client.public_key(),
            );

            client.put_unseq_mutable_data(data).then(|res| res)
        });

        random_client(move |client| {
            client.delete_mdata(mdataref).then(|res| {
                match res {
                    Err(CoreError::DataError(SndError::AccessDenied)) => (),
                    res => panic!("Unexpected result: {:?}", res),
                }
                Ok::<_, SndError>(())
            })
        });
    }

    // 1. Create a mutable data with some permissions and store it on the network.
    // 2. Modify the permissions of a user in the permission set.
    // 3. Fetch the list of permissions and verify the edit.
    // 4. Delete a user's permissions from the permission set and verify the deletion.
    #[test]
    pub fn mdata_permissions_test() {
        random_client(|client| {
            let client1 = client.clone();
            let client2 = client.clone();
            let client3 = client.clone();
            let client4 = client.clone();
            let client5 = client.clone();
            let client6 = client.clone();
            // The `random_client()` initializes the client with 10 coins.
            let start_bal = unwrap!(Coins::from_str("10"));
            let name = XorName(rand::random());
            let tag = 15001;
            let mut permissions: BTreeMap<_, _> = Default::default();
            let permission_set = MDataPermissionSet::new()
                .allow(MDataAction::Read)
                .allow(MDataAction::Insert)
                .allow(MDataAction::ManagePermissions);
            let user = client.public_key();
            let user2 = user;
            let random_user = gen_bls_keypair().public_key();
            let random_pk = gen_bls_keypair().public_key();

            let _ = permissions.insert(user, permission_set.clone());
            let _ = permissions.insert(random_user, permission_set);

            let data = SeqMutableData::new_with_data(
                name,
                tag,
                Default::default(),
                permissions.clone(),
                client.public_key(),
            );
            let test_data = SeqMutableData::new_with_data(
                XorName(rand::random()),
                15000,
                Default::default(),
                permissions,
                random_pk,
            );

            client
                .put_seq_mutable_data(data)
                .then(move |res| {
                    assert!(res.is_ok());
                    Ok(())
                })
                .and_then(move |_| {
                    client1
                        .put_seq_mutable_data(test_data.clone())
                        .then(|res| match res {
                            Ok(_) => panic!("Unexpected Success: Validating owners should fail"),
                            Err(CoreError::DataError(SndError::InvalidOwners)) => Ok(()),
                            Err(e) => panic!("Unexpected: {:?}", e),
                        })
                })
                // Check if coins are refunded
                .and_then(move |_| client2.get_balance(None))
                .and_then(move |balance| {
                    let expected_bal = calculate_new_balance(start_bal, Some(2), None);
                    assert_eq!(balance, expected_bal);
                    Ok(())
                })
                .and_then(move |_| {
                    let new_perm_set = MDataPermissionSet::new()
                        .allow(MDataAction::ManagePermissions)
                        .allow(MDataAction::Read);
                    client3
                        .set_mdata_user_permissions(
                            MDataAddress::Seq { name, tag },
                            user,
                            new_perm_set,
                            1,
                        )
                        .then(move |res| {
                            assert!(res.is_ok());
                            Ok(())
                        })
                })
                .and_then(move |_| {
                    println!("Modified user permissions");

                    client4
                        .list_mdata_user_permissions(MDataAddress::Seq { name, tag }, user2)
                        .and_then(|permissions| {
                            assert!(!permissions.is_allowed(MDataAction::Insert));
                            assert!(permissions.is_allowed(MDataAction::Read));
                            assert!(permissions.is_allowed(MDataAction::ManagePermissions));
                            println!("Verified new permissions");

                            Ok(())
                        })
                })
                .and_then(move |_| {
                    client5
                        .del_mdata_user_permissions(MDataAddress::Seq { name, tag }, random_user, 2)
                        .then(move |res| {
                            assert!(res.is_ok());
                            Ok(())
                        })
                })
                .and_then(move |_| {
                    println!("Deleted permissions");
                    client6
                        .list_mdata_permissions(MDataAddress::Seq { name, tag })
                        .and_then(|permissions| {
                            assert_eq!(permissions.len(), 1);
                            println!("Permission set verified");
                            Ok(())
                        })
                })
        })
    }

    // 1. Create a mutable data and store it on the network
    // 2. Create some entry actions and mutate the data on the network.
    // 3. List the entries and verify that the mutation was applied.
    // 4. Fetch a value for a particular key and verify
    #[test]
    pub fn mdata_mutations_test() {
        random_client(|client| {
            let client2 = client.clone();
            let client3 = client.clone();
            let client4 = client.clone();
            let client5 = client.clone();
            let client6 = client.clone();
            let name = XorName(rand::random());
            let tag = 15001;
            let mut permissions: BTreeMap<_, _> = Default::default();
            let permission_set = MDataPermissionSet::new()
                .allow(MDataAction::Read)
                .allow(MDataAction::Insert)
                .allow(MDataAction::Update)
                .allow(MDataAction::Delete);
            let user = client.public_key();
            let _ = permissions.insert(user, permission_set);
            let mut entries: MDataSeqEntries = Default::default();
            let _ = entries.insert(
                b"key1".to_vec(),
                MDataSeqValue {
                    data: b"value".to_vec(),
                    version: 0,
                },
            );
            let _ = entries.insert(
                b"key2".to_vec(),
                MDataSeqValue {
                    data: b"value".to_vec(),
                    version: 0,
                },
            );
            let data = SeqMutableData::new_with_data(
                name,
                tag,
                entries.clone(),
                permissions,
                client.public_key(),
            );
            client
                .put_seq_mutable_data(data)
                .and_then(move |_| {
                    println!("Put seq. MData successfully");

                    client2
                        .list_seq_mdata_entries(name, tag)
                        .map(move |fetched_entries| {
                            assert_eq!(fetched_entries, entries);
                        })
                })
                .and_then(move |_| {
                    let entry_actions: MDataSeqEntryActions = MDataSeqEntryActions::new()
                        .update(b"key1".to_vec(), b"newValue".to_vec(), 1)
                        .del(b"key2".to_vec(), 1)
                        .ins(b"key3".to_vec(), b"value".to_vec(), 0);

                    client3
                        .mutate_seq_mdata_entries(name, tag, entry_actions)
                        .then(move |res| {
                            assert!(res.is_ok());
                            Ok(())
                        })
                })
                .and_then(move |_| {
                    client4
                        .list_seq_mdata_entries(name, tag)
                        .map(move |fetched_entries| {
                            let mut expected_entries: BTreeMap<_, _> = Default::default();
                            let _ = expected_entries.insert(
                                b"key1".to_vec(),
                                MDataSeqValue {
                                    data: b"newValue".to_vec(),
                                    version: 1,
                                },
                            );
                            let _ = expected_entries.insert(
                                b"key3".to_vec(),
                                MDataSeqValue {
                                    data: b"value".to_vec(),
                                    version: 0,
                                },
                            );
                            assert_eq!(fetched_entries, expected_entries);
                        })
                })
                .and_then(move |_| {
                    client5
                        .get_seq_mdata_value(name, tag, b"key3".to_vec())
                        .and_then(|fetched_value| {
                            assert_eq!(
                                fetched_value,
                                MDataSeqValue {
                                    data: b"value".to_vec(),
                                    version: 0
                                }
                            );
                            Ok(())
                        })
                })
                .then(move |_| {
                    client6
                        .get_seq_mdata_value(name, tag, b"wrongKey".to_vec())
                        .then(|res| {
                            match res {
                                Ok(_) => panic!("Unexpected: Entry should not exist"),
                                Err(CoreError::DataError(SndError::NoSuchEntry)) => (),
                                Err(err) => panic!("Unexpected error: {:?}", err),
                            }
                            Ok::<_, SndError>(())
                        })
                })
        });

        random_client(|client| {
            let client2 = client.clone();
            let client3 = client.clone();
            let client4 = client.clone();
            let client5 = client.clone();
            let client6 = client.clone();
            let name = XorName(rand::random());
            let tag = 15001;
            let mut permissions: BTreeMap<_, _> = Default::default();
            let permission_set = MDataPermissionSet::new()
                .allow(MDataAction::Read)
                .allow(MDataAction::Insert)
                .allow(MDataAction::Update)
                .allow(MDataAction::Delete);
            let user = client.public_key();
            let _ = permissions.insert(user, permission_set);
            let mut entries: BTreeMap<Vec<u8>, Vec<u8>> = Default::default();
            let _ = entries.insert(b"key1".to_vec(), b"value".to_vec());
            let _ = entries.insert(b"key2".to_vec(), b"value".to_vec());
            let data = UnseqMutableData::new_with_data(
                name,
                tag,
                entries.clone(),
                permissions,
                client.public_key(),
            );
            client
                .put_unseq_mutable_data(data)
                .and_then(move |_| {
                    println!("Put unseq. MData successfully");

                    client2
                        .list_unseq_mdata_entries(name, tag)
                        .map(move |fetched_entries| {
                            assert_eq!(fetched_entries, entries);
                        })
                })
                .and_then(move |_| {
                    let entry_actions: MDataUnseqEntryActions = MDataUnseqEntryActions::new()
                        .update(b"key1".to_vec(), b"newValue".to_vec())
                        .del(b"key2".to_vec())
                        .ins(b"key3".to_vec(), b"value".to_vec());

                    client3
                        .mutate_unseq_mdata_entries(name, tag, entry_actions)
                        .then(move |res| {
                            assert!(res.is_ok());
                            Ok(())
                        })
                })
                .and_then(move |_| {
                    client4
                        .list_unseq_mdata_entries(name, tag)
                        .map(move |fetched_entries| {
                            let mut expected_entries: BTreeMap<_, _> = Default::default();
                            let _ = expected_entries.insert(b"key1".to_vec(), b"newValue".to_vec());
                            let _ = expected_entries.insert(b"key3".to_vec(), b"value".to_vec());
                            assert_eq!(fetched_entries, expected_entries);
                        })
                })
                .and_then(move |_| {
                    client5
                        .get_unseq_mdata_value(name, tag, b"key1".to_vec())
                        .and_then(|fetched_value| {
                            assert_eq!(fetched_value, b"newValue".to_vec());
                            Ok(())
                        })
                })
                .then(move |_| {
                    client6
                        .get_unseq_mdata_value(name, tag, b"wrongKey".to_vec())
                        .then(|res| {
                            match res {
                                Ok(_) => panic!("Unexpected: Entry should not exist"),
                                Err(CoreError::DataError(SndError::NoSuchEntry)) => (),
                                Err(err) => panic!("Unexpected error: {:?}", err),
                            }
                            Ok::<_, SndError>(())
                        })
                })
        });
    }

    #[test]
    pub fn adata_basics_test() {
        random_client(move |client| {
            let client1 = client.clone();
            let client2 = client.clone();
            let client3 = client.clone();
            let client4 = client.clone();

            let name = XorName(rand::random());
            let tag = 15000;
            let mut data = UnpubSeqAppendOnlyData::new(name, tag);
            let mut perms = BTreeMap::<PublicKey, ADataUnpubPermissionSet>::new();
            let set = ADataUnpubPermissionSet::new(true, true, true);
            let index = ADataIndex::FromStart(0);
            let _ = perms.insert(client.public_key(), set);
            let address = ADataAddress::UnpubSeq { name, tag };

            unwrap!(data.append_permissions(
                ADataUnpubPermissions {
                    permissions: perms,
                    entries_index: 0,
                    owners_index: 0,
                },
                0
            ));

            let owner = ADataOwner {
                public_key: client.public_key(),
                entries_index: 0,
                permissions_index: 1,
            };
            unwrap!(data.append_owner(owner, 0));

            client
                .put_adata(AData::UnpubSeq(data))
                .and_then(move |_| {
                    client1.get_adata(address).map(move |data| match data {
                        AData::UnpubSeq(adata) => assert_eq!(*adata.name(), name),
                        _ => panic!("Unexpected data found"),
                    })
                })
                .and_then(move |_| {
                    client2
                        .get_adata_shell(index, address)
                        .map(move |data| match data {
                            AData::UnpubSeq(adata) => {
                                assert_eq!(*adata.name(), name);
                                assert_eq!(adata.tag(), tag);
                                assert_eq!(adata.permissions_index(), 1);
                                assert_eq!(adata.owners_index(), 1);
                            }
                            _ => panic!("Unexpected data found"),
                        })
                })
                .and_then(move |_| client3.delete_adata(address))
                .and_then(move |_| {
                    client4.get_adata(address).then(|res| match res {
                        Ok(_) => panic!("AData was not deleted"),
                        Err(CoreError::DataError(SndError::NoSuchData)) => Ok(()),
                        Err(e) => panic!("Unexpected error: {:?}", e),
                    })
                })
                .then(move |res| res)
        });
    }

    #[test]
    pub fn adata_permissions_test() {
        random_client(move |client| {
            let client1 = client.clone();
            let client2 = client.clone();
            let client3 = client.clone();
            let client4 = client.clone();
            let client5 = client.clone();
            let client6 = client.clone();
            let client7 = client.clone();
            let client8 = client.clone();

            let name = XorName(rand::random());
            let tag = 15000;
            let adataref = ADataAddress::UnpubSeq { name, tag };
            let mut data = UnpubSeqAppendOnlyData::new(name, tag);
            let mut perms = BTreeMap::<PublicKey, ADataUnpubPermissionSet>::new();
            let set = ADataUnpubPermissionSet::new(true, true, true);

            let _ = perms.insert(client.public_key(), set);

            let key1 = b"KEY1".to_vec();
            let key2 = b"KEY2".to_vec();
            let key3 = b"KEY3".to_vec();
            let key4 = b"KEY4".to_vec();

            let val1 = b"VALUE1".to_vec();
            let val2 = b"VALUE2".to_vec();
            let val3 = b"VALUE3".to_vec();
            let val4 = b"VALUE4".to_vec();

            let kvdata = vec![
                ADataEntry::new(key1, val1),
                ADataEntry::new(key2, val2),
                ADataEntry::new(key3, val3),
            ];

            unwrap!(data.append(kvdata, 0));
            // Test push
            unwrap!(data.append(vec![ADataEntry::new(key4, val4)], 3));

            unwrap!(data.append_permissions(
                ADataUnpubPermissions {
                    permissions: perms,
                    entries_index: 4,
                    owners_index: 0,
                },
                0
            ));

            let index_start = ADataIndex::FromStart(0);
            let index_end = ADataIndex::FromEnd(2);
            let perm_index = ADataIndex::FromStart(1);

            let sim_client = gen_bls_keypair().public_key();
            let sim_client1 = sim_client;

            let mut perms2 = BTreeMap::<PublicKey, ADataUnpubPermissionSet>::new();
            let set2 = ADataUnpubPermissionSet::new(true, true, false);

            let _ = perms2.insert(sim_client, set2);

            let perm_set = ADataUnpubPermissions {
                permissions: perms2,
                entries_index: 4,
                owners_index: 1,
            };

            let owner = ADataOwner {
                public_key: client.public_key(),
                entries_index: 4,
                permissions_index: 1,
            };

            unwrap!(data.append_owner(owner, 0));

            let mut test_data = UnpubSeqAppendOnlyData::new(XorName(rand::random()), 15000);
            let test_owner = ADataOwner {
                public_key: gen_bls_keypair().public_key(),
                entries_index: 0,
                permissions_index: 0,
            };

            unwrap!(test_data.append_owner(test_owner, 0));

            client
                .put_adata(AData::UnpubSeq(data))
                .then(move |res| {
                    assert!(res.is_ok());
                    Ok(())
                })
                .and_then(move |_| {
                    client1
                        .put_adata(AData::UnpubSeq(test_data.clone()))
                        .then(|res| match res {
                            Ok(_) => panic!("Unexpected Success: Validating owners should fail"),
                            Err(CoreError::DataError(SndError::InvalidOwners)) => Ok(()),
                            Err(e) => panic!("Unexpected: {:?}", e),
                        })
                })
                .and_then(move |_| {
                    client2
                        .get_adata_range(adataref, (index_start, index_end))
                        .map(move |data| {
                            assert_eq!(
                                unwrap!(std::str::from_utf8(&unwrap!(data.last()).key)),
                                "KEY2"
                            );
                            assert_eq!(
                                unwrap!(std::str::from_utf8(&unwrap!(data.last()).value)),
                                "VALUE2"
                            );
                        })
                })
                .and_then(move |_| {
                    client3.get_adata_indices(adataref).map(move |data| {
                        assert_eq!(data.entries_index(), 4);
                        assert_eq!(data.owners_index(), 1);
                        assert_eq!(data.permissions_index(), 1);
                    })
                })
                .and_then(move |_| {
                    client4
                        .get_adata_value(adataref, b"KEY1".to_vec())
                        .map(move |data| {
                            assert_eq!(unwrap!(std::str::from_utf8(data.as_slice())), "VALUE1");
                        })
                })
                .and_then(move |_| {
                    client5.get_adata_last_entry(adataref).map(move |data| {
                        assert_eq!(unwrap!(std::str::from_utf8(data.key.as_slice())), "KEY4");
                        assert_eq!(
                            unwrap!(std::str::from_utf8(data.value.as_slice())),
                            "VALUE4"
                        );
                    })
                })
                .and_then(move |_| {
                    client6
                        .add_unpub_adata_permissions(adataref, perm_set, 1)
                        .then(move |res| {
                            assert!(res.is_ok());
                            Ok(())
                        })
                })
                .and_then(move |_| {
                    client7
                        .get_unpub_adata_permissions_at_index(adataref, perm_index)
                        .map(move |data| {
                            let set = unwrap!(data.permissions.get(&sim_client1));
                            assert!(set.is_allowed(ADataAction::Append));
                        })
                })
                .and_then(move |_| {
                    client8
                        .get_unpub_adata_user_permissions(
                            adataref,
                            index_start,
                            client8.public_key(),
                        )
                        .map(move |set| {
                            assert!(set.is_allowed(ADataAction::Append));
                        })
                })
                .then(|res| res)
        });
    }

    #[test]
    pub fn append_seq_adata_test() {
        let name = XorName(rand::random());
        let tag = 10;
        random_client(move |client| {
            let client1 = client.clone();
            let client2 = client.clone();

            let adataref = ADataAddress::PubSeq { name, tag };
            let mut data = PubSeqAppendOnlyData::new(name, tag);

            let mut perms = BTreeMap::<ADataUser, ADataPubPermissionSet>::new();
            let set = ADataPubPermissionSet::new(true, true);

            let usr = ADataUser::Key(client.public_key());
            let _ = perms.insert(usr, set);

            unwrap!(data.append_permissions(
                ADataPubPermissions {
                    permissions: perms,
                    entries_index: 0,
                    owners_index: 0,
                },
                0
            ));

            let key1 = b"KEY1".to_vec();
            let val1 = b"VALUE1".to_vec();
            let key2 = b"KEY2".to_vec();
            let val2 = b"VALUE2".to_vec();

            let tup = vec![ADataEntry::new(key1, val1), ADataEntry::new(key2, val2)];

            let append = ADataAppendOperation {
                address: adataref,
                values: tup,
            };

            let owner = ADataOwner {
                public_key: client.public_key(),
                entries_index: 0,
                permissions_index: 1,
            };

            unwrap!(data.append_owner(owner, 0));

            client
                .put_adata(AData::PubSeq(data))
                .and_then(move |_| {
                    client1.append_seq_adata(append, 0).then(move |res| {
                        assert!(res.is_ok());
                        Ok(())
                    })
                })
                .and_then(move |_| {
                    client2.get_adata(adataref).map(move |data| match data {
                        AData::PubSeq(adata) => assert_eq!(
                            unwrap!(std::str::from_utf8(&unwrap!(adata.last_entry()).key)),
                            "KEY2"
                        ),
                        _ => panic!("UNEXPECTED DATA!"),
                    })
                })
                .then(|res| res)
        });
    }

    #[test]
    pub fn append_unseq_adata_test() {
        let name = XorName(rand::random());
        let tag = 10;
        random_client(move |client| {
            let client1 = client.clone();
            let client2 = client.clone();

            let adataref = ADataAddress::UnpubUnseq { name, tag };
            let mut data = UnpubUnseqAppendOnlyData::new(name, tag);

            let mut perms = BTreeMap::<PublicKey, ADataUnpubPermissionSet>::new();
            let set = ADataUnpubPermissionSet::new(true, true, true);

            let _ = perms.insert(client.public_key(), set);

            unwrap!(data.append_permissions(
                ADataUnpubPermissions {
                    permissions: perms,
                    entries_index: 0,
                    owners_index: 0,
                },
                0
            ));

            let key1 = b"KEY1".to_vec();
            let val1 = b"VALUE1".to_vec();
            let key2 = b"KEY2".to_vec();
            let val2 = b"VALUE2".to_vec();

            let tup = vec![ADataEntry::new(key1, val1), ADataEntry::new(key2, val2)];

            let append = ADataAppendOperation {
                address: adataref,
                values: tup,
            };

            let owner = ADataOwner {
                public_key: client.public_key(),
                entries_index: 0,
                permissions_index: 1,
            };

            unwrap!(data.append_owner(owner, 0));

            client
                .put_adata(AData::UnpubUnseq(data))
                .and_then(move |_| {
                    client1.append_unseq_adata(append).then(move |res| {
                        assert!(res.is_ok());
                        Ok(())
                    })
                })
                .and_then(move |_| {
                    client2.get_adata(adataref).map(move |data| match data {
                        AData::UnpubUnseq(adata) => assert_eq!(
                            unwrap!(std::str::from_utf8(&unwrap!(adata.last_entry()).key)),
                            "KEY2"
                        ),
                        _ => panic!("UNEXPECTED DATA!"),
                    })
                })
                .then(|res| res)
        });
    }

    #[test]
    pub fn set_and_get_owner_adata_test() {
        let name = XorName(rand::random());
        let tag = 10;
        random_client(move |client| {
            let client1 = client.clone();
            let client2 = client.clone();
            let client3 = client.clone();

            let adataref = ADataAddress::UnpubUnseq { name, tag };
            let mut data = UnpubUnseqAppendOnlyData::new(name, tag);

            let mut perms = BTreeMap::<PublicKey, ADataUnpubPermissionSet>::new();
            let set = ADataUnpubPermissionSet::new(true, true, true);

            let _ = perms.insert(client.public_key(), set);

            unwrap!(data.append_permissions(
                ADataUnpubPermissions {
                    permissions: perms,
                    entries_index: 0,
                    owners_index: 0,
                },
                0
            ));

            let key1 = b"KEY1".to_vec();
            let key2 = b"KEY2".to_vec();

            let val1 = b"VALUE1".to_vec();
            let val2 = b"VALUE2".to_vec();

            let kvdata = vec![ADataEntry::new(key1, val1), ADataEntry::new(key2, val2)];

            unwrap!(data.append(kvdata));

            let owner = ADataOwner {
                public_key: client.public_key(),
                entries_index: 2,
                permissions_index: 1,
            };

            unwrap!(data.append_owner(owner, 0));

            let owner2 = ADataOwner {
                public_key: client1.public_key(),
                entries_index: 2,
                permissions_index: 1,
            };

            let owner3 = ADataOwner {
                public_key: client2.public_key(),
                entries_index: 2,
                permissions_index: 1,
            };

            client
                .put_adata(AData::UnpubUnseq(data))
                .and_then(move |_| {
                    client1
                        .set_adata_owners(adataref, owner2, 1)
                        .then(move |res| {
                            assert!(res.is_ok());
                            Ok(())
                        })
                })
                .and_then(move |_| {
                    client2
                        .set_adata_owners(adataref, owner3, 2)
                        .then(move |res| {
                            assert!(res.is_ok());
                            Ok(())
                        })
                })
                .and_then(move |_| {
                    client3.get_adata(adataref).map(move |data| match data {
                        AData::UnpubUnseq(adata) => assert_eq!(adata.owners_index(), 3),
                        _ => panic!("UNEXPECTED DATA!"),
                    })
                })
                .then(|res| res)
        });
    }

    // 1. Create a random BLS key and create a wallet for it with some test safecoin.
    // 2. Without a client object, try to get the balance, create new wallets and transfer safecoin.
    #[test]
    pub fn wallet_transactions_without_client() {
        let client_id = gen_client_id();

        unwrap!(test_create_balance(
            &client_id,
            unwrap!(Coins::from_str("50"))
        ));

        let balance = unwrap!(wallet_get_balance(&client_id));
        let ten_coins = unwrap!(Coins::from_str("10"));
        assert_eq!(balance, unwrap!(Coins::from_str("50")));

        let new_client_id = gen_client_id();
        let new_client_pk = new_client_id.public_id().public_key();
        let new_wallet: XorName = *new_client_id.public_id().name();
        let txn = unwrap!(wallet_create_balance(
            &client_id,
            *new_client_pk,
            ten_coins,
            None
        ));
        assert_eq!(txn.amount, ten_coins);
        let txn2 = unwrap!(wallet_transfer_coins(
            &client_id, new_wallet, ten_coins, None
        ));
        assert_eq!(txn2.amount, ten_coins);

        let client_balance = unwrap!(wallet_get_balance(&client_id));
        let expected = unwrap!(Coins::from_str("30"));
        let expected = unwrap!(expected.checked_sub(COST_OF_PUT));
        assert_eq!(client_balance, expected);

        let new_client_balance = unwrap!(wallet_get_balance(&new_client_id));
        assert_eq!(new_client_balance, unwrap!(Coins::from_str("20")));
    }

    // 1. Store different variants of unpublished data on the network.
    // 2. Get the balance of the client.
    // 3. Delete data from the network.
    // 4. Verify that the balance has not changed since deletions are free.
    #[test]
    pub fn deletions_should_be_free() {
        let name = XorName(rand::random());
        let tag = 10;
        random_client(move |client| {
            let c2 = client.clone();
            let c3 = client.clone();
            let c4 = client.clone();
            let c5 = client.clone();
            let c6 = client.clone();
            let c7 = client.clone();
            let c8 = client.clone();

            let idata = UnpubImmutableData::new(
                unwrap!(generate_random_vector::<u8>(10)),
                client.public_key(),
            );
            let address = *idata.name();
            client
                .put_idata(idata)
                .and_then(move |_| {
                    let mut adata = UnpubSeqAppendOnlyData::new(name, tag);
                    let owner = ADataOwner {
                        public_key: c2.public_key(),
                        entries_index: 0,
                        permissions_index: 0,
                    };
                    unwrap!(adata.append_owner(owner, 0));
                    c2.put_adata(adata.into())
                })
                .and_then(move |_| {
                    let mdata = UnseqMutableData::new(name, tag, c3.public_key());
                    c3.put_unseq_mutable_data(mdata)
                })
                .and_then(move |_| c4.get_balance(None))
                .and_then(move |balance| {
                    c5.delete_adata(ADataAddress::from_kind(ADataKind::UnpubSeq, name, tag))
                        .map(move |_| balance)
                })
                .and_then(move |balance| {
                    c6.delete_mdata(MDataAddress::from_kind(MDataKind::Unseq, name, tag))
                        .map(move |_| balance)
                })
                .and_then(move |balance| c7.del_unpub_idata(address).map(move |_| balance))
                .and_then(move |balance| {
                    c8.get_balance(None)
                        .map(move |bal| assert_eq!(bal, balance))
                })
        });
    }
}
