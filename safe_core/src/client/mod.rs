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
use crate::ipc::BootstrapConfig;
use crate::network_event::{NetworkEvent, NetworkTx};
use futures::{channel::mpsc, lock::Mutex};
use std::sync::Arc;

use log::trace;
use lru::LruCache;
use quic_p2p::Config as QuicP2pConfig;
use safe_nd::{
    AppPermissions, ClientFullId, ClientRequest, Coins, CoinsRequest, IData, IDataAddress,
    IDataRequest, LoginPacket, LoginPacketRequest, MData, MDataAddress, MDataEntries,
    MDataEntryActions, MDataPermissionSet, MDataRequest, MDataSeqEntries, MDataSeqEntryActions,
    MDataSeqValue, MDataUnseqEntryActions, MDataValue, MDataValues, Message, MessageId, PublicId,
    PublicKey, Request, RequestType, Response, SData, SDataAction, SDataAddress, SDataEntries,
    SDataEntry, SDataIndex, SDataOwner, SDataPrivPermissions, SDataPrivUserPermissions,
    SDataPubPermissions, SDataPubUserPermissions, SDataRequest, SDataUser, SDataUserPermissions,
    SeqMutableData, Transaction, UnseqMutableData, XorName,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};
use unwrap::unwrap;

/// Capacity of the immutable data cache.
pub const IMMUT_DATA_CACHE_SIZE: usize = 300;

/// Capacity of the Sequence CRDT local replica size.
pub const SEQUENCE_CRDT_REPLICA_SIZE: usize = 300;

/// Expected cost of mutation operations.
pub const COST_OF_PUT: Coins = Coins::from_nano(1);

/// Return the `crust::Config` associated with the `crust::Service` (if any).
pub fn bootstrap_config() -> Result<BootstrapConfig, CoreError> {
    Ok(Config::new().quic_p2p.hard_coded_contacts)
}

async fn send(client: &impl Client, request: Request) -> Result<Response, CoreError> {
    // `sign` should be false for GETs on published data, true otherwise.
    let sign = request.get_type() != RequestType::PublicGet;
    let request = client.compose_message(request, sign).await?;
    let inner = client.inner();
    let cm = &mut inner.lock().await.connection_manager;
    cm.send(&client.public_id().await, &request).await
}

// Sends a mutation request to a new routing.
async fn send_mutation(client: &impl Client, req: Request) -> Result<(), CoreError> {
    let response = send(client, req).await?;
    match response {
        Response::Mutation(result) => {
            trace!("mutation result: {:?}", result);
            result.map_err(CoreError::from)
        }
        _ => Err(CoreError::ReceivedUnexpectedEvent),
    }
}

async fn send_as_helper(
    client: &impl Client,
    request: Request,
    client_id: Option<&ClientFullId>,
) -> Result<Response, CoreError> {
    let (message, identity) = match client_id {
        Some(id) => (sign_request(request, id), SafeKey::client(id.clone())),
        None => {
            let msg = client.compose_message(request, true).await?;
            let client_id = client.full_id().await;
            (msg, client_id)
        }
    };

    let pub_id = identity.public_id();

    let inner = client.inner();

    let cm = &mut inner.lock().await.connection_manager;

    let _bootstrapped = cm.bootstrap(identity).await;
    cm.send(&pub_id, &message).await
}

/// Trait providing an interface for self-authentication client implementations, so they can
/// interface all requests from high-level APIs to the actual routing layer and manage all
/// interactions with it. Clients are non-blocking, with an asynchronous API using the futures
/// abstraction from the futures-rs crate.
#[async_trait]
pub trait Client: Clone + Send + Sync {
    /// Associated message type.
    type Context;

    /// Return the client's ID.
    async fn full_id(&self) -> SafeKey;

    /// Return the client's public ID.
    async fn public_id(&self) -> PublicId {
        self.full_id().await.public_id()
    }

    /// Returns the client's public key.
    async fn public_key(&self) -> PublicKey {
        self.full_id().await.public_key()
    }

    /// Returns the client's owner key.
    async fn owner_key(&self) -> PublicKey;

    /// Return a `crust::Config` if the `Client` was initialized with one.
    async fn config(&self) -> Option<BootstrapConfig>;

    /// Return an associated `ClientInner` type which is expected to contain fields associated with
    /// the implementing type.
    fn inner(&self) -> Arc<Mutex<Inner>>
    where
        Self: Sized;

    /// Return the public encryption key.
    async fn public_encryption_key(&self) -> threshold_crypto::PublicKey;

    /// Return the secret encryption key.
    async fn secret_encryption_key(&self) -> shared_box::SecretKey;

    /// Return the public and secret encryption keys.
    async fn encryption_keypair(&self) -> (threshold_crypto::PublicKey, shared_box::SecretKey) {
        let enc_key = self.public_encryption_key().await;
        let sec_key = self.secret_encryption_key().await;
        (enc_key, sec_key)
    }

    /// Return the symmetric encryption key.
    async fn secret_symmetric_key(&self) -> shared_secretbox::Key;

    /// Create a `Message` from the given request.
    /// This function adds the requester signature and message ID.
    async fn compose_message(&self, request: Request, sign: bool) -> Result<Message, CoreError> {
        let message_id = MessageId::new();
        let signature = if sign {
            let serialised_req =
                bincode::serialize(&(&request, message_id)).map_err(CoreError::from)?;
            Some(self.full_id().await.sign(&serialised_req))
        } else {
            None
        };

        Ok(Message::Request {
            request,
            message_id,
            signature,
        })
    }

    /// Set request timeout.
    async fn set_timeout(&self, duration: Duration) {
        let inner = self.inner();
        inner.lock().await.timeout = duration;
    }

    /// Restart the client and reconnect to the network.
    async fn restart_network(&self) -> Result<(), CoreError> {
        trace!("Restarting the network connection");

        let inner = self.inner();
        let mut inner = inner.lock().await;

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
        send_mutation(self, Request::MData(MDataRequest::Put(MData::Unseq(data)))).await
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
            Request::Coins(CoinsRequest::Transfer {
                destination,
                amount,
                transaction_id: transaction_id.unwrap_or_else(rand::random),
            }),
            client_id,
        )
        .await
        {
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
            Request::Coins(CoinsRequest::CreateBalance {
                new_balance_owner,
                amount,
                transaction_id: transaction_id.unwrap_or_else(rand::random),
            }),
            client_id,
        )
        .await
        {
            Ok(res) => match res {
                Response::Transaction(result) => match result {
                    Ok(transaction) => Ok(transaction),
                    Err(error) => Err(CoreError::from(error)),
                },
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            },

            Err(error) => Err(error),
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
            Request::LoginPacket(LoginPacketRequest::CreateFor {
                new_owner,
                amount,
                transaction_id,
                new_login_packet,
            }),
            client_id,
        )
        .await
        {
            Ok(res) => match res {
                Response::Transaction(result) => match result {
                    Ok(transaction) => Ok(transaction),
                    Err(error) => Err(CoreError::from(error)),
                },
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            },

            Err(error) => Err(error),
        }
    }

    /// Get the current coin balance.
    async fn get_balance(&self, client_id: Option<&ClientFullId>) -> Result<Coins, CoreError>
    where
        Self: Sized,
    {
        trace!("Get balance for {:?}", client_id);

        match send_as_helper(self, Request::Coins(CoinsRequest::GetBalance), client_id).await {
            Ok(res) => match res {
                Response::GetBalance(result) => match result {
                    Ok(coins) => Ok(coins),
                    Err(error) => Err(CoreError::from(error)),
                },
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            },
            Err(error) => Err(error),
        }
    }

    /// Put immutable data to the network.
    async fn put_idata<D: Into<IData> + Send>(&self, data: D) -> Result<(), CoreError>
    where
        Self: Sized + Send,
    {
        let idata: IData = data.into();
        trace!("Put IData at {:?}", idata.name());
        send_mutation(self, Request::IData(IDataRequest::Put(idata))).await
    }

    /// Get immutable data from the network. If the data exists locally in the cache then it will be
    /// immediately returned without making an actual network request.
    async fn get_idata(&self, address: IDataAddress) -> Result<IData, CoreError>
    where
        Self: Sized,
    {
        trace!("Fetch Immutable Data");

        let inner = self.inner();
        if let Some(data) = inner.lock().await.idata_cache.get_mut(&address) {
            trace!("ImmutableData found in cache.");
            return Ok(data.clone());
        }

        let inner = Arc::downgrade(&self.inner());
        let res = send(self, Request::IData(IDataRequest::Get(address))).await?;
        let data = match res {
            Response::GetIData(res) => res.map_err(CoreError::from),
            _ => return Err(CoreError::ReceivedUnexpectedEvent),
        }?;

        if let Some(inner) = inner.upgrade() {
            // Put to cache
            let _ = inner
                .lock()
                .await
                .idata_cache
                .put(*data.address(), data.clone());
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
            .await
            .idata_cache
            .pop(&IDataAddress::Unpub(name))
            .is_some()
        {
            trace!("Deleted UnpubImmutableData from cache.");
        }

        // let inner = self.inner().clone();
        let inner = self.inner().clone();

        let _ = Arc::downgrade(&inner);
        trace!("Delete Unpublished IData at {:?}", name);
        send_mutation(
            self,
            Request::IData(IDataRequest::DeleteUnpub(IDataAddress::Unpub(name))),
        )
        .await
    }

    /// Put sequenced mutable data to the network
    async fn put_seq_mutable_data(&self, data: SeqMutableData) -> Result<(), CoreError>
    where
        Self: Sized,
    {
        trace!("Put Sequenced MData at {:?}", data.name());
        send_mutation(self, Request::MData(MDataRequest::Put(MData::Seq(data)))).await
    }

    /// Fetch unpublished mutable data from the network
    async fn get_unseq_mdata(&self, name: XorName, tag: u64) -> Result<UnseqMutableData, CoreError>
    where
        Self: Sized,
    {
        trace!("Fetch Unsequenced Mutable Data");

        match send(
            self,
            Request::MData(MDataRequest::Get(MDataAddress::Unseq { name, tag })),
        )
        .await?
        {
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
            Request::MData(MDataRequest::GetValue {
                address: MDataAddress::Seq { name, tag },
                key,
            }),
        )
        .await?
        {
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
            Request::MData(MDataRequest::GetValue {
                address: MDataAddress::Unseq { name, tag },
                key,
            }),
        )
        .await?
        {
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

        match send(
            self,
            Request::MData(MDataRequest::Get(MDataAddress::Seq { name, tag })),
        )
        .await?
        {
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
            Request::MData(MDataRequest::MutateEntries {
                address: MDataAddress::Seq { name, tag },
                actions: MDataEntryActions::Seq(actions),
            }),
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
            Request::MData(MDataRequest::MutateEntries {
                address: MDataAddress::Unseq { name, tag },
                actions: MDataEntryActions::Unseq(actions),
            }),
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
            Request::MData(MDataRequest::GetShell(MDataAddress::Seq { name, tag })),
        )
        .await?
        {
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
            Request::MData(MDataRequest::GetShell(MDataAddress::Unseq { name, tag })),
        )
        .await?
        {
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

        match send(self, Request::MData(MDataRequest::GetVersion(address))).await? {
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
            Request::MData(MDataRequest::ListEntries(MDataAddress::Unseq { name, tag })),
        )
        .await?
        {
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
            Request::MData(MDataRequest::ListEntries(MDataAddress::Seq { name, tag })),
        )
        .await?
        {
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

        match send(self, Request::MData(MDataRequest::ListKeys(address))).await? {
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
            Request::MData(MDataRequest::ListValues(MDataAddress::Seq { name, tag })),
        )
        .await?
        {
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

        match send(
            self,
            Request::MData(MDataRequest::ListUserPermissions { address, user }),
        )
        .await?
        {
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
            Request::MData(MDataRequest::ListValues(MDataAddress::Unseq { name, tag })),
        )
        .await?
        {
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

    // ======= Sequence Data =======
    //
    /// Store Private Sequence Data into the Network
    async fn store_priv_sdata(
        &self,
        name: XorName,
        tag: u64,
        owner: PublicKey,
        permissions: BTreeMap<PublicKey, SDataPrivUserPermissions>,
    ) -> Result<SDataAddress, CoreError> {
        trace!("Store Private Sequence Data {:?}", name);
        let mut data = SData::new_priv(self.public_key().await, name, tag);
        let address = *data.address();
        let _ = data.set_priv_permissions(permissions)?;
        let _ = data.set_owner(owner);
        send_mutation(self, Request::SData(SDataRequest::Store(data.clone()))).await?;
        // Store in local Sequence CRDT replica
        let _ = self
            .inner()
            .lock()
            .await
            .sdata_cache
            .put(*data.address(), data);

        Ok(address)
    }

    /// Store Public Sequence Data into the Network
    async fn store_pub_sdata(
        &self,
        name: XorName,
        tag: u64,
        owner: PublicKey,
        permissions: BTreeMap<SDataUser, SDataPubUserPermissions>,
    ) -> Result<SDataAddress, CoreError> {
        trace!("Store Public Sequence Data {:?}", name);
        let mut data = SData::new_pub(self.public_key().await, name, tag);
        let address = *data.address();
        let _ = data.set_pub_permissions(permissions)?;
        let _ = data.set_owner(owner);
        send_mutation(self, Request::SData(SDataRequest::Store(data.clone()))).await?;
        // Store in local Sequence CRDT replica
        let _ = self
            .inner()
            .lock()
            .await
            .sdata_cache
            .put(*data.address(), data);

        Ok(address)
    }

    /// Get Sequence Data from the Network
    async fn get_sdata(&self, address: SDataAddress) -> Result<SData, CoreError> {
        trace!("Get Sequence Data at {:?}", address.name());
        // First try to fetch it from local CRDT replica
        // TODO: implement some logic to refresh data from the network if local replica
        // is too old, to mitigate the risk of successfully apply mutations locally but which
        // can fail on other replicas, e.g. due to being out of sync with permissions/owner
        if let Some(sdata) = self.inner().lock().await.sdata_cache.get(&address) {
            trace!("Sequence found in local CRDT replica");
            return Ok(sdata.clone());
        }

        trace!("Sequence not found in local CRDT replica");
        // Let's fetch it from the network then
        let sdata = match send(self, Request::SData(SDataRequest::Get(address))).await? {
            Response::GetSData(res) => res.map_err(CoreError::from),
            _ => Err(CoreError::ReceivedUnexpectedEvent),
        }?;

        trace!("Store Sequence in local CRDT replica");
        // Store in local Sequence CRDT replica
        let _ = self
            .inner()
            .lock()
            .await
            .sdata_cache
            .put(*sdata.address(), sdata.clone());

        Ok(sdata)
    }

    /// Get the last data entry from a Sequence Data.
    async fn get_sdata_last_entry(
        &self,
        address: SDataAddress,
    ) -> Result<(u64, SDataEntry), CoreError> {
        trace!(
            "Get latest entry from Sequence Data at {:?}",
            address.name()
        );

        let sdata = self.get_sdata(address).await?;
        match sdata.last_entry() {
            Some(entry) => Ok((sdata.entries_index() - 1, entry.to_vec())),
            None => Err(CoreError::from(safe_nd::Error::NoSuchEntry)),
        }
    }

    /// Get a set of Entries for the requested range from a Sequence.
    async fn get_sdata_range(
        &self,
        address: SDataAddress,
        range: (SDataIndex, SDataIndex),
    ) -> Result<SDataEntries, CoreError> {
        trace!(
            "Get range of entries from Sequence Data at {:?}",
            address.name()
        );

        let sdata = self.get_sdata(address).await?;
        sdata
            .in_range(range.0, range.1)
            .ok_or_else(|| CoreError::from(safe_nd::Error::NoSuchEntry))
    }

    /// Append to Sequence Data
    async fn sdata_append(
        &self,
        address: SDataAddress,
        entry: SDataEntry,
    ) -> Result<(), CoreError> {
        // First we fetch it so we can get the causality info,
        // either from local CRDT replica or from the network if not found
        let mut sdata = self.get_sdata(address).await?;

        // We do a permissions check just to make sure it won't fail when the operation
        // is broadcasted to the network, assuming our replica is in sync and up to date
        // with the permissions and ownership information compared with the replicas on the network.
        sdata.check_permission(SDataAction::Append, self.public_id().await.public_key())?;

        // We can now append the entry to the Sequence
        let append_op = sdata.append(entry);

        // Update the local Sequence CRDT replica
        let _ = self
            .inner()
            .lock()
            .await
            .sdata_cache
            .put(*sdata.address(), sdata.clone());

        // Finally we can send the mutation to the network's replicas
        send_mutation(self, Request::SData(SDataRequest::Mutate(append_op))).await
    }

    /// Get the set of Permissions of a Public Sequence.
    async fn get_sdata_pub_permissions(
        &self,
        address: SDataAddress,
    ) -> Result<SDataPubPermissions, CoreError> {
        trace!(
            "Get permissions from Public Sequence Data at {:?}",
            address.name()
        );

        // TODO: perhaps we want to grab it directly from the network and update local replica
        let sdata = self.get_sdata(address).await?;
        let perms = sdata
            .pub_permissions(sdata.permissions_index() - 1)
            .map_err(CoreError::from)?;

        Ok(perms.clone())
    }

    /// Get the set of Permissions of a Private Sequence.
    async fn get_sdata_priv_permissions(
        &self,
        address: SDataAddress,
    ) -> Result<SDataPrivPermissions, CoreError> {
        trace!(
            "Get permissions from Private Sequence Data at {:?}",
            address.name()
        );

        // TODO: perhaps we want to grab it directly from the network and update local replica
        let sdata = self.get_sdata(address).await?;
        let perms = sdata
            .priv_permissions(sdata.permissions_index() - 1)
            .map_err(CoreError::from)?;

        Ok(perms.clone())
    }

    /// Get the set of Permissions for a specific user in a Sequence.
    async fn get_sdata_user_permissions(
        &self,
        address: SDataAddress,
        user: SDataUser,
    ) -> Result<SDataUserPermissions, CoreError> {
        trace!(
            "Get permissions for user {:?} from Sequence Data at {:?}",
            user,
            address.name()
        );

        // TODO: perhaps we want to grab it directly from the network and update local replica
        let sdata = self.get_sdata(address).await?;
        let perms = sdata
            .user_permissions(user, sdata.permissions_index() - 1)
            .map_err(CoreError::from)?;

        Ok(perms)
    }

    /// Set permissions to Public Sequence Data
    async fn sdata_set_pub_permissions(
        &self,
        address: SDataAddress,
        permissions: BTreeMap<SDataUser, SDataPubUserPermissions>,
    ) -> Result<(), CoreError> {
        // First we fetch it either from local CRDT replica or from the network if not found
        let mut sdata = self.get_sdata(address).await?;

        // We do a permissions check just to make sure it won't fail when the operation
        // is broadcasted to the network, assuming our replica is in sync and up to date
        // with the permissions information compared with the replicas on the network.
        sdata.check_permission(
            SDataAction::ManagePermissions,
            self.public_id().await.public_key(),
        )?;

        // We can now set the new permissions to the Sequence
        let perms_op = sdata.set_pub_permissions(permissions)?;

        // Update the local Sequence CRDT replica
        let _ = self
            .inner()
            .lock()
            .await
            .sdata_cache
            .put(*sdata.address(), sdata.clone());

        // Finally we can send the mutation to the network's replicas
        send_mutation(
            self,
            Request::SData(SDataRequest::MutatePubPermissions(perms_op)),
        )
        .await
    }

    /// Set permissions to Private Sequence Data
    async fn sdata_set_priv_permissions(
        &self,
        address: SDataAddress,
        permissions: BTreeMap<PublicKey, SDataPrivUserPermissions>,
    ) -> Result<(), CoreError> {
        // First we fetch it either from local CRDT replica or from the network if not found
        let mut sdata = self.get_sdata(address).await?;

        // We do a permissions check just to make sure it won't fail when the operation
        // is broadcasted to the network, assuming our replica is in sync and up to date
        // with the permissions information compared with the replicas on the network.
        // TODO: if it fails, try to sync-up perms with rmeote replicas and try once more
        sdata.check_permission(
            SDataAction::ManagePermissions,
            self.public_id().await.public_key(),
        )?;

        // We can now set the new permissions to the Sequence
        let perms_op = sdata.set_priv_permissions(permissions)?;

        // Update the local Sequence CRDT replica
        let _ = self
            .inner()
            .lock()
            .await
            .sdata_cache
            .put(*sdata.address(), sdata.clone());

        // Finally we can send the mutation to the network's replicas
        send_mutation(
            self,
            Request::SData(SDataRequest::MutatePrivPermissions(perms_op)),
        )
        .await
    }

    /// Get the owner of a Sequence.
    async fn get_sdata_owner(&self, address: SDataAddress) -> Result<SDataOwner, CoreError> {
        trace!("Get owner of the Sequence Data at {:?}", address.name());

        // TODO: perhaps we want to grab it directly from the network and update local replica
        let sdata = self.get_sdata(address).await?;
        let owner = sdata.owner(sdata.owners_index() - 1).ok_or_else(|| {
            CoreError::from("Unexpectedly failed to obtain current owner of Sequence")
        })?;

        Ok(*owner)
    }

    /// Set the new owner of a Sequence Data
    async fn sdata_set_owner(
        &self,
        address: SDataAddress,
        owner: PublicKey,
    ) -> Result<(), CoreError> {
        // First we fetch it either from local CRDT replica or from the network if not found
        let mut sdata = self.get_sdata(address).await?;

        // We do a permissions check just to make sure it won't fail when the operation
        // is broadcasted to the network, assuming our replica is in sync and up to date
        // with the ownership information compared with the replicas on the network.
        sdata.check_permission(
            SDataAction::ManagePermissions,
            self.public_id().await.public_key(),
        )?;

        // We can now set the new owner to the Sequence
        let owner_op = sdata.set_owner(owner);

        // Update the local Sequence CRDT replica
        let _ = self
            .inner()
            .lock()
            .await
            .sdata_cache
            .put(*sdata.address(), sdata.clone());

        // Finally we can send the mutation to the network's replicas
        send_mutation(self, Request::SData(SDataRequest::MutateOwner(owner_op))).await
    }

    /// Delete Private Sequence Data from the Network
    async fn delete_sdata(&self, address: SDataAddress) -> Result<(), CoreError> {
        trace!("Delete Private Sequence Data {:?}", address.name());

        send_mutation(self, Request::SData(SDataRequest::Delete(address))).await?;

        // Delete it from local Sequence CRDT replica
        let _ = self.inner().lock().await.sdata_cache.pop(&address);

        Ok(())
    }

    // ========== END of Sequence Data functions =========

    /// Return a list of permissions in `MutableData` stored on the network.
    async fn list_mdata_permissions(
        &self,
        address: MDataAddress,
    ) -> Result<BTreeMap<PublicKey, MDataPermissionSet>, CoreError>
    where
        Self: Sized,
    {
        trace!("List MDataPermissions for {:?}", address);

        match send(self, Request::MData(MDataRequest::ListPermissions(address))).await? {
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
            Request::MData(MDataRequest::SetUserPermissions {
                address,
                user,
                permissions,
                version,
            }),
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
            Request::MData(MDataRequest::DelUserPermissions {
                address,
                user,
                version,
            }),
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
    async fn set_network_limits(&self, max_ops_count: Option<u64>) {
        let inner = self.inner();
        inner
            .lock()
            .await
            .connection_manager
            .set_network_limits(max_ops_count);
    }

    #[cfg(any(
        all(test, feature = "mock-network"),
        all(feature = "testing", feature = "mock-network")
    ))]
    #[doc(hidden)]
    async fn simulate_network_disconnect(&self) {
        let inner = self.inner();
        inner
            .lock()
            .await
            .connection_manager
            .simulate_disconnect()
            .await;
    }

    #[cfg(any(
        all(test, feature = "mock-network"),
        all(feature = "testing", feature = "mock-network")
    ))]
    #[doc(hidden)]
    async fn set_simulate_timeout(&self, enabled: bool) {
        let inner = self.inner();
        inner
            .lock()
            .await
            .connection_manager
            .set_simulate_timeout(enabled);
    }

    /// Set the coin balance to a specific value for testing
    #[cfg(any(test, feature = "testing"))]
    async fn test_set_balance(
        &self,
        client_id: Option<&ClientFullId>,
        amount: Coins,
    ) -> Result<(), CoreError>
    where
        Self: Sized,
    {
        let new_balance_owner = match client_id {
            None => self.public_key().await,
            Some(client_id) => *client_id.public_id().public_key(),
        };
        trace!(
            "Set the coin balance of {:?} to {:?}",
            new_balance_owner,
            amount,
        );

        match send_as_helper(
            self,
            Request::Coins(CoinsRequest::CreateBalance {
                new_balance_owner,
                amount,
                transaction_id: rand::random(),
            }),
            client_id,
        )
        .await
        {
            Ok(res) => match res {
                Response::Transaction(result) => match result {
                    Ok(_) => Ok(()),
                    Err(error) => Err(CoreError::from(error)),
                },
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            },

            Err(error) => Err(error),
        }
    }
}

/// Creates a throw-away client to execute requests sequentially.
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
            Request::Coins(CoinsRequest::CreateBalance {
                new_balance_owner,
                amount,
                transaction_id: rand::random(),
            }),
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
            Request::Coins(CoinsRequest::GetBalance),
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
            Request::Coins(CoinsRequest::CreateBalance {
                new_balance_owner,
                amount,
                transaction_id,
            }),
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
            Request::Coins(CoinsRequest::Transfer {
                destination,
                amount,
                transaction_id,
            }),
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

        match send(self, Request::Client(ClientRequest::ListAuthKeysAndVersion)).await? {
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
            Request::Client(ClientRequest::InsAuthKey {
                key,
                permissions,
                version,
            }),
        )
        .await
    }

    /// Removes an authorised key.
    async fn del_auth_key(&self, key: PublicKey, version: u64) -> Result<(), CoreError>
    where
        Self: Sized,
    {
        trace!("DelAuthKey ({:?})", key);

        send_mutation(
            self,
            Request::Client(ClientRequest::DelAuthKey { key, version }),
        )
        .await
    }

    /// Delete MData from network
    async fn delete_mdata(&self, address: MDataAddress) -> Result<(), CoreError>
    where
        Self: Sized,
    {
        trace!("Delete entire Mutable Data at {:?}", address);

        send_mutation(self, Request::MData(MDataRequest::Delete(address))).await
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
pub struct Inner {
    connection_manager: ConnectionManager,
    idata_cache: LruCache<IDataAddress, IData>,
    /// Sequence CRDT replica
    sdata_cache: LruCache<SDataAddress, SData>,
    timeout: Duration,
    net_tx: NetworkTx,
}

impl Inner {
    /// Create a new `ClientInner` object.
    #[allow(clippy::too_many_arguments)]
    pub fn new(connection_manager: ConnectionManager, timeout: Duration, net_tx: NetworkTx) -> Inner
    where
        Self: Sized,
    {
        Self {
            connection_manager,
            idata_cache: LruCache::new(IMMUT_DATA_CACHE_SIZE),
            sdata_cache: LruCache::new(SEQUENCE_CRDT_REPLICA_SIZE),
            timeout,
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
    use crate::utils::{
        generate_random_vector,
        test_utils::{calculate_new_balance, gen_bls_keypair, gen_client_id, random_client},
    };
    use safe_nd::{
        Coins, Error as SndError, MDataAction, MDataKind, PubImmutableData,
        SDataPrivUserPermissions, UnpubImmutableData, XorName,
    };
    use std::str::FromStr;

    // Test putting and getting pub idata.
    #[tokio::test]
    async fn pub_idata_test() -> Result<(), CoreError> {
        let client = random_client()?;
        // The `random_client()` initializes the client with 10 coins.
        let start_bal = unwrap!(Coins::from_str("10"));

        let value = unwrap!(generate_random_vector::<u8>(10));
        let data = PubImmutableData::new(value.clone());
        let address = *data.address();
        let pk = gen_bls_keypair().public_key();

        let test_data = UnpubImmutableData::new(value, pk);
        let res = client
            // Get inexistent idata
            .get_idata(address)
            .await;
        match res {
            Ok(data) => panic!("Pub idata should not exist yet: {:?}", data),
            Err(CoreError::DataError(SndError::NoSuchData)) => (),
            Err(e) => panic!("Unexpected: {:?}", e),
        }
        // Put idata
        client.put_idata(data.clone()).await?;
        let res = client.put_idata(test_data.clone()).await;
        match res {
            Ok(_) => panic!("Unexpected Success: Validating owners should fail"),
            Err(CoreError::DataError(SndError::InvalidOwners)) => (),
            Err(e) => panic!("Unexpected: {:?}", e),
        }

        let balance = client.get_balance(None).await?;
        let expected_bal = calculate_new_balance(start_bal, Some(2), None);
        assert_eq!(balance, expected_bal);
        // Fetch idata
        let fetched_data = client.get_idata(address).await?;
        assert_eq!(*fetched_data.address(), address);
        Ok(())
    }

    // Test putting, getting, and deleting unpub idata.
    #[tokio::test]
    async fn unpub_idata_test() -> Result<(), CoreError> {
        crate::utils::test_utils::init_log();
        // The `random_client()` initializes the client with 10 coins.
        let start_bal = unwrap!(Coins::from_str("10"));

        let client = random_client()?;
        let client9 = client.clone();

        let value = unwrap!(generate_random_vector::<u8>(10));
        let data = UnpubImmutableData::new(value.clone(), client.public_key().await);
        let data2 = data.clone();
        let data3 = data.clone();
        let address = *data.address();
        assert_eq!(address, *data2.address());

        let pub_data = PubImmutableData::new(value);

        let res = client
            // Get inexistent idata
            .get_idata(address)
            .await;
        match res {
            Ok(_) => panic!("Unpub idata should not exist yet"),
            Err(CoreError::DataError(SndError::NoSuchData)) => (),
            Err(e) => panic!("Unexpected: {:?}", e),
        }
        // Put idata
        client.put_idata(data.clone()).await?;
        // Test putting unpub idata with the same value.
        // Should conflict because duplication does .await?;not apply to unpublished data.
        let res = client.put_idata(data2.clone()).await;
        match res {
            Err(CoreError::DataError(SndError::DataExists)) => (),
            res => panic!("Unexpected: {:?}", res),
        }
        let balance = client.get_balance(None).await?;
        let expected_bal = calculate_new_balance(start_bal, Some(2), None);
        assert_eq!(balance, expected_bal);
        // Test putting published idata with the same value. Should not conflict.
        client.put_idata(pub_data).await?;
        // Fetch idata
        let fetched_data = client.get_idata(address).await?;
        assert_eq!(*fetched_data.address(), address);
        // Delete idata
        client.del_unpub_idata(*address.name()).await?;
        // Make sure idata was deleted
        let res = client.get_idata(address).await;
        match res {
            Ok(_) => panic!("Unpub idata still exists after deletion"),
            Err(CoreError::DataError(SndError::NoSuchData)) => (),
            Err(e) => panic!("Unexpected: {:?}", e),
        }
        // Test putting unpub idata with the same value again. Should not conflict.
        client9.put_idata(data3.clone()).await?;
        Ok(())
    }

    // 1. Create unseq. mdata with some entries and perms and put it on the network
    // 2. Fetch the shell version, entries, keys, values anv verify them
    // 3. Fetch the entire. data object and verify
    #[tokio::test]
    pub async fn unseq_mdata_test() -> Result<(), CoreError> {
        let client = random_client()?;

        let name = XorName(rand::random());
        let tag = 15001;
        let mut entries: BTreeMap<Vec<u8>, Vec<u8>> = Default::default();
        let mut permissions: BTreeMap<_, _> = Default::default();
        let permission_set = MDataPermissionSet::new().allow(MDataAction::Read);
        let _ = permissions.insert(client.public_key().await, permission_set);
        let _ = entries.insert(b"key".to_vec(), b"value".to_vec());
        let entries_keys = entries.keys().cloned().collect();
        let entries_values: Vec<Vec<u8>> = entries.values().cloned().collect();

        let data = UnseqMutableData::new_with_data(
            name,
            tag,
            entries.clone(),
            permissions,
            client.public_key().await,
        );
        client.put_unseq_mutable_data(data.clone()).await?;
        println!("Put unseq. MData successfully");

        let version = client
            .get_mdata_version(MDataAddress::Unseq { name, tag })
            .await?;
        assert_eq!(version, 0);
        let fetched_entries = client.list_unseq_mdata_entries(name, tag).await?;
        assert_eq!(fetched_entries, entries);
        let keys = client
            .list_mdata_keys(MDataAddress::Unseq { name, tag })
            .await?;
        assert_eq!(keys, entries_keys);
        let values = client.list_unseq_mdata_values(name, tag).await?;
        assert_eq!(values, entries_values);
        let fetched_data = client.get_unseq_mdata(*data.name(), data.tag()).await?;
        assert_eq!(fetched_data.name(), data.name());
        assert_eq!(fetched_data.tag(), data.tag());
        Ok(())
    }

    // 1. Create an put seq. mdata on the network with some entries and permissions.
    // 2. Fetch the shell version, entries, keys, values anv verify them
    // 3. Fetch the entire. data object and verify
    #[tokio::test]
    pub async fn seq_mdata_test() -> Result<(), CoreError> {
        let client = random_client()?;

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
        let _ = permissions.insert(client.public_key().await, permission_set);
        let data = SeqMutableData::new_with_data(
            name,
            tag,
            entries.clone(),
            permissions,
            client.public_key().await,
        );

        client.put_seq_mutable_data(data.clone()).await?;
        println!("Put seq. MData successfully");

        let fetched_entries = client.list_seq_mdata_entries(name, tag).await?;
        assert_eq!(fetched_entries, entries);
        let mdata_shell = client.get_seq_mdata_shell(name, tag).await?;
        assert_eq!(*mdata_shell.name(), name);
        assert_eq!(mdata_shell.tag(), tag);
        assert_eq!(mdata_shell.entries().len(), 0);
        let keys = client
            .list_mdata_keys(MDataAddress::Seq { name, tag })
            .await?;
        assert_eq!(keys, entries_keys);
        let values = client.list_seq_mdata_values(name, tag).await?;
        assert_eq!(values, entries_values);
        let fetched_data = client.get_seq_mdata(name, tag).await?;
        assert_eq!(fetched_data.name(), data.name());
        assert_eq!(fetched_data.tag(), data.tag());
        assert_eq!(fetched_data.entries().len(), 1);
        Ok(())
    }

    // 1. Put seq. mdata on the network and then delete it
    // 2. Try getting the data object. It should panic
    #[tokio::test]
    pub async fn del_seq_mdata_test() -> Result<(), CoreError> {
        let client = random_client()?;
        let name = XorName(rand::random());
        let tag = 15001;
        let mdataref = MDataAddress::Seq { name, tag };
        let data = SeqMutableData::new_with_data(
            name,
            tag,
            Default::default(),
            Default::default(),
            client.public_key().await,
        );

        client.put_seq_mutable_data(data.clone()).await?;
        client.delete_mdata(mdataref).await?;
        let res = client.get_unseq_mdata(*data.name(), data.tag()).await;
        match res {
            Err(CoreError::DataError(SndError::NoSuchData)) => (),
            _ => panic!("Unexpected success"),
        }
        Ok(())
    }

    // 1. Put unseq. mdata on the network and then delete it
    // 2. Try getting the data object. It should panic
    #[tokio::test]
    pub async fn del_unseq_mdata_test() -> Result<(), CoreError> {
        let client = random_client()?;
        let name = XorName(rand::random());
        let tag = 15001;
        let mdataref = MDataAddress::Unseq { name, tag };
        let data = UnseqMutableData::new_with_data(
            name,
            tag,
            Default::default(),
            Default::default(),
            client.public_key().await,
        );

        client.put_unseq_mutable_data(data.clone()).await?;
        client.delete_mdata(mdataref).await?;

        let res = client.get_unseq_mdata(*data.name(), data.tag()).await;
        match res {
            Err(CoreError::DataError(SndError::NoSuchData)) => (),
            _ => panic!("Unexpected success"),
        }

        Ok(())
    }

    // 1. Create 2 accounts and create a wallet only for account A.
    // 2. Try to transfer coins from A to inexistent wallet. This request should fail.
    // 3. Try to request balance of wallet B. This request should fail.
    // 4. Now create a wallet for account B and transfer some coins to A. This should pass.
    // 5. Try to request transaction from wallet A using account B. This request should succeed
    // (because transactions are always open).
    #[tokio::test]
    async fn coin_permissions() -> Result<(), CoreError> {
        let client = random_client()?;
        let wallet_a_addr: XorName = client.public_key().await.into();
        let res = client
            .transfer_coins(None, rand::random(), unwrap!(Coins::from_str("5.0")), None)
            .await;
        match res {
            Err(CoreError::DataError(SndError::NoSuchBalance)) => (),
            res => panic!("Unexpected result: {:?}", res),
        }

        let client = random_client()?;
        let res = client.get_balance(None).await;
        // Subtract to cover the cost of inserting the login packet
        let expected_amt = unwrap!(Coins::from_str("10")
            .ok()
            .and_then(|x| x.checked_sub(COST_OF_PUT)));
        match res {
            Ok(fetched_amt) => assert_eq!(expected_amt, fetched_amt),
            res => panic!("Unexpected result: {:?}", res),
        }
        client
            .test_set_balance(None, unwrap!(Coins::from_str("50.0")))
            .await?;
        let res = client
            .transfer_coins(None, wallet_a_addr, unwrap!(Coins::from_str("10")), None)
            .await;
        match res {
            Ok(transaction) => assert_eq!(transaction.amount, unwrap!(Coins::from_str("10"))),
            res => panic!("Unexpected error: {:?}", res),
        }
        let res = client.get_balance(None).await;
        let expected_amt = unwrap!(Coins::from_str("40"));
        match res {
            Ok(fetched_amt) => assert_eq!(expected_amt, fetched_amt),
            res => panic!("Unexpected result: {:?}", res),
        }
        Ok(())
    }

    // 1. Create a client with a wallet. Create an anonymous wallet preloading it from the client's wallet.
    // 2. Transfer some safecoin from the anonymous wallet to the client.
    // 3. Fetch the balances of both the wallets and verify them.
    // 5. Try to create a balance using an inexistent wallet. This should fail.
    #[tokio::test]
    async fn anonymous_wallet() -> Result<(), CoreError> {
        let client = random_client()?;
        let wallet1: XorName = client.owner_key().await.into();
        let init_bal = unwrap!(Coins::from_str("500.0"));

        let client_id = gen_client_id();
        let bls_pk = *client_id.public_id().public_key();

        client.test_set_balance(None, init_bal).await?;
        let transaction = client
            .create_balance(None, bls_pk, unwrap!(Coins::from_str("100.0")), None)
            .await?;
        assert_eq!(transaction.amount, unwrap!(Coins::from_str("100")));
        let transaction = client
            .transfer_coins(
                Some(&client_id.clone()),
                wallet1,
                unwrap!(Coins::from_str("5.0")),
                None,
            )
            .await?;
        assert_eq!(transaction.amount, unwrap!(Coins::from_str("5.0")));
        let balance = client.get_balance(Some(&client_id)).await?;
        assert_eq!(balance, unwrap!(Coins::from_str("95.0")));
        let balance = client.get_balance(None).await?;
        let expected =
            calculate_new_balance(init_bal, Some(1), Some(unwrap!(Coins::from_str("95"))));
        assert_eq!(balance, expected);
        let random_pk = gen_bls_keypair().public_key();
        let random_source = gen_client_id();

        let res = client
            .create_balance(
                Some(&random_source),
                random_pk,
                unwrap!(Coins::from_str("100.0")),
                None,
            )
            .await;
        match res {
            Err(CoreError::DataError(SndError::NoSuchBalance)) => {}
            res => panic!("Unexpected result: {:?}", res),
        }
        Ok(())
    }

    // 1. Create a client A with a wallet and allocate some test safecoin to it.
    // 2. Get the balance and verify it.
    // 3. Create another client B with a wallet holding some safecoin.
    // 4. Transfer some coins from client B to client A and verify the new balance.
    // 5. Fetch the transaction using the transaction ID and verify the amount.
    // 6. Try to do a coin transfer without enough funds, it should return `InsufficientBalance`
    // 7. Try to do a coin transfer with the amount set to 0, it should return `InvalidOperation`
    // 8. Set the client's balance to zero and try to put data. It should fail.
    #[tokio::test]
    async fn coin_balance_transfer() -> Result<(), CoreError> {
        let client = random_client()?;
        // let wallet1: XorName =
        let owner_key = client.owner_key().await;
        let wallet1: XorName = owner_key.into();

        client
            .test_set_balance(None, unwrap!(Coins::from_str("100.0")))
            .await?;
        let balance = client.get_balance(None).await?;
        assert_eq!(balance, unwrap!(Coins::from_str("100.0")));

        let client = random_client()?;
        let init_bal = unwrap!(Coins::from_str("10"));
        let orig_balance = client.get_balance(None).await?;
        let _ = client
            .transfer_coins(None, wallet1, unwrap!(Coins::from_str("5.0")), None)
            .await?;
        let new_balance = client.get_balance(None).await?;
        assert_eq!(
            new_balance,
            unwrap!(orig_balance.checked_sub(unwrap!(Coins::from_str("5.0")))),
        );
        let res = client
            .transfer_coins(None, wallet1, unwrap!(Coins::from_str("5000")), None)
            .await;
        match res {
            Err(CoreError::DataError(SndError::InsufficientBalance)) => (),
            res => panic!("Unexpected result: {:?}", res),
        };
        // Check if coins are refunded
        let balance = client.get_balance(None).await?;
        let expected =
            calculate_new_balance(init_bal, Some(1), Some(unwrap!(Coins::from_str("5"))));
        assert_eq!(balance, expected);
        let res = client
            .transfer_coins(None, wallet1, unwrap!(Coins::from_str("0")), None)
            .await;
        match res {
            Err(CoreError::DataError(SndError::InvalidOperation)) => (),
            res => panic!("Unexpected result: {:?}", res),
        }
        client
            .test_set_balance(None, unwrap!(Coins::from_str("0")))
            .await?;
        let data = PubImmutableData::new(unwrap!(generate_random_vector::<u8>(10)));
        let res = client.put_idata(data).await;
        match res {
            Err(CoreError::DataError(SndError::InsufficientBalance)) => (),
            res => panic!("Unexpected result: {:?}", res),
        };
        Ok(())
    }

    // 1. Create a client that PUTs some mdata on the network
    // 2. Create a different client that tries to delete the data. It should panic.
    #[tokio::test]
    pub async fn del_unseq_mdata_permission_test() -> Result<(), CoreError> {
        let name = XorName(rand::random());
        let tag = 15001;
        let mdataref = MDataAddress::Unseq { name, tag };

        let client = random_client()?;
        let data = UnseqMutableData::new_with_data(
            name,
            tag,
            Default::default(),
            Default::default(),
            client.public_key().await,
        );

        client.put_unseq_mutable_data(data).await?;

        let client = random_client()?;
        let res = client.delete_mdata(mdataref).await;
        match res {
            Err(CoreError::DataError(SndError::AccessDenied)) => (),
            res => panic!("Unexpected result: {:?}", res),
        }

        Ok(())
    }

    // 1. Create a mutable data with some permissions and store it on the network.
    // 2. Modify the permissions of a user in the permission set.
    // 3. Fetch the list of permissions and verify the edit.
    // 4. Delete a user's permissions from the permission set and verify the deletion.
    #[tokio::test]
    pub async fn mdata_permissions_test() -> Result<(), CoreError> {
        let client = random_client()?;
        // The `random_client()` initializes the client with 10 coins.
        let start_bal = unwrap!(Coins::from_str("10"));
        let name = XorName(rand::random());
        let tag = 15001;
        let mut permissions: BTreeMap<_, _> = Default::default();
        let permission_set = MDataPermissionSet::new()
            .allow(MDataAction::Read)
            .allow(MDataAction::Insert)
            .allow(MDataAction::ManagePermissions);
        let user = client.public_key().await;
        let random_user = gen_bls_keypair().public_key();
        let random_pk = gen_bls_keypair().public_key();

        let _ = permissions.insert(user, permission_set.clone());
        let _ = permissions.insert(random_user, permission_set);

        let data = SeqMutableData::new_with_data(
            name,
            tag,
            Default::default(),
            permissions.clone(),
            client.public_key().await,
        );
        let test_data = SeqMutableData::new_with_data(
            XorName(rand::random()),
            15000,
            Default::default(),
            permissions,
            random_pk,
        );

        client.put_seq_mutable_data(data).await?;
        let res = client.put_seq_mutable_data(test_data.clone()).await;
        match res {
            Err(CoreError::DataError(SndError::InvalidOwners)) => (),
            Ok(_) => panic!("Unexpected Success: Validating owners should fail"),
            Err(e) => panic!("Unexpected: {:?}", e),
        };
        // Check if coins are refunded
        let balance = client.get_balance(None).await?;
        let expected_bal = calculate_new_balance(start_bal, Some(2), None);
        assert_eq!(balance, expected_bal);
        let new_perm_set = MDataPermissionSet::new()
            .allow(MDataAction::ManagePermissions)
            .allow(MDataAction::Read);
        client
            .set_mdata_user_permissions(MDataAddress::Seq { name, tag }, user, new_perm_set, 1)
            .await?;
        println!("Modified user permissions");

        let permissions = client
            .list_mdata_user_permissions(MDataAddress::Seq { name, tag }, user)
            .await?;
        assert!(!permissions.is_allowed(MDataAction::Insert));
        assert!(permissions.is_allowed(MDataAction::Read));
        assert!(permissions.is_allowed(MDataAction::ManagePermissions));
        println!("Verified new permissions");

        client
            .del_mdata_user_permissions(MDataAddress::Seq { name, tag }, random_user, 2)
            .await?;
        println!("Deleted permissions");
        let permissions = client
            .list_mdata_permissions(MDataAddress::Seq { name, tag })
            .await?;
        assert_eq!(permissions.len(), 1);
        println!("Permission set verified");

        Ok(())
    }

    // 1. Create a mutable data and store it on the network
    // 2. Create some entry actions and mutate the data on the network.
    // 3. List the entries and verify that the mutation was applied.
    // 4. Fetch a value for a particular key and verify
    #[tokio::test]
    pub async fn mdata_mutations_test() -> Result<(), CoreError> {
        let client = random_client()?;
        let name = XorName(rand::random());
        let tag = 15001;
        let mut permissions: BTreeMap<_, _> = Default::default();
        let permission_set = MDataPermissionSet::new()
            .allow(MDataAction::Read)
            .allow(MDataAction::Insert)
            .allow(MDataAction::Update)
            .allow(MDataAction::Delete);
        let user = client.public_key().await;
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
            client.public_key().await,
        );
        client.put_seq_mutable_data(data).await?;
        println!("Put seq. MData successfully");

        let fetched_entries = client.list_seq_mdata_entries(name, tag).await?;
        assert_eq!(fetched_entries, entries);
        let entry_actions: MDataSeqEntryActions = MDataSeqEntryActions::new()
            .update(b"key1".to_vec(), b"newValue".to_vec(), 1)
            .del(b"key2".to_vec(), 1)
            .ins(b"key3".to_vec(), b"value".to_vec(), 0);

        client
            .mutate_seq_mdata_entries(name, tag, entry_actions)
            .await?;
        let fetched_entries = client.list_seq_mdata_entries(name, tag).await?;
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
        let fetched_value = client
            .get_seq_mdata_value(name, tag, b"key3".to_vec())
            .await?;
        assert_eq!(
            fetched_value,
            MDataSeqValue {
                data: b"value".to_vec(),
                version: 0
            }
        );
        let res = client
            .get_seq_mdata_value(name, tag, b"wrongKey".to_vec())
            .await;
        match res {
            Ok(_) => panic!("Unexpected: Entry should not exist"),
            Err(CoreError::DataError(SndError::NoSuchEntry)) => (),
            Err(err) => panic!("Unexpected error: {:?}", err),
        };

        let client = random_client()?;
        let name = XorName(rand::random());
        let tag = 15001;
        let mut permissions: BTreeMap<_, _> = Default::default();
        let permission_set = MDataPermissionSet::new()
            .allow(MDataAction::Read)
            .allow(MDataAction::Insert)
            .allow(MDataAction::Update)
            .allow(MDataAction::Delete);
        let user = client.public_key().await;
        let _ = permissions.insert(user, permission_set);
        let mut entries: BTreeMap<Vec<u8>, Vec<u8>> = Default::default();
        let _ = entries.insert(b"key1".to_vec(), b"value".to_vec());
        let _ = entries.insert(b"key2".to_vec(), b"value".to_vec());
        let data = UnseqMutableData::new_with_data(
            name,
            tag,
            entries.clone(),
            permissions,
            client.public_key().await,
        );
        client.put_unseq_mutable_data(data).await?;
        println!("Put unseq. MData successfully");

        let fetched_entries = client.list_unseq_mdata_entries(name, tag).await?;
        assert_eq!(fetched_entries, entries);
        let entry_actions: MDataUnseqEntryActions = MDataUnseqEntryActions::new()
            .update(b"key1".to_vec(), b"newValue".to_vec())
            .del(b"key2".to_vec())
            .ins(b"key3".to_vec(), b"value".to_vec());

        client
            .mutate_unseq_mdata_entries(name, tag, entry_actions)
            .await?;
        let fetched_entries = client.list_unseq_mdata_entries(name, tag).await?;
        let mut expected_entries: BTreeMap<_, _> = Default::default();
        let _ = expected_entries.insert(b"key1".to_vec(), b"newValue".to_vec());
        let _ = expected_entries.insert(b"key3".to_vec(), b"value".to_vec());
        assert_eq!(fetched_entries, expected_entries);
        let fetched_value = client
            .get_unseq_mdata_value(name, tag, b"key1".to_vec())
            .await?;
        assert_eq!(fetched_value, b"newValue".to_vec());
        let res = client
            .get_unseq_mdata_value(name, tag, b"wrongKey".to_vec())
            .await;
        match res {
            Ok(_) => panic!("Unexpected: Entry should not exist"),
            Err(CoreError::DataError(SndError::NoSuchEntry)) => Ok(()),
            Err(err) => panic!("Unexpected error: {:?}", err),
        }
    }

    // 1. Create a random BLS key and create a wallet for it with some test safecoin.
    // 2. Without a client object, try to get the balance, create new wallets and transfer safecoin.
    #[tokio::test]
    pub async fn wallet_transactions_without_client() -> Result<(), CoreError> {
        let client_id = gen_client_id();

        test_create_balance(&client_id, unwrap!(Coins::from_str("50"))).await?;

        let balance = wallet_get_balance(&client_id).await?;
        let ten_coins = unwrap!(Coins::from_str("10"));
        assert_eq!(balance, unwrap!(Coins::from_str("50")));

        let new_client_id = gen_client_id();
        let new_client_pk = new_client_id.public_id().public_key();
        let new_wallet: XorName = *new_client_id.public_id().name();
        let txn = wallet_create_balance(&client_id, *new_client_pk, ten_coins, None).await?;
        assert_eq!(txn.amount, ten_coins);
        let txn2 = wallet_transfer_coins(&client_id, new_wallet, ten_coins, None).await?;
        assert_eq!(txn2.amount, ten_coins);

        let client_balance = wallet_get_balance(&client_id).await?;
        let expected = unwrap!(Coins::from_str("30"));
        let expected = unwrap!(expected.checked_sub(COST_OF_PUT));
        assert_eq!(client_balance, expected);

        let new_client_balance = wallet_get_balance(&new_client_id).await?;
        assert_eq!(new_client_balance, unwrap!(Coins::from_str("20")));

        Ok(())
    }

    // 1. Store different variants of unpublished data on the network.
    // 2. Get the balance of the client.
    // 3. Delete data from the network.
    // 4. Verify that the balance has not changed since deletions are free.
    #[tokio::test]
    pub async fn deletions_should_be_free() -> Result<(), CoreError> {
        let name = XorName(rand::random());
        let tag = 10;
        let client = random_client()?;

        let idata = UnpubImmutableData::new(
            unwrap!(generate_random_vector::<u8>(10)),
            client.public_key().await,
        );
        let idata_address = *idata.name();
        client.put_idata(idata).await?;

        let owner = client.public_key().await;
        let perms = BTreeMap::<PublicKey, SDataPrivUserPermissions>::new();
        let sdata_address = client.store_priv_sdata(name, tag, owner, perms).await?;

        let mdata = UnseqMutableData::new(name, tag, client.public_key().await);
        client.put_unseq_mutable_data(mdata).await?;
        let mdata_address = MDataAddress::from_kind(MDataKind::Unseq, name, tag);

        let balance = client.get_balance(None).await?;
        client.delete_sdata(sdata_address).await?;
        client.delete_mdata(mdata_address).await?;
        client.del_unpub_idata(idata_address).await?;
        let new_balance = client.get_balance(None).await?;
        assert_eq!(new_balance, balance);

        Ok(())
    }

    /// Sequence data tests ///

    #[tokio::test]
    pub async fn sdata_basics_test() -> Result<(), CoreError> {
        let client = random_client()?;

        let name = XorName(rand::random());
        let tag = 15000;
        let owner = client.public_key().await;

        // store a Private Sequence
        let mut perms = BTreeMap::<PublicKey, SDataPrivUserPermissions>::new();
        let _ = perms.insert(owner, SDataPrivUserPermissions::new(true, true, true));
        let address = client.store_priv_sdata(name, tag, owner, perms).await?;
        let sdata = client.get_sdata(address).await?;
        assert!(sdata.is_priv());
        assert_eq!(*sdata.name(), name);
        assert_eq!(sdata.tag(), tag);
        assert_eq!(sdata.permissions_index(), 1);
        assert_eq!(sdata.owners_index(), 1);
        assert_eq!(sdata.entries_index(), 0);

        // store a Public Sequence
        let mut perms = BTreeMap::<SDataUser, SDataPubUserPermissions>::new();
        let _ = perms.insert(SDataUser::Anyone, SDataPubUserPermissions::new(true, true));
        let address = client.store_pub_sdata(name, tag, owner, perms).await?;
        let sdata = client.get_sdata(address).await?;
        assert!(sdata.is_pub());
        assert_eq!(*sdata.name(), name);
        assert_eq!(sdata.tag(), tag);
        assert_eq!(sdata.permissions_index(), 1);
        assert_eq!(sdata.owners_index(), 1);
        assert_eq!(sdata.entries_index(), 0);

        Ok(())
    }

    #[tokio::test]
    pub async fn sdata_priv_permissions_test() -> Result<(), CoreError> {
        let client = random_client()?;

        let name = XorName(rand::random());
        let tag = 15000;
        let owner = client.public_key().await;
        let mut perms = BTreeMap::<PublicKey, SDataPrivUserPermissions>::new();
        let _ = perms.insert(owner, SDataPrivUserPermissions::new(true, true, true));
        let address = client.store_priv_sdata(name, tag, owner, perms).await?;

        let data = client.get_sdata(address).await?;
        assert_eq!(data.entries_index(), 0);
        assert_eq!(data.owners_index(), 1);
        assert_eq!(data.permissions_index(), 1);

        let priv_permissions = client.get_sdata_priv_permissions(address).await?;
        let user_perms = priv_permissions
            .permissions
            .get(&owner)
            .ok_or_else(|| CoreError::from("Unexpectedly failed to get user permissions"))?;
        assert!(user_perms.is_allowed(SDataAction::Read));
        assert!(user_perms.is_allowed(SDataAction::Append));
        assert!(user_perms.is_allowed(SDataAction::ManagePermissions));

        match client
            .get_sdata_user_permissions(address, SDataUser::Key(owner))
            .await?
        {
            SDataUserPermissions::Priv(user_perms) => {
                assert!(user_perms.is_allowed(SDataAction::Read));
                assert!(user_perms.is_allowed(SDataAction::Append));
                assert!(user_perms.is_allowed(SDataAction::ManagePermissions));
            }
            SDataUserPermissions::Pub(_) => {
                return Err(CoreError::from(
                    "Unexpectedly obtained incorrect user permissions",
                ))
            }
        }

        let sim_client = gen_bls_keypair().public_key();
        let mut perms2 = BTreeMap::<PublicKey, SDataPrivUserPermissions>::new();
        let _ = perms2.insert(
            sim_client,
            SDataPrivUserPermissions::new(false, true, false),
        );
        client.sdata_set_priv_permissions(address, perms2).await?;

        let priv_permissions = client.get_sdata_priv_permissions(address).await?;
        let user_perms = priv_permissions
            .permissions
            .get(&sim_client)
            .ok_or_else(|| CoreError::from("Unexpectedly failed to get user permissions"))?;
        assert!(!user_perms.is_allowed(SDataAction::Read));
        assert!(user_perms.is_allowed(SDataAction::Append));
        assert!(!user_perms.is_allowed(SDataAction::ManagePermissions));

        match client
            .get_sdata_user_permissions(address, SDataUser::Key(sim_client))
            .await?
        {
            SDataUserPermissions::Priv(user_perms) => {
                assert!(!user_perms.is_allowed(SDataAction::Read));
                assert!(user_perms.is_allowed(SDataAction::Append));
                assert!(!user_perms.is_allowed(SDataAction::ManagePermissions));
                Ok(())
            }
            SDataUserPermissions::Pub(_) => Err(CoreError::from(
                "Unexpectedly obtained incorrect user permissions",
            )),
        }
    }

    #[tokio::test]
    pub async fn sdata_pub_permissions_test() -> Result<(), CoreError> {
        let client = random_client()?;

        let name = XorName(rand::random());
        let tag = 15000;
        let owner = client.public_key().await;
        let mut perms = BTreeMap::<SDataUser, SDataPubUserPermissions>::new();
        let _ = perms.insert(
            SDataUser::Key(owner),
            SDataPubUserPermissions::new(None, true),
        );
        let address = client.store_pub_sdata(name, tag, owner, perms).await?;

        let data = client.get_sdata(address).await?;
        assert_eq!(data.entries_index(), 0);
        assert_eq!(data.owners_index(), 1);
        assert_eq!(data.permissions_index(), 1);

        let pub_permissions = client.get_sdata_pub_permissions(address).await?;
        let user_perms = pub_permissions
            .permissions
            .get(&SDataUser::Key(owner))
            .ok_or_else(|| CoreError::from("Unexpectedly failed to get user permissions"))?;
        assert_eq!(Some(true), user_perms.is_allowed(SDataAction::Read));
        assert_eq!(None, user_perms.is_allowed(SDataAction::Append));
        assert_eq!(
            Some(true),
            user_perms.is_allowed(SDataAction::ManagePermissions)
        );

        match client
            .get_sdata_user_permissions(address, SDataUser::Key(owner))
            .await?
        {
            SDataUserPermissions::Pub(user_perms) => {
                assert_eq!(Some(true), user_perms.is_allowed(SDataAction::Read));
                assert_eq!(None, user_perms.is_allowed(SDataAction::Append));
                assert_eq!(
                    Some(true),
                    user_perms.is_allowed(SDataAction::ManagePermissions)
                );
            }
            SDataUserPermissions::Priv(_) => {
                return Err(CoreError::from(
                    "Unexpectedly obtained incorrect user permissions",
                ))
            }
        }

        let sim_client = gen_bls_keypair().public_key();
        let mut perms2 = BTreeMap::<SDataUser, SDataPubUserPermissions>::new();
        let _ = perms2.insert(
            SDataUser::Key(sim_client),
            SDataPubUserPermissions::new(false, false),
        );
        client.sdata_set_pub_permissions(address, perms2).await?;

        let pub_permissions = client.get_sdata_pub_permissions(address).await?;
        let user_perms = pub_permissions
            .permissions
            .get(&SDataUser::Key(sim_client))
            .ok_or_else(|| CoreError::from("Unexpectedly failed to get user permissions"))?;
        assert_eq!(Some(true), user_perms.is_allowed(SDataAction::Read));
        assert_eq!(Some(false), user_perms.is_allowed(SDataAction::Append));
        assert_eq!(
            Some(false),
            user_perms.is_allowed(SDataAction::ManagePermissions)
        );

        match client
            .get_sdata_user_permissions(address, SDataUser::Key(sim_client))
            .await?
        {
            SDataUserPermissions::Pub(user_perms) => {
                assert_eq!(Some(true), user_perms.is_allowed(SDataAction::Read));
                assert_eq!(Some(false), user_perms.is_allowed(SDataAction::Append));
                assert_eq!(
                    Some(false),
                    user_perms.is_allowed(SDataAction::ManagePermissions)
                );
                Ok(())
            }
            SDataUserPermissions::Priv(_) => Err(CoreError::from(
                "Unexpectedly obtained incorrect user permissions",
            )),
        }
    }

    #[tokio::test]
    pub async fn sdata_append_test() -> Result<(), CoreError> {
        let name = XorName(rand::random());
        let tag = 10;
        let client = random_client()?;

        let owner = client.public_key().await;
        let mut perms = BTreeMap::<SDataUser, SDataPubUserPermissions>::new();
        let _ = perms.insert(
            SDataUser::Key(owner),
            SDataPubUserPermissions::new(true, true),
        );
        let address = client.store_pub_sdata(name, tag, owner, perms).await?;

        client.sdata_append(address, b"VALUE1".to_vec()).await?;

        let (index, data) = client.get_sdata_last_entry(address).await?;
        assert_eq!(0, index);
        assert_eq!(unwrap!(std::str::from_utf8(&data)), "VALUE1");

        client.sdata_append(address, b"VALUE2".to_vec()).await?;

        let (index, data) = client.get_sdata_last_entry(address).await?;
        assert_eq!(1, index);
        assert_eq!(unwrap!(std::str::from_utf8(&data)), "VALUE2");

        let data = client
            .get_sdata_range(address, (SDataIndex::FromStart(0), SDataIndex::FromEnd(0)))
            .await?;
        assert_eq!(unwrap!(std::str::from_utf8(&data[0])), "VALUE1");
        assert_eq!(unwrap!(std::str::from_utf8(&data[1])), "VALUE2");

        Ok(())
    }

    #[tokio::test]
    pub async fn sdata_owner_test() -> Result<(), CoreError> {
        let name = XorName(rand::random());
        let tag = 10;
        let client = random_client()?;

        let owner = client.public_key().await;
        let mut perms = BTreeMap::<PublicKey, SDataPrivUserPermissions>::new();
        let _ = perms.insert(owner, SDataPrivUserPermissions::new(true, true, true));
        let address = client.store_priv_sdata(name, tag, owner, perms).await?;

        client.sdata_append(address, b"VALUE1".to_vec()).await?;
        client.sdata_append(address, b"VALUE2".to_vec()).await?;

        let data = client.get_sdata(address).await?;
        assert_eq!(data.entries_index(), 2);
        assert_eq!(data.owners_index(), 1);
        assert_eq!(data.permissions_index(), 1);

        let current_owner = client.get_sdata_owner(address).await?;
        assert_eq!(owner, current_owner.public_key);

        let sim_client = gen_bls_keypair().public_key();
        client.sdata_set_owner(address, sim_client).await?;

        let current_owner = client.get_sdata_owner(address).await?;
        assert_eq!(sim_client, current_owner.public_key);

        Ok(())
    }

    #[tokio::test]
    pub async fn sdata_delete_test() -> Result<(), CoreError> {
        let client = random_client()?;

        let name = XorName(rand::random());
        let tag = 15000;
        let owner = client.public_key().await;

        // store a Private Sequence
        let mut perms = BTreeMap::<PublicKey, SDataPrivUserPermissions>::new();
        let _ = perms.insert(owner, SDataPrivUserPermissions::new(true, true, true));
        let address = client.store_priv_sdata(name, tag, owner, perms).await?;
        let sdata = client.get_sdata(address).await?;
        assert!(sdata.is_priv());

        client.delete_sdata(address).await?;

        match client.get_sdata(address).await {
            Err(CoreError::DataError(SndError::NoSuchData)) => {}
            Err(err) => {
                return Err(CoreError::from(format!(
                    "Unexpected error returned when deleting a nonexisting Private Sequence: {}",
                    err
                )))
            }
            Ok(_) => {
                return Err(CoreError::from(
                    "Unexpectedly retrieved a deleted Private Sequence!",
                ))
            }
        }

        // store a Public Sequence
        let mut perms = BTreeMap::<SDataUser, SDataPubUserPermissions>::new();
        let _ = perms.insert(SDataUser::Anyone, SDataPubUserPermissions::new(true, true));
        let address = client.store_pub_sdata(name, tag, owner, perms).await?;
        let sdata = client.get_sdata(address).await?;
        assert!(sdata.is_pub());

        match client.delete_sdata(address).await {
            Err(CoreError::DataError(SndError::InvalidOperation)) => Ok(()),
            Err(err) => {
                return Err(CoreError::from(format!(
                    "Unexpected error returned when attempting to delete a Public Sequence: {}",
                    err
                )))
            }
            Ok(()) => Err(CoreError::from("Unexpectedly deleted a Public Sequence!")),
        }
    }
}
