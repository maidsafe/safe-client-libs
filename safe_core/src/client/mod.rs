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
/// Safe Transfers wrapper, with Money APIs
pub mod transfer_actor;

use async_trait::async_trait;

#[cfg(feature = "mock-network")]
mod mock;

// safe-transfers wrapper
pub use self::transfer_actor::{ClientTransferValidator, TransferActor};

pub use self::account::ClientKeys;
pub use self::mdata_info::MDataInfo;
#[cfg(feature = "mock-network")]
pub use self::mock::vault::mock_vault_path;
#[cfg(feature = "mock-network")]
pub use self::mock::ConnectionManager as MockConnectionManager;
pub use safe_nd::SafeKey;

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
use lru_cache::LruCache;
use quic_p2p::Config as QuicP2pConfig;
use safe_nd::{
    AData, ADataAddress, ADataAppendOperation, ADataEntries, ADataEntry, ADataIndex, ADataIndices,
    ADataOwner, ADataPermissions, ADataPubPermissionSet, ADataPubPermissions, ADataRequest,
    ADataUnpubPermissionSet, ADataUnpubPermissions, ADataUser, AppPermissions, ClientFullId,
    ClientRequest, IData, IDataAddress, IDataRequest, LoginPacket, LoginPacketRequest, MData,
    MDataAddress, MDataEntries, MDataEntryActions, MDataPermissionSet, MDataRequest,
    MDataSeqEntries, MDataSeqEntryActions, MDataSeqValue, MDataUnseqEntryActions, MDataValue,
    MDataValues, Message, MessageId, Money, MoneyRequest, PublicId, PublicKey, Request,
    RequestType, Response, SeqMutableData, Transfer, TransferRegistered, UnseqMutableData, XorName,
};
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;
use unwrap::unwrap;

/// Capacity of the immutable data cache.
pub const IMMUT_DATA_CACHE_SIZE: usize = 300;

/// Expected cost of mutation operations.
pub const COST_OF_PUT: Money = Money::from_nano(1);

/// Return the `crust::Config` associated with the `crust::Service` (if any).
pub fn bootstrap_config() -> Result<BootstrapConfig, CoreError> {
    Ok(Config::new().quic_p2p.hard_coded_contacts)
}

async fn send(client: &impl Client, request: Request) -> Result<Response, CoreError> {
    // `sign` should be false for GETs on published data, true otherwise.
    let sign = request.get_type() != RequestType::PublicGet;
    let request = client.compose_message(request, sign).await;
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
// TODO: retrieve our actor for this clientID....

async fn send_as_helper(
    client: &impl Client,
    request: Request,
    client_id: Option<&ClientFullId>,
) -> Result<Response, CoreError> {
    let (message, identity) = match client_id {
        Some(id) => (sign_request(request, id), SafeKey::client(id.clone())),
        None => {
            let msg = client.compose_message(request, true).await;
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

    /// Return the TransferActor for this client
    async fn transfer_actor(&self) -> TransferActor;

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
    async fn compose_message(&self, request: Request, sign: bool) -> Message {
        let message_id = MessageId::new();

        let signature = if sign {
            Some(
                self.full_id()
                    .await
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
    async fn transfer_money(
        &self,
        // client_id: Option<&ClientFullId>,
        destination: PublicKey,
        amount: Money,
        _transfer_id: Option<u64>,
    ) -> Result<TransferRegistered, CoreError>
    where
        Self: Sized,
    {
        trace!("Transfer {} coins to {:?}", amount, destination);
        // TODO: retrieve our actor for this clientID....
        // NOte: this currently has clintId as an option.. . but it's _mostly_ ignored...
        // we can remove that and set up an API for transfer_as if needs be...

        let cm = self.inner().lock().await.connection_manager.clone();

        let mut actor = self.transfer_actor().await;

        let transfer_result = actor
            .send_money_as(self.full_id().await, cm, destination, amount)
            .await;

        match transfer_result {
            Ok(res) => match res {
                Response::TransferRegistration(result) => match result {
                    Ok(transfer) => Ok(transfer),
                    Err(error) => Err(CoreError::from(error)),
                },
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            },
            Err(_error) => Err(CoreError::ReceivedUnexpectedEvent),
        }
    }

    // TODO: is this API needed at all? Why not just transfer?
    /// Creates a new balance on the network.
    async fn create_balance(
        &self,
        _client_id: Option<&ClientFullId>,
        new_balance_owner: PublicKey,
        amount: Money,
        _transfer_id: Option<u64>,
    ) -> Result<TransferRegistered, CoreError>
    where
        Self: Sized,
    {
        trace!(
            "Create a new balance for {:?} with {} coins.",
            new_balance_owner,
            amount
        );
        // TODO: retrieve our actor for this clientID....
        let cm = self.inner().lock().await.connection_manager.clone();

        let mut actor = self.transfer_actor().await;

        // TODO: is this send_money_as or what shoudl this API be?
        let transfer_result = actor
            .send_money_as(self.full_id().await, cm, new_balance_owner, amount)
            .await;

        // match send_as_helper(
        //     self,
        //     Request::Money(MoneyRequest::CreateBalance {
        //         new_balance_owner,
        //         amount,
        //         transfer_id: transfer_id.unwrap_or_else(rand::random),
        //     }),
        //     client_id,
        // )
        // .await

        match transfer_result {
            Ok(res) => match res {
                Response::TransferRegistration(result) => match result {
                    Ok(transfer) => Ok(transfer),
                    Err(error) => Err(CoreError::from(error)),
                },
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            },

            Err(error) => Err(error),
        }
    }

    // /// Insert a given login packet at the specified destination
    // async fn insert_login_packet_for(
    //     &self,
    //     client_id: Option<&ClientFullId>,
    //     new_owner: PublicKey,
    //     amount: Money,
    //     transfer_id: Option<u64>,
    //     new_login_packet: LoginPacket,
    // ) -> Result<TransferRegistered, CoreError>
    // where
    //     Self: Sized,
    // {
    //     trace!(
    //         "Insert a login packet for {:?} preloading the wallet with {} coins.",
    //         new_owner,
    //         amount
    //     );

    //     let transfer_id = transfer_id.unwrap_or_else(rand::random);

    //     // TOD   // TODO: retrieve our actor for this clientID....

    // O: update login packet flow
    //     match send_as_helper(
    //         self,
    //         Request::LoginPacket(LoginPacketRequest::CreateFor {
    //             new_owner,
    //             amount,
    //             transfer_id,
    //             new_login_packet,
    //         }),
    //         client_id,
    //     )
    //     .await
    //     {
    //         Ok(res) => match res {
    //             Response::TransferRegistration(result) => match result {
    //                 Ok(transfer) => Ok(transfer),
    //                 Err(error) => Err(CoreError::from(error)),
    //             },
    //             _ => Err(CoreError::ReceivedUnexpectedEvent),
    //         },

    //         Err(error) => Err(error),
    //     }
    // }

    /// Get the current coin balance via TransferActor for this client.
    async fn get_balance(&self, client_id: Option<&ClientFullId>) -> Result<Money, CoreError>
    where
        Self: Sized,
    {
        trace!("Get balance for {:?}", client_id);

        // TODO: another api for getting from network
        // TODO: handle client_id passed in
        self.transfer_actor()
            .await
            .get_local_balance(self.full_id().await)
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
        if let Some(data) = inner.lock().await.cache.get_mut(&address) {
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
            .await
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
    // ======= Append Only Data =======
    //
    /// Put AppendOnly Data into the Network
    async fn put_adata(&self, data: AData) -> Result<(), CoreError>
    where
        Self: Sized,
    {
        trace!("Put AppendOnly Data {:?}", data.name());
        send_mutation(self, Request::AData(ADataRequest::Put(data))).await
    }

    /// Get AppendOnly Data from the Network
    async fn get_adata(&self, address: ADataAddress) -> Result<AData, CoreError>
    where
        Self: Sized,
    {
        trace!("Get AppendOnly Data at {:?}", address.name());

        match send(self, Request::AData(ADataRequest::Get(address))).await? {
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
            Request::AData(ADataRequest::GetShell {
                address,
                data_index,
            }),
        )
        .await?
        {
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

        match send(
            self,
            Request::AData(ADataRequest::GetValue { address, key }),
        )
        .await?
        {
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

        match send(
            self,
            Request::AData(ADataRequest::GetRange { address, range }),
        )
        .await?
        {
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

        match send(self, Request::AData(ADataRequest::GetIndices(address))).await? {
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

        match send(self, Request::AData(ADataRequest::GetLastEntry(address))).await? {
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
            Request::AData(ADataRequest::GetPermissions {
                address,
                permissions_index,
            }),
        )
        .await?
        {
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
            Request::AData(ADataRequest::GetPermissions {
                address,
                permissions_index,
            }),
        )
        .await?
        {
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
            Request::AData(ADataRequest::GetPubUserPermissions {
                address,
                permissions_index,
                user,
            }),
        )
        .await?
        {
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
            Request::AData(ADataRequest::GetUnpubUserPermissions {
                address,
                permissions_index,
                public_key,
            }),
        )
        .await?
        {
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
            Request::AData(ADataRequest::AddUnpubPermissions {
                address,
                permissions,
                permissions_index,
            }),
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
            Request::AData(ADataRequest::AddPubPermissions {
                address,
                permissions,
                permissions_index,
            }),
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
            Request::AData(ADataRequest::SetOwner {
                address,
                owner,
                owners_index,
            }),
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
            Request::AData(ADataRequest::GetOwners {
                address,
                owners_index,
            }),
        )
        .await?
        {
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
        send_mutation(
            self,
            Request::AData(ADataRequest::AppendSeq { append, index }),
        )
        .await
    }

    /// Append to Unpublished Unseq AppendOnly Data
    async fn append_unseq_adata(&self, append: ADataAppendOperation) -> Result<(), CoreError>
    where
        Self: Sized,
    {
        send_mutation(self, Request::AData(ADataRequest::AppendUnseq(append))).await
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
        amount: Money,
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

        let cm = self.inner().lock().await.connection_manager.clone();

        let mut actor = self.transfer_actor().await;

        let transfer_result = actor
            .send_money_as(self.full_id().await, cm, new_balance_owner, amount)
            .await;

        match transfer_result {
            Ok(res) => match res {
                Response::TransferRegistration(result) => match result {
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

    let validator = ClientTransferValidator {};

    let (net_tx, _net_rx) = mpsc::unbounded();

    let mut cm = attempt_bootstrap(&Config::new().quic_p2p, &net_tx, full_id.clone()).await?;
    let _actor = TransferActor::new(validator, full_id.clone(), cm.clone());

    let res = func(&mut cm, &full_id);

    cm.disconnect(&full_id.public_id()).await?;

    res
}

/// Create a new mock balance at an arbitrary address.
pub async fn test_create_balance(owner: &ClientFullId, amount: Money) -> Result<(), CoreError> {
    trace!("Create test balance of {} for {:?}", amount, owner);

    let full_id = SafeKey::client(owner.clone());

    let validator = ClientTransferValidator {};

    let (net_tx, _net_rx) = mpsc::unbounded();

    let mut cm = attempt_bootstrap(&Config::new().quic_p2p, &net_tx, full_id.clone()).await?;
    let mut actor = TransferActor::new(validator, full_id.clone(), cm.clone()).await?;

    // let res = func(&mut cm, &full_id);
    let public_id = full_id.public_id();

    // Create the balance for the client
    let _new_balance_owner = match public_id.clone() {
        PublicId::Client(id) => *id.public_key(),
        x => return Err(CoreError::from(format!("Unexpected ID type {:?}", x))),
    };

    let public_key = full_id.public_key();

    // let response = futures::executor::block_on(req(
    //     &mut cm,
    //     Request::Money(MoneyRequest::CreateBalance {
    //         new_balance_owner,
    //         amount,
    //         transfer_id: rand::random(),
    //     }),
    //     &full_id,
    // ))?;

    // let mut cm = self.inner().lock().await.connection_manager.clone();

    // let mut actor = self.transfer_actor().await;

    let response = actor
        .send_money_as(full_id.clone(), cm.clone(), public_key, amount)
        .await?;

    let _result = match response {
        Response::TransferRegistration(res) => res.map(|_| Ok(()))?,
        _ => Err(CoreError::from("Unexpected response")),
    };

    cm.disconnect(&full_id.public_id()).await?;

    Ok(())

    // temp_client(owner, move |mut cm, full_id| {
    // })
    // .await
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

    /// Delete AData from network.
    async fn delete_adata(&self, address: ADataAddress) -> Result<(), CoreError>
    where
        Self: Sized,
    {
        trace!("Delete entire Unpublished AppendOnly Data at {:?}", address);

        send_mutation(self, Request::AData(ADataRequest::Delete(address))).await
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
    cache: LruCache<IDataAddress, IData>,
    timeout: Duration,
    net_tx: NetworkTx,
}

impl Inner {
    /// Create a new `ClientInner` object.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        connection_manager: ConnectionManager,
        cache: LruCache<IDataAddress, IData>,
        timeout: Duration,
        net_tx: NetworkTx,
    ) -> Inner
    where
        Self: Sized,
    {
        Self {
            connection_manager,
            cache,
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
    use crate::utils::generate_random_vector;
    use crate::utils::test_utils::{
        calculate_new_balance, gen_bls_keypair, gen_client_id, random_client,
    };
    use safe_nd::{
        ADataAction, ADataEntry, ADataKind, ADataOwner, ADataUnpubPermissionSet,
        ADataUnpubPermissions, AppendOnlyData, Error as SndError, MDataAction, MDataKind, Money,
        PubImmutableData, PubSeqAppendOnlyData, SeqAppendOnly, UnpubImmutableData,
        UnpubSeqAppendOnlyData, UnpubUnseqAppendOnlyData, UnseqAppendOnly, XorName,
    };
    use std::str::FromStr;

    // Test putting and getting pub idata.
    #[tokio::test]
    async fn pub_idata_test() -> Result<(), CoreError> {
        let client = random_client()?;
        // The `random_client()` initializes the client with 10 coins.
        let start_bal = unwrap!(Money::from_str("10"));

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
        let start_bal = unwrap!(Money::from_str("10"));

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
    // 5. Try to request transfer from wallet A using account B. This request should succeed
    // (because transfers are always open).
    #[tokio::test]
    async fn coin_permissions() -> Result<(), CoreError> {
        let client = random_client()?;
        let wallet_a_addr: XorName = client.public_key().await.into();
        let res = client
            .transfer_money(None, rand::random(), unwrap!(Money::from_str("5.0")), None)
            .await;
        match res {
            Err(CoreError::DataError(SndError::NoSuchBalance)) => (),
            res => panic!("Unexpected result: {:?}", res),
        }

        let client = random_client()?;
        let res = client.get_balance(None).await;
        // Subtract to cover the cost of inserting the login packet
        let expected_amt = unwrap!(Money::from_str("10")
            .ok()
            .and_then(|x| x.checked_sub(COST_OF_PUT)));
        match res {
            Ok(fetched_amt) => assert_eq!(expected_amt, fetched_amt),
            res => panic!("Unexpected result: {:?}", res),
        }
        client
            .test_set_balance(None, unwrap!(Money::from_str("50.0")))
            .await?;
        let res = client
            .transfer_money(None, wallet_a_addr, unwrap!(Money::from_str("10")), None)
            .await;
        match res {
            Ok(transfer) => assert_eq!(transfer.amount, unwrap!(Money::from_str("10"))),
            res => panic!("Unexpected error: {:?}", res),
        }
        let res = client.get_balance(None).await;
        let expected_amt = unwrap!(Money::from_str("40"));
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
        let init_bal = unwrap!(Money::from_str("500.0"));

        let client_id = gen_client_id();
        let bls_pk = *client_id.public_id().public_key();

        client.test_set_balance(None, init_bal).await?;
        let transfer = client
            .create_balance(None, bls_pk, unwrap!(Money::from_str("100.0")), None)
            .await?;
        assert_eq!(transfer.amount, unwrap!(Money::from_str("100")));
        let transfer = client
            .transfer_money(
                Some(&client_id.clone()),
                wallet1,
                unwrap!(Money::from_str("5.0")),
                None,
            )
            .await?;
        assert_eq!(transfer.amount, unwrap!(Money::from_str("5.0")));
        let balance = client.get_balance(Some(&client_id)).await?;
        assert_eq!(balance, unwrap!(Money::from_str("95.0")));
        let balance = client.get_balance(None).await?;
        let expected =
            calculate_new_balance(init_bal, Some(1), Some(unwrap!(Money::from_str("95"))));
        assert_eq!(balance, expected);
        let random_pk = gen_bls_keypair().public_key();
        let random_source = gen_client_id();

        let res = client
            .create_balance(
                Some(&random_source),
                random_pk,
                unwrap!(Money::from_str("100.0")),
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
    // 5. Fetch the transfer using the transfer ID and verify the amount.
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
            .test_set_balance(None, unwrap!(Money::from_str("100.0")))
            .await?;
        let balance = client.get_balance(None).await?;
        assert_eq!(balance, unwrap!(Money::from_str("100.0")));

        let client = random_client()?;
        let init_bal = unwrap!(Money::from_str("10"));
        let orig_balance = client.get_balance(None).await?;
        let _ = client
            .transfer_money(None, wallet1, unwrap!(Money::from_str("5.0")), None)
            .await?;
        let new_balance = client.get_balance(None).await?;
        assert_eq!(
            new_balance,
            unwrap!(orig_balance.checked_sub(unwrap!(Money::from_str("5.0")))),
        );
        let res = client
            .transfer_money(None, wallet1, unwrap!(Money::from_str("5000")), None)
            .await;
        match res {
            Err(CoreError::DataError(SndError::InsufficientBalance)) => (),
            res => panic!("Unexpected result: {:?}", res),
        };
        // Check if coins are refunded
        let balance = client.get_balance(None).await?;
        let expected =
            calculate_new_balance(init_bal, Some(1), Some(unwrap!(Money::from_str("5"))));
        assert_eq!(balance, expected);
        let res = client
            .transfer_money(None, wallet1, unwrap!(Money::from_str("0")), None)
            .await;
        match res {
            Err(CoreError::DataError(SndError::InvalidOperation)) => (),
            res => panic!("Unexpected result: {:?}", res),
        }
        client
            .test_set_balance(None, unwrap!(Money::from_str("0")))
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
        let start_bal = unwrap!(Money::from_str("10"));
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

    #[tokio::test]
    pub async fn adata_basics_test() -> Result<(), CoreError> {
        let client = random_client()?;

        let name = XorName(rand::random());
        let tag = 15000;
        let mut data = UnpubSeqAppendOnlyData::new(name, tag);
        let mut perms = BTreeMap::<PublicKey, ADataUnpubPermissionSet>::new();
        let set = ADataUnpubPermissionSet::new(true, true, true);
        let index = ADataIndex::FromStart(0);
        let _ = perms.insert(client.public_key().await, set);
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
            public_key: client.public_key().await,
            entries_index: 0,
            permissions_index: 1,
        };
        unwrap!(data.append_owner(owner, 0));

        client.put_adata(AData::UnpubSeq(data)).await?;
        let data = client.get_adata(address).await?;
        match data {
            AData::UnpubSeq(adata) => assert_eq!(*adata.name(), name),
            _ => panic!("Unexpected data found"),
        }
        let data = client.get_adata_shell(index, address).await?;
        match data {
            AData::UnpubSeq(adata) => {
                assert_eq!(*adata.name(), name);
                assert_eq!(adata.tag(), tag);
                assert_eq!(adata.permissions_index(), 1);
                assert_eq!(adata.owners_index(), 1);
            }
            _ => panic!("Unexpected data found"),
        }
        client.delete_adata(address).await?;
        let res = client.get_adata(address).await;
        match res {
            Ok(_) => panic!("AData was not deleted"),
            Err(CoreError::DataError(SndError::NoSuchData)) => Ok(()),
            Err(e) => panic!("Unexpected error: {:?}", e),
        }
    }

    #[tokio::test]
    pub async fn adata_permissions_test() -> Result<(), CoreError> {
        let client = random_client()?;

        let name = XorName(rand::random());
        let tag = 15000;
        let adataref = ADataAddress::UnpubSeq { name, tag };
        let mut data = UnpubSeqAppendOnlyData::new(name, tag);
        let mut perms = BTreeMap::<PublicKey, ADataUnpubPermissionSet>::new();
        let set = ADataUnpubPermissionSet::new(true, true, true);

        let _ = perms.insert(client.public_key().await, set);

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
            public_key: client.public_key().await,
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

        client.put_adata(AData::UnpubSeq(data)).await?;
        let res = client.put_adata(AData::UnpubSeq(test_data.clone())).await;
        match res {
            Ok(_) => panic!("Unexpected Success: Validating owners should fail"),
            Err(CoreError::DataError(SndError::InvalidOwners)) => (),
            Err(e) => panic!("Unexpected: {:?}", e),
        };

        let data = client
            .get_adata_range(adataref, (index_start, index_end))
            .await?;
        assert_eq!(
            unwrap!(std::str::from_utf8(&unwrap!(data.last()).key)),
            "KEY2"
        );
        assert_eq!(
            unwrap!(std::str::from_utf8(&unwrap!(data.last()).value)),
            "VALUE2"
        );
        let data = client.get_adata_indices(adataref).await?;
        assert_eq!(data.entries_index(), 4);
        assert_eq!(data.owners_index(), 1);
        assert_eq!(data.permissions_index(), 1);
        let data = client.get_adata_value(adataref, b"KEY1".to_vec()).await?;
        assert_eq!(unwrap!(std::str::from_utf8(data.as_slice())), "VALUE1");
        let data = client.get_adata_last_entry(adataref).await?;
        assert_eq!(unwrap!(std::str::from_utf8(data.key.as_slice())), "KEY4");
        assert_eq!(
            unwrap!(std::str::from_utf8(data.value.as_slice())),
            "VALUE4"
        );
        client
            .add_unpub_adata_permissions(adataref, perm_set, 1)
            .await?;
        let data = client
            .get_unpub_adata_permissions_at_index(adataref, perm_index)
            .await?;
        let set = unwrap!(data.permissions.get(&sim_client1));
        assert!(set.is_allowed(ADataAction::Append));
        let set = client
            .get_unpub_adata_user_permissions(adataref, index_start, client.public_key().await)
            .await?;
        assert!(set.is_allowed(ADataAction::Append));
        Ok(())
    }

    #[tokio::test]
    pub async fn append_seq_adata_test() -> Result<(), CoreError> {
        let name = XorName(rand::random());
        let tag = 10;
        let client = random_client()?;

        let adataref = ADataAddress::PubSeq { name, tag };
        let mut data = PubSeqAppendOnlyData::new(name, tag);

        let mut perms = BTreeMap::<ADataUser, ADataPubPermissionSet>::new();
        let set = ADataPubPermissionSet::new(true, true);

        let usr = ADataUser::Key(client.public_key().await);
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
            public_key: client.public_key().await,
            entries_index: 0,
            permissions_index: 1,
        };

        unwrap!(data.append_owner(owner, 0));

        client.put_adata(AData::PubSeq(data)).await?;
        client.append_seq_adata(append, 0).await?;
        let data = client.get_adata(adataref).await?;
        match data {
            AData::PubSeq(adata) => assert_eq!(
                unwrap!(std::str::from_utf8(&unwrap!(adata.last_entry()).key)),
                "KEY2"
            ),
            _ => panic!("UNEXPECTED DATA!"),
        }
        Ok(())
    }

    #[tokio::test]
    pub async fn append_unseq_adata_test() -> Result<(), CoreError> {
        let name = XorName(rand::random());
        let tag = 10;
        let client = random_client()?;

        let adataref = ADataAddress::UnpubUnseq { name, tag };
        let mut data = UnpubUnseqAppendOnlyData::new(name, tag);

        let mut perms = BTreeMap::<PublicKey, ADataUnpubPermissionSet>::new();
        let set = ADataUnpubPermissionSet::new(true, true, true);

        let _ = perms.insert(client.public_key().await, set);

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
            public_key: client.public_key().await,
            entries_index: 0,
            permissions_index: 1,
        };

        unwrap!(data.append_owner(owner, 0));

        client.put_adata(AData::UnpubUnseq(data)).await?;
        client.append_unseq_adata(append).await?;
        let data = client.get_adata(adataref).await?;
        match data {
            AData::UnpubUnseq(adata) => assert_eq!(
                unwrap!(std::str::from_utf8(&unwrap!(adata.last_entry()).key)),
                "KEY2"
            ),
            _ => panic!("UNEXPECTED DATA!"),
        }

        Ok(())
    }

    #[tokio::test]
    pub async fn set_and_get_owner_adata_test() -> Result<(), CoreError> {
        let name = XorName(rand::random());
        let tag = 10;
        let client = random_client()?;

        let adataref = ADataAddress::UnpubUnseq { name, tag };
        let mut data = UnpubUnseqAppendOnlyData::new(name, tag);

        let mut perms = BTreeMap::<PublicKey, ADataUnpubPermissionSet>::new();
        let set = ADataUnpubPermissionSet::new(true, true, true);

        let _ = perms.insert(client.public_key().await, set);

        data.append_permissions(
            ADataUnpubPermissions {
                permissions: perms,
                entries_index: 0,
                owners_index: 0,
            },
            0,
        )?;

        let key1 = b"KEY1".to_vec();
        let key2 = b"KEY2".to_vec();

        let val1 = b"VALUE1".to_vec();
        let val2 = b"VALUE2".to_vec();

        let kvdata = vec![ADataEntry::new(key1, val1), ADataEntry::new(key2, val2)];

        data.append(kvdata)?;

        let owner = ADataOwner {
            public_key: client.public_key().await,
            entries_index: 2,
            permissions_index: 1,
        };

        data.append_owner(owner, 0)?;

        let owner2 = ADataOwner {
            public_key: client.public_key().await,
            entries_index: 2,
            permissions_index: 1,
        };

        let owner3 = ADataOwner {
            public_key: client.public_key().await,
            entries_index: 2,
            permissions_index: 1,
        };

        client.put_adata(AData::UnpubUnseq(data)).await?;
        client.set_adata_owners(adataref, owner2, 1).await?;
        client.set_adata_owners(adataref, owner3, 2).await?;
        let data = client.get_adata(adataref).await?;
        match data {
            AData::UnpubUnseq(adata) => assert_eq!(adata.owners_index(), 3),
            _ => panic!("UNEXPECTED DATA!"),
        }

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
        let address = *idata.name();
        client.put_idata(idata).await?;
        let mut adata = UnpubSeqAppendOnlyData::new(name, tag);
        let owner = ADataOwner {
            public_key: client.public_key().await,
            entries_index: 0,
            permissions_index: 0,
        };
        unwrap!(adata.append_owner(owner, 0));
        client.put_adata(adata.into()).await?;
        let mdata = UnseqMutableData::new(name, tag, client.public_key().await);
        client.put_unseq_mutable_data(mdata).await?;

        let balance = client.get_balance(None).await?;
        client
            .delete_adata(ADataAddress::from_kind(ADataKind::UnpubSeq, name, tag))
            .await?;
        client
            .delete_mdata(MDataAddress::from_kind(MDataKind::Unseq, name, tag))
            .await?;
        client.del_unpub_idata(address).await?;
        let new_balance = client.get_balance(None).await?;
        assert_eq!(new_balance, balance);

        Ok(())
    }
}
