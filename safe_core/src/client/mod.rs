// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

/// User Account information.
pub mod account;
/// Not exclusively for testing purposes but also for its wait_for_response macro
#[macro_use]
pub mod core_client;
/// `MDataInfo` utilities.
pub mod mdata_info;
/// Operations with recovery.
pub mod recovery;

#[cfg(feature = "mock-network")]
mod mock;
mod routing_event_loop;

pub use self::account::ClientKeys;
pub use self::mdata_info::MDataInfo;
#[cfg(feature = "mock-network")]
pub use self::mock::vault::mock_vault_path;
#[cfg(feature = "mock-network")]
pub use self::mock::NewFullId;
#[cfg(feature = "mock-network")]
pub use self::mock::Routing as MockRouting;

#[cfg(feature = "mock-network")]
use self::mock::Routing;
#[cfg(not(feature = "mock-network"))]
use routing::Client as Routing;

use crate::crypto::{shared_box, shared_secretbox, shared_sign};
use crate::errors::CoreError;
use crate::event::{CoreEvent, NetworkEvent, NetworkTx};
use crate::event_loop::{CoreFuture, CoreMsgTx};
use crate::ipc::BootstrapConfig;
use crate::utils::FutureExt;
use futures::{
    future::{self, Either, Loop},
    sync::oneshot,
    Complete, Future,
};
use lru_cache::LruCache;
use maidsafe_utilities::serialisation::{deserialise, serialise};
use maidsafe_utilities::thread::{self, Joiner};
use routing::{
    Authority, EntryAction, Event, FullId, InterfaceError, MutableData, PermissionSet, User, Value,
};
use rust_sodium::crypto::{box_, sign};
use safe_nd::{
    AData, ADataAddress, ADataAppend, ADataEntries, ADataEntry, ADataIndex, ADataIndices,
    ADataOwner, ADataPubPermissionSet, ADataPubPermissions, ADataUnpubPermissionSet,
    ADataUnpubPermissions, ADataUser, AppPermissions, ClientFullId, ClientPublicId, Coins,
    Error as SndError, IData, IDataAddress, LoginPacket, MData, MDataAddress,
    MDataPermissionSet as NewPermissionSet, MDataSeqEntryActions, MDataUnseqEntryActions,
    MDataValue as Val, Message, MessageId, PubImmutableData, PublicId, PublicKey, Request,
    Response, SeqMutableData, Signature, Transaction, UnpubImmutableData, UnseqMutableData,
    XorName,
};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::rc::Rc;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};
use tokio::runtime::current_thread::Handle;
use tokio::timer::Delay;

/// Capacity of the immutable data cache.
pub const IMMUT_DATA_CACHE_SIZE: usize = 300;
/// Request timeout in seconds.
pub const REQUEST_TIMEOUT_SECS: u64 = 180;

const CONNECTION_TIMEOUT_SECS: u64 = 40;
const RETRY_DELAY_MS: u64 = 800;

macro_rules! match_event {
    ($r:ident, $event:path) => {
        match $r {
            $event(res) => res,
            x => {
                debug!("Unexpected Event: {:?}", x);
                Err(CoreError::ReceivedUnexpectedEvent)
            }
        }
    };
}

macro_rules! some_or_err {
    ($opt:expr) => {
        match $opt {
            Some(res) => res,
            None => return err!(CoreError::OperationForbidden),
        }
    };
}

/// Return the `crust::Config` associated with the `crust::Service` (if any).
pub fn bootstrap_config() -> Result<BootstrapConfig, CoreError> {
    Ok(Routing::bootstrap_config()?)
}

/// Trait providing an interface for self-authentication client implementations, so they can
/// interface all requests from high-level APIs to the actual routing layer and manage all
/// interactions with it. Clients are non-blocking, with an asynchronous API using the futures
/// abstraction from the futures-rs crate.
pub trait Client: Clone + 'static {
    /// Associated message type.
    type MsgType;

    /// Return the client's ID.
    fn full_id(&self) -> Option<FullId>;

    /// Return the client's public ID.
    fn public_id(&self) -> PublicId;

    /// Return a `crust::Config` if the `Client` was initialized with one.
    fn config(&self) -> Option<BootstrapConfig>;

    /// Address of the Client Manager.
    fn cm_addr(&self) -> Option<Authority<XorName>>;

    /// Return an associated `ClientInner` type which is expected to contain fields associated with
    /// the implementing type.
    fn inner(&self) -> Rc<RefCell<ClientInner<Self, Self::MsgType>>>;

    /// Return the public encryption key.
    fn public_encryption_key(&self) -> Option<box_::PublicKey>;

    /// Return the secret encryption key.
    fn secret_encryption_key(&self) -> Option<shared_box::SecretKey>;

    /// Return the public and secret encryption keys.
    fn encryption_keypair(&self) -> Option<(box_::PublicKey, shared_box::SecretKey)> {
        Some((self.public_encryption_key()?, self.secret_encryption_key()?))
    }

    /// Return the symmetric encryption key.
    fn secret_symmetric_key(&self) -> Option<shared_secretbox::Key>;

    /// Return the public signing key.
    fn public_signing_key(&self) -> Option<sign::PublicKey>;

    /// Return the secret signing key.
    fn secret_signing_key(&self) -> Option<shared_sign::SecretKey>;

    /// Return the public BLS key.
    fn public_bls_key(&self) -> Option<threshold_crypto::PublicKey>;

    /// Return the secret BLS key.
    fn secret_bls_key(&self) -> Option<threshold_crypto::SecretKey>;

    /// Create a `Message` from the given request.
    /// This function adds the requester signature and message ID.
    fn compose_message(&self, req: Request, sign: bool) -> Message;

    /// Return the public and secret signing keys.
    fn signing_keypair(&self) -> Option<(sign::PublicKey, shared_sign::SecretKey)> {
        Some((self.public_signing_key()?, self.secret_signing_key()?))
    }

    /// Return the owner signing key.
    fn owner_key(&self) -> Option<PublicKey>;

    /// Set request timeout.
    fn set_timeout(&self, duration: Duration) {
        let inner = self.inner();
        inner.borrow_mut().timeout = duration;
    }

    /// Restart the routing client and reconnect to the network.
    fn restart_routing(&self) -> Result<(), CoreError> {
        let opt_id = self.full_id();
        let inner = self.inner();
        let mut inner = inner.borrow_mut();

        let (routing, routing_rx) = setup_routing(opt_id, self.public_id(), self.config())?;

        let joiner = spawn_routing_thread(routing_rx, inner.core_tx.clone(), inner.net_tx.clone());

        inner.hooks.clear();
        inner.routing = routing;
        inner.joiner = joiner;

        inner.net_tx.unbounded_send(NetworkEvent::Connected)?;

        Ok(())
    }

    #[doc(hidden)]
    fn fire_hook(&self, id: &MessageId, event: CoreEvent) {
        // Using in `if` keeps borrow alive. Do not try to combine the 2 lines into one.
        let inner = self.inner();
        let opt = inner.borrow_mut().hooks.remove(id);
        if let Some(hook) = opt {
            let _ = hook.send(event);
        }
    }

    /// Get immutable data from the network. If the data exists locally in the cache then it will be
    /// immediately returned without making an actual network request.
    fn get_idata(&self, name: XorName) -> Box<CoreFuture<PubImmutableData>> {
        trace!("GetIData for {:?}", name);

        let inner = self.inner();
        if let Some(data) = inner.borrow_mut().cache.get_mut(&name) {
            trace!("PubImmutableData found in cache.");
            return future::ok(data.clone()).into_box();
        }

        let inner = Rc::downgrade(&self.inner());
        let msg_id = MessageId::new();
        send(self, msg_id, move |routing| {
            routing.get_idata(Authority::NaeManager(name), name, msg_id)
        })
        .and_then(|event| match_event!(event, CoreEvent::GetIData))
        .map(move |data| {
            if let Some(inner) = inner.upgrade() {
                // Put to cache
                let _ = inner.borrow_mut().cache.insert(*data.name(), data.clone());
            }
            data
        })
        .into_box()
    }

    // TODO All these return the same future from all branches. So convert to impl
    // Trait when it arrives in stable. Change from `Box<CoreFuture>` -> `impl
    // CoreFuture`.
    /// Put immutable data onto the network.
    fn put_idata(&self, data: PubImmutableData) -> Box<CoreFuture<()>> {
        trace!("PutIData for {:?}", data);

        let msg_id = MessageId::new();
        send_mutation(self, msg_id, move |routing, dst| {
            routing.put_idata(dst, data.clone(), msg_id)
        })
    }

    /// Put `MutableData` onto the network.
    fn put_mdata(&self, data: MutableData) -> Box<CoreFuture<()>> {
        trace!("PutMData for {:?}", data);

        let requester = some_or_err!(self.public_bls_key());
        let msg_id = MessageId::new();
        send_mutation(self, msg_id, move |routing, dst| {
            routing.put_mdata(dst, data.clone(), msg_id, PublicKey::from(requester))
        })
    }

    /// Put unsequenced mutable data to the network
    fn put_unseq_mutable_data(&self, data: UnseqMutableData) -> Box<CoreFuture<()>> {
        trace!("Put Unsequenced MData at {:?}", data.name());
        send_mutation_new(self, Request::PutMData(MData::Unseq(data.clone())))
    }

    /// Transfer coin balance
    fn transfer_coins(
        &self,
        secret_key: Option<&threshold_crypto::SecretKey>,
        destination: XorName,
        amount: Coins,
        transaction_id: Option<u64>,
    ) -> Box<CoreFuture<Transaction>> {
        trace!("Transfer {} coins to {:?}", amount, destination);

        let transaction_id = transaction_id.unwrap_or_else(rand::random);
        let req = Request::TransferCoins {
            destination,
            amount,
            transaction_id,
        };
        let (message, requester) = match secret_key {
            Some(key) => (
                sign_request_with_key(req, key),
                Some(PublicKey::from(key.public_key())),
            ),
            None => (self.compose_message(req, true), None),
        };
        send(
            self,
            fry!(message
                .message_id()
                .ok_or_else(|| CoreError::from("Logic error: no message ID found"))),
            move |routing| routing.send(requester, &unwrap!(serialise(&message))),
        )
        .and_then(|event| {
            let res = match event {
                CoreEvent::RpcResponse(res) => res,
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            };
            let result_buffer = unwrap!(res);
            let res: Response = unwrap!(deserialise(&result_buffer));
            match res {
                Response::Transaction(res) => res.map_err(CoreError::from),
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            }
        })
        .into_box()
    }

    /// Creates a new balance on the network.
    fn create_balance(
        &self,
        secret_key: Option<&threshold_crypto::SecretKey>,
        new_balance_owner: PublicKey,
        amount: Coins,
        transaction_id: Option<u64>,
    ) -> Box<CoreFuture<Transaction>> {
        trace!(
            "Create a new balance for {:?} with {} coins.",
            new_balance_owner,
            amount
        );

        let transaction_id = transaction_id.unwrap_or_else(rand::random);
        let req = Request::CreateBalance {
            new_balance_owner,
            amount,
            transaction_id,
        };
        let (message, requester) = match secret_key {
            Some(key) => (
                sign_request_with_key(req, key),
                Some(PublicKey::from(key.public_key())),
            ),
            None => (self.compose_message(req, true), None),
        };
        send(
            self,
            fry!(message
                .message_id()
                .ok_or_else(|| CoreError::from("Logic error: no message ID found"))),
            move |routing| routing.send(requester, &unwrap!(serialise(&message))),
        )
        .and_then(|event| {
            let res = match event {
                CoreEvent::RpcResponse(res) => res,
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            };
            let result_buffer = unwrap!(res);
            let res: Response = unwrap!(deserialise(&result_buffer));
            match res {
                Response::Transaction(res) => res.map_err(CoreError::from),
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            }
        })
        .into_box()
    }

    /// Insert a given login packet at the specified destination
    fn insert_login_packet_for(
        &self,
        secret_key: Option<&threshold_crypto::SecretKey>,
        new_owner: PublicKey,
        amount: Coins,
        transaction_id: Option<u64>,
        new_login_packet: LoginPacket,
    ) -> Box<CoreFuture<()>> {
        trace!(
            "Insert a login packet for {:?} preloading the wallet with {} coins.",
            new_owner,
            amount
        );

        let transaction_id = transaction_id.unwrap_or_else(rand::random);
        let req = Request::CreateLoginPacketFor {
            new_owner,
            amount,
            transaction_id,
            new_login_packet,
        };
        let (message, requester) = match secret_key {
            Some(key) => (
                sign_request_with_key(req, key),
                Some(PublicKey::from(key.public_key())),
            ),
            None => (self.compose_message(req, true), None),
        };
        send_mutation(
            self,
            fry!(message
                .message_id()
                .ok_or_else(|| CoreError::from("Logic error: no message ID found"))),
            move |routing, _| routing.send(requester, &unwrap!(serialise(&message))),
        )
    }

    /// Get the current coin balance.
    fn get_balance(
        &self,
        secret_key: Option<&threshold_crypto::SecretKey>,
    ) -> Box<CoreFuture<Coins>> {
        let req = Request::GetBalance;
        let (request, requester) = match secret_key {
            Some(key) => (
                sign_request_with_key(req, key),
                Some(PublicKey::from(key.public_key())),
            ),
            None => (self.compose_message(req, true), None),
        };
        trace!(
            "Get balance for {:?}",
            requester.unwrap_or_else(|| unwrap!(self.owner_key()))
        );
        send(
            self,
            fry!(request
                .message_id()
                .ok_or_else(|| CoreError::from("Logic error: no message ID found"))),
            move |routing| routing.send(requester, &unwrap!(serialise(&request))),
        )
        .and_then(|event| {
            let res = match event {
                CoreEvent::RpcResponse(res) => res,
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            };
            let result_buffer = unwrap!(res);
            let res: Response = unwrap!(deserialise(&result_buffer));
            match res {
                Response::GetBalance(res) => res.map_err(CoreError::from),
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            }
        })
        .into_box()
    }

    /// Get published immutable data from the network.
    fn get_pub_idata(&self, name: XorName) -> Box<CoreFuture<PubImmutableData>> {
        trace!("Fetch Published Immutable Data");

        send_new(self, Request::GetIData(IDataAddress::Pub(name)), false)
            .and_then(|event| {
                let res = match event {
                    CoreEvent::RpcResponse(res) => res,
                    _ => Err(CoreError::ReceivedUnexpectedEvent),
                };
                let result_buffer = unwrap!(res);
                let res: Response = unwrap!(deserialise(&result_buffer));
                match res {
                    Response::GetIData(res) => match res {
                        Ok(IData::Pub(data)) => Ok(data),
                        Ok(IData::Unpub(_)) => Err(CoreError::ReceivedUnexpectedData),
                        Err(e) => Err(e).map_err(CoreError::from),
                    },
                    _ => Err(CoreError::ReceivedUnexpectedEvent),
                }
            })
            .into_box()
    }

    /// Put published immutable data to the network.
    fn put_pub_idata(&self, data: PubImmutableData) -> Box<CoreFuture<()>> {
        trace!("Put Published IData at {:?}", data.name());
        send_mutation_new(self, Request::PutIData(data.into()))
    }

    /// Get unpublished immutable data from the network.
    fn get_unpub_idata(&self, name: XorName) -> Box<CoreFuture<UnpubImmutableData>> {
        trace!("Fetch Unpublished Immutable Data");

        send_new(self, Request::GetIData(IDataAddress::Unpub(name)), true)
            .and_then(|event| {
                let res = match event {
                    CoreEvent::RpcResponse(res) => res,
                    _ => Err(CoreError::ReceivedUnexpectedEvent),
                };
                let result_buffer = unwrap!(res);
                let res: Response = unwrap!(deserialise(&result_buffer));
                match res {
                    Response::GetIData(res) => match res {
                        Ok(IData::Unpub(data)) => Ok(data),
                        Ok(IData::Pub(_)) => Err(CoreError::ReceivedUnexpectedData),
                        Err(e) => Err(e).map_err(CoreError::from),
                    },
                    _ => Err(CoreError::ReceivedUnexpectedEvent),
                }
            })
            .into_box()
    }

    /// Put unpublished immutable data to the network.
    fn put_unpub_idata(&self, data: UnpubImmutableData) -> Box<CoreFuture<()>> {
        trace!("Put Unpublished IData at {:?}", data.name());
        send_mutation_new(self, Request::PutIData(data.into()))
    }

    /// Delete unpublished immutable data from the network.
    fn del_unpub_idata(&self, name: XorName) -> Box<CoreFuture<()>> {
        trace!("Delete Unpublished IData at {:?}", name);
        send_mutation_new(self, Request::DeleteUnpubIData(IDataAddress::Unpub(name)))
    }

    /// Put sequenced mutable data to the network
    fn put_seq_mutable_data(&self, data: SeqMutableData) -> Box<CoreFuture<()>> {
        trace!("Put Sequenced MData at {:?}", data.name());
        send_mutation_new(self, Request::PutMData(MData::Seq(data)))
    }

    /// Fetch unpublished mutable data from the network
    fn get_unseq_mdata(&self, name: XorName, tag: u64) -> Box<CoreFuture<UnseqMutableData>> {
        trace!("Fetch Unsequenced Mutable Data");

        send_new(
            self,
            Request::GetMData(MDataAddress::Unseq { name, tag }),
            true,
        )
        .and_then(|event| {
            let res = match event {
                CoreEvent::RpcResponse(res) => res,
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            };
            let result_buffer = unwrap!(res);
            let res: Response = unwrap!(deserialise(&result_buffer));
            match res {
                Response::GetMData(res) => {
                    res.map_err(CoreError::from).and_then(|mdata| match mdata {
                        MData::Unseq(data) => Ok(data),
                        MData::Seq(_) => Err(CoreError::ReceivedUnexpectedData),
                    })
                }
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            }
        })
        .into_box()
    }

    /// Fetch the value for a given key in a sequenced mutable data
    fn get_seq_mdata_value(&self, name: XorName, tag: u64, key: Vec<u8>) -> Box<CoreFuture<Val>> {
        trace!("Fetch MDataValue for {:?}", name);

        send_new(
            self,
            Request::GetMDataValue {
                address: MDataAddress::Seq { name, tag },
                key,
            },
            true,
        )
        .and_then(|event| {
            let res = match event {
                CoreEvent::RpcResponse(res) => res,
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            };
            let result_buffer = unwrap!(res);
            let res: Response = unwrap!(deserialise(&result_buffer));
            match res {
                Response::GetSeqMDataValue(res) => res.map_err(CoreError::from),
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            }
        })
        .into_box()
    }

    /// Fetch the value for a given key in a sequenced mutable data
    fn get_unseq_mdata_value(
        &self,
        name: XorName,
        tag: u64,
        key: Vec<u8>,
    ) -> Box<CoreFuture<Vec<u8>>> {
        trace!("Fetch MDataValue for {:?}", name);

        send_new(
            self,
            Request::GetMDataValue {
                address: MDataAddress::Unseq { name, tag },
                key,
            },
            true,
        )
        .and_then(|event| {
            let res = match event {
                CoreEvent::RpcResponse(res) => res,
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            };
            let result_buffer = unwrap!(res);
            let res: Response = unwrap!(deserialise(&result_buffer));
            match res {
                Response::GetUnseqMDataValue(res) => res.map_err(CoreError::from),
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            }
        })
        .into_box()
    }

    /// Fetch sequenced mutable data from the network
    fn get_seq_mdata(&self, name: XorName, tag: u64) -> Box<CoreFuture<SeqMutableData>> {
        trace!("Fetch Sequenced Mutable Data");

        send_new(
            self,
            Request::GetMData(MDataAddress::Seq { name, tag }),
            true,
        )
        .and_then(|event| {
            let res = match event {
                CoreEvent::RpcResponse(res) => res,
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            };
            let result_buffer = unwrap!(res);
            let res: Response = unwrap!(deserialise(&result_buffer));
            match res {
                Response::GetMData(res) => {
                    res.map_err(CoreError::from).and_then(|mdata| match mdata {
                        MData::Seq(data) => Ok(data),
                        MData::Unseq(_) => Err(CoreError::ReceivedUnexpectedData),
                    })
                }
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            }
        })
        .into_box()
    }

    /// Mutates `MutableData` entries in bulk.
    fn mutate_mdata_entries(
        &self,
        name: XorName,
        tag: u64,
        actions: BTreeMap<Vec<u8>, EntryAction>,
    ) -> Box<CoreFuture<()>> {
        trace!("PutMData for {:?}", name);

        let requester = some_or_err!(self.public_bls_key());
        let msg_id = MessageId::new();
        send_mutation(self, msg_id, move |routing, dst| {
            routing.mutate_mdata_entries(
                dst,
                name,
                tag,
                actions.clone(),
                msg_id,
                PublicKey::from(requester),
            )
        })
    }

    /// Mutates sequenced `MutableData` entries in bulk
    fn mutate_seq_mdata_entries(
        &self,
        name: XorName,
        tag: u64,
        actions: MDataSeqEntryActions,
    ) -> Box<CoreFuture<()>> {
        trace!("Mutate MData for {:?}", name);

        send_mutation_new(
            self,
            Request::MutateSeqMDataEntries {
                address: MDataAddress::Seq { name, tag },
                actions,
            },
        )
    }

    /// Mutates unsequenced `MutableData` entries in bulk
    fn mutate_unseq_mdata_entries(
        &self,
        name: XorName,
        tag: u64,
        actions: MDataUnseqEntryActions,
    ) -> Box<CoreFuture<()>> {
        trace!("Mutate MData for {:?}", name);

        send_mutation_new(
            self,
            Request::MutateUnseqMDataEntries {
                address: MDataAddress::Unseq { name, tag },
                actions,
            },
        )
    }

    /// Get entire `MutableData` from the network.
    fn get_mdata(&self, name: XorName, tag: u64) -> Box<CoreFuture<MutableData>> {
        trace!("GetMData for {:?}", name);

        let msg_id = MessageId::new();
        send(self, msg_id, move |routing| {
            routing.get_mdata(Authority::NaeManager(name), name, tag, msg_id)
        })
        .and_then(|event| match_event!(event, CoreEvent::GetMData))
        .into_box()
    }

    /// Get a shell (bare bones) version of `MutableData` from the network.
    fn get_mdata_shell(&self, name: XorName, tag: u64) -> Box<CoreFuture<MutableData>> {
        trace!("GetMDataShell for {:?}", name);

        let msg_id = MessageId::new();
        send(self, msg_id, move |routing| {
            routing.get_mdata_shell(Authority::NaeManager(name), name, tag, msg_id)
        })
        .and_then(|event| match_event!(event, CoreEvent::GetMDataShell))
        .into_box()
    }

    /// Get a shell (bare bones) version of `MutableData` from the network.
    fn get_seq_mdata_shell(&self, name: XorName, tag: u64) -> Box<CoreFuture<SeqMutableData>> {
        trace!("GetMDataShell for {:?}", name);

        send_new(
            self,
            Request::GetMDataShell(MDataAddress::Seq { name, tag }),
            true,
        )
        .and_then(|event| {
            let res = match event {
                CoreEvent::RpcResponse(res) => res,
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            };
            let result_buffer = unwrap!(res);
            let res: Response = unwrap!(deserialise(&result_buffer));
            match res {
                Response::GetMDataShell(res) => {
                    res.map_err(CoreError::from).and_then(|mdata| match mdata {
                        MData::Seq(data) => Ok(data),
                        _ => Err(CoreError::ReceivedUnexpectedData),
                    })
                }
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            }
        })
        .into_box()
    }

    /// Get a shell (bare bones) version of `MutableData` from the network.
    fn get_unseq_mdata_shell(&self, name: XorName, tag: u64) -> Box<CoreFuture<UnseqMutableData>> {
        trace!("GetMDataShell for {:?}", name);

        send_new(
            self,
            Request::GetMDataShell(MDataAddress::Unseq { name, tag }),
            true,
        )
        .and_then(|event| {
            let res = match event {
                CoreEvent::RpcResponse(res) => res,
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            };
            let result_buffer = unwrap!(res);
            let res: Response = unwrap!(deserialise(&result_buffer));
            match res {
                Response::GetMDataShell(res) => {
                    res.map_err(CoreError::from).and_then(|mdata| match mdata {
                        MData::Unseq(data) => Ok(data),
                        _ => Err(CoreError::ReceivedUnexpectedData),
                    })
                }
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            }
        })
        .into_box()
    }

    /// Get a current version of `MutableData` from the network.
    fn get_mdata_version_new(&self, address: MDataAddress) -> Box<CoreFuture<u64>> {
        trace!("GetMDataVersion for {:?}", address);

        send_new(self, Request::GetMDataVersion(address), true)
            .and_then(|event| {
                let res = match event {
                    CoreEvent::RpcResponse(res) => res,
                    _ => Err(CoreError::ReceivedUnexpectedEvent),
                };
                let result_buffer = unwrap!(res);
                let res: Response = unwrap!(deserialise(&result_buffer));
                match res {
                    Response::GetMDataVersion(res) => res.map_err(CoreError::from),
                    _ => Err(CoreError::ReceivedUnexpectedEvent),
                }
            })
            .into_box()
    }

    /// Get a current version of `MutableData` from the network.
    fn get_mdata_version(&self, name: XorName, tag: u64) -> Box<CoreFuture<u64>> {
        trace!("GetMDataVersion for {:?}", name);

        let msg_id = MessageId::new();
        send(self, msg_id, move |routing| {
            routing.get_mdata_version(Authority::NaeManager(name), name, tag, msg_id)
        })
        .and_then(|event| match_event!(event, CoreEvent::GetMDataVersion))
        .into_box()
    }

    /// Return a complete list of entries in `MutableData`.
    fn list_mdata_entries(
        &self,
        name: XorName,
        tag: u64,
    ) -> Box<CoreFuture<BTreeMap<Vec<u8>, Value>>> {
        trace!("ListMDataEntries for {:?}", name);

        let msg_id = MessageId::new();
        send(self, msg_id, move |routing| {
            routing.list_mdata_entries(Authority::NaeManager(name), name, tag, msg_id)
        })
        .and_then(|event| match_event!(event, CoreEvent::ListMDataEntries))
        .into_box()
    }

    /// Return a complete list of entries in `MutableData`.
    fn list_unseq_mdata_entries(
        &self,
        name: XorName,
        tag: u64,
    ) -> Box<CoreFuture<BTreeMap<Vec<u8>, Vec<u8>>>> {
        trace!("ListMDataEntries for {:?}", name);

        send_new(
            self,
            Request::ListMDataEntries(MDataAddress::Unseq { name, tag }),
            true,
        )
        .and_then(|event| {
            let res = match event {
                CoreEvent::RpcResponse(res) => res,
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            };
            let result_buffer = unwrap!(res);
            let res: Response = unwrap!(deserialise(&result_buffer));
            match res {
                Response::ListUnseqMDataEntries(res) => res.map_err(CoreError::from),
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            }
        })
        .into_box()
    }

    /// Return a complete list of entries in `MutableData`.
    fn list_seq_mdata_entries(
        &self,
        name: XorName,
        tag: u64,
    ) -> Box<CoreFuture<BTreeMap<Vec<u8>, Val>>> {
        trace!("ListSeqMDataEntries for {:?}", name);

        send_new(
            self,
            Request::ListMDataEntries(MDataAddress::Seq { name, tag }),
            true,
        )
        .and_then(|event| {
            let res = match event {
                CoreEvent::RpcResponse(res) => res,
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            };
            let result_buffer = unwrap!(res);
            let res: Response = unwrap!(deserialise(&result_buffer));
            match res {
                Response::ListSeqMDataEntries(res) => res.map_err(CoreError::from),
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            }
        })
        .into_box()
    }

    /// Return a list of keys in `MutableData` stored on the network.
    fn list_mdata_keys(&self, name: XorName, tag: u64) -> Box<CoreFuture<BTreeSet<Vec<u8>>>> {
        trace!("ListMDataKeys for {:?}", name);

        let msg_id = MessageId::new();
        send(self, msg_id, move |routing| {
            routing.list_mdata_keys(Authority::NaeManager(name), name, tag, msg_id)
        })
        .and_then(|event| match_event!(event, CoreEvent::ListMDataKeys))
        .into_box()
    }

    /// Return a list of keys in `MutableData` stored on the network.
    fn list_mdata_keys_new(&self, address: MDataAddress) -> Box<CoreFuture<BTreeSet<Vec<u8>>>> {
        trace!("ListMDataKeys for {:?}", address);

        send_new(self, Request::ListMDataKeys(address), true)
            .and_then(|event| {
                let res = match event {
                    CoreEvent::RpcResponse(res) => res,
                    _ => Err(CoreError::ReceivedUnexpectedEvent),
                };
                let result_buffer = unwrap!(res);
                let res: Response = unwrap!(deserialise(&result_buffer));
                match res {
                    Response::ListMDataKeys(res) => res.map_err(CoreError::from),
                    _ => Err(CoreError::ReceivedUnexpectedEvent),
                }
            })
            .into_box()
    }

    /// Return a list of values in a Sequenced Mutable Data
    fn list_seq_mdata_values(&self, name: XorName, tag: u64) -> Box<CoreFuture<Vec<Val>>> {
        trace!("List MDataValues for {:?}", name);

        send_new(
            self,
            Request::ListMDataValues(MDataAddress::Seq { name, tag }),
            true,
        )
        .and_then(|event| {
            let res = match event {
                CoreEvent::RpcResponse(res) => res,
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            };
            let result_buffer = unwrap!(res);
            let res: Response = unwrap!(deserialise(&result_buffer));
            match res {
                Response::ListSeqMDataValues(res) => res.map_err(CoreError::from),
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            }
        })
        .into_box()
    }

    /// Return the permissions set for a particular user
    fn list_mdata_user_permissions_new(
        &self,
        address: MDataAddress,
        user: PublicKey,
    ) -> Box<CoreFuture<NewPermissionSet>> {
        trace!("GetMDataUserPermissions for {:?}", address);

        send_new(
            self,
            Request::ListMDataUserPermissions { address, user },
            true,
        )
        .and_then(|event| {
            let res = match event {
                CoreEvent::RpcResponse(res) => res,
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            };
            let result_buffer = unwrap!(res);
            let res: Response = unwrap!(deserialise(&result_buffer));
            match res {
                Response::ListMDataUserPermissions(res) => res.map_err(CoreError::from),
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            }
        })
        .into_box()
    }

    /// Returns a list of values in an Unsequenced Mutable Data
    fn list_unseq_mdata_values(&self, name: XorName, tag: u64) -> Box<CoreFuture<Vec<Vec<u8>>>> {
        trace!("List MDataValues for {:?}", name);

        send_new(
            self,
            Request::ListMDataValues(MDataAddress::Unseq { name, tag }),
            true,
        )
        .and_then(|event| {
            let res = match event {
                CoreEvent::RpcResponse(res) => res,
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            };
            let result_buffer = unwrap!(res);
            let res: Response = unwrap!(deserialise(&result_buffer));
            match res {
                Response::ListUnseqMDataValues(res) => res.map_err(CoreError::from),
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            }
        })
        .into_box()
    }

    /// Return a list of keys in `MutableData` stored on the network.
    fn list_mdata_values(&self, name: XorName, tag: u64) -> Box<CoreFuture<Vec<Value>>> {
        trace!("ListMDataValues for {:?}", name);

        let msg_id = MessageId::new();
        send(self, msg_id, move |routing| {
            routing.list_mdata_values(Authority::NaeManager(name), name, tag, msg_id)
        })
        .and_then(|event| match_event!(event, CoreEvent::ListMDataValues))
        .into_box()
    }

    /// Get a single entry from `MutableData`.
    fn get_mdata_value(&self, name: XorName, tag: u64, key: Vec<u8>) -> Box<CoreFuture<Value>> {
        trace!("GetMDataValue for {:?}", name);

        let msg_id = MessageId::new();
        send(self, msg_id, move |routing| {
            routing.get_mdata_value(Authority::NaeManager(name), name, tag, key.clone(), msg_id)
        })
        .and_then(|event| match_event!(event, CoreEvent::GetMDataValue))
        .into_box()
    }
    // ======= Append Only Data =======
    //
    /// Put AppendOnly Data into the Network
    fn put_adata(&self, data: AData) -> Box<CoreFuture<()>> {
        trace!("Put AppendOnly Data {:?}", data.name());
        send_mutation_new(self, Request::PutAData(data))
    }

    /// Get AppendOnly Data from the Network
    fn get_adata(&self, address: ADataAddress) -> Box<CoreFuture<AData>> {
        trace!("Get AppendOnly Data at {:?}", address.name());

        send_new(self, Request::GetAData(address), address.is_unpub())
            .and_then(|event| {
                let res = match event {
                    CoreEvent::RpcResponse(res) => res,
                    _ => Err(CoreError::ReceivedUnexpectedEvent),
                };
                let result_buffer = unwrap!(res);
                let res: Response = unwrap!(deserialise(&result_buffer));
                match res {
                    Response::GetAData(res) => res.map_err(CoreError::from),
                    _ => Err(CoreError::ReceivedUnexpectedEvent),
                }
            })
            .into_box()
    }

    /// Delete AData from network.
    fn delete_adata(&self, address: ADataAddress) -> Box<CoreFuture<()>> {
        send_mutation_new(self, Request::DeleteAData(address))
    }

    /// Get AppendOnly Data Shell from the Network
    fn get_adata_shell(
        &self,
        data_index: ADataIndex,
        address: ADataAddress,
    ) -> Box<CoreFuture<AData>> {
        trace!("Get AppendOnly Data at {:?}", address.name());

        send_new(
            self,
            Request::GetADataShell {
                address,
                data_index,
            },
            address.is_unpub(),
        )
        .and_then(|event| {
            let res = match event {
                CoreEvent::RpcResponse(res) => res,
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            };
            let result_buffer = unwrap!(res);
            let res: Response = unwrap!(deserialise(&result_buffer));
            match res {
                Response::GetADataShell(res) => res.map_err(CoreError::from),
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            }
        })
        .into_box()
    }

    /// Fetch Value for the provided key from AppendOnly Data at {:?}
    fn get_adata_value(&self, address: ADataAddress, key: Vec<u8>) -> Box<CoreFuture<Vec<u8>>> {
        trace!(
            "Fetch Value for the provided key from AppendOnly Data at {:?}",
            address.name()
        );

        send_new(
            self,
            Request::GetADataValue { address, key },
            address.is_unpub(),
        )
        .and_then(|event| {
            let res = match event {
                CoreEvent::RpcResponse(res) => res,
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            };
            let result_buffer = unwrap!(res);
            let res: Response = unwrap!(deserialise(&result_buffer));
            match res {
                Response::GetADataValue(res) => res.map_err(CoreError::from),
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            }
        })
        .into_box()
    }

    /// Get a Set of Entries for the requested range from an AData.
    fn get_adata_range(
        &self,
        address: ADataAddress,
        range: (ADataIndex, ADataIndex),
    ) -> Box<CoreFuture<ADataEntries>> {
        trace!(
            "Get Range of entries from AppendOnly Data at {:?}",
            address.name()
        );

        send_new(
            self,
            Request::GetADataRange { address, range },
            address.is_unpub(),
        )
        .and_then(|event| {
            let res = match event {
                CoreEvent::RpcResponse(res) => res,
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            };
            let result_buffer = unwrap!(res);
            let res: Response = unwrap!(deserialise(&result_buffer));
            match res {
                Response::GetADataRange(res) => res.map_err(CoreError::from),
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            }
        })
        .into_box()
    }

    /// Get latest indices from an AppendOnly Data.
    fn get_adata_indices(&self, address: ADataAddress) -> Box<CoreFuture<ADataIndices>> {
        trace!(
            "Get latest indices from AppendOnly Data at {:?}",
            address.name()
        );

        send_new(self, Request::GetADataIndices(address), address.is_unpub())
            .and_then(|event| {
                let res = match event {
                    CoreEvent::RpcResponse(res) => res,
                    _ => Err(CoreError::ReceivedUnexpectedEvent),
                };
                let result_buffer = unwrap!(res);
                let res: Response = unwrap!(deserialise(&result_buffer));
                match res {
                    Response::GetADataIndices(res) => res.map_err(CoreError::from),
                    _ => Err(CoreError::ReceivedUnexpectedEvent),
                }
            })
            .into_box()
    }

    /// Get the last data entry from an AppendOnly Data.
    fn get_adata_last_entry(&self, address: ADataAddress) -> Box<CoreFuture<ADataEntry>> {
        trace!(
            "Get latest indices from AppendOnly Data at {:?}",
            address.name()
        );

        send_new(
            self,
            Request::GetADataLastEntry(address),
            address.is_unpub(),
        )
        .and_then(|event| {
            let res = match event {
                CoreEvent::RpcResponse(res) => res,
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            };
            let result_buffer = unwrap!(res);
            let res: Response = unwrap!(deserialise(&result_buffer));
            match res {
                Response::GetADataLastEntry(res) => res.map_err(CoreError::from),
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            }
        })
        .into_box()
    }

    /// Get permissions at the provided index.
    fn get_unpub_adata_permissions_at_index(
        &self,
        address: ADataAddress,
        permissions_index: ADataIndex,
    ) -> Box<CoreFuture<ADataUnpubPermissions>> {
        trace!(
            "Get latest indices from AppendOnly Data at {:?}",
            address.name()
        );

        send_new(
            self,
            Request::GetADataPermissions {
                address,
                permissions_index,
            },
            true,
        )
        .and_then(|event| {
            let res = match event {
                CoreEvent::RpcResponse(res) => res,
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            };
            let result_buffer = unwrap!(res);
            let res: Response = unwrap!(deserialise(&result_buffer));
            match res {
                Response::GetUnpubADataPermissionAtIndex(res) => res.map_err(CoreError::from),
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            }
        })
        .into_box()
    }

    /// Get permissions at the provided index.
    fn get_pub_adata_permissions_at_index(
        &self,
        address: ADataAddress,
        permissions_index: ADataIndex,
    ) -> Box<CoreFuture<ADataPubPermissions>> {
        trace!(
            "Get latest indices from AppendOnly Data at {:?}",
            address.name()
        );

        send_new(
            self,
            Request::GetADataPermissions {
                address,
                permissions_index,
            },
            false,
        )
        .and_then(|event| {
            let res = match event {
                CoreEvent::RpcResponse(res) => res,
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            };
            let result_buffer = unwrap!(res);
            let res: Response = unwrap!(deserialise(&result_buffer));
            match res {
                Response::GetPubADataPermissionAtIndex(res) => res.map_err(CoreError::from),
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            }
        })
        .into_box()
    }

    /// Get permissions for a specified user(s).
    fn get_pub_adata_user_permissions(
        &self,
        address: ADataAddress,
        permissions_index: ADataIndex,
        user: ADataUser,
    ) -> Box<CoreFuture<ADataPubPermissionSet>> {
        trace!(
            "Get permissions for a specified user(s) from AppendOnly Data at {:?}",
            address.name()
        );

        send_new(
            self,
            Request::GetPubADataUserPermissions {
                address,
                permissions_index,
                user,
            },
            false,
        )
        .and_then(|event| {
            let res = match event {
                CoreEvent::RpcResponse(res) => res,
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            };
            let result_buffer = unwrap!(res);
            let res: Response = unwrap!(deserialise(&result_buffer));
            match res {
                Response::GetPubADataUserPermissions(res) => res.map_err(CoreError::from),
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            }
        })
        .into_box()
    }

    /// Get permissions for a specified user(s).
    fn get_unpub_adata_user_permissions(
        &self,
        address: ADataAddress,
        permissions_index: ADataIndex,
        public_key: PublicKey,
    ) -> Box<CoreFuture<ADataUnpubPermissionSet>> {
        trace!(
            "Get permissions for a specified user(s) from AppendOnly Data at {:?}",
            address.name()
        );

        send_new(
            self,
            Request::GetUnpubADataUserPermissions {
                address,
                permissions_index,
                public_key,
            },
            true,
        )
        .and_then(|event| {
            let res = match event {
                CoreEvent::RpcResponse(res) => res,
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            };
            let result_buffer = unwrap!(res);
            let res: Response = unwrap!(deserialise(&result_buffer));
            match res {
                Response::GetUnpubADataUserPermissions(res) => res.map_err(CoreError::from),
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            }
        })
        .into_box()
    }

    /// Add AData Permissions
    fn add_unpub_adata_permissions(
        &self,
        address: ADataAddress,
        permissions: ADataUnpubPermissions,
        permissions_idx: u64,
    ) -> Box<CoreFuture<()>> {
        trace!(
            "Add Permissions to UnPub AppendOnly Data {:?}",
            address.name()
        );

        send_mutation_new(
            self,
            Request::AddUnpubADataPermissions {
                address,
                permissions,
                permissions_idx,
            },
        )
    }

    /// Add Pub AData Permissions
    fn add_pub_adata_permissions(
        &self,
        address: ADataAddress,
        permissions: ADataPubPermissions,
        permissions_idx: u64,
    ) -> Box<CoreFuture<()>> {
        trace!("Add Permissions to AppendOnly Data {:?}", address.name());

        send_mutation_new(
            self,
            Request::AddPubADataPermissions {
                address,
                permissions,
                permissions_idx,
            },
        )
    }

    /// Set new Owners to AData
    fn set_adata_owners(
        &self,
        address: ADataAddress,
        owner: ADataOwner,
        owners_idx: u64,
    ) -> Box<CoreFuture<()>> {
        trace!("Set Owners to AppendOnly Data {:?}", address.name());

        send_mutation_new(
            self,
            Request::SetADataOwner {
                address,
                owner,
                owners_idx,
            },
        )
    }

    /// Set new Owners to AData
    fn get_adata_owners(
        &self,
        address: ADataAddress,
        owners_index: ADataIndex,
    ) -> Box<CoreFuture<ADataOwner>> {
        trace!("Get Owners from AppendOnly Data at {:?}", address.name());

        send_new(
            self,
            Request::GetADataOwners {
                address,
                owners_index,
            },
            address.is_unpub(),
        )
        .and_then(|event| {
            let res = match event {
                CoreEvent::RpcResponse(res) => res,
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            };
            let result_buffer = unwrap!(res);
            let res: Response = unwrap!(deserialise(&result_buffer));
            match res {
                Response::GetADataOwners(res) => res.map_err(CoreError::from),
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            }
        })
        .into_box()
    }

    /// Append to Published Seq AppendOnly Data
    fn append_seq_adata(&self, append: ADataAppend, index: u64) -> Box<CoreFuture<()>> {
        send_mutation_new(self, Request::AppendSeq { append, index })
    }

    /// Append to Unpublished Unseq AppendOnly Data
    fn append_unseq_adata(&self, append: ADataAppend) -> Box<CoreFuture<()>> {
        send_mutation_new(self, Request::AppendUnseq(append))
    }

    /// Return a list of permissions in `MutableData` stored on the network.
    fn list_mdata_permissions(
        &self,
        name: XorName,
        tag: u64,
    ) -> Box<CoreFuture<BTreeMap<User, PermissionSet>>> {
        trace!("ListMDataPermissions for {:?}", name);

        let msg_id = MessageId::new();
        send(self, msg_id, move |routing| {
            routing.list_mdata_permissions(Authority::NaeManager(name), name, tag, msg_id)
        })
        .and_then(|event| match_event!(event, CoreEvent::ListMDataPermissions))
        .into_box()
    }

    /// Return a list of permissions in `MutableData` stored on the network.
    fn list_mdata_permissions_new(
        &self,
        address: MDataAddress,
    ) -> Box<CoreFuture<BTreeMap<PublicKey, NewPermissionSet>>> {
        trace!("List MDataPermissions for {:?}", address);

        send_new(self, Request::ListMDataPermissions(address), true)
            .and_then(|event| {
                let res = match event {
                    CoreEvent::RpcResponse(res) => res,
                    _ => Err(CoreError::ReceivedUnexpectedEvent),
                };
                let result_buffer = unwrap!(res);
                let res: Response = unwrap!(deserialise(&result_buffer));
                match res {
                    Response::ListMDataPermissions(res) => res.map_err(CoreError::from),
                    _ => Err(CoreError::ReceivedUnexpectedEvent),
                }
            })
            .into_box()
    }

    /// Return a list of permissions for a particular User in MutableData.
    fn list_mdata_user_permissions(
        &self,
        name: XorName,
        tag: u64,
        user: User,
    ) -> Box<CoreFuture<PermissionSet>> {
        trace!("ListMDataUserPermissions for {:?}", name);

        let msg_id = MessageId::new();
        send(self, msg_id, move |routing| {
            let dst = Authority::NaeManager(name);
            routing.list_mdata_user_permissions(dst, name, tag, user, msg_id)
        })
        .and_then(|event| match_event!(event, CoreEvent::ListMDataUserPermissions))
        .into_box()
    }

    /// Updates or inserts a permission set for a given user
    fn set_mdata_user_permissions(
        &self,
        name: XorName,
        tag: u64,
        user: User,
        permissions: PermissionSet,
        version: u64,
    ) -> Box<CoreFuture<()>> {
        trace!("SetMDataUserPermissions for {:?}", name);

        let requester = some_or_err!(self.public_bls_key());
        let msg_id = MessageId::new();
        send_mutation(self, msg_id, move |routing, dst| {
            routing.set_mdata_user_permissions(
                dst,
                name,
                tag,
                user,
                permissions,
                version,
                msg_id,
                PublicKey::from(requester),
            )
        })
    }

    /// Updates or inserts a permissions set for a user
    fn set_mdata_user_permissions_new(
        &self,
        address: MDataAddress,
        user: PublicKey,
        permissions: NewPermissionSet,
        version: u64,
    ) -> Box<CoreFuture<()>> {
        trace!("SetMDataUserPermissions for {:?}", address);

        send_mutation_new(
            self,
            Request::SetMDataUserPermissions {
                address,
                user,
                permissions: permissions.clone(),
                version,
            },
        )
    }

    /// Updates or inserts a permissions set for a user
    fn del_mdata_user_permissions_new(
        &self,
        address: MDataAddress,
        user: PublicKey,
        version: u64,
    ) -> Box<CoreFuture<()>> {
        trace!("DelMDataUserPermissions for {:?}", address);

        send_mutation_new(
            self,
            Request::DelMDataUserPermissions {
                address,
                user,
                version,
            },
        )
    }

    /// Deletes a permission set for a given user
    fn del_mdata_user_permissions(
        &self,
        name: XorName,
        tag: u64,
        user: User,
        version: u64,
    ) -> Box<CoreFuture<()>> {
        trace!("DelMDataUserPermissions for {:?}", name);

        let requester = some_or_err!(self.public_bls_key());
        let msg_id = MessageId::new();
        send_mutation(self, msg_id, move |routing, dst| {
            routing.del_mdata_user_permissions(
                dst,
                name,
                tag,
                user,
                version,
                msg_id,
                PublicKey::from(requester),
            )
        })
    }

    /// Sends an ownership transfer request.
    fn change_mdata_owner(
        &self,
        name: XorName,
        tag: u64,
        new_owner: PublicKey,
        version: u64,
    ) -> Box<CoreFuture<()>> {
        trace!("ChangeMDataOwner for {:?}", name);

        let msg_id = MessageId::new();
        send_mutation(self, msg_id, move |routing, dst| {
            routing.change_mdata_owner(dst, name, tag, btree_set![new_owner], version, msg_id)
        })
    }

    #[cfg(any(
        all(test, feature = "mock-network"),
        all(feature = "testing", feature = "mock-network")
    ))]
    #[doc(hidden)]
    fn set_network_limits(&self, max_ops_count: Option<u64>) {
        let inner = self.inner();
        inner.borrow_mut().routing.set_network_limits(max_ops_count);
    }

    #[cfg(any(
        all(test, feature = "mock-network"),
        all(feature = "testing", feature = "mock-network")
    ))]
    #[doc(hidden)]
    fn simulate_network_disconnect(&self) {
        let inner = self.inner();
        inner.borrow_mut().routing.simulate_disconnect();
    }

    #[cfg(any(
        all(test, feature = "mock-network"),
        all(feature = "testing", feature = "mock-network")
    ))]
    #[doc(hidden)]
    fn set_simulate_timeout(&self, enabled: bool) {
        let inner = self.inner();
        inner.borrow_mut().routing.set_simulate_timeout(enabled);
    }

    /// Create a new mock balance at an arbitrary address.
    #[cfg(any(
        all(test, feature = "mock-network"),
        all(feature = "testing", feature = "mock-network")
    ))]
    fn test_create_balance(&self, owner: PublicKey, amount: Coins) {
        let inner = self.inner();
        inner.borrow_mut().routing.create_balance(owner, amount);
    }

    /// Add coins to a coinbalance for testing
    #[cfg(any(
        all(test, feature = "mock-network"),
        all(feature = "testing", feature = "mock-network")
    ))]
    fn allocate_test_coins(
        &self,
        coin_balance_name: &XorName,
        amount: Coins,
    ) -> Result<(), SndError> {
        let inner = self.inner();
        let result = inner
            .borrow_mut()
            .routing
            .allocate_test_coins(coin_balance_name, amount);
        result.clone()
    }
}

/// Get the balance at the given key's location
pub fn wallet_get_balance(wallet_sk: &threshold_crypto::SecretKey) -> Result<Coins, SndError> {
    trace!("Get balance for {:?}", wallet_sk);
    let client_pk = PublicKey::from(wallet_sk.public_key());
    let (mut routing, routing_rx) = setup_routing(
        None,
        PublicId::Client(ClientPublicId::new(client_pk.into(), client_pk)),
        None,
    )
    .map_err(|_| SndError::from("Routing error"))?;

    let full_id = NewFullId::Client(ClientFullId::with_bls_key(wallet_sk.clone()));
    let rpc_response = routing.req(&routing_rx, Request::GetBalance, &full_id);
    match rpc_response {
        Response::GetBalance(res) => res,
        _ => Err(SndError::from("Unexpected response")),
    }
}

/// Creates a new coin balance on the network.
pub fn wallet_create_balance(
    secret_key: &threshold_crypto::SecretKey,
    new_balance_owner: PublicKey,
    amount: Coins,
    transaction_id: Option<u64>,
) -> Result<Transaction, SndError> {
    trace!(
        "Create a new coin balance for {:?} with {} coins.",
        new_balance_owner,
        amount
    );

    let transaction_id = transaction_id.unwrap_or_else(rand::random);
    let req = Request::CreateBalance {
        new_balance_owner,
        amount,
        transaction_id,
    };
    let client_pk = PublicKey::from(secret_key.public_key());
    let (mut routing, routing_rx) = setup_routing(
        None,
        PublicId::Client(ClientPublicId::new(client_pk.into(), client_pk)),
        None,
    )
    .map_err(|_| SndError::from("Routing error"))?;
    let client_full_id = NewFullId::Client(ClientFullId::with_bls_key(secret_key.clone()));
    let rpc_response = routing.req(&routing_rx, req, &client_full_id);
    match rpc_response {
        Response::Transaction(res) => res,
        _ => Err(SndError::from("Unexpected response")),
    }
}

/// Transfer coins
pub fn wallet_transfer_coins(
    secret_key: &threshold_crypto::SecretKey,
    destination: XorName,
    amount: Coins,
    transaction_id: Option<u64>,
) -> Result<Transaction, SndError> {
    trace!("Transfer {} coins to {:?}", amount, destination);
    let transaction_id = transaction_id.unwrap_or_else(rand::random);
    let req = Request::TransferCoins {
        destination,
        amount,
        transaction_id,
    };

    let client_pk = PublicKey::from(secret_key.public_key());
    let (mut routing, routing_rx) = setup_routing(
        None,
        PublicId::Client(ClientPublicId::new(client_pk.into(), client_pk)),
        None,
    )
    .map_err(|_| SndError::from("Routing error"))?;

    let client_full_id = NewFullId::Client(ClientFullId::with_bls_key(secret_key.clone()));
    let rpc_response = routing.req(&routing_rx, req, &client_full_id);
    match rpc_response {
        Response::Transaction(res) => res,
        _ => Err(SndError::from("Unexpected response")),
    }
}

/// This trait implements functions that are supposed to be called only by CoreClient and AuthClient.
/// Applications are not allowed to DELETE MData and get/mutate auth keys, hence AppClient does not implement
/// this trait.
pub trait AuthActions: Client + Clone + 'static {
    /// Fetches a list of authorised keys and version.
    fn list_auth_keys_and_version(
        &self,
    ) -> Box<CoreFuture<(BTreeMap<PublicKey, AppPermissions>, u64)>> {
        trace!("ListAuthKeysAndVersion");

        send_new(self, Request::ListAuthKeysAndVersion, true)
            .and_then(|event| {
                let res = match event {
                    CoreEvent::RpcResponse(res) => res,
                    _ => Err(CoreError::ReceivedUnexpectedEvent),
                };
                let result_buffer = unwrap!(res);
                let res: Response = unwrap!(deserialise(&result_buffer));
                match res {
                    Response::ListAuthKeysAndVersion(res) => res.map_err(CoreError::from),
                    _ => Err(CoreError::ReceivedUnexpectedEvent),
                }
            })
            .into_box()
    }

    /// Adds a new authorised key.
    fn ins_auth_key(
        &self,
        key: PublicKey,
        permissions: AppPermissions,
        version: u64,
    ) -> Box<CoreFuture<()>> {
        trace!("InsAuthKey ({:?})", key);

        send_mutation_new(
            self,
            Request::InsAuthKey {
                key,
                permissions,
                version,
            },
        )
    }

    /// Removes an authorised key.
    fn del_auth_key(&self, key: PublicKey, version: u64) -> Box<CoreFuture<()>> {
        trace!("DelAuthKey ({:?})", key);

        send_mutation_new(self, Request::DelAuthKey { key, version })
    }

    /// Delete MData from network
    fn delete_mdata(&self, address: MDataAddress) -> Box<CoreFuture<()>> {
        trace!("Delete entire Mutable Data at {:?}", address);

        send_mutation_new(self, Request::DeleteMData(address))
    }
}

fn sign_request_with_key(request: Request, key: &threshold_crypto::SecretKey) -> Message {
    let message_id = MessageId::new();

    let signature = Some(Signature::from(
        key.sign(&unwrap!(bincode::serialize(&(&request, message_id)))),
    ));

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
pub struct ClientInner<C: Client, T> {
    el_handle: Handle,
    routing: Routing,
    hooks: HashMap<MessageId, Complete<CoreEvent>>,
    cache: LruCache<XorName, PubImmutableData>,
    timeout: Duration,
    joiner: Joiner,
    core_tx: CoreMsgTx<C, T>,
    net_tx: NetworkTx,
}

impl<C: Client, T> ClientInner<C, T> {
    /// Create a new `ClientInner` object.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        el_handle: Handle,
        routing: Routing,
        hooks: HashMap<MessageId, Complete<CoreEvent>>,
        cache: LruCache<XorName, PubImmutableData>,
        timeout: Duration,
        joiner: Joiner,
        core_tx: CoreMsgTx<C, T>,
        net_tx: NetworkTx,
    ) -> ClientInner<C, T> {
        ClientInner {
            el_handle,
            routing,
            hooks,
            cache,
            timeout,
            joiner,
            core_tx,
            net_tx,
        }
    }
}

/// Spawn a routing thread and run the routing event loop.
pub fn spawn_routing_thread<C, T>(
    routing_rx: Receiver<Event>,
    core_tx: CoreMsgTx<C, T>,
    net_tx: NetworkTx,
) -> Joiner
where
    C: Client,
    T: 'static,
{
    thread::named("Routing Event Loop", move || {
        routing_event_loop::run(&routing_rx, core_tx, &net_tx)
    })
}

/// Set up routing given a Client `full_id` and optional `config` and connect to the network.
pub fn setup_routing(
    full_id: Option<FullId>,
    public_id: PublicId,
    config: Option<BootstrapConfig>,
) -> Result<(Routing, Receiver<Event>), CoreError> {
    let (routing_tx, routing_rx) = mpsc::channel();
    let routing = Routing::new(
        routing_tx,
        full_id,
        public_id,
        config,
        Duration::from_secs(REQUEST_TIMEOUT_SECS),
    )?;

    trace!("Waiting to get connected to the Network...");
    match routing_rx.recv_timeout(Duration::from_secs(CONNECTION_TIMEOUT_SECS)) {
        Ok(Event::Connected) => (),
        Ok(Event::Terminate) => {
            // TODO: Consider adding a separate error type for this
            return Err(CoreError::from(
                "Could not connect to the SAFE Network".to_string(),
            ));
        }
        Err(RecvTimeoutError::Timeout) => {
            return Err(CoreError::RequestTimeout);
        }
        x => {
            warn!("Could not connect to the Network. Unexpected: {:?}", x);
            // TODO: we should return more descriptive error here
            return Err(CoreError::OperationAborted);
        }
    }
    trace!("Connected to the Network.");

    Ok((routing, routing_rx))
}

// `sign` should be false for GETs on published data, true otherwise.
fn send_new(client: &impl Client, request: Request, sign: bool) -> Box<CoreFuture<CoreEvent>> {
    let request = client.compose_message(request, sign);

    send(
        client,
        fry!(request
            .message_id()
            .ok_or_else(|| CoreError::from("Logic error: no message ID found"))),
        move |routing| routing.send(None, &unwrap!(serialise(&request))),
    )
}

/// Send a request and return a future that resolves to the response.
fn send<F>(client: &impl Client, msg_id: MessageId, req: F) -> Box<CoreFuture<CoreEvent>>
where
    F: Fn(&mut Routing) -> Result<(), InterfaceError> + 'static,
{
    let inner = Rc::downgrade(&client.inner());
    let func = move |_| {
        if let Some(inner) = inner.upgrade() {
            if let Err(error) = req(&mut inner.borrow_mut().routing) {
                return future::err(CoreError::from(error)).into_box();
            }

            let (hook, rx) = oneshot::channel();
            let _ = inner.borrow_mut().hooks.insert(msg_id, hook);

            let rx = rx.map_err(|_| CoreError::OperationAborted);
            let rx = setup_timeout_and_retry_delay(&inner, msg_id, rx);
            let rx = rx.map(|event| {
                if let CoreEvent::RateLimitExceeded = event {
                    Loop::Continue(())
                } else {
                    Loop::Break(event)
                }
            });
            rx.into_box()
        } else {
            future::err(CoreError::OperationAborted).into_box()
        }
    };

    future::loop_fn((), func).into_box()
}

/// Sends a mutation request to a new routing.
fn send_mutation_new(client: &impl Client, req: Request) -> Box<CoreFuture<()>> {
    let message = client.compose_message(req, true);

    send_mutation(
        client,
        fry!(message
            .message_id()
            .ok_or_else(|| CoreError::from("Logic error: no message ID found"))),
        move |routing, _| routing.send(None, &unwrap!(serialise(&message))),
    )
}

/// Sends a mutation request.
fn send_mutation<F>(client: &impl Client, msg_id: MessageId, req: F) -> Box<CoreFuture<()>>
where
    F: Fn(&mut Routing, Authority<XorName>) -> Result<(), InterfaceError> + 'static,
{
    let dst = some_or_err!(client.cm_addr());

    send(client, msg_id, move |routing| req(routing, dst))
        .and_then(|event| match event {
            CoreEvent::RpcResponse(res) => {
                let response_buffer = unwrap!(res);
                let response: Response = unwrap!(deserialise(&response_buffer));
                match response {
                    Response::Mutation(res) => res.map_err(CoreError::from),
                    _ => Err(CoreError::ReceivedUnexpectedEvent),
                }
            }
            CoreEvent::Mutation(res) => res,
            _ => Err(CoreError::ReceivedUnexpectedEvent),
        })
        .into_box()
}

fn setup_timeout_and_retry_delay<C, T, F>(
    inner: &Rc<RefCell<ClientInner<C, T>>>,
    msg_id: MessageId,
    future: F,
) -> Box<CoreFuture<CoreEvent>>
where
    C: Client,
    F: Future<Item = CoreEvent, Error = CoreError> + 'static,
    T: 'static,
{
    // Delay after rate limit exceeded.
    let inner_weak = Rc::downgrade(inner);
    let future = future.and_then(move |event| {
        if let CoreEvent::RateLimitExceeded = event {
            if let Some(inner) = inner_weak.upgrade() {
                let delay = Duration::from_millis(RETRY_DELAY_MS);
                let fut = timeout(delay, &inner.borrow().el_handle).or_else(move |_| Ok(event));
                return Either::A(fut);
            }
        }

        Either::B(future::ok(event))
    });

    // Fail if no response received within the timeout.
    let duration = inner.borrow().timeout;
    let inner_weak = Rc::downgrade(inner);
    let timeout = timeout(duration, &inner.borrow().el_handle).then(move |result| {
        if let Some(inner) = inner_weak.upgrade() {
            let _ = inner.borrow_mut().hooks.remove(&msg_id);
        }

        result
    });

    future
        .select(timeout)
        .then(|result| match result {
            Ok((a, _)) => Ok(a),
            Err((a, _)) => Err(a),
        })
        .into_box()
}

// Create a future that resolves into `CoreError::RequestTimeout` after the given time interval.
// TODO: replace with tokio::timer::Timeout
fn timeout(
    duration: Duration,
    _handle: &Handle,
) -> impl Future<Item = CoreEvent, Error = CoreError> {
    Delay::new(Instant::now() + duration).then(|result| match result {
        Ok(()) => Err(CoreError::RequestTimeout),
        Err(err) => Err(CoreError::Unexpected(format!(
            "Timeout fire error {:?}",
            err
        ))),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::mock::vault::COST_OF_PUT;
    use crate::utils::generate_random_vector;
    use crate::utils::test_utils::random_client;
    use safe_nd::{
        ADataAction, ADataEntry, ADataOwner, ADataUnpubPermissionSet, ADataUnpubPermissions,
        AppendOnlyData, Coins, Error as SndError, MDataAction, PubSeqAppendOnlyData, SeqAppendOnly,
        UnpubSeqAppendOnlyData, UnpubUnseqAppendOnlyData, UnseqAppendOnly, XorName,
    };
    use std::str::FromStr;
    use threshold_crypto::SecretKey;

    // Test putting and getting pub idata.
    #[test]
    fn pub_idata_test() {
        random_client(move |client| {
            let client2 = client.clone();
            let client3 = client.clone();
            let client4 = client.clone();

            let value = unwrap!(generate_random_vector::<u8>(10));
            let data = PubImmutableData::new(value.clone());
            let name = *data.name();

            let test_data = UnpubImmutableData::new(
                value.clone(),
                PublicKey::Bls(threshold_crypto::SecretKey::random().public_key()),
            );
            client
                // Get inexistent idata
                .get_pub_idata(name)
                .then(|res| -> Result<(), CoreError> {
                    match res {
                        Ok(data) => panic!("Pub idata should not exist yet: {:?}", data),
                        Err(CoreError::NewRoutingClientError(SndError::NoSuchData)) => Ok(()),
                        Err(e) => panic!("Unexpected: {:?}", e),
                    }
                })
                .and_then(move |_| {
                    // Put idata
                    client2.put_pub_idata(data.clone())
                })
                .and_then(move |_| {
                    client3
                        .put_unpub_idata(test_data.clone())
                        .then(|res| match res {
                            Ok(_) => panic!("Unexpected Success: Validating owners should fail"),
                            Err(CoreError::NewRoutingClientError(SndError::InvalidOwners)) => {
                                Ok(())
                            }
                            Err(e) => panic!("Unexpected: {:?}", e),
                        })
                })
                .and_then(move |_| {
                    // Fetch idata
                    client4.get_pub_idata(name).map(move |fetched_data| {
                        assert_eq!(*fetched_data.name(), name);
                    })
                })
        })
    }

    // Test putting, getting, and deleting unpub idata.
    #[test]
    fn unpub_idata_test() {
        random_client(move |client| {
            let client2 = client.clone();
            let client3 = client.clone();
            let client4 = client.clone();
            let client5 = client.clone();
            let client6 = client.clone();
            let client7 = client.clone();
            let client8 = client.clone();

            let value = unwrap!(generate_random_vector::<u8>(10));
            let data = UnpubImmutableData::new(
                value.clone(),
                PublicKey::Bls(unwrap!(client.public_bls_key())),
            );
            let data2 = data.clone();
            let data3 = data.clone();
            let name = *data.name();
            assert_eq!(name, *data2.name());

            let pub_data = PubImmutableData::new(value);

            client
                // Get inexistent idata
                .get_unpub_idata(name)
                .then(|res| -> Result<(), CoreError> {
                    match res {
                        Ok(_) => panic!("Unpub idata should not exist yet"),
                        Err(CoreError::NewRoutingClientError(SndError::NoSuchData)) => Ok(()),
                        Err(e) => panic!("Unexpected: {:?}", e),
                    }
                })
                .and_then(move |_| {
                    // Put idata
                    client2.put_unpub_idata(data.clone())
                })
                .and_then(move |_| {
                    // Test putting unpub idata with the same value. Should conflict.
                    client3.put_unpub_idata(data2.clone())
                })
                .then(|res| -> Result<(), CoreError> {
                    match res {
                        Ok(_) => panic!("Put duplicate unpub idata"),
                        Err(CoreError::NewRoutingClientError(SndError::DataExists)) => Ok(()),
                        Err(e) => panic!("Unexpected: {:?}", e),
                    }
                })
                .and_then(move |_| {
                    // Test putting published idata with the same value. Should not conflict.
                    client4.put_pub_idata(pub_data)
                })
                .and_then(move |_| {
                    // Fetch idata
                    client5.get_unpub_idata(name).map(move |fetched_data| {
                        assert_eq!(*fetched_data.name(), name);
                    })
                })
                .and_then(move |()| {
                    // Delete idata
                    client6.del_unpub_idata(name)
                })
                .and_then(move |()| {
                    // Make sure idata was deleted
                    client7.get_unpub_idata(name)
                })
                .then(|res| -> Result<(), CoreError> {
                    match res {
                        Ok(_) => panic!("Unpub idata still exists after deletion"),
                        Err(CoreError::NewRoutingClientError(SndError::NoSuchData)) => Ok(()),
                        Err(e) => panic!("Unexpected: {:?}", e),
                    }
                })
                .and_then(move |_| {
                    // Test putting unpub idata with the same value again. Should not conflict.
                    client8.put_unpub_idata(data3.clone())
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
            let permission_set = NewPermissionSet::new().allow(MDataAction::Read);
            let _ = permissions.insert(
                PublicKey::Bls(unwrap!(client.public_bls_key())),
                permission_set.clone(),
            );
            let _ = entries.insert(b"key".to_vec(), b"value".to_vec());
            let entries_keys = entries.keys().cloned().collect();
            let entries_values: Vec<Vec<u8>> = entries.values().cloned().collect();

            let data = UnseqMutableData::new_with_data(
                name,
                tag,
                entries.clone(),
                permissions,
                PublicKey::from(unwrap!(client.public_bls_key())),
            );
            client
                .put_unseq_mutable_data(data.clone())
                .and_then(move |_| {
                    println!("Put unseq. MData successfully");

                    client3
                        .get_mdata_version_new(MDataAddress::Unseq { name, tag })
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
                        .list_mdata_keys_new(MDataAddress::Unseq { name, tag })
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
            let mut entries: BTreeMap<Vec<u8>, Val> = Default::default();
            let _ = entries.insert(
                b"key".to_vec(),
                Val {
                    data: b"value".to_vec(),
                    version: 0,
                },
            );
            let entries_keys = entries.keys().cloned().collect();
            let entries_values: Vec<Val> = entries.values().cloned().collect();
            let mut permissions: BTreeMap<_, _> = Default::default();
            let permission_set = NewPermissionSet::new().allow(MDataAction::Read);
            let _ = permissions.insert(
                PublicKey::Bls(unwrap!(client.public_bls_key())),
                permission_set.clone(),
            );
            let data = SeqMutableData::new_with_data(
                name,
                tag,
                entries.clone(),
                permissions,
                PublicKey::from(unwrap!(client.public_bls_key())),
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
                        .list_mdata_keys_new(MDataAddress::Seq { name, tag })
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
                PublicKey::from(unwrap!(client.public_bls_key())),
            );

            client
                .put_seq_mutable_data(data.clone())
                .and_then(move |_| {
                    client2.delete_mdata(mdataref).map(move |result| {
                        assert_eq!(result, ());
                    })
                })
                .then(move |_| {
                    client3
                        .get_unseq_mdata(*data.name(), data.tag())
                        .then(move |res| {
                            match res {
                                Err(CoreError::NewRoutingClientError(SndError::NoSuchData)) => (),
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
                PublicKey::from(unwrap!(client.public_bls_key())),
            );

            client
                .put_unseq_mutable_data(data.clone())
                .and_then(move |_| {
                    client2.delete_mdata(mdataref).and_then(move |result| {
                        assert_eq!(result, ());
                        Ok(())
                    })
                })
                .then(move |_| {
                    client3
                        .get_unseq_mdata(*data.name(), data.tag())
                        .then(move |res| {
                            match res {
                                Err(CoreError::NewRoutingClientError(SndError::NoSuchData)) => (),
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
    // 5. Try to request transaction from wallet A using account B. This request should succeed (because transactions are always open).
    #[test]
    fn coin_permissions() {
        let wallet_a_addr = random_client(move |client| {
            let wallet_a_addr: XorName = unwrap!(client.owner_key()).into();
            client.test_create_balance(
                unwrap!(client.owner_key()),
                unwrap!(Coins::from_str("10.0")),
            );
            client
                .transfer_coins(
                    None,
                    new_rand::random(),
                    unwrap!(Coins::from_str("5.0")),
                    None,
                )
                .then(move |res| {
                    match res {
                        Err(CoreError::NewRoutingClientError(SndError::NoSuchBalance)) => (),
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
                        .and_then(|x| x.checked_sub(*COST_OF_PUT)));
                    match res {
                        Ok(fetched_amt) => assert_eq!(expected_amt, fetched_amt),
                        res => panic!("Unexpected result: {:?}", res),
                    }
                    c2.test_create_balance(
                        unwrap!(c3.owner_key()),
                        unwrap!(Coins::from_str("50.0")),
                    );

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
    // 4. Try to create a balance using an inexistent wallet. This should fail.
    #[test]
    fn anonymous_wallet() {
        random_client(move |client| {
            let client1 = client.clone();
            let client2 = client.clone();
            let client3 = client.clone();
            let client4 = client.clone();
            let client5 = client.clone();
            let bls_sk = threshold_crypto::SecretKey::random();
            let bls_sk2 = bls_sk.clone();
            let wallet1: XorName = unwrap!(client.owner_key()).into();

            client.test_create_balance(
                unwrap!(client.owner_key()),
                unwrap!(Coins::from_str("500.0")),
            );

            client1
                .create_balance(
                    None,
                    PublicKey::from(bls_sk.public_key()),
                    unwrap!(Coins::from_str("100.0")),
                    None,
                )
                .and_then(move |transaction| {
                    assert_eq!(transaction.amount, unwrap!(Coins::from_str("100")));
                    client2
                        .transfer_coins(
                            Some(&bls_sk),
                            wallet1,
                            unwrap!(Coins::from_str("5.0")),
                            None,
                        )
                        .and_then(move |transaction| {
                            assert_eq!(transaction.amount, unwrap!(Coins::from_str("5.0")));
                            Ok(())
                        })
                })
                .and_then(move |_| {
                    client3.get_balance(Some(&bls_sk2)).and_then(|balance| {
                        assert_eq!(balance, unwrap!(Coins::from_str("95.0")));
                        Ok(())
                    })
                })
                .and_then(move |_| {
                    client4.get_balance(None).and_then(|balance| {
                        assert_eq!(balance, unwrap!(Coins::from_str("405.0")));
                        Ok(())
                    })
                })
                .and_then(move |_| {
                    let random_key = threshold_crypto::SecretKey::random();
                    let random_pk = PublicKey::from(random_key.public_key());
                    client5
                        .create_balance(
                            Some(&random_key),
                            random_pk,
                            unwrap!(Coins::from_str("100.0")),
                            None,
                        )
                        .then(|res| {
                            match res {
                                Err(CoreError::NewRoutingClientError(SndError::NoSuchBalance)) => {}
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
    #[test]
    fn coin_balance_transfer() {
        let wallet1: XorName = random_client(move |client| {
            let client1 = client.clone();
            let client2 = client.clone();
            let owner_key = unwrap!(client.owner_key());
            let wallet1: XorName = owner_key.into();

            client.test_create_balance(owner_key, unwrap!(Coins::from_str("0.0")));

            unwrap!(client1.allocate_test_coins(&wallet1, unwrap!(Coins::from_str("100.0"))));

            client2.get_balance(None).and_then(move |balance| {
                assert_eq!(balance, unwrap!(Coins::from_str("100.0")));
                Ok(wallet1)
            })
        });

        random_client(move |client| {
            let owner_key = unwrap!(client.owner_key());
            client.test_create_balance(owner_key, unwrap!(Coins::from_str("100.0")));

            let c2 = client.clone();
            let c3 = client.clone();

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
                    Ok(())
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
                PublicKey::from(unwrap!(client.public_bls_key())),
            );

            client.put_unseq_mutable_data(data.clone()).then(|res| res)
        });

        random_client(move |client| {
            client.delete_mdata(mdataref).then(|res| {
                match res {
                    Err(CoreError::NewRoutingClientError(SndError::AccessDenied)) => (),
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
            let name = XorName(rand::random());
            let tag = 15001;
            let mut permissions: BTreeMap<_, _> = Default::default();
            let permission_set = NewPermissionSet::new()
                .allow(MDataAction::Read)
                .allow(MDataAction::Insert)
                .allow(MDataAction::ManagePermissions);
            let user = PublicKey::Bls(unwrap!(client.public_bls_key()));
            let user2 = user;
            let random_user = PublicKey::Bls(threshold_crypto::SecretKey::random().public_key());
            let _ = permissions.insert(user, permission_set.clone());
            let _ = permissions.insert(random_user, permission_set.clone());
            let data = SeqMutableData::new_with_data(
                name,
                tag,
                Default::default(),
                permissions.clone(),
                PublicKey::from(unwrap!(client.public_bls_key())),
            );
            let test_data = SeqMutableData::new_with_data(
                XorName(rand::random()),
                15000,
                Default::default(),
                permissions,
                PublicKey::Bls(threshold_crypto::SecretKey::random().public_key()),
            );
            client
                .put_seq_mutable_data(data.clone())
                .and_then(move |res| {
                    assert_eq!(res, ());
                    Ok(())
                })
                .and_then(move |_| {
                    client1
                        .put_seq_mutable_data(test_data.clone())
                        .then(|res| match res {
                            Ok(_) => panic!("Unexpected Success: Validating owners should fail"),
                            Err(CoreError::NewRoutingClientError(SndError::InvalidOwners)) => {
                                Ok(())
                            }
                            Err(e) => panic!("Unexpected: {:?}", e),
                        })
                })
                .and_then(move |_| {
                    let new_perm_set = NewPermissionSet::new()
                        .allow(MDataAction::ManagePermissions)
                        .allow(MDataAction::Read);
                    client2
                        .set_mdata_user_permissions_new(
                            MDataAddress::Seq { name, tag },
                            user,
                            new_perm_set,
                            1,
                        )
                        .then(move |res| {
                            assert_eq!(unwrap!(res), ());
                            Ok(())
                        })
                })
                .and_then(move |_| {
                    println!("Modified user permissions");

                    client3
                        .list_mdata_user_permissions_new(MDataAddress::Seq { name, tag }, user2)
                        .and_then(|permissions| {
                            assert!(!permissions.is_allowed(MDataAction::Insert));
                            assert!(permissions.is_allowed(MDataAction::Read));
                            assert!(permissions.is_allowed(MDataAction::ManagePermissions));
                            println!("Verified new permissions");

                            Ok(())
                        })
                })
                .and_then(move |_| {
                    client4
                        .del_mdata_user_permissions_new(
                            MDataAddress::Seq { name, tag },
                            random_user,
                            2,
                        )
                        .then(move |res| {
                            assert_eq!(unwrap!(res), ());
                            Ok(())
                        })
                })
                .and_then(move |_| {
                    println!("Deleted permissions");
                    client5
                        .list_mdata_permissions_new(MDataAddress::Seq { name, tag })
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
            let permission_set = NewPermissionSet::new()
                .allow(MDataAction::Read)
                .allow(MDataAction::Insert)
                .allow(MDataAction::Update)
                .allow(MDataAction::Delete);
            let user = PublicKey::Bls(unwrap!(client.public_bls_key()));
            let _ = permissions.insert(user, permission_set.clone());
            let mut entries: BTreeMap<Vec<u8>, Val> = Default::default();
            let _ = entries.insert(
                b"key1".to_vec(),
                Val {
                    data: b"value".to_vec(),
                    version: 0,
                },
            );
            let _ = entries.insert(
                b"key2".to_vec(),
                Val {
                    data: b"value".to_vec(),
                    version: 0,
                },
            );
            let data = SeqMutableData::new_with_data(
                name,
                tag,
                entries.clone(),
                permissions,
                PublicKey::from(unwrap!(client.public_bls_key())),
            );
            client
                .put_seq_mutable_data(data.clone())
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
                        .mutate_seq_mdata_entries(name, tag, entry_actions.clone())
                        .then(move |res| {
                            assert_eq!(unwrap!(res), ());
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
                                Val {
                                    data: b"newValue".to_vec(),
                                    version: 1,
                                },
                            );
                            let _ = expected_entries.insert(
                                b"key3".to_vec(),
                                Val {
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
                                Val {
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
                                Err(CoreError::NewRoutingClientError(SndError::NoSuchEntry)) => (),
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
            let permission_set = NewPermissionSet::new()
                .allow(MDataAction::Read)
                .allow(MDataAction::Insert)
                .allow(MDataAction::Update)
                .allow(MDataAction::Delete);
            let user = PublicKey::Bls(unwrap!(client.public_bls_key()));
            let _ = permissions.insert(user, permission_set.clone());
            let mut entries: BTreeMap<Vec<u8>, Vec<u8>> = Default::default();
            let _ = entries.insert(b"key1".to_vec(), b"value".to_vec());
            let _ = entries.insert(b"key2".to_vec(), b"value".to_vec());
            let data = UnseqMutableData::new_with_data(
                name,
                tag,
                entries.clone(),
                permissions,
                PublicKey::from(unwrap!(client.public_bls_key())),
            );
            client
                .put_unseq_mutable_data(data.clone())
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
                        .mutate_unseq_mdata_entries(name, tag, entry_actions.clone())
                        .then(move |res| {
                            assert_eq!(unwrap!(res), ());
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
                                Err(CoreError::NewRoutingClientError(SndError::NoSuchEntry)) => (),
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
            let idx = ADataIndex::FromStart(0);
            let _ = perms.insert(PublicKey::Bls(unwrap!(client.public_bls_key())), set);
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
                public_key: PublicKey::Bls(unwrap!(client.public_bls_key())),
                entries_index: 0,
                permissions_index: 1,
            };
            unwrap!(data.append_owner(owner, 0));

            client
                .put_adata(AData::UnpubSeq(data.clone()))
                .and_then(move |_| {
                    client1.get_adata(address).map(move |data| match data {
                        AData::UnpubSeq(adata) => assert_eq!(*adata.name(), name),
                        _ => panic!("Unexpected data found"),
                    })
                })
                .and_then(move |_| {
                    client2
                        .get_adata_shell(idx, address)
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
                        Err(CoreError::NewRoutingClientError(SndError::NoSuchData)) => Ok(()),
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

            let _ = perms.insert(PublicKey::Bls(unwrap!(client.public_bls_key())), set);

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

            let idx_start = ADataIndex::FromStart(0);
            let idx_end = ADataIndex::FromEnd(2);
            let perm_idx = ADataIndex::FromStart(1);

            let sim_client = PublicKey::Bls(SecretKey::random().public_key());
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
                public_key: PublicKey::Bls(unwrap!(client.public_bls_key())),
                entries_index: 4,
                permissions_index: 1,
            };

            unwrap!(data.append_owner(owner, 0));

            let mut test_data = UnpubSeqAppendOnlyData::new(XorName(rand::random()), 15000);
            let test_owner = ADataOwner {
                public_key: PublicKey::Bls(SecretKey::random().public_key()),
                entries_index: 0,
                permissions_index: 0,
            };

            unwrap!(test_data.append_owner(test_owner, 0));

            client
                .put_adata(AData::UnpubSeq(data.clone()))
                .map(move |res| {
                    assert_eq!(res, ());
                })
                .and_then(move |_| {
                    client1
                        .put_adata(AData::UnpubSeq(test_data.clone()))
                        .then(|res| match res {
                            Ok(_) => panic!("Unexpected Success: Validating owners should fail"),
                            Err(CoreError::NewRoutingClientError(SndError::InvalidOwners)) => {
                                Ok(())
                            }
                            Err(e) => panic!("Unexpected: {:?}", e),
                        })
                })
                .and_then(move |_| {
                    client2
                        .get_adata_range(adataref, (idx_start, idx_end))
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
                            assert_eq!(unwrap!(res), ());
                            Ok(())
                        })
                })
                .and_then(move |_| {
                    client7
                        .get_unpub_adata_permissions_at_index(adataref, perm_idx)
                        .map(move |data| {
                            let set = unwrap!(data.permissions.get(&sim_client1));
                            assert!(set.is_allowed(ADataAction::Append));
                        })
                })
                .and_then(move |_| {
                    client8
                        .get_unpub_adata_user_permissions(
                            adataref,
                            idx_start,
                            PublicKey::Bls(unwrap!(client8.public_bls_key())),
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

            let usr = ADataUser::Key(PublicKey::Bls(unwrap!(client.public_bls_key())));
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

            let append = ADataAppend {
                address: adataref,
                values: tup,
            };

            let owner = ADataOwner {
                public_key: PublicKey::Bls(unwrap!(client.public_bls_key())),
                entries_index: 0,
                permissions_index: 1,
            };

            unwrap!(data.append_owner(owner, 0));

            client
                .put_adata(AData::PubSeq(data.clone()))
                .and_then(move |_| {
                    client1.append_seq_adata(append, 0).then(move |res| {
                        assert_eq!(unwrap!(res), ());
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

            let _ = perms.insert(PublicKey::Bls(unwrap!(client.public_bls_key())), set);

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

            let append = ADataAppend {
                address: adataref,
                values: tup,
            };

            let owner = ADataOwner {
                public_key: PublicKey::Bls(unwrap!(client.public_bls_key())),
                entries_index: 0,
                permissions_index: 1,
            };

            unwrap!(data.append_owner(owner, 0));

            client
                .put_adata(AData::UnpubUnseq(data.clone()))
                .and_then(move |_| {
                    client1.append_unseq_adata(append).then(move |res| {
                        assert_eq!(unwrap!(res), ());
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

            let _ = perms.insert(PublicKey::Bls(unwrap!(client.public_bls_key())), set);

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
                public_key: PublicKey::Bls(unwrap!(client.public_bls_key())),
                entries_index: 2,
                permissions_index: 1,
            };

            unwrap!(data.append_owner(owner, 0));

            let owner2 = ADataOwner {
                public_key: PublicKey::Bls(unwrap!(client1.public_bls_key())),
                entries_index: 2,
                permissions_index: 1,
            };

            let owner3 = ADataOwner {
                public_key: PublicKey::Bls(unwrap!(client2.public_bls_key())),
                entries_index: 2,
                permissions_index: 1,
            };

            client
                .put_adata(AData::UnpubUnseq(data.clone()))
                .and_then(move |_| {
                    client1
                        .set_adata_owners(adataref, owner2, 1)
                        .then(move |res| {
                            assert_eq!(unwrap!(res), ());
                            Ok(())
                        })
                })
                .and_then(move |_| {
                    client2
                        .set_adata_owners(adataref, owner3, 2)
                        .map(move |data| {
                            assert_eq!(data, ());
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
        let bls_sk = threshold_crypto::SecretKey::random();
        let client_pk = PublicKey::from(bls_sk.public_key());

        random_client(move |client| {
            client.test_create_balance(client_pk, unwrap!(Coins::from_str("50")));
            Ok::<(), SndError>(())
        });

        let balance = unwrap!(wallet_get_balance(&bls_sk));
        let ten_coins = unwrap!(Coins::from_str("10"));
        assert_eq!(balance, unwrap!(Coins::from_str("50")));

        let new_bls_sk = threshold_crypto::SecretKey::random();
        let new_client_pk = PublicKey::from(new_bls_sk.public_key());
        let new_wallet: XorName = new_client_pk.into();
        let txn = unwrap!(wallet_create_balance(
            &bls_sk,
            new_client_pk,
            ten_coins,
            None
        ));
        assert_eq!(txn.amount, ten_coins);
        let txn2 = unwrap!(wallet_transfer_coins(&bls_sk, new_wallet, ten_coins, None));
        assert_eq!(txn2.amount, ten_coins);

        let client_balance = unwrap!(wallet_get_balance(&bls_sk));
        assert_eq!(client_balance, unwrap!(Coins::from_str("30")));

        let new_client_balance = unwrap!(wallet_get_balance(&new_bls_sk));
        assert_eq!(new_client_balance, unwrap!(Coins::from_str("20")));
    }
}
