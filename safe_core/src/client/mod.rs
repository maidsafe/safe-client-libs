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
use futures::future::{self, Either, FutureResult, Loop, Then};
use futures::sync::oneshot;
use futures::{Complete, Future};
use lru_cache::LruCache;
use maidsafe_utilities::serialisation::{deserialise, serialise};
use maidsafe_utilities::thread::{self, Joiner};
use routing::{
    AccountInfo, Authority, EntryAction, Event, FullId, InterfaceError, MutableData, PermissionSet,
    User, Value,
};
use rust_sodium::crypto::{box_, sign};
use safe_nd::{
    AData, ADataAddress, ADataAppend, ADataIndex, ADataIndices, ADataOwner, ADataPubPermissionSet,
    ADataPubPermissions, ADataUnpubPermissionSet, ADataUnpubPermissions, ADataUser, AppPermissions,
    Coins, IDataAddress, IDataKind, ImmutableData, MDataAddress,
    MDataPermissionSet as NewPermissionSet, MDataSeqEntryAction as SeqEntryAction,
    MDataUnseqEntryAction as UnseqEntryAction, MDataValue as Val, Message, MessageId,
    MutableData as NewMutableData, PublicKey, Request, Response, SeqMutableData, Transaction,
    UnpubImmutableData, UnseqMutableData, XorName,
};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io;
use std::rc::Rc;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::Duration;
use tokio_core::reactor::{Handle, Timeout};

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

    /// Return the client's new ID.
    fn full_id_new(&self) -> Option<NewFullId>;

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
    fn compose_message(&self, req: Request) -> Message;

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

        let (routing, routing_rx) = setup_routing(opt_id, self.full_id_new(), self.config())?;

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
    fn get_idata(&self, name: XorName) -> Box<CoreFuture<ImmutableData>> {
        trace!("GetIData for {:?}", name);

        let inner = self.inner();
        if let Some(data) = inner.borrow_mut().cache.get_mut(&name) {
            trace!("ImmutableData found in cache.");
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
    fn put_idata(&self, data: ImmutableData) -> Box<CoreFuture<()>> {
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
        send_mutation_new(self, Request::PutUnseqMData(data.clone()))
    }

    /// Transfer coin balance
    fn transfer_coins(
        &self,
        source: XorName,
        destination: XorName,
        amount: Coins,
        transaction_id: Option<u64>,
    ) -> Box<CoreFuture<u64>> {
        trace!("Transfer {} coins to {:?}", amount, destination);

        let transaction_id = transaction_id.unwrap_or_else(rand::random);

        send_mutation_new(
            self,
            Request::TransferCoins {
                source,
                destination,
                amount,
                transaction_id,
            },
        )
        .map(move |_| transaction_id)
        .into_box()
    }

    /// Get the current coin balance.
    fn get_balance(&self, destination: XorName) -> Box<CoreFuture<Coins>> {
        trace!("Get balance for {:?}", destination);

        send_new(self, Request::GetBalance(destination))
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
    fn get_pub_idata(&self, name: XorName) -> Box<CoreFuture<ImmutableData>> {
        trace!("Fetch Published Immutable Data");

        send_new(self, Request::GetIData(IDataAddress::Pub(name)))
            .and_then(|event| {
                let res = match event {
                    CoreEvent::RpcResponse(res) => res,
                    _ => Err(CoreError::ReceivedUnexpectedEvent),
                };
                let result_buffer = unwrap!(res);
                let res: Response = unwrap!(deserialise(&result_buffer));
                match res {
                    Response::GetIData(res) => match res {
                        Ok(IDataKind::Pub(data)) => Ok(data),
                        Ok(IDataKind::Unpub(_)) => Err(CoreError::ReceivedUnexpectedEvent),
                        Err(e) => Err(e).map_err(CoreError::from),
                    },
                    _ => Err(CoreError::ReceivedUnexpectedEvent),
                }
            })
            .into_box()
    }

    /// Put published immutable data to the network.
    fn put_pub_idata(&self, data: ImmutableData) -> Box<CoreFuture<()>> {
        trace!("Put Published IData at {:?}", data.name());
        send_mutation_new(self, Request::PutIData(data.into()))
    }

    /// Get unpublished immutable data from the network.
    fn get_unpub_idata(&self, name: XorName) -> Box<CoreFuture<UnpubImmutableData>> {
        trace!("Fetch Unpublished Immutable Data");

        send_new(self, Request::GetIData(IDataAddress::Unpub(name)))
            .and_then(|event| {
                let res = match event {
                    CoreEvent::RpcResponse(res) => res,
                    _ => Err(CoreError::ReceivedUnexpectedEvent),
                };
                let result_buffer = unwrap!(res);
                let res: Response = unwrap!(deserialise(&result_buffer));
                match res {
                    Response::GetIData(res) => match res {
                        Ok(IDataKind::Unpub(data)) => Ok(data),
                        Ok(IDataKind::Pub(_)) => Err(CoreError::ReceivedUnexpectedEvent),
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

    /// Get a transaction.
    fn get_transaction(
        &self,
        destination: XorName,
        transaction_id: u64,
    ) -> Box<CoreFuture<Transaction>> {
        trace!("Get transaction {} for {:?}", transaction_id, destination);

        send_new(
            self,
            Request::GetTransaction {
                coins_balance_id: destination,
                transaction_id,
            },
        )
        .and_then(|event| {
            let res = match event {
                CoreEvent::RpcResponse(res) => res,
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            };
            let result_buffer = unwrap!(res);
            let res: Response = unwrap!(deserialise(&result_buffer));
            match res {
                Response::GetTransaction(res) => res.map_err(CoreError::from),
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            }
        })
        .into_box()
    }

    /// Put sequenced mutable data to the network
    fn put_seq_mutable_data(&self, data: SeqMutableData) -> Box<CoreFuture<()>> {
        trace!("Put Sequenced MData at {:?}", data.name());
        send_mutation_new(self, Request::PutSeqMData(data))
    }

    /// Fetch unpublished mutable data from the network
    fn get_unseq_mdata(&self, name: XorName, tag: u64) -> Box<CoreFuture<UnseqMutableData>> {
        trace!("Fetch Unsequenced Mutable Data");

        send_new(self, Request::GetMData(MDataAddress::new_unseq(name, tag)))
            .and_then(|event| {
                let res = match event {
                    CoreEvent::RpcResponse(res) => res,
                    _ => Err(CoreError::ReceivedUnexpectedEvent),
                };
                let result_buffer = unwrap!(res);
                let res: Response = unwrap!(deserialise(&result_buffer));
                match res {
                    Response::GetUnseqMData(res) => res.map_err(CoreError::from),
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
                address: MDataAddress::new_seq(name, tag),
                key,
            },
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
                address: MDataAddress::new_unseq(name, tag),
                key,
            },
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

        send_new(self, Request::GetMData(MDataAddress::new_seq(name, tag)))
            .and_then(|event| {
                let res = match event {
                    CoreEvent::RpcResponse(res) => res,
                    _ => Err(CoreError::ReceivedUnexpectedEvent),
                };
                let result_buffer = unwrap!(res);
                let res: Response = unwrap!(deserialise(&result_buffer));
                match res {
                    Response::GetSeqMData(res) => res.map_err(CoreError::from),
                    _ => Err(CoreError::ReceivedUnexpectedEvent),
                }
            })
            .into_box()
    }

    /// Delete MData from network
    fn delete_mdata(&self, address: MDataAddress) -> Box<CoreFuture<()>> {
        trace!("Delete entire Mutable Data at {:?}", address);

        send_mutation_new(self, Request::DeleteMData(address))
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
        actions: BTreeMap<Vec<u8>, SeqEntryAction>,
    ) -> Box<CoreFuture<()>> {
        trace!("Mutate MData for {:?}", name);

        send_mutation_new(
            self,
            Request::MutateSeqMDataEntries {
                address: MDataAddress::new_seq(name, tag),
                actions: actions.clone(),
            },
        )
    }

    /// Mutates unsequenced `MutableData` entries in bulk
    fn mutate_unseq_mdata_entries(
        &self,
        name: XorName,
        tag: u64,
        actions: BTreeMap<Vec<u8>, UnseqEntryAction>,
    ) -> Box<CoreFuture<()>> {
        trace!("Mutate MData for {:?}", name);

        send_mutation_new(
            self,
            Request::MutateUnseqMDataEntries {
                address: MDataAddress::new_unseq(name, tag),
                actions: actions.clone(),
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
            Request::GetMDataShell(MDataAddress::new_seq(name, tag)),
        )
        .and_then(|event| {
            let res = match event {
                CoreEvent::RpcResponse(res) => res,
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            };
            let result_buffer = unwrap!(res);
            let res: Response = unwrap!(deserialise(&result_buffer));
            match res {
                Response::GetSeqMDataShell(res) => res.map_err(CoreError::from),
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
            Request::GetMDataShell(MDataAddress::new_unseq(name, tag)),
        )
        .and_then(|event| {
            let res = match event {
                CoreEvent::RpcResponse(res) => res,
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            };
            let result_buffer = unwrap!(res);
            let res: Response = unwrap!(deserialise(&result_buffer));
            match res {
                Response::GetUnseqMDataShell(res) => res.map_err(CoreError::from),
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            }
        })
        .into_box()
    }

    /// Get a current version of `MutableData` from the network.
    fn get_mdata_version_new(&self, address: MDataAddress) -> Box<CoreFuture<u64>> {
        trace!("GetMDataVersion for {:?}", address);

        send_new(self, Request::GetMDataVersion(address))
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
            Request::ListMDataEntries(MDataAddress::new_unseq(name, tag)),
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
            Request::ListMDataEntries(MDataAddress::new_seq(name, tag)),
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

        send_new(self, Request::ListMDataKeys(address))
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
            Request::ListMDataValues(MDataAddress::new_seq(name, tag)),
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

        send_new(self, Request::ListMDataUserPermissions { address, user })
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
            Request::ListMDataValues(MDataAddress::new_unseq(name, tag)),
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

        send_new(self, Request::GetAData(address))
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

    /// Get a Set of Entries for the requested range from an AData.
    #[allow(clippy::type_complexity)]
    fn get_adata_range(
        &self,
        address: ADataAddress,
        range: (ADataIndex, ADataIndex),
    ) -> Box<CoreFuture<Vec<(Vec<u8>, Vec<u8>)>>> {
        trace!(
            "Get Rage of entries from AppendOnly Data at {:?}",
            address.name()
        );

        send_new(self, Request::GetADataRange { address, range })
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

        send_new(self, Request::GetADataIndices(address))
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
    fn get_adata_last_entry(&self, address: ADataAddress) -> Box<CoreFuture<(Vec<u8>, Vec<u8>)>> {
        trace!(
            "Get latest indices from AppendOnly Data at {:?}",
            address.name()
        );

        send_new(self, Request::GetADataLastEntry(address))
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
            },
        )
    }

    /// Add Pub AData Permissions
    fn add_pub_adata_permissions(
        &self,
        address: ADataAddress,
        permissions: ADataPubPermissions,
    ) -> Box<CoreFuture<()>> {
        trace!("Add Permissions to AppendOnly Data {:?}", address.name());

        send_mutation_new(
            self,
            Request::AddPubADataPermissions {
                address,
                permissions,
            },
        )
    }

    /// Set new Owners to AData
    fn set_adata_owners(&self, address: ADataAddress, owner: ADataOwner) -> Box<CoreFuture<()>> {
        trace!("Set Owners to AppendOnly Data {:?}", address.name());

        send_mutation_new(self, Request::SetADataOwner { address, owner })
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

    /// Get data from the network.
    fn get_account_info(&self) -> Box<CoreFuture<AccountInfo>> {
        trace!("Account info GET issued.");

        let dst = some_or_err!(self.cm_addr());
        let msg_id = MessageId::new();
        send(self, msg_id, move |routing| {
            routing.get_account_info(dst, msg_id)
        })
        .and_then(|event| match_event!(event, CoreEvent::GetAccountInfo))
        .into_box()
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

        send_new(self, Request::ListMDataPermissions(address))
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

    /// Fetches a list of authorised keys and version in MaidManager.
    fn list_auth_keys_and_version(
        &self,
    ) -> Box<CoreFuture<(BTreeMap<PublicKey, AppPermissions>, u64)>> {
        trace!("ListAuthKeysAndVersion");

        send_new(self, Request::ListAuthKeysAndVersion)
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

    /// Adds a new authorised key to MaidManager.
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

    /// Removes an authorised key from MaidManager.
    fn del_auth_key(&self, key: PublicKey, version: u64) -> Box<CoreFuture<()>> {
        trace!("DelAuthKey ({:?})", key);

        send_mutation_new(self, Request::DelAuthKey { key, version })
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
    fn create_coin_balance(
        &self,
        coin_balance_name: &XorName,
        amount: Coins,
        owner: threshold_crypto::PublicKey,
    ) {
        let inner = self.inner();
        inner
            .borrow_mut()
            .routing
            .create_coin_balance(coin_balance_name, amount, owner);
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
    cache: LruCache<XorName, ImmutableData>,
    timeout: Duration,
    joiner: Joiner,
    core_tx: CoreMsgTx<C, T>,
    net_tx: NetworkTx,
}

impl<C: Client, T> ClientInner<C, T> {
    /// Create a new `ClientInner` object.
    pub fn new(
        el_handle: Handle,
        routing: Routing,
        hooks: HashMap<MessageId, Complete<CoreEvent>>,
        cache: LruCache<XorName, ImmutableData>,
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
    full_id_new: Option<NewFullId>,
    config: Option<BootstrapConfig>,
) -> Result<(Routing, Receiver<Event>), CoreError> {
    let (routing_tx, routing_rx) = mpsc::channel();
    let routing = Routing::new(
        routing_tx,
        full_id,
        full_id_new,
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

fn send_new(client: &impl Client, request: Request) -> Box<CoreFuture<CoreEvent>> {
    let dst = some_or_err!(client.cm_addr());
    let request = client.compose_message(request);
    send(client, request.message_id(), move |routing| {
        routing.send(dst, &unwrap!(serialise(&request)))
    })
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
    let message = client.compose_message(req);

    send_mutation(client, message.message_id(), move |routing, dst| {
        routing.send(dst, &unwrap!(serialise(&message)))
    })
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
                    Response::PutIData(res)
                    | Response::DeleteUnpubIData(res)
                    | Response::TransferCoins(res)
                    | Response::InsAuthKey(res)
                    | Response::DelAuthKey(res)
                    | Response::PutUnseqMData(res)
                    | Response::DeleteMData(res)
                    | Response::SetMDataUserPermissions(res)
                    | Response::DelMDataUserPermissions(res)
                    | Response::MutateSeqMDataEntries(res)
                    | Response::MutateUnseqMDataEntries(res)
                    | Response::PutAData(res)
                    | Response::DeleteAData(res)
                    | Response::AddPubADataPermissions(res)
                    | Response::AddUnpubADataPermissions(res)
                    | Response::AppendSeq(res)
                    | Response::AppendUnseq(res)
                    | Response::SetADataOwner(res)
                    | Response::PutSeqMData(res) => res.map_err(CoreError::from),
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
fn timeout(duration: Duration, handle: &Handle) -> TimeoutFuture {
    let timeout = match Timeout::new(duration, handle) {
        Ok(timeout) => timeout,
        Err(err) => {
            return Either::A(future::err(CoreError::Unexpected(format!(
                "Timeout create error: {:?}",
                err
            ))));
        }
    };

    fn map_result(result: io::Result<()>) -> Result<CoreEvent, CoreError> {
        match result {
            Ok(()) => Err(CoreError::RequestTimeout),
            Err(err) => Err(CoreError::Unexpected(format!(
                "Timeout fire error {:?}",
                err
            ))),
        }
    }

    Either::B(timeout.then(map_result))
}

type TimeoutFuture = Either<
    FutureResult<CoreEvent, CoreError>,
    Then<Timeout, Result<CoreEvent, CoreError>, fn(io::Result<()>) -> Result<CoreEvent, CoreError>>,
>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::generate_random_vector;
    use crate::utils::test_utils::random_client;
    use safe_nd::{
        ADataAction, ADataOwner, ADataUnpubPermissionSet, ADataUnpubPermissions, AppendOnlyData,
        MDataAction, PubSeqAppendOnlyData, SeqAppendOnly, UnpubSeqAppendOnlyData,
        UnpubUnseqAppendOnlyData, UnseqAppendOnly,
    };
    use safe_nd::{Coins, Error, XorName};
    use std::str::FromStr;
    use threshold_crypto::SecretKey;

    // Test putting and getting pub idata.
    #[test]
    fn pub_idata_test() {
        random_client(move |client| {
            let client2 = client.clone();
            let client3 = client.clone();

            let value = unwrap!(generate_random_vector::<u8>(10));
            let data = ImmutableData::new(value.clone());
            let name = *data.name();

            client
                // Get inexistent idata
                .get_pub_idata(name)
                .then(|res| -> Result<(), CoreError> {
                    match res {
                        Ok(data) => panic!("Pub idata should not exist yet: {:?}", data),
                        Err(CoreError::NewRoutingClientError(Error::NoSuchData)) => Ok(()),
                        Err(e) => panic!("Unexpected: {:?}", e),
                    }
                })
                .and_then(move |_| {
                    // Put idata
                    client2.put_pub_idata(data.clone())
                })
                .and_then(move |_| {
                    // Fetch idata
                    client3.get_pub_idata(name).map(move |fetched_data| {
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
            let data = UnpubImmutableData::new(value.clone(), unwrap!(client.public_bls_key()));
            let data2 = data.clone();
            let data3 = data.clone();
            let name = *data.name();
            assert_eq!(name, *data2.name());

            let pub_data = ImmutableData::new(value);

            client
                // Get inexistent idata
                .get_unpub_idata(name)
                .then(|res| -> Result<(), CoreError> {
                    match res {
                        Ok(_) => panic!("Unpub idata should not exist yet"),
                        Err(CoreError::NewRoutingClientError(Error::NoSuchData)) => Ok(()),
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
                        Err(CoreError::NewRoutingClientError(Error::DataExists)) => Ok(()),
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
                        Err(CoreError::NewRoutingClientError(Error::NoSuchData)) => Ok(()),
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
                        .get_mdata_version_new(MDataAddress::new_unseq(name, tag))
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
                        .list_mdata_keys_new(MDataAddress::new_unseq(name, tag))
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
            let _ = entries.insert(b"key".to_vec(), Val::new(b"value".to_vec(), 0));
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
                        .list_mdata_keys_new(MDataAddress::new_seq(name, tag))
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
            let mdataref = MDataAddress::new_seq(name, tag);
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
                                Err(CoreError::NewRoutingClientError(Error::NoSuchData)) => (),
                                _ => panic!("Unexpected success"),
                            }
                            Ok::<_, Error>(())
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
            let mdataref = MDataAddress::new_unseq(name, tag);
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
                                Err(CoreError::NewRoutingClientError(Error::NoSuchData)) => (),
                                _ => panic!("Unexpected success"),
                            }
                            Ok::<_, Error>(())
                        })
                })
        });
    }

    // 1. Create 2 accounts with 2 wallets (A and B).
    // 2. Try to request balance of wallet A from account B. This request should fail.
    // 3. Try to transfer balance from wallet A to wallet B using account B. This request should fail. -- TODO
    // 4. Try to request transaction from wallet A using account B. This request should succeed (because transactions are always open).
    #[test]
    fn coin_permissions() {
        let wallet1 = random_client(move |client| {
            let name: XorName = new_rand::random();
            client.create_coin_balance(
                &name,
                unwrap!(Coins::from_str("1000.0")),
                unwrap!(client.public_bls_key()),
            );
            Ok::<_, Error>(name)
        });

        random_client(move |client| {
            let c2 = client.clone();

            client
                .get_balance(wallet1)
                .then(move |res| {
                    match res {
                        Err(CoreError::NewRoutingClientError(Error::AccessDenied)) => (),
                        res => panic!("Unexpected result: {:?}", res),
                    }

                    c2.get_transaction(wallet1, 1)
                })
                .then(move |res| {
                    match res {
                        Ok(Transaction::NoSuchTransaction) => (),
                        res => panic!("Unexpected result: {:?}", res),
                    }
                    Ok::<_, Error>(())
                })
        });
    }

    // 1. Create 2 accounts with 2 wallets.
    // 2. Transfer 5 coins from wallet A to wallet B.
    // 3. Check that the balance of wallet B is credited for 5 coins and the balance of
    //    wallet A is debited for 5 coins.
    #[test]
    fn coin_balance_transfer() {
        let wallet1 = random_client(move |client| {
            let name: XorName = new_rand::random();
            client.create_coin_balance(
                &name,
                unwrap!(Coins::from_str("0.0")),
                unwrap!(client.public_bls_key()),
            );
            Ok::<_, Error>(name)
        });

        random_client(move |client| {
            let wallet2 = new_rand::random();
            client.create_coin_balance(
                &wallet2,
                unwrap!(Coins::from_str("100.0")),
                unwrap!(client.public_bls_key()),
            );

            let c2 = client.clone();
            let c3 = client.clone();
            let c4 = client.clone();

            client
                .get_balance(wallet2)
                .and_then(move |orig_balance| {
                    c2.transfer_coins(wallet2, wallet1, unwrap!(Coins::from_str("5.0")), None)
                        .map(move |transaction_id| (transaction_id, orig_balance))
                })
                .and_then(move |(transaction_id, orig_balance)| {
                    c3.get_balance(wallet2)
                        .map(move |new_balance| (transaction_id, new_balance, orig_balance))
                })
                .and_then(move |(transaction_id, new_balance, orig_balance)| {
                    assert_eq!(
                        new_balance,
                        unwrap!(orig_balance.checked_sub(unwrap!(Coins::from_str("5.0")))),
                    );

                    c4.get_transaction(wallet1, transaction_id)
                })
                .and_then(move |transaction| {
                    match transaction {
                        Transaction::Success(amount) => {
                            assert_eq!(amount, unwrap!(Coins::from_str("5.0")))
                        }
                        res => panic!("Unexpected transaction result: {:?}", res),
                    }
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
        let mdataref = MDataAddress::new_unseq(name, tag);

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
                    Err(CoreError::NewRoutingClientError(Error::AccessDenied)) => (),
                    res => panic!("Unexpected result: {:?}", res),
                }
                Ok::<_, Error>(())
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
                permissions,
                PublicKey::from(unwrap!(client.public_bls_key())),
            );
            client
                .put_seq_mutable_data(data.clone())
                .and_then(move |_| {
                    println!("Put seq. MData successfully");

                    Ok(())
                })
                .and_then(move |_| {
                    let new_perm_set = NewPermissionSet::new()
                        .allow(MDataAction::ManagePermissions)
                        .allow(MDataAction::Read);
                    client2
                        .set_mdata_user_permissions_new(
                            MDataAddress::new_seq(name, tag),
                            user,
                            new_perm_set,
                            1,
                        )
                        .and_then(|_| Ok(()))
                })
                .and_then(move |_| {
                    println!("Modified user permissions");

                    client3
                        .list_mdata_user_permissions_new(MDataAddress::new_seq(name, tag), user2)
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
                            MDataAddress::new_seq(name, tag),
                            random_user,
                            2,
                        )
                        .and_then(|_| Ok(()))
                })
                .and_then(move |_| {
                    println!("Deleted permissions");
                    client5
                        .list_mdata_permissions_new(MDataAddress::new_seq(name, tag))
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
            let _ = entries.insert(b"key1".to_vec(), Val::new(b"value".to_vec(), 0));
            let _ = entries.insert(b"key2".to_vec(), Val::new(b"value".to_vec(), 0));
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
                    let mut entry_actions: BTreeMap<Vec<u8>, SeqEntryAction> = Default::default();
                    let _ = entry_actions.insert(
                        b"key1".to_vec(),
                        SeqEntryAction::Update(Val::new(b"newValue".to_vec(), 1)),
                    );
                    let _ = entry_actions.insert(b"key2".to_vec(), SeqEntryAction::Del(1));
                    let _ = entry_actions.insert(
                        b"key3".to_vec(),
                        SeqEntryAction::Ins(Val::new(b"value".to_vec(), 0)),
                    );

                    client3
                        .mutate_seq_mdata_entries(name, tag, entry_actions.clone())
                        .and_then(|_| Ok(()))
                })
                .and_then(move |_| {
                    client4
                        .list_seq_mdata_entries(name, tag)
                        .map(move |fetched_entries| {
                            let mut expected_entries: BTreeMap<_, _> = Default::default();
                            let _ = expected_entries
                                .insert(b"key1".to_vec(), Val::new(b"newValue".to_vec(), 1));
                            let _ = expected_entries
                                .insert(b"key3".to_vec(), Val::new(b"value".to_vec(), 0));
                            assert_eq!(fetched_entries, expected_entries);
                        })
                })
                .and_then(move |_| {
                    client5
                        .get_seq_mdata_value(name, tag, b"key1".to_vec())
                        .and_then(|fetched_value| {
                            assert_eq!(fetched_value, Val::new(b"newValue".to_vec(), 1));
                            Ok(())
                        })
                })
        });

        random_client(|client| {
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
                    let mut entry_actions: BTreeMap<Vec<u8>, UnseqEntryAction> = Default::default();
                    let _ = entry_actions.insert(
                        b"key1".to_vec(),
                        UnseqEntryAction::Update(b"newValue".to_vec()),
                    );
                    let _ = entry_actions.insert(b"key2".to_vec(), UnseqEntryAction::Del);
                    let _ = entry_actions
                        .insert(b"key3".to_vec(), UnseqEntryAction::Ins(b"value".to_vec()));

                    client3
                        .mutate_unseq_mdata_entries(name, tag, entry_actions.clone())
                        .and_then(|_| Ok(()))
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
            let address = ADataAddress::new_unpub_seq(name, tag);

            unwrap!(data.append_permissions(ADataUnpubPermissions {
                permissions: perms,
                data_index: 0,
                owner_entry_index: 0,
            }));

            let owner = ADataOwner {
                public_key: PublicKey::Bls(unwrap!(client.public_bls_key())),
                data_index: 0,
                permissions_index: 1,
            };
            unwrap!(data.append_owner(owner));

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
                        Err(CoreError::NewRoutingClientError(Error::NoSuchData)) => Ok(()),
                        Err(e) => panic!("Unexpected Error: {:?}", e),
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

            let name = XorName(rand::random());
            let tag = 15000;
            let adataref = ADataAddress::new_unpub_seq(name, tag);
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

            let tup1 = (key1, val1);
            let tup2 = (key2, val2);
            let tup3 = (key3, val3);
            let tup4 = &[(key4, val4)].to_vec();

            let mut kvdata = Vec::<(Vec<u8>, Vec<u8>)>::new();
            kvdata.push(tup1);
            kvdata.push(tup2);
            kvdata.push(tup3);

            unwrap!(data.append(&kvdata, 0));
            // Test push
            unwrap!(data.append(tup4, 3));

            unwrap!(data.append_permissions(ADataUnpubPermissions {
                permissions: perms,
                data_index: 4,
                owner_entry_index: 0,
            }));

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
                data_index: 4,
                owner_entry_index: 1,
            };

            let owner = ADataOwner {
                public_key: PublicKey::Bls(unwrap!(client.public_bls_key())),
                data_index: 4,
                permissions_index: 1,
            };

            unwrap!(data.append_owner(owner));

            client
                .put_adata(AData::UnpubSeq(data.clone()))
                .map(move |res| {
                    assert_eq!(res, ());
                })
                .and_then(move |_| {
                    client1
                        .get_adata_range(adataref, (idx_start, idx_end))
                        .map(move |data| {
                            assert_eq!(
                                unwrap!(std::str::from_utf8(&unwrap!(data.last()).0)),
                                "KEY2"
                            );
                            assert_eq!(
                                unwrap!(std::str::from_utf8(&unwrap!(data.last()).1)),
                                "VALUE2"
                            );
                        })
                })
                .and_then(move |_| {
                    client2.get_adata_indices(adataref).map(move |data| {
                        assert_eq!(data.data_index(), 4);
                        assert_eq!(data.owners_index(), 1);
                        assert_eq!(data.permissions_index(), 1);
                    })
                })
                .and_then(move |_| {
                    client3.get_adata_last_entry(adataref).map(move |data| {
                        assert_eq!(unwrap!(std::str::from_utf8(data.0.as_slice())), "KEY4");
                        assert_eq!(unwrap!(std::str::from_utf8(data.1.as_slice())), "VALUE4");
                    })
                })
                .and_then(move |_| client4.add_unpub_adata_permissions(adataref, perm_set))
                .and_then(move |_| {
                    client5
                        .get_unpub_adata_permissions_at_index(adataref, perm_idx)
                        .map(move |data| {
                            let set = unwrap!(data.permissions.get(&sim_client1));
                            assert!(set.is_allowed(ADataAction::Append));
                        })
                })
                .and_then(move |_| {
                    client6
                        .get_unpub_adata_user_permissions(
                            adataref,
                            idx_start,
                            PublicKey::Bls(unwrap!(client6.public_bls_key())),
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

            let adataref = ADataAddress::new_pub_seq(name, tag);
            let mut data = PubSeqAppendOnlyData::new(name, tag);

            let mut perms = BTreeMap::<ADataUser, ADataPubPermissionSet>::new();
            let set = ADataPubPermissionSet::new(true, true);

            let usr = ADataUser::Key(PublicKey::Bls(unwrap!(client.public_bls_key())));
            let _ = perms.insert(usr, set);

            unwrap!(data.append_permissions(ADataPubPermissions {
                permissions: perms,
                data_index: 0,
                owner_entry_index: 0,
            }));

            let key1 = b"KEY1".to_vec();
            let val1 = b"VALUE1".to_vec();
            let key2 = b"KEY2".to_vec();
            let val2 = b"VALUE2".to_vec();

            let tup = [(key1, val1), (key2, val2)].to_vec();

            let append = ADataAppend {
                address: adataref,
                values: tup,
            };

            let owner = ADataOwner {
                public_key: PublicKey::Bls(unwrap!(client.public_bls_key())),
                data_index: 0,
                permissions_index: 1,
            };

            unwrap!(data.append_owner(owner));

            client
                .put_adata(AData::PubSeq(data.clone()))
                .and_then(move |_| {
                    client1.append_seq_adata(append, 0).map(move |data| {
                        assert_eq!(data, ());
                    })
                })
                .and_then(move |_| {
                    client2.get_adata(adataref).map(move |data| match data {
                        AData::PubSeq(adata) => assert_eq!(
                            unwrap!(std::str::from_utf8(&unwrap!(adata.last()).0)),
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

            let adataref = ADataAddress::new_unpub_unseq(name, tag);
            let mut data = UnpubUnseqAppendOnlyData::new(name, tag);

            let mut perms = BTreeMap::<PublicKey, ADataUnpubPermissionSet>::new();
            let set = ADataUnpubPermissionSet::new(true, true, true);

            let _ = perms.insert(PublicKey::Bls(unwrap!(client.public_bls_key())), set);

            unwrap!(data.append_permissions(ADataUnpubPermissions {
                permissions: perms,
                data_index: 0,
                owner_entry_index: 0,
            }));

            let key1 = b"KEY1".to_vec();
            let val1 = b"VALUE1".to_vec();
            let key2 = b"KEY2".to_vec();
            let val2 = b"VALUE2".to_vec();

            let tup = [(key1, val1), (key2, val2)].to_vec();

            let append = ADataAppend {
                address: adataref,
                values: tup,
            };

            let owner = ADataOwner {
                public_key: PublicKey::Bls(unwrap!(client.public_bls_key())),
                data_index: 0,
                permissions_index: 1,
            };

            unwrap!(data.append_owner(owner));

            client
                .put_adata(AData::UnpubUnseq(data.clone()))
                .and_then(move |_| {
                    client1.append_unseq_adata(append).map(move |data| {
                        assert_eq!(data, ());
                    })
                })
                .and_then(move |_| {
                    client2.get_adata(adataref).map(move |data| match data {
                        AData::UnpubUnseq(adata) => assert_eq!(
                            unwrap!(std::str::from_utf8(&unwrap!(adata.last()).0)),
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

            let adataref = ADataAddress::new_unpub_unseq(name, tag);
            let mut data = UnpubUnseqAppendOnlyData::new(name, tag);

            let mut perms = BTreeMap::<PublicKey, ADataUnpubPermissionSet>::new();
            let set = ADataUnpubPermissionSet::new(true, true, true);

            let _ = perms.insert(PublicKey::Bls(unwrap!(client.public_bls_key())), set);

            unwrap!(data.append_permissions(ADataUnpubPermissions {
                permissions: perms,
                data_index: 0,
                owner_entry_index: 0,
            }));

            let key1 = b"KEY1".to_vec();
            let key2 = b"KEY2".to_vec();

            let val1 = b"VALUE1".to_vec();
            let val2 = b"VALUE2".to_vec();

            let tup1 = (key1, val1);
            let tup2 = (key2, val2);

            let mut kvdata = Vec::<(Vec<u8>, Vec<u8>)>::new();
            kvdata.push(tup1);
            kvdata.push(tup2);

            unwrap!(data.append(&kvdata));

            let owner = ADataOwner {
                public_key: PublicKey::Bls(unwrap!(client.public_bls_key())),
                data_index: 2,
                permissions_index: 1,
            };

            unwrap!(data.append_owner(owner));

            let owner2 = ADataOwner {
                public_key: PublicKey::Bls(unwrap!(client1.public_bls_key())),
                data_index: 2,
                permissions_index: 1,
            };

            let owner3 = ADataOwner {
                public_key: PublicKey::Bls(unwrap!(client2.public_bls_key())),
                data_index: 2,
                permissions_index: 1,
            };

            client
                .put_adata(AData::UnpubUnseq(data.clone()))
                .and_then(move |_| {
                    client1.set_adata_owners(adataref, owner2).map(move |data| {
                        assert_eq!(data, ());
                    })
                })
                .and_then(move |_| {
                    client2.set_adata_owners(adataref, owner3).map(move |data| {
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

}
