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
    AppPermissions, Coins, ImmutableData, MDataAddress, MDataPermissionSet as NewPermissionSet,
    MDataSeqEntryAction as SeqEntryAction, MDataUnseqEntryAction, MDataValue as Val, Message,
    MessageId, MutableData as NewMutableData, PublicKey, Request, Response, SeqMutableData,
    Transaction, UnpubImmutableData, UnseqMutableData, XorName,
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

        let (routing, routing_rx) = setup_routing(opt_id, self.config())?;

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

    /// Get unpublished immutable data from the network.
    fn get_unpub_idata(&self, name: XorName) -> Box<CoreFuture<UnpubImmutableData>> {
        trace!("Fetch Unpublished Immutable Data");

        send_new(self, Request::GetUnpubIData { address: name })
            .and_then(|event| {
                let res = match event {
                    CoreEvent::RpcResponse(res) => res,
                    _ => Err(CoreError::ReceivedUnexpectedEvent),
                };
                let result_buffer = unwrap!(res);
                let res: Response = unwrap!(deserialise(&result_buffer));
                match res {
                    Response::GetUnpubIData(res) => res.map_err(CoreError::from),
                    _ => Err(CoreError::ReceivedUnexpectedEvent),
                }
            })
            .into_box()
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

    /// Put unpublished immutable data to the network.
    fn put_unpub_idata(&self, data: UnpubImmutableData) -> Box<CoreFuture<()>> {
        trace!("Put Unpublished IData at {:?}", data.name());
        send_mutation_new(self, Request::PutIData(data))
    }

    /// Delete unpublished immutable data from the network.
    fn del_unpub_idata(&self, name: XorName) -> Box<CoreFuture<()>> {
        trace!("Delete Unpublished IData at {:?}", name);
        send_mutation_new(self, Request::DeleteUnpubIData(name))
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
    fn delete_mdata(&self, mdataref: MutableDataRef) -> Box<CoreFuture<()>> {
        trace!("Delete entire Mutable Data");

        send_mutation_new(self, Request::DeleteMData(mdataref))
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
            Request::GetUnseqMDataShell {
                address: MDataAddress::new_unseq(name, tag),
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
                Response::GetUnseqMDataShell(res) => res.map_err(CoreError::from),
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            }
        })
        .into_box()
    }

    /// Get a current version of `MutableData` from the network.
    fn get_mdata_version_new(&self, name: XorName, tag: u64) -> Box<CoreFuture<u64>> {
        trace!("GetMDataVersion for {:?}", name);

        send_new(
            self,
            Request::GetMDataVersion {
                address: MDataAddress::new_seq(name, tag),
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
            Request::ListUnseqMDataEntries {
                address: MDataAddress::new_unseq(name, tag),
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
            Request::ListSeqMDataEntries {
                address: MDataAddress::new_seq(name, tag),
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
    fn list_mdata_keys_new(&self, name: XorName, tag: u64) -> Box<CoreFuture<BTreeSet<Vec<u8>>>> {
        trace!("ListMDataKeys for {:?}", name);

        send_new(
            self,
            Request::ListMDataKeys(MDataAddress::new_seq(name, tag)),
        )
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
        name: XorName,
        tag: u64,
        user: PublicKey,
    ) -> Box<CoreFuture<NewPermissionSet>> {
        trace!("GetMDataUserPermissions for {:?}", name);

        send_new(
            self,
            Request::ListMDataUserPermissions {
                address: MDataAddress::new_seq(name, tag),
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
            Request::ListUnseqMDataValues(MDataAddress::new_unseq(name, tag)),
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
        name: XorName,
        tag: u64,
    ) -> Box<CoreFuture<BTreeMap<PublicKey, NewPermissionSet>>> {
        trace!("List MDataPermissions for {:?}", name);

        send_new(
            self,
            Request::ListMDataPermissions {
                address: MDataAddress::new_seq(name, tag),
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
        name: XorName,
        tag: u64,
        user: PublicKey,
        permissions: NewPermissionSet,
        version: u64,
    ) -> Box<CoreFuture<()>> {
        trace!("SetMDataUserPermissions for {:?}", name);

        send_mutation_new(
            self,
            Request::SetMDataUserPermissions {
                address: MDataAddress::new_seq(name, tag),
                user,
                permissions: permissions.clone(),
                version,
            },
        )
    }

    /// Updates or inserts a permissions set for a user
    fn del_mdata_user_permissions_new(
        &self,
        name: XorName,
        tag: u64,
        user: PublicKey,
        version: u64,
    ) -> Box<CoreFuture<()>> {
        trace!("DelMDataUserPermissions for {:?}", name);

        send_mutation_new(
            self,
            Request::DelMDataUserPermissions {
                address: MDataAddress::new_seq(name, tag),
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
    config: Option<BootstrapConfig>,
) -> Result<(Routing, Receiver<Event>), CoreError> {
    let (routing_tx, routing_rx) = mpsc::channel();
    let routing = Routing::new(
        routing_tx,
        full_id,
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
                    Response::PutUnpubIData(res)
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
    use crate::utils::test_utils::random_client;
    use safe_nd::mutable_data::Action;
    use safe_nd::{Coins, Error, XorName};
    use std::str::FromStr;

    // Test putting, getting, and deleting unpub idata.
    #[test]
    pub fn unpub_idata_test() {
        random_client(move |client| {
            let client2 = client.clone();
            let client3 = client.clone();
            let client4 = client.clone();
            let client5 = client.clone();
            let client6 = client.clone();
            let client7 = client.clone();
            let client8 = client.clone();

            let value: Vec<u8> = Default::default();
            let data = UnpubImmutableData::new(value.clone(), unwrap!(client.public_bls_key()));
            let data2 = UnpubImmutableData::new(value.clone(), unwrap!(client.public_bls_key()));
            let data3 = UnpubImmutableData::new(value.clone(), unwrap!(client.public_bls_key()));
            let name = *data.name();
            assert_eq!(name, *data2.name());

            let pub_data = ImmutableData::new(value);

            client
                // Get inexistant idata
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
                    client4.put_idata(pub_data)
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
            let permission_set = NewPermissionSet::new().allow(Action::Read);
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
                unwrap!(client.public_bls_key()),
            );
            client
                .put_unseq_mutable_data(data.clone())
                .and_then(move |_| {
                    println!("Put unseq. MData successfully");

                    client3
                        .get_mdata_version_new(name, tag)
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
                        .list_mdata_keys_new(name, tag)
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
            let permission_set = NewPermissionSet::new().allow(Action::Read);
            let _ = permissions.insert(
                PublicKey::Bls(unwrap!(client.public_bls_key())),
                permission_set.clone(),
            );
            let data = SeqMutableData::new_with_data(
                name,
                tag,
                entries.clone(),
                permissions,
                unwrap!(client.public_bls_key()),
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
                        .list_mdata_keys_new(name, tag)
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
                unwrap!(client.public_bls_key()),
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
                unwrap!(client.public_bls_key()),
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
                unwrap!(client.public_bls_key()),
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
                .allow(Action::Read)
                .allow(Action::Insert)
                .allow(Action::ManagePermissions);
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
                unwrap!(client.public_bls_key()),
            );
            client
                .put_seq_mutable_data(data.clone())
                .and_then(move |_| {
                    println!("Put seq. MData successfully");

                    Ok(())
                })
                .and_then(move |_| {
                    let new_perm_set = NewPermissionSet::new()
                        .allow(Action::ManagePermissions)
                        .allow(Action::Read);
                    client2
                        .set_mdata_user_permissions_new(name, tag, user, new_perm_set, 1)
                        .and_then(|_| Ok(()))
                })
                .and_then(move |_| {
                    println!("Modified user permissions");

                    client3
                        .list_mdata_user_permissions_new(name, tag, user2)
                        .and_then(|permissions| {
                            assert!(!permissions.is_allowed(Action::Insert));
                            assert!(permissions.is_allowed(Action::Read));
                            assert!(permissions.is_allowed(Action::ManagePermissions));
                            println!("Verified new permissions");

                            Ok(())
                        })
                })
                .and_then(move |_| {
                    client4
                        .del_mdata_user_permissions_new(name, tag, random_user, 2)
                        .and_then(|_| Ok(()))
                })
                .and_then(move |_| {
                    println!("Deleted permissions");
                    client5
                        .list_mdata_permissions_new(name, tag)
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
                .allow(Action::Read)
                .allow(Action::Insert)
                .allow(Action::Update)
                .allow(Action::Delete);
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
                unwrap!(client.public_bls_key()),
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
                .allow(Action::Read)
                .allow(Action::Insert)
                .allow(Action::Update)
                .allow(Action::Delete);
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
                unwrap!(client.public_bls_key()),
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
}
