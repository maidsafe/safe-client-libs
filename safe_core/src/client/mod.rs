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
    AccountInfo, Authority, EntryAction, Event, FullId, ImmutableData, InterfaceError, MessageId,
    MutableData, PermissionSet, User, Value, XorName,
};
use rust_sodium::crypto::{box_, sign};
use safe_nd::mutable_data::{
    MutableData as NewMutableData, MutableDataRef, SeqMutableData, UnseqMutableData, Value as Val,
};
use safe_nd::request::{Request, Requester};
use safe_nd::response::Response;
use safe_nd::{MessageId as NewMessageId, XorName as NewXorName};
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

    /// Return the public BLS key
    fn public_bls_key(&self) -> Option<threshold_crypto::PublicKey>;

    /// Return the secret BLS key
    fn secret_bls_key(&self) -> Option<threshold_crypto::SecretKey>;

    /// Return the public and secret signing keys.
    fn signing_keypair(&self) -> Option<(sign::PublicKey, shared_sign::SecretKey)> {
        Some((self.public_signing_key()?, self.secret_signing_key()?))
    }

    /// Return the owner signing key.
    fn owner_key(&self) -> Option<sign::PublicKey>;

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
        send(self, move |routing, msg_id| {
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

        send_mutation(self, move |routing, dst, msg_id| {
            routing.put_idata(dst, data.clone(), msg_id)
        })
    }

    /// Put `MutableData` onto the network.
    fn put_mdata(&self, data: MutableData) -> Box<CoreFuture<()>> {
        trace!("PutMData for {:?}", data);

        let requester = some_or_err!(self.public_signing_key());
        send_mutation(self, move |routing, dst, msg_id| {
            routing.put_mdata(dst, data.clone(), msg_id, requester)
        })
    }

    /// Put unsequenced mutable data to the network
    fn put_unseq_mutable_data(&self, data: UnseqMutableData) -> Box<CoreFuture<()>> {
        trace!("Put Unsequenced MData at {:?}", data.name());

        let requester = some_or_err!(self.public_bls_key());
        let client = Authority::Client {
            client_id: *some_or_err!(self.full_id()).public_id(),
            proxy_node_name: rand::random(),
        };
        send_mutation(self, move |routing, dst, message_id| {
            let request = Request::PutUnseqMData {
                data: data.clone(),
                requester: Requester::Key(requester),
                message_id: message_id.to_new(),
            };
            routing.send(client, dst, &unwrap!(serialise(&request)))
        })
    }

    /// Put sequenced mutable data to the network
    fn put_seq_mutable_data(&self, data: SeqMutableData) -> Box<CoreFuture<()>> {
        trace!("Put Sequenced MData at {:?}", data.name());

        let requester = some_or_err!(self.public_bls_key());
        let client = Authority::Client {
            client_id: *some_or_err!(self.full_id()).public_id(),
            proxy_node_name: rand::random(),
        };
        send_mutation(self, move |routing, dst, message_id| {
            let request = Request::PutSeqMData {
                data: data.clone(),
                requester: Requester::Key(requester),
                message_id: message_id.to_new(),
            };
            routing.send(client, dst, &unwrap!(serialise(&request)))
        })
    }

    /// Fetch unpublished mutable data from the network
    fn get_unseq_mdata(&self, name: XorName, tag: u64) -> Box<CoreFuture<UnseqMutableData>> {
        trace!("Fetch Unpublished Mutable Data");

        let requester = some_or_err!(self.public_bls_key());
        let client = Authority::Client {
            client_id: *some_or_err!(self.full_id()).public_id(),
            proxy_node_name: rand::random(),
        };
        send(self, move |routing, msg_id| {
            let request = Request::GetUnseqMData {
                address: MutableDataRef::new(name.to_new(), tag),
                requester: Requester::Key(requester),
                message_id: msg_id.to_new(),
            };
            routing.send(
                client,
                Authority::NaeManager(name),
                &unwrap!(serialise(&request)),
            )
        })
        .and_then(|event| {
            let res = match event {
                CoreEvent::RpcResponse(res) => res,
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            };
            let result_buffer = unwrap!(res);
            let res: Response = unwrap!(deserialise(&result_buffer));
            match res {
                Response::GetUnseqMData { res, .. } => res.map_err(CoreError::from),
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            }
        })
        .into_box()
    }

    /// Fetch sequenced mutable data from the network
    fn get_seq_mdata(&self, name: XorName, tag: u64) -> Box<CoreFuture<SeqMutableData>> {
        trace!("Fetch entries from  Mutable Data");

        let requester = some_or_err!(self.public_bls_key());
        let client = Authority::Client {
            client_id: *some_or_err!(self.full_id()).public_id(),
            proxy_node_name: rand::random(),
        };
        send(self, move |routing, msg_id| {
            let request = Request::GetSeqMData {
                address: MutableDataRef::new(name.to_new(), tag),
                requester: Requester::Key(requester),
                message_id: msg_id.to_new(),
            };
            routing.send(
                client,
                Authority::NaeManager(name),
                &unwrap!(serialise(&request)),
            )
        })
        .and_then(|event| {
            let res = match event {
                CoreEvent::RpcResponse(res) => res,
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            };
            let result_buffer = unwrap!(res);
            let res: Response = unwrap!(deserialise(&result_buffer));
            match res {
                Response::GetSeqMData { res, .. } => res.map_err(CoreError::from),
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            }
        })
        .into_box()
    }

    /// Delete MData from network
    fn delete_mdata(&self, mdataref: MutableDataRef) -> Box<CoreFuture<()>> {
        trace!("Delete entire Mutable Data");

        let requester = some_or_err!(self.public_bls_key());
        let client = Authority::Client {
            client_id: *some_or_err!(self.full_id()).public_id(),
            proxy_node_name: rand::random(),
        };

        send_mutation(self, move |routing, dst, msg_id| {
            let request = Request::DeleteMData {
                address: mdataref.clone(),
                requester: Requester::Key(requester),
                message_id: msg_id.to_new(),
            };
            routing.send(client, dst, &unwrap!(serialise(&request)))
        })
    }

    /// Mutates `MutableData` entries in bulk.
    fn mutate_mdata_entries(
        &self,
        name: XorName,
        tag: u64,
        actions: BTreeMap<Vec<u8>, EntryAction>,
    ) -> Box<CoreFuture<()>> {
        trace!("PutMData for {:?}", name);

        let requester = some_or_err!(self.public_signing_key());
        send_mutation(self, move |routing, dst, msg_id| {
            routing.mutate_mdata_entries(dst, name, tag, actions.clone(), msg_id, requester)
        })
    }

    /// Get entire `MutableData` from the network.
    fn get_mdata(&self, name: XorName, tag: u64) -> Box<CoreFuture<MutableData>> {
        trace!("GetMData for {:?}", name);

        send(self, move |routing, msg_id| {
            routing.get_mdata(Authority::NaeManager(name), name, tag, msg_id)
        })
        .and_then(|event| match_event!(event, CoreEvent::GetMData))
        .into_box()
    }

    /// Get a shell (bare bones) version of `MutableData` from the network.
    fn get_mdata_shell(&self, name: XorName, tag: u64) -> Box<CoreFuture<MutableData>> {
        trace!("GetMDataShell for {:?}", name);

        send(self, move |routing, msg_id| {
            routing.get_mdata_shell(Authority::NaeManager(name), name, tag, msg_id)
        })
        .and_then(|event| match_event!(event, CoreEvent::GetMDataShell))
        .into_box()
    }

    /// Get a shell (bare bones) version of `MutableData` from the network.
    fn get_seq_mdata_shell(&self, name: XorName, tag: u64) -> Box<CoreFuture<SeqMutableData>> {
        trace!("GetMDataShell for {:?}", name);

        let requester = some_or_err!(self.public_bls_key());
        let client = Authority::Client {
            client_id: *some_or_err!(self.full_id()).public_id(),
            proxy_node_name: rand::random(),
        };
        send(self, move |routing, msg_id| {
            let request = Request::GetSeqMDataShell {
                address: MutableDataRef::new(name.to_new(), tag),
                requester: Requester::Key(requester),
                message_id: msg_id.to_new(),
            };

            routing.send(
                client,
                Authority::NaeManager(name),
                &unwrap!(serialise(&request)),
            )
        })
        .and_then(|event| {
            let res = match event {
                CoreEvent::RpcResponse(res) => res,
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            };
            let result_buffer = unwrap!(res);
            let res: Response = unwrap!(deserialise(&result_buffer));
            match res {
                Response::GetSeqMDataShell { res, .. } => res.map_err(CoreError::from),
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            }
        })
        .into_box()
    }

    /// Get a shell (bare bones) version of `MutableData` from the network.
    fn get_unseq_mdata_shell(&self, name: XorName, tag: u64) -> Box<CoreFuture<UnseqMutableData>> {
        trace!("GetMDataShell for {:?}", name);

        let requester = some_or_err!(self.public_bls_key());
        let client = Authority::Client {
            client_id: *some_or_err!(self.full_id()).public_id(),
            proxy_node_name: rand::random(),
        };
        send(self, move |routing, msg_id| {
            let request = Request::GetUnseqMDataShell {
                address: MutableDataRef::new(name.to_new(), tag),
                requester: Requester::Key(requester),
                message_id: msg_id.to_new(),
            };

            routing.send(
                client,
                Authority::NaeManager(name),
                &unwrap!(serialise(&request)),
            )
        })
        .and_then(|event| {
            let res = match event {
                CoreEvent::RpcResponse(res) => res,
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            };
            let result_buffer = unwrap!(res);
            let res: Response = unwrap!(deserialise(&result_buffer));
            match res {
                Response::GetUnseqMDataShell { res, .. } => res.map_err(CoreError::from),
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            }
        })
        .into_box()
    }

    /// Get a current version of `MutableData` from the network.
    fn get_mdata_version_new(&self, name: XorName, tag: u64) -> Box<CoreFuture<u64>> {
        trace!("GetMDataVersion for {:?}", name);

        let requester = some_or_err!(self.public_bls_key());
        let client = Authority::Client {
            client_id: *some_or_err!(self.full_id()).public_id(),
            proxy_node_name: rand::random(),
        };
        send(self, move |routing, msg_id| {
            let request = Request::GetMDataVersion {
                address: MutableDataRef::new(name.to_new(), tag),
                requester: Requester::Key(requester),
                message_id: msg_id.to_new(),
            };

            routing.send(
                client,
                Authority::NaeManager(name),
                &unwrap!(serialise(&request)),
            )
        })
        .and_then(|event| {
            let res = match event {
                CoreEvent::RpcResponse(res) => res,
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            };
            let result_buffer = unwrap!(res);
            let res: Response = unwrap!(deserialise(&result_buffer));
            match res {
                Response::GetMDataVersion { res, .. } => res.map_err(CoreError::from),
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            }
        })
        .into_box()
    }

    /// Get a current version of `MutableData` from the network.
    fn get_mdata_version(&self, name: XorName, tag: u64) -> Box<CoreFuture<u64>> {
        trace!("GetMDataVersion for {:?}", name);

        send(self, move |routing, msg_id| {
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

        send(self, move |routing, msg_id| {
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

        let requester = some_or_err!(self.public_bls_key());
        let client = Authority::Client {
            client_id: *some_or_err!(self.full_id()).public_id(),
            proxy_node_name: rand::random(),
        };
        send(self, move |routing, msg_id| {
            let request = Request::ListUnseqMDataEntries {
                address: MutableDataRef::new(name.to_new(), tag),
                requester: Requester::Key(requester),
                message_id: msg_id.to_new(),
            };

            routing.send(
                client,
                Authority::NaeManager(name),
                &unwrap!(serialise(&request)),
            )
        })
        .and_then(|event| {
            let res = match event {
                CoreEvent::RpcResponse(res) => res,
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            };
            let result_buffer = unwrap!(res);
            let res: Response = unwrap!(deserialise(&result_buffer));
            match res {
                Response::ListUnseqMDataEntries { res, .. } => res.map_err(CoreError::from),
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
        trace!("ListMDataEntries for {:?}", name);

        let requester = some_or_err!(self.public_bls_key());
        let client = Authority::Client {
            client_id: *some_or_err!(self.full_id()).public_id(),
            proxy_node_name: rand::random(),
        };
        send(self, move |routing, msg_id| {
            let request = Request::ListSeqMDataEntries {
                address: MutableDataRef::new(name.to_new(), tag),
                requester: Requester::Key(requester),
                message_id: msg_id.to_new(),
            };

            routing.send(
                client,
                Authority::NaeManager(name),
                &unwrap!(serialise(&request)),
            )
        })
        .and_then(|event| {
            let res = match event {
                CoreEvent::RpcResponse(res) => res,
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            };
            let result_buffer = unwrap!(res);
            let res: Response = unwrap!(deserialise(&result_buffer));
            match res {
                Response::ListSeqMDataEntries { res, .. } => res.map_err(CoreError::from),
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            }
        })
        .into_box()
    }

    /// Return a list of keys in `MutableData` stored on the network.
    fn list_mdata_keys(&self, name: XorName, tag: u64) -> Box<CoreFuture<BTreeSet<Vec<u8>>>> {
        trace!("ListMDataKeys for {:?}", name);

        send(self, move |routing, msg_id| {
            routing.list_mdata_keys(Authority::NaeManager(name), name, tag, msg_id)
        })
        .and_then(|event| match_event!(event, CoreEvent::ListMDataKeys))
        .into_box()
    }

    /// Return a list of keys in `MutableData` stored on the network.
    fn list_mdata_keys_new(&self, name: XorName, tag: u64) -> Box<CoreFuture<BTreeSet<Vec<u8>>>> {
        trace!("ListMDataKeys for {:?}", name);

        let requester = some_or_err!(self.public_bls_key());
        let client = Authority::Client {
            client_id: *some_or_err!(self.full_id()).public_id(),
            proxy_node_name: rand::random(),
        };
        send(self, move |routing, msg_id| {
            let request = Request::ListMDataKeys {
                address: MutableDataRef::new(name.to_new(), tag),
                requester: Requester::Key(requester),
                message_id: msg_id.to_new(),
            };

            routing.send(
                client,
                Authority::NaeManager(name),
                &unwrap!(serialise(&request)),
            )
        })
        .and_then(|event| {
            let res = match event {
                CoreEvent::RpcResponse(res) => res,
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            };
            let result_buffer = unwrap!(res);
            let res: Response = unwrap!(deserialise(&result_buffer));
            match res {
                Response::ListMDataKeys { res, .. } => res.map_err(CoreError::from),
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            }
        })
        .into_box()
    }

    /// Return a list of values in a Sequenced Mutable Data
    fn list_seq_mdata_values(&self, name: XorName, tag: u64) -> Box<CoreFuture<Vec<Val>>> {
        trace!("List MDataValues for {:?}", name);

        let requester = some_or_err!(self.public_bls_key());
        let client = Authority::Client {
            client_id: *some_or_err!(self.full_id()).public_id(),
            proxy_node_name: rand::random(),
        };
        send(self, move |routing, msg_id| {
            let request = Request::ListSeqMDataValues {
                address: MutableDataRef::new(name.to_new(), tag),
                requester: Requester::Key(requester),
                message_id: msg_id.to_new(),
            };

            routing.send(
                client,
                Authority::NaeManager(name),
                &unwrap!(serialise(&request)),
            )
        })
        .and_then(|event| {
            let res = match event {
                CoreEvent::RpcResponse(res) => res,
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            };
            let result_buffer = unwrap!(res);
            let res: Response = unwrap!(deserialise(&result_buffer));
            match res {
                Response::ListSeqMDataValues { res, .. } => res.map_err(CoreError::from),
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            }
        })
        .into_box()
    }

    /// Returns a list of values in an Unsequenced Mutable Data
    fn list_unseq_mdata_values(&self, name: XorName, tag: u64) -> Box<CoreFuture<Vec<Vec<u8>>>> {
        trace!("List MDataValues for {:?}", name);

        let requester = some_or_err!(self.public_bls_key());
        let client = Authority::Client {
            client_id: *some_or_err!(self.full_id()).public_id(),
            proxy_node_name: rand::random(),
        };
        send(self, move |routing, msg_id| {
            let request = Request::ListUnseqMDataValues {
                address: MutableDataRef::new(name.to_new(), tag),
                requester: Requester::Key(requester),
                message_id: msg_id.to_new(),
            };

            routing.send(
                client,
                Authority::NaeManager(name),
                &unwrap!(serialise(&request)),
            )
        })
        .and_then(|event| {
            let res = match event {
                CoreEvent::RpcResponse(res) => res,
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            };
            let result_buffer = unwrap!(res);
            let res: Response = unwrap!(deserialise(&result_buffer));
            match res {
                Response::ListUnseqMDataValues { res, .. } => res.map_err(CoreError::from),
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            }
        })
        .into_box()
    }

    /// Return a list of keys in `MutableData` stored on the network.
    fn list_mdata_values(&self, name: XorName, tag: u64) -> Box<CoreFuture<Vec<Value>>> {
        trace!("ListMDataValues for {:?}", name);

        send(self, move |routing, msg_id| {
            routing.list_mdata_values(Authority::NaeManager(name), name, tag, msg_id)
        })
        .and_then(|event| match_event!(event, CoreEvent::ListMDataValues))
        .into_box()
    }

    /// Get a single entry from `MutableData`.
    fn get_mdata_value(&self, name: XorName, tag: u64, key: Vec<u8>) -> Box<CoreFuture<Value>> {
        trace!("GetMDataValue for {:?}", name);

        send(self, move |routing, msg_id| {
            routing.get_mdata_value(Authority::NaeManager(name), name, tag, key.clone(), msg_id)
        })
        .and_then(|event| match_event!(event, CoreEvent::GetMDataValue))
        .into_box()
    }

    /// Get data from the network.
    fn get_account_info(&self) -> Box<CoreFuture<AccountInfo>> {
        trace!("Account info GET issued.");

        let dst = some_or_err!(self.cm_addr());
        send(self, move |routing, msg_id| {
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

        send(self, move |routing, msg_id| {
            routing.list_mdata_permissions(Authority::NaeManager(name), name, tag, msg_id)
        })
        .and_then(|event| match_event!(event, CoreEvent::ListMDataPermissions))
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

        send(self, move |routing, msg_id| {
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

        let requester = some_or_err!(self.public_signing_key());
        send_mutation(self, move |routing, dst, msg_id| {
            routing.set_mdata_user_permissions(
                dst,
                name,
                tag,
                user,
                permissions,
                version,
                msg_id,
                requester,
            )
        })
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

        let requester = some_or_err!(self.public_signing_key());
        send_mutation(self, move |routing, dst, msg_id| {
            routing.del_mdata_user_permissions(dst, name, tag, user, version, msg_id, requester)
        })
    }

    /// Sends an ownership transfer request.
    fn change_mdata_owner(
        &self,
        name: XorName,
        tag: u64,
        new_owner: sign::PublicKey,
        version: u64,
    ) -> Box<CoreFuture<()>> {
        trace!("ChangeMDataOwner for {:?}", name);

        send_mutation(self, move |routing, dst, msg_id| {
            routing.change_mdata_owner(dst, name, tag, btree_set![new_owner], version, msg_id)
        })
    }

    /// Fetches a list of authorised keys and version in MaidManager.
    fn list_auth_keys_and_version(&self) -> Box<CoreFuture<(BTreeSet<sign::PublicKey>, u64)>> {
        trace!("ListAuthKeysAndVersion");

        let dst = some_or_err!(self.cm_addr());
        send(self, move |routing, msg_id| {
            routing.list_auth_keys_and_version(dst, msg_id)
        })
        .and_then(|event| match_event!(event, CoreEvent::ListAuthKeysAndVersion))
        .into_box()
    }

    /// Adds a new authorised key to MaidManager.
    fn ins_auth_key(&self, key: sign::PublicKey, version: u64) -> Box<CoreFuture<()>> {
        trace!("InsAuthKey ({:?})", key);

        send_mutation(self, move |routing, dst, msg_id| {
            routing.ins_auth_key(dst, key, version, msg_id)
        })
    }

    /// Removes an authorised key from MaidManager.
    fn del_auth_key(&self, key: sign::PublicKey, version: u64) -> Box<CoreFuture<()>> {
        trace!("DelAuthKey ({:?})", key);

        send_mutation(self, move |routing, dst, msg_id| {
            routing.del_auth_key(dst, key, version, msg_id)
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

/// Send a request and return a future that resolves to the response.
fn send<F>(client: &impl Client, req: F) -> Box<CoreFuture<CoreEvent>>
where
    F: Fn(&mut Routing, MessageId) -> Result<(), InterfaceError> + 'static,
{
    let inner = Rc::downgrade(&client.inner());
    let func = move |_| {
        if let Some(inner) = inner.upgrade() {
            let msg_id = MessageId::new();
            if let Err(error) = req(&mut inner.borrow_mut().routing, msg_id) {
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

/// Sends a mutation request.
fn send_mutation<F>(client: &impl Client, req: F) -> Box<CoreFuture<()>>
where
    F: Fn(&mut Routing, Authority<XorName>, MessageId) -> Result<(), InterfaceError> + 'static,
{
    let dst = some_or_err!(client.cm_addr());

    send(client, move |routing, msg_id| req(routing, dst, msg_id))
        .and_then(|event| match event {
            CoreEvent::RpcResponse(res) => {
                let response_buffer = unwrap!(res);
                let response: Response = unwrap!(deserialise(&response_buffer));
                match response {
                    Response::PutUnseqMData { res, .. }
                    | Response::PutSeqMData { res, .. }
                    | Response::DeleteMData { res, .. } => res.map_err(CoreError::from),
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

// We need this to impl. MessageId
/// Conversion functions for MessageId
pub trait MsgIdConverter {
    /// Converts routing::MessageId to safe-nd::Message
    fn to_new(&self) -> NewMessageId;

    /// Converts safe-nd::MessageId to routing::MessageId
    fn from_new(new_msg_id: NewMessageId) -> Self;
}

/// Conversion functions for XorName
pub trait XorNameConverter {
    /// Converts routing::XorName to safe-nd::XorName
    fn to_new(&self) -> NewXorName;

    /// Converts safe-nd::XorName to routing::XorName
    fn from_new(new_xor_name: NewXorName) -> Self;
}

impl XorNameConverter for XorName {
    fn to_new(&self) -> NewXorName {
        NewXorName { 0: self.0 }
    }

    fn from_new(new_xor_name: NewXorName) -> Self {
        XorName { 0: new_xor_name.0 }
    }
}

impl MsgIdConverter for MessageId {
    fn to_new(&self) -> NewMessageId {
        NewMessageId {
            0: (self.0.to_new()),
        }
    }

    fn from_new(new_msg_id: NewMessageId) -> Self {
        MessageId {
            0: XorName::from_new(new_msg_id.0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::random_client;
    use safe_nd::XorName as SndXorName;

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
            let _ = entries.insert(b"key".to_vec(), b"value".to_vec());
            let entries_keys = entries.keys().cloned().collect();
            let entries_values: Vec<Vec<u8>> = entries.values().cloned().collect();

            let data = UnseqMutableData::new_with_data(
                name.to_new(),
                tag,
                entries.clone(),
                Default::default(),
                unwrap!(client.public_bls_key()),
            );
            client
                .put_unseq_mutable_data(data.clone())
                .and_then(move |_| {
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
                    println!("Put unseq. MData successfully");

                    client2
                        .get_unseq_mdata(XorName::from_new(*data.name()), data.tag())
                        .map(move |fetched_data| {
                            assert_eq!(fetched_data.name(), data.name());
                            assert_eq!(fetched_data.tag(), data.tag());
                            fetched_data
                        })
                })
                .then(|res| res)
        });
    }

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

            let data = SeqMutableData::new_with_data(
                name.to_new(),
                tag,
                entries.clone(),
                Default::default(),
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
                            assert_eq!(*mdata_shell.name(), name.to_new());
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

    #[test]
    #[should_panic]
    pub fn del_seq_mdata_test() {
        let _ = random_client(move |client| {
            let client2 = client.clone();
            let client3 = client.clone();
            let name = SndXorName(rand::random());
            let tag = 15001;
            let mdataref = MutableDataRef::new(name, tag);
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
                .and_then(move |_| {
                    client3.get_seq_mdata(XorName::from_new(*data.name()), data.tag())
                })
                .then(|res| res)
        });
    }

    #[test]
    #[should_panic]
    pub fn del_unseq_mdata_test() {
        let _ = random_client(move |client| {
            let client2 = client.clone();
            let client3 = client.clone();
            let name = SndXorName(rand::random());
            let tag = 15001;
            let mdataref = MutableDataRef::new(name, tag);
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
                    client2.delete_mdata(mdataref).map(move |result| {
                        assert_eq!(result, ());
                    })
                })
                .and_then(move |_| {
                    client3.get_unseq_mdata(XorName::from_new(*data.name()), data.tag())
                })
                .then(|res| res)
        });
    }

    #[test]
    #[should_panic]
    pub fn del_unseq_mdata_permission_test() {
        let name = SndXorName(rand::random());
        let tag = 15001;
        let mdataref = MutableDataRef::new(name, tag);

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

        random_client(move |client1| client1.delete_mdata(mdataref).map_err(CoreError::from));
    }
}
