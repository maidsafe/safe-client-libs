// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement.  This, along with the Licenses can be
// found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

/// `MDataInfo` utilities.
pub mod mdata_info;
/// Operations with recovery.
pub mod recovery;

mod account;
#[cfg(feature = "use-mock-routing")]
mod mock;
mod routing_event_loop;

use self::account::Account;
pub use self::account::ClientKeys;
pub use self::mdata_info::MDataInfo;
#[cfg(feature = "use-mock-routing")]
use self::mock::Routing;
#[cfg(feature = "use-mock-routing")]
pub use self::mock::Routing as MockRouting;
use crypto::{shared_box, shared_secretbox, shared_sign};
use errors::CoreError;
use event::{CoreEvent, NetworkEvent, NetworkTx};
use event_loop::{CoreFuture, CoreMsgTx};
use futures::{Complete, Future};
use futures::future::{self, Either, FutureResult, Loop, Then};
use futures::sync::oneshot;
use ipc::BootstrapConfig;
use lru_cache::LruCache;
use maidsafe_utilities::serialisation::{deserialise, serialise};
use maidsafe_utilities::thread::{self, Joiner};
use routing::{ACC_LOGIN_ENTRY_KEY, AccountInfo, AccountPacket, Authority, EntryAction, Event,
              FullId, ImmutableData, InterfaceError, MessageId, MutableData, PermissionSet,
              Response, TYPE_TAG_SESSION_PACKET, User, Value, XorName};
#[cfg(not(feature = "use-mock-routing"))]
use routing::Client as Routing;
use rust_sodium::crypto::box_;
use rust_sodium::crypto::sign::{self, Seed};
use std::cell::{Ref, RefCell, RefMut};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::io;
use std::rc::Rc;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::Duration;
use tiny_keccak::sha3_256;
use tokio_core::reactor::{Handle, Timeout};
use utils::{self, FutureExt};

const CONNECTION_TIMEOUT_SECS: u64 = 40;
const REQUEST_TIMEOUT_SECS: u64 = 180;
const SEED_SUBPARTS: usize = 4;
const IMMUT_DATA_CACHE_SIZE: usize = 300;
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
    }
}

macro_rules! wait_for_response {
    ($rx:expr, $res:path, $msg_id:expr) => {
        match $rx.recv_timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS)) {
            Ok(Event::Response {
                response: $res { res, msg_id: res_msg_id },
                ..
            }) => {
                if res_msg_id == $msg_id {
                    res.map_err(CoreError::RoutingClientError)
                } else {
                    warn!("Received response with unexpected message id");
                    Err(CoreError::OperationAborted)
                }
            }
            Ok(x) => {
                warn!("Received unexpected response: {:?}", x);
                Err(CoreError::OperationAborted)
            }
            Err(err) => {
                warn!("Failed to receive response: {:?}", err);
                Err(CoreError::OperationAborted)
            }
        }
    }
}

/// The main self-authentication client instance that will interface all the
/// request from high level API's to the actual routing layer and manage all
/// interactions with it. This is essentially a non-blocking Client with
/// an asynchronous API using the futures abstraction from the futures-rs crate
pub struct Client<T> {
    inner: Rc<RefCell<Inner<T>>>,
}

struct Inner<T> {
    el_handle: Handle,
    routing: Routing,
    hooks: HashMap<MessageId, Complete<CoreEvent>>,
    cache: LruCache<XorName, ImmutableData>,
    client_type: ClientType,
    timeout: Duration,
    joiner: Joiner,
    session_packet_version: u64,
    core_tx: CoreMsgTx<T>,
    net_tx: NetworkTx,
}

impl<T> Clone for Client<T> {
    fn clone(&self) -> Self {
        Client { inner: Rc::clone(&self.inner) }
    }
}

impl<T: 'static> Client<T> {
    /// This is a getter-only Gateway function to the Maidsafe network. It will
    /// create an unregistered random client, which can do very limited set of
    /// operations - eg., a Network-Get
    pub fn unregistered(
        el_handle: Handle,
        core_tx: CoreMsgTx<T>,
        net_tx: NetworkTx,
        config: Option<BootstrapConfig>,
    ) -> Result<Self, CoreError> {
        trace!("Creating unregistered client.");

        let (routing, routing_rx) = setup_routing(None, config.clone())?;
        let joiner = spawn_routing_thread(routing_rx, core_tx.clone(), net_tx.clone());

        Ok(Self::new(Inner {
            el_handle: el_handle,
            routing: routing,
            hooks: HashMap::with_capacity(10),
            cache: LruCache::new(IMMUT_DATA_CACHE_SIZE),
            client_type: ClientType::unreg(config),
            timeout: Duration::from_secs(REQUEST_TIMEOUT_SECS),
            joiner: joiner,
            session_packet_version: 0,
            net_tx: net_tx,
            core_tx: core_tx,
        }))
    }

    /// Calculate sign key from seed
    pub fn sign_pk_from_seed(seed: &str) -> Result<sign::PublicKey, CoreError> {
        let arr = Self::divide_seed(seed)?;
        let id_seed = Seed(sha3_256(arr[SEED_SUBPARTS - 2]));
        let maid_keys = ClientKeys::new(Some(&id_seed));
        Ok(maid_keys.sign_pk)
    }

    /// This is one of the Gateway functions to the Maidsafe network, the others being
    /// `unregistered`, `registered`, and `login`. This will help create an account given a seed.
    /// Everything including both account secrets and all MAID keys will be deterministically
    /// derived from the supplied seed, so this seed needs to be strong. For ordinary users, it's
    /// recommended to use the normal `registered` function where the secrets can be what's easy
    /// to remember for the user while also being strong.
    pub fn registered_with_seed(
        seed: &str,
        el_handle: Handle,
        core_tx: CoreMsgTx<T>,
        net_tx: NetworkTx,
    ) -> Result<Client<T>, CoreError>
    where
        T: 'static,
    {
        let arr = Self::divide_seed(seed)?;

        let id_seed = Seed(sha3_256(arr[SEED_SUBPARTS - 2]));

        Self::registered_impl(
            arr[0],
            arr[1],
            "",
            el_handle,
            core_tx,
            net_tx,
            Some(&id_seed),
            |routing| routing,
        )
    }

    /// This is a Gateway function to the Maidsafe network. This will help
    /// create a fresh acc for the user in the SAFE-network.
    pub fn registered(
        acc_locator: &str,
        acc_password: &str,
        invitation: &str,
        el_handle: Handle,
        core_tx: CoreMsgTx<T>,
        net_tx: NetworkTx,
    ) -> Result<Client<T>, CoreError>
    where
        T: 'static,
    {
        Self::registered_impl(acc_locator.as_bytes(),
                              acc_password.as_bytes(),
                              invitation,
                              el_handle,
                              core_tx,
                              net_tx,
                              None,
                              |routing| routing)
    }

    /// This is a Gateway function to the Maidsafe network. This will help
    /// create a fresh acc for the user in the SAFE-network.
    fn registered_impl<F>(
        acc_locator: &[u8],
        acc_password: &[u8],
        invitation: &str,
        el_handle: Handle,
        core_tx: CoreMsgTx<T>,
        net_tx: NetworkTx,
        id_seed: Option<&Seed>,
        routing_wrapper_fn: F,
    ) -> Result<Client<T>, CoreError>
    where
        T: 'static,
        F: Fn(Routing) -> Routing,
    {
        trace!("Creating an account.");

        let (password, keyword, pin) = utils::derive_secrets(acc_locator, acc_password);

        let acc_loc = Account::generate_network_id(&keyword, &pin)?;
        let user_cred = UserCred::new(password, pin);

        let maid_keys = ClientKeys::new(id_seed);
        let pub_key = maid_keys.sign_pk;
        let full_id = Some(maid_keys.clone().into());

        let (mut routing, routing_rx) = setup_routing(full_id, None)?;
        routing = routing_wrapper_fn(routing);

        let acc = Account::new(maid_keys)?;

        let acc_ciphertext = acc.encrypt(&user_cred.password, &user_cred.pin)?;
        let acc_data =
            btree_map![
            ACC_LOGIN_ENTRY_KEY.to_owned() => Value {
                content: serialise(&if !invitation.is_empty() {
                    AccountPacket::WithInvitation {
                        invitation_string: invitation.to_owned(),
                        acc_pkt: acc_ciphertext
                    }
                } else {
                    AccountPacket::AccPkt(acc_ciphertext)
                })?,
                entry_version: 0,
            }
        ];

        let acc_md = MutableData::new(
            acc_loc,
            TYPE_TAG_SESSION_PACKET,
            BTreeMap::new(),
            acc_data,
            btree_set![pub_key],
        )?;

        let digest = sha3_256(&pub_key.0);
        let cm_addr = Authority::ClientManager(XorName(digest));

        let msg_id = MessageId::new();
        routing
            .put_mdata(cm_addr, acc_md.clone(), msg_id, pub_key)
            .map_err(CoreError::from)
            .and_then(|_| {
                wait_for_response!(routing_rx, Response::PutMData, msg_id)
            })
            .map_err(|e| {
                warn!("Could not put account to the Network: {:?}", e);
                e
            })?;

        // Create the client
        let joiner = spawn_routing_thread(routing_rx, core_tx.clone(), net_tx.clone());

        Ok(Self::new(Inner {
            el_handle: el_handle,
            routing: routing,
            hooks: HashMap::with_capacity(10),
            cache: LruCache::new(IMMUT_DATA_CACHE_SIZE),
            client_type: ClientType::reg(acc, acc_loc, user_cred, cm_addr),
            timeout: Duration::from_secs(REQUEST_TIMEOUT_SECS),
            joiner: joiner,
            session_packet_version: 0,
            net_tx: net_tx,
            core_tx: core_tx,
        }))
    }

    /// Login using seeded account
    pub fn login_with_seed(
        seed: &str,
        el_handle: Handle,
        core_tx: CoreMsgTx<T>,
        net_tx: NetworkTx,
    ) -> Result<Client<T>, CoreError>
    where
        T: 'static,
    {
        let arr = Self::divide_seed(seed)?;
        Self::login_impl(
            arr[0],
            arr[1],
            el_handle,
            core_tx,
            net_tx,
            |routing| routing,
        )
    }

    /// This is a Gateway function to the Maidsafe network. This will help
    /// login to an already existing account of the user in the SAFE-network.
    pub fn login(
        acc_locator: &str,
        acc_password: &str,
        el_handle: Handle,
        core_tx: CoreMsgTx<T>,
        net_tx: NetworkTx,
    ) -> Result<Client<T>, CoreError>
    where
        T: 'static,
    {
        Self::login_impl(acc_locator.as_bytes(),
                         acc_password.as_bytes(),
                         el_handle,
                         core_tx,
                         net_tx,
                         |routing| routing)
    }

    fn login_impl<F>(
        acc_locator: &[u8],
        acc_password: &[u8],
        el_handle: Handle,
        core_tx: CoreMsgTx<T>,
        net_tx: NetworkTx,
        routing_wrapper_fn: F,
    ) -> Result<Client<T>, CoreError>
    where
        T: 'static,
        F: Fn(Routing) -> Routing,
    {
        trace!("Attempting to log into an acc.");

        let (password, keyword, pin) = utils::derive_secrets(acc_locator, acc_password);

        let acc_loc = Account::generate_network_id(&keyword, &pin)?;
        let user_cred = UserCred::new(password, pin);

        let dst = Authority::NaeManager(acc_loc);

        let (acc_content, acc_version) = {
            trace!("Creating throw-away routing getter for account packet.");
            let (mut routing, routing_rx) = setup_routing(None, None)?;
            routing = routing_wrapper_fn(routing);

            let msg_id = MessageId::new();
            let val = routing
                .get_mdata_value(
                    dst,
                    acc_loc,
                    TYPE_TAG_SESSION_PACKET,
                    ACC_LOGIN_ENTRY_KEY.to_owned(),
                    msg_id,
                )
                .map_err(CoreError::from)
                .and_then(|_| {
                    wait_for_response!(routing_rx, Response::GetMDataValue, msg_id)
                })
                .map_err(|e| {
                    warn!("Could not fetch account from the Network: {:?}", e);
                    e
                })?;
            (val.content, val.entry_version)
        };

        let acc = match deserialise::<AccountPacket>(&acc_content)? {
            AccountPacket::AccPkt(acc_content) |
            AccountPacket::WithInvitation { acc_pkt: acc_content, .. } => {
                Account::decrypt(&acc_content, &user_cred.password, &user_cred.pin)?
            }
        };

        let id_packet = acc.maid_keys.clone().into();

        let pub_key = acc.maid_keys.sign_pk;
        let digest = sha3_256(&pub_key.0);
        let cm_addr = Authority::ClientManager(XorName(digest));

        trace!("Creating an actual routing...");
        let (mut routing, routing_rx) = setup_routing(Some(id_packet), None)?;
        routing = routing_wrapper_fn(routing);

        let joiner = spawn_routing_thread(routing_rx, core_tx.clone(), net_tx.clone());

        Ok(Self::new(Inner {
            el_handle: el_handle,
            routing: routing,
            hooks: HashMap::with_capacity(10),
            cache: LruCache::new(IMMUT_DATA_CACHE_SIZE),
            client_type: ClientType::reg(acc, acc_loc, user_cred, cm_addr),
            timeout: Duration::from_secs(REQUEST_TIMEOUT_SECS),
            joiner: joiner,
            session_packet_version: acc_version,
            net_tx: net_tx,
            core_tx: core_tx,
        }))
    }

    /// This is a Gateway function to the Maidsafe network. This will help
    /// apps to authorise using an existing pair of keys.
    pub fn from_keys(
        keys: ClientKeys,
        owner: sign::PublicKey,
        el_handle: Handle,
        core_tx: CoreMsgTx<T>,
        net_tx: NetworkTx,
        config: BootstrapConfig,
    ) -> Result<Client<T>, CoreError> {
        Self::from_keys_impl(
            keys,
            owner,
            el_handle,
            core_tx,
            net_tx,
            config,
            |routing| routing,
        )
    }

    fn from_keys_impl<F>(
        keys: ClientKeys,
        owner: sign::PublicKey,
        el_handle: Handle,
        core_tx: CoreMsgTx<T>,
        net_tx: NetworkTx,
        config: BootstrapConfig,
        routing_wrapper_fn: F,
    ) -> Result<Client<T>, CoreError>
    where
        T: 'static,
        F: Fn(Routing) -> Routing,
    {
        trace!("Attempting to log into an acc using client keys.");
        let (mut routing, routing_rx) =
            setup_routing(Some(keys.clone().into()), Some(config.clone()))?;
        routing = routing_wrapper_fn(routing);
        let joiner = spawn_routing_thread(routing_rx, core_tx.clone(), net_tx.clone());

        Ok(Self::new(Inner {
            el_handle: el_handle,
            routing: routing,
            hooks: HashMap::with_capacity(10),
            cache: LruCache::new(IMMUT_DATA_CACHE_SIZE),
            client_type: ClientType::from_keys(keys, owner, config),
            timeout: Duration::from_secs(REQUEST_TIMEOUT_SECS),
            joiner: joiner,
            session_packet_version: 0,
            net_tx: net_tx,
            core_tx: core_tx,
        }))
    }


    /// Allows customising the mock Routing client before logging in using client keys
    #[cfg(any(all(test, feature = "use-mock-routing"),
                all(feature = "testing", feature = "use-mock-routing")))]
    pub fn from_keys_with_hook<F>(
        keys: ClientKeys,
        owner: sign::PublicKey,
        el_handle: Handle,
        core_tx: CoreMsgTx<T>,
        net_tx: NetworkTx,
        config: BootstrapConfig,
        routing_wrapper_fn: F,
    ) -> Result<Client<T>, CoreError>
    where
        F: Fn(Routing) -> Routing,
    {
        Self::from_keys_impl(
            keys,
            owner,
            el_handle,
            core_tx,
            net_tx,
            config,
            routing_wrapper_fn,
        )
    }

    fn new(inner: Inner<T>) -> Self {
        Client { inner: Rc::new(RefCell::new(inner)) }
    }

    /// Set request timeout.
    pub fn set_timeout(&self, duration: Duration) {
        self.inner_mut().timeout = duration;
    }

    /// Restart the routing client and reconnect to the network.
    pub fn restart_routing(&self) -> Result<(), CoreError> {
        let opt_id = match self.inner().client_type {
            ClientType::Registered { ref acc, .. } => Some(acc.maid_keys.clone().into()),
            ClientType::FromKeys { ref keys, .. } => Some(keys.clone().into()),
            ClientType::Unregistered { .. } => None,
        };

        let (routing, routing_rx) = setup_routing(opt_id, self.inner().client_type.config())?;

        let joiner = spawn_routing_thread(
            routing_rx,
            self.inner().core_tx.clone(),
            self.inner().net_tx.clone(),
        );

        self.inner_mut().hooks.clear();
        self.inner_mut().routing = routing;
        self.inner_mut().joiner = joiner;

        self.inner().net_tx.unbounded_send(NetworkEvent::Connected)?;

        Ok(())
    }

    #[doc(hidden)]
    pub fn fire_hook(&self, id: &MessageId, event: CoreEvent) {
        // Using in `if` keeps borrow alive. Do not try to combine the 2 lines into one.
        let opt = self.inner_mut().hooks.remove(id);
        if let Some(hook) = opt {
            let _ = hook.send(event);
        }
    }

    fn divide_seed(seed: &str) -> Result<[&[u8]; SEED_SUBPARTS], CoreError> {
        let seed = seed.as_bytes();
        if seed.len() < SEED_SUBPARTS {
            let e = format!(
                "Improper Seed length of {}. Please supply bigger Seed.",
                seed.len()
            );
            return Err(CoreError::Unexpected(e));
        }

        let interval = seed.len() / SEED_SUBPARTS;

        let mut arr: [&[u8]; SEED_SUBPARTS] = Default::default();
        for (i, val) in arr.iter_mut().enumerate() {
            *val = &seed[interval * i..interval * (i + 1)];
        }

        Ok(arr)
    }

    /// Get immutable data from the network. If the data exists locally in the cache
    /// then it will be immediately be returned without making an actual network
    /// request.
    pub fn get_idata(&self, name: XorName) -> Box<CoreFuture<ImmutableData>> {
        trace!("GetIData for {:?}", name);

        if let Some(data) = self.inner.borrow_mut().cache.get_mut(&name) {
            trace!("ImmutableData found in cache.");
            return future::ok(data.clone()).into_box();
        }

        let inner = Rc::downgrade(&self.inner);
        self.send(move |routing, msg_id| {
            routing.get_idata(Authority::NaeManager(name), name, msg_id)
        }).and_then(|event| match_event!(event, CoreEvent::GetIData))
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
    pub fn put_idata(&self, data: ImmutableData) -> Box<CoreFuture<()>> {
        trace!("PutIData for {:?}", data);

        self.send_mutation(move |routing, dst, msg_id| {
            routing.put_idata(dst, data.clone(), msg_id)
        })
    }

    /// Put `MutableData` onto the network.
    pub fn put_mdata(&self, data: MutableData) -> Box<CoreFuture<()>> {
        trace!("PutMData for {:?}", data);

        let requester = fry!(self.public_signing_key());
        self.send_mutation(move |routing, dst, msg_id| {
            routing.put_mdata(dst, data.clone(), msg_id, requester)
        })
    }

    /// Mutates `MutableData` entries in bulk.
    pub fn mutate_mdata_entries(
        &self,
        name: XorName,
        tag: u64,
        actions: BTreeMap<Vec<u8>, EntryAction>,
    ) -> Box<CoreFuture<()>> {
        trace!("PutMData for {:?}", name);

        let requester = fry!(self.public_signing_key());
        self.send_mutation(move |routing, dst, msg_id| {
            routing.mutate_mdata_entries(dst, name, tag, actions.clone(), msg_id, requester)
        })
    }

    /// Get entire `MutableData` from the network.
    pub fn get_mdata(&self, name: XorName, tag: u64) -> Box<CoreFuture<MutableData>> {
        trace!("GetMData for {:?}", name);

        self.send(move |routing, msg_id| {
            routing.get_mdata(Authority::NaeManager(name), name, tag, msg_id)
        }).and_then(|event| match_event!(event, CoreEvent::GetMData))
            .into_box()
    }

    /// Get a shell (bare bones) version of `MutableData` from the network.
    pub fn get_mdata_shell(&self, name: XorName, tag: u64) -> Box<CoreFuture<MutableData>> {
        trace!("GetMDataShell for {:?}", name);

        self.send(move |routing, msg_id| {
            routing.get_mdata_shell(Authority::NaeManager(name), name, tag, msg_id)
        }).and_then(|event| match_event!(event, CoreEvent::GetMDataShell))
            .into_box()
    }

    /// Get a current version of `MutableData` from the network.
    pub fn get_mdata_version(&self, name: XorName, tag: u64) -> Box<CoreFuture<u64>> {
        trace!("GetMDataVersion for {:?}", name);

        self.send(move |routing, msg_id| {
            routing.get_mdata_version(Authority::NaeManager(name), name, tag, msg_id)
        }).and_then(|event| match_event!(event, CoreEvent::GetMDataVersion))
            .into_box()
    }

    /// Returns a complete list of entries in `MutableData`.
    pub fn list_mdata_entries(
        &self,
        name: XorName,
        tag: u64,
    ) -> Box<CoreFuture<BTreeMap<Vec<u8>, Value>>> {
        trace!("ListMDataEntries for {:?}", name);

        self.send(move |routing, msg_id| {
            routing.list_mdata_entries(Authority::NaeManager(name), name, tag, msg_id)
        }).and_then(|event| match_event!(event, CoreEvent::ListMDataEntries))
            .into_box()
    }

    /// Returns a list of keys in `MutableData` stored on the network
    pub fn list_mdata_keys(&self, name: XorName, tag: u64) -> Box<CoreFuture<BTreeSet<Vec<u8>>>> {
        trace!("ListMDataKeys for {:?}", name);

        self.send(move |routing, msg_id| {
            routing.list_mdata_keys(Authority::NaeManager(name), name, tag, msg_id)
        }).and_then(|event| match_event!(event, CoreEvent::ListMDataKeys))
            .into_box()
    }

    /// Returns a list of keys in `MutableData` stored on the network
    pub fn list_mdata_values(&self, name: XorName, tag: u64) -> Box<CoreFuture<Vec<Value>>> {
        trace!("ListMDataValues for {:?}", name);

        self.send(move |routing, msg_id| {
            routing.list_mdata_values(Authority::NaeManager(name), name, tag, msg_id)
        }).and_then(|event| match_event!(event, CoreEvent::ListMDataValues))
            .into_box()
    }

    /// Get a single entry from `MutableData`
    pub fn get_mdata_value(&self, name: XorName, tag: u64, key: Vec<u8>) -> Box<CoreFuture<Value>> {
        trace!("GetMDataValue for {:?}", name);

        self.send(move |routing, msg_id| {
            routing.get_mdata_value(Authority::NaeManager(name), name, tag, key.clone(), msg_id)
        }).and_then(|event| match_event!(event, CoreEvent::GetMDataValue))
            .into_box()
    }

    /// Get data from the network.
    pub fn get_account_info(&self) -> Box<CoreFuture<AccountInfo>> {
        trace!("Account info GET issued.");

        let dst = fry!(self.cm_addr());
        self.send(move |routing, msg_id| routing.get_account_info(dst, msg_id))
            .and_then(|event| match_event!(event, CoreEvent::GetAccountInfo))
            .into_box()
    }

    /// Returns a list of permissions in `MutableData` stored on the network
    pub fn list_mdata_permissions(
        &self,
        name: XorName,
        tag: u64,
    ) -> Box<CoreFuture<BTreeMap<User, PermissionSet>>> {
        trace!("ListMDataPermissions for {:?}", name);

        self.send(move |routing, msg_id| {
            routing.list_mdata_permissions(Authority::NaeManager(name), name, tag, msg_id)
        }).and_then(|event| match_event!(event, CoreEvent::ListMDataPermissions))
            .into_box()
    }

    /// Returns a list of permissions for a particular User in MutableData
    pub fn list_mdata_user_permissions(
        &self,
        name: XorName,
        tag: u64,
        user: User,
    ) -> Box<CoreFuture<PermissionSet>> {
        trace!("ListMDataUserPermissions for {:?}", name);

        self.send(move |routing, msg_id| {
            let dst = Authority::NaeManager(name);
            routing.list_mdata_user_permissions(dst, name, tag, user, msg_id)
        }).and_then(|event| {
                match_event!(event, CoreEvent::ListMDataUserPermissions)
            })
            .into_box()
    }

    /// Updates or inserts a permission set for a given user
    pub fn set_mdata_user_permissions(
        &self,
        name: XorName,
        tag: u64,
        user: User,
        permissions: PermissionSet,
        version: u64,
    ) -> Box<CoreFuture<()>> {
        trace!("SetMDataUserPermissions for {:?}", name);

        let requester = fry!(self.public_signing_key());
        self.send_mutation(move |routing, dst, msg_id| {
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
    pub fn del_mdata_user_permissions(
        &self,
        name: XorName,
        tag: u64,
        user: User,
        version: u64,
    ) -> Box<CoreFuture<()>> {
        trace!("DelMDataUserPermissions for {:?}", name);

        let requester = fry!(self.public_signing_key());
        self.send_mutation(move |routing, dst, msg_id| {
            routing.del_mdata_user_permissions(dst, name, tag, user, version, msg_id, requester)
        })
    }

    /// Sends an ownership transfer request
    pub fn change_mdata_owner(
        &self,
        name: XorName,
        tag: u64,
        new_owner: sign::PublicKey,
        version: u64,
    ) -> Box<CoreFuture<()>> {
        trace!("ChangeMDataOwner for {:?}", name);

        self.send_mutation(move |routing, dst, msg_id| {
            routing.change_mdata_owner(dst, name, tag, btree_set![new_owner], version, msg_id)
        })
    }

    /// Fetches a list of authorised keys and version in MaidManager
    pub fn list_auth_keys_and_version(&self) -> Box<CoreFuture<(BTreeSet<sign::PublicKey>, u64)>> {
        trace!("ListAuthKeysAndVersion");

        let dst = fry!(self.cm_addr());
        self.send(move |routing, msg_id| {
            routing.list_auth_keys_and_version(dst, msg_id)
        }).and_then(|event| {
                match_event!(event, CoreEvent::ListAuthKeysAndVersion)
            })
            .into_box()
    }

    /// Adds a new authorised key to MaidManager
    pub fn ins_auth_key(&self, key: sign::PublicKey, version: u64) -> Box<CoreFuture<()>> {
        trace!("InsAuthKey ({:?})", key);

        self.send_mutation(move |routing, dst, msg_id| {
            routing.ins_auth_key(dst, key, version, msg_id)
        })
    }

    /// Removes an authorised key from MaidManager
    pub fn del_auth_key(&self, key: sign::PublicKey, version: u64) -> Box<CoreFuture<()>> {
        trace!("DelAuthKey ({:?})", key);

        self.send_mutation(move |routing, dst, msg_id| {
            routing.del_auth_key(dst, key, version, msg_id)
        })
    }

    /// Sets the current status of std/root dirs creation
    pub fn set_std_dirs_created(&self, val: bool) -> Result<(), CoreError> {
        let mut inner = self.inner_mut();
        let account = inner.client_type.acc_mut()?;
        account.root_dirs_created = val;
        Ok(())
    }

    /// Returns the current status of std/root dirs creation
    pub fn std_dirs_created(&self) -> Result<bool, CoreError> {
        let inner = self.inner();
        let account = inner.client_type.acc()?;
        Ok(account.root_dirs_created)
    }

    /// Replaces the config root reference in the account packet.
    /// Returns `false` if it wasn't updated.
    /// Doesn't actually modify the session packet - you should call
    /// `update_account_packet` afterwards to actually update it on the
    /// network.
    pub fn set_access_container(&self, dir: MDataInfo) -> Result<bool, CoreError> {
        trace!("Setting user root Dir ID.");

        let mut inner = self.inner_mut();
        let account = inner.client_type.acc_mut()?;

        if account.access_container != dir {
            account.access_container = dir;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Get User's Access Container if available in account packet used for
    /// current login
    pub fn access_container(&self) -> Result<MDataInfo, CoreError> {
        self.inner().client_type.acc().map(|account| {
            account.access_container.clone()
        })
    }

    /// Replaces the config root reference in the account packet.
    /// Returns `false` if it wasn't updated.
    /// Doesn't actually modify the session packet - you should call
    /// `update_account_packet` afterwards to actually update it on the
    /// network.
    pub fn set_config_root_dir(&self, dir: MDataInfo) -> Result<bool, CoreError> {
        trace!("Setting configuration root Dir ID.");

        let mut inner = self.inner_mut();
        let account = inner.client_type.acc_mut()?;

        if account.config_root != dir {
            account.config_root = dir;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Get Maidsafe specific configuration's Root Directory ID if available in
    /// account packet used for current login
    pub fn config_root_dir(&self) -> Result<MDataInfo, CoreError> {
        self.inner().client_type.acc().map(|account| {
            account.config_root.clone()
        })
    }

    /// Returns the public encryption key
    pub fn public_encryption_key(&self) -> Result<box_::PublicKey, CoreError> {
        self.inner().client_type.public_encryption_key()
    }

    /// Returns the Secret encryption key
    pub fn secret_encryption_key(&self) -> Result<shared_box::SecretKey, CoreError> {
        self.inner().client_type.secret_encryption_key()
    }

    /// Returns the public and secret encryption keys.
    pub fn encryption_keypair(
        &self,
    ) -> Result<(box_::PublicKey, shared_box::SecretKey), CoreError> {
        let inner = self.inner();
        let pk = inner.client_type.public_encryption_key()?;
        let sk = inner.client_type.secret_encryption_key()?;
        Ok((pk, sk))
    }

    /// Returns the Public Signing key
    pub fn public_signing_key(&self) -> Result<sign::PublicKey, CoreError> {
        self.inner().client_type.public_signing_key()
    }

    /// Returns the Secret Signing key
    pub fn secret_signing_key(&self) -> Result<shared_sign::SecretKey, CoreError> {
        self.inner().client_type.secret_signing_key()
    }

    /// Returns the Symmetric Encryption key
    pub fn secret_symmetric_key(&self) -> Result<shared_secretbox::Key, CoreError> {
        self.inner().client_type.secret_symmetric_key()
    }

    /// Returns the public and secret signing keys.
    pub fn signing_keypair(&self) -> Result<(sign::PublicKey, shared_sign::SecretKey), CoreError> {
        let inner = self.inner();
        let pk = inner.client_type.public_signing_key()?;
        let sk = inner.client_type.secret_signing_key()?;
        Ok((pk, sk))
    }

    /// Return the owner signing key
    pub fn owner_key(&self) -> Result<sign::PublicKey, CoreError> {
        self.inner().client_type.owner_key()
    }

    /// Returns the `crust::Config` associated with the `crust::Service` (if any).
    pub fn bootstrap_config() -> Result<BootstrapConfig, CoreError> {
        Ok(Routing::bootstrap_config()?)
    }

    fn prepare_account_packet_update(
        account: &Account,
        keys: &UserCred,
        entry_version: u64,
    ) -> Result<BTreeMap<Vec<u8>, EntryAction>, CoreError> {
        let encrypted_account = account.encrypt(&keys.password, &keys.pin)?;
        let content = serialise(&AccountPacket::AccPkt(encrypted_account))?;
        Ok(btree_map![
            ACC_LOGIN_ENTRY_KEY.to_owned() => EntryAction::Update(Value {
                content,
                entry_version,
            })
        ])
    }

    /// Updates user's account packet
    pub fn update_account_packet(&self) -> Box<CoreFuture<()>> {
        trace!("Updating account packet.");

        let entry_version = {
            let mut inner = self.inner_mut();
            inner.session_packet_version += 1;
            inner.session_packet_version
        };

        let update = {
            let inner = self.inner();
            let account = fry!(inner.client_type.acc());
            let keys = fry!(inner.client_type.user_cred());

            fry!(Self::prepare_account_packet_update(
                account,
                keys,
                entry_version,
            ))
        };

        let data_name = fry!(self.inner().client_type.acc_loc());

        self.mutate_mdata_entries(data_name, TYPE_TAG_SESSION_PACKET, update)
    }

    /// Sends a request and returns a future that resolves to the response.
    fn send<F>(&self, req: F) -> Box<CoreFuture<CoreEvent>>
    where
        F: Fn(&mut Routing, MessageId) -> Result<(), InterfaceError> + 'static,
    {
        let inner = Rc::downgrade(&self.inner);
        let func = move |_| if let Some(inner) = inner.upgrade() {
            let msg_id = MessageId::new();
            if let Err(error) = req(&mut inner.borrow_mut().routing, msg_id) {
                return future::err(CoreError::from(error)).into_box();
            }

            let (hook, rx) = oneshot::channel();
            let _ = inner.borrow_mut().hooks.insert(msg_id, hook);

            let rx = rx.map_err(|_| CoreError::OperationAborted);
            let rx = setup_timeout_and_retry_delay(&inner, msg_id, rx);
            let rx = rx.map(|event| if let CoreEvent::RateLimitExceeded = event {
                Loop::Continue(())
            } else {
                Loop::Break(event)
            });
            rx.into_box()
        } else {
            future::err(CoreError::OperationAborted).into_box()
        };

        future::loop_fn((), func).into_box()
    }

    /// Sends a mutation request.
    fn send_mutation<F>(&self, req: F) -> Box<CoreFuture<()>>
    where
        F: Fn(&mut Routing, Authority<XorName>, MessageId) -> Result<(), InterfaceError> + 'static,
    {
        let dst = fry!(self.cm_addr());

        self.send(move |routing, msg_id| req(routing, dst, msg_id))
            .and_then(|event| match_event!(event, CoreEvent::Mutation))
            .into_box()
    }

    fn inner(&self) -> Ref<Inner<T>> {
        self.inner.borrow()
    }

    fn inner_mut(&self) -> RefMut<Inner<T>> {
        self.inner.borrow_mut()
    }

    fn cm_addr(&self) -> Result<Authority<XorName>, CoreError> {
        self.inner().client_type.cm_addr().map(|a| *a)
    }
}


#[cfg(any(all(test, feature = "use-mock-routing"),
            all(feature = "testing", feature = "use-mock-routing")))]
impl<T: 'static> Client<T> {
    /// Allows customising the mock Routing client before registering a new account
    pub fn registered_with_hook<F>(
        acc_locator: &str,
        acc_password: &str,
        invitation: &str,
        el_handle: Handle,
        core_tx: CoreMsgTx<T>,
        net_tx: NetworkTx,
        routing_wrapper_fn: F,
    ) -> Result<Client<T>, CoreError>
    where
        T: 'static,
        F: Fn(Routing) -> Routing,
    {
        Self::registered_impl(
            acc_locator.as_bytes(),
            acc_password.as_bytes(),
            invitation,
            el_handle,
            core_tx,
            net_tx,
            None,
            routing_wrapper_fn,
        )
    }

    /// Allows to customise the mock Routing client before logging into the network
    pub fn login_with_hook<F>(
        acc_locator: &str,
        acc_password: &str,
        el_handle: Handle,
        core_tx: CoreMsgTx<T>,
        net_tx: NetworkTx,
        routing_wrapper_fn: F,
    ) -> Result<Client<T>, CoreError>
    where
        T: 'static,
        F: Fn(Routing) -> Routing,
    {
        Self::login_impl(
            acc_locator.as_bytes(),
            acc_password.as_bytes(),
            el_handle,
            core_tx,
            net_tx,
            routing_wrapper_fn,
        )
    }

    #[doc(hidden)]
    pub fn set_network_limits(&self, max_ops_count: Option<u64>) {
        self.inner.borrow_mut().routing.set_network_limits(
            max_ops_count,
        );
    }

    #[doc(hidden)]
    pub fn simulate_network_disconnect(&self) {
        self.inner.borrow_mut().routing.simulate_disconnect();
    }

    #[doc(hidden)]
    pub fn set_simulate_timeout(&self, enabled: bool) {
        self.inner.borrow_mut().routing.set_simulate_timeout(
            enabled,
        );
    }
}

impl<T> fmt::Debug for Client<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Client")
    }
}

fn setup_timeout_and_retry_delay<T, F>(
    inner: &Rc<RefCell<Inner<T>>>,
    msg_id: MessageId,
    future: F,
) -> Box<CoreFuture<CoreEvent>>
where
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
            return Either::A(future::err(CoreError::Unexpected(
                format!("Timeout create error: {:?}", err),
            )));
        }
    };

    fn map_result(result: io::Result<()>) -> Result<CoreEvent, CoreError> {
        match result {
            Ok(()) => Err(CoreError::RequestTimeout),
            Err(err) => Err(CoreError::Unexpected(
                format!("Timeout fire error {:?}", err),
            )),
        }
    }

    Either::B(timeout.then(map_result))
}


type TimeoutFuture = Either<
    FutureResult<CoreEvent, CoreError>,
    Then<
        Timeout,
        Result<CoreEvent, CoreError>,
        fn(io::Result<()>) -> Result<CoreEvent, CoreError>,
    >,
>;

// ------------------------------------------------------------
// Helper Struct
// ------------------------------------------------------------

struct UserCred {
    pin: Vec<u8>,
    password: Vec<u8>,
}

impl UserCred {
    fn new(password: Vec<u8>, pin: Vec<u8>) -> UserCred {
        UserCred {
            pin: pin,
            password: password,
        }
    }
}

#[cfg_attr(feature = "cargo-clippy", allow(large_enum_variant))]
enum ClientType {
    Unregistered { config: Option<BootstrapConfig> },
    Registered {
        acc: Account,
        acc_loc: XorName,
        user_cred: UserCred,
        cm_addr: Authority<XorName>,
    },
    FromKeys {
        keys: ClientKeys,
        owner_key: sign::PublicKey,
        cm_addr: Authority<XorName>,
        config: BootstrapConfig,
    },
}

impl ClientType {
    fn from_keys(keys: ClientKeys, owner_key: sign::PublicKey, config: BootstrapConfig) -> Self {
        let digest = sha3_256(&owner_key.0);
        let cm_addr = Authority::ClientManager(XorName(digest));

        ClientType::FromKeys {
            keys,
            owner_key,
            cm_addr,
            config,
        }
    }

    fn reg(
        acc: Account,
        acc_loc: XorName,
        user_cred: UserCred,
        cm_addr: Authority<XorName>,
    ) -> Self {
        ClientType::Registered {
            acc,
            acc_loc,
            user_cred,
            cm_addr,
        }
    }

    fn unreg(config: Option<BootstrapConfig>) -> Self {
        ClientType::Unregistered { config }
    }

    fn config(&self) -> Option<BootstrapConfig> {
        match *self {
            ClientType::Registered { .. } => None,
            ClientType::Unregistered { ref config, .. } => config.clone(),
            ClientType::FromKeys { ref config, .. } => Some(config.clone()),
        }
    }

    fn acc(&self) -> Result<&Account, CoreError> {
        match *self {
            ClientType::Registered { ref acc, .. } => Ok(acc),
            ClientType::FromKeys { .. } |
            ClientType::Unregistered { .. } => Err(CoreError::OperationForbidden),
        }
    }

    fn acc_mut(&mut self) -> Result<&mut Account, CoreError> {
        match *self {
            ClientType::Registered { ref mut acc, .. } => Ok(acc),
            ClientType::FromKeys { .. } |
            ClientType::Unregistered { .. } => Err(CoreError::OperationForbidden),
        }
    }

    fn acc_loc(&self) -> Result<XorName, CoreError> {
        match *self {
            ClientType::Registered { acc_loc, .. } => Ok(acc_loc),
            ClientType::FromKeys { .. } |
            ClientType::Unregistered { .. } => Err(CoreError::OperationForbidden),
        }
    }

    fn user_cred(&self) -> Result<&UserCred, CoreError> {
        match *self {
            ClientType::Registered { ref user_cred, .. } => Ok(user_cred),
            ClientType::FromKeys { .. } |
            ClientType::Unregistered { .. } => Err(CoreError::OperationForbidden),
        }
    }

    fn cm_addr(&self) -> Result<&Authority<XorName>, CoreError> {
        match *self {
            ClientType::FromKeys { ref cm_addr, .. } |
            ClientType::Registered { ref cm_addr, .. } => Ok(cm_addr),
            ClientType::Unregistered { .. } => Err(CoreError::OperationForbidden),
        }
    }

    fn owner_key(&self) -> Result<sign::PublicKey, CoreError> {
        match *self {
            ClientType::FromKeys { owner_key, .. } => Ok(owner_key),
            ClientType::Registered { ref acc, .. } => Ok(acc.maid_keys.sign_pk),
            ClientType::Unregistered { .. } => Err(CoreError::OperationForbidden),
        }
    }

    fn public_signing_key(&self) -> Result<sign::PublicKey, CoreError> {
        match *self {
            ClientType::FromKeys { ref keys, .. } => Ok(keys.sign_pk),
            ClientType::Registered { ref acc, .. } => Ok(acc.maid_keys.sign_pk),
            ClientType::Unregistered { .. } => Err(CoreError::OperationForbidden),
        }
    }

    fn secret_signing_key(&self) -> Result<shared_sign::SecretKey, CoreError> {
        match *self {
            ClientType::FromKeys { ref keys, .. } => Ok(keys.sign_sk.clone()),
            ClientType::Registered { ref acc, .. } => Ok(acc.maid_keys.sign_sk.clone()),
            ClientType::Unregistered { .. } => Err(CoreError::OperationForbidden),
        }
    }

    fn public_encryption_key(&self) -> Result<box_::PublicKey, CoreError> {
        match *self {
            ClientType::FromKeys { ref keys, .. } => Ok(keys.enc_pk),
            ClientType::Registered { ref acc, .. } => Ok(acc.maid_keys.enc_pk),
            ClientType::Unregistered { .. } => Err(CoreError::OperationForbidden),
        }
    }

    fn secret_encryption_key(&self) -> Result<shared_box::SecretKey, CoreError> {
        match *self {
            ClientType::FromKeys { ref keys, .. } => Ok(keys.enc_sk.clone()),
            ClientType::Registered { ref acc, .. } => Ok(acc.maid_keys.enc_sk.clone()),
            ClientType::Unregistered { .. } => Err(CoreError::OperationForbidden),
        }
    }

    fn secret_symmetric_key(&self) -> Result<shared_secretbox::Key, CoreError> {
        match *self {
            ClientType::FromKeys { ref keys, .. } => Ok(keys.enc_key.clone()),
            ClientType::Registered { ref acc, .. } => Ok(acc.maid_keys.enc_key.clone()),
            ClientType::Unregistered { .. } => Err(CoreError::OperationForbidden),
        }
    }
}

fn setup_routing(
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

fn spawn_routing_thread<T>(
    routing_rx: Receiver<Event>,
    core_tx: CoreMsgTx<T>,
    net_tx: NetworkTx,
) -> Joiner
where
    T: 'static,
{
    thread::named("Routing Event Loop", move || {
        routing_event_loop::run(&routing_rx, core_tx, &net_tx)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use DIR_TAG;
    use errors::CoreError;
    use futures::Future;
    use futures::sync::mpsc;
    #[cfg(feature = "use-mock-routing")]
    use rand;
    use routing::{ClientError, ImmutableData};
    use tokio_core::reactor::Core;
    use utils;
    use utils::test_utils::{finish, random_client, setup_client};

    // Test logging in using a seeded account.
    #[test]
    fn seeded_login() {
        let invalid_seed = String::from("123");
        {
            let el = unwrap!(Core::new());
            let (core_tx, _): (CoreMsgTx<()>, _) = mpsc::unbounded();
            let (net_tx, _) = mpsc::unbounded();

            match Client::registered_with_seed(&invalid_seed, el.handle(), core_tx, net_tx) {
                Err(CoreError::Unexpected(_)) => (),
                _ => panic!("Expected a failure"),
            }
        }
        {
            let el = unwrap!(Core::new());
            let (core_tx, _): (CoreMsgTx<()>, _) = mpsc::unbounded();
            let (net_tx, _) = mpsc::unbounded();

            match Client::login_with_seed(&invalid_seed, el.handle(), core_tx, net_tx) {
                Err(CoreError::Unexpected(_)) => (),
                _ => panic!("Expected a failure"),
            }
        }

        let seed = unwrap!(utils::generate_random_string(30));

        setup_client(
            |el_h, core_tx, net_tx| {
                match Client::login_with_seed(
                    &seed,
                    el_h.clone(),
                    core_tx.clone(),
                    net_tx.clone(),
                ) {
                    Err(CoreError::RoutingClientError(ClientError::NoSuchAccount)) => (),
                    x => panic!("Unexpected Login outcome: {:?}", x),
                }
                Client::registered_with_seed(&seed, el_h, core_tx, net_tx)
            },
            |_| finish(),
        );

        setup_client(|el_h, core_tx, net_tx| Client::login_with_seed(&seed, el_h, core_tx, net_tx),
                     |_| finish());
    }

    // Tests for unregistered clients.
    // 1. Have a registered client PUT something on the network.
    // 2. Try to set the access container as unregistered - this should fail.
    // 3. Try to set the config root directory as unregistered - this should fail.
    #[test]
    fn unregistered_client() {
        let orig_data = ImmutableData::new(unwrap!(utils::generate_random_vector(30)));

        // Registered Client PUTs something onto the network
        {
            let orig_data = orig_data.clone();
            random_client(|client| client.put_idata(orig_data));
        }

        // Unregistered Client should be able to retrieve the data
        setup_client(|el_h, core_tx, net_tx| Client::unregistered(el_h, core_tx, net_tx, None),
                     move |client| {
            let client2 = client.clone();
            let client3 = client.clone();

            client
                .get_idata(*orig_data.name())
                .then(move |res| {
                          let data = unwrap!(res);
                          assert_eq!(data, orig_data);
                          let dir = unwrap!(MDataInfo::random_private(DIR_TAG));
                          client2.set_access_container(dir)
                      })
                .then(move |res| {
                    let e = match res {
                        Ok(_) => {
                            panic!("Unregistered client should not be allowed to set user root dir")
                        }
                        Err(e) => e,
                    };
                    match e {
                        CoreError::OperationForbidden => (),
                        _ => panic!("Unexpected {:?}", e),
                    }

                    let dir = unwrap!(MDataInfo::random_private(DIR_TAG));
                    client3.set_config_root_dir(dir)
                })
                .then(|res| {
                    let e = match res {
                        Ok(_) => {
                            panic!("Unregistered client should not be allowed to set config root \
                                    dir")
                        }
                        Err(e) => e,
                    };
                    match e {
                        CoreError::OperationForbidden => (),
                        _ => panic!("Unexpected {:?}", e),
                    }
                    finish()
                })
        });
    }

    // Test account creation.
    // It should succeed the first time and fail the second time with the same secrets.
    #[test]
    fn registered_client() {
        let el = unwrap!(Core::new());
        let (core_tx, _): (CoreMsgTx<()>, _) = mpsc::unbounded();
        let (net_tx, _) = mpsc::unbounded();

        let sec_0 = unwrap!(utils::generate_random_string(10));
        let sec_1 = unwrap!(utils::generate_random_string(10));
        let inv = unwrap!(utils::generate_random_string(10));

        // Account creation for the 1st time - should succeed
        let _ = unwrap!(Client::registered(
            &sec_0,
            &sec_1,
            &inv,
            el.handle(),
            core_tx.clone(),
            net_tx.clone(),
        ));

        // Account creation - same secrets - should fail
        match Client::registered(&sec_0, &sec_1, &inv, el.handle(), core_tx, net_tx) {
            Ok(_) => panic!("Account name hijacking should fail"),
            Err(CoreError::RoutingClientError(ClientError::AccountExists)) => (),
            Err(err) => panic!("{:?}", err),
        }
    }

    // Test creating and logging in to an account on the network.
    #[test]
    fn login() {
        let sec_0 = unwrap!(utils::generate_random_string(10));
        let sec_1 = unwrap!(utils::generate_random_string(10));
        let inv = unwrap!(utils::generate_random_string(10));

        setup_client(
            |el_h, core_tx, net_tx| {
                match Client::login(
                    &sec_0,
                    &sec_1,
                    el_h.clone(),
                    core_tx.clone(),
                    net_tx.clone(),
                ) {
                    Err(CoreError::RoutingClientError(ClientError::NoSuchAccount)) => (),
                    x => panic!("Unexpected Login outcome: {:?}", x),
                }
                Client::registered(&sec_0, &sec_1, &inv, el_h, core_tx, net_tx)
            },
            |_| finish(),
        );

        setup_client(|el_h, core_tx, net_tx| Client::login(&sec_0, &sec_1, el_h, core_tx, net_tx),
                     |_| finish());
    }

    // Test creation of an access container.
    #[test]
    fn access_container_creation() {
        let sec_0 = unwrap!(utils::generate_random_string(10));
        let sec_1 = unwrap!(utils::generate_random_string(10));
        let inv = unwrap!(utils::generate_random_string(10));

        let dir = unwrap!(MDataInfo::random_private(DIR_TAG));
        let dir_clone = dir.clone();

        setup_client(|el_h, core_tx, net_tx| {
                         Client::registered(&sec_0, &sec_1, &inv, el_h, core_tx, net_tx)
                     },
                     move |client| {
                         assert!(client.access_container().is_ok());
                         assert!(client.set_access_container(dir).is_ok());
                         client.update_account_packet()
                     });

        setup_client(|el_h, core_tx, net_tx| Client::login(&sec_0, &sec_1, el_h, core_tx, net_tx),
                     move |client| {
                         let got_dir = unwrap!(client.access_container());
                         assert_eq!(got_dir, dir_clone);
                         finish()
                     });
    }

    // Test setting the configuration root directory.
    #[test]
    fn config_root_dir_creation() {
        let sec_0 = unwrap!(utils::generate_random_string(10));
        let sec_1 = unwrap!(utils::generate_random_string(10));
        let inv = unwrap!(utils::generate_random_string(10));

        let dir = unwrap!(MDataInfo::random_private(DIR_TAG));
        let dir_clone = dir.clone();

        setup_client(|el_h, core_tx, net_tx| {
                         Client::registered(&sec_0, &sec_1, &inv, el_h, core_tx, net_tx)
                     },
                     move |client| {
                         assert!(client.config_root_dir().is_ok());
                         assert!(client.set_config_root_dir(dir).is_ok());
                         client.update_account_packet()
                     });

        setup_client(|el_h, core_tx, net_tx| Client::login(&sec_0, &sec_1, el_h, core_tx, net_tx),
                     move |client| {
                         let got_dir = unwrap!(client.config_root_dir());
                         assert_eq!(got_dir, dir_clone);
                         finish()
                     });
    }

    // Test restarting routing after a network disconnect.
    #[cfg(feature = "use-mock-routing")]
    #[test]
    fn restart_routing() {
        use event::NetworkEvent;
        use utils::test_utils::random_client_with_net_obs;
        use futures;
        use maidsafe_utilities::thread;
        use std::sync::mpsc;

        let (tx, rx) = mpsc::channel();
        let (hook, keep_alive) = futures::oneshot();

        let _joiner = thread::named("Network Observer", move || {
            match unwrap!(rx.recv()) {
                NetworkEvent::Disconnected => (),
                x => panic!("Unexpected network event: {:?}", x),
            }
            match unwrap!(rx.recv()) {
                NetworkEvent::Connected => (),
                x => panic!("Unexpected network event: {:?}", x),
            }
            let _ = hook.send(());
        });

        random_client_with_net_obs(
            move |net_event| unwrap!(tx.send(net_event)),
            move |client| {
                client.simulate_network_disconnect();
                unwrap!(client.restart_routing());
                keep_alive
            },
        );
    }

    // Test that a `RequestTimeout` error is returned on network timeout.
    #[cfg(feature = "use-mock-routing")]
    #[test]
    fn timeout() {
        use std::time::Duration;

        // Get
        random_client(|client| {
            let client2 = client.clone();

            client.set_simulate_timeout(true);
            client.set_timeout(Duration::from_millis(250));

            client
                .get_idata(rand::random())
                .then(|result| match result {
                    Ok(_) => panic!("Unexpected success"),
                    Err(CoreError::RequestTimeout) => Ok::<_, CoreError>(()),
                    Err(err) => panic!("Unexpected {:?}", err),
                })
                .then(move |result| {
                    unwrap!(result);

                    let data = unwrap!(utils::generate_random_vector(4));
                    let data = ImmutableData::new(data);

                    client2.put_idata(data)
                })
                .then(|result| match result {
                    Ok(_) => panic!("Unexpected success"),
                    Err(CoreError::RequestTimeout) => Ok::<_, CoreError>(()),
                    Err(err) => panic!("Unexpected {:?}", err),
                })
        })
    }
}
