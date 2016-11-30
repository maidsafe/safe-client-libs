// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net
// Commercial License, version 1.0 or later, or (2) The General Public License
// (GPL), version 3, depending on which licence you accepted on initial access
// to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project
// generally, you agree to be bound by the terms of the MaidSafe Contributor
// Agreement, version 1.0.
// This, along with the Licenses can be found in the root directory of this
// project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network
// Software distributed under the GPL Licence is distributed on an "AS IS"
// BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
//
// Please review the Licences for the specific language governing permissions
// and limitations relating to use of the SAFE Network Software.

mod account;
#[cfg(feature = "use-mock-routing")]
mod mock_routing;
mod routing_el;

use core::{CoreError, CoreEvent, CoreFuture, CoreMsg, CoreMsgTx, DIR_TAG, FutureExt, NetworkEvent,
           NetworkTx, utility};
use futures::{self, Complete, Future};
use lru_cache::LruCache;
use maidsafe_utilities::thread::{self, Joiner};
use routing::{AccountInfo, Authority, EntryAction, Event, FullId, ImmutableData, InterfaceError,
              MessageId, MutableData, PermissionSet, Response, TYPE_TAG_SESSION_PACKET, User,
              Value, XorName};
#[cfg(not(feature = "use-mock-routing"))]
use routing::Client as Routing;
use rust_sodium::crypto::{box_, sign};
use rust_sodium::crypto::hash::sha256::{self, Digest};
pub use self::account::{ClientKeys, Dir};
use self::account::Account;
#[cfg(feature = "use-mock-routing")]
use self::mock_routing::MockRouting as Routing;
use std::cell::{Ref, RefCell, RefMut};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::rc::Rc;
use std::sync::mpsc::{self, Receiver};
use std::time::Duration;
use tokio_core::reactor::{Handle, Timeout};

const ACC_PKT_TIMEOUT_SECS: u64 = 60;
const CONNECTION_TIMEOUT_SECS: u64 = 10;
const IMMUT_DATA_CACHE_SIZE: usize = 300;
const REQUEST_TIMEOUT_SECS: u64 = 120;

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

macro_rules! oneshot {
    ($client:ident, $event:path) => {{
        let msg_id = MessageId::new();
        let (hook, oneshot) = futures::oneshot();
        let fut = oneshot.map_err(|_| CoreError::OperationAborted)
            .and_then(|event| match_event!(event, $event));

        (hook, $client.timeout(msg_id, fut), msg_id)
    }}
}

/// The main self-authentication client instance that will interface all the
/// request from high level API's to the actual routing layer and manage all
/// interactions with it. This is essentially a non-blocking Client with
/// an asynchronous API using the futures abstraction from the futures-rs crate
#[derive(Clone)]
pub struct Client {
    inner: Rc<RefCell<Inner>>,
}

struct Inner {
    el_handle: Handle,
    routing: Routing,
    hooks: HashMap<MessageId, Complete<CoreEvent>>,
    cache: LruCache<XorName, ImmutableData>,
    client_type: ClientType,
    timeout: Duration,
    joiner: Joiner,
    session_packet_version: u64,
}

impl Client {
    /// This is a getter-only Gateway function to the Maidsafe network. It will
    /// create an unregistered random client, which can do very limited set of
    /// operations - eg., a Network-Get
    pub fn unregistered<T>(el_handle: Handle,
                           core_tx: CoreMsgTx<T>,
                           net_tx: NetworkTx)
                           -> Result<Self, CoreError>
        where T: 'static
    {
        trace!("Creating unregistered client.");

        let (routing, routing_rx) = setup_routing(None)?;
        let net_tx_clone = net_tx.clone();
        let core_tx_clone = core_tx.clone();
        let joiner = spawn_routing_thread(routing_rx, core_tx_clone, net_tx_clone);

        Ok(Self::new(Inner {
            el_handle: el_handle,
            routing: routing,
            hooks: HashMap::with_capacity(10),
            cache: LruCache::new(IMMUT_DATA_CACHE_SIZE),
            client_type: ClientType::Unregistered,
            timeout: Duration::from_secs(REQUEST_TIMEOUT_SECS),
            joiner: joiner,
            session_packet_version: 0,
        }))
    }

    /// This is a Gateway function to the Maidsafe network. This will help
    /// create a fresh acc for the user in the SAFE-network.
    pub fn registered<T>(acc_locator: &str,
                         acc_password: &str,
                         el_handle: Handle,
                         core_tx: CoreMsgTx<T>,
                         net_tx: NetworkTx)
                         -> Result<Client, CoreError>
        where T: 'static
    {
        trace!("Creating an acc.");

        let (password, keyword, pin) = utility::derive_secrets(acc_locator, acc_password);

        let acc_loc = Account::generate_network_id(&keyword, &pin)?;
        let user_cred = UserCred::new(password, pin);

        let maid_keys = ClientKeys::new();
        let pub_key = maid_keys.sign_pk;
        let full_id = Some(maid_keys.clone().into());

        let mut owners = BTreeSet::new();
        owners.insert(pub_key);

        let (routing, routing_rx) = setup_routing(full_id)?;

        let user_root = Client::create_empty_dir(&routing, &routing_rx, owners.clone(), pub_key)?;
        let config_dir = Client::create_empty_dir(&routing, &routing_rx, owners.clone(), pub_key)?;

        let acc = Account::new(maid_keys, user_root, config_dir);

        let mut acc_data = BTreeMap::new();
        let _ = acc_data.insert(b"Login".to_vec(),
                                Value {
                                    content: acc.encrypt(&user_cred.password, &user_cred.pin)?,
                                    entry_version: 0,
                                });

        let acc_md = MutableData::new(acc_loc,
                                      TYPE_TAG_SESSION_PACKET,
                                      BTreeMap::new(),
                                      acc_data,
                                      owners)?;

        let Digest(digest) = sha256::hash(&pub_key.0);
        let cm_addr = Authority::ClientManager(XorName(digest));

        let msg_id = MessageId::new();
        routing.put_mdata(cm_addr, acc_md, msg_id, pub_key)?;

        match routing_rx.recv_timeout(Duration::from_secs(ACC_PKT_TIMEOUT_SECS)) {
            Ok(Event::Response { response: Response::PutMData { ref res, msg_id: ref id }, .. })
                if *id == msg_id => {
                match *res {
                    Ok(..) => (),
                    Err(ref client_error) => {
                        return Err(CoreError::RoutingClientError(client_error.clone()));
                    }
                }
            }
            x => {
                warn!("Could not put session packet to the Network. Unexpected: {:?}",
                      x);
                return Err(CoreError::OperationAborted);
            }
        }

        let net_tx_clone = net_tx.clone();
        let core_tx_clone = core_tx.clone();
        let joiner = spawn_routing_thread(routing_rx, core_tx_clone, net_tx_clone);

        Ok(Self::new(Inner {
            el_handle: el_handle,
            routing: routing,
            hooks: HashMap::with_capacity(10),
            cache: LruCache::new(IMMUT_DATA_CACHE_SIZE),
            client_type: ClientType::reg(acc, acc_loc, user_cred, cm_addr),
            timeout: Duration::from_secs(REQUEST_TIMEOUT_SECS),
            joiner: joiner,
            session_packet_version: 0,
        }))
    }

    /// This is a Gateway function to the Maidsafe network. This will help
    /// login to an already existing account of the user in the SAFE-network.
    pub fn login<T>(acc_locator: &str,
                    acc_password: &str,
                    el_handle: Handle,
                    core_tx: CoreMsgTx<T>,
                    net_tx: NetworkTx)
                    -> Result<Client, CoreError>
        where T: 'static
    {
        trace!("Attempting to log into an acc.");

        let (password, keyword, pin) = utility::derive_secrets(acc_locator, acc_password);

        let acc_loc = Account::generate_network_id(&keyword, &pin)?;
        let user_cred = UserCred::new(password, pin);

        let msg_id = MessageId::new();
        let dst = Authority::NaeManager(acc_loc);

        let (acc_content, acc_version) = {
            trace!("Creating throw-away routing getter for account packet.");
            let (routing, routing_rx) = setup_routing(None)?;

            routing.get_mdata_value(dst,
                                 acc_loc,
                                 TYPE_TAG_SESSION_PACKET,
                                 b"Login".to_vec(),
                                 msg_id)?;

            match routing_rx.recv_timeout(Duration::from_secs(ACC_PKT_TIMEOUT_SECS)) {
                Ok(Event::Response { response:
                                     Response::GetMDataValue { msg_id: id, res }, .. }) => {
                    if id != msg_id {
                        return Err(CoreError::OperationAborted);
                    }
                    match res {
                        Ok(Value { content, entry_version }) => {
                            (content, entry_version)
                        },
                        Err(client_error) => {
                            return Err(CoreError::RoutingClientError(client_error));
                        }
                    }
                }
                x => {
                    warn!("Could not fetch account packet from the Network. Unexpected: {:?}",
                          x);
                    return Err(CoreError::OperationAborted);
                }
            }
        };

        let acc = Account::decrypt(&acc_content, &user_cred.password, &user_cred.pin)?;
        let id_packet = acc.maid_keys.clone().into();

        let Digest(digest) = sha256::hash(&acc.maid_keys.sign_pk.0);
        let cm_addr = Authority::ClientManager(XorName(digest));

        trace!("Creating an actual routing...");
        let (routing, routing_rx) = setup_routing(Some(id_packet))?;
        let net_tx_clone = net_tx.clone();
        let core_tx_clone = core_tx.clone();
        let joiner = spawn_routing_thread(routing_rx, core_tx_clone, net_tx_clone);

        Ok(Self::new(Inner {
            el_handle: el_handle,
            routing: routing,
            hooks: HashMap::with_capacity(10),
            cache: LruCache::new(IMMUT_DATA_CACHE_SIZE),
            client_type: ClientType::reg(acc, acc_loc, user_cred, cm_addr),
            timeout: Duration::from_secs(REQUEST_TIMEOUT_SECS),
            joiner: joiner,
            session_packet_version: acc_version,
        }))
    }

    /// This is a Gateway function to the Maidsafe network. This will help
    /// apps to authorise using an existing pair of keys.
    pub fn from_keys<T>(keys: ClientKeys,
                        owner: sign::PublicKey,
                        el_handle: Handle,
                        core_tx: CoreMsgTx<T>,
                        net_tx: NetworkTx)
                        -> Result<Client, CoreError>
        where T: 'static
    {
        trace!("Attempting to log into an acc using client keys.");

        let Digest(digest) = sha256::hash(&keys.sign_pk.0);
        let cm_addr = Authority::ClientManager(XorName(digest));

        trace!("Creating an actual routing...");
        let (routing, routing_rx) = setup_routing(Some(keys.clone().into()))?;
        let net_tx_clone = net_tx.clone();
        let core_tx_clone = core_tx.clone();
        let joiner = spawn_routing_thread(routing_rx, core_tx_clone, net_tx_clone);

        Ok(Self::new(Inner {
            el_handle: el_handle,
            routing: routing,
            hooks: HashMap::with_capacity(10),
            cache: LruCache::new(IMMUT_DATA_CACHE_SIZE),
            client_type: ClientType::from_keys(owner, cm_addr),
            timeout: Duration::from_secs(REQUEST_TIMEOUT_SECS),
            joiner: joiner,
            session_packet_version: 0,
        }))
    }

    fn new(inner: Inner) -> Self {
        Client { inner: Rc::new(RefCell::new(inner)) }
    }

    /// Set request timeout.
    pub fn set_timeout(&self, duration: Duration) {
        self.inner_mut().timeout = duration;
    }

    #[doc(hidden)]
    pub fn restart_routing<T>(&self, mut core_tx: CoreMsgTx<T>, mut net_tx: NetworkTx)
        where T: 'static
    {
        let opt_id = if let ClientType::Registered { ref acc, .. } = self.inner().client_type {
            Some(acc.maid_keys.clone().into())
        } else {
            None
        };

        let (routing, routing_rx) = match setup_routing(opt_id) {
            Ok(elt) => elt,
            Err(e) => {
                info!("Could not restart routing (will re-attempt, unless dropped): {:?}",
                      e);
                let msg = {
                    let core_tx = core_tx.clone();
                    let net_tx = net_tx.clone();
                    CoreMsg::new(move |client, _| {
                        client.restart_routing(core_tx, net_tx);
                        None
                    })
                };
                let _ = core_tx.send(msg);
                return;
            }
        };

        let _ = net_tx.send(NetworkEvent::Connected);

        let joiner = spawn_routing_thread(routing_rx, core_tx, net_tx);

        self.inner_mut().hooks.clear();
        self.inner_mut().routing = routing;
        self.inner_mut().joiner = joiner;
    }

    #[doc(hidden)]
    pub fn fire_hook(&self, id: &MessageId, event: CoreEvent) {
        // Using in `if` keeps borrow alive. Do not try to combine the 2 lines into one.
        let opt = self.inner_mut().hooks.remove(id);
        if let Some(hook) = opt {
            hook.complete(event);
        }
    }

    fn insert_hook(&self, msg_id: MessageId, hook: Complete<CoreEvent>) {
        let _ = self.inner_mut().hooks.insert(msg_id, hook);
    }

    /// Get immutable data from the network. If the data exists locally in the cache
    /// then it will be immediately be returned without making an actual network
    /// request.
    pub fn get_idata(&self, name: XorName) -> Box<CoreFuture<ImmutableData>> {
        trace!("GetIData for {:?}", name);

        let (hook, rx, msg_id) = oneshot!(self, CoreEvent::GetIData);

        // Check if the data is in the cache. If it is, return it immediately.
        // If not, retrieve it from the network and store it in the cache.
        let rx = {
            if let Some(data) = self.inner_mut()
                .cache
                .get_mut(&name) {
                trace!("ImmutableData found in cache.");
                hook.complete(CoreEvent::GetIData(Ok(data.clone())));
                return rx.into_box();
            }

            let inner = self.inner.clone();
            rx.map(move |data| {
                    let _ = inner.borrow_mut().cache.insert(*data.name(), data.clone());
                    data
                })
                .into_box()
        };

        let result = self.routing_mut().get_idata(Authority::NaeManager(name), name, msg_id);
        if let Err(err) = result {
            hook.complete(CoreEvent::GetIData(Err(CoreError::from(err))));
        } else {
            self.insert_hook(msg_id, hook);
        }

        rx
    }

    // TODO All these return the same future from all branches. So convert to impl
    // Trait when it arrives in stable. Change from `Box<CoreFuture>` -> `impl
    // CoreFuture`.
    /// Put immutable data onto the network.
    pub fn put_idata(&self, data: ImmutableData) -> Box<CoreFuture<()>> {
        trace!("PutIData for {:?}", data);

        self.mutate(|routing, dst, msg_id| routing.put_idata(dst, data, msg_id))
    }

    /// Put `MutableData` onto the network.
    pub fn put_mdata(&self, data: MutableData) -> Box<CoreFuture<()>> {
        trace!("PutMData for {:?}", data);

        let requester = fry!(self.public_signing_key());
        self.mutate(|routing, dst, msg_id| routing.put_mdata(dst, data, msg_id, requester))
    }

    /// Mutates `MutableData` entries in bulk.
    pub fn mutate_mdata_entries(&self,
                                name: XorName,
                                tag: u64,
                                actions: BTreeMap<Vec<u8>, EntryAction>)
                                -> Box<CoreFuture<()>> {
        trace!("PutMData for {:?}", name);

        let requester = fry!(self.public_signing_key());

        self.mutate(|routing, dst, msg_id| {
            routing.mutate_mdata_entries(dst, name, tag, actions, msg_id, requester)
        })
    }

    /// Get a current version of `MutableData` from the network.
    pub fn get_mdata_version(&self, name: XorName, tag: u64) -> Box<CoreFuture<u64>> {
        trace!("GetMDataVersion for {:?}", name);

        self.get(CoreEvent::GetMDataVersion, |routing, msg_id| {
                routing.get_mdata_version(Authority::NaeManager(name), name, tag, msg_id)
            })
            .and_then(|event| match_event!(event, CoreEvent::GetMDataVersion))
            .into_box()
    }

    /// Returns a complete list of entries in `MutableData`.
    pub fn list_mdata_entries(&self,
                              name: XorName,
                              tag: u64)
                              -> Box<CoreFuture<BTreeMap<Vec<u8>, Value>>> {
        trace!("ListMDataEntries for {:?}", name);

        self.get(CoreEvent::ListMDataEntries, |routing, msg_id| {
                routing.list_mdata_entries(Authority::NaeManager(name), name, tag, msg_id)
            })
            .and_then(|event| match_event!(event, CoreEvent::ListMDataEntries))
            .into_box()
    }

    /// Returns a list of keys in `MutableData` stored on the network
    pub fn list_mdata_keys(&self, name: XorName, tag: u64) -> Box<CoreFuture<BTreeSet<Vec<u8>>>> {
        trace!("ListMDataKeys for {:?}", name);

        self.get(CoreEvent::ListMDataKeys, |routing, msg_id| {
                routing.list_mdata_keys(Authority::NaeManager(name), name, tag, msg_id)
            })
            .and_then(|event| match_event!(event, CoreEvent::ListMDataKeys))
            .into_box()
    }

    /// Returns a list of keys in `MutableData` stored on the network
    pub fn list_mdata_values(&self, name: XorName, tag: u64) -> Box<CoreFuture<Vec<Value>>> {
        trace!("ListMDataValues for {:?}", name);

        self.get(CoreEvent::ListMDataValues, |routing, msg_id| {
                routing.list_mdata_values(Authority::NaeManager(name), name, tag, msg_id)
            })
            .and_then(|event| match_event!(event, CoreEvent::ListMDataValues))
            .into_box()
    }

    /// Get a single entry from `MutableData`
    pub fn get_mdata_value(&self, name: XorName, tag: u64, key: Vec<u8>) -> Box<CoreFuture<Value>> {
        trace!("GetMDataValue for {:?}", name);

        self.get(CoreEvent::GetMDataValue, |routing, msg_id| {
                routing.get_mdata_value(Authority::NaeManager(name), name, tag, key, msg_id)
            })
            .and_then(|event| match_event!(event, CoreEvent::GetMDataValue))
            .into_box()
    }

    /// Get data from the network.
    pub fn get_account_info(&self) -> Box<CoreFuture<AccountInfo>> {
        trace!("Account info GET issued.");

        let (hook, rx, msg_id) = oneshot!(self, CoreEvent::AccountInfo);

        let dst = fry!(self.inner().client_type.cm_addr().map(|a| a.clone()));
        let result = self.routing_mut().get_account_info(dst, msg_id);

        if let Err(e) = result {
            hook.complete(CoreEvent::AccountInfo(Err(From::from(e))));
        } else {
            self.insert_hook(msg_id, hook);
        }

        rx
    }

    /// Returns a list of permissions in `MutableData` stored on the network
    pub fn list_mdata_permissions(&self,
                                  name: XorName,
                                  tag: u64)
                                  -> Box<CoreFuture<BTreeMap<User, PermissionSet>>> {
        trace!("ListMDataPermissions for {:?}", name);

        self.get(CoreEvent::ListMDataPermissions, |routing, msg_id| {
                routing.list_mdata_permissions(Authority::NaeManager(name), name, tag, msg_id)
            })
            .and_then(|event| match_event!(event, CoreEvent::ListMDataPermissions))
            .into_box()
    }

    /// Returns a list of permissions for a particular User in MutableData
    pub fn list_mdata_user_permissions(&self,
                                       name: XorName,
                                       tag: u64,
                                       user: User)
                                       -> Box<CoreFuture<PermissionSet>> {
        trace!("ListMDataUserPermissions for {:?}", name);

        self.get(CoreEvent::ListMDataUserPermissions, |routing, msg_id| {
                let dst = Authority::NaeManager(name);
                routing.list_mdata_user_permissions(dst, name, tag, user, msg_id)
            })
            .and_then(|event| match_event!(event, CoreEvent::ListMDataUserPermissions))
            .into_box()
    }

    /// Updates or inserts a permission set for a given user
    pub fn set_mdata_user_permissions(&self,
                                      name: XorName,
                                      tag: u64,
                                      user: User,
                                      permissions: PermissionSet,
                                      version: u64)
                                      -> Box<CoreFuture<()>> {
        trace!("SetMDataUserPermissions for {:?}", name);

        let requester = fry!(self.public_signing_key());

        self.mutate(|routing, dst, msg_id| {
            routing.set_mdata_user_permissions(dst,
                                               name,
                                               tag,
                                               user,
                                               permissions,
                                               version,
                                               msg_id,
                                               requester)
        })
    }

    /// Deletes a permission set for a given user
    pub fn del_mdata_user_permissions(&self,
                                      name: XorName,
                                      tag: u64,
                                      user: User,
                                      version: u64)
                                      -> Box<CoreFuture<()>> {
        trace!("DelMDataUserPermissions for {:?}", name);

        let requester = fry!(self.public_signing_key());

        self.mutate(|routing, dst, msg_id| {
            routing.del_mdata_user_permissions(dst, name, tag, user, version, msg_id, requester)
        })
    }

    /// Sends an ownership transfer request
    pub fn change_mdata_owner(&self,
                              name: XorName,
                              tag: u64,
                              new_owner: sign::PublicKey,
                              version: u64)
                              -> Box<CoreFuture<()>> {
        trace!("ChangeMDataOwner for {:?}", name);

        let requester = fry!(self.public_signing_key());

        self.mutate(|routing, dst, msg_id| {
            routing.change_mdata_owner(dst, name, tag, new_owner, version, msg_id, requester)
        })
    }

    /// Fetches a list of authorised keys and version in MaidManager
    pub fn list_auth_keys(&self) -> Box<CoreFuture<BTreeSet<sign::PublicKey>>> {
        trace!("ListAuthKeysAndVersion");

        let dst = fry!(self.inner().client_type.cm_addr().map(|a| a.clone()));

        self.get(CoreEvent::ListAuthKeysAndVersion,
                 |routing, msg_id| routing.list_auth_keys(dst, msg_id))
            .and_then(|event| match_event!(event, CoreEvent::ListAuthKeysAndVersion))
            .into_box()
    }

    /// Adds a new authorised key to MaidManager
    pub fn ins_auth_key(&self, key: sign::PublicKey, version: u64) -> Box<CoreFuture<()>> {
        trace!("InsAuthKey ({:?})", key);

        self.mutate(|routing, dst, msg_id| routing.ins_auth_key(dst, key, version, msg_id))
    }

    /// Removes an authorised key from MaidManager
    pub fn del_auth_key(&self, key: sign::PublicKey, version: u64) -> Box<CoreFuture<()>> {
        trace!("DelAuthKey ({:?})", key);

        self.mutate(|routing, dst, msg_id| routing.del_auth_key(dst, key, version, msg_id))
    }

    /// Create an entry for the Root Directory ID for the user into the session
    /// packet, encrypt and store it. It will be retrieved when the user logs
    /// into their account.  Root directory ID is necessary to fetch all of the
    /// user's data as all further data is encoded as meta-information into the
    /// Root Directory or one of its subdirectories.
    pub fn set_user_root_dir(&self, dir: Dir) -> Box<CoreFuture<()>> {
        trace!("Setting user root Dir ID.");
        {
            let mut inner = self.inner_mut();
            let mut account = fry!(inner.client_type.acc_mut());
            account.user_root = dir;
        }
        self.update_session_packet()
    }

    /// Get User's Root Directory ID if available in session packet used for
    /// current login
    pub fn user_root_dir(&self) -> Option<Dir> {
        self.inner().client_type.acc().ok().and_then(|account| Some(account.user_root.clone()))
    }

    /// Create an entry for the Maidsafe configuration specific Root Directory
    /// ID into the session packet, encrypt and store it. It will be retrieved
    /// when the user logs into their account. Root directory ID is necessary
    /// to fetch all of configuration data as all further data is encoded as
    /// meta-information into the config Root Directory or one of its
    /// subdirectories.
    pub fn set_config_root_dir(&self, dir: Dir) -> Box<CoreFuture<()>> {
        trace!("Setting configuration root Dir ID.");
        {
            let mut inner = self.inner_mut();
            let mut account = fry!(inner.client_type.acc_mut());
            account.config_root = dir;
        }
        self.update_session_packet()
    }

    /// Get Maidsafe specific configuration's Root Directory ID if available in
    /// session packet used for current login
    pub fn config_root_dir(&self) -> Option<Dir> {
        self.inner().client_type.acc().ok().and_then(|account| Some(account.config_root.clone()))
    }

    /// Returns the public encryption key
    pub fn public_encryption_key(&self) -> Result<box_::PublicKey, CoreError> {
        let inner = self.inner();
        let account = inner.client_type.acc()?;
        Ok(account.maid_keys.enc_pk)
    }

    /// Returns the Secret encryption key
    pub fn secret_encryption_key(&self) -> Result<box_::SecretKey, CoreError> {
        let inner = self.inner();
        let account = inner.client_type.acc()?;
        Ok(account.maid_keys.enc_sk.clone())
    }

    /// Returns the Public Signing key
    pub fn public_signing_key(&self) -> Result<sign::PublicKey, CoreError> {
        let inner = self.inner();
        let account = inner.client_type.acc()?;
        Ok(account.maid_keys.sign_pk)
    }

    /// Returns the Secret Signing key
    pub fn secret_signing_key(&self) -> Result<sign::SecretKey, CoreError> {
        let inner = self.inner();
        let account = inner.client_type.acc()?;
        Ok(account.maid_keys.sign_sk.clone())
    }

    /// Returns the public and secret signing keys.
    pub fn signing_keypair(&self) -> Result<(sign::PublicKey, sign::SecretKey), CoreError> {
        let inner = self.inner();
        let account = inner.client_type.acc()?;
        Ok((account.maid_keys.sign_pk, account.maid_keys.sign_sk.clone()))
    }

    fn update_session_packet(&self) -> Box<CoreFuture<()>> {
        trace!("Updating session packet.");

        let data_name = fry!(self.inner().client_type.acc_loc());

        let encrypted_account = {
            let inner = self.inner();
            let account = fry!(inner.client_type.acc());
            let keys = fry!(inner.client_type.user_cred());
            fry!(account.encrypt(&keys.password, &keys.pin))
        };

        let entry_version = {
            let mut inner = self.inner_mut();
            inner.session_packet_version += 1;
            inner.session_packet_version
        };

        let mut actions = BTreeMap::new();
        let _ = actions.insert(b"Login".to_vec(),
                               EntryAction::Update(Value {
                                   content: encrypted_account,
                                   entry_version: entry_version,
                               }));

        self.mutate_mdata_entries(data_name, TYPE_TAG_SESSION_PACKET, actions)
    }

    /// Creates an empty dir to hold configuration or user data
    fn create_empty_dir(routing: &Routing,
                        routing_rx: &Receiver<Event>,
                        owners: BTreeSet<sign::PublicKey>,
                        requester: sign::PublicKey)
                        -> Result<Dir, CoreError> {
        let dir = Dir::random(DIR_TAG);
        let dir_md = MutableData::new(dir.name,
                                      dir.type_tag,
                                      BTreeMap::new(),
                                      BTreeMap::new(),
                                      owners)?;

        let msg_id = MessageId::new();
        routing.put_mdata(Authority::NaeManager(dir.name), dir_md, msg_id, requester)?;

        match routing_rx.recv_timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS)) {
            Ok(Event::Response { response: Response::PutMData { ref res, msg_id: ref id }, .. })
                if *id == msg_id => {
                match *res {
                    Ok(..) => (),
                    Err(ref client_error) => {
                        return Err(CoreError::RoutingClientError(client_error.clone()));
                    }
                }
            }
            x => {
                warn!("Could not put MutableData to the Network. Unexpected: {:?}",
                      x);
                return Err(CoreError::OperationAborted);
            }
        }

        Ok(dir)
    }

    /// Generic GET request
    fn get<T, F, G>(&self, err_event: F, req: G) -> Box<CoreFuture<CoreEvent>>
        where F: FnOnce(Result<T, CoreError>) -> CoreEvent,
              G: FnOnce(&mut Routing, MessageId) -> Result<(), InterfaceError>
    {
        let msg_id = MessageId::new();
        let (hook, oneshot) = futures::oneshot();

        let fut = oneshot.map_err(|_| CoreError::OperationAborted);
        let rx = self.timeout(msg_id, fut);

        let result = req(&mut *self.routing_mut(), msg_id);

        if let Err(err) = result {
            hook.complete(err_event(Err(CoreError::from(err))));
        } else {
            self.insert_hook(msg_id, hook);
        }

        rx
    }

    /// Generic mutation request
    fn mutate<F>(&self, req: F) -> Box<CoreFuture<()>>
        where F: FnOnce(&mut Routing, Authority, MessageId) -> Result<(), InterfaceError>
    {
        let dst = fry!(self.inner().client_type.cm_addr().map(|a| a.clone()));

        self.get(CoreEvent::Mutation,
                 |routing, msg_id| req(routing, dst, msg_id))
            .and_then(|event| match_event!(event, CoreEvent::Mutation))
            .into_box()
    }

    fn timeout<F, T>(&self, msg_id: MessageId, future: F) -> Box<CoreFuture<T>>
        where F: Future<Item = T, Error = CoreError> + 'static,
              T: 'static
    {
        let duration = self.inner().timeout;
        let timeout = match Timeout::new(duration, &self.inner().el_handle) {
            Ok(timeout) => timeout,
            Err(err) => {
                return err!(CoreError::Unexpected(format!("Timeout create error: {:?}", err)))
            }
        };

        let client = self.clone();
        let timeout = timeout.then(move |result| -> Result<T, _> {
            let _ = client.inner_mut().hooks.remove(&msg_id);

            match result {
                Ok(()) => Err(CoreError::RequestTimeout),
                Err(err) => Err(CoreError::Unexpected(format!("Timeout fire error {:?}", err))),
            }
        });

        future.select(timeout)
            .then(|result| match result {
                Ok((a, _)) => Ok(a),
                Err((a, _)) => Err(a),
            })
            .into_box()
    }

    fn routing_mut(&self) -> RefMut<Routing> {
        RefMut::map(self.inner.borrow_mut(), |i| &mut i.routing)
    }

    fn inner(&self) -> Ref<Inner> {
        self.inner.borrow()
    }

    fn inner_mut(&self) -> RefMut<Inner> {
        self.inner.borrow_mut()
    }
}

#[cfg(all(test, feature = "use-mock-routing"))]
impl Client {
    #[doc(hidden)]
    pub fn set_network_limits(&self, max_ops_count: Option<u64>) {
        self.routing_mut().set_network_limits(max_ops_count);
    }

    #[doc(hidden)]
    pub fn simulate_network_disconnect(&self) {
        self.routing_mut().simulate_disconnect();
    }

    #[doc(hidden)]
    pub fn set_simulate_timeout(&self, enabled: bool) {
        self.routing_mut().set_simulate_timeout(enabled);
    }
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Client")
    }
}

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

#[allow(unused)] // <- TODO(nbaksalyar) remove this
enum ClientType {
    Unregistered,
    Registered {
        acc: Account,
        acc_loc: XorName,
        user_cred: UserCred,
        cm_addr: Authority,
    },
    FromKeys {
        owner: sign::PublicKey,
        cm_addr: Authority,
    },
}

impl ClientType {
    fn from_keys(owner: sign::PublicKey, cm_addr: Authority) -> Self {
        ClientType::FromKeys {
            owner: owner,
            cm_addr: cm_addr,
        }
    }

    fn reg(acc: Account, acc_loc: XorName, user_cred: UserCred, cm_addr: Authority) -> Self {
        ClientType::Registered {
            acc: acc,
            acc_loc: acc_loc,
            user_cred: user_cred,
            cm_addr: cm_addr,
        }
    }

    fn acc(&self) -> Result<&Account, CoreError> {
        match *self {
            ClientType::Registered { ref acc, .. } => Ok(acc),
            ClientType::FromKeys { .. } |
            ClientType::Unregistered => Err(CoreError::OperationForbiddenForClient),
        }
    }

    fn acc_mut(&mut self) -> Result<&mut Account, CoreError> {
        match *self {
            ClientType::Registered { ref mut acc, .. } => Ok(acc),
            ClientType::FromKeys { .. } |
            ClientType::Unregistered => Err(CoreError::OperationForbiddenForClient),
        }
    }

    fn acc_loc(&self) -> Result<XorName, CoreError> {
        match *self {
            ClientType::Registered { acc_loc, .. } => Ok(acc_loc),
            ClientType::FromKeys { .. } |
            ClientType::Unregistered => Err(CoreError::OperationForbiddenForClient),
        }
    }

    fn user_cred(&self) -> Result<&UserCred, CoreError> {
        match *self {
            ClientType::Registered { ref user_cred, .. } => Ok(user_cred),
            ClientType::FromKeys { .. } |
            ClientType::Unregistered => Err(CoreError::OperationForbiddenForClient),
        }
    }

    fn cm_addr(&self) -> Result<&Authority, CoreError> {
        match *self {
            ClientType::FromKeys { ref cm_addr, .. } |
            ClientType::Registered { ref cm_addr, .. } => Ok(cm_addr),
            ClientType::Unregistered => Err(CoreError::OperationForbiddenForClient),
        }
    }
}

fn setup_routing(full_id: Option<FullId>) -> Result<(Routing, Receiver<Event>), CoreError> {
    let (routing_tx, routing_rx) = mpsc::channel();
    let routing = Routing::new(routing_tx, full_id)?;

    trace!("Waiting to get connected to the Network...");
    match routing_rx.recv_timeout(Duration::from_secs(CONNECTION_TIMEOUT_SECS)) {
        Ok(Event::Connected) => (),
        x => {
            warn!("Could not connect to the Network. Unexpected: {:?}", x);
            // TODO: we should return more descriptive error here
            return Err(CoreError::OperationAborted);
        }
    }
    trace!("Connected to the Network.");

    Ok((routing, routing_rx))
}

fn spawn_routing_thread<T>(routing_rx: Receiver<Event>,
                           core_tx: CoreMsgTx<T>,
                           net_tx: NetworkTx)
                           -> Joiner
    where T: 'static
{
    thread::named("Routing Event Loop",
                  move || routing_el::run(routing_rx, core_tx, net_tx))
}

#[cfg(test)]
mod tests {
    use core::{CoreError, DIR_TAG, utility};
    use core::utility::test_utils::{finish, random_client, setup_client};
    use futures::Future;
    use futures::sync::mpsc;
    #[cfg(feature = "use-mock-routing")]
    use rand;
    use routing::{ClientError, ImmutableData};
    use super::*;
    use tokio_core::reactor::Core;

    #[test]
    fn unregistered_client() {
        let orig_data = ImmutableData::new(unwrap!(utility::generate_random_vector(30)));

        // Registered Client PUTs something onto the network
        {
            let orig_data = orig_data.clone();
            random_client(|client| client.put_idata(orig_data));
        }

        // Unregistered Client should be able to retrieve the data
        setup_client(Client::unregistered, move |client| {
            let client2 = client.clone();
            let client3 = client.clone();

            client.get_idata(*orig_data.name())
                .then(move |res| {
                    let data = unwrap!(res);
                    assert_eq!(data, orig_data);
                    let dir = Dir::random(DIR_TAG);
                    client2.set_user_root_dir(dir)
                })
                .then(move |res| {
                    let e = match res {
                        Ok(_) => {
                            panic!("Unregistered client should not be allowed to set user root dir")
                        }
                        Err(e) => e,
                    };
                    match e {
                        CoreError::OperationForbiddenForClient => (),
                        _ => panic!("Unexpected {:?}", e),
                    }

                    let dir = Dir::random(DIR_TAG);
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
                        CoreError::OperationForbiddenForClient => (),
                        _ => panic!("Unexpected {:?}", e),
                    }
                    finish()
                })
        });
    }

    #[test]
    fn registered_client() {
        let el = unwrap!(Core::new());
        let (core_tx, _) = mpsc::unbounded();
        let (net_tx, _) = mpsc::unbounded();

        let sec_0 = unwrap!(utility::generate_random_string(10));
        let sec_1 = unwrap!(utility::generate_random_string(10));

        // Account creation for the 1st time - should succeed
        let _ = unwrap!(Client::registered::<()>(&sec_0,
                                                 &sec_1,
                                                 el.handle(),
                                                 core_tx.clone(),
                                                 net_tx.clone()));

        // Account creation - same secrets - should fail
        match Client::registered(&sec_0, &sec_1, el.handle(), core_tx, net_tx) {
            Ok(_) => panic!("Account name hijacking should fail"),
            Err(CoreError::RoutingClientError(ClientError::AccountExists)) => (),
            Err(err) => panic!("{:?}", err),
        }
    }

    #[test]
    fn login() {
        let sec_0 = unwrap!(utility::generate_random_string(10));
        let sec_1 = unwrap!(utility::generate_random_string(10));

        setup_client(|el_h, core_tx, net_tx| {
            match Client::login(&sec_0,
                                &sec_1,
                                el_h.clone(),
                                core_tx.clone(),
                                net_tx.clone()) {
                Err(CoreError::RoutingClientError(ClientError::NoSuchAccount)) => (),
                x => panic!("Unexpected Login outcome: {:?}", x),
            }
            Client::registered(&sec_0, &sec_1, el_h, core_tx, net_tx)
        },
                     |_| finish());

        setup_client(|el_h, core_tx, net_tx| Client::login(&sec_0, &sec_1, el_h, core_tx, net_tx),
                     |_| finish());
    }

    #[test]
    fn user_root_dir_creation() {
        let sec_0 = unwrap!(utility::generate_random_string(10));
        let sec_1 = unwrap!(utility::generate_random_string(10));

        let dir = Dir::random(DIR_TAG);
        let dir_clone = dir.clone();

        setup_client(|el_h, core_tx, net_tx| {
                         Client::registered(&sec_0, &sec_1, el_h, core_tx, net_tx)
                     },
                     move |client| {
                         assert!(client.user_root_dir().is_some());
                         client.set_user_root_dir(dir)
                     });

        setup_client(|el_h, core_tx, net_tx| Client::login(&sec_0, &sec_1, el_h, core_tx, net_tx),
                     move |client| {
                         let got_dir = unwrap!(client.user_root_dir());
                         assert_eq!(got_dir, dir_clone);
                         finish()
                     });
    }

    #[test]
    fn config_root_dir_creation() {
        let sec_0 = unwrap!(utility::generate_random_string(10));
        let sec_1 = unwrap!(utility::generate_random_string(10));

        let dir = Dir::random(DIR_TAG);
        let dir_clone = dir.clone();

        setup_client(|el_h, core_tx, net_tx| {
                         Client::registered(&sec_0, &sec_1, el_h, core_tx, net_tx)
                     },
                     move |client| {
                         assert!(client.config_root_dir().is_some());
                         client.set_config_root_dir(dir)
                     });

        setup_client(|el_h, core_tx, net_tx| Client::login(&sec_0, &sec_1, el_h, core_tx, net_tx),
                     move |client| {
                         let got_dir = unwrap!(client.config_root_dir());
                         assert_eq!(got_dir, dir_clone);
                         finish()
                     });
    }

    /*
    #[test]
    fn put_or_reclaim_structured_data() {
        random_client(|client| {
            let client2 = client.clone();
            let client3 = client.clone();
            let client4 = client.clone();

            let owner_keys = vec![unwrap!(client.public_signing_key())];
            let owner_keys2 = owner_keys.clone();
            let owner_keys3 = owner_keys.clone();
            let owner_keys4 = owner_keys.clone();

            let sign_sk = unwrap!(client.secret_signing_key());
            let sign_sk2 = sign_sk.clone();
            let sign_sk3 = sign_sk.clone();
            let sign_sk4 = sign_sk.clone();

            let tag = ::UNVERSIONED_STRUCT_DATA_TYPE_TAG;
            let name = rand::random();
            let value = unwrap!(utility::generate_random_vector(10));

            // PUT the data to the network.
            let data = unwrap!(StructuredData::new(tag,
                                                   name,
                                                   0,
                                                   value,
                                                   owner_keys,
                                                   vec![],
                                                   Some(&sign_sk)));

            client.put(Data::Structured(data), None)
                .then(move |result| {
                    unwrap!(result);

                    // DELETE it.
                    let data = unwrap!(StructuredData::new(tag,
                                                           name,
                                                           1,
                                                           vec![],
                                                           vec![],
                                                           owner_keys2,
                                                           Some(&sign_sk2)));
                    client2.delete(Data::Structured(data), None)
                })
                .then(move |result| {
                    unwrap!(result);

                    // Try to PUT new data under the same name. Should fail.
                    let value = unwrap!(utility::generate_random_vector(10));
                    let data = unwrap!(StructuredData::new(tag,
                                                           name,
                                                           0,
                                                           value,
                                                           owner_keys3,
                                                           vec![],
                                                           Some(&sign_sk3)));
                    client3.put(Data::Structured(data), None)
                })
                .then(move |result| {
                    match result {
                        Err(CoreError::MutationFailure {
                            reason: MutationError::InvalidSuccessor, ..
                        }) => (),
                        Ok(()) => panic!("Unexpected success"),
                        Err(err) => panic!("{:?}", err),
                    }

                    // Not try again, but using `put_or_reclaim`. Should succeed.
                    let value = unwrap!(utility::generate_random_vector(10));
                    let data = unwrap!(StructuredData::new(tag,
                                                           name,
                                                           0,
                                                           value,
                                                           owner_keys4,
                                                           vec![],
                                                           Some(&sign_sk4)));
                    client4.put_recover(Data::Structured(data), None, sign_sk4)
                })
                .map_err(|err| panic!("{:?}", err))
                .map(|ver| assert!(ver != 0))
        })
    }
*/

    #[cfg(feature = "use-mock-routing")]
    #[test]
    fn restart_routing() {
        use core::NetworkEvent;
        use core::utility::test_utils::random_client_with_net_obs;
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
            hook.complete(());
        });

        random_client_with_net_obs(move |net_event| unwrap!(tx.send(net_event)),
                                   move |client| {
                                       client.simulate_network_disconnect();
                                       keep_alive
                                   });
    }

    #[cfg(feature = "use-mock-routing")]
    #[test]
    fn timeout() {
        use std::time::Duration;

        // Get
        random_client(|client| {
            let client2 = client.clone();

            client.set_simulate_timeout(true);
            client.set_timeout(Duration::from_millis(250));

            client.get_idata(rand::random())
                .then(|result| match result {
                    Ok(_) => panic!("Unexpected success"),
                    Err(CoreError::RequestTimeout) => Ok::<_, CoreError>(()),
                    Err(err) => panic!("Unexpected {:?}", err),
                })
                .then(move |result| {
                    unwrap!(result);

                    let data = unwrap!(utility::generate_random_vector(4));
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
