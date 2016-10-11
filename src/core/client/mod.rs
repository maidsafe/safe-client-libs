// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

mod account;
#[cfg(feature = "use-mock-routing")]
mod mock_routing;
mod routing_el;

use core::{CoreError, CoreMsgTx, FutureExt, utility};
use core::event::CoreEvent;
use futures::{self, Complete, Future, Oneshot};
use lru_cache::LruCache;
use maidsafe_utilities::thread::{self, Joiner};
use routing::{AppendWrapper, Authority, Data, DataIdentifier, Event, FullId, MessageId, Response,
              StructuredData, TYPE_TAG_SESSION_PACKET, XorName};
#[cfg(not(feature = "use-mock-routing"))]
use routing::Client as Routing;
use rust_sodium::crypto::{box_, sign};
use rust_sodium::crypto::hash::sha256::{self, Digest};
use rust_sodium::crypto::secretbox;
use self::account::Account;
#[cfg(feature = "use-mock-routing")]
use self::mock_routing::MockRouting as Routing;
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

pub type ReturnType<T> = Future<Item = T, Error = CoreError>;

const CONNECTION_TIMEOUT_SECS: u64 = 60;
const ACC_PKT_TIMEOUT_SECS: u64 = 60;
const IMMUT_DATA_CACHE_SIZE: usize = 300;

/// The main self-authentication client instance that will interface all the request from high
/// level API's to the actual routing layer and manage all interactions with it. This is
/// essentially a non-blocking Client with upper layers having an option to either block and wait
/// on the returned ResponseGetters for receiving network response or spawn a new thread. The Client
/// itself is however well equipped for parallel and non-blocking PUTs and GETS.
pub struct Client {
    routing: Routing,
    heads: HashMap<MessageId, Complete<CoreEvent>>,
    cache: Rc<RefCell<LruCache<XorName, Data>>>,
    client_type: ClientType,
    stats: Stats,
    _joiner: Joiner,
}

impl Client {
    /// This is a getter-only Gateway function to the Maidsafe network. It will create an
    /// unregistered random client, which can do very limited set of operations - eg., a
    /// Network-Get
    pub fn unregistered(core_tx: CoreMsgTx) -> Result<Client, CoreError> {
        trace!("Creating unregistered client.");

        let (routing, routing_rx) = try!(setup_routing(None));
        let joiner = spawn_routing_thread(routing_rx, core_tx);

        Ok(Client {
            routing: routing,
            heads: HashMap::with_capacity(10),
            cache: Rc::new(RefCell::new(LruCache::new(IMMUT_DATA_CACHE_SIZE))),
            client_type: ClientType::Unregistered,
            stats: Default::default(),
            _joiner: joiner,
        })
    }

    /// This is a Gateway function to the Maidsafe network. This will help create a fresh acc for
    /// the user in the SAFE-network.
    pub fn registered(acc_locator: &str,
                      acc_password: &str,
                      core_tx: CoreMsgTx)
                      -> Result<Client, CoreError> {
        trace!("Creating an acc.");

        let (password, keyword, pin) = utility::derive_secrets(acc_locator, acc_password);

        let acc = Account::new();
        let id_packet = FullId::with_keys((acc.get_maid().public_keys().1,
                                           acc.get_maid().secret_keys().1.clone()),
                                          (acc.get_maid().public_keys().0,
                                           acc.get_maid().secret_keys().0.clone()));

        let (routing, routing_rx) = try!(setup_routing(Some(id_packet)));

        let acc_loc = try!(Account::generate_network_id(&keyword, &pin));
        let user_cred = UserCred::new(password, pin);
        let acc_sd = try!(StructuredData::new(TYPE_TAG_SESSION_PACKET,
                                              acc_loc,
                                              0,
                                              try!(acc.encrypt(&user_cred.password,
                                                               &user_cred.pin)),
                                              vec![acc.get_public_maid().public_keys().0.clone()],
                                              Vec::new(),
                                              Some(&acc.get_maid().secret_keys().0)));

        let Digest(digest) = sha256::hash(&(acc.get_maid().public_keys().0).0);
        let cm_addr = Authority::ClientManager(XorName(digest));

        let msg_id = MessageId::new();
        try!(routing.send_put_request(cm_addr.clone(), Data::Structured(acc_sd), msg_id));
        match routing_rx.recv_timeout(Duration::from_secs(ACC_PKT_TIMEOUT_SECS)) {
            Ok(Event::Response { response: Response::PutSuccess(_, id), .. }) if id == msg_id => (),
            Ok(Event::Response { response: Response::PutFailure { id,
                                                        data_id,
                                                        ref external_error_indicator },
                                 .. }) if id == msg_id => {
                return Err(CoreError::MutationFailure {
                    data_id: data_id,
                    reason: routing_el::parse_mutation_err(external_error_indicator),
                });
            }
            x => {
                warn!("Could not put session packet to the Network. Unexpected: {:?}",
                      x);
                return Err(CoreError::OperationAborted);
            }
        }

        let joiner = spawn_routing_thread(routing_rx, core_tx);

        Ok(Client {
            routing: routing,
            heads: HashMap::with_capacity(10),
            cache: Rc::new(RefCell::new(LruCache::new(IMMUT_DATA_CACHE_SIZE))),
            client_type: ClientType::reg(acc, acc_loc, user_cred, cm_addr),
            stats: Default::default(),
            _joiner: joiner,
        })
    }

    /// This is a Gateway function to the Maidsafe network. This will help login to an already
    /// existing account of the user in the SAFE-network.
    pub fn login(acc_locator: &str,
                 acc_password: &str,
                 core_tx: CoreMsgTx)
                 -> Result<Client, CoreError> {
        trace!("Attempting to log into an acc.");

        let (password, keyword, pin) = utility::derive_secrets(acc_locator, acc_password);

        let acc_loc = try!(Account::generate_network_id(&keyword, &pin));
        let user_cred = UserCred::new(password, pin);
        let acc_sd_id = DataIdentifier::Structured(acc_loc, TYPE_TAG_SESSION_PACKET);

        let msg_id = MessageId::new();
        let dst = Authority::NaeManager(*acc_sd_id.name());

        let acc_sd = {
            trace!("Creating throw-away routing getter for account packet.");
            let (mut routing, routing_rx) = try!(setup_routing(None));

            try!(routing.send_get_request(dst, acc_sd_id, msg_id));
            match routing_rx.recv_timeout(Duration::from_secs(ACC_PKT_TIMEOUT_SECS)) {
                Ok(Event::Response { response:
                    Response::GetSuccess(Data::Structured(data), id), .. }) => {
                    if id == msg_id {
                        data
                    } else {
                        return Err(CoreError::OperationAborted);
                    }
                }
                Ok(Event::Response {
                    response: Response::GetFailure { id, data_id, ref external_error_indicator }, ..
                }) if id == msg_id => {
                    return Err(CoreError::GetFailure {
                        data_id: data_id,
                        reason: routing_el::parse_get_err(external_error_indicator),
                    });
                }
                x => {
                    warn!("Could not fetch account packet from the Network. Unexpected: {:?}",
                          x);
                    return Err(CoreError::OperationAborted);
                }
            }
        };

        let acc = try!(Account::decrypt(acc_sd.get_data(), &user_cred.password, &user_cred.pin));
        let id_packet = FullId::with_keys((acc.get_maid().public_keys().1,
                                           acc.get_maid().secret_keys().1.clone()),
                                          (acc.get_maid().public_keys().0,
                                           acc.get_maid().secret_keys().0.clone()));

        let Digest(digest) = sha256::hash(&(acc.get_maid().public_keys().0).0);
        let cm_addr = Authority::ClientManager(XorName(digest));

        trace!("Creating an actual routing...");
        let (routing, routing_rx) = try!(setup_routing(Some(id_packet)));
        let joiner = spawn_routing_thread(routing_rx, core_tx);

        Ok(Client {
            routing: routing,
            heads: HashMap::with_capacity(10),
            cache: Rc::new(RefCell::new(LruCache::new(IMMUT_DATA_CACHE_SIZE))),
            client_type: ClientType::reg(acc, acc_loc, user_cred, cm_addr),
            stats: Default::default(),
            _joiner: joiner,
        })
    }

    /// Remove the completion handle associated with the given message id.
    pub fn remove_head(&mut self, id: &MessageId) -> Option<Complete<CoreEvent>> {
        self.heads.remove(id)
    }

    /// Get data from the network. If the data exists locally in the cache (for ImmutableData) then
    /// it will immediately be returned without making an actual network request.
    pub fn get(&mut self,
               data_id: DataIdentifier,
               opt_dst: Option<Authority>)
               -> Box<ReturnType<Data>> {
        trace!("GET for {:?}", data_id);
        self.stats.issued_gets += 1;

        let (head, oneshot) = futures::oneshot();
        let rx = oneshot.map_err(|_| CoreError::OperationAborted)
            .and_then(|event| match event {
                CoreEvent::Get(res) => res,
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            });

        let rx = if let DataIdentifier::Immutable(..) = data_id {
            if let Some(data) = self.cache.borrow_mut().get_mut(data_id.name()) {
                trace!("ImmutableData found in cache.");
                head.complete(CoreEvent::Get(Ok(data.clone())));
                return rx.into_box();
            }

            let cache = self.cache.clone();
            rx.map(move |data| {
                match data {
                    ref data @ Data::Immutable(_) => {
                        let _ = cache.borrow_mut().insert(*data.name(), data.clone());
                    }
                    _ => (),
                }
                data
            }).into_box()
        } else {
            rx.into_box()
        };

        let dst = match opt_dst {
            Some(auth) => auth,
            None => Authority::NaeManager(*data_id.name()),
        };

        let msg_id = MessageId::new();
        if let Err(e) = self.routing.send_get_request(dst, data_id, msg_id) {
            head.complete(CoreEvent::Get(Err(From::from(e))));
        } else {
            let _ = self.heads.insert(msg_id, head);
        }

        rx
    }

    // TODO All these return the same future from all branches. So convert to impl Trait when it
    // arrives in stable. Change from `Box<ReturnType>` -> `impl ReturnType`.
    /// Put data onto the network.
    pub fn put(&mut self, data: Data, opt_dst: Option<Authority>) -> Box<ReturnType<()>> {
        trace!("PUT for {:?}", data);
        self.stats.issued_puts += 1;

        let (head, oneshot) = futures::oneshot();
        let rx = build_mutation_future(oneshot);

        let dst = match opt_dst {
            Some(auth) => auth,
            None => {
                match self.cm_addr() {
                    Ok(addr) => addr.clone(),
                    Err(e) => {
                        head.complete(CoreEvent::Mutation(Err(e)));
                        return rx;
                    }
                }
            }
        };

        let msg_id = MessageId::new();
        if let Err(e) = self.routing.send_put_request(dst, data, msg_id) {
            head.complete(CoreEvent::Get(Err(From::from(e))));
        } else {
            let _ = self.heads.insert(msg_id, head);
        }

        rx
    }

    /// Post data onto the network.
    pub fn post(&mut self, data: Data, dst: Option<Authority>) -> Box<ReturnType<()>> {
        trace!("Post for {:?}", data);
        self.stats.issued_posts += 1;

        let (head, oneshot) = futures::oneshot();
        let rx = build_mutation_future(oneshot);

        let dst = dst.unwrap_or_else(|| Authority::NaeManager(*data.name()));
        let msg_id = MessageId::new();

        if let Err(e) = self.routing.send_post_request(dst, data, msg_id) {
            head.complete(CoreEvent::Mutation(Err(From::from(e))));
        } else {
            let _ = self.heads.insert(msg_id, head);
        }

        rx
    }

    /// Delete data from the network
    pub fn delete(&mut self, data: Data, dst: Option<Authority>) -> Box<ReturnType<()>> {
        trace!("DELETE for {:?}", data);

        self.stats.issued_deletes += 1;

        let (head, oneshot) = futures::oneshot();
        let rx = build_mutation_future(oneshot);

        let dst = dst.unwrap_or_else(|| Authority::NaeManager(*data.name()));
        let msg_id = MessageId::new();

        if let Err(e) = self.routing.send_delete_request(dst, data, msg_id) {
            head.complete(CoreEvent::Mutation(Err(From::from(e))));
        } else {
            let _ = self.heads.insert(msg_id, head);
        }

        rx
    }

    /// Append request
    pub fn append(&mut self,
                  appender: AppendWrapper,
                  dst: Option<Authority>)
                  -> Box<ReturnType<()>> {
        trace!("APPEND for {:?}", appender);

        self.stats.issued_appends += 1;

        let (head, oneshot) = futures::oneshot();
        let rx = build_mutation_future(oneshot);

        let dst = match dst {
            Some(auth) => auth,
            None => {
                let append_to = match appender {
                    AppendWrapper::Pub { ref append_to, .. } |
                    AppendWrapper::Priv { ref append_to, .. } => *append_to,
                };
                Authority::NaeManager(append_to)
            }
        };

        let msg_id = MessageId::new();

        if let Err(e) = self.routing.send_append_request(dst, appender, msg_id) {
            head.complete(CoreEvent::Mutation(Err(From::from(e))));
        } else {
            let _ = self.heads.insert(msg_id, head);
        }

        rx
    }

    /// Get data from the network.
    pub fn get_account_info(&mut self, dst: Option<Authority>) -> Box<ReturnType<(u64, u64)>> {
        trace!("Account info GET issued.");

        let (head, oneshot) = futures::oneshot();
        let rx = oneshot.map_err(|_| CoreError::OperationAborted)
            .and_then(|event| match event {
                CoreEvent::AccountInfo(res) => res,
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            }).into_box();

        let dst = match dst {
            Some(auth) => auth,
            None => {
                match self.cm_addr() {
                    Ok(addr) => addr.clone(),
                    Err(e) => {
                        head.complete(CoreEvent::Mutation(Err(e)));
                        return rx;
                    }
                }
            }
        };


        let msg_id = MessageId::new();
        if let Err(e) = self.routing.send_get_account_info_request(dst, msg_id) {
            head.complete(CoreEvent::AccountInfo(Err(From::from(e))));
        } else {
            let _ = self.heads.insert(msg_id, head);
        }

        rx
    }

    /// Create an entry for the Root Directory ID for the user into the session packet, encrypt and
    /// store it. It will be retrieved when the user logs into their account. Root directory ID is
    /// necessary to fetch all of the user's data as all further data is encoded as meta-information
    /// into the Root Directory or one of its subdirectories.
    pub fn set_user_root_dir_id(&mut self, dir_id: (XorName, secretbox::Key)) -> Box<ReturnType<()>> {
        trace!("Setting user root Dir ID.");

        let set = {
            let mut account = fry!(self.client_type.acc_mut());
            account.set_user_root_dir_id(dir_id)
        };

        if set {
            self.update_session_packet()
        } else {
            err!(CoreError::RootDirectoryAlreadyExists).into_box()
        }
    }

    /// Get User's Root Directory ID if available in session packet used for current login
    pub fn user_root_dir_id(&self) -> Option<&(XorName, secretbox::Key)> {
        self.client_type.acc().ok().and_then(|account| account.user_root_dir())
    }

    /// Create an entry for the Maidsafe configuration specific Root Directory ID into the
    /// session packet, encrypt and store it. It will be retrieved when the user logs into
    /// their account. Root directory ID is necessary to fetch all of configuration data as all
    /// further data is encoded as meta-information into the config Root Directory or one of its
    /// subdirectories.
    pub fn set_config_root_dir_id(&mut self, dir_id: (XorName, secretbox::Key)) -> Box<ReturnType<()>> {
        trace!("Setting configuration root Dir ID.");

        let set = {
            let mut account = fry!(self.client_type.acc_mut());
            account.set_config_root_dir(dir_id)
        };

        if set {
            self.update_session_packet()
        } else {
            err!(CoreError::RootDirectoryAlreadyExists).into_box()
        }
    }

    /// Get Maidsafe specific configuration's Root Directory ID if available in session packet used
    /// for current login
    pub fn config_root_dir_id(&self) -> Option<&(XorName, secretbox::Key)> {
        self.client_type.acc().ok().and_then(|account| account.config_root_dir())
    }

    /// Returns the public encryption key
    pub fn public_encryption_key(&self) -> Result<&box_::PublicKey, CoreError> {
        let account = try!(self.client_type.acc());
        Ok(&account.get_maid().public_keys().1)
    }

    /// Returns the Secret encryption key
    pub fn secret_encryption_key(&self) -> Result<&box_::SecretKey, CoreError> {
        let account = try!(self.client_type.acc());
        Ok(&account.get_maid().secret_keys().1)
    }

    /// Returns the Public Signing key
    pub fn public_signing_key(&self) -> Result<&sign::PublicKey, CoreError> {
        let account = try!(self.client_type.acc());
        Ok(&account.get_maid().public_keys().0)
    }

    /// Returns the Secret Signing key
    pub fn secret_signing_key(&self) -> Result<&sign::SecretKey, CoreError> {
        let account = try!(self.client_type.acc());
        Ok(&account.get_maid().secret_keys().0)
    }

    /// Return the amount of calls that were done to `get`
    pub fn issued_gets(&self) -> u64 {
        self.stats.issued_gets
    }

    /// Return the amount of calls that were done to `put`
    pub fn issued_puts(&self) -> u64 {
        self.stats.issued_puts
    }

    /// Return the amount of calls that were done to `post`
    pub fn issued_posts(&self) -> u64 {
        self.stats.issued_posts
    }

    /// Return the amount of calls that were done to `delete`
    pub fn issued_deletes(&self) -> u64 {
        self.stats.issued_deletes
    }

    /// Return the amount of calls that were done to `append`
    pub fn issued_appends(&self) -> u64 {
        self.stats.issued_appends
    }

    /// Get the default address where the PUTs will go to for this client
    pub fn cm_addr(&self) -> Result<&Authority, CoreError> {
        self.client_type.cm_addr()
    }

    #[cfg(all(test, feature = "use-mock-routing"))]
    pub fn set_network_limits(&mut self, max_ops_count: Option<u64>) {
        self.routing.set_network_limits(max_ops_count);
    }

    fn update_session_packet(&mut self) -> Box<ReturnType<()>> {
        // TODO (adam): implement this
        ok!(()).into_box()
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

enum ClientType {
    Unregistered,
    Registered {
        acc: Account,
        _acc_loc: XorName,
        _user_cred: UserCred,
        cm_addr: Authority,
    },
}

impl ClientType {
    fn reg(acc: Account, acc_loc: XorName, user_cred: UserCred, cm_addr: Authority) -> Self {
        ClientType::Registered {
            acc: acc,
            _acc_loc: acc_loc,
            _user_cred: user_cred,
            cm_addr: cm_addr,
        }
    }

    fn acc(&self) -> Result<&Account, CoreError> {
        match *self {
            ClientType::Registered { ref acc, .. } => Ok(acc),
            ClientType::Unregistered => Err(CoreError::OperationForbiddenForClient),
        }
    }

    fn acc_mut(&mut self) -> Result<&mut Account, CoreError> {
        match *self {
            ClientType::Registered { ref mut acc, .. } => Ok(acc),
            ClientType::Unregistered => Err(CoreError::OperationForbiddenForClient),
        }
    }

    fn _acc_loc(&self) -> Result<XorName, CoreError> {
        match *self {
            ClientType::Registered { _acc_loc, .. } => Ok(_acc_loc),
            ClientType::Unregistered => Err(CoreError::OperationForbiddenForClient),
        }
    }

    fn _user_cred(&self) -> Result<&UserCred, CoreError> {
        match *self {
            ClientType::Registered { ref _user_cred, .. } => Ok(_user_cred),
            ClientType::Unregistered => Err(CoreError::OperationForbiddenForClient),
        }
    }

    fn cm_addr(&self) -> Result<&Authority, CoreError> {
        match *self {
            ClientType::Registered { ref cm_addr, .. } => Ok(cm_addr),
            ClientType::Unregistered => Err(CoreError::OperationForbiddenForClient),
        }
    }
}

struct Stats {
    issued_gets: u64,
    issued_puts: u64,
    issued_posts: u64,
    issued_deletes: u64,
    issued_appends: u64,
}

impl Default for Stats {
    fn default() -> Self {
        Stats {
            issued_gets: 0,
            issued_puts: 0,
            issued_posts: 0,
            issued_deletes: 0,
            issued_appends: 0,
        }
    }
}

fn setup_routing(full_id: Option<FullId>) -> Result<(Routing, Receiver<Event>), CoreError> {
    let (routing_tx, routing_rx) = mpsc::channel();
    let routing = try!(Routing::new(routing_tx, full_id));

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

fn spawn_routing_thread(routing_rx: Receiver<Event>, core_tx: CoreMsgTx) -> Joiner {
    thread::named("Routing Event Loop",
                  move || routing_el::run(routing_rx, core_tx))
}

fn build_mutation_future(oneshot: Oneshot<CoreEvent>) -> Box<ReturnType<()>> {
    oneshot.map_err(|_| CoreError::OperationAborted).and_then(|event| match event {
        CoreEvent::Mutation(res) => res,
        _ => Err(CoreError::ReceivedUnexpectedEvent),
    }).into_box()
}

#[cfg(test)]
mod tests {
    use core::{CoreError, CoreMsg, FutureExt};
    use core::{core_el, utility};
    use futures::Future;
    use rand;
    use routing::{Data, DataIdentifier, ImmutableData};
    use routing::client_errors::MutationError;
    use rust_sodium::crypto::secretbox;
    use std::cell::RefCell;
    use std::rc::Rc;
    use super::*;
    use tokio_core::channel;
    use tokio_core::reactor::Core;

    #[test]
    fn unregistered_client() {
        let orig_data = ImmutableData::new(unwrap!(utility::generate_random_vector(30)));
        let orig_data = Data::Immutable(orig_data);

        // Registered Client PUTs something onto the network
        {
            let core = unwrap!(Core::new());
            let (core_tx, core_rx) = unwrap!(channel::channel(&core.handle()));

            let secret_0 = unwrap!(utility::generate_random_string(10));
            let secret_1 = unwrap!(utility::generate_random_string(10));
            let client = unwrap!(Client::registered(&secret_0, &secret_1, core_tx.clone()));

            let orig_data = orig_data.clone();

            unwrap!(core_tx.send(CoreMsg::new(move |cptr| {
                let future = cptr.borrow_mut().put(orig_data, None)
                                              .then(|_| Ok(()))
                                              .into_box();
                Some(future)
            })));

            unwrap!(core_tx.send(CoreMsg::build_terminator()));
            core_el::run(core, Rc::new(RefCell::new(client)), core_rx);
        }

        // Unregistered Client should be able to retrieve the data
        let core = unwrap!(Core::new());
        let (core_tx, core_rx) = unwrap!(channel::channel(&core.handle()));
        let client = unwrap!(Client::unregistered(core_tx.clone()));

        let data_id = DataIdentifier::Immutable(*orig_data.name());

        unwrap!(core_tx.send(CoreMsg::new(move |cptr| {
            let cptr2 = cptr.clone();
            let cptr3 = cptr.clone();

            let future = cptr.borrow_mut().get(data_id, None).map(move |data| {
                assert_eq!(data, orig_data);
            }).and_then(move |_| {
                let name = rand::random();
                let key  = secretbox::gen_key();

                let mut cptr = cptr2.borrow_mut();
                cptr.set_user_root_dir_id((name, key))
            }).map(|_| {
                panic!("Unregistered client should not be allowed to set user root dir");
            }).or_else(move |err| {
                match err {
                    CoreError::OperationForbiddenForClient => (),
                    _ => panic!("Unexpected {:?}", err),
                }

                let name = rand::random();
                let key  = secretbox::gen_key();

                let mut cptr = cptr3.borrow_mut();
                cptr.set_config_root_dir_id((name, key))
            }).map(|_| {
                panic!("Unregistered client should not be allowed to set config root dir");
            }).map_err(|err| {
                match err {
                    CoreError::OperationForbiddenForClient => (),
                    _ => panic!("Unexpected {:?}", err),
                }
            }).into_box();

            Some(future)
        })));
        unwrap!(core_tx.send(CoreMsg::build_terminator()));
        core_el::run(core, Rc::new(RefCell::new(client)), core_rx);
    }

    #[test]
    fn registered_client() {
        let el = unwrap!(Core::new());
        let (core_tx, _) = unwrap!(channel::channel(&el.handle()));

        let sec_0 = unwrap!(utility::generate_random_string(10));
        let sec_1 = unwrap!(utility::generate_random_string(10));

        // Account creation for the 1st time - should succeed
        let _ = unwrap!(Client::registered(&sec_0, &sec_1, core_tx.clone()));

        // Account creation - same secrets - should fail
        match Client::registered(&sec_0, &sec_1, core_tx) {
            Ok(_) => panic!("Account name hijacking should fail"),
            Err(CoreError::MutationFailure { reason: MutationError::AccountExists, .. }) => (),
            Err(err) => panic!("{:?}", err),
        }
    }

    #[test]
    fn login() {
        let el = unwrap!(Core::new());
        let (core_tx, _) = unwrap!(channel::channel(&el.handle()));

        let sec_0 = unwrap!(utility::generate_random_string(10));
        let sec_1 = unwrap!(utility::generate_random_string(10));
        assert!(Client::login(&sec_0, &sec_1, core_tx.clone()).is_err());
        let _ = unwrap!(Client::registered(&sec_0, &sec_1, core_tx.clone()));
        let _ = unwrap!(Client::login(&sec_0, &sec_1, core_tx));
    }
}
