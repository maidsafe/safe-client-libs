// Copyright 2015 MaidSafe.net limited.
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

/// Lazy evaluated response getter.
pub mod response_getter;

mod user_account;
mod message_queue;

#[cfg(feature = "use-mock-routing")]
mod non_networking_test_framework;


use core::errors::CoreError;
use core::translated_events::NetworkEvent;
use core::utility;

use maidsafe_utilities::serialisation::serialise;
use maidsafe_utilities::thread::Joiner;
use routing::{AppendWrapper, Authority, Data, DataIdentifier, FullId, MessageId, PlainData,
              StructuredData, XorName};
#[cfg(not(feature = "use-mock-routing"))]
use routing::Client as Routing;
use routing::TYPE_TAG_SESSION_PACKET;
use routing::client_errors::MutationError;
use routing::messaging::{MpidMessage, MpidMessageWrapper};
use rust_sodium::crypto::{box_, sign};
use rust_sodium::crypto::hash::sha256;

use self::message_queue::MessageQueue;

#[cfg(feature = "use-mock-routing")]
use self::non_networking_test_framework::RoutingMock as Routing;
use self::response_getter::{GetAccountInfoResponseGetter, GetResponseGetter,
                            MutationResponseGetter};
use self::user_account::Account;
use std::sync::{Arc, Mutex, mpsc};
use std::sync::mpsc::Sender;

/// The main self-authentication client instance that will interface all the request from high
/// level API's to the actual routing layer and manage all interactions with it. This is
/// essentially a non-blocking Client with upper layers having an option to either block and wait
/// on the returned ResponseGetters for receiving network response or spawn a new thread. The Client
/// itself is however well equipped for parallel and non-blocking PUTs and GETS.
pub struct Client {
    account: Option<Account>,
    routing: Routing,
    _raii_joiner: Joiner,
    message_queue: Arc<Mutex<MessageQueue>>,
    session_packet_id: Option<XorName>,
    session_packet_keys: Option<SessionPacketEncryptionKeys>,
    client_manager_addr: Option<XorName>,
    issued_gets: u64,
    issued_puts: u64,
    issued_posts: u64,
    issued_deletes: u64,
    issued_appends: u64,
}

impl Client {
    /// This is a getter-only Gateway function to the Maidsafe network. It will create an
    /// unregistered random clinet, which can do very limited set of operations - eg., a
    /// Network-Get
    pub fn create_unregistered_client() -> Result<Client, CoreError> {
        trace!("Creating unregistered client.");

        let (routing_sender, routing_receiver) = mpsc::channel();
        let (network_event_sender, network_event_receiver) = mpsc::channel();

        let (message_queue, raii_joiner) = MessageQueue::new(routing_receiver,
                                                             vec![network_event_sender]);
        let routing = try!(Routing::new(routing_sender, None));

        trace!("Waiting to get connected to the Network...");
        match try!(network_event_receiver.recv()) {
            NetworkEvent::Connected => (),
            x => {
                warn!("Could not connect to the Network. Unexpected: {:?}", x);
                return Err(CoreError::OperationAborted);
            }
        }
        trace!("Connected to the Network.");

        Ok(Client {
            account: None,
            routing: routing,
            _raii_joiner: raii_joiner,
            message_queue: message_queue,
            session_packet_id: None,
            session_packet_keys: None,
            client_manager_addr: None,
            issued_gets: 0,
            issued_puts: 0,
            issued_posts: 0,
            issued_deletes: 0,
            issued_appends: 0,
        })
    }

    /// This is one of the two Gateway functions to the Maidsafe network, the other being the
    /// log_in. This will help create a fresh account for the user in the SAFE-network.
    pub fn create_account(acc_locator: &str, acc_password: &str) -> Result<Client, CoreError> {
        trace!("Creating an account.");

        let (password, keyword, pin) = utility::derive_secrets(acc_locator, acc_password);

        let account_packet = Account::new(None, None);
        let id_packet = FullId::with_keys((account_packet.get_maid().public_keys().1,
                                           account_packet.get_maid().secret_keys().1.clone()),
                                          (account_packet.get_maid().public_keys().0,
                                           account_packet.get_maid().secret_keys().0.clone()));

        let (routing_sender, routing_receiver) = mpsc::channel();
        let (network_event_sender, network_event_receiver) = mpsc::channel();

        let (message_queue, raii_joiner) = MessageQueue::new(routing_receiver,
                                                             vec![network_event_sender]);
        let routing = try!(Routing::new(routing_sender, Some(id_packet)));

        trace!("Waiting to get connected to the Network...");
        match try!(network_event_receiver.recv()) {
            NetworkEvent::Connected => (),
            x => {
                warn!("Could not connect to the Network. Unexpected: {:?}", x);
                return Err(CoreError::OperationAborted);
            }
        }
        trace!("Connected to the Network.");

        let hash_sign_key = sha256::hash(&(account_packet.get_maid().public_keys().0).0);
        let client_manager_addr = XorName(hash_sign_key.0);

        let mut client = Client {
            account: Some(account_packet),
            routing: routing,
            _raii_joiner: raii_joiner,
            message_queue: message_queue,
            session_packet_id: Some(try!(Account::generate_network_id(&keyword, &pin))),
            session_packet_keys: Some(SessionPacketEncryptionKeys::new(password, pin)),
            client_manager_addr: Some(client_manager_addr),
            issued_gets: 0,
            issued_puts: 0,
            issued_posts: 0,
            issued_deletes: 0,
            issued_appends: 0,
        };

        {
            let account_version = {
                let account = unwrap!(client.account.as_ref());
                let session_packet_keys = unwrap!(client.session_packet_keys.as_ref());

                let session_packet_id = unwrap!(client.session_packet_id.as_ref());
                try!(StructuredData::new(TYPE_TAG_SESSION_PACKET,
                                         *session_packet_id,
                                         0,
                                         try!(account.encrypt(session_packet_keys.get_password(),
                                                              session_packet_keys.get_pin())),
                                         vec![account.get_public_maid().public_keys().0.clone()],
                                         Vec::new(),
                                         Some(&account.get_maid().secret_keys().0)))
            };

            try!(try!(client.put(Data::Structured(account_version), None)).get());
        }

        Ok(client)
    }

    /// This is one of the two Gateway functions to the Maidsafe network, the other being the
    /// create_account. This will help log into an already created account for the user in the
    /// SAFE-network.
    pub fn log_in(acc_locator: &str, acc_password: &str) -> Result<Client, CoreError> {
        let (password, keyword, pin) = utility::derive_secrets(acc_locator, acc_password);

        let mut unregistered_client = try!(Client::create_unregistered_client());
        let user_id = try!(Account::generate_network_id(&keyword, &pin));

        let session_packet_request = DataIdentifier::Structured(user_id, TYPE_TAG_SESSION_PACKET);

        let resp_getter = try!(unregistered_client.get(session_packet_request, None));

        if let Data::Structured(session_packet) = try!(resp_getter.get()) {
            let decrypted_session_packet =
                try!(Account::decrypt(session_packet.get_data(), &password, &pin));
            let id_packet = FullId::with_keys((decrypted_session_packet.get_maid()
                                                  .public_keys()
                                                  .1,
                                               decrypted_session_packet.get_maid()
                                                  .secret_keys()
                                                  .1
                                                  .clone()),
                                              (decrypted_session_packet.get_maid()
                                                  .public_keys()
                                                  .0,
                                               decrypted_session_packet.get_maid()
                                                  .secret_keys()
                                                  .0
                                                  .clone()));

            let (routing_sender, routing_receiver) = mpsc::channel();
            let (network_event_sender, network_event_receiver) = mpsc::channel();

            let (message_queue, raii_joiner) = MessageQueue::new(routing_receiver,
                                                                 vec![network_event_sender]);
            let routing = try!(Routing::new(routing_sender, Some(id_packet)));

            trace!("Waiting to get connected to the Network...");
            match try!(network_event_receiver.recv()) {
                NetworkEvent::Connected => (),
                x => {
                    warn!("Could not connect to the Network. Unexpected: {:?}", x);
                    return Err(CoreError::OperationAborted);
                }
            }
            trace!("Connected to the Network.");

            let hash_sign_key =
                sha256::hash(&(decrypted_session_packet.get_maid().public_keys().0).0);
            let client_manager_addr = XorName(hash_sign_key.0);

            let client = Client {
                account: Some(decrypted_session_packet),
                routing: routing,
                _raii_joiner: raii_joiner,
                message_queue: message_queue,
                session_packet_id: Some(try!(Account::generate_network_id(&keyword, &pin))),
                session_packet_keys: Some(SessionPacketEncryptionKeys::new(password, pin)),
                client_manager_addr: Some(client_manager_addr),
                issued_gets: 0,
                issued_puts: 0,
                issued_posts: 0,
                issued_deletes: 0,
                issued_appends: 0,
            };

            Ok(client)
        } else {
            Err(CoreError::ReceivedUnexpectedData)
        }
    }

    /// Create an entry for the Root Directory ID for the user into the session packet, encrypt and
    /// store it. It will be retrieved when the user logs into their account. Root directory ID is
    /// necessary to fetch all of the user's data as all further data is encoded as meta-information
    /// into the Root Directory or one of its subdirectories.
    pub fn set_user_root_directory_id(&mut self, root_dir_id: XorName) -> Result<(), CoreError> {
        trace!("Setting user root Dir ID.");

        if try!(self.account.as_mut().ok_or(CoreError::OperationForbiddenForClient))
            .set_user_root_dir_id(root_dir_id) {
            self.update_session_packet()
        } else {
            Err(CoreError::RootDirectoryAlreadyExists)
        }
    }

    /// Get User's Root Directory ID if available in session packet used for current login
    pub fn get_user_root_directory_id(&self) -> Option<&XorName> {
        self.account.as_ref().and_then(|account| account.get_user_root_dir_id())
    }

    /// Create an entry for the Maidsafe configuration specific Root Directory ID into the
    /// session packet, encrypt and store it. It will be retrieved when the user logs into
    /// their account. Root directory ID is necessary to fetch all of configuration data as all
    /// further data is encoded as meta-information into the config Root Directory or one of its
    /// subdirectories.
    pub fn set_configuration_root_directory_id(&mut self,
                                               root_dir_id: XorName)
                                               -> Result<(), CoreError> {
        trace!("Setting configuration root Dir ID.");

        if try!(self.account.as_mut().ok_or(CoreError::OperationForbiddenForClient))
            .set_maidsafe_config_root_dir_id(root_dir_id) {
            self.update_session_packet()
        } else {
            Err(CoreError::RootDirectoryAlreadyExists)
        }
    }

    /// Get Maidsafe specific configuration's Root Directory ID if available in session packet used
    /// for current login
    pub fn get_configuration_root_directory_id(&self) -> Option<&XorName> {
        self.account.as_ref().and_then(|account| account.get_maidsafe_config_root_dir_id())
    }

    /// Combined Asymmetric and Symmetric encryption. The data is encrypted using random Key and
    /// IV with Xsalsa-symmetric encryption. Random IV ensures that same plain text produces
    /// different cipher-texts for each fresh symmetric encryption. The Key and IV are then
    /// asymmetrically encrypted using Public-MAID and the whole thing is then serialised into a
    /// single `Vec<u8>`.
    pub fn hybrid_encrypt(&self,
                          data_to_encrypt: &[u8],
                          nonce_opt: Option<&box_::Nonce>)
                          -> Result<Vec<u8>, CoreError> {
        let account = try!(self.account.as_ref().ok_or(CoreError::OperationForbiddenForClient));

        let mut nonce_default = box_::Nonce([0u8; box_::NONCEBYTES]);
        let nonce = match nonce_opt {
            Some(nonce) => nonce,
            None => {
                let digest = sha256::hash(&account.get_public_maid().name().0);
                let min_length = ::std::cmp::min(box_::NONCEBYTES, digest.0.len());
                for it in digest.0.iter().take(min_length).enumerate() {
                    nonce_default.0[it.0] = *it.1;
                }
                &nonce_default
            }
        };

        utility::hybrid_encrypt(data_to_encrypt,
                                nonce,
                                &account.get_public_maid().public_keys().1,
                                &account.get_maid().secret_keys().1)
    }

    /// Reverse of hybrid_encrypt. Refer hybrid_encrypt.
    pub fn hybrid_decrypt(&self,
                          data_to_decrypt: &[u8],
                          nonce_opt: Option<&box_::Nonce>)
                          -> Result<Vec<u8>, CoreError> {
        let account = try!(self.account.as_ref().ok_or(CoreError::OperationForbiddenForClient));

        let mut nonce_default = box_::Nonce([0u8; box_::NONCEBYTES]);
        let nonce = match nonce_opt {
            Some(nonce) => nonce,
            None => {
                let digest = sha256::hash(&account.get_public_maid().name().0);
                let min_length = ::std::cmp::min(box_::NONCEBYTES, digest.0.len());
                for it in digest.0.iter().take(min_length).enumerate() {
                    nonce_default.0[it.0] = *it.1;
                }
                &nonce_default
            }
        };

        utility::hybrid_decrypt(data_to_decrypt,
                                nonce,
                                &account.get_public_maid().public_keys().1,
                                &account.get_maid().secret_keys().1)
    }

    /// Get data from the network. This is non-blocking.
    pub fn get(&mut self,
               request_for: DataIdentifier,
               opt_dst: Option<Authority>)
               -> Result<GetResponseGetter, CoreError> {
        trace!("GET for {:?}", request_for);

        self.issued_gets += 1;

        if let DataIdentifier::Immutable(..) = request_for {
            let mut msg_queue = unwrap!(self.message_queue.lock());
            if msg_queue.local_cache_check(request_for.name()) {
                trace!("ImmutableData found in cache.");
                return Ok(GetResponseGetter::new(None, self.message_queue.clone(), request_for));
            }
        }

        let dst = match opt_dst {
            Some(auth) => auth,
            None => Authority::NaeManager(*request_for.name()),
        };

        let (tx, rx) = mpsc::channel();
        let msg_id = MessageId::new();
        unwrap!(self.message_queue.lock()).register_response_observer(msg_id, tx.clone());

        try!(self.routing.send_get_request(dst, request_for.clone(), msg_id));

        Ok(GetResponseGetter::new(Some((tx, rx)), self.message_queue.clone(), request_for))
    }

    /// Put data onto the network. This is non-blocking.
    pub fn put(&mut self,
               data: Data,
               opt_dst: Option<Authority>)
               -> Result<MutationResponseGetter, CoreError> {
        trace!("PUT for {:?}", data);

        self.issued_puts += 1;

        let dst = match opt_dst {
            Some(auth) => auth,
            None => Authority::ClientManager(*try!(self.get_default_client_manager_address())),
        };

        let (tx, rx) = mpsc::channel();
        let msg_id = MessageId::new();
        unwrap!(self.message_queue.lock()).register_response_observer(msg_id, tx.clone());

        try!(self.routing.send_put_request(dst, data, msg_id));

        Ok(MutationResponseGetter::new((tx, rx)))
    }

    /// Put data to the network. Unlike `put` this method is blocking and will return success if
    /// the data has already been put to the network.
    pub fn put_recover(client: Arc<Mutex<Self>>,
                       data: Data,
                       opt_dst: Option<Authority>)
                       -> Result<(), CoreError> {
        trace!("PUT with recovery for {:?}", data);

        let data_owners = match data {
            Data::Structured(ref sd) => sd.get_owner_keys().clone(),
            _ => {
                // Don't do recovery for non-structured-data.
                let getter = try!(unwrap!(client.lock()).put(data, opt_dst));
                return getter.get();
            }
        };

        let data_id = data.identifier();
        let put_err = match unwrap!(client.lock()).put(data, opt_dst.clone()) {
            Ok(getter) => {
                match getter.get() {
                    // Success! We're done.
                    Ok(()) => return Ok(()),
                    Err(e) => e,
                }
            }
            Err(e) => e,
        };

        debug!("PUT of StructuredData failed with {:?}. Attempting recovery.",
               put_err);

        if let CoreError::MutationFailure { reason: MutationError::LowBalance, .. } = put_err {
            debug!("Low balance error cannot be recovered from.");
            return Err(put_err);
        }

        match unwrap!(client.lock()).get(data_id, opt_dst) {
            Err(_) => Err(put_err),
            Ok(getter) => {
                match getter.get() {
                    Err(e) => {
                        debug!("Address space is vacant but still unable to PUT due to {:?}.",
                               e);
                        Err(put_err)
                    }
                    Ok(Data::Structured(ref sd)) => {
                        if *sd.get_owner_keys() == data_owners {
                            debug!("PUT recovery successful !");
                            Ok(())
                        } else {
                            debug!("StructuredData exists but we are not the owner.");
                            Err(put_err)
                        }
                    }
                    Ok(data) => {
                        debug!("Address space already occupied by: {:?}.", data);
                        Err(put_err)
                    }
                }
            }
        }
    }

    /// Post data onto the network
    pub fn post(&mut self,
                data: Data,
                opt_dst: Option<Authority>)
                -> Result<MutationResponseGetter, CoreError> {
        trace!("POST for {:?}", data);

        self.issued_posts += 1;

        let dst = match opt_dst {
            Some(auth) => auth,
            None => Authority::NaeManager(*data.name()),
        };

        let (tx, rx) = mpsc::channel();
        let msg_id = MessageId::new();
        unwrap!(self.message_queue.lock()).register_response_observer(msg_id, tx.clone());

        try!(self.routing.send_post_request(dst, data, msg_id));

        Ok(MutationResponseGetter::new((tx, rx)))
    }

    /// Delete data from the network
    pub fn delete(&mut self,
                  data: Data,
                  opt_dst: Option<Authority>)
                  -> Result<MutationResponseGetter, CoreError> {
        trace!("DELETE for {:?}", data);

        self.issued_deletes += 1;

        let dst = match opt_dst {
            Some(auth) => auth,
            None => Authority::NaeManager(*data.name()),
        };

        let (tx, rx) = mpsc::channel();
        let msg_id = MessageId::new();
        unwrap!(self.message_queue.lock()).register_response_observer(msg_id, tx.clone());

        try!(self.routing.send_delete_request(dst, data, msg_id));

        Ok(MutationResponseGetter::new((tx, rx)))
    }

    /// A blocking version of `delete` that returns success if the data was already not present on
    /// the network.
    pub fn delete_recover(client: Arc<Mutex<Self>>,
                          data: Data,
                          opt_dst: Option<Authority>)
                          -> Result<(), CoreError> {
        trace!("DELETE with recovery for {:?}", data);

        let resp_getter = try!(unwrap!(client.lock()).delete(data, opt_dst));
        match resp_getter.get() {
            Ok(()) |
            Err(CoreError::MutationFailure { reason: MutationError::NoSuchData, .. }) => {
                debug!("DELETE recovery successful !");
                Ok(())
            }
            Err(e) => {
                debug!("Recovery failed: {:?}", e);
                Err(e)
            }
        }
    }

    /// Append request
    pub fn append(&mut self,
                  appender: AppendWrapper,
                  opt_dst: Option<Authority>)
                  -> Result<MutationResponseGetter, CoreError> {
        trace!("APPEND for {:?}", appender);

        self.issued_appends += 1;

        let dst = match opt_dst {
            Some(auth) => auth,
            None => {
                let append_to = match appender {
                    AppendWrapper::Pub { ref append_to, .. } |
                    AppendWrapper::Priv { ref append_to, .. } => *append_to,
                };
                Authority::NaeManager(append_to)
            }
        };

        let (tx, rx) = mpsc::channel();
        let msg_id = MessageId::new();
        unwrap!(self.message_queue.lock()).register_response_observer(msg_id, tx.clone());

        try!(self.routing.send_append_request(dst, appender, msg_id));

        Ok(MutationResponseGetter::new((tx, rx)))
    }

    /// Get data from the network. This is non-blocking.
    pub fn get_account_info(&mut self,
                            opt_dst: Option<Authority>)
                            -> Result<GetAccountInfoResponseGetter, CoreError> {
        trace!("Account info GET issued.");

        let dst = match opt_dst {
            Some(auth) => auth,
            None => Authority::ClientManager(*try!(self.get_default_client_manager_address())),
        };

        let (tx, rx) = mpsc::channel();
        let msg_id = MessageId::new();
        unwrap!(self.message_queue.lock()).register_response_observer(msg_id, tx.clone());

        try!(self.routing.send_get_account_info_request(dst, msg_id));

        Ok(GetAccountInfoResponseGetter::new((tx, rx)))
    }

    // TODO Redo this since response handling is integrated - For Qi right now
    /// Send a message to receiver via the network. This is non-blocking.
    pub fn send_message(&mut self,
                        mpid_account: XorName,
                        msg_metadata: Vec<u8>,
                        msg_content: Vec<u8>,
                        receiver: XorName,
                        secret_key: &sign::SecretKey)
                        -> Result<MutationResponseGetter, CoreError> {
        let mpid_message = try!(MpidMessage::new(mpid_account,
                                                 msg_metadata,
                                                 receiver,
                                                 msg_content,
                                                 secret_key));
        let name = try!(mpid_message.name());
        let request = MpidMessageWrapper::PutMessage(mpid_message);

        let serialised_request = try!(serialise(&request));
        let data = Data::Plain(PlainData::new(name, serialised_request));

        self.put(data, Some(Authority::ClientManager(mpid_account)))
    }

    /// Delete a message from own or sender's outbox. This is non-blocking.
    pub fn delete_message(&mut self,
                          target_account: XorName,
                          message_name: XorName)
                          -> Result<MutationResponseGetter, CoreError> {
        self.messaging_delete_request(target_account,
                                      message_name,
                                      MpidMessageWrapper::DeleteMessage(message_name))
    }

    /// Delete a header from own inbox. This is non-blocking.
    pub fn delete_header(&mut self,
                         mpid_account: XorName,
                         header_name: XorName)
                         -> Result<MutationResponseGetter, CoreError> {
        self.messaging_delete_request(mpid_account,
                                      header_name,
                                      MpidMessageWrapper::DeleteHeader(header_name))
    }

    fn messaging_delete_request(&mut self,
                                account: XorName,
                                name: XorName,
                                request: MpidMessageWrapper)
                                -> Result<MutationResponseGetter, CoreError> {
        let serialised_request = try!(serialise(&request));
        let data = Data::Plain(PlainData::new(name, serialised_request));

        self.delete(data, Some(Authority::ClientManager(account)))
    }

    /// Register as an online mpid_messaging client to the network. This is non-blocking.
    pub fn register_online(&mut self,
                           mpid_account: XorName)
                           -> Result<GetResponseGetter, CoreError> {
        self.messaging_post_request(mpid_account, MpidMessageWrapper::Online)
    }

    /// Query the targeted messages' header that still in the outbox. This is non-blocking.
    pub fn query_outbox_headers(&mut self,
                                mpid_account: XorName,
                                headers: Vec<XorName>)
                                -> Result<GetResponseGetter, CoreError> {
        self.messaging_post_request(mpid_account, MpidMessageWrapper::OutboxHas(headers))
    }

    /// Get the list of messages' headers that still in the outbox. This is non-blocking.
    pub fn get_outbox_headers(&mut self,
                              mpid_account: XorName)
                              -> Result<GetResponseGetter, CoreError> {
        self.messaging_post_request(mpid_account, MpidMessageWrapper::GetOutboxHeaders)
    }

    // TODO - Qi to check if this is alright - Post something should not require version caching.
    // Should this not be a GET ? - Asked by Spandan
    fn messaging_post_request(&mut self,
                              mpid_account: XorName,
                              request: MpidMessageWrapper)
                              -> Result<GetResponseGetter, CoreError> {
        let data_request = DataIdentifier::Plain(mpid_account);

        {
            let mut msg_queue = unwrap!(self.message_queue.lock());
            if msg_queue.local_cache_check(&mpid_account) {
                return Ok(GetResponseGetter::new(None, self.message_queue.clone(), data_request));
            }
        }

        let serialised_request = try!(serialise(&request));
        let data = Data::Plain(PlainData::new(mpid_account, serialised_request));
        try!(try!(self.post(data, Some(Authority::ClientManager(mpid_account)))).get());

        let (tx, rx) = mpsc::channel();
        let msg_id = MessageId::new();
        unwrap!(self.message_queue.lock()).register_response_observer(msg_id, tx.clone());

        Ok(GetResponseGetter::new(Some((tx, rx)), self.message_queue.clone(), data_request))
    }

    /// Returns the public encryption key
    pub fn get_public_encryption_key(&self) -> Result<&box_::PublicKey, CoreError> {
        let account = try!(self.account.as_ref().ok_or(CoreError::OperationForbiddenForClient));
        Ok(&account.get_maid().public_keys().1)
    }

    /// Returns the Secret encryption key
    pub fn get_secret_encryption_key(&self) -> Result<&box_::SecretKey, CoreError> {
        let account = try!(self.account.as_ref().ok_or(CoreError::OperationForbiddenForClient));
        Ok(&account.get_maid().secret_keys().1)
    }

    /// Returns the Public Signing key
    pub fn get_public_signing_key(&self) -> Result<&sign::PublicKey, CoreError> {
        let account = try!(self.account.as_ref().ok_or(CoreError::OperationForbiddenForClient));
        Ok(&account.get_maid().public_keys().0)
    }

    /// Returns the Secret Signing key
    pub fn get_secret_signing_key(&self) -> Result<&sign::SecretKey, CoreError> {
        let account = try!(self.account.as_ref().ok_or(CoreError::OperationForbiddenForClient));
        Ok(&account.get_maid().secret_keys().0)
    }

    /// Add observers for Network Events like `Connected`, `Disconnected`, `Terminated`
    pub fn add_network_event_observer(&self, sender: Sender<NetworkEvent>) {
        unwrap!(self.message_queue.lock()).add_network_event_observer(sender);
    }

    /// Get the default address where the PUTs will go to for this client
    pub fn get_default_client_manager_address(&self) -> Result<&XorName, CoreError> {
        self.client_manager_addr.as_ref().ok_or(CoreError::OperationForbiddenForClient)
    }

    /// Set the default address where the PUTs and DELETEs will go to for this client
    pub fn set_default_client_manager_address(&mut self,
                                              address: XorName)
                                              -> Result<(), CoreError> {
        match self.client_manager_addr.as_mut() {
            Some(contained_address) => *contained_address = address,
            None => return Err(CoreError::OperationForbiddenForClient),
        }

        Ok(())
    }

    fn update_session_packet(&mut self) -> Result<(), CoreError> {
        trace!("Updating session packet.");

        let session_packet_id = *try!(self.session_packet_id
            .as_ref()
            .ok_or(CoreError::OperationForbiddenForClient));
        let session_packet_request = DataIdentifier::Structured(session_packet_id,
                                                                TYPE_TAG_SESSION_PACKET);

        let resp_getter = try!(self.get(session_packet_request, None));

        if let Data::Structured(retrieved_session_packet) = try!(resp_getter.get()) {
            let new_account_version = {
                let account = try!(self.account
                    .as_ref()
                    .ok_or(CoreError::OperationForbiddenForClient));

                let encrypted_account = {
                    let session_packet_keys = try!(self.session_packet_keys
                        .as_ref()
                        .ok_or(CoreError::OperationForbiddenForClient));
                    try!(account.encrypt(session_packet_keys.get_password(),
                                         session_packet_keys.get_pin()))
                };

                try!(StructuredData::new(TYPE_TAG_SESSION_PACKET,
                                         session_packet_id,
                                         retrieved_session_packet.get_version() + 1,
                                         encrypted_account,
                                         vec![account.get_public_maid()
                                                  .public_keys()
                                                  .0
                                                  .clone()],
                                         Vec::new(),
                                         Some(&account.get_maid().secret_keys().0)))
            };
            try!(self.post(Data::Structured(new_account_version), None)).get()
        } else {
            Err(CoreError::ReceivedUnexpectedData)
        }
    }

    /// Return the amount of calls that were done to `get`
    pub fn issued_gets(&self) -> u64 {
        self.issued_gets
    }

    /// Return the amount of calls that were done to `put`
    pub fn issued_puts(&self) -> u64 {
        self.issued_puts
    }

    /// Return the amount of calls that were done to `post`
    pub fn issued_posts(&self) -> u64 {
        self.issued_posts
    }

    /// Return the amount of calls that were done to `delete`
    pub fn issued_deletes(&self) -> u64 {
        self.issued_deletes
    }

    /// Return the amount of calls that were done to `append`
    pub fn issued_appends(&self) -> u64 {
        self.issued_appends
    }

    #[cfg(all(test, feature = "use-mock-routing"))]
    pub fn set_network_limits(&mut self, max_ops_count: Option<u64>) {
        self.routing.set_network_limits(max_ops_count);
    }
}

/// //////////////////////////////////////////////////////////////
/// Helper Struct
/// //////////////////////////////////////////////////////////////

struct SessionPacketEncryptionKeys {
    pin: Vec<u8>,
    password: Vec<u8>,
}

impl SessionPacketEncryptionKeys {
    fn new(password: Vec<u8>, pin: Vec<u8>) -> SessionPacketEncryptionKeys {
        SessionPacketEncryptionKeys {
            pin: pin,
            password: password,
        }
    }

    fn get_password(&self) -> &[u8] {
        &self.password[..]
    }

    fn get_pin(&self) -> &[u8] {
        &self.pin[..]
    }
}

/// //////////////////////////////////////////////////////////////
#[cfg(test)]
mod test {

    use core::client::response_getter::GetResponseGetter;
    use core::errors::CoreError;
    use core::utility;

    use rand;
    use routing::{Data, DataIdentifier, ImmutableData, StructuredData, XOR_NAME_LEN, XorName};
    use routing::client_errors::MutationError;
    use super::*;

    #[test]
    fn account_creation() {
        let secret_0 = unwrap!(utility::generate_random_string(10));
        let secret_1 = unwrap!(utility::generate_random_string(10));

        // Account creation for the 1st time - should succeed
        let _ = unwrap!(Client::create_account(&secret_0, &secret_1));

        // Account creation - same secrets - should fail
        match Client::create_account(&secret_0, &secret_1) {
            Ok(_) => panic!("Account name hijaking should fail !"),
            Err(CoreError::MutationFailure { reason: MutationError::AccountExists, .. }) => (),
            Err(err) => panic!("{:?}", err),
        }
    }

    #[test]
    fn account_login() {
        let secret_0 = unwrap!(utility::generate_random_string(10));
        let secret_1 = unwrap!(utility::generate_random_string(10));

        // Creation should pass
        let _ = unwrap!(Client::create_account(&secret_0, &secret_1));

        // Correct Credentials - Login Should Pass
        let _ = unwrap!(Client::log_in(&secret_0, &secret_1));
    }

    #[test]
    fn unregistered_client() {
        let immut_data = ImmutableData::new(unwrap!(utility::generate_random_vector(30)));
        let orig_data = Data::Immutable(immut_data);

        // Registered Client PUTs something onto the network
        {
            let secret_0 = unwrap!(utility::generate_random_string(10));
            let secret_1 = unwrap!(utility::generate_random_string(10));

            // Creation should pass
            let mut client = unwrap!(Client::create_account(&secret_0, &secret_1));
            unwrap!(unwrap!(client.put(orig_data.clone(), None)).get());
        }

        // Unregistered Client should be able to retrieve the data
        let mut unregistered_client = unwrap!(Client::create_unregistered_client());
        let request = DataIdentifier::Immutable(*orig_data.name());
        let rxd_data = unwrap!(unwrap!(unregistered_client.get(request, None)).get());

        assert_eq!(rxd_data, orig_data);

        // Operations Not Allowed for Unregistered Client
        let rand_name: XorName = rand::random();

        match (unregistered_client.set_user_root_directory_id(rand_name),
               unregistered_client.set_configuration_root_directory_id(rand_name)) {
            (Err(CoreError::OperationForbiddenForClient),
             Err(CoreError::OperationForbiddenForClient)) => (),
            _ => panic!("Unexpected !!"),
        };
    }

    #[test]
    fn user_root_dir_id_creation() {
        // Construct Client
        let secret_0 = unwrap!(utility::generate_random_string(10));
        let secret_1 = unwrap!(utility::generate_random_string(10));

        let mut client = unwrap!(Client::create_account(&secret_0, &secret_1));

        assert!(client.get_user_root_directory_id().is_none());
        assert!(client.get_configuration_root_directory_id().is_none());

        let root_dir_id = XorName([99u8; XOR_NAME_LEN]);
        unwrap!(client.set_user_root_directory_id(root_dir_id.clone()));

        // Correct Credentials - Login Should Pass
        let client = unwrap!(Client::log_in(&secret_0, &secret_1));

        assert!(client.get_user_root_directory_id().is_some());
        assert!(client.get_configuration_root_directory_id().is_none());

        assert_eq!(client.get_user_root_directory_id(), Some(&root_dir_id));
    }

    #[test]
    fn maidsafe_config_root_dir_id_creation() {
        // Construct Client
        let secret_0 = unwrap!(utility::generate_random_string(10));
        let secret_1 = unwrap!(utility::generate_random_string(10));

        let mut client = unwrap!(Client::create_account(&secret_0, &secret_1));

        assert!(client.get_user_root_directory_id().is_none());
        assert!(client.get_configuration_root_directory_id().is_none());

        let root_dir_id = XorName([99u8; XOR_NAME_LEN]);
        unwrap!(client.set_configuration_root_directory_id(root_dir_id.clone()));

        // Correct Credentials - Login Should Pass
        let client = unwrap!(Client::log_in(&secret_0, &secret_1));

        assert!(client.get_user_root_directory_id().is_none());
        assert!(client.get_configuration_root_directory_id().is_some());

        assert_eq!(client.get_configuration_root_directory_id(),
                   Some(&root_dir_id));
    }

    #[test]
    fn hybrid_encryption_decryption() {
        // Construct Client
        let secret_0 = unwrap!(utility::generate_random_string(10));
        let secret_1 = unwrap!(utility::generate_random_string(10));

        let client = unwrap!(Client::create_account(&secret_0, &secret_1));

        // Identical Plain Texts
        let plain_text_original_0 = vec![123u8; 1000];
        let plain_text_original_1 = plain_text_original_0.clone();

        // Encrypt passing Nonce
        let nonce = ::rust_sodium::crypto::box_::gen_nonce();
        let cipher_text_0 =
            unwrap!(client.hybrid_encrypt(&plain_text_original_0[..], Some(&nonce)));
        let cipher_text_1 =
            unwrap!(client.hybrid_encrypt(&plain_text_original_1[..], Some(&nonce)));

        // Encrypt without passing Nonce
        let cipher_text_2 = unwrap!(client.hybrid_encrypt(&plain_text_original_0[..], None));
        let cipher_text_3 = unwrap!(client.hybrid_encrypt(&plain_text_original_1[..], None));

        // Same Plain Texts
        assert_eq!(plain_text_original_0, plain_text_original_1);

        // Different Results because of random "iv"
        assert!(cipher_text_0 != cipher_text_1);
        assert!(cipher_text_0 != cipher_text_2);
        assert!(cipher_text_0 != cipher_text_3);
        assert!(cipher_text_2 != cipher_text_1);
        assert!(cipher_text_2 != cipher_text_3);

        // Decrypt with Nonce
        let plain_text_0 = unwrap!(client.hybrid_decrypt(&cipher_text_0, Some(&nonce)));
        let plain_text_1 = unwrap!(client.hybrid_decrypt(&cipher_text_1, Some(&nonce)));

        // Decrypt without Nonce
        let plain_text_2 = unwrap!(client.hybrid_decrypt(&cipher_text_2, None));
        let plain_text_3 = unwrap!(client.hybrid_decrypt(&cipher_text_3, None));

        // Decryption without passing Nonce for something encrypted with passing Nonce - Should Fail
        match client.hybrid_decrypt(&cipher_text_0, None) {
            Ok(_) => panic!("Should have failed !"),
            Err(CoreError::AsymmetricDecipherFailure) => (),
            Err(error) => panic!("{:?}", error),
        }
        // Decryption passing Nonce for something encrypted without passing Nonce - Should Fail
        match client.hybrid_decrypt(&cipher_text_3, Some(&nonce)) {
            Ok(_) => panic!("Should have failed !"),
            Err(CoreError::AsymmetricDecipherFailure) => (),
            Err(error) => panic!("{:?}", error),
        }

        // Should have decrypted to the same Plain Texts
        assert_eq!(plain_text_original_0, plain_text_0);
        assert_eq!(plain_text_original_1, plain_text_1);
        assert_eq!(plain_text_original_0, plain_text_2);
        assert_eq!(plain_text_original_1, plain_text_3);
    }

    #[test]
    fn version_caching() {
        let mut client = unwrap!(utility::test_utils::get_client());

        // Version Caching should work for ImmutableData
        {
            let immut_data = ImmutableData::new(unwrap!(utility::generate_random_vector(10)));
            let data = Data::Immutable(immut_data);

            unwrap!(unwrap!(client.put(data.clone(), None)).get());

            let data_request = DataIdentifier::Immutable(*data.name());

            // Should not initially be in version cache
            {
                let resp_getter =
                    GetResponseGetter::new(None, client.message_queue.clone(), data_request);

                match resp_getter.get() {
                    Ok(_) => panic!("Should not have found data in version cache !!"),
                    Err(CoreError::VersionCacheMiss) => (),
                    Err(error) => panic!("{:?}", error),
                }
            }

            let response_getter = unwrap!(client.get(data_request, None));
            assert_eq!(unwrap!(response_getter.get()), data);

            let resp_getter =
                GetResponseGetter::new(None, client.message_queue.clone(), data_request);
            assert_eq!(unwrap!(resp_getter.get()), data);
        }

        // Version Caching should NOT work for StructuredData
        {
            const TYPE_TAG: u64 = 15000;
            let id: XorName = rand::random();

            let struct_data = unwrap!(StructuredData::new(TYPE_TAG,
                                                          id.clone(),
                                                          0,
                                                          Vec::new(),
                                                          Vec::new(),
                                                          Vec::new(),
                                                          None));
            let data = Data::Structured(struct_data);

            unwrap!(unwrap!(client.put(data.clone(), None)).get());

            let data_request = DataIdentifier::Structured(id, TYPE_TAG);

            // Should not initially be in version cache
            {
                let resp_getter =
                    GetResponseGetter::new(None, client.message_queue.clone(), data_request);

                match resp_getter.get() {
                    Ok(_) => panic!("Should not have found data in version cache !!"),
                    Err(CoreError::VersionCacheMiss) => (),
                    Err(error) => panic!("{:?}", error),
                }
            }

            let response_getter = unwrap!(client.get(data_request, None));
            assert_eq!(unwrap!(response_getter.get()), data);

            // Should not be in version cache even after fetch
            {
                let resp_getter =
                    GetResponseGetter::new(None, client.message_queue.clone(), data_request);

                match resp_getter.get() {
                    Ok(_) => panic!("Should not have found data in version cache !!"),
                    Err(CoreError::VersionCacheMiss) => (),
                    Err(error) => panic!("{:?}", error),
                }
            }
        }
    }
}
