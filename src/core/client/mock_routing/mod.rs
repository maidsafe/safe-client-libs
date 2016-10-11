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

mod storage;

use maidsafe_utilities::serialisation::serialise;
use maidsafe_utilities::thread;
use rand;
use routing::{AppendWrapper, Authority, Data, DataIdentifier, Event, FullId, InterfaceError,
              MessageId, Request, Response, RoutingError, XorName};
use routing::TYPE_TAG_SESSION_PACKET;
use routing::client_errors::{GetError, MutationError};
use rust_sodium::crypto::hash::sha256;
use rust_sodium::crypto::sign;
use rustc_serialize::Encodable;
use self::storage::{ClientAccount, Storage};
use std;
use std::cell::Cell;
use std::sync::Mutex;
use std::sync::mpsc::Sender;
use std::time::Duration;

const CONNECT_THREAD: &'static str = "Mock routing connect";

// Activating these (ie., non-zero values) will require an update to all test cases. Once activated
// the GET's should only be performed once success from PUT's/POST's/DELETE's have been obtained.
//
// These will allow to code properly for behavioural anomalies like GETs reaching the address faster
// than PUTs. So a proper delay will help code better logic against scenarios where it is required
// to do a GET after a PUT/DELETE to confirm that action. So for example if a GET done immediately
// after a PUT failed, it could mean that the PUT either failed or hasn't reached the address yet.
const DELAY_GETS_POSTS_MS: u64 = 0;
const DELAY_PUTS_DELETS_MS: u64 = 2 * DELAY_GETS_POSTS_MS;

lazy_static! {
    static ref STORAGE: Mutex<Storage> = Mutex::new(Storage::new());
}

pub struct MockRouting {
    sender: Sender<Event>,
    client_auth: Authority,
    max_ops_countdown: Option<Cell<u64>>,
}

impl MockRouting {
    pub fn new(sender: Sender<Event>, _id: Option<FullId>) -> Result<MockRouting, RoutingError> {
        ::rust_sodium::init();

        let cloned_sender = sender.clone();
        let _ = thread::named(CONNECT_THREAD, move || {
            std::thread::sleep(Duration::from_millis(DELAY_PUTS_DELETS_MS));
            let _ = cloned_sender.send(Event::Connected);
        });

        let client_auth = Authority::Client {
            client_key: sign::gen_keypair().0,
            peer_id: rand::random(),
            proxy_node_name: rand::random(),
        };
        Ok(MockRouting {
            sender: sender,
            client_auth: client_auth,
            max_ops_countdown: None,
        })
    }

    // Note: destination authority is ignored (everywhere in Mock) because the clients can direct
    // data to wherever they want. It is only the requirement of maidsafe-routing that GET's should
    // go to MaidManagers etc.
    pub fn send_get_request(&mut self,
                            _dst: Authority,
                            data_id: DataIdentifier,
                            msg_id: MessageId)
                            -> Result<(), InterfaceError> {
        let cloned_sender = self.sender.clone();
        let client_auth = self.client_auth.clone();

        let err = if self.network_limits_reached() {
            info!("Mock GET: {:?} {:?} [0]", data_id, msg_id);
            Some(GetError::NetworkOther("Max operations exhausted".to_string()))
        } else {
            if let Some(count) = self.update_network_limits() {
                info!("Mock GET: {:?} {:?} [{}]", data_id, msg_id, count);
            }

            None
        };

        let _ = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(DELAY_GETS_POSTS_MS));
            let data_name = *data_id.name();
            let nae_auth = Authority::NaeManager(data_name);
            let request = Request::Get(data_id, msg_id);

            if let Some(reason) = err {
                Self::send_failure_resp(&cloned_sender, nae_auth, client_auth, request, reason);
                return;
            }

            match unwrap!(STORAGE.lock()).get_data(&data_name) {
                Ok(data) => {
                    if match (&data, &data_id) {
                        (&Data::Immutable(_), &DataIdentifier::Immutable(_)) => true,
                        (&Data::PrivAppendable(_), &DataIdentifier::PrivAppendable(_)) => true,
                        (&Data::PubAppendable(_), &DataIdentifier::PubAppendable(_)) => true,
                        (&Data::Structured(ref struct_data),
                         &DataIdentifier::Structured(_, ref tag)) => {
                            struct_data.get_type_tag() == *tag
                        }
                        _ => false,
                    } {
                        let event = Event::Response {
                            src: nae_auth,
                            dst: client_auth,
                            response: Response::GetSuccess(data, msg_id),
                        };

                        Self::send(&cloned_sender, event);
                    } else {
                        Self::send_failure_resp(&cloned_sender,
                                                nae_auth,
                                                client_auth,
                                                request,
                                                GetError::NoSuchData);
                    }
                }
                Err(error) => {
                    Self::send_failure_resp(&cloned_sender,
                                            nae_auth,
                                            client_auth,
                                            request,
                                            GetError::from(error));
                }
            };
        });

        Ok(())
    }

    pub fn send_put_request(&self,
                            _dst: Authority,
                            data: Data,
                            msg_id: MessageId)
                            -> Result<(), InterfaceError> {
        let cloned_sender = self.sender.clone();
        let client_auth = self.client_auth.clone();

        let data_name = *data.name();
        let data_id = data.identifier();
        // NaeManager is used as the destination authority here because in the Mock we assume that
        // MaidManagers always pass the PUT. Errors if any can come only from NaeManagers
        let nae_auth = Authority::NaeManager(data_name);
        let request = Request::Put(data.clone(), msg_id);

        let mut storage = unwrap!(STORAGE.lock());
        let err = if self.network_limits_reached() {
            info!("Mock PUT: {:?} {:?} [0]", data_id, msg_id);
            Some(MutationError::NetworkOther("Max operations exhausted".to_string()))
        } else if storage.contains_data(&data_name) {
            match data {
                Data::Immutable(_) => {
                    match storage.get_data(&data_name) {
                        // Immutable data is de-duplicated so always allowed
                        Ok(Data::Immutable(_)) => None,
                        Ok(_) => Some(MutationError::DataExists),
                        Err(error) => Some(MutationError::from(error)),
                    }
                }
                Data::Structured(struct_data) => {
                    if struct_data.get_type_tag() == TYPE_TAG_SESSION_PACKET {
                        Some(MutationError::AccountExists)
                    } else {
                        Some(MutationError::DataExists)
                    }
                }
                _ => Some(MutationError::DataExists),
            }
        } else {
            match storage.put_data(data_name, data) {
                Ok(()) => None,
                Err(error) => Some(MutationError::from(error)),
            }
        };

        if err == None {
            if let Some(count) = self.update_network_limits() {
                info!("Mock PUT: {:?} {:?} [{}]", data_id, msg_id, count);
            }

            {
                let account = storage.client_accounts
                                     .entry(self.client_name())
                                     .or_insert_with(ClientAccount::default);
                account.data_stored += 1;
                account.space_available -= 1;
            }

            storage.sync();
        }

        let _ = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(DELAY_PUTS_DELETS_MS));
            if let Some(reason) = err {
                Self::send_failure_resp(&cloned_sender, nae_auth, client_auth, request, reason);
            } else {
                let event = Event::Response {
                    src: nae_auth,
                    dst: client_auth,
                    response: Response::PutSuccess(data_id, msg_id),
                };

                Self::send(&cloned_sender, event);
            }
        });

        Ok(())
    }

    pub fn send_post_request(&self,
                             _dst: Authority,
                             data: Data,
                             msg_id: MessageId)
                             -> Result<(), InterfaceError> {
        let cloned_sender = self.sender.clone();
        let client_auth = self.client_auth.clone();

        let data_name = *data.name();
        let data_id = data.identifier();
        let nae_auth = Authority::NaeManager(data_name);
        let request = Request::Post(data.clone(), msg_id);

        let mut storage = unwrap!(STORAGE.lock());
        let result = if storage.contains_data(&data_name) {
            if self.network_limits_reached() {
                info!("Mock POST: {:?} {:?} [0]", data_id, msg_id);
                Err(MutationError::NetworkOther("Max operations exhausted".to_string()))
            } else {
                match (data, storage.get_data(&data_name)) {
                    (Data::Structured(sd_new), Ok(Data::Structured(sd_stored))) => {
                        if let Ok(_) = sd_stored.validate_self_against_successor(&sd_new) {
                            Ok(Data::Structured(sd_new))
                        } else {
                            Err(MutationError::InvalidSuccessor)
                        }
                    }
                    (Data::PrivAppendable(ad_new),
                     Ok(Data::PrivAppendable(mut ad_stored))) => {
                        if let Ok(()) = ad_stored.update_with_other(ad_new) {
                            Ok(Data::PrivAppendable(ad_stored))
                        } else {
                            Err(MutationError::InvalidSuccessor)
                        }
                    }
                    (Data::PubAppendable(ad_new),
                     Ok(Data::PubAppendable(mut ad_stored))) => {
                        if let Ok(()) = ad_stored.update_with_other(ad_new) {
                            Ok(Data::PubAppendable(ad_stored))
                        } else {
                            Err(MutationError::InvalidSuccessor)
                        }
                    }
                    (_, Ok(_)) => Err(MutationError::InvalidOperation),
                    (_, Err(error)) => Err(MutationError::from(error)),
                }
            }
        } else {
            Err(MutationError::NoSuchData)
        };

        let err = match result {
            Ok(data) => {
                match storage.put_data(data_name, data) {
                    Ok(()) => {
                        if let Some(count) = self.update_network_limits() {
                            info!("Mock POST: {:?} {:?} [{}]", data_id, msg_id, count);
                        }

                        storage.sync();
                        None
                    }
                    Err(error) => Some(MutationError::from(error)),
                }
            }
            Err(error) => Some(error),
        };

        let _ = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(DELAY_PUTS_DELETS_MS));
            if let Some(reason) = err {
                Self::send_failure_resp(&cloned_sender, nae_auth, client_auth, request, reason);
            } else {
                let event = Event::Response {
                    src: nae_auth,
                    dst: client_auth,
                    response: Response::PostSuccess(data_id, msg_id),
                };

                Self::send(&cloned_sender, event);
            }
        });

        Ok(())
    }

    pub fn send_delete_request(&self,
                               _dst: Authority,
                               data: Data,
                               msg_id: MessageId)
                               -> Result<(), InterfaceError> {
        let cloned_sender = self.sender.clone();
        let client_auth = self.client_auth.clone();

        let data_name = *data.name();
        let data_id = data.identifier();
        let nae_auth = Authority::NaeManager(data_name);
        let request = Request::Delete(data.clone(), msg_id);

        let mut storage = unwrap!(STORAGE.lock());
        let err = if self.network_limits_reached() {
            info!("Mock DELETE: {:?} {:?} [0]", data_id, msg_id);
            Some(MutationError::NetworkOther("Max operations exhausted".to_string()))
        } else {
            match (data, storage.get_data(&data_name)) {
                (Data::Structured(sd_new), Ok(Data::Structured(sd_stored))) => {
                    if let Ok(_) = sd_stored.validate_self_against_successor(&sd_new) {
                        storage.remove_data(&data_name);
                        storage.sync();
                        None
                    } else {
                        Some(MutationError::InvalidSuccessor)
                    }
                }
                (_, Ok(_)) => Some(MutationError::InvalidOperation),
                (_, Err(error)) => Some(MutationError::from(error)),
            }
        };

        if err == None {
            if let Some(count) = self.update_network_limits() {
                info!("Mock DELETE: {:?} {:?} [{}]", data_id, msg_id, count);
            }
        }

        let _ = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(DELAY_PUTS_DELETS_MS));
            if let Some(reason) = err {
                Self::send_failure_resp(&cloned_sender, nae_auth, client_auth, request, reason);
            } else {
                let event = Event::Response {
                    src: nae_auth,
                    dst: client_auth,
                    response: Response::DeleteSuccess(data_id, msg_id),
                };

                Self::send(&cloned_sender, event);
            }
        });

        Ok(())
    }

    pub fn send_get_account_info_request(&mut self,
                                         dst: Authority,
                                         msg_id: MessageId)
                                         -> Result<(), InterfaceError> {
        let cloned_sender = self.sender.clone();
        let client_auth = self.client_auth.clone();
        let client_name = self.client_name();

        let err = if self.network_limits_reached() {
            info!("Mock GetAccountInfo: {:?} {:?} [0]", client_name, msg_id);
            Some(GetError::NetworkOther("Max operations exhausted".to_string()))
        } else {
            None
        };

        if err == None {
            if let Some(count) = self.update_network_limits() {
                info!("Mock GetAccountInfo: {:?} {:?} [{}]",
                      client_name,
                      msg_id,
                      count);
            }
        }

        let _ = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(DELAY_GETS_POSTS_MS));
            let request = Request::GetAccountInfo(msg_id);

            if let Some(reason) = err {
                Self::send_failure_resp(&cloned_sender, dst, client_auth, request, reason);
                return;
            }

            match unwrap!(STORAGE.lock()).client_accounts.get(&client_name) {
                Some(account) => {
                    let event = Event::Response {
                        src: dst,
                        dst: client_auth,
                        response: Response::GetAccountInfoSuccess {
                            id: msg_id,
                            data_stored: account.data_stored,
                            space_available: account.space_available,
                        },
                    };
                    Self::send(&cloned_sender, event);
                }
                None => {
                    Self::send_failure_resp(&cloned_sender,
                                            dst,
                                            client_auth,
                                            request,
                                            GetError::NoSuchAccount);
                }
            };
        });

        Ok(())
    }

    pub fn send_append_request(&self,
                               _dst: Authority,
                               wrapper: AppendWrapper,
                               msg_id: MessageId)
                               -> Result<(), InterfaceError> {
        let cloned_sender = self.sender.clone();
        let client_auth = self.client_auth.clone();

        let data_id = wrapper.identifier();
        let data_name = *data_id.name();
        let nae_auth = Authority::NaeManager(data_name);
        let request = Request::Append(wrapper.clone(), msg_id);

        let mut storage = unwrap!(STORAGE.lock());
        let err = if storage.contains_data(&data_name) {
            if self.network_limits_reached() {
                info!("Mock APPEND: {:?} {:?} [0]", data_id, msg_id);
                Some(MutationError::NetworkOther("Max operations exhausted".to_string()))
            } else {
                match (wrapper, storage.get_data(&data_name)) {
                    (AppendWrapper::Priv { data, version, sign_key, .. },
                     Ok(Data::PrivAppendable(mut ad_stored))) => {
                        if version == ad_stored.version && ad_stored.append(data, &sign_key) {
                            match storage.put_data(data_name, Data::PrivAppendable(ad_stored)) {
                                Ok(()) => None,
                                Err(error) => Some(MutationError::from(error)),
                            }
                        } else {
                            Some(MutationError::InvalidSuccessor)
                        }
                    }
                    (AppendWrapper::Pub { data, version, .. },
                     Ok(Data::PubAppendable(mut ad_stored))) => {
                        if version == ad_stored.version && ad_stored.append(data) {
                            match storage.put_data(data_name, Data::PubAppendable(ad_stored)) {
                                Ok(()) => None,
                                Err(error) => Some(MutationError::from(error)),
                            }
                        } else {
                            Some(MutationError::InvalidSuccessor)
                        }
                    }
                    (_, Ok(_)) => Some(MutationError::InvalidOperation),
                    (_, Err(error)) => Some(MutationError::from(error)),
                }
            }
        } else {
            Some(MutationError::NoSuchData)
        };

        if err == None {
            storage.sync();

            if let Some(count) = self.update_network_limits() {
                info!("Mock POST: {:?} {:?} [{}]", data_id, msg_id, count);
            }
        }

        let _ = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(DELAY_PUTS_DELETS_MS));
            if let Some(reason) = err {
                Self::send_failure_resp(&cloned_sender, nae_auth, client_auth, request, reason);
            } else {
                let event = Event::Response {
                    src: nae_auth,
                    dst: client_auth,
                    response: Response::AppendSuccess(data_id, msg_id),
                };

                Self::send(&cloned_sender, event);
            }
        });

        Ok(())
    }

    fn send(sender: &Sender<Event>, event: Event) {
        if let Err(error) = sender.send(event) {
            error!("mpsc-send failure: {:?}", error);
        }
    }

    fn send_failure_resp<E: Encodable>(sender: &Sender<Event>,
                                       src: Authority,
                                       dst: Authority,
                                       request: Request,
                                       err: E) {
        let ext_err = match serialise(&err) {
            Ok(serialised) => serialised,
            Err(err) => {
                warn!("Could not serialise client-vault error - {:?}", err);
                Vec::new()
            }
        };

        let response = match request {
            Request::Get(data_id, msg_id) => {
                Response::GetFailure {
                    id: msg_id,
                    data_id: data_id,
                    external_error_indicator: ext_err,
                }
            }
            Request::Put(data, msg_id) => {
                Response::PutFailure {
                    id: msg_id,
                    data_id: data.identifier(),
                    external_error_indicator: ext_err,
                }
            }
            Request::Post(data, msg_id) => {
                Response::PostFailure {
                    id: msg_id,
                    data_id: data.identifier(),
                    external_error_indicator: ext_err,
                }
            }
            Request::Delete(data, msg_id) => {
                Response::DeleteFailure {
                    id: msg_id,
                    data_id: data.identifier(),
                    external_error_indicator: ext_err,
                }
            }
            Request::GetAccountInfo(msg_id) => {
                Response::GetAccountInfoFailure {
                    id: msg_id,
                    external_error_indicator: ext_err,
                }
            }
            Request::Append(append_wrapper, msg_id) => {
                Response::AppendFailure {
                    id: msg_id,
                    data_id: append_wrapper.identifier(),
                    external_error_indicator: ext_err,
                }
            }
            _ => {
                unreachable!("Cannot handle {:?} in this function. Report as bug",
                             request)
            }
        };

        let event = Event::Response {
            src: src,
            dst: dst,
            response: response,
        };

        Self::send(sender, event)
    }

    fn client_name(&self) -> XorName {
        match self.client_auth {
            Authority::Client { ref client_key, .. } => XorName(sha256::hash(&client_key[..]).0),
            _ => panic!("This authority must be Client"),
        }
    }

    #[cfg(test)]
    pub fn set_network_limits(&mut self, max_ops_count: Option<u64>) {
        self.max_ops_countdown = max_ops_count.map(Cell::new)
    }

    fn network_limits_reached(&self) -> bool {
        self.max_ops_countdown.as_ref().map_or(false, |count| count.get() == 0)
    }

    fn update_network_limits(&self) -> Option<u64> {
        self.max_ops_countdown.as_ref().map(|count| {
            let ops = count.get();
            count.set(ops - 1);
            ops
        })
    }
}

#[cfg(test)]
mod test {
    use core::client::account::Account;
    use core::errors::CoreError;
    use core::utility;
    use maidsafe_utilities::serialisation::{deserialise, serialise};
    use rand;
    use routing::{AppendWrapper, AppendedData, Authority, Data, DataIdentifier, Event, Filter,
                  FullId, ImmutableData, MessageId, PubAppendableData, Response, StructuredData,
                  XOR_NAME_LEN, XorName};
    use routing::client_errors::{GetError, MutationError};
    use rust_sodium::crypto::sign;
    use std::collections::HashMap;
    use std::iter;
    use std::sync::mpsc::{self, Receiver};
    use super::*;
    use super::storage::DEFAULT_CLIENT_ACCOUNT_SIZE;

    #[test]
    fn map_serialisation() {
        let mut map_before = HashMap::<XorName, Vec<u8>>::new();
        let _ = map_before.insert(XorName([1; XOR_NAME_LEN]), vec![1; 10]);

        let serialised_data = unwrap!(serialise(&map_before));

        let map_after: HashMap<XorName, Vec<u8>> = unwrap!(deserialise(&serialised_data));
        assert_eq!(map_before, map_after);
    }

    #[test]
    fn check_put_post_get_delete_for_immutable_data() {
        let (_, id_packet) = create_account_and_full_id();
        let (routing_sender, routing_receiver) = mpsc::channel();
        let mut mock_routing = unwrap!(MockRouting::new(routing_sender, Some(id_packet)));
        wait_for_connection(&routing_receiver);

        // Construct ImmutableData
        let orig_immutable_data = generate_random_immutable_data();
        let orig_data = Data::Immutable(orig_immutable_data);

        let location_nae_mgr = Authority::NaeManager(*orig_data.name());
        let location_client_mgr = Authority::ClientManager(*orig_data.name());

        // GET ImmutableData should fail
        {
            let result = do_get(&mut mock_routing,
                                &routing_receiver,
                                location_nae_mgr.clone(),
                                orig_data.identifier());

            match result {
                Ok(_) => panic!("Expected Get Failure!"),
                Err(CoreError::GetFailure { reason: GetError::NoSuchData, .. }) => (),
                Err(err) => panic!("Unexpected: {:?}", err),
            }
        }

        // First PUT should succeed
        unwrap!(do_put(&mut mock_routing,
                       &routing_receiver,
                       location_client_mgr.clone(),
                       orig_data.clone()));

        // GET ImmutableData should pass
        assert_eq!(unwrap!(do_get(&mut mock_routing,
                                  &routing_receiver,
                                  location_nae_mgr.clone(),
                                  orig_data.identifier())),
                   orig_data);

        // GetAccountInfo should pass and show one chunk stored
        assert_eq!(unwrap!(do_get_account_info(&mut mock_routing,
                                               &routing_receiver,
                                               location_client_mgr.clone())),

                   (1, DEFAULT_CLIENT_ACCOUNT_SIZE - 1));

        // Subsequent PUTs for same ImmutableData should succeed - De-duplication
        unwrap!(do_put(&mut mock_routing,
                       &routing_receiver,
                       location_client_mgr.clone(),
                       orig_data.clone()));

        // POSTs for ImmutableData should fail
        {
            let result = do_post(&mut mock_routing,
                                 &routing_receiver,
                                 location_nae_mgr.clone(),
                                 orig_data.clone());

            match result {
                Ok(_) => panic!("Expected Post Failure!"),
                Err(CoreError::MutationFailure { reason: MutationError::InvalidOperation, .. }) => {
                    ()
                }
                Err(err) => panic!("Unexpected: {:?}", err),
            }
        }

        // DELETEs of ImmutableData should fail
        {
            let result = do_delete(&mut mock_routing,
                                   &routing_receiver,
                                   location_client_mgr.clone(),
                                   orig_data.clone());

            match result {
                Ok(_) => panic!("Expected Delete Failure!"),
                Err(CoreError::MutationFailure { reason: MutationError::InvalidOperation, .. }) => {
                    ()
                }
                Err(err) => panic!("Unexpected: {:?}", err),
            }
        }

        // GET ImmutableData should pass
        assert_eq!(unwrap!(do_get(&mut mock_routing,
                                  &routing_receiver,
                                  location_nae_mgr.clone(),
                                  orig_data.identifier())),
                   orig_data);

        // GetAccountInfo should pass and show two chunks stored
        assert_eq!(unwrap!(do_get_account_info(&mut mock_routing,
                                               &routing_receiver,
                                               location_client_mgr)),

                   (2, DEFAULT_CLIENT_ACCOUNT_SIZE - 2));
    }

    #[test]
    fn check_put_post_get_delete_for_structured_data() {
        let (account_packet, id_packet) = create_account_and_full_id();
        let (routing_sender, routing_receiver) = mpsc::channel();
        let mut mock_routing = unwrap!(MockRouting::new(routing_sender, Some(id_packet)));
        wait_for_connection(&routing_receiver);

        let owner_key = account_packet.get_public_maid().public_keys().0.clone();

        // Construct ImmutableData
        let orig_immutable_data = generate_random_immutable_data();
        let orig_data = Data::Immutable(orig_immutable_data);

        const TYPE_TAG: u64 = 999;

        // Construct StructuredData, 1st version, for this ImmutableData
        let keyword = unwrap!(utility::generate_random_string(10));
        let pin = unwrap!(utility::generate_random_string(10));
        let user_id = unwrap!(Account::generate_network_id(keyword.as_bytes(),
                                                           pin.to_string().as_bytes()));
        let account_ver_res = StructuredData::new(TYPE_TAG,
                                                  user_id,
                                                  0,
                                                  unwrap!(serialise(&vec![orig_data.name()])),
                                                  vec![account_packet.get_public_maid()
                                                                     .public_keys()
                                                                     .0
                                                                     .clone()],
                                                  Vec::new(),
                                                  Some(&account_packet.get_maid().secret_keys().0));
        let mut account_version = unwrap!(account_ver_res);
        let mut data_account_version = Data::Structured(account_version);


        let location_nae_mgr_immut = Authority::NaeManager(*orig_data.name());
        let location_nae_mgr_struct = Authority::NaeManager(*data_account_version.name());

        let location_client_mgr_immut = Authority::ClientManager(*orig_data.name());
        let location_client_mgr_struct = Authority::ClientManager(*data_account_version.name());

        // First PUT of StructuredData should succeed
        unwrap!(do_put(&mut mock_routing,
                       &routing_receiver,
                       location_client_mgr_struct.clone(),
                       data_account_version.clone()));

        // PUT for ImmutableData should succeed
        unwrap!(do_put(&mut mock_routing,
                       &routing_receiver,
                       location_client_mgr_immut.clone(),
                       orig_data.clone()));

        let mut received_structured_data: StructuredData;

        // GET StructuredData should pass
        {
            let struct_data_id = DataIdentifier::Structured(user_id, TYPE_TAG);
            let data = unwrap!(do_get(&mut mock_routing,
                                      &routing_receiver,
                                      location_client_mgr_struct.clone(),
                                      struct_data_id));

            assert_eq!(data, data_account_version);
            match data {
                Data::Structured(struct_data) => received_structured_data = struct_data,
                _ => unreachable!("Unexpected! {:?}", data),
            }
        }

        // GetAccountInfo should pass and show two chunks stored
        assert_eq!(unwrap!(do_get_account_info(&mut mock_routing,
                                               &routing_receiver,
                                               location_client_mgr_struct.clone())),

                   (2, DEFAULT_CLIENT_ACCOUNT_SIZE - 2));

        // GET ImmutableData from latest version of StructuredData should pass
        {
            let mut location_vec =
                unwrap!(deserialise::<Vec<XorName>>(received_structured_data.get_data()));
            let immut_data_id = DataIdentifier::Immutable(unwrap!(location_vec.pop(),
                                                                  "Value must exist !"));

            assert_eq!(unwrap!(do_get(&mut mock_routing,
                                      &routing_receiver,
                                      location_client_mgr_immut.clone(),
                                      immut_data_id)),
                       orig_data);
        }

        // Construct ImmutableData
        let new_immutable_data = generate_random_immutable_data();
        let new_data = Data::Immutable(new_immutable_data);

        // PUT for new ImmutableData should succeed
        unwrap!(do_put(&mut mock_routing,
                       &routing_receiver,
                       location_client_mgr_struct.clone(),
                       new_data.clone()));

        // Construct StructuredData, 2nd version, for this ImmutableData - IVALID Versioning
        let invalid_version_account_version = unwrap!(StructuredData::new(TYPE_TAG,
                                               user_id,
                                               0,
                                               Vec::new(),
                                               vec![owner_key.clone()],
                                               Vec::new(),
                                               Some(&account_packet.get_maid()
                                                   .secret_keys()
                                                   .0)));
        let invalid_version_data_account_version =
            Data::Structured(invalid_version_account_version);

        // Construct StructuredData, 2nd version, for this ImmutableData - IVALID Signature
        let invalid_signature_account_version = unwrap!(StructuredData::new(TYPE_TAG,
                                        user_id,
                                        1,
                                        Vec::new(),
                                        vec![owner_key.clone()],
                                        Vec::new(),
                                        Some(&account_packet.get_mpid().secret_keys().0)));
        let invalid_signature_data_account_version =
            Data::Structured(invalid_signature_account_version);

        let data_for_version_2 = unwrap!(serialise(&vec![orig_data.name(), new_data.name()]));
        // Construct StructuredData, 2nd version, for this ImmutableData - Valid
        account_version = unwrap!(StructuredData::new(TYPE_TAG,
                                                      user_id,
                                                      1,
                                                      data_for_version_2,
                                                      vec![owner_key.clone()],
                                                      Vec::new(),
                                                      Some(&account_packet.get_maid()
                                                                          .secret_keys()
                                                                          .0)));
        data_account_version = Data::Structured(account_version);

        // Subsequent PUTs for same StructuredData should fail
        {
            let result = do_put(&mut mock_routing,
                                &routing_receiver,
                                location_client_mgr_struct.clone(),
                                data_account_version.clone());

            match result {
                Ok(_) => panic!("Expected Put Failure!"),
                Err(CoreError::MutationFailure { reason: MutationError::DataExists, .. }) => (),
                Err(err) => panic!("Unexpected: {:?}", err),
            }
        }

        // Subsequent POSTSs for same StructuredData should fail if versioning is invalid
        {
            let result = do_post(&mut mock_routing,
                                 &routing_receiver,
                                 location_nae_mgr_struct.clone(),
                                 invalid_version_data_account_version);

            match result {
                Ok(_) => panic!("Expected Post Failure!"),
                Err(CoreError::MutationFailure { reason: MutationError::InvalidSuccessor, .. }) => {
                    ()
                }
                Err(err) => panic!("Unexpected: {:?}", err),
            }
        }

        // Subsequent POSTSs for same StructuredData should fail if signature is invalid
        {
            let result = do_post(&mut mock_routing,
                                 &routing_receiver,
                                 location_client_mgr_struct.clone(),
                                 invalid_signature_data_account_version);

            match result {
                Ok(_) => panic!("Expected Post Failure!"),
                Err(CoreError::MutationFailure { reason: MutationError::InvalidSuccessor, .. }) => {
                    ()
                }
                Err(err) => panic!("Unexpected: {:?}", err),
            }
        }

        // Subsequent POSTSs for existing StructuredData version should pass for valid update
        unwrap!(do_post(&mut mock_routing,
                        &routing_receiver,
                        location_nae_mgr_struct.clone(),
                        data_account_version.clone()));

        // GET for new StructuredData version should pass
        {
            let struct_data_id = DataIdentifier::Structured(user_id, TYPE_TAG);
            let data = unwrap!(do_get(&mut mock_routing,
                                      &routing_receiver,
                                      location_nae_mgr_struct.clone(),
                                      struct_data_id));

            assert_eq!(data, data_account_version);
            match data {
                Data::Structured(struct_data) => received_structured_data = struct_data,
                _ => unreachable!("Unexpected! {:?}", data),
            }
        }

        let location_vec =
            unwrap!(deserialise::<Vec<XorName>>(received_structured_data.get_data()));
        assert_eq!(location_vec.len(), 2);

        // GET new ImmutableData should pass
        {
            let immut_data_id = DataIdentifier::Immutable(location_vec[1]);
            assert_eq!(unwrap!(do_get(&mut mock_routing,
                                      &routing_receiver,
                                      location_nae_mgr_immut.clone(),
                                      immut_data_id)),
                       new_data);
        }

        // GET original ImmutableData should pass
        {
            let immut_data_id = DataIdentifier::Immutable(location_vec[0]);
            assert_eq!(unwrap!(do_get(&mut mock_routing,
                                      &routing_receiver,
                                      location_client_mgr_immut.clone(),
                                      immut_data_id)),
                       orig_data);
        }

        // DELETE of Structured Data without version bump should fail
        {
            let result = do_delete(&mut mock_routing,
                                   &routing_receiver,
                                   location_client_mgr_struct.clone(),
                                   data_account_version.clone());

            match result {
                Ok(_) => panic!("Expected Delete Failure!"),
                Err(CoreError::MutationFailure { reason: MutationError::InvalidSuccessor, .. }) => {
                    ()
                }
                Err(err) => panic!("Unexpected: {:?}", err),
            }
        }

        // GET for StructuredData version should still pass
        {
            let struct_data_id = DataIdentifier::Structured(user_id, TYPE_TAG);
            assert_eq!(unwrap!(do_get(&mut mock_routing,
                                      &routing_receiver,
                                      location_client_mgr_struct.clone(),
                                      struct_data_id)),
                       data_account_version);
        }

        // Construct StructuredData, 3rd version, for DELETE - Valid
        account_version = unwrap!(StructuredData::new(TYPE_TAG,
                                                      user_id,
                                                      2,
                                                      Vec::new(),
                                                      vec![owner_key.clone()],
                                                      Vec::new(),
                                                      Some(&account_packet.get_maid()
                                                                          .secret_keys()
                                                                          .0)));
        data_account_version = Data::Structured(account_version);

        // DELETE of Structured Data with version bump should pass
        unwrap!(do_delete(&mut mock_routing,
                          &routing_receiver,
                          location_client_mgr_struct,
                          data_account_version));

        // GET for DELETED StructuredData version should fail
        {
            let struct_data_id = DataIdentifier::Structured(user_id, TYPE_TAG);
            let result = do_get(&mut mock_routing,
                                &routing_receiver,
                                location_nae_mgr_struct.clone(),
                                struct_data_id);

            match result {
                Ok(_) => panic!("Expected Get Failure!"),
                Err(CoreError::GetFailure { reason: GetError::NoSuchData, .. }) => (),
                Err(err) => panic!("Unexpected: {:?}", err),
            }
        }

        // GetAccountInfo should pass and show three chunks stored
        assert_eq!(unwrap!(do_get_account_info(&mut mock_routing,
                                               &routing_receiver,
                                               location_client_mgr_immut)),
                   (3, DEFAULT_CLIENT_ACCOUNT_SIZE - 3));
    }

    #[test]
    fn check_put_post_get_append_delete_for_pub_appendable_data() {
        let (account_packet, id_packet) = create_account_and_full_id();
        let (routing_sender, routing_receiver) = mpsc::channel();
        let mut mock_routing = unwrap!(MockRouting::new(routing_sender, Some(id_packet)));
        wait_for_connection(&routing_receiver);

        let owner_key = account_packet.get_public_maid().public_keys().0.clone();
        let signing_key = account_packet.get_maid().secret_keys().0.clone();

        // Construct some immutable data to be later appended to an appendable data.
        let immut_data_0 = Data::Immutable(generate_random_immutable_data());
        let immut_data_0_nae_mgr = Authority::NaeManager(*immut_data_0.name());

        unwrap!(do_put(&mut mock_routing,
                       &routing_receiver,
                       immut_data_0_nae_mgr,
                       immut_data_0.clone()));

        let immut_data_1 = Data::Immutable(generate_random_immutable_data());
        let immut_data_1_nae_mgr = Authority::NaeManager(*immut_data_1.name());

        unwrap!(do_put(&mut mock_routing,
                       &routing_receiver,
                       immut_data_1_nae_mgr,
                       immut_data_1.clone()));

        // Construct appendable data
        let appendable_data_name = rand::random();
        let appendable_data_nae_mgr = Authority::NaeManager(appendable_data_name);

        let appendable_data = unwrap!(PubAppendableData::new(appendable_data_name,
                                                             0,
                                                             vec![owner_key],
                                                             vec![],
                                                             Default::default(),
                                                             Filter::black_list(iter::empty()),
                                                             Some(&signing_key)));

        let appendable_data_id = appendable_data.identifier();

        // PUT it to the network
        unwrap!(do_put(&mut mock_routing,
                       &routing_receiver,
                       appendable_data_nae_mgr.clone(),
                       Data::PubAppendable(appendable_data)));

        // APPEND data
        {
            let appended_data = unwrap!(AppendedData::new(immut_data_0.identifier(),
                                                          owner_key,
                                                          &signing_key));
            let append_wrapper = AppendWrapper::new_pub(appendable_data_name, appended_data, 0);

            unwrap!(do_append(&mut mock_routing,
                              &routing_receiver,
                              appendable_data_nae_mgr.clone(),
                              append_wrapper));
        }

        // GET the appendable data back from the network and verify it has the
        // previously appended data.
        let appendable_data = unwrap!(do_get(&mut mock_routing,
                                             &routing_receiver,
                                             appendable_data_nae_mgr.clone(),
                                             appendable_data_id));

        let appendable_data = match appendable_data {
            Data::PubAppendable(data) => data,
            _ => panic!("Unexpected data type"),
        };

        assert_eq!(appendable_data.name, appendable_data_name);
        assert_eq!(appendable_data.data.len(), 1);

        let appended_data = unwrap!(appendable_data.data.iter().next());
        assert_eq!(appended_data.pointer, immut_data_0.identifier());

        // APPEND more data
        {
            let appended_data = unwrap!(AppendedData::new(immut_data_1.identifier(),
                                                          owner_key,
                                                          &signing_key));
            let append_wrapper = AppendWrapper::new_pub(appendable_data_name,
                                                        appended_data,
                                                        appendable_data.version);

            unwrap!(do_append(&mut mock_routing,
                              &routing_receiver,
                              appendable_data_nae_mgr.clone(),
                              append_wrapper));
        }

        // GET the appendable data back from the network and verify it has all the
        // previously appended data.
        let appendable_data = unwrap!(do_get(&mut mock_routing,
                                             &routing_receiver,
                                             appendable_data_nae_mgr.clone(),
                                             appendable_data_id));

        let appendable_data = match appendable_data {
            Data::PubAppendable(data) => data,
            _ => panic!("Unexpected data type"),
        };

        assert_eq!(appendable_data.version, 0);
        assert_eq!(appendable_data.name, appendable_data_name);
        assert_eq!(appendable_data.data.len(), 2);

        // POST without version bump should fail
        let result = do_post(&mut mock_routing,
                             &routing_receiver,
                             appendable_data_nae_mgr.clone(),
                             Data::PubAppendable(appendable_data.clone()));

        match result {
            Ok(_) => panic!("Expected POST failure"),
            Err(CoreError::MutationFailure { reason: MutationError::InvalidSuccessor, .. }) => (),
            Err(error) => panic!("Unexpected: {:?}", error),
        }

        // POST with modified filter.
        let (blacklisted_pk, blacklisted_sk) = sign::gen_keypair();
        let filter = Filter::black_list(iter::once(blacklisted_pk));
        let appendable_data = unwrap!(PubAppendableData::new(appendable_data.name,
                                                             appendable_data.version + 1,
                                                             appendable_data.current_owner_keys
                                                                            .clone(),
                                                             appendable_data.previous_owner_keys
                                                                            .clone(),
                                                             appendable_data.deleted_data.clone(),
                                                             filter,
                                                             Some(&signing_key)));

        unwrap!(do_post(&mut mock_routing,
                        &routing_receiver,
                        appendable_data_nae_mgr.clone(),
                        Data::PubAppendable(appendable_data)));

        // GET it back and verify the filter and version are modified.
        let appendable_data = unwrap!(do_get(&mut mock_routing,
                                             &routing_receiver,
                                             appendable_data_nae_mgr.clone(),
                                             appendable_data_id));

        let appendable_data = match appendable_data {
            Data::PubAppendable(data) => data,
            _ => panic!("Unexpected data type"),
        };

        assert_eq!(appendable_data.version, 1);

        match appendable_data.filter {
            Filter::BlackList(ref list) => {
                assert_eq!(list.len(), 1);
                assert!(list.contains(&blacklisted_pk));
            }
            _ => panic!("Unexpected filter type"),
        }

        // APPEND by a blacklisted user should fail.
        {
            let immut_data_name = rand::random();
            let immut_data_id = DataIdentifier::Immutable(immut_data_name);

            let appended_data = unwrap!(AppendedData::new(immut_data_id,
                                                          blacklisted_pk,
                                                          &blacklisted_sk));
            let append_wrapper = AppendWrapper::new_pub(appendable_data_name,
                                                        appended_data,
                                                        appendable_data.version);

            let result = do_append(&mut mock_routing,
                                   &routing_receiver,
                                   appendable_data_nae_mgr.clone(),
                                   append_wrapper);

            match result {
                Ok(_) => panic!("Expected APPEND failure"),
                Err(CoreError::MutationFailure { reason: MutationError::InvalidSuccessor, .. }) => {
                    ()
                }
                Err(error) => panic!("Unexpected {:?}", error),
            }
        }

        // TODO: test also whitelist

        // PUT with data already appended.
        let appendable_data_name = rand::random();
        let appendable_data_nae_mgr = Authority::NaeManager(appendable_data_name);

        let mut appendable_data = unwrap!(PubAppendableData::new(appendable_data_name,
                                                                 0,
                                                                 vec![owner_key],
                                                                 vec![],
                                                                 Default::default(),
                                                                 Filter::black_list(iter::empty()),
                                                                 Some(&signing_key)));

        let appendable_data_id = appendable_data.identifier();

        let appended_data = unwrap!(AppendedData::new(immut_data_0.identifier(),
                                                      owner_key,
                                                      &signing_key));
        assert!(appendable_data.append(appended_data));

        unwrap!(do_put(&mut mock_routing,
                       &routing_receiver,
                       appendable_data_nae_mgr.clone(),
                       Data::PubAppendable(appendable_data)));

        // GET it back and verify the appended data is there.
        let appendable_data = unwrap!(do_get(&mut mock_routing,
                                             &routing_receiver,
                                             appendable_data_nae_mgr.clone(),
                                             appendable_data_id));

        let appendable_data = match appendable_data {
            Data::PubAppendable(data) => data,
            _ => panic!("Unexpected data type"),
        };

        assert_eq!(appendable_data.data.len(), 1);

        let appended_data = unwrap!(appendable_data.data.iter().next());
        assert_eq!(appended_data.pointer, immut_data_0.identifier());

        // TODO: test POST with appended data too
        // TODO: test simultaneous POSTs with different appended data - verify
        // the appendable data contains data items from both POSTs afterwards.
    }

    fn create_account_and_full_id() -> (Account, FullId) {
        let account = Account::new();
        let id = FullId::with_keys((account.get_maid().public_keys().1,
                                    account.get_maid().secret_keys().1.clone()),
                                   (account.get_maid().public_keys().0,
                                    account.get_maid().secret_keys().0.clone()));

        (account, id)
    }

    fn generate_random_immutable_data() -> ImmutableData {
        let data = unwrap!(utility::generate_random_vector(100));
        ImmutableData::new(data)
    }


    // Wait until connection is established.
    fn wait_for_connection(routing_rx: &Receiver<Event>) {
        match unwrap!(routing_rx.recv()) {
            Event::Connected => (),
            _ => panic!("Could not Connect !!"),
        }
    }

    // Do a GET request and wait for the response.
    fn do_get(routing: &mut MockRouting,
              routing_rx: &Receiver<Event>,
              dst: Authority,
              data_id: DataIdentifier)
              -> Result<Data, CoreError> {
        let message_id = MessageId::new();
        unwrap!(routing.send_get_request(dst, data_id, message_id));

        match unwrap!(routing_rx.recv()) {
            Event::Response { response: Response::GetSuccess(data, id), .. } => {
                assert_eq!(id, message_id);
                Ok(data)
            }
            Event::Response { response: Response::GetFailure { id,
                                                     data_id,
                                                     external_error_indicator },
                              .. } => {
                assert_eq!(id, message_id);
                let reason = unwrap!(deserialise(&external_error_indicator));

                Err(CoreError::GetFailure {
                    data_id: data_id,
                    reason: reason,
                })
            }
            event => panic!("Unexpected routing event: {:?}", event),
        }
    }

    // Do a PUT request and wait for the response.
    fn do_put(routing: &mut MockRouting,
              routing_rx: &Receiver<Event>,
              dst: Authority,
              data: Data)
              -> Result<(), CoreError> {
        let message_id = MessageId::new();
        unwrap!(routing.send_put_request(dst, data, message_id));

        match unwrap!(routing_rx.recv()) {
            Event::Response { response: Response::PutSuccess(_, id), .. } => {
                assert_eq!(id, message_id);
                Ok(())
            }
            Event::Response { response: Response::PutFailure { id,
                                                     data_id,
                                                     external_error_indicator },
                              .. } => {
                assert_eq!(id, message_id);
                let reason = unwrap!(deserialise(&external_error_indicator));

                Err(CoreError::MutationFailure {
                    data_id: data_id,
                    reason: reason,
                })
            }
            event => panic!("Unexpected routing event: {:?}", event),
        }
    }

    // Do a POST request and wait for the response.
    fn do_post(routing: &mut MockRouting,
               routing_rx: &Receiver<Event>,
               dst: Authority,
               data: Data)
               -> Result<(), CoreError> {
        let message_id = MessageId::new();
        unwrap!(routing.send_post_request(dst, data, message_id));

        match unwrap!(routing_rx.recv()) {
            Event::Response { response: Response::PostSuccess(_, id), .. } => {
                assert_eq!(id, message_id);
                Ok(())
            }
            Event::Response { response: Response::PostFailure { id,
                                                      data_id,
                                                      external_error_indicator },
                              .. } => {
                assert_eq!(id, message_id);
                let reason = unwrap!(deserialise(&external_error_indicator));

                Err(CoreError::MutationFailure {
                    data_id: data_id,
                    reason: reason,
                })
            }
            event => panic!("Unexpected routing event: {:?}", event),
        }
    }

    // Do a DELETE request and wait for the response.
    fn do_delete(routing: &mut MockRouting,
                 routing_rx: &Receiver<Event>,
                 dst: Authority,
                 data: Data)
                 -> Result<(), CoreError> {
        let message_id = MessageId::new();
        unwrap!(routing.send_delete_request(dst, data, message_id));

        match unwrap!(routing_rx.recv()) {
            Event::Response { response: Response::DeleteSuccess(_, id), .. } => {
                assert_eq!(id, message_id);
                Ok(())
            }
            Event::Response { response: Response::DeleteFailure { id,
                                                        data_id,
                                                        external_error_indicator },
                              .. } => {
                assert_eq!(id, message_id);
                let reason = unwrap!(deserialise(&external_error_indicator));

                Err(CoreError::MutationFailure {
                    data_id: data_id,
                    reason: reason,
                })
            }
            event => panic!("Unexpected routing event: {:?}", event),
        }
    }

    // Do an APPEND request and wait for the response.
    fn do_append(routing: &mut MockRouting,
                 routing_rx: &Receiver<Event>,
                 dst: Authority,
                 append_wrapper: AppendWrapper)
                 -> Result<(), CoreError> {
        let message_id = MessageId::new();
        unwrap!(routing.send_append_request(dst, append_wrapper, message_id));

        match unwrap!(routing_rx.recv()) {
            Event::Response { response: Response::AppendSuccess(_, id), .. } => {
                assert_eq!(id, message_id);
                Ok(())
            }
            Event::Response { response: Response::AppendFailure { id,
                                                        data_id,
                                                        external_error_indicator },
                              .. } => {
                assert_eq!(id, message_id);
                let reason = unwrap!(deserialise(&external_error_indicator));

                Err(CoreError::MutationFailure {
                    data_id: data_id,
                    reason: reason,
                })
            }
            event => panic!("Unexpected routing event: {:?}", event),
        }
    }

    // Do a GetAccountInfo request and wait for the response.
    fn do_get_account_info(routing: &mut MockRouting,
                           routing_rx: &Receiver<Event>,
                           dst: Authority)
                           -> Result<(u64, u64), CoreError> {
        let message_id = MessageId::new();
        unwrap!(routing.send_get_account_info_request(dst, message_id));

        match unwrap!(routing_rx.recv()) {
            Event::Response { response: Response::GetAccountInfoSuccess { id,
                                                                data_stored,
                                                                space_available },
                              .. } => {
                assert_eq!(id, message_id);
                Ok((data_stored, space_available))
            }
            Event::Response {
                response: Response::GetAccountInfoFailure { id, external_error_indicator }, ..
            } => {
                assert_eq!(id, message_id);
                let reason = unwrap!(deserialise(&external_error_indicator));

                Err(CoreError::GetAccountInfoFailure { reason: reason })
            }
            event => panic!("Unexpected routing event: {:?}", event),
        }
    }
}
