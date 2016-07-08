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

#![cfg_attr(feature="clippy", allow(map_entry))]  // TODO: Look to enable this lint check.

use std;
use std::cell::Cell;
use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::io::{Read, Write};
use std::mem;
use std::sync::{Arc, Mutex, ONCE_INIT, Once, mpsc};
use std::time::Duration;

use bincode::SizeLimit;
use maidsafe_utilities::thread;
use maidsafe_utilities::serialisation::{deserialise, deserialise_with_limit, serialise,
                                        serialise_with_limit};
use rand;
use routing::{Authority, Data, DataIdentifier, Event, FullId, InterfaceError, MessageId, Request,
              Response, RoutingError, XorName};
use safe_network_common::TYPE_TAG_SESSION_PACKET;
use safe_network_common::client_errors::{GetError, MutationError};
use sodiumoxide::crypto::sign;
use sodiumoxide::crypto::hash::sha256;

const STORAGE_FILE_NAME: &'static str = "VaultStorageSimulation";
const NETWORK_CONNECT_DELAY_SIMULATION_THREAD: &'static str = "NetworkConnectDelaySimulation";

// Activating these (ie., non-zero values) will require an update to all test cases. Once activated
// the GET's should only be performed once success from PUT's/POST's/DELETE's have been obtained.
//
// These will allow to code properly for behavioural anomalies like GETs reaching the address faster
// than PUTs. So a proper delay will help code better logic against scenarios where it is required
// to do a GET after a PUT/DELETE to confirm that action. So for example if a GET done immediately
// after a PUT failed, it could mean that the PUT either failed or hasn't reached the address yet.
const SIMULATED_NETWORK_DELAY_GETS_POSTS_MS: u64 = 0;
const SIMULATED_NETWORK_DELAY_PUTS_DELETS_MS: u64 = 2 * SIMULATED_NETWORK_DELAY_GETS_POSTS_MS;

// This should ideally be replaced with `safe_vault::maid_manager::DEFAULT_ACCOUNT_SIZE`, but that's
// not exported by Vault currently.
const DEFAULT_CLIENT_ACCOUNT_SIZE: u64 = 100;

#[derive(RustcEncodable, RustcDecodable)]
pub struct ClientAccount {
    data_stored: u64,
    space_available: u64,
}

impl Default for ClientAccount {
    fn default() -> ClientAccount {
        ClientAccount {
            data_stored: 0,
            space_available: DEFAULT_CLIENT_ACCOUNT_SIZE,
        }
    }
}

#[derive(RustcEncodable, RustcDecodable)]
struct PersistentStorageSimulation {
    data_store: HashMap<XorName, Vec<u8>>,
    client_accounts: HashMap<XorName, ClientAccount>,
}

#[allow(unsafe_code)]
fn get_storage() -> Arc<Mutex<PersistentStorageSimulation>> {
    static mut STORAGE: *const Arc<Mutex<PersistentStorageSimulation>> =
        0 as *const Arc<Mutex<PersistentStorageSimulation>>;
    static mut ONCE: Once = ONCE_INIT;

    unsafe {
        ONCE.call_once(|| {
            let mut memory_storage = PersistentStorageSimulation {
                data_store: HashMap::new(),
                client_accounts: HashMap::new(),
            };

            let mut temp_dir_pathbuf = env::temp_dir();
            temp_dir_pathbuf.push(STORAGE_FILE_NAME);

            if let Ok(mut file) = File::open(temp_dir_pathbuf) {
                let mut raw_disk_data = Vec::with_capacity(unwrap!(file.metadata()).len() as usize);
                if let Ok(_) = file.read_to_end(&mut raw_disk_data) {
                    if !raw_disk_data.is_empty() {
                        if let Ok(parsed) = deserialise_with_limit(&raw_disk_data,
                                                                   SizeLimit::Infinite) {
                            memory_storage = parsed;
                        }
                    }
                }
            }

            STORAGE = mem::transmute(Box::new(Arc::new(Mutex::new(memory_storage))));
        });

        (*STORAGE).clone()
    }
}

fn sync_disk_storage(memory_storage: &PersistentStorageSimulation) {
    let mut temp_dir_pathbuf = env::temp_dir();
    temp_dir_pathbuf.push(STORAGE_FILE_NAME);

    let mut file = unwrap!(File::create(temp_dir_pathbuf));
    let _ = file.write_all(&unwrap!(serialise_with_limit(&memory_storage, SizeLimit::Infinite)));
    unwrap!(file.sync_all());
}

pub struct RoutingMock {
    sender: mpsc::Sender<Event>,
    client_auth: Authority,
    max_ops_countdown: Option<Cell<u64>>,
}

impl RoutingMock {
    pub fn new(sender: mpsc::Sender<Event>,
               _id: Option<FullId>)
               -> Result<RoutingMock, RoutingError> {
        ::sodiumoxide::init();

        let cloned_sender = sender.clone();
        let _ = thread::named(NETWORK_CONNECT_DELAY_SIMULATION_THREAD, move || {
            std::thread::sleep(Duration::from_millis(SIMULATED_NETWORK_DELAY_PUTS_DELETS_MS));
            let _ = cloned_sender.send(Event::Connected);
        });

        let client_auth = Authority::Client {
            client_key: sign::gen_keypair().0,
            peer_id: rand::random(),
            proxy_node_name: rand::random(),
        };
        Ok(RoutingMock {
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
        let storage = get_storage();
        let cloned_sender = self.sender.clone();
        let client_auth = self.client_auth.clone();

        let err = if self.max_ops_countdown.as_ref().map_or(false, |count| count.get() == 0) {
            info!("Mock GET: {:?} {:?} [0]", data_id, msg_id);
            Some(GetError::NetworkOther("Max operations exhausted".to_string()))
        } else {
            None
        };

        if err == None {
            if let Some(ref count) = self.max_ops_countdown {
                let ops = count.get();
                info!("Mock GET: {:?} {:?} [{}]", data_id, msg_id, ops);
                count.set(ops - 1);
            }
        }

        let _ = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(SIMULATED_NETWORK_DELAY_GETS_POSTS_MS));
            let data_name = data_id.name();
            let nae_auth = Authority::NaeManager(data_name);
            let request = Request::Get(data_id, msg_id);

            if let Some(reason) = err {
                let ext_err = match serialise(&reason) {
                    Ok(serialised_err) => serialised_err,
                    Err(err) => {
                        warn!("Could not serialise client-vault error - {:?}", err);
                        Vec::new()
                    }
                };
                let event =
                    RoutingMock::construct_failure_resp(nae_auth, client_auth, request, ext_err);
                if let Err(error) = cloned_sender.send(event) {
                    error!("Get-Response mpsc-send failure: {:?}", error);
                }
                return;
            }

            match unwrap!(storage.lock()).data_store.get(&data_name) {
                Some(raw_data) => {
                    if let Ok(data) = deserialise::<Data>(raw_data) {
                        if match (&data, &data_id) {
                            (&Data::Immutable(_), &DataIdentifier::Immutable(_)) => true,
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

                            if let Err(error) = cloned_sender.send(event) {
                                error!("Get-Response mpsc-send failure: {:?}", error);
                            }
                        } else {
                            let ext_err = match serialise(&GetError::NoSuchData) {
                                Ok(serialised_err) => serialised_err,
                                Err(err) => {
                                    warn!("Could not serialise client-vault error - {:?}", err);
                                    Vec::new()
                                }
                            };
                            let event = RoutingMock::construct_failure_resp(nae_auth,
                                                                            client_auth,
                                                                            request,
                                                                            ext_err);
                            if let Err(error) = cloned_sender.send(event) {
                                error!("Get-Response mpsc-send failure: {:?}", error);
                            }
                        }
                    }
                }
                None => {
                    let ext_err = match serialise(&GetError::NoSuchData) {
                        Ok(serialised_err) => serialised_err,
                        Err(err) => {
                            warn!("Could not serialise client-vault error - {:?}", err);
                            Vec::new()
                        }
                    };
                    let event = RoutingMock::construct_failure_resp(nae_auth,
                                                                    client_auth,
                                                                    request,
                                                                    ext_err);
                    if let Err(error) = cloned_sender.send(event) {
                        error!("Get-Response mpsc-send failure: {:?}", error);
                    }
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
        let storage = get_storage();
        let cloned_sender = self.sender.clone();
        let client_auth = self.client_auth.clone();

        let data_name = data.name();
        let data_id = data.identifier();
        // NaeManager is used as the destination authority here because in the Mock we assume that
        // MaidManagers always pass the PUT. Errors if any can come only from NaeManagers
        let nae_auth = Authority::NaeManager(data_name);
        let request = Request::Put(data.clone(), msg_id);

        let mut storage_mutex_guard = unwrap!(storage.lock());
        let err = if self.max_ops_countdown.as_ref().map_or(false, |count| count.get() == 0) {
            info!("Mock PUT: {:?} {:?} [0]", data_id, msg_id);
            Some(MutationError::NetworkOther("Max operations exhausted".to_string()))
        } else if storage_mutex_guard.data_store.contains_key(&data_name) {
            match data {
                Data::Immutable(_) => {
                    match deserialise(unwrap!(storage_mutex_guard.data_store.get(&data_name))) {
                        // Immutable data is de-duplicated so always allowed
                        Ok(Data::Immutable(_)) => None,
                        Ok(_) => Some(MutationError::DataExists),
                        Err(error) => Some(MutationError::NetworkOther(format!("{}", error))),
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
        } else if let Ok(raw_data) = serialise(&data) {
            let _ = storage_mutex_guard.data_store.insert(data_name, raw_data);
            None
        } else {
            Some(MutationError::NetworkOther("Serialisation error".to_owned()))
        };

        if err == None {
            if let Some(ref count) = self.max_ops_countdown {
                let ops = count.get();
                info!("Mock PUT: {:?} {:?} [{}]", data_id, msg_id, ops);
                count.set(ops - 1);
            }
            {
                let account = storage_mutex_guard.client_accounts
                    .entry(self.client_name())
                    .or_insert_with(ClientAccount::default);
                account.data_stored += 1;
                account.space_available -= 1;
            }
            sync_disk_storage(&*storage_mutex_guard);
        }

        let _ = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(SIMULATED_NETWORK_DELAY_PUTS_DELETS_MS));
            if let Some(reason) = err {
                let ext_err = match serialise(&reason) {
                    Ok(serialised_err) => serialised_err,
                    Err(err) => {
                        warn!("Could not serialise client-vault error - {:?}", err);
                        Vec::new()
                    }
                };
                let event =
                    RoutingMock::construct_failure_resp(nae_auth, client_auth, request, ext_err);
                if let Err(error) = cloned_sender.send(event) {
                    error!("Put-Response mpsc-send failure: {:?}", error);
                }
            } else {
                let event = Event::Response {
                    src: nae_auth,
                    dst: client_auth,
                    response: Response::PutSuccess(data_id, msg_id),
                };

                if let Err(error) = cloned_sender.send(event) {
                    error!("Put-Response mpsc-send failure: {:?}", error);
                }
            }
        });

        Ok(())
    }

    pub fn send_post_request(&self,
                             _dst: Authority,
                             data: Data,
                             msg_id: MessageId)
                             -> Result<(), InterfaceError> {
        let storage = get_storage();
        let cloned_sender = self.sender.clone();
        let client_auth = self.client_auth.clone();

        let data_name = data.name();
        let data_id = data.identifier();
        let nae_auth = Authority::NaeManager(data_name);
        let request = Request::Post(data.clone(), msg_id);

        let mut storage_mutex_guard = unwrap!(storage.lock());
        let err = if storage_mutex_guard.data_store.contains_key(&data_name) {
            if self.max_ops_countdown.as_ref().map_or(false, |count| count.get() == 0) {
                info!("Mock POST: {:?} {:?} [0]", data_id, msg_id);
                Some(MutationError::NetworkOther("Max operations exhausted".to_string()))
            } else if let Data::Structured(ref sd_new) = data {
                match (serialise(&data),
                       deserialise(unwrap!(storage_mutex_guard.data_store.get(&data_name)))) {
                    (Ok(raw_data), Ok(Data::Structured(sd_stored))) => {
                        if let Ok(_) = sd_stored.validate_self_against_successor(sd_new) {
                            let _ = storage_mutex_guard.data_store.insert(data_name, raw_data);
                            sync_disk_storage(&*storage_mutex_guard);
                            None
                        } else {
                            Some(MutationError::InvalidSuccessor)
                        }
                    }
                    _ => Some(MutationError::NetworkOther("Serialisation error".to_owned())),
                }
            } else {
                Some(MutationError::InvalidOperation)
            }
        } else {
            Some(MutationError::NoSuchData)
        };

        if err == None {
            if let Some(ref count) = self.max_ops_countdown {
                let ops = count.get();
                info!("Mock POST: {:?} {:?} [{}]", data_id, msg_id, ops);
                count.set(ops - 1);
            }
        }

        let _ = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(SIMULATED_NETWORK_DELAY_PUTS_DELETS_MS));
            if let Some(reason) = err {
                let ext_err = match serialise(&reason) {
                    Ok(serialised_err) => serialised_err,
                    Err(err) => {
                        warn!("Could not serialise client-vault error - {:?}", err);
                        Vec::new()
                    }
                };
                let event =
                    RoutingMock::construct_failure_resp(nae_auth, client_auth, request, ext_err);
                if let Err(error) = cloned_sender.send(event) {
                    error!("Post-Response mpsc-send failure: {:?}", error);
                }
            } else {
                let event = Event::Response {
                    src: nae_auth,
                    dst: client_auth,
                    response: Response::PostSuccess(data_id, msg_id),
                };

                if let Err(error) = cloned_sender.send(event) {
                    error!("Post-Response mpsc-send failure: {:?}", error);
                }
            }
        });

        Ok(())
    }

    pub fn send_delete_request(&self,
                               _dst: Authority,
                               data: Data,
                               msg_id: MessageId)
                               -> Result<(), InterfaceError> {
        let storage = get_storage();
        let cloned_sender = self.sender.clone();
        let client_auth = self.client_auth.clone();

        let data_name = data.name();
        let data_id = data.identifier();
        let nae_auth = Authority::NaeManager(data_name);
        let request = Request::Delete(data.clone(), msg_id);

        let mut storage_mutex_guard = unwrap!(storage.lock());
        let err = if self.max_ops_countdown.as_ref().map_or(false, |count| count.get() == 0) {
            info!("Mock DELETE: {:?} {:?} [0]", data_id, msg_id);
            Some(MutationError::NetworkOther("Max operations exhausted".to_string()))
        } else if storage_mutex_guard.data_store.contains_key(&data_name) {
            if let Data::Structured(ref sd_new) = data {
                match (serialise(&data),
                       deserialise(unwrap!(storage_mutex_guard.data_store.get(&data_name)))) {
                    (Ok(_), Ok(Data::Structured(sd_stored))) => {
                        if let Ok(_) = sd_stored.validate_self_against_successor(sd_new) {
                            let _ = storage_mutex_guard.data_store.remove(&data_name);
                            sync_disk_storage(&*storage_mutex_guard);
                            None
                        } else {
                            Some(MutationError::InvalidSuccessor)
                        }
                    }
                    _ => Some(MutationError::NetworkOther("Serialisation error".to_owned())),
                }
            } else {
                Some(MutationError::InvalidOperation)
            }
        } else {
            Some(MutationError::NoSuchData)
        };

        if err == None {
            if let Some(ref count) = self.max_ops_countdown {
                let ops = count.get();
                info!("Mock DELETE: {:?} {:?} [{}]", data_id, msg_id, ops);
                count.set(ops - 1);
                count.set(count.get() - 1);
            }
        }

        let _ = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(SIMULATED_NETWORK_DELAY_PUTS_DELETS_MS));
            if let Some(reason) = err {
                let ext_err = match serialise(&reason) {
                    Ok(serialised_err) => serialised_err,
                    Err(err) => {
                        warn!("Could not serialise client-vault error - {:?}", err);
                        Vec::new()
                    }
                };
                let event =
                    RoutingMock::construct_failure_resp(nae_auth, client_auth, request, ext_err);
                if let Err(error) = cloned_sender.send(event) {
                    error!("Delete-Response mpsc-send failure: {:?}", error);
                }
            } else {
                let event = Event::Response {
                    src: nae_auth,
                    dst: client_auth,
                    response: Response::DeleteSuccess(data_id, msg_id),
                };

                if let Err(error) = cloned_sender.send(event) {
                    error!("Delete-Response mpsc-send failure: {:?}", error);
                }
            }
        });

        Ok(())
    }

    pub fn send_get_account_info_request(&mut self,
                                         dst: Authority,
                                         msg_id: MessageId)
                                         -> Result<(), InterfaceError> {
        let storage = get_storage();
        let cloned_sender = self.sender.clone();
        let client_auth = self.client_auth.clone();
        let client_name = self.client_name();

        let err = if self.max_ops_countdown.as_ref().map_or(false, |count| count.get() == 0) {
            info!("Mock GetAccountInfo: {:?} {:?} [0]", client_name, msg_id);
            Some(GetError::NetworkOther("Max operations exhausted".to_string()))
        } else {
            None
        };

        if err == None {
            if let Some(ref count) = self.max_ops_countdown {
                let ops = count.get();
                info!("Mock GetAccountInfo: {:?} {:?} [{}]",
                      client_name,
                      msg_id,
                      ops);
                count.set(ops - 1);
            }
        }

        let _ = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(SIMULATED_NETWORK_DELAY_GETS_POSTS_MS));
            let request = Request::GetAccountInfo(msg_id);

            if let Some(reason) = err {
                let ext_err = match serialise(&reason) {
                    Ok(serialised_err) => serialised_err,
                    Err(err) => {
                        warn!("Could not serialise client-vault error - {:?}", err);
                        Vec::new()
                    }
                };
                let event = RoutingMock::construct_failure_resp(dst, client_auth, request, ext_err);
                if let Err(error) = cloned_sender.send(event) {
                    error!("GetAccountInfo-Response mpsc-send failure: {:?}", error);
                }
                return;
            }

            match unwrap!(storage.lock()).client_accounts.get(&client_name) {
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
                    if let Err(error) = cloned_sender.send(event) {
                        error!("GetAccountInfo-Response mpsc-send failure: {:?}", error);
                    }
                }
                None => {
                    let ext_err = match serialise(&GetError::NoSuchAccount) {
                        Ok(serialised_err) => serialised_err,
                        Err(err) => {
                            warn!("Could not serialise client-vault error - {:?}", err);
                            Vec::new()
                        }
                    };
                    let event =
                        RoutingMock::construct_failure_resp(dst, client_auth, request, ext_err);
                    if let Err(error) = cloned_sender.send(event) {
                        error!("GetAccountInfo-Response mpsc-send failure: {:?}", error);
                    }
                }
            };
        });

        Ok(())
    }

    fn construct_failure_resp(src: Authority,
                              dst: Authority,
                              request: Request,
                              ext_err: Vec<u8>)
                              -> Event {
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
            _ => {
                unreachable!("Cannot handle {:?} in this function. Report as bug",
                             request)
            }
        };

        Event::Response {
            src: src,
            dst: dst,
            response: response,
        }
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
}

#[cfg(test)]
mod test {
    use super::*;
    use super::DEFAULT_CLIENT_ACCOUNT_SIZE;
    use std::sync::mpsc;
    use std::collections::HashMap;

    use core::utility;
    use core::errors::CoreError;
    use core::client::user_account::Account;
    use core::translated_events::NetworkEvent;
    use core::client::message_queue::MessageQueue;
    use core::client::response_getter::{GetAccountInfoResponseGetter, GetResponseGetter,
                                        MutationResponseGetter};

    use maidsafe_utilities::serialisation::{deserialise, serialise};
    use safe_network_common::client_errors::{GetError, MutationError};
    use routing::{Authority, Data, DataIdentifier, FullId, ImmutableData, MessageId,
                  StructuredData, XOR_NAME_LEN, XorName};

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
        let account_packet = Account::new(None, None);

        let id_packet = FullId::with_keys((account_packet.get_maid().public_keys().1,
                                           account_packet.get_maid().secret_keys().1.clone()),
                                          (account_packet.get_maid().public_keys().0,
                                           account_packet.get_maid().secret_keys().0.clone()));

        let (routing_sender, routing_receiver) = mpsc::channel();
        let (network_event_sender, network_event_receiver) = mpsc::channel();

        let (message_queue, _raii_joiner) = MessageQueue::new(routing_receiver,
                                                              vec![network_event_sender]);
        let mut mock_routing = unwrap!(RoutingMock::new(routing_sender, Some(id_packet)));

        match unwrap!(network_event_receiver.recv()) {
            NetworkEvent::Connected => (),
            _ => panic!("Could not Connect !!"),
        }

        // Construct ImmutableData
        let orig_raw_data: Vec<u8> = unwrap!(utility::generate_random_vector(100));
        let orig_immutable_data = ImmutableData::new(orig_raw_data.clone());
        let orig_data = Data::Immutable(orig_immutable_data);

        let location_nae_mgr = Authority::NaeManager(orig_data.name());
        let location_client_mgr = Authority::ClientManager(orig_data.name());

        // GET ImmutableData should fail
        {
            let data_id = DataIdentifier::Immutable(orig_data.name());

            let (tx, rx) = mpsc::channel();
            let msg_id = MessageId::new();

            unwrap!(message_queue.lock()).register_response_observer(msg_id, tx.clone());

            unwrap!(mock_routing.send_get_request(location_nae_mgr.clone(), data_id, msg_id));

            let resp_getter =
                GetResponseGetter::new(Some((tx, rx)), message_queue.clone(), data_id);

            match resp_getter.get() {
                Ok(_) => panic!("Expected Get Failure!"),
                Err(CoreError::GetFailure { reason: GetError::NoSuchData, .. }) => (),
                Err(err) => panic!("Unexpected: {:?}", err),
            }
        }

        // First PUT should succeed
        {
            let (tx, rx) = mpsc::channel();
            let msg_id = MessageId::new();

            unwrap!(message_queue.lock()).register_response_observer(msg_id, tx.clone());
            unwrap!(mock_routing.send_put_request(location_client_mgr.clone(),
                                                         orig_data.clone(),
                                                         msg_id));
            let resp_getter = MutationResponseGetter::new((tx, rx));

            unwrap!(resp_getter.get());
        }

        // GET ImmutableData should pass
        {
            let data_id = DataIdentifier::Immutable(orig_data.name());

            let (tx, rx) = mpsc::channel();
            let msg_id = MessageId::new();

            unwrap!(message_queue.lock()).register_response_observer(msg_id, tx.clone());

            unwrap!(mock_routing.send_get_request(location_nae_mgr.clone(), data_id, msg_id));

            let resp_getter =
                GetResponseGetter::new(Some((tx, rx)), message_queue.clone(), data_id);

            assert_eq!(unwrap!(resp_getter.get()), orig_data);
        }

        // GetAccountInfo should pass and show one chunk stored
        {
            let (tx, rx) = mpsc::channel();
            let msg_id = MessageId::new();

            unwrap!(message_queue.lock()).register_response_observer(msg_id, tx.clone());

            unwrap!(mock_routing.send_get_account_info_request(location_client_mgr.clone(),
                                                               msg_id));

            let resp_getter = GetAccountInfoResponseGetter::new((tx, rx));

            assert_eq!(unwrap!(resp_getter.get()),
                       (1, DEFAULT_CLIENT_ACCOUNT_SIZE - 1));
        }

        // Subsequent PUTs for same ImmutableData should succeed - De-duplication
        {
            let (tx, rx) = mpsc::channel();
            let msg_id = MessageId::new();

            unwrap!(message_queue.lock()).register_response_observer(msg_id, tx.clone());
            unwrap!(mock_routing.send_put_request(location_client_mgr.clone(),
                                                         orig_data.clone(),
                                                         msg_id));
            let resp_getter = MutationResponseGetter::new((tx, rx));

            unwrap!(resp_getter.get());
        }

        // POSTs for ImmutableData should fail
        {
            let (tx, rx) = mpsc::channel();
            let msg_id = MessageId::new();

            unwrap!(message_queue.lock()).register_response_observer(msg_id, tx.clone());
            unwrap!(mock_routing.send_post_request(location_nae_mgr.clone(),
                                                          orig_data.clone(),
                                                          msg_id));
            let resp_getter = MutationResponseGetter::new((tx, rx));

            match resp_getter.get() {
                Ok(_) => panic!("Expected Post Failure!"),
                Err(CoreError::MutationFailure { reason: MutationError::InvalidOperation, .. }) => {
                    ()
                }
                Err(err) => panic!("Unexpected: {:?}", err),
            }
        }

        // DELETEs of ImmutableData should fail
        {
            let (tx, rx) = mpsc::channel();
            let msg_id = MessageId::new();

            unwrap!(message_queue.lock()).register_response_observer(msg_id, tx.clone());
            unwrap!(mock_routing.send_delete_request(location_client_mgr.clone(),
                                                     orig_data.clone(),
                                                     msg_id));
            let resp_getter = MutationResponseGetter::new((tx, rx));

            match resp_getter.get() {
                Ok(_) => panic!("Expected Delete Failure!"),
                Err(CoreError::MutationFailure { reason: MutationError::InvalidOperation, .. }) => {
                    ()
                }
                Err(err) => panic!("Unexpected: {:?}", err),
            }
        }

        // GET ImmutableData should pass
        {
            let data_id = DataIdentifier::Immutable(orig_data.name());

            let (tx, rx) = mpsc::channel();
            let msg_id = MessageId::new();

            unwrap!(message_queue.lock()).register_response_observer(msg_id, tx.clone());

            unwrap!(mock_routing.send_get_request(location_nae_mgr, data_id, msg_id));

            let resp_getter =
                GetResponseGetter::new(Some((tx, rx)), message_queue.clone(), data_id);

            assert_eq!(unwrap!(resp_getter.get()), orig_data);
        }

        // GetAccountInfo should pass and show two chunks stored
        {
            let (tx, rx) = mpsc::channel();
            let msg_id = MessageId::new();

            unwrap!(message_queue.lock()).register_response_observer(msg_id, tx.clone());

            unwrap!(mock_routing.send_get_account_info_request(location_client_mgr, msg_id));

            let resp_getter = GetAccountInfoResponseGetter::new((tx, rx));

            assert_eq!(unwrap!(resp_getter.get()),
                       (2, DEFAULT_CLIENT_ACCOUNT_SIZE - 2));
        }
    }

    #[test]
    fn check_put_post_get_delete_for_structured_data() {
        let account_packet = Account::new(None, None);

        let id_packet = FullId::with_keys((account_packet.get_maid().public_keys().1,
                                           account_packet.get_maid().secret_keys().1.clone()),
                                          (account_packet.get_maid().public_keys().0,
                                           account_packet.get_maid().secret_keys().0.clone()));

        let (routing_sender, routing_receiver) = mpsc::channel();
        let (network_event_sender, network_event_receiver) = mpsc::channel();

        let (message_queue, _raii_joiner) = MessageQueue::new(routing_receiver,
                                                              vec![network_event_sender]);
        let mut mock_routing = unwrap!(RoutingMock::new(routing_sender, Some(id_packet)));

        match unwrap!(network_event_receiver.recv()) {
            NetworkEvent::Connected => (),
            _ => panic!("Could not Bootstrap !!"),
        }

        // Construct ImmutableData
        let orig_raw_data: Vec<u8> = unwrap!(utility::generate_random_vector(100));
        let orig_immutable_data = ImmutableData::new(orig_raw_data);
        let orig_data_immutable = Data::Immutable(orig_immutable_data);

        const TYPE_TAG: u64 = 999;

        // Construct StructuredData, 1st version, for this ImmutableData
        let keyword = unwrap!(utility::generate_random_string(10));
        let pin = unwrap!(utility::generate_random_string(10));
        let user_id = unwrap!(Account::generate_network_id(keyword.as_bytes(),
                                                           pin.to_string().as_bytes()));
        let account_ver_res =
            StructuredData::new(TYPE_TAG,
                                user_id,
                                0,
                                unwrap!(serialise(&vec![orig_data_immutable.name()])),
                                vec![account_packet.get_public_maid().public_keys().0.clone()],
                                Vec::new(),
                                Some(&account_packet.get_maid().secret_keys().0));
        let mut account_version = unwrap!(account_ver_res);
        let mut data_account_version = Data::Structured(account_version);


        let location_nae_mgr_immut = Authority::NaeManager(orig_data_immutable.name());
        let location_nae_mgr_struct = Authority::NaeManager(data_account_version.name());

        let location_client_mgr_immut = Authority::ClientManager(orig_data_immutable.name());
        let location_client_mgr_struct = Authority::ClientManager(data_account_version.name());

        // First PUT of StructuredData should succeed
        {
            let (tx, rx) = mpsc::channel();
            let msg_id = MessageId::new();

            unwrap!(message_queue.lock()).register_response_observer(msg_id, tx.clone());
            unwrap!(mock_routing.send_put_request(location_client_mgr_struct.clone(),
                                                  data_account_version.clone(),
                                                  msg_id));
            let resp_getter = MutationResponseGetter::new((tx, rx));

            unwrap!(resp_getter.get());
        }

        // PUT for ImmutableData should succeed
        {
            let (tx, rx) = mpsc::channel();
            let msg_id = MessageId::new();

            unwrap!(message_queue.lock()).register_response_observer(msg_id, tx.clone());
            unwrap!(mock_routing.send_put_request(location_client_mgr_immut.clone(),
                                                  orig_data_immutable.clone(),
                                                  msg_id));
            let resp_getter = MutationResponseGetter::new((tx, rx));

            unwrap!(resp_getter.get());
        }

        let mut received_structured_data: StructuredData;

        // GET StructuredData should pass
        {
            let struct_data_id = DataIdentifier::Structured(user_id, TYPE_TAG);

            let (tx, rx) = mpsc::channel();
            let msg_id = MessageId::new();

            unwrap!(message_queue.lock()).register_response_observer(msg_id, tx.clone());

            unwrap!(mock_routing.send_get_request(location_nae_mgr_struct.clone(),
                                                  struct_data_id,
                                                  msg_id));

            let resp_getter =
                GetResponseGetter::new(Some((tx, rx)), message_queue.clone(), struct_data_id);

            let data = unwrap!(resp_getter.get());
            assert_eq!(data, data_account_version);
            match data {
                Data::Structured(struct_data) => received_structured_data = struct_data,
                _ => unreachable!("Unexpected! {:?}", data),
            }
        }

        // GetAccountInfo should pass and show two chunks stored
        {
            let (tx, rx) = mpsc::channel();
            let msg_id = MessageId::new();

            unwrap!(message_queue.lock()).register_response_observer(msg_id, tx.clone());

            unwrap!(mock_routing.send_get_account_info_request(location_client_mgr_immut.clone(),
                                                               msg_id));

            let resp_getter = GetAccountInfoResponseGetter::new((tx, rx));

            assert_eq!(unwrap!(resp_getter.get()),
                       (2, DEFAULT_CLIENT_ACCOUNT_SIZE - 2));
        }

        // GET ImmutableData from latest version of StructuredData should pass
        {
            let mut location_vec =
                unwrap!(deserialise::<Vec<XorName>>(received_structured_data.get_data()));
            let immut_data_id = DataIdentifier::Immutable(unwrap!(location_vec.pop(),
                                                                  "Value must exist !"));

            let (tx, rx) = mpsc::channel();
            let msg_id = MessageId::new();

            unwrap!(message_queue.lock()).register_response_observer(msg_id, tx.clone());

            unwrap!(mock_routing.send_get_request(location_nae_mgr_immut.clone(),
                                                  immut_data_id,
                                                  msg_id));

            let resp_getter =
                GetResponseGetter::new(Some((tx, rx)), message_queue.clone(), immut_data_id);

            assert_eq!(unwrap!(resp_getter.get()), orig_data_immutable);
        }

        // Construct ImmutableData
        let new_data: Vec<u8> = unwrap!(utility::generate_random_vector(100));
        let new_immutable_data = ImmutableData::new(new_data);
        let new_data_immutable = Data::Immutable(new_immutable_data);

        // PUT for new ImmutableData should succeed
        {
            let (tx, rx) = mpsc::channel();
            let msg_id = MessageId::new();

            unwrap!(message_queue.lock()).register_response_observer(msg_id, tx.clone());
            unwrap!(mock_routing.send_put_request(location_client_mgr_immut.clone(),
                                                  new_data_immutable.clone(),
                                                  msg_id));
            let resp_getter = MutationResponseGetter::new((tx, rx));

            unwrap!(resp_getter.get());
        }

        // Construct StructuredData, 2nd version, for this ImmutableData - IVALID Versioning
        let invalid_version_account_version = unwrap!(StructuredData::new(TYPE_TAG,
                                               user_id.clone(),
                                               0,
                                               Vec::new(),
                                               vec![account_packet.get_public_maid()
                                                        .public_keys()
                                                        .0
                                                        .clone()],
                                               Vec::new(),
                                               Some(&account_packet.get_maid()
                                                   .secret_keys()
                                                   .0)));
        let invalid_version_data_account_version =
            Data::Structured(invalid_version_account_version);

        // Construct StructuredData, 2nd version, for this ImmutableData - IVALID Signature
        let invalid_signature_account_version = unwrap!(StructuredData::new(TYPE_TAG,
                                               user_id.clone(),
                                               1,
                                               Vec::new(),
                                               vec![account_packet.get_public_maid()
                                                                  .public_keys()
                                                                  .0
                                                                  .clone()],
                                               Vec::new(),
                                               Some(&account_packet.get_mpid().secret_keys().0)));
        let invalid_signature_data_account_version =
            Data::Structured(invalid_signature_account_version);

        let data_for_version_2 = unwrap!(serialise(&vec![orig_data_immutable.name(),
                                                         new_data_immutable.name()]));
        // Construct StructuredData, 2nd version, for this ImmutableData - Valid
        account_version = unwrap!(StructuredData::new(TYPE_TAG,
                                                      user_id.clone(),
                                                      1,
                                                      data_for_version_2,
                                                      vec![account_packet.get_public_maid()
                                                               .public_keys()
                                                               .0
                                                               .clone()],
                                                      Vec::new(),
                                                      Some(&account_packet.get_maid()
                                                          .secret_keys()
                                                          .0)));
        data_account_version = Data::Structured(account_version);

        // Subsequent PUTs for same StructuredData should fail
        {
            let (tx, rx) = mpsc::channel();
            let msg_id = MessageId::new();

            unwrap!(message_queue.lock()).register_response_observer(msg_id, tx.clone());
            unwrap!(mock_routing.send_put_request(location_client_mgr_struct.clone(),
                                                  data_account_version.clone(),
                                                  msg_id));
            let resp_getter = MutationResponseGetter::new((tx, rx));

            match resp_getter.get() {
                Ok(_) => panic!("Expected Put Failure!"),
                Err(CoreError::MutationFailure { reason: MutationError::DataExists, .. }) => (),
                Err(err) => panic!("Unexpected: {:?}", err),
            }
        }

        // Subsequent POSTSs for same StructuredData should fail if versioning is invalid
        {
            let (tx, rx) = mpsc::channel();
            let msg_id = MessageId::new();

            unwrap!(message_queue.lock()).register_response_observer(msg_id, tx.clone());
            unwrap!(mock_routing.send_post_request(location_nae_mgr_struct.clone(),
                                                   invalid_version_data_account_version,
                                                   msg_id));
            let resp_getter = MutationResponseGetter::new((tx, rx));

            match resp_getter.get() {
                Ok(_) => panic!("Expected Post Failure!"),
                Err(CoreError::MutationFailure { reason: MutationError::InvalidSuccessor, .. }) => {
                    ()
                }
                Err(err) => panic!("Unexpected: {:?}", err),
            }
        }

        // Subsequent POSTSs for same StructuredData should fail if signature is invalid
        {
            let (tx, rx) = mpsc::channel();
            let msg_id = MessageId::new();

            unwrap!(message_queue.lock()).register_response_observer(msg_id, tx.clone());
            unwrap!(mock_routing.send_post_request(location_nae_mgr_struct.clone(),
                                                   invalid_signature_data_account_version,
                                                   msg_id));
            let resp_getter = MutationResponseGetter::new((tx, rx));

            match resp_getter.get() {
                Ok(_) => panic!("Expected Post Failure!"),
                Err(CoreError::MutationFailure { reason: MutationError::InvalidSuccessor, .. }) => {
                    ()
                }
                Err(err) => panic!("Unexpected: {:?}", err),
            }
        }

        // Subsequent POSTSs for existing StructuredData version should pass for valid update
        {
            let (tx, rx) = mpsc::channel();
            let msg_id = MessageId::new();

            unwrap!(message_queue.lock()).register_response_observer(msg_id, tx.clone());
            unwrap!(mock_routing.send_post_request(location_nae_mgr_struct.clone(),
                                                   data_account_version.clone(),
                                                   msg_id));
            let resp_getter = MutationResponseGetter::new((tx, rx));

            unwrap!(resp_getter.get());
        }

        // GET for new StructuredData version should pass
        {
            let struct_data_id = DataIdentifier::Structured(user_id, TYPE_TAG);

            let (tx, rx) = mpsc::channel();
            let msg_id = MessageId::new();

            unwrap!(message_queue.lock()).register_response_observer(msg_id, tx.clone());

            unwrap!(mock_routing.send_get_request(location_nae_mgr_struct.clone(),
                                                  struct_data_id,
                                                  msg_id));

            let resp_getter =
                GetResponseGetter::new(Some((tx, rx)), message_queue.clone(), struct_data_id);

            let data = unwrap!(resp_getter.get());
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

            let (tx, rx) = mpsc::channel();
            let msg_id = MessageId::new();

            unwrap!(message_queue.lock()).register_response_observer(msg_id, tx.clone());

            unwrap!(mock_routing.send_get_request(location_nae_mgr_immut.clone(),
                                                  immut_data_id,
                                                  msg_id));

            let resp_getter =
                GetResponseGetter::new(Some((tx, rx)), message_queue.clone(), immut_data_id);

            assert_eq!(unwrap!(resp_getter.get()), new_data_immutable);
        }

        // GET original ImmutableData should pass
        {
            let immut_data_id = DataIdentifier::Immutable(location_vec[0]);

            let (tx, rx) = mpsc::channel();
            let msg_id = MessageId::new();

            unwrap!(message_queue.lock()).register_response_observer(msg_id, tx.clone());

            unwrap!(mock_routing.send_get_request(location_nae_mgr_immut, immut_data_id, msg_id));

            let resp_getter =
                GetResponseGetter::new(Some((tx, rx)), message_queue.clone(), immut_data_id);

            assert_eq!(unwrap!(resp_getter.get()), orig_data_immutable);
        }

        // DELETE of Structured Data without version bump should fail
        {
            let (tx, rx) = mpsc::channel();
            let msg_id = MessageId::new();

            unwrap!(message_queue.lock()).register_response_observer(msg_id, tx.clone());
            unwrap!(mock_routing.send_delete_request(location_client_mgr_struct.clone(),
                                                     data_account_version.clone(),
                                                     msg_id));
            let resp_getter = MutationResponseGetter::new((tx, rx));

            match resp_getter.get() {
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

            let (tx, rx) = mpsc::channel();
            let msg_id = MessageId::new();

            unwrap!(message_queue.lock()).register_response_observer(msg_id, tx.clone());

            unwrap!(mock_routing.send_get_request(location_nae_mgr_struct.clone(),
                                                  struct_data_id,
                                                  msg_id));

            let resp_getter =
                GetResponseGetter::new(Some((tx, rx)), message_queue.clone(), struct_data_id);

            assert_eq!(unwrap!(resp_getter.get()), data_account_version);
        }

        // Construct StructuredData, 3rd version, for DELETE - Valid
        account_version = unwrap!(StructuredData::new(TYPE_TAG,
                                                      user_id.clone(),
                                                      2,
                                                      Vec::new(),
                                                      vec![account_packet.get_public_maid()
                                                               .public_keys()
                                                               .0
                                                               .clone()],
                                                      Vec::new(),
                                                      Some(&account_packet.get_maid()
                                                          .secret_keys()
                                                          .0)));
        data_account_version = Data::Structured(account_version);

        // DELETE of Structured Data with version bump should pass
        {
            let (tx, rx) = mpsc::channel();
            let msg_id = MessageId::new();

            unwrap!(message_queue.lock()).register_response_observer(msg_id, tx.clone());
            unwrap!(mock_routing.send_delete_request(location_client_mgr_struct,
                                                            data_account_version,
                                                            msg_id));
            let resp_getter = MutationResponseGetter::new((tx, rx));

            unwrap!(resp_getter.get());
        }

        // GET for DELETED StructuredData version should fail
        {
            let struct_data_id = DataIdentifier::Structured(user_id, TYPE_TAG);

            let (tx, rx) = mpsc::channel();
            let msg_id = MessageId::new();

            unwrap!(message_queue.lock()).register_response_observer(msg_id, tx.clone());

            unwrap!(mock_routing.send_get_request(location_nae_mgr_struct, struct_data_id, msg_id));

            let resp_getter =
                GetResponseGetter::new(Some((tx, rx)), message_queue.clone(), struct_data_id);

            match resp_getter.get() {
                Ok(_) => panic!("Expected Get Failure!"),
                Err(CoreError::GetFailure { reason: GetError::NoSuchData, .. }) => (),
                Err(err) => panic!("Unexpected: {:?}", err),
            }
        }

        // GetAccountInfo should pass and show three chunks stored
        {
            let (tx, rx) = mpsc::channel();
            let msg_id = MessageId::new();

            unwrap!(message_queue.lock()).register_response_observer(msg_id, tx.clone());

            unwrap!(mock_routing.send_get_account_info_request(location_client_mgr_immut, msg_id));

            let resp_getter = GetAccountInfoResponseGetter::new((tx, rx));

            assert_eq!(unwrap!(resp_getter.get()),
                       (3, DEFAULT_CLIENT_ACCOUNT_SIZE - 3));
        }
    }
}
