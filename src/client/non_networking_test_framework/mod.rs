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

use std::io::{Read, Write};

type DataStore = ::std::sync::Arc<::std::sync::Mutex<::std::collections::HashMap<::routing::NameType, Vec<u8>>>>;

const STORAGE_FILE_NAME: &'static str = "VaultStorageSimulation";

// TODO(Spandan) Activating these (ie., non-zero values) will require an update to all test cases.
// See how it is intended to be handled.
//
// These will allow to code properly for behavioral anomalies like GETs reaching the address faster
// than PUTs. So a proper delay will help code better logic against scenarios where it is required
// to do a GET after a PUT/DELETE to confirm that action. So for example if a GET done immediately
// after a PUT failed, it could mean that the PUT either failed or hasn't reached the address yet.
const SIMULATED_NETWORK_DELAY_GETS_POSTS_MS: u32 = 0;
const SIMULATED_NETWORK_DELAY_PUTS_DELETS_MS: u32 = 2 * SIMULATED_NETWORK_DELAY_GETS_POSTS_MS;

struct PersistentStorageSimulation {
    data_store: DataStore,
}

// This is a hack because presently cbor isn't able to encode HashMap<NameType, Vec<u8>>
pub fn convert_hashmap_to_vec(hashmap: &::std::collections::HashMap<::routing::NameType, Vec<u8>>) -> Vec<(::routing::NameType, Vec<u8>)> {
    hashmap.iter().map(|a| (a.0.clone(), a.1.clone())).collect()
}

// This is a hack because presently cbor isn't able to encode HashMap<NameType, Vec<u8>>
pub fn convert_vec_to_hashmap(vec: Vec<(::routing::NameType, Vec<u8>)>) -> ::std::collections::HashMap<::routing::NameType, Vec<u8>> {
    vec.into_iter().collect()
}

#[allow(unsafe_code)]
fn get_storage() -> DataStore {
    static mut STORAGE: *const PersistentStorageSimulation = 0 as *const PersistentStorageSimulation;
    static mut ONCE: ::std::sync::Once = ::std::sync::ONCE_INIT;

    unsafe {
        ONCE.call_once(|| {
            let mut memory_storage = ::std::collections::HashMap::new();

            let mut temp_dir_pathbuf = ::std::env::temp_dir();
            temp_dir_pathbuf.push(STORAGE_FILE_NAME);

            if let Ok(mut file) = ::std::fs::File::open(temp_dir_pathbuf) {
                let mut raw_disk_data = Vec::with_capacity(eval_result!(file.metadata()).len() as usize);
                if let Ok(_) = file.read_to_end(&mut raw_disk_data) {
                    if raw_disk_data.len() != 0 {
                        let vec: Vec<(::routing::NameType, Vec<u8>)>;
                        vec = eval_result!(::utility::deserialise(&raw_disk_data));
                        memory_storage = convert_vec_to_hashmap(vec);
                    }
                }
            }

            STORAGE = ::std::mem::transmute(Box::new(
                    PersistentStorageSimulation {
                        data_store: ::std::sync::Arc::new(::std::sync::Mutex::new(memory_storage)),
                    }
                    ));
        });

        (*STORAGE).data_store.clone()
    }
}

fn sync_disk_storage(memory_storage: &::std::collections::HashMap<::routing::NameType, Vec<u8>>) {
    let mut temp_dir_pathbuf = ::std::env::temp_dir();
    temp_dir_pathbuf.push(STORAGE_FILE_NAME);

    let mut file = eval_result!(::std::fs::File::create(temp_dir_pathbuf));
    let _ = file.write_all(&eval_result!(::utility::serialise(&convert_hashmap_to_vec(memory_storage))));
    eval_result!(file.sync_all());
}

pub struct RoutingMock {
    sender: ::std::sync::mpsc::Sender<::routing::event::Event>,
}

impl RoutingMock {
    pub fn new(sender: ::std::sync::mpsc::Sender<::routing::event::Event>,
               _id   : Option<::routing::id::Id>) -> RoutingMock {
        ::sodiumoxide::init();

        let cloned_sender = sender.clone();
        let _ = ::std::thread::spawn(move || {
            ::std::thread::sleep(::std::time::Duration::from_millis(SIMULATED_NETWORK_DELAY_PUTS_DELETS_MS as u64));
            let _ = cloned_sender.send(::routing::event::Event::Bootstrapped);
        });

        RoutingMock {
            sender: sender,
        }
    }

    pub fn get_request(&mut self,
                       _location  : ::routing::authority::Authority,
                       request_for: ::routing::data::DataRequest) {
        let data_store = get_storage();
        let cloned_sender = self.sender.clone();

        let _ = ::std::thread::spawn(move || {
            ::std::thread::sleep(::std::time::Duration::from_millis(SIMULATED_NETWORK_DELAY_GETS_POSTS_MS as u64));
            let data_name = request_for.name();
            match eval_result!(data_store.lock()).get(&data_name) {
                Some(raw_data) => {
                    if let Ok(data) = ::utility::deserialise::<::routing::data::Data>(raw_data) {
                        if match (&data, &request_for) {
                               (&::routing::data::Data::ImmutableData(ref immut_data), &::routing::data::DataRequest::ImmutableData(_, ref tag)) => immut_data.get_type_tag() == tag,
                               (&::routing::data::Data::StructuredData(ref struct_data), &::routing::data::DataRequest::StructuredData(_, ref tag)) => struct_data.get_type_tag() == *tag,
                               _ => false,
                           } {
                            let external_response = ::routing::ExternalResponse::Get(data, request_for, None);
                            if let Err(error) = cloned_sender.send(::routing::event::Event::Response {
                                response      : external_response,
                                our_authority : ::routing::authority::Authority::NaeManager(data_name.clone()),
                                from_authority: ::routing::authority::Authority::NaeManager(data_name),
                            }) {
                                debug!("Get-Request Send Failure: {:?}", error);
                            }
                        }
                    }
                },
                None => (),
            };
        });
    }

    pub fn put_request(&self,
                       _location: ::routing::authority::Authority,
                       data     : ::routing::data::Data) {
        let data_store = get_storage();

        let data_name = data.name();

        let mut data_store_mutex_guard = eval_result!(data_store.lock());
        let success = if data_store_mutex_guard.contains_key(&data_name) {
            if let ::routing::data::Data::ImmutableData(immut_data) = data {
                match ::utility::deserialise(eval_option!(data_store_mutex_guard.get(&data_name), "Programming Error - Report this as a Bug.")) {
                    Ok(::routing::data::Data::ImmutableData(immut_data_stored)) => immut_data_stored.get_type_tag() == immut_data.get_type_tag(), // Immutable data is de-duplicated so always allowed
                    _ => false
                }
            } else {
                false
            }
        } else if let Ok(raw_data) = ::utility::serialise(&data) {
            let _ = data_store_mutex_guard.insert(data_name, raw_data);
            sync_disk_storage(&*data_store_mutex_guard);
            true
        } else {
            false
        };

        let _ = ::std::thread::spawn(move || {
            ::std::thread::sleep(::std::time::Duration::from_millis(SIMULATED_NETWORK_DELAY_PUTS_DELETS_MS as u64));
            if !success { // TODO(Spandan) Check how routing is going to handle PUT errors
            }
        });
    }

    pub fn post_request(&self,
                        _location: ::routing::authority::Authority,
                        data     : ::routing::data::Data) {
        let data_store = get_storage();

        let data_name = data.name();

        let mut data_store_mutex_guard = eval_result!(data_store.lock());
        let success = if data_store_mutex_guard.contains_key(&data_name) {
            let raw_data_result = ::utility::serialise(&data);
            match (raw_data_result, data, ::utility::deserialise(eval_option!(data_store_mutex_guard.get(&data_name), "Programming Error - Report this as a Bug."))) {
                (Ok(raw_data), ::routing::data::Data::StructuredData(struct_data_new), Ok(::routing::data::Data::StructuredData(struct_data_stored))) => {
                    if let Ok(_) = struct_data_stored.validate_self_against_successor(&struct_data_new) {
                        let _ = data_store_mutex_guard.insert(data_name, raw_data);
                        sync_disk_storage(&*data_store_mutex_guard);
                        true
                    } else {
                        false
                    }
                },
                _ => false,
            }
        } else {
            false
        };

        let _ = ::std::thread::spawn(move || {
            ::std::thread::sleep(::std::time::Duration::from_millis(SIMULATED_NETWORK_DELAY_GETS_POSTS_MS as u64));
            if !success { // TODO(Spandan) Check how routing is going to handle POST errors
            }
        });
    }

    pub fn delete_request(&self,
                           _location: ::routing::authority::Authority,
                           data     : ::routing::data::Data) {
        let data_store = get_storage();

        let data_name = data.name();

        let mut data_store_mutex_guard = eval_result!(data_store.lock());
        let success = if data_store_mutex_guard.contains_key(&data_name) {
            let raw_data_result = ::utility::serialise(&data);
            match (raw_data_result, data, ::utility::deserialise(eval_option!(data_store_mutex_guard.get(&data_name), "Programming Error - Report this as a Bug."))) {
                (Ok(_), ::routing::data::Data::StructuredData(struct_data_new), Ok(::routing::data::Data::StructuredData(struct_data_stored))) => {
                    if let Ok(_) = struct_data_stored.validate_self_against_successor(&struct_data_new) {
                        let _ = data_store_mutex_guard.remove(&data_name);
                        sync_disk_storage(&*data_store_mutex_guard);
                        true
                    } else {
                        false
                    }
                },
                _ => false,
            }
        } else {
            false
        };

        let _ = ::std::thread::spawn(move || {
            ::std::thread::sleep(::std::time::Duration::from_millis(SIMULATED_NETWORK_DELAY_PUTS_DELETS_MS as u64));
            if !success { // TODO(Spandan) Check how routing is going to handle DELETE errors
            }
        });
    }

    pub fn stop(&self) {
        let _ = self.sender.send(::routing::event::Event::Terminated);
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn map_serialisation() {
        let mut map_before = ::std::collections::HashMap::<::routing::NameType, Vec<u8>>::new();
        let _ = map_before.insert(::routing::NameType::new([1; 64]), vec![1; 10]);

        let vec_before = convert_hashmap_to_vec(&map_before);
        let serialised_data = eval_result!(::utility::serialise(&vec_before));

        let vec_after: Vec<(::routing::NameType, Vec<u8>)> = eval_result!(::utility::deserialise(&serialised_data));
        let map_after = convert_vec_to_hashmap(vec_after);
        assert_eq!(map_before, map_after);
    }

    #[test]
    fn check_put_post_get_delete_for_immutable_data() {
        let account_packet = ::client::user_account::Account::new(None, None);

        let id_packet = ::routing::id::Id::with_keys((account_packet.get_maid().public_keys().0.clone(),
                                                      account_packet.get_maid().secret_keys().0.clone()),
                                                     (account_packet.get_maid().public_keys().1.clone(),
                                                      account_packet.get_maid().secret_keys().1.clone()));

        let (routing_sender, routing_receiver) = ::std::sync::mpsc::channel();
        let (network_event_sender, network_event_receiver) = ::std::sync::mpsc::channel();

        let mut mock_routing = RoutingMock::new(routing_sender, Some(id_packet));
        let (message_queue, _raii_joiner) = ::client::message_queue::MessageQueue::new(routing_receiver, vec![network_event_sender], Vec::new());

        match eval_result!(network_event_receiver.recv()) {
            ::translated_events::NetworkEvent::Bootstrapped => (),
            _ => panic!("Could not Bootstrap !!"),
        }

        // Construct ImmutableData
        let orig_raw_data: Vec<u8> = eval_result!(::utility::generate_random_vector(100));
        let orig_immutable_data = ::routing::immutable_data::ImmutableData::new(::routing::immutable_data::ImmutableDataType::Normal,
                                                                                orig_raw_data.clone());
        let orig_data = ::routing::data::Data::ImmutableData(orig_immutable_data);

        let location_nae_mgr = ::routing::authority::Authority::NaeManager(orig_data.name());
        let location_client_mgr = ::routing::authority::Authority::ClientManager(orig_data.name());

        // First PUT should succeed
        mock_routing.put_request(location_client_mgr.clone(), orig_data.clone());

        // GET ImmutableData should pass
        {
            let data_request = ::routing::data::DataRequest::ImmutableData(orig_data.name(),
                                                                           ::routing::immutable_data::ImmutableDataType::Normal);

            let (data_event_sender, data_event_receiver) = ::std::sync::mpsc::channel();
            eval_result!(message_queue.lock()).add_data_receive_event_observer(data_request.name(),
                                                                               data_event_sender.clone());

            mock_routing.get_request(location_nae_mgr.clone(), data_request.clone());

            let response_getter = ::client::response_getter::ResponseGetter::new(Some((data_event_sender, data_event_receiver)),
                                                                                 message_queue.clone(),
                                                                                 data_request);
            match response_getter.get() {
                Ok(data) => assert_eq!(data, orig_data),
                Err(error) => panic!("Should have found data put before by a PUT {:?}", error),
            }
        }

        // Subsequent PUTs for same ImmutableData should succeed - De-duplication
        mock_routing.put_request(location_client_mgr.clone(), orig_data.clone());

        // Construct Backup ImmutableData
        let new_immutable_data = ::routing::immutable_data::ImmutableData::new(::routing::immutable_data::ImmutableDataType::Backup, orig_raw_data);
        let new_data = ::routing::data::Data::ImmutableData(new_immutable_data.clone());

        // Subsequent PUTs for same ImmutableData of different type should fail
        mock_routing.put_request(location_client_mgr.clone(), new_data);

        // POSTs for ImmutableData should fail
        mock_routing.post_request(location_nae_mgr.clone(), orig_data.clone());

        // DELETEs of ImmutableData should fail
        mock_routing.delete_request(location_client_mgr, orig_data.clone());

        // GET ImmutableData should pass
        {
            let data_request = ::routing::data::DataRequest::ImmutableData(orig_data.name(),
                                                                           ::routing::immutable_data::ImmutableDataType::Normal);

            let (data_event_sender, data_event_receiver) = ::std::sync::mpsc::channel();
            eval_result!(message_queue.lock()).add_data_receive_event_observer(data_request.name(),
                                                                               data_event_sender.clone());

            mock_routing.get_request(location_nae_mgr, data_request.clone());

            let response_getter = ::client::response_getter::ResponseGetter::new(Some((data_event_sender, data_event_receiver)),
                                                                                 message_queue.clone(),
                                                                                 data_request);

            match response_getter.get() {
                Ok(data) => assert_eq!(data, orig_data),
                Err(error) => panic!("Should have found data put before by a PUT {:?}", error),
            }
        }

        mock_routing.stop();
    }

    #[test]
    fn check_put_post_get_delete_for_structured_data() {
        let account_packet = ::client::user_account::Account::new(None, None);

        let id_packet = ::routing::id::Id::with_keys((account_packet.get_maid().public_keys().0.clone(),
                                                      account_packet.get_maid().secret_keys().0.clone()),
                                                     (account_packet.get_maid().public_keys().1.clone(),
                                                      account_packet.get_maid().secret_keys().1.clone()));

        let (routing_sender, routing_receiver) = ::std::sync::mpsc::channel();
        let (network_event_sender, network_event_receiver) = ::std::sync::mpsc::channel();

        let mut mock_routing = RoutingMock::new(routing_sender, Some(id_packet));
        let (message_queue, _raii_joiner) = ::client::message_queue::MessageQueue::new(routing_receiver, vec![network_event_sender], Vec::new());

        match eval_result!(network_event_receiver.recv()) {
            ::translated_events::NetworkEvent::Bootstrapped => (),
            _ => panic!("Could not Bootstrap !!"),
        }

        // Construct ImmutableData
        let orig_raw_data: Vec<u8> = eval_result!(::utility::generate_random_vector(100));
        let orig_immutable_data = ::routing::immutable_data::ImmutableData::new(::routing::immutable_data::ImmutableDataType::Normal, orig_raw_data);
        let orig_data_immutable = ::routing::data::Data::ImmutableData(orig_immutable_data);

        const TYPE_TAG: u64 = 999;

        // Construct StructuredData, 1st version, for this ImmutableData
        let keyword = eval_result!(::utility::generate_random_string(10));
        let pin = eval_result!(::utility::generate_random_string(10));
        let user_id = eval_result!(::client::user_account::Account::generate_network_id(keyword.as_bytes(), pin.to_string().as_bytes()));
        let mut account_version = eval_result!(::routing::structured_data::StructuredData::new(TYPE_TAG,
                                                                                               user_id.clone(),
                                                                                               0,
                                                                                               eval_result!(::utility::serialise(&vec![orig_data_immutable.name()])),
                                                                                               vec![account_packet.get_public_maid().public_keys().0.clone()],
                                                                                               Vec::new(),
                                                                                               Some(&account_packet.get_maid().secret_keys().0)));
        let mut data_account_version = ::routing::data::Data::StructuredData(account_version);


        let location_nae_mgr_immut = ::routing::authority::Authority::NaeManager(orig_data_immutable.name());
        let location_nae_mgr_struct = ::routing::authority::Authority::NaeManager(data_account_version.name());

        let location_client_mgr_immut = ::routing::authority::Authority::ClientManager(orig_data_immutable.name());
        let location_client_mgr_struct = ::routing::authority::Authority::ClientManager(data_account_version.name());

        // First PUT of StructuredData should succeed
        mock_routing.put_request(location_client_mgr_struct.clone(), data_account_version.clone());

        // PUT for ImmutableData should succeed
        mock_routing.put_request(location_client_mgr_immut.clone(), orig_data_immutable.clone());

        let mut received_structured_data: ::routing::structured_data::StructuredData;

        // GET StructuredData should pass
        {
            let struct_data_request = ::routing::data::DataRequest::StructuredData(user_id.clone(), TYPE_TAG);

            let (data_event_sender, data_event_receiver) = ::std::sync::mpsc::channel();
            eval_result!(message_queue.lock()).add_data_receive_event_observer(struct_data_request.name(),
                                                                               data_event_sender.clone());

            mock_routing.get_request(location_nae_mgr_struct.clone(), struct_data_request.clone());

            let response_getter = ::client::response_getter::ResponseGetter::new(Some((data_event_sender, data_event_receiver)),
                                                                                 message_queue.clone(),
                                                                                 struct_data_request);
            match response_getter.get() {
                Ok(data) => {
                    assert_eq!(data, data_account_version);
                    match data {
                        ::routing::data::Data::StructuredData(struct_data) => received_structured_data = struct_data,
                        _ => panic!("Unexpected!"),
                    }
                },
                Err(error) => panic!("Should have found data put before by a PUT {:?}", error),
            }
        }

        // GET ImmutableData from lastest version of StructuredData should pass
        {
            let mut location_vec = eval_result!(::utility::deserialise::<Vec<::routing::NameType>>(received_structured_data.get_data()));
            let immut_data_request = ::routing::data::DataRequest::ImmutableData(eval_option!(location_vec.pop(), "Value must exist !"),
                                                                                 ::routing::immutable_data::ImmutableDataType::Normal);

            let (data_event_sender, data_event_receiver) = ::std::sync::mpsc::channel();
            eval_result!(message_queue.lock()).add_data_receive_event_observer(immut_data_request.name(),
                                                                               data_event_sender.clone());

            mock_routing.get_request(location_nae_mgr_immut.clone(), immut_data_request.clone());

            let response_getter = ::client::response_getter::ResponseGetter::new(Some((data_event_sender, data_event_receiver)),
                                                                                 message_queue.clone(),
                                                                                 immut_data_request);
            match response_getter.get() {
                Ok(data) => assert_eq!(data, orig_data_immutable),
                Err(error) => panic!("Should have found data put before by a PUT {:?}", error),
            }
        }

        // Construct ImmutableData
        let new_data: Vec<u8> = eval_result!(::utility::generate_random_vector(100));
        let new_immutable_data = ::routing::immutable_data::ImmutableData::new(::routing::immutable_data::ImmutableDataType::Normal, new_data);
        let new_data_immutable = ::routing::data::Data::ImmutableData(new_immutable_data);

        // PUT for new ImmutableData should succeed
        mock_routing.put_request(location_client_mgr_immut, new_data_immutable.clone());

        // Construct StructuredData, 2nd version, for this ImmutableData - IVALID Versioning
        let invalid_version_account_version = eval_result!(::routing::structured_data::StructuredData::new(TYPE_TAG,
                                                                                                           user_id.clone(),
                                                                                                           0,
                                                                                                           Vec::new(),
                                                                                                           vec![account_packet.get_public_maid().public_keys().0.clone()],
                                                                                                           Vec::new(),
                                                                                                           Some(&account_packet.get_maid().secret_keys().0)));
        let invalid_version_data_account_version = ::routing::data::Data::StructuredData(invalid_version_account_version);

        // Construct StructuredData, 2nd version, for this ImmutableData - IVALID Signature
        let invalid_signature_account_version = eval_result!(::routing::structured_data::StructuredData::new(TYPE_TAG,
                                                                                                             user_id.clone(),
                                                                                                             1,
                                                                                                             Vec::new(),
                                                                                                             vec![account_packet.get_public_maid().public_keys().0.clone()],
                                                                                                             Vec::new(),
                                                                                                             Some(&account_packet.get_mpid().secret_keys().0)));
        let invalid_signature_data_account_version = ::routing::data::Data::StructuredData(invalid_signature_account_version);

        // Construct StructuredData, 2nd version, for this ImmutableData - Valid
        account_version = eval_result!(::routing::structured_data::StructuredData::new(TYPE_TAG,
                                                                                       user_id.clone(),
                                                                                       1,
                                                                                       eval_result!(::utility::serialise(&vec![orig_data_immutable.name(), new_data_immutable.name()])),
                                                                                       vec![account_packet.get_public_maid().public_keys().0.clone()],
                                                                                       Vec::new(),
                                                                                       Some(&account_packet.get_maid().secret_keys().0)));
        data_account_version = ::routing::data::Data::StructuredData(account_version);

        // Subsequent PUTs for same StructuredData should fail
        mock_routing.put_request(location_client_mgr_struct.clone(), data_account_version.clone());

        // Subsequent POSTSs for same StructuredData should fail if versioning is invalid
        mock_routing.post_request(location_nae_mgr_struct.clone(), invalid_version_data_account_version);

        // Subsequent POSTSs for same StructuredData should fail if signature is invalid
        mock_routing.post_request(location_nae_mgr_struct.clone(), invalid_signature_data_account_version);

        // Subsequent POSTSs for existing StructuredData version should pass for valid update
        mock_routing.post_request(location_nae_mgr_struct.clone(), data_account_version.clone());

        // GET for new StructuredData version should pass
        {
            let struct_data_request = ::routing::data::DataRequest::StructuredData(user_id.clone(), TYPE_TAG);

            let (data_event_sender, data_event_receiver) = ::std::sync::mpsc::channel();
            eval_result!(message_queue.lock()).add_data_receive_event_observer(struct_data_request.name(),
                                                                               data_event_sender.clone());

            mock_routing.get_request(location_nae_mgr_struct.clone(), struct_data_request.clone());

            let response_getter = ::client::response_getter::ResponseGetter::new(Some((data_event_sender, data_event_receiver)),
                                                                                 message_queue.clone(),
                                                                                 struct_data_request);
            match response_getter.get() {
                Ok(data) => {
                    assert_eq!(data, data_account_version);
                    match data {
                        ::routing::data::Data::StructuredData(structured_data) => received_structured_data = structured_data,
                        _ => panic!("Unexpected!"),
                    }
                },
                Err(error) => panic!("Should have found data put before by a PUT {:?}", error),
            }
        }

        let location_vec = eval_result!(::utility::deserialise::<Vec<::routing::NameType>>(received_structured_data.get_data()));
        assert_eq!(location_vec.len(), 2);

        // GET new ImmutableData should pass
        {
            let immut_data_request = ::routing::data::DataRequest::ImmutableData(location_vec[1].clone(),
                                                                                 ::routing::immutable_data::ImmutableDataType::Normal);

            let (data_event_sender, data_event_receiver) = ::std::sync::mpsc::channel();
            eval_result!(message_queue.lock()).add_data_receive_event_observer(immut_data_request.name(),
                                                                               data_event_sender.clone());

            mock_routing.get_request(location_nae_mgr_immut.clone(), immut_data_request.clone());

            let response_getter = ::client::response_getter::ResponseGetter::new(Some((data_event_sender, data_event_receiver)),
                                                                                 message_queue.clone(),
                                                                                 immut_data_request);
            match response_getter.get() {
                Ok(data) => assert_eq!(data, new_data_immutable),
                Err(error) => panic!("Should have found data put before by a PUT {:?}", error),
            }
        }

        // GET original ImmutableData should pass
        {
            let immut_data_request = ::routing::data::DataRequest::ImmutableData(location_vec[0].clone(),
                                                                                 ::routing::immutable_data::ImmutableDataType::Normal);

            let (data_event_sender, data_event_receiver) = ::std::sync::mpsc::channel();
            eval_result!(message_queue.lock()).add_data_receive_event_observer(immut_data_request.name(),
                                                                               data_event_sender.clone());

            mock_routing.get_request(location_nae_mgr_immut, immut_data_request.clone());

            let response_getter = ::client::response_getter::ResponseGetter::new(Some((data_event_sender, data_event_receiver)),
                                                                                 message_queue.clone(),
                                                                                 immut_data_request);
            match response_getter.get() {
                Ok(data) => assert_eq!(data, orig_data_immutable),
                Err(error) => panic!("Should have found data put before by a PUT {:?}", error),
            }
        }

        // DELETE of Structured Data without version bump should fail
        mock_routing.delete_request(location_client_mgr_struct.clone(), data_account_version.clone());

        // GET for StructuredData version should still pass
        {
            let struct_data_request = ::routing::data::DataRequest::StructuredData(user_id.clone(), TYPE_TAG);

            let (data_event_sender, data_event_receiver) = ::std::sync::mpsc::channel();
            eval_result!(message_queue.lock()).add_data_receive_event_observer(struct_data_request.name(),
                                                                               data_event_sender.clone());

            mock_routing.get_request(location_nae_mgr_struct, struct_data_request.clone());

            let response_getter = ::client::response_getter::ResponseGetter::new(Some((data_event_sender, data_event_receiver)),
                                                                                 message_queue.clone(),
                                                                                 struct_data_request);
            match response_getter.get() {
                Ok(data) => assert_eq!(data, data_account_version),
                Err(error) => panic!("Should have found data put before by a PUT {:?}", error),
            }
        }

        // Construct StructuredData, 3rd version, for DELETE - Valid
        account_version = eval_result!(::routing::structured_data::StructuredData::new(TYPE_TAG,
                                                                                       user_id,
                                                                                       2,
                                                                                       Vec::new(),
                                                                                       vec![account_packet.get_public_maid().public_keys().0.clone()],
                                                                                       Vec::new(),
                                                                                       Some(&account_packet.get_maid().secret_keys().0)));
        data_account_version = ::routing::data::Data::StructuredData(account_version);

        // DELETE of Structured Data with version bump should pass
        mock_routing.delete_request(location_client_mgr_struct, data_account_version);

        mock_routing.stop();
    }
}
