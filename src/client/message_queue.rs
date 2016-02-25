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
// relating to use of the SAFE Network Software.                                                                 */

use errors::CoreError;
use xor_name::XorName;
use lru_time_cache::LruCache;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, mpsc};
use routing::{Data, Event, ResponseContent, RequestContent};
use maidsafe_utilities::thread::RaiiThreadJoiner;

const EVENT_RECEIVER_THREAD_NAME: &'static str = "EventReceiverThread";

/// MessageQueue gets and collects messages/responses from routing. It also maintains local caching
/// of previously fetched ImmutableData (because the very nature of such data implies Immutability)
/// enabling fast re-retrieval and avoiding networking.
pub struct MessageQueue {
    local_cache: LruCache<XorName, Data>,
    data_senders: HashMap<XorName, Vec<mpsc::Sender<::translated_events::DataReceivedEvent>>>,
    error_senders: Vec<mpsc::Sender<::translated_events::OperationFailureEvent>>,
    network_event_senders: Vec<mpsc::Sender<::translated_events::NetworkEvent>>,
    routing_message_cache: LruCache<XorName, Data>,
}

impl MessageQueue {
    /// Create a new instance of MessageQueue. `data_senders` can be added later via function to
    /// add observer since one will not receive data until one asks for it. Thus there is enough
    /// chance to add an observer before requesting data.
    pub fn new(routing_event_receiver: mpsc::Receiver<Event>,
               network_event_senders: Vec<mpsc::Sender<::translated_events::NetworkEvent>>,
               error_senders: Vec<mpsc::Sender<::translated_events::OperationFailureEvent>>)
               -> (Arc<Mutex<MessageQueue>>, RaiiThreadJoiner) {
        let message_queue = Arc::new(Mutex::new(MessageQueue {
            local_cache: LruCache::with_capacity(1000),
            data_senders: HashMap::new(),
            error_senders: error_senders,
            network_event_senders: network_event_senders,
            routing_message_cache: LruCache::with_capacity(1000),
        }));

        let message_queue_cloned = message_queue.clone();
        let receiver_joiner = thread!(EVENT_RECEIVER_THREAD_NAME, move || {
            for it in routing_event_receiver.iter() {
                match it {
                    Event::Response(msg) => {
                        match msg.content {
                            ResponseContent::GetSuccess(data, _) => {
                                let data_name = data.name();
                                let mut dead_sender_positions = Vec::<usize>::new();
                                let mut queue_guard = unwrap_result!(message_queue_cloned.lock());
                                let _ = queue_guard.routing_message_cache
                                                   .insert(data_name.clone(), data);
                                if let Some(mut specific_data_senders) =
                                       queue_guard.data_senders.get_mut(&data_name) {
                                    for it in specific_data_senders.iter().enumerate() {
                                        if it.1.send(::translated_events::DataReceivedEvent::DataReceived).is_err() {
                                            dead_sender_positions.push(it.0);
                                        }
                                    }

                                    MessageQueue::purge_dead_senders(&mut specific_data_senders,
                                                                     dead_sender_positions);
                                }
                            }
                            _ => {
                                warn!("Received Response Message: {:?} ;; This is currently not \
                                       supported.",
                                      msg)
                            }
                        }
                    }
                    Event::Connected => {
                        let mut dead_sender_positions = Vec::<usize>::new();
                        let mut queue_guard = unwrap_result!(message_queue_cloned.lock());
                        for it in queue_guard.network_event_senders.iter().enumerate() {
                            if it.1.send(::translated_events::NetworkEvent::Connected).is_err() {
                                dead_sender_positions.push(it.0);
                            }
                        }

                        MessageQueue::purge_dead_senders(&mut queue_guard.network_event_senders,
                                                         dead_sender_positions);
                    }
                    // PostRequest used for messaging features
                    Event::Request(msg) => {
                        match msg.content {
                            RequestContent::Post(data, _) => {
                                let account_name = msg.src.name();
                                let mut dead_sender_positions = Vec::<usize>::new();
                                let mut queue_guard = unwrap_result!(message_queue_cloned.lock());
                                // The generic ResponseGetter waiting on the account_name
                                let _ = queue_guard.routing_message_cache
                                                   .insert(account_name.clone(), data);
                                if let Some(mut specific_data_senders) =
                                       queue_guard.data_senders.get_mut(&account_name) {
                                    for it in specific_data_senders.iter().enumerate() {
                                        if it.1.send(::translated_events::DataReceivedEvent::DataReceived).is_err() {
                                            dead_sender_positions.push(it.0);
                                        }
                                    }

                                    MessageQueue::purge_dead_senders(&mut specific_data_senders,
                                                                     dead_sender_positions);
                                }
                            }
                            _ => {
                                warn!("Received Request Message: {:?} ; This is currently not supported.", msg)
                            }
                        }
                    }
                    _ => {
                        debug!("Received Routing Event: {:?} ;; This is currently not supported.",
                               it)
                    }
                }
            }
        });

        (message_queue, RaiiThreadJoiner::new(receiver_joiner))
    }

    pub fn add_data_receive_event_observer(&mut self,
                                           data_name: XorName,
                                           sender   : mpsc::Sender<::translated_events::DataReceivedEvent>) {
        self.data_senders.entry(data_name).or_insert(Vec::new()).push(sender);
    }

    pub fn add_operation_failure_event_observer(&mut self, sender: mpsc::Sender<::translated_events::OperationFailureEvent>) {
        self.error_senders.push(sender);
    }

    pub fn add_network_event_observer(&mut self,
                                      sender: mpsc::Sender<::translated_events::NetworkEvent>) {
        self.network_event_senders.push(sender);
    }

    pub fn local_cache_check(&mut self, key: &XorName) -> bool {
        self.local_cache.contains_key(key)
    }

    pub fn local_cache_get(&mut self, key: &XorName) -> Result<Data, CoreError> {
        self.local_cache.get(key).ok_or(CoreError::VersionCacheMiss).map(|elt| elt.clone())
    }

    pub fn local_cache_insert(&mut self, key: XorName, value: Data) {
        let _ = self.local_cache.insert(key, value);
    }

    pub fn get_response(&mut self, location: &XorName) -> Result<Data, CoreError> {
        self.routing_message_cache
            .get(location)
            .ok_or(CoreError::RoutingMessageCacheMiss)
            .map(|elt| elt.clone())
    }

    fn purge_dead_senders<T>(senders: &mut Vec<mpsc::Sender<T>>, positions: Vec<usize>) {
        let mut delta = 0;
        for val in positions {
            let _ = senders.remove(val - delta);
            delta += 1;
        }
    }
}
