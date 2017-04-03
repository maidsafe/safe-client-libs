// Copyright 2015 MaidSafe.net limited.
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

use core::errors::CoreError;
use core::translated_events::{NetworkEvent, ResponseEvent};

use lru_cache::LruCache;
use maidsafe_utilities::serialisation::deserialise;
use maidsafe_utilities::thread::{self, Joiner};
use routing::{Data, DataIdentifier, Event, MessageId, Response, XorName};
use routing::client_errors::{GetError, MutationError};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::sync::mpsc::{Receiver, Sender};

const EVENT_RECEIVER_THREAD_NAME: &'static str = "EventReceiverThread";

/// `MessageQueue` gets and collects messages/responses from routing. It also maintains local
/// caching of previously fetched `ImmutableData` (because the very nature of such data implies
/// Immutability) enabling fast re-retrieval and avoiding networking.
pub struct MessageQueue {
    local_cache: LruCache<XorName, Data>,
    network_event_observers: Vec<Sender<NetworkEvent>>,
    response_observers: HashMap<MessageId, Sender<ResponseEvent>>,
}

fn handle_response(response: Response, mut queue_guard: MutexGuard<MessageQueue>) {
    match response {
        Response::GetSuccess(data, id) => {
            if let Some(response_observer) = queue_guard.response_observers.remove(&id) {
                let _ = response_observer.send(ResponseEvent::GetResp(Ok(data)));
            }
        }
        Response::GetFailure {
            id,
            data_id,
            external_error_indicator,
        } => {
            if let Some(response_observer) = queue_guard.response_observers.remove(&id) {
                let reason: GetError = match deserialise(&external_error_indicator) {
                    Ok(err) => err,
                    Err(err) => {
                        let err_msg = format!("Couldn't obtain GET Failure reason: {:?}", err);
                        warn!("{}", err_msg);
                        GetError::NetworkOther(err_msg)
                    }
                };
                let err = Err(CoreError::GetFailure {
                                  data_id: data_id,
                                  reason: reason,
                              });
                let _ = response_observer.send(ResponseEvent::GetResp(err));
            }
        }
        Response::PutSuccess(_, id) |
        Response::PostSuccess(_, id) |
        Response::DeleteSuccess(_, id) |
        Response::AppendSuccess(_, id) => {
            if let Some(response_observer) = queue_guard.response_observers.remove(&id) {
                let _ = response_observer.send(ResponseEvent::MutationResp(Ok(())));
            }
        }
        Response::PutFailure {
            id,
            data_id,
            external_error_indicator,
        } => {
            if let Some(response_observer) = queue_guard.response_observers.remove(&id) {
                let err = parse_mutation_failure(external_error_indicator, data_id, "PUT");
                let _ = response_observer.send(ResponseEvent::MutationResp(Err(err)));
            }
        }
        Response::PostFailure {
            id,
            data_id,
            external_error_indicator,
        } => {
            if let Some(response_observer) = queue_guard.response_observers.remove(&id) {
                let err = parse_mutation_failure(external_error_indicator, data_id, "POST");
                let _ = response_observer.send(ResponseEvent::MutationResp(Err(err)));
            }
        }
        Response::DeleteFailure {
            id,
            data_id,
            external_error_indicator,
        } => {
            if let Some(response_observer) = queue_guard.response_observers.remove(&id) {
                let err = parse_mutation_failure(external_error_indicator, data_id, "DELETE");
                let _ = response_observer.send(ResponseEvent::MutationResp(Err(err)));
            }
        }
        Response::AppendFailure {
            id,
            data_id,
            external_error_indicator,
        } => {
            if let Some(response_observer) = queue_guard.response_observers.remove(&id) {
                let err = parse_mutation_failure(external_error_indicator, data_id, "APPEND");
                let _ = response_observer.send(ResponseEvent::MutationResp(Err(err)));
            }
        }
        Response::GetAccountInfoSuccess {
            id,
            data_stored,
            space_available,
        } => {
            if let Some(response_observer) = queue_guard.response_observers.remove(&id) {
                let _ =
                    response_observer
                        .send(ResponseEvent::GetAccountInfoResp(Ok((data_stored,
                                                                    space_available))));
            }
        }
        Response::GetAccountInfoFailure {
            id,
            external_error_indicator,
        } => {
            if let Some(response_observer) = queue_guard.response_observers.remove(&id) {
                let reason: GetError = match deserialise(&external_error_indicator) {
                    Ok(err) => err,
                    Err(err) => {
                        let err_msg = format!("Couldn't obtain GetAccountInfoFailure reason: {:?}",
                                              err);
                        warn!("{}", err_msg);
                        GetError::NetworkOther(err_msg)
                    }
                };
                let err = Err(CoreError::GetAccountInfoFailure { reason: reason });
                let _ = response_observer.send(ResponseEvent::GetAccountInfoResp(err));
            }
        }
    }
}

impl MessageQueue {
    /// Create a new instance of MessageQueue. `data_senders` can be added later via function to
    /// add observer since one will not receive data until one asks for it. Thus there is enough
    /// chance to add an observer before requesting data.
    pub fn new(routing_event_receiver: Receiver<Event>,
               network_event_observers: Vec<Sender<NetworkEvent>>)
               -> (Arc<Mutex<MessageQueue>>, Joiner) {
        let message_queue = Arc::new(Mutex::new(MessageQueue {
                                                    local_cache: LruCache::new(1000),
                                                    network_event_observers:
                                                        network_event_observers,
                                                    response_observers: HashMap::new(),
                                                }));

        let message_queue_cloned = message_queue.clone();
        let receiver_joiner =
            thread::named(EVENT_RECEIVER_THREAD_NAME,
                          move || for it in routing_event_receiver.iter() {
                              trace!("{} received: {:?}", EVENT_RECEIVER_THREAD_NAME, it);

                              match it {
                                  Event::Response { response, .. } => {
                    handle_response(response, unwrap!(message_queue_cloned.lock()));
                }
                                  Event::Connected => {
                    let mut dead_sender_positions = Vec::<usize>::new();
                    let mut queue_guard = unwrap!(message_queue_cloned.lock());
                    for it in queue_guard.network_event_observers.iter().enumerate() {
                        if it.1.send(NetworkEvent::Connected).is_err() {
                            dead_sender_positions.push(it.0);
                        }
                    }

                    MessageQueue::purge_dead_senders(&mut queue_guard.network_event_observers,
                                                     dead_sender_positions);
                }
                                  Event::Terminate => {
                    let mut dead_sender_positions = Vec::<usize>::new();
                    let mut queue_guard = unwrap!(message_queue_cloned.lock());
                    info!("Received a Terminate event. Informing {} observers.",
                          queue_guard.network_event_observers.len());
                    for it in queue_guard.network_event_observers.iter().enumerate() {
                        if it.1.send(NetworkEvent::Disconnected).is_err() {
                            dead_sender_positions.push(it.0);
                        }
                    }

                    MessageQueue::purge_dead_senders(&mut queue_guard.network_event_observers,
                                                     dead_sender_positions);
                }
                                  _ => debug!("Received unsupported routing event: {:?}.", it),
                              }
                          });

        (message_queue, receiver_joiner)
    }

    pub fn register_response_observer(&mut self,
                                      msg_id: MessageId,
                                      sender: Sender<ResponseEvent>) {
        let _ = self.response_observers.insert(msg_id, sender);
    }

    pub fn add_network_event_observer(&mut self, sender: Sender<NetworkEvent>) {
        self.network_event_observers.push(sender);
    }

    pub fn local_cache_check(&mut self, key: &XorName) -> bool {
        self.local_cache.contains_key(key)
    }

    pub fn local_cache_get(&mut self, key: &XorName) -> Result<Data, CoreError> {
        self.local_cache
            .get_mut(key)
            .ok_or(CoreError::VersionCacheMiss)
            .map(|elt| elt.clone())
    }

    pub fn local_cache_insert(&mut self, key: XorName, value: Data) {
        let _ = self.local_cache.insert(key, value);
    }

    fn purge_dead_senders<T>(senders: &mut Vec<Sender<T>>, positions: Vec<usize>) {
        for (delta, val) in positions.into_iter().enumerate() {
            let _ = senders.remove(val - delta);
        }
    }
}

fn parse_mutation_failure(external_error_indicator: Vec<u8>,
                          data_id: DataIdentifier,
                          op: &str)
                          -> CoreError {
    let reason: MutationError = match deserialise(&external_error_indicator) {
        Ok(err) => err,
        Err(err) => {
            let err_msg = format!("Couldn't obtain {} failure reason: {:?}", op, err);
            warn!("{}", err_msg);
            MutationError::NetworkOther(err_msg)
        }
    };

    CoreError::MutationFailure {
        data_id: data_id,
        reason: reason,
    }
}
