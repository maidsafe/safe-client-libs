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

use errors::CoreError;
use xor_name::XorName;
use routing::{DataRequest, Data};
use std::sync::{Arc, Mutex, mpsc};
use client::message_queue::MessageQueue;

/// ResponseGetter is a lazy evaluated response getter. It will fetch either from local cache or
/// wait for the MessageQueue to notify it of the incoming response from the network.
pub struct ResponseGetter {
    data_channel: Option<(mpsc::Sender<::translated_events::DataReceivedEvent>,
                          mpsc::Receiver<::translated_events::DataReceivedEvent>)>,
    message_queue: Arc<Mutex<MessageQueue>>,
    requested_name: XorName,
    requested_type: DataRequest,
}

impl ResponseGetter {
    /// Create a new instance of ResponseGetter
    pub fn new(data_channel: Option<(mpsc::Sender<::translated_events::DataReceivedEvent>,
                                     mpsc::Receiver<::translated_events::DataReceivedEvent>)>,
               message_queue: Arc<Mutex<MessageQueue>>,
               requested_type: DataRequest)
               -> ResponseGetter {
        ResponseGetter {
            data_channel: data_channel,
            message_queue: message_queue,
            requested_name: requested_type.name(),
            requested_type: requested_type,
        }
    }

    /// Get either from local cache or (if not available there) get it when it comes from the
    /// network as informed by MessageQueue. This is blocking.
    pub fn get(&self) -> Result<Data, CoreError> {
        if let Some((_, ref data_receiver)) = self.data_channel {
            match try!(data_receiver.recv()) {
                ::translated_events::DataReceivedEvent::DataReceived => {
                    let mut msg_queue = unwrap_result!(self.message_queue.lock());
                    let response = try!(msg_queue.get_response(&self.requested_name));

                    if let DataRequest::Immutable(..) = self.requested_type {
                        msg_queue.local_cache_insert(self.requested_name.clone(), response.clone());
                    }

                    Ok(response)
                }
            }
        } else {
            let mut msg_queue = unwrap_result!(self.message_queue.lock());
            msg_queue.local_cache_get(&self.requested_name)
        }
    }

    /// Extract associated sender. This will help cancel the blocking wait at will if so desired.
    /// All that is needed is to extract the sender before doing a `get()` and then while blocking
    /// on `get()` fire `sender.send(::translated_events::DataReceivedEvent::Terminated)` to
    /// gracefully exit the receiver.
    pub fn get_sender(&self) -> Option<&mpsc::Sender<::translated_events::DataReceivedEvent>> {
        self.data_channel.as_ref().and_then(|&(ref sender, _)| Some(sender))
    }
}
