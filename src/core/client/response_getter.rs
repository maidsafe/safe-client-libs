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

use std::sync::{Arc, Mutex};
use std::sync::mpsc::{Receiver, Sender};

use core::client::message_queue::MessageQueue;
use core::errors::CoreError;
use core::translated_events::ResponseEvent;
use routing::{Data, DataIdentifier, XorName};

/// GetResponseGetter is a lazy evaluated response getter for GET Requests. It will fetch either
/// from local cache or wait for the MessageQueue to notify it of the incoming response from the
/// network
pub struct GetResponseGetter {
    data_channel: Option<(Sender<ResponseEvent>, Receiver<ResponseEvent>)>,
    message_queue: Arc<Mutex<MessageQueue>>,
    requested_name: XorName,
    requested_id: DataIdentifier,
}

impl GetResponseGetter {
    /// Create a new instance of GetResponseGetter
    pub fn new(data_channel: Option<(Sender<ResponseEvent>, Receiver<ResponseEvent>)>,
               message_queue: Arc<Mutex<MessageQueue>>,
               requested_id: DataIdentifier)
               -> GetResponseGetter {
        GetResponseGetter {
            data_channel: data_channel,
            message_queue: message_queue,
            requested_name: requested_id.name(),
            requested_id: requested_id,
        }
    }

    /// Get either from local cache or (if not available there) get it when it comes from the
    /// network as informed by MessageQueue. This is blocking.
    pub fn get(&self) -> Result<Data, CoreError> {
        if let Some((_, ref data_receiver)) = self.data_channel {
            match try!(data_receiver.recv()) {
                ResponseEvent::GetResp(result) => {
                    let data = try!(result);
                    if let DataIdentifier::Immutable(..) = self.requested_id {
                        let mut msg_queue = unwrap!(self.message_queue.lock());
                        msg_queue.local_cache_insert(self.requested_name, data.clone());
                    }

                    Ok(data)
                }
                ResponseEvent::Terminated => Err(CoreError::OperationAborted),
                _ => Err(CoreError::ReceivedUnexpectedData),
            }
        } else {
            let mut msg_queue = unwrap!(self.message_queue.lock());
            msg_queue.local_cache_get(&self.requested_name)
        }
    }

    /// Extract associated sender. This will help cancel the blocking wait at will if so desired.
    /// All that is needed is to extract the sender before doing a `get()` and then while blocking
    /// on `get()` fire `sender.send(ResponseEvent::Terminated)` to gracefully exit the receiver.
    pub fn get_sender(&self) -> Option<&Sender<ResponseEvent>> {
        self.data_channel.as_ref().and_then(|&(ref sender, _)| Some(sender))
    }
}

/// MutationResponseGetter is a lazy evaluated response getter for mutating network requests such
/// as PUT/POST/DELETE. It will fetch either from local cache or wait for the MessageQueue to notify
/// it of the incoming response from the network
pub struct MutationResponseGetter {
    data_channel: (Sender<ResponseEvent>, Receiver<ResponseEvent>),
}

impl MutationResponseGetter {
    /// Create a new instance of MutationResponseGetter
    pub fn new(data_channel: (Sender<ResponseEvent>, Receiver<ResponseEvent>))
               -> MutationResponseGetter {
        MutationResponseGetter { data_channel: data_channel }
    }

    /// Get response when it comes from the network as informed by MessageQueue. This is blocking
    pub fn get(&self) -> Result<(), CoreError> {
        let (_, ref data_receiver) = self.data_channel;
        match try!(data_receiver.recv()) {
            ResponseEvent::MutationResp(result) => result,
            ResponseEvent::Terminated => Err(CoreError::OperationAborted),
            _ => Err(CoreError::ReceivedUnexpectedData),
        }
    }

    /// Extract associated sender. This will help cancel the blocking wait at will if so desired.
    /// All that is needed is to extract the sender before doing a `get()` and then while blocking
    /// on `get()` fire `sender.send(ResponseEvent::Terminated)` to gracefully exit the receiver.
    pub fn get_sender(&self) -> &Sender<ResponseEvent> {
        &self.data_channel.0
    }
}
