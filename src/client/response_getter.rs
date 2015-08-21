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

/// ResponseGetter is a lazy evaluated response getter. It will fetch either from local cache or
/// wait for the MessageQueue to notify it of the incoming response from the network.
pub struct ResponseGetter {
    response_notifier: Option<::client::misc::ResponseNotifier>,
    message_queue    : ::std::sync::Arc<::std::sync::Mutex<::client::message_queue::MessageQueue>>,
    requested_name   : ::routing::NameType,
    requested_type   : ::routing::data::DataRequest,
}

impl ResponseGetter {
    /// Create a new instance of ResponseGetter
    pub fn new(notifier      : Option<::client::misc::ResponseNotifier>,
               message_queue : ::std::sync::Arc<::std::sync::Mutex<::client::message_queue::MessageQueue>>,
               requested_name: ::routing::NameType,
               requested_type: ::routing::data::DataRequest) -> ResponseGetter {
        ResponseGetter {
            response_notifier: notifier,
            message_queue    : message_queue,
            requested_name   : requested_name,
            requested_type   : requested_type,
        }
    }

    /// Get either from local cache or (if not available there) get it when it comes from the
    /// network as informed by MessageQueue. This is blocking.
    pub fn get(&self) -> Result<::routing::data::Data, ::errors::ClientError> {
        if let Some(ref notifier) = self.response_notifier {
            let (ref lock, ref condition_var) = **notifier;
            let mut mutex_guard: _;

            {
                let mut msg_queue = self.message_queue.lock().unwrap();
                match msg_queue.get_response(&self.requested_name) {
                    Ok(response) => return Ok(response),
                    Err(_) => {
                        mutex_guard = lock.lock().unwrap();
                        if *mutex_guard == Some(self.requested_name.clone()) {
                            *mutex_guard = None;
                        }
                    },
                }
            }

            let valid_condition = Some(self.requested_name.clone());
            while *mutex_guard != valid_condition {
                mutex_guard = condition_var.wait(mutex_guard).unwrap();
            }

            let mut msg_queue = self.message_queue.lock().unwrap();
            let response = try!(msg_queue.get_response(&self.requested_name));

            if let ::routing::data::DataRequest::ImmutableData(..) = self.requested_type {
                msg_queue.local_cache_insert(self.requested_name.clone(), response.clone());
            }

            Ok(response)
        } else {
            let mut msg_queue = self.message_queue.lock().unwrap();
            Ok(try!(msg_queue.local_cache_get(&self.requested_name)))
        }
    }
}
