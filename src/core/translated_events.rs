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

use core::errors::CoreError;
use routing::Data;

/// Network Events will be translated into values starting from this number for propagating them
/// beyond the FFI boudaries when required
pub const NETWORK_EVENT_START_RANGE: i32 = 0;

/// These events are received as a response to a GET/PUT/POST/DELETE requests made by clients
pub enum ResponseEvent {
    /// Response to a previous GET request
    GetResp(Result<Data, CoreError>),
    /// Response to a previous Mutating (PUT/POST/DELETE) request
    MutationResp(Result<(), CoreError>),
    /// Graceful Exit Condition
    Terminated,
}

/// Netowork Events that Client Modules need to deal with
pub enum NetworkEvent {
    /// The client engine is connected to atleast one peer
    Connected,
    /// The client engine is disconnected from the network (under usual circumstances this would
    /// indicate that client connection to proxy node has been lost)
    Disconnected,
    /// Graceful Exit Condition
    Terminated,
}

impl Into<i32> for NetworkEvent {
    fn into(self) -> i32 {
        match self {
            NetworkEvent::Connected => NETWORK_EVENT_START_RANGE,
            NetworkEvent::Disconnected => NETWORK_EVENT_START_RANGE + 1,
            NetworkEvent::Terminated => NETWORK_EVENT_START_RANGE + 2,
        }
    }
}
