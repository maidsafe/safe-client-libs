// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use futures::channel::mpsc;

/// Network Events will be translated into values starting from this number for
/// propagating them beyond the FFI boudaries when required
pub const NETWORK_EVENT_START_RANGE: i32 = 0;

/// Network Events that Client Modules need to deal with.
#[derive(Debug)]
pub enum NetworkEvent {
    /// The core engine is connected to atleast one peer
    Connected,
    /// The core engine is disconnected from the network (under usual
    /// circumstances this would indicate that client connection to proxy node
    /// has been lost)
    Disconnected,
}

impl Into<i32> for NetworkEvent {
    fn into(self) -> i32 {
        match self {
            Self::Connected => NETWORK_EVENT_START_RANGE,
            Self::Disconnected => NETWORK_EVENT_START_RANGE - 1,
        }
    }
}

/// `NetworkEvent` receiver stream.
pub type NetworkRx = mpsc::UnboundedReceiver<NetworkEvent>;
/// `NetworkEvent` transmitter.
pub type NetworkTx = mpsc::UnboundedSender<NetworkEvent>;
