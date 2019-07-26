// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

// TODO - remove this.
#![allow(unused)]

mod connection_group;

use crate::{client::NewFullId, CoreError};
use connection_group::ConnectionGroup;
use crossbeam_channel::Receiver;
use futures::{future, Future};
use quic_p2p::{self, Config as QuicP2pConfig, Event, NodeInfo, Peer, QuicP2p};
use safe_nd::{PublicId, Response};
use std::collections::HashMap;

/// Initialises QuicP2p instance. Establishes new connections.
/// Contains a reference to crossbeam channel provided by quic-p2p for capturing the events.
pub(crate) struct ConnectionManager {
    quic_p2p: QuicP2p,
    quic_p2p_events_rx: Receiver<Event>,
    groups: HashMap<PublicId, ConnectionGroup>,
}

impl ConnectionManager {
    pub fn new(config: &QuicP2pConfig) -> Self {
        // 1. build QuicP2p object.
        // 2. start an event loop passing quic-p2p events to the core event loop, triggering the future task.
        unimplemented!();
    }

    pub fn send(
        &mut self,
        pub_id: &PublicId,
        msg: &[u8],
    ) -> impl Future<Item = Response, Error = CoreError> {
        // 1. Get the connection group, either from `self.groups` or connect if need be.
        // 2. Call `group.send()`.
        future::err(CoreError::Unexpected("unimplemented".to_string()))
    }

    pub fn connect(&mut self, full_id: &NewFullId) -> impl Future<Item = (), Error = CoreError> {
        // 1. handle the initial handshake process (responding to the challenge etc.)
        // 2. return a new connection
        future::err(CoreError::Unexpected("unimplemented".to_string()))
    }

    fn handle_quic_p2p_event(&mut self, event: Event) {
        // should handle new messages sent by vault (assuming it's only the `Challenge::Request` or `Response` for now)
        // if the message is found to be related to a certain `ConnectionGroup`, `connection_group.handle_response(sender, token, response)` should be called.
        unimplemented!();
    }
}
