// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

// TODO - remove this.
#![allow(unused)]

use crate::{CoreError, CoreFuture};
use bytes::Bytes;
use futures::{
    future,
    sync::oneshot::{self, Sender},
    Future,
};
use new_rand::Rng;
use quic_p2p::{self, Config as QuicP2pConfig, Event, NodeInfo, Peer, QuicP2p, Token};
use safe_nd::Response;
use std::collections::HashMap;

/// Encapsulates multiple QUIC connections with a group of Client Handlers.
/// Accumulates responses. During Phase 1 connects only to a single vault.
pub(super) struct ConnectionGroup {
    elders: Vec<NodeInfo>,
    hooks: HashMap<Token, Sender<Response>>, // to be replaced with Accumulator for multiple vaults.
}

impl ConnectionGroup {
    pub fn new() -> Self {
        Self {
            elders: Default::default(),
            hooks: Default::default(),
        }
    }

    pub fn send(&mut self, quic_p2p: &mut QuicP2p, msg: &[u8]) -> Box<CoreFuture<Response>> {
        // 1. generate a random `quic_p2p::Token`.
        let token = new_rand::thread_rng().gen();

        // 2. send the signed message.
        for node_info in self.elders.iter().cloned() {
            quic_p2p.send(Peer::Node { node_info }, Bytes::from(msg), token);
        }

        // 3. bind a future & its task to the token generated at step 1.
        let (future_tx, future_rx) = oneshot::channel();
        let _ = self.hooks.insert(token, future_tx);
        // future_rx
        Box::new(future::err(CoreError::Unexpected(
            "unimplemented".to_string(),
        )))
    }

    /// Handle a response from one of the elders.
    /// `_sender` is unused because we don't need to handle elder groups during the Phase 1.
    pub fn handle_response(&mut self, _sender: NodeInfo, token: Token, response: Response) {
        let _ = self
            .hooks
            .remove(&token)
            .map(|sender| sender.send(response));
    }

    /// Terminate the QUIC connections.
    pub fn close(&mut self) -> impl Future<Item = (), Error = CoreError> {
        future::err(CoreError::Unexpected("unimplemented".to_string()))
    }
}
