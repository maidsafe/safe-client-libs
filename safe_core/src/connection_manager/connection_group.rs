// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

// TODO - remove this.
#![allow(dead_code)]

use crate::{client::NewFullId, CoreError, CoreFuture};
use bytes::Bytes;
use futures::{
    future,
    sync::oneshot::{self, Sender},
    Future,
};
use maidsafe_utilities::serialisation::{deserialise, serialise};
use new_rand::Rng;
use quic_p2p::{self, NodeInfo, Peer, QuicP2p};
use safe_nd::{Challenge, Message, MessageId, NodePublicId, PublicId, Response};
use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    net::SocketAddr,
    rc::Rc,
};

// Represents a connection or connection attempt to one of the group's elder vaults.  `public_id`
// will be `None` if we haven't received the `Challenge::Request` from this vault yet.
#[derive(Clone)]
struct Elder {
    peer: Peer,
    public_id: Option<NodePublicId>,
}

impl Elder {
    fn new(node_info: NodeInfo) -> Self {
        Self {
            peer: Peer::Node { node_info },
            public_id: None,
        }
    }

    fn peer(&self) -> Peer {
        self.peer.clone()
    }
}

/// Encapsulates multiple QUIC connections with a group of Client Handlers.
/// Accumulates responses. During Phase 1 connects only to a single vault.
pub(super) struct ConnectionGroup {
    full_id: NewFullId,
    elders: HashMap<SocketAddr, Elder>,
    hooks: HashMap<MessageId, Sender<Response>>, // to be replaced with Accumulator for multiple vaults.
    quic_p2p: Rc<RefCell<QuicP2p>>,
}

impl ConnectionGroup {
    pub fn new(
        full_id: NewFullId,
        mut elders: HashSet<NodeInfo>,
        quic_p2p: Rc<RefCell<QuicP2p>>,
    ) -> Self {
        Self {
            full_id,
            elders: elders
                .drain()
                .map(|node_info| (node_info.peer_addr, Elder::new(node_info)))
                .collect(),
            hooks: Default::default(),
            quic_p2p,
        }
    }

    pub fn send(&mut self, msg_id: MessageId, msg: &Message) -> Box<CoreFuture<Response>> {
        let mut rng = new_rand::thread_rng();
        let bytes = Bytes::from(unwrap!(serialise(msg)));
        for peer in self.elders.values().map(Elder::peer) {
            let token = rng.gen();
            self.quic_p2p.borrow_mut().send(peer, bytes.clone(), token);
        }

        let (future_tx, future_rx) = oneshot::channel();
        let _ = self.hooks.insert(msg_id, future_tx);
        Box::new(future_rx.map_err(|_| CoreError::OperationAborted))
    }

    pub fn handle_bootstrapped_to(&mut self, node_info: NodeInfo) {
        let _ = self
            .elders
            .insert(node_info.peer_addr, Elder::new(node_info));
    }

    pub fn handle_new_message(&mut self, peer_addr: SocketAddr, msg: Bytes) {
        let have_handled_challenge = self
            .elders
            .get(&peer_addr)
            .map(|elder| elder.public_id.is_some())
            .unwrap_or(false);

        if have_handled_challenge {
            if let Ok(Message::Response {
                response,
                message_id,
            }) = deserialise(&msg)
            {
                self.handle_response(peer_addr, message_id, response)
            }
        } else if let Ok(Challenge::Request(PublicId::Node(node_public_id), challenge)) =
            deserialise(&msg)
        {
            self.handle_challenge(peer_addr, node_public_id, challenge);
        }
    }

    /// Handle a response from one of the elders.
    /// `_sender` is unused because we don't need to handle elder groups during the Phase 1.
    fn handle_response(&mut self, _sender_addr: SocketAddr, msg_id: MessageId, response: Response) {
        let _ = self
            .hooks
            .remove(&msg_id)
            .map(|sender| sender.send(response));
    }

    /// Handle a challenge request from a newly-connected vault.
    fn handle_challenge(
        &mut self,
        sender_addr: SocketAddr,
        sender_id: NodePublicId,
        challenge: Vec<u8>,
    ) {
        // safe to unwrap as we just found this elder before calling this method.
        let mut elder = unwrap!(self.elders.get_mut(&sender_addr));
        elder.public_id = Some(sender_id);
        let token = new_rand::thread_rng().gen();
        let response = Challenge::Response(self.full_id.public_id(), self.full_id.sign(&challenge));
        let msg = Bytes::from(unwrap!(serialise(&response)));
        self.quic_p2p
            .borrow_mut()
            .send(elder.peer.clone(), msg, token);
    }

    /// Terminate the QUIC connections.
    pub fn close(&mut self) -> impl Future<Item = (), Error = CoreError> {
        future::err(CoreError::Unexpected("unimplemented".to_string()))
    }

    pub fn has_peer(&self, peer_addr: &SocketAddr) -> bool {
        self.elders.contains_key(peer_addr)
    }
}
