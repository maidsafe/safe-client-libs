// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

// TODO - remove this.
#![allow(dead_code)]

use crate::{client::SafeKey, utils, CoreError, CoreFuture};
use bincode::{deserialize, serialize};
use bytes::Bytes;
use futures::{
    sync::oneshot::{self, Sender},
    Future,
};
use lazy_static::lazy_static;
use new_rand::Rng;
use quic_p2p::{self, Error as QuicP2pError, NodeInfo, Peer, QuicP2p, Token};
use safe_nd::{Challenge, Message, MessageId, NodePublicId, PublicId, Request, Response};
use std::sync::atomic::{AtomicU64, Ordering};
use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::prelude::FutureExt;

/// Request timeout in seconds.
pub const REQUEST_TIMEOUT_SECS: u64 = 180;

lazy_static! {
    static ref GROUP_COUNTER: AtomicU64 = AtomicU64::new(0);
}

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
    full_id: SafeKey,
    elders: HashMap<SocketAddr, Elder>,
    hooks: HashMap<MessageId, Sender<Response>>, // to be replaced with Accumulator for multiple vaults.
    quic_p2p: Arc<Mutex<QuicP2p>>,
    connection_hook: Option<Sender<Result<(), CoreError>>>,
    disconnect_tx: Option<Sender<()>>,
    pub(super) id: u64,
}

impl ConnectionGroup {
    pub fn new(
        full_id: SafeKey,
        mut elders: HashSet<NodeInfo>,
        quic_p2p: Arc<Mutex<QuicP2p>>,
        connection_hook: Sender<Result<(), CoreError>>,
    ) -> Self {
        Self {
            full_id,
            elders: elders
                .drain()
                .map(|node_info| (node_info.peer_addr, Elder::new(node_info)))
                .collect(),
            hooks: Default::default(),
            quic_p2p,
            connection_hook: Some(connection_hook),
            disconnect_tx: None,
            id: GROUP_COUNTER.fetch_add(1, Ordering::SeqCst),
        }
    }

    pub fn send(&mut self, msg_id: MessageId, msg: &Message) -> Box<CoreFuture<Response>> {
        let mut rng = new_rand::thread_rng();

        trace!("Sending message {:?}", msg_id);

        let (future_tx, future_rx) = oneshot::channel();
        let _ = self.hooks.insert(msg_id, future_tx);

        let bytes = Bytes::from(unwrap!(serialize(msg)));
        {
            let mut qp2p = unwrap!(self.quic_p2p.lock());

            for peer in self.elders.values().map(Elder::peer) {
                let token = rng.gen();
                qp2p.send(peer, bytes.clone(), token);
            }
        }

        Box::new(
            future_rx
                .timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS))
                .map_err(|_e| CoreError::RequestTimeout), // .then(move |result| {
                                                          //     if let Some(inner) = inner_weak.upgrade() {
                                                          //         let _ = inner.borrow_mut().hooks.remove(&msg_id);
                                                          //     }
                                                          //     result
                                                          // }),
        )
    }

    pub fn handle_bootstrap_failure(&mut self) {
        let _ = self
            .connection_hook
            .take()
            .map(|hook| hook.send(Err(CoreError::from(format!("Bootstrap failure")))));
    }

    pub fn handle_bootstrapped_to(&mut self, node_info: NodeInfo) {
        trace!("{}: Bootstrapped", self.id);
        let _ = self
            .elders
            .insert(node_info.peer_addr, Elder::new(node_info));
    }

    pub fn handle_connection_failure(&mut self, peer_addr: SocketAddr, err: QuicP2pError) {
        if let QuicP2pError::ConnectionCancelled = err {
            if let Some(tx) = self.disconnect_tx.take() {
                trace!("{}: Successfully disconnected", self.id);
                let _ = tx.send(());
                return;
            }
        }
        trace!(
            "{}: Recvd connection failure for {}, {}",
            self.id,
            peer_addr,
            err
        );
    }

    pub fn handle_sent_user_message(&mut self, _peer_addr: SocketAddr, _msg: Bytes, _token: Token) {
        // TODO: check if we have handled the challenge?
        trace!("{}: Sent user message", self.id);
    }

    pub fn handle_unsent_user_message(&mut self, peer_addr: SocketAddr, msg: Bytes, token: Token) {
        // TODO: check if we have handled the challenge?

        match deserialize(&msg) {
            Ok(Message::Request {
                request,
                message_id,
                ..
            }) => self.handle_unsent_request(peer_addr, request, message_id, token),
            Ok(_) => println!("Unexpected message type"),
            Err(e) => println!("Unexpected error {:?}", e),
        }
    }

    fn handle_unsent_request(
        &mut self,
        _peer_addr: SocketAddr,
        _request: Request,
        _message_id: MessageId,
        _token: Token,
    ) {
        trace!("{}: Not sent user message", self.id);
        // TODO: unimplemented
    }

    pub fn handle_new_message(&mut self, peer_addr: SocketAddr, msg: Bytes) {
        let have_handled_challenge = self
            .elders
            .get(&peer_addr)
            .map(|elder| elder.public_id.is_some())
            .unwrap_or(false);

        trace!(
            "{}: Message from {:?}: {}. We have handled challenge? {:?}",
            self.id,
            peer_addr,
            utils::bin_data_format(&msg),
            have_handled_challenge
        );

        if have_handled_challenge {
            match deserialize(&msg) {
                Ok(Message::Response {
                    response,
                    message_id,
                }) => self.handle_response(peer_addr, message_id, response),
                Ok(Message::Notification { notification }) => {
                    trace!("Got transaction notification: {:?}", notification);
                }
                Ok(_msg) => error!("Unexpected message type, expected response."),
                Err(e) => {
                    if let Ok(_x) = deserialize::<Challenge>(&msg) {
                        error!("Unexpected challenge, expected response ({:?}).", e);
                    } else {
                        error!("Unexpected error {:?}", e);
                    }
                }
            }
        } else {
            match deserialize(&msg) {
                Ok(Challenge::Request(PublicId::Node(node_public_id), challenge)) => {
                    trace!("Got the challenge");
                    self.handle_challenge(peer_addr, node_public_id, challenge)
                }
                Ok(_msg) => error!("Unexpected message type, expected challenge."),
                Err(e) => error!("Unexpected error {:?}", e),
            }
        }
    }

    /// Handle a response from one of the elders.
    /// `_sender` is unused because we don't need to handle elder groups during the Phase 1.
    fn handle_response(&mut self, sender_addr: SocketAddr, msg_id: MessageId, response: Response) {
        trace!(
            "{}: Response from: {:?}, msg_id: {:?}, resp: {:?}",
            self.id,
            sender_addr,
            msg_id,
            response
        );
        let _ = self
            .hooks
            .remove(&msg_id)
            .map(|sender| sender.send(response))
            .or_else(|| {
                info!(
                    "{}: {:?} - No hook found for message ID {:?}",
                    self.id,
                    self.full_id.public_id(),
                    msg_id
                );
                None
            });
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
        let msg = Bytes::from(unwrap!(serialize(&response)));
        unwrap!(self.quic_p2p.lock()).send(elder.peer.clone(), msg, token);
        // trigger the connection future
        let _ = self.connection_hook.take().map(|hook| hook.send(Ok(())));
    }

    /// Terminate the QUIC connections gracefully.
    pub fn close(&mut self) -> Box<CoreFuture<()>> {
        trace!("{}: Terminating connection", self.id);

        let (disconnect_tx, disconnect_rx) = futures::oneshot();
        self.terminate();
        self.disconnect_tx = Some(disconnect_tx);

        Box::new(disconnect_rx.map_err(|e| CoreError::Unexpected(format!("{}", e))))
    }

    /// Ask quic-p2p to disconnect this group without waiting on it.
    /// Use for `ConnectionManager::drop` only!
    pub(super) fn terminate(&mut self) {
        let mut qp2p = unwrap!(self.quic_p2p.lock());
        for peer in self.elders.values().map(Elder::peer) {
            qp2p.disconnect_from(peer.peer_addr());
        }
    }

    pub fn has_peer(&self, peer_addr: &SocketAddr) -> bool {
        self.elders.contains_key(peer_addr)
    }
}
