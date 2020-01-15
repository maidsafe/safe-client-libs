// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{client::SafeKey, utils, CoreError, CoreFuture};
use bincode::{deserialize, serialize};
use bytes::Bytes;
use crossbeam_channel::{self, Receiver};
use futures::{
    sync::oneshot::{self, Sender},
    Future,
};
use lazy_static::lazy_static;
use log::{error, info, trace};
use quic_p2p::{
    self, Builder, Config as QuicP2pConfig, Error as QuicP2pError, Event, NodeInfo, Peer, QuicP2p,
    Token,
};
use rand::Rng;
use safe_nd::{Challenge, Message, MessageId, NodePublicId, PublicId, Request, Response};
use std::sync::atomic::{AtomicU64, Ordering};
use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    sync::{Arc, Mutex},
    thread::{self, JoinHandle},
    time::Duration,
};
use tokio::prelude::FutureExt;
use unwrap::unwrap;

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
    inner: Arc<Mutex<Inner>>,
}

impl ConnectionGroup {
    pub fn new(
        config: QuicP2pConfig,
        full_id: SafeKey,
        mut elders: HashSet<NodeInfo>,
        connection_hook: Sender<Result<(), CoreError>>,
    ) -> Result<Self, CoreError> {
        let (event_tx, event_rx) = crossbeam_channel::unbounded();

        let mut quic_p2p = Builder::new(event_tx).with_config(config).build()?;
        quic_p2p.bootstrap();

        let inner = Arc::new(Mutex::new(Inner {
            quic_p2p,
            full_id,
            hooks: HashMap::<MessageId, Sender<Response>>::default(),
            connection_hook: Some(connection_hook),
            disconnect_tx: None,
            elders: elders
                .drain()
                .map(|node_info| (node_info.peer_addr, Elder::new(node_info)))
                .collect(),
            id: GROUP_COUNTER.fetch_add(1, Ordering::SeqCst),
        }));

        let _ = setup_quic_p2p_event_loop(&inner, event_rx);

        Ok(Self { inner })
    }

    pub fn send(&mut self, msg_id: MessageId, msg: &Message) -> Box<CoreFuture<Response>> {
        unwrap!(self.inner.lock()).send(msg_id, msg)
    }

    /// Terminate the QUIC connections gracefully.
    pub fn close(&mut self) -> Box<CoreFuture<()>> {
        unwrap!(self.inner.lock()).close()
    }
}

struct Inner {
    quic_p2p: QuicP2p,
    full_id: SafeKey,
    elders: HashMap<SocketAddr, Elder>,
    // TODO: to be replaced with Accumulator for multiple vaults.
    hooks: HashMap<MessageId, Sender<Response>>,
    connection_hook: Option<Sender<Result<(), CoreError>>>,
    disconnect_tx: Option<Sender<()>>,
    id: u64,
}

impl Drop for Inner {
    fn drop(&mut self) {
        for peer in self.elders.values().map(Elder::peer) {
            self.quic_p2p.disconnect_from(peer.peer_addr());
        }
        thread::sleep(Duration::from_millis(50));
    }
}

impl Inner {
    fn terminate(&mut self) {
        for peer in self.elders.values().map(Elder::peer) {
            self.quic_p2p.disconnect_from(peer.peer_addr());
        }
    }

    fn send(&mut self, msg_id: MessageId, msg: &Message) -> Box<CoreFuture<Response>> {
        trace!("Sending message {:?}", msg_id);
        let mut rng = rand::thread_rng();

        let (future_tx, future_rx) = oneshot::channel();
        let _ = self.hooks.insert(msg_id, future_tx);

        let bytes = Bytes::from(unwrap!(serialize(msg)));
        {
            for peer in self.elders.values().map(Elder::peer) {
                let token = rng.gen();
                self.quic_p2p.send(peer, bytes.clone(), token);
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

    /// Terminate the QUIC connections gracefully.
    fn close(&mut self) -> Box<CoreFuture<()>> {
        trace!("{}: Terminating connection", self.id);

        let (disconnect_tx, disconnect_rx) = futures::oneshot();
        self.terminate();
        self.disconnect_tx = Some(disconnect_tx);

        Box::new(disconnect_rx.map_err(|e| CoreError::Unexpected(format!("{}", e))))
    }

    fn handle_quic_p2p_event(&mut self, event: Event) {
        use Event::*;
        // should handle new messages sent by vault (assuming it's only the `Challenge::Request` for
        // now) if the message is found to be related to a certain `ConnectionGroup`,
        // `connection_group.handle_response(sender, token, response)` should be called.
        match event {
            BootstrapFailure => self.handle_bootstrap_failure(),
            BootstrappedTo { node } => self.handle_bootstrapped_to(node),
            SentUserMessage {
                peer_addr,
                msg,
                token,
            } => self.handle_sent_user_message(peer_addr, msg, token),
            UnsentUserMessage {
                peer_addr,
                msg,
                token,
            } => self.handle_unsent_user_message(peer_addr, &msg, token),
            NewMessage { peer_addr, msg } => self.handle_new_message(peer_addr, &msg),
            Finish => {
                info!("Received unexpected event: {}", event);
            }
            ConnectionFailure { peer_addr, err } => self.handle_connection_failure(peer_addr, err),
            // We don't connect to peers yet, so we ignore this event.
            ConnectedTo { peer: _peer } => (),
        }
    }

    fn handle_bootstrapped_to(&mut self, node_info: NodeInfo) {
        trace!("{}: Bootstrapped", self.id);
        let _ = self
            .elders
            .insert(node_info.peer_addr, Elder::new(node_info));
    }

    fn handle_bootstrap_failure(&mut self) {
        let _ = self
            .connection_hook
            .take()
            .map(|hook| hook.send(Err(CoreError::from("Bootstrap failure".to_string()))));
    }

    fn handle_sent_user_message(&mut self, _peer_addr: SocketAddr, _msg: Bytes, _token: Token) {
        // TODO: check if we have handled the challenge?
        trace!("{}: Sent user message", self.id);
    }

    fn handle_unsent_user_message(&mut self, peer_addr: SocketAddr, msg: &Bytes, token: Token) {
        // TODO: check if we have handled the challenge?

        match deserialize(msg) {
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

    fn handle_new_message(&mut self, peer_addr: SocketAddr, msg: &Bytes) {
        let have_handled_challenge = self
            .elders
            .get(&peer_addr)
            .map_or(false, |elder| elder.public_id.is_some());

        trace!(
            "{}: Message from {:?}: {}. Have we handled challenge? {:?}",
            self.id,
            peer_addr,
            utils::bin_data_format(msg),
            have_handled_challenge
        );

        if have_handled_challenge {
            match deserialize(msg) {
                Ok(Message::Response {
                    response,
                    message_id,
                }) => self.handle_response(peer_addr, message_id, response),
                Ok(Message::Notification { notification }) => {
                    trace!("Got transaction notification: {:?}", notification);
                }
                Ok(_) => error!("Unexpected message type, expected response."),
                Err(e) => {
                    if let Ok(_x) = deserialize::<Challenge>(msg) {
                        error!("Unexpected challenge, expected response ({:?}).", e);
                    } else {
                        error!("Unexpected error {:?}", e);
                    }
                }
            }
        } else {
            match deserialize(msg) {
                Ok(Challenge::Request(PublicId::Node(node_public_id), challenge)) => {
                    trace!("Got the challenge");
                    self.handle_challenge(peer_addr, node_public_id, challenge)
                }
                Ok(_) => error!("Unexpected message type, expected challenge."),
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
        let token = rand::thread_rng().gen();
        let response = Challenge::Response {
            client_id: self.full_id.public_id(),
            signature: self.full_id.sign(&challenge),
            request_section_info: false,
        };
        let msg = Bytes::from(unwrap!(serialize(&response)));
        self.quic_p2p.send(elder.peer.clone(), msg, token);
        // trigger the connection future
        let _ = self.connection_hook.take().map(|hook| hook.send(Ok(())));
    }

    fn handle_connection_failure(&mut self, peer_addr: SocketAddr, err: quic_p2p::Error) {
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
}

fn setup_quic_p2p_event_loop(
    inner: &Arc<Mutex<Inner>>,
    event_rx: Receiver<Event>,
) -> JoinHandle<()> {
    let inner_weak = Arc::downgrade(inner);

    thread::spawn(move || {
        while let Ok(event) = event_rx.recv() {
            match event {
                Event::Finish => break, // Graceful shutdown
                event => {
                    if let Some(inner) = inner_weak.upgrade() {
                        let mut inner = unwrap!(inner.lock());
                        inner.handle_quic_p2p_event(event);
                    } else {
                        // Event loop got dropped
                        trace!("Gracefully terminating quic-p2p event loop");
                        break;
                    }
                }
            }
        }
    })
}
