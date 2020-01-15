// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::err;
use crate::{client::SafeKey, utils, CoreError, CoreFuture};
use bincode::{deserialize, serialize};
use bytes::Bytes;
use crossbeam_channel::{self, Receiver};
use futures::{
    sync::oneshot::{self, Sender},
    Future,
};
use lazy_static::lazy_static;
use log::{error, info, trace, warn};
use quic_p2p::{
    self, Builder, Config as QuicP2pConfig, Error as QuicP2pError, Event, NodeInfo, Peer, QuicP2p,
    Token,
};
use rand::Rng;
use safe_nd::{
    ConnectionInfo, HandshakeRequest, HandshakeResponse, Message, MessageId, NodePublicId,
    PublicId, Request, Response,
};
use std::sync::atomic::{AtomicU64, Ordering};
use std::{
    collections::HashMap,
    mem,
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

/// Encapsulates multiple QUIC connections with a group of Client Handlers. Accumulates responses.
pub(super) struct ConnectionGroup {
    inner: Arc<Mutex<Inner>>,
}

impl ConnectionGroup {
    pub fn new(
        config: QuicP2pConfig,
        full_id: SafeKey,
        connection_hook: Sender<Result<(), CoreError>>,
    ) -> Result<Self, CoreError> {
        let (event_tx, event_rx) = crossbeam_channel::unbounded();

        let mut quic_p2p = Builder::new(event_tx).with_config(config).build()?;

        let mut initial_state = Bootstrapping {
            connection_hook,
            full_id,
        };
        initial_state.init(&mut quic_p2p);

        let inner = Arc::new(Mutex::new(Inner {
            quic_p2p,
            disconnect_tx: None,
            id: GROUP_COUNTER.fetch_add(1, Ordering::SeqCst),
            state: State::Bootstrapping(initial_state),
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

struct Bootstrapping {
    connection_hook: Sender<Result<(), CoreError>>,
    full_id: SafeKey,
}

impl Bootstrapping {
    fn init(&mut self, quic_p2p: &mut QuicP2p) {
        quic_p2p.bootstrap();
    }

    fn handle_bootstrapped_to(&mut self, quic_p2p: &mut QuicP2p, node_info: NodeInfo) {
        let token = rand::thread_rng().gen();
        let handshake = HandshakeRequest::Bootstrap(self.full_id.public_id());
        let msg = Bytes::from(unwrap!(serialize(&handshake)));
        quic_p2p.send(Peer::Node { node_info }, msg, token);
    }

    fn handle_new_message(
        &mut self,
        quic_p2p: &mut QuicP2p,
        peer_addr: SocketAddr,
        msg: Bytes,
    ) -> Transition {
        match deserialize(&msg) {
            Ok(HandshakeResponse::Rebootstrap(_elders)) => {
                trace!("HandshakeResponse::Rebootstrap, trying again");

                // Try again
                quic_p2p.disconnect_from(peer_addr);

                // TODO: initialise `hard_coded_contacts` with received `_elders`.
                unimplemented!();
            }
            Ok(HandshakeResponse::Join(elders)) => {
                trace!(
                    "HandshakeResponse::Join, transitioning to Joining state ({:?})",
                    elders
                );

                // Drop the current connection to clean up the state.
                quic_p2p.disconnect_from(peer_addr);

                // Transition to a new state
                let pending_elders: Vec<_> = elders
                    .into_iter()
                    .map(|(_xor_name, ci)| convert_node_info(ci))
                    .collect();

                return Transition::ToJoining(pending_elders);
            }
            Ok(_msg) => error!("Unexpected message type, expected challenge."),
            Err(e) => error!("Unexpected error {:?}", e),
        }

        Transition::None
    }
}

struct JoiningElder {
    elder: Elder,
    sent_challenge: bool,
}

struct Joining {
    connected_elders: HashMap<SocketAddr, JoiningElder>,
    connection_hook: Sender<Result<(), CoreError>>,
    full_id: SafeKey,
}

impl Joining {
    fn new(
        old_state: Bootstrapping,
        mut pending_elders: Vec<NodeInfo>,
        quic_p2p: &mut QuicP2p,
    ) -> Self {
        for elder in pending_elders.drain(..) {
            quic_p2p.connect_to(elder);
        }
        Self {
            connected_elders: Default::default(),
            connection_hook: old_state.connection_hook,
            full_id: old_state.full_id,
        }
    }

    fn terminate(self, quic_p2p: &mut QuicP2p) {
        for e in self.connected_elders.values() {
            quic_p2p.disconnect_from(e.elder.peer().peer_addr());
        }
    }

    /// Handle a challenge request from a newly-connected vault.
    fn handle_challenge(
        &mut self,
        quic_p2p: &mut QuicP2p,
        sender_addr: SocketAddr,
        _sender_id: NodePublicId,
        challenge: Vec<u8>,
    ) {
        if let Some(connected) = self.connected_elders.get_mut(&sender_addr) {
            // safe to unwrap as we just found this elder before calling this method.
            if connected.sent_challenge {
                warn!("Already sent challenge to {:?}; ignoring.", sender_addr);
                return;
            }
            let token = rand::thread_rng().gen();
            let response = HandshakeRequest::ChallengeResult(self.full_id.sign(&challenge));
            let msg = Bytes::from(unwrap!(serialize(&response)));
            quic_p2p.send(connected.elder.peer.clone(), msg, token);
            connected.sent_challenge = true;
        } else {
            // Doesn't have this connected peer?
        }
    }

    fn handle_connected_to(&mut self, quic_p2p: &mut QuicP2p, peer: Peer) {
        if let Peer::Node { ref node_info } = &peer {
            let _ = self.connected_elders.insert(
                node_info.peer_addr,
                JoiningElder {
                    elder: Elder::new(node_info.clone()),
                    sent_challenge: false,
                },
            );
            let token = rand::thread_rng().gen();
            let handshake = HandshakeRequest::Join(self.full_id.public_id());
            let msg = Bytes::from(unwrap!(serialize(&handshake)));
            quic_p2p.send(peer, msg, token);
        } else {
            // Invalid state
        }
    }

    fn is_everyone_joined(&self) -> bool {
        self.connected_elders.values().all(|e| e.sent_challenge)
    }

    fn handle_new_message(
        &mut self,
        quic_p2p: &mut QuicP2p,
        peer_addr: SocketAddr,
        msg: Bytes,
    ) -> Transition {
        match deserialize(&msg) {
            Ok(HandshakeResponse::Challenge(PublicId::Node(node_public_id), challenge)) => {
                trace!("Got the challenge from {:?}", peer_addr);
                self.handle_challenge(quic_p2p, peer_addr, node_public_id, challenge);

                if self.is_everyone_joined() {
                    return Transition::ToConnected;
                }
            }
            Ok(HandshakeResponse::InvalidSection) => {
                //
            }
            Ok(_msg) => error!("Unexpected message type, expected challenge."),
            Err(e) => error!("Unexpected error {:?}", e),
        }

        Transition::None
    }
}

struct Connected {
    elders: HashMap<SocketAddr, Elder>,
    hooks: HashMap<MessageId, (Sender<Response>, usize)>, // to be replaced with Accumulator for multiple vaults.
}

impl Connected {
    fn new(old_state: Joining) -> Self {
        // trigger the connection future
        let _ = old_state.connection_hook.send(Ok(()));

        Self {
            hooks: Default::default(),
            elders: old_state
                .connected_elders
                .into_iter()
                .map(|(k, v)| (k, v.elder))
                .collect(),
        }
    }

    fn terminate(self, quic_p2p: &mut QuicP2p) {
        for peer in self.elders.values().map(Elder::peer) {
            quic_p2p.disconnect_from(peer.peer_addr());
        }
    }

    fn send(
        &mut self,
        quic_p2p: &mut QuicP2p,
        msg_id: MessageId,
        msg: &Message,
    ) -> Box<CoreFuture<Response>> {
        trace!("Sending message {:?}", msg_id);
        let mut rng = rand::thread_rng();

        let (future_tx, future_rx) = oneshot::channel();
        let _ = self.hooks.insert(msg_id, (future_tx, self.elders.len()));

        let bytes = Bytes::from(unwrap!(serialize(msg)));
        {
            for peer in self.elders.values().map(Elder::peer) {
                let token = rng.gen();
                quic_p2p.send(peer, bytes.clone(), token);
            }
        }

        Box::new(
            future_rx
                .timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS))
                .map_err(|e| {
                    if let Some(err) = e.into_inner() {
                        CoreError::from(format!("{}", err)) // TODO: introduce a wrapper error type?
                    } else {
                        CoreError::RequestTimeout
                    }
                }),
        )
    }

    /// Handle a response from one of the elders.
    fn handle_response(&mut self, sender_addr: SocketAddr, msg_id: MessageId, response: Response) {
        trace!(
            "Response from: {:?}, msg_id: {:?}, resp: {:?}",
            sender_addr,
            msg_id,
            response
        );
        let _ = self
            .hooks
            .remove(&msg_id)
            .map(|(sender, count)| {
                let count = count - 1;
                dbg!("Response no: {}", count);
                if count == 0 {
                    sender.send(response)
                } else {
                    let _ = self.hooks.insert(msg_id, (sender, count));
                    Ok(())
                }
            })
            .or_else(|| {
                trace!("No hook found for message ID {:?}", msg_id);
                None
            });
    }

    fn handle_new_message(
        &mut self,
        _quic_p2p: &mut QuicP2p,
        peer_addr: SocketAddr,
        msg: Bytes,
    ) -> Transition {
        trace!("{}: Message: {}.", peer_addr, utils::bin_data_format(&msg),);

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
                error!("Unexpected error: {:?}", e);
            }
        }

        Transition::None
    }
}

/// Represents the connection state of a certain connection group.
enum State {
    Bootstrapping(Bootstrapping),
    Joining(Joining),
    Connected(Connected),
    Terminated,
}

enum Transition {
    None,
    ToJoining(Vec<NodeInfo>),
    ToConnected,
    Terminate,
}

impl State {
    fn apply_transition(self, quic_p2p: &mut QuicP2p, transition: Transition) -> State {
        use Transition::*;
        match transition {
            None => self,
            ToJoining(pending_elders) => {
                if let State::Bootstrapping(old_state) = self {
                    State::Joining(Joining::new(old_state, pending_elders, quic_p2p))
                } else {
                    unreachable!()
                }
            }
            ToConnected => {
                if let State::Joining(old_state) = self {
                    State::Connected(Connected::new(old_state))
                } else {
                    unreachable!()
                }
            }
            Terminate => self.terminate(quic_p2p),
        }
    }

    fn terminate(self, quic_p2p: &mut QuicP2p) -> State {
        match self {
            State::Connected(state) => state.terminate(quic_p2p),
            State::Bootstrapping(_state) => (), // No state to terminate
            State::Joining(state) => state.terminate(quic_p2p),
            State::Terminated => (),
        }
        State::Terminated
    }

    fn send(
        &mut self,
        quic_p2p: &mut QuicP2p,
        msg_id: MessageId,
        msg: &Message,
    ) -> Box<CoreFuture<Response>> {
        match self {
            State::Connected(state) => state.send(quic_p2p, msg_id, msg),
            // This message is not expected for the rest of states
            _state => err!(CoreError::OperationForbidden),
        }
    }

    fn handle_bootstrapped_to(&mut self, quic_p2p: &mut QuicP2p, node_info: NodeInfo) {
        trace!("Bootstrapped; node_info: {:?}", node_info);
        match self {
            State::Bootstrapping(state) => state.handle_bootstrapped_to(quic_p2p, node_info),
            // This message is not expected for the rest of states
            _state => {
                warn!("handle_bootstrapped_to called for invalid state");
            }
        }
    }

    fn handle_connected_to(&mut self, quic_p2p: &mut QuicP2p, peer: Peer) {
        match self {
            State::Joining(state) => state.handle_connected_to(quic_p2p, peer),
            // This message is not expected for the rest of states
            _state => {
                warn!("handle_connected_to called for invalid state");
            }
        }
    }

    fn handle_new_message(
        &mut self,
        quic_p2p: &mut QuicP2p,
        peer_addr: SocketAddr,
        msg: Bytes,
    ) -> Transition {
        match self {
            State::Bootstrapping(state) => state.handle_new_message(quic_p2p, peer_addr, msg),
            State::Joining(state) => state.handle_new_message(quic_p2p, peer_addr, msg),
            State::Connected(state) => state.handle_new_message(quic_p2p, peer_addr, msg),
            State::Terminated => Transition::None,
        }
    }
}

struct Inner {
    quic_p2p: QuicP2p,
    disconnect_tx: Option<Sender<()>>,
    id: u64,
    state: State,
}

impl Drop for Inner {
    fn drop(&mut self) {
        self.terminate();
        thread::sleep(Duration::from_millis(50));
    }
}

impl Inner {
    fn terminate(&mut self) {
        let old_state = mem::replace(&mut self.state, State::Terminated);
        let _ = old_state.apply_transition(&mut self.quic_p2p, Transition::Terminate);
    }

    fn send(&mut self, msg_id: MessageId, msg: &Message) -> Box<CoreFuture<Response>> {
        self.state.send(&mut self.quic_p2p, msg_id, msg)
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
        // should handle new messages sent by vault (assuming it's only the `Challenge::Request` for now)
        // if the message is found to be related to a certain `ConnectionGroup`, `connection_group.handle_response(sender, token, response)` should be called.
        match event {
            BootstrapFailure => self.handle_bootstrap_failure(),
            BootstrappedTo { node } => self.state.handle_bootstrapped_to(&mut self.quic_p2p, node),
            ConnectedTo { peer } => self.state.handle_connected_to(&mut self.quic_p2p, peer),
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
            NewMessage { peer_addr, msg } => {
                let transition = self
                    .state
                    .handle_new_message(&mut self.quic_p2p, peer_addr, msg);

                match transition {
                    Transition::None => (), // do nothing
                    t => {
                        let old_state = mem::replace(&mut self.state, State::Terminated);
                        self.state = old_state.apply_transition(&mut self.quic_p2p, t);
                    }
                }
            }
            Finish => {
                info!("Received unexpected event: {}", event);
            }
            ConnectionFailure { peer_addr, err } => self.handle_connection_failure(peer_addr, err),
        }
    }

    fn handle_bootstrap_failure(&mut self) {
        /*
                let _ = self
                    .connection_hook
                    .take()
                    .map(|hook| hook.send(Err(CoreError::from("Bootstrap failure".to_string()))));
        */
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

fn convert_node_info(ci: ConnectionInfo) -> NodeInfo {
    let ConnectionInfo {
        peer_addr,
        peer_cert_der,
    } = ci;
    NodeInfo {
        peer_addr,
        peer_cert_der,
    }
}
