// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::response_manager::ResponseManager;
use crate::{client::SafeKey, client::TransferActor, utils, CoreError};
use bincode::{deserialize, serialize};
use bytes::Bytes;
use crossbeam_channel::{self, Receiver};
use futures::{
    channel,
    channel::mpsc::{self},
    channel::oneshot::{self, Sender},
    lock::Mutex,
};
use lazy_static::lazy_static;
use log::{error, info, trace, warn};
use quic_p2p::{
    self, Config as QuicP2pConfig, Event, EventSenders, Peer, QuicP2p, QuicP2pError, Token,
};
use rand::Rng;
use safe_nd::{
    DebitAgreementProof, HandshakeRequest, HandshakeResponse, Message, MessageId, NodePublicId,
    PublicId, Request, RequestType, Response,
};

use tokio::time::timeout;

// use std::iter::Iterator;
use futures_util::stream::StreamExt;
use std::{
    collections::HashMap,
    mem,
    net::SocketAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};

use unwrap::unwrap;

// use safe_transfers::();

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
    fn new(socket: SocketAddr) -> Self {
        Self {
            peer: Peer::Node(socket),
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
    pub async fn new(
        config: QuicP2pConfig,
        full_id: SafeKey,
        connection_hook: Sender<Result<(), CoreError>>,
    ) -> Result<Self, CoreError> {
        let (node_tx, node_rx) = crossbeam_channel::unbounded();
        let (client_tx, _client_rx) = crossbeam_channel::unbounded();

        let ev_tx = EventSenders { node_tx, client_tx };
        let mut quic_p2p = QuicP2p::with_config(ev_tx, Some(config), Default::default(), false)?;

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

        setup_quic_p2p_events_receiver(&inner, node_rx);

        Ok(Self { inner })
    }

    pub async fn send(&mut self, msg_id: MessageId, msg: &Message) -> Result<Response, CoreError> {
        // user block here to drop lock asap
        let mut receiver_future = { self.inner.lock().await.send(msg_id, msg).await? };

        // TODO reimpl timeout here
        let response_future = async {
            let mut response = Err(CoreError::RequestTimeout);
            while let Some((res, _message_id)) = receiver_future.next().await {
                response = Ok(res);
                receiver_future.close();
            }

            response
        };

        match timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS), response_future).await {
            Ok(response) => response.map_err(|err| CoreError::from(format!("{}", err))),
            Err(_) => Err(CoreError::RequestTimeout),
        }
    }

    /// Send transfer validation, which requires all responses to be handled for signature reconstruction.
    pub async fn send_for_validation(
        &mut self,
        msg_id: &MessageId,
        msg: &Message,
        transfer_actor: &mut TransferActor,
    ) -> Result<DebitAgreementProof, CoreError> {
        trace!("Sending transfer req for validation");

        let mut receiver_future = {
            self.inner
                .lock()
                .await
                .send_for_validation(*msg_id, msg)
                .await?
        };

        // wrap receiver for a timeout
        let response_future = async {
            let mut response = Err(CoreError::from("No debit agreement proof received"));

            while let Some((res, message_id)) = receiver_future.next().await {
                // Let the actor handle receipt of each response from elders

                match transfer_actor
                    .handle_validation_response(res, &message_id)
                    .await
                {
                    Ok(proof) => {
                        if let Some(debit_agreement_proof) = proof {
                            receiver_future.close();
                            response = Ok(debit_agreement_proof)
                        };
                    }
                    Err(error) => response = Err(error),
                }
            }

            response
        };

        match timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS), response_future).await {
            Ok(response) => response.map_err(|err| CoreError::from(format!("{}", err))),
            Err(_) => Err(CoreError::RequestTimeout),
        }
    }

    /// Terminate the QUIC connections gracefully.
    pub async fn close(&mut self) -> Result<(), CoreError> {
        // user block here to drop lock asap
        let disconnect_receiver_future = { self.inner.lock().await.close().await? };

        disconnect_receiver_future
            .await
            .map_err(|e| CoreError::Unexpected(format!("{}", e)))
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

    fn handle_bootstrapped_to(&mut self, quic_p2p: &mut QuicP2p, socket: SocketAddr) {
        let token = rand::thread_rng().gen();
        let handshake = HandshakeRequest::Bootstrap(self.full_id.public_id());
        let msg = Bytes::from(unwrap!(serialize(&handshake)));
        quic_p2p.send(Peer::Node(socket), msg, token);
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
                let pending_elders: Vec<_> = elders.into_iter().map(|(_xor_name, ci)| ci).collect();

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
        mut pending_elders: Vec<SocketAddr>,
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
        if let Peer::Node(socket) = &peer {
            let _ = self.connected_elders.insert(
                *socket,
                JoiningElder {
                    elder: Elder::new(*socket),
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
    response_manager: ResponseManager,
}

impl Connected {
    fn new(old_state: Joining) -> Self {
        // trigger the connection future
        let _ = old_state.connection_hook.send(Ok(()));

        let response_threshold: usize = old_state.connected_elders.len() / 2 + 1;

        Self {
            response_manager: ResponseManager::new(response_threshold),
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

    async fn send(
        &mut self,
        quic_p2p: &mut QuicP2p,
        msg_id: MessageId,
        msg: &Message,
    ) -> Result<mpsc::UnboundedReceiver<(Response, MessageId)>, CoreError> {
        trace!("Sending message {:?}", msg_id);

        let (sender_future, response_future) = mpsc::unbounded();
        let expected_responses = if is_get_request(&msg) {
            self.elders.len()
        } else {
            self.elders.len() / 2 + 1
        };

        let is_this_validation_request = false;

        let _ = self.response_manager.await_responses(
            msg_id,
            (
                sender_future,
                expected_responses,
                is_this_validation_request,
            ),
        );

        let bytes = Bytes::from(unwrap!(serialize(msg)));
        {
            for peer in self.elders.values().map(Elder::peer) {
                let token = rand::random();
                quic_p2p.send(peer, bytes.clone(), token);
            }
        }

        Ok(response_future)
    }

    async fn send_for_validation(
        &mut self,
        quic_p2p: &mut QuicP2p,
        msg_id: MessageId,
        msg: &Message,
    ) -> Result<mpsc::UnboundedReceiver<(Response, MessageId)>, CoreError> {
        trace!("Sending message {:?}", msg_id);
        //let mut rng = rand::thread_rng();

        let (sender_future, response_future) = mpsc::unbounded();

        let expected_responses = 7;
        // let expected_responses =  self.elders.len() / 2 + 1;

        let is_this_validation_request = true;

        // is validator to be added to response manager
        let _ = self.response_manager.await_responses(
            msg_id,
            (
                sender_future,
                expected_responses,
                is_this_validation_request,
            ),
        );

        // send the message to our elders list
        let bytes = Bytes::from(unwrap!(serialize(msg)));
        {
            for peer in self.elders.values().map(Elder::peer) {
                let token = rand::random();
                quic_p2p.send(peer, bytes.clone(), token);
            }
        }

        Ok(response_future)
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
            }) => {
                trace!(
                    "Response from: {:?}, msg_id: {:?}, resp: {:?}",
                    peer_addr,
                    message_id,
                    response
                );
                let _ = self.response_manager.handle_response(message_id, response);
            }
            Ok(Message::TransferNotification { payload }) => {
                trace!("Got transfer_id notification: {:?}", payload);
            }
            Ok(_msg) => error!("Unexpected message type, expected response."),
            Err(e) => {
                error!("Unexpected error: {:?}", e);
            }
        }

        Transition::None
    }
}

// Returns true when a message holds a GET request.
fn is_get_request(msg: &Message) -> bool {
    if let Message::Request { request, .. } = msg {
        match request.get_type() {
            RequestType::PublicGet | RequestType::PrivateGet => true,
            _ => false,
        }
    } else {
        false
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
    ToJoining(Vec<SocketAddr>),
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

    async fn send(
        &mut self,
        quic_p2p: &mut QuicP2p,
        msg_id: MessageId,
        msg: &Message,
    ) -> Result<channel::mpsc::UnboundedReceiver<(Response, MessageId)>, CoreError> {
        match self {
            State::Connected(state) => state.send(quic_p2p, msg_id, msg).await,
            // This message is not expected for the rest of states
            _state => Err(CoreError::OperationForbidden),
        }
    }

    async fn send_for_validation(
        &mut self,
        quic_p2p: &mut QuicP2p,
        msg_id: MessageId,
        msg: &Message,
    ) -> Result<channel::mpsc::UnboundedReceiver<(Response, MessageId)>, CoreError> {
        match self {
            State::Connected(state) => state.send_for_validation(quic_p2p, msg_id, msg).await,
            // This message is not expected for the rest of states
            _state => Err(CoreError::OperationForbidden),
        }
    }

    fn handle_bootstrapped_to(&mut self, quic_p2p: &mut QuicP2p, socket: SocketAddr) {
        trace!("Bootstrapped; SocketAddr: {:?}", socket);
        match self {
            State::Bootstrapping(state) => state.handle_bootstrapped_to(quic_p2p, socket),
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

    async fn send(
        &mut self,
        msg_id: MessageId,
        msg: &Message,
    ) -> Result<channel::mpsc::UnboundedReceiver<(Response, MessageId)>, CoreError> {
        self.state.send(&mut self.quic_p2p, msg_id, msg).await
    }

    async fn send_for_validation(
        &mut self,
        msg_id: MessageId,
        msg: &Message,
    ) -> Result<channel::mpsc::UnboundedReceiver<(Response, MessageId)>, CoreError> {
        self.state
            .send_for_validation(&mut self.quic_p2p, msg_id, msg)
            .await
    }

    /// Terminate the QUIC connections gracefully.
    async fn close(&mut self) -> Result<oneshot::Receiver<()>, CoreError> {
        trace!("{}: Terminating connection", self.id);

        let (disconnect_tx, disconnect_rx) = oneshot::channel();
        self.terminate();
        self.disconnect_tx = Some(disconnect_tx);
        Ok(disconnect_rx)
    }

    fn handle_quic_p2p_event(&mut self, event: Event) {
        use Event::*;
        // should handle new messages sent by vault (assuming it's only the `Challenge::Request` for now)
        // if the message is found to be related to a certain `ConnectionGroup`, `connection_group.response_manager.handle_response(message_id, response)` should be called.
        match event {
            BootstrapFailure => self.handle_bootstrap_failure(),
            BootstrappedTo { node } => self.state.handle_bootstrapped_to(&mut self.quic_p2p, node),
            ConnectedTo { peer } => self.state.handle_connected_to(&mut self.quic_p2p, peer),
            SentUserMessage { peer, msg, token } => {
                self.handle_sent_user_message(peer.peer_addr(), msg, token)
            }
            UnsentUserMessage { peer, msg, token } => {
                self.handle_unsent_user_message(peer.peer_addr(), &msg, token)
            }
            NewMessage { peer, msg } => {
                let transition =
                    self.state
                        .handle_new_message(&mut self.quic_p2p, peer.peer_addr(), msg);

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
            ConnectionFailure { peer, err } => {
                self.handle_connection_failure(peer.peer_addr(), err)
            }
        }
    }

    fn handle_bootstrap_failure(&mut self) {
        /*
            TODO: handle this properly as part of the new bootstrap process

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

    fn handle_connection_failure(&mut self, peer_addr: SocketAddr, err: QuicP2pError) {
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

fn setup_quic_p2p_events_receiver(inner: &Arc<Mutex<Inner>>, event_rx: Receiver<Event>) {
    let inner_weak = Arc::downgrade(inner);
    let _ = tokio::task::spawn_blocking(move || {
        while let Ok(event) = event_rx.recv() {
            match event {
                Event::Finish => {
                    // Graceful shutdown
                    trace!("Gracefully terminated quic-p2p event loop by remote peer");
                    break;
                }
                event => {
                    if let Some(inner) = inner_weak.upgrade() {
                        let mut inner = futures::executor::block_on(inner.lock());
                        inner.handle_quic_p2p_event(event);
                    } else {
                        // Event loop got dropped
                        trace!("Gracefully terminating quic-p2p event loop");
                        break;
                    }
                }
            }
        }
    });
}
