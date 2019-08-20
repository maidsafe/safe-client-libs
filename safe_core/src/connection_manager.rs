// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod connection_group;

use crate::{
    client::SafeKey,
    event::{NetworkEvent, NetworkTx},
    CoreError, CoreFuture,
};
use bytes::Bytes;
use connection_group::ConnectionGroup;
use crossbeam_channel::{self, Receiver};
use futures::{future, Future};
use quic_p2p::{self, Builder, Config as QuicP2pConfig, Event, NodeInfo, Peer, QuicP2p, Token};
use safe_nd::{Message, PublicId, Response};
use std::{
    mem,
    sync::{Arc, Mutex},
    thread::{self, JoinHandle},
    time::Duration,
    {
        collections::{hash_map::Entry, HashMap},
        net::SocketAddr,
    },
};
use tokio::prelude::FutureExt;

const CONNECTION_TIMEOUT_SECS: u64 = 30;

/// Initialises QuicP2p instance. Establishes new connections.
/// Contains a reference to crossbeam channel provided by quic-p2p for capturing the events.
#[derive(Clone)]
pub struct ConnectionManager {
    inner: Arc<Mutex<Inner>>,
}

impl ConnectionManager {
    /// Create a new connection manager.
    pub fn new(config: QuicP2pConfig, net_tx: &NetworkTx) -> Result<Self, CoreError> {
        // config.idle_timeout_msec = Some(0);

        let (event_tx, event_rx) = crossbeam_channel::unbounded();
        let quic_p2p = Arc::new(Mutex::new(
            Builder::new(event_tx).with_config(config).build()?,
        ));

        let inner = Arc::new(Mutex::new(Inner {
            quic_p2p,
            groups: HashMap::default(),
            net_tx: net_tx.clone(),
        }));
        let _ = setup_quic_p2p_event_loop(inner.clone(), event_rx);

        Ok(Self { inner })
    }

    /// Returns `true` if this connection manager is already connected to a Client Handlers
    /// group serving the provided public ID.
    pub fn has_connection_to(&self, pub_id: &PublicId) -> bool {
        unwrap!(self.inner.lock()).groups.contains_key(&pub_id)
    }

    /// Send `message` via the `ConnectionGroup` specified by our given `pub_id`.
    pub fn send(&mut self, pub_id: &PublicId, msg: &Message) -> Box<CoreFuture<Response>> {
        let msg_id = if let Message::Request { message_id, .. } = msg {
            *message_id
        } else {
            return Box::new(future::err(CoreError::Unexpected(
                "Not a Request".to_string(),
            )));
        };

        let mut inner = unwrap!(self.inner.lock());
        let conn_group = fry!(inner.groups.get_mut(&pub_id).ok_or_else(|| {
            CoreError::Unexpected("No connection group found - did you call `connect`?".to_string())
        }));

        conn_group.send(msg_id, msg)
    }

    /// Connect to Client Handlers that manage the provided ID.
    pub fn bootstrap(&mut self, full_id: SafeKey) -> Box<CoreFuture<()>> {
        trace!("Trying to bootstrap with group {:?}", full_id.public_id());

        let elders = Default::default();

        let quic_p2p = unwrap!(self.inner.lock()).quic_p2p.clone();

        let (connected_tx, connected_rx) = futures::oneshot();

        if unwrap!(self.inner.lock()).groups.len() == 0 {
            unwrap!(quic_p2p.lock()).bootstrap();
        }

        if let Entry::Vacant(value) = unwrap!(self.inner.lock()).groups.entry(full_id.public_id()) {
            let _ = value.insert(ConnectionGroup::new(
                full_id,
                elders,
                quic_p2p,
                connected_tx,
            ));
            Box::new(
                connected_rx
                    .map_err(|err| CoreError::from(format!("{}", err)))
                    .and_then(|res| res)
                    .timeout(Duration::from_secs(CONNECTION_TIMEOUT_SECS))
                    .map_err(|_e| CoreError::RequestTimeout),
            )
        } else {
            trace!("Group {} is already connected", full_id.public_id());
            ok!(())
        }
    }

    /// Reconnect to the network.
    pub fn restart_network(&mut self) {
        unimplemented!();
    }

    /// Disconnect from all groups.
    pub fn disconnect_all(&mut self) -> Box<CoreFuture<()>> {
        trace!("Disconnecting all groups");

        let mut inner = unwrap!(self.inner.lock());
        let inner_ref = Arc::downgrade(&self.inner);

        let futures: Vec<_> = inner
            .groups
            .iter_mut()
            .map(|(_, group)| group.close())
            .collect();

        Box::new(future::join_all(futures).map(move |_res| {
            // Remove all groups once they're disconnected
            if let Some(inner) = inner_ref.upgrade() {
                let _ = mem::replace(&mut unwrap!(inner.lock()).groups, Default::default());
            }
        }))
    }

    /// Disconnect from a group.
    pub fn disconnect(&mut self, pub_id: &PublicId) -> Box<CoreFuture<()>> {
        trace!("Disconnecting group {:?}", pub_id);

        let mut inner = unwrap!(self.inner.lock());
        let inner_ref = Arc::downgrade(&self.inner);

        let group = inner.groups.get_mut(&pub_id);
        let pub_id = pub_id.clone();

        if let Some(group) = group {
            Box::new(group.close().map(move |res| {
                // Remove the group once it's disconnected
                if let Some(inner) = inner_ref.upgrade() {
                    let _ = unwrap!(inner.lock()).groups.remove(&pub_id);
                }
                res
            }))
        } else {
            error!("No group found for {}", pub_id); // FIXME: handle properly
            ok!(())
        }
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        // Disconnect from all groups gracefully
        trace!("Dropped ConnectionManager - terminating gracefully");

        let groups = mem::replace(&mut self.groups, Default::default());
        for (_pub_id, mut group) in groups.into_iter() {
            group.terminate();
        }

        let _ = self.net_tx.unbounded_send(NetworkEvent::Disconnected);

        thread::sleep(Duration::from_millis(50));
    }
}

struct Inner {
    quic_p2p: Arc<Mutex<QuicP2p>>,
    groups: HashMap<PublicId, ConnectionGroup>,
    net_tx: NetworkTx,
}

impl Inner {
    #[allow(unused)]
    fn handle_quic_p2p_event(&mut self, event: Event) {
        use Event::*;
        // should handle new messages sent by vault (assuming it's only the `Challenge::Request` for now)
        // if the message is found to be related to a certain `ConnectionGroup`, `connection_group.handle_response(sender, token, response)` should be called.
        match event {
            BootstrapFailure => self.handle_bootstrap_failure(),
            BootstrappedTo { node } => self.handle_bootstrapped_to(node),
            ConnectionFailure { peer_addr, err } => self.handle_connection_failure(peer_addr, err),
            SentUserMessage {
                peer_addr,
                msg,
                token,
            } => self.handle_sent_user_message(peer_addr, msg, token),
            UnsentUserMessage {
                peer_addr,
                msg,
                token,
            } => self.handle_unsent_user_message(peer_addr, msg, token),
            ConnectedTo { peer } => self.handle_connected_to(peer),
            NewMessage { peer_addr, msg } => self.handle_new_message(peer_addr, msg),
            Finish => {
                info!("Received unexpected event: {}", event);
            }
        }
    }

    fn handle_bootstrap_failure(&mut self) {
        if let Some(group) = self.groups.values_mut().next() {
            group.handle_bootstrap_failure()
        }
    }

    fn handle_bootstrapped_to(&mut self, node: NodeInfo) {
        if let Some(group) = self.groups.values_mut().next() {
            group.handle_bootstrapped_to(node)
        }
    }

    fn handle_connection_failure(&mut self, peer_addr: SocketAddr, err: quic_p2p::Error) {
        trace!(
            "Connection failure, peer_addr: {}, conn groups: {:?}, group: {:?}",
            peer_addr,
            self.groups.keys(),
            self.groups
                .values()
                .find(|group| group.has_peer(&peer_addr))
                .map(|grp| grp.id)
        );
        let _ = self
            .connection_group_mut(&peer_addr)
            .map(|group| group.handle_connection_failure(peer_addr, err))
            .or_else(|| {
                warn!("No connection group found for peer {:?}", peer_addr);
                None
            });
    }

    fn handle_sent_user_message(&mut self, peer_addr: SocketAddr, msg: Bytes, token: Token) {
        let _ = self
            .connection_group_mut(&peer_addr)
            .map(|group| group.handle_sent_user_message(peer_addr, msg, token));
    }

    fn handle_unsent_user_message(&mut self, peer_addr: SocketAddr, msg: Bytes, token: Token) {
        let _ = self
            .connection_group_mut(&peer_addr)
            .map(|group| group.handle_unsent_user_message(peer_addr, msg, token));
    }

    fn handle_connected_to(&mut self, _peer: Peer) {
        // Do nothing
    }

    fn handle_new_message(&mut self, peer_addr: SocketAddr, msg: Bytes) {
        trace!(
            "New message! peer_addr: {:?}, conn groups: {:?}, group: {:?}",
            peer_addr,
            self.groups.keys(),
            self.groups
                .values()
                .find(|group| group.has_peer(&peer_addr))
                .map(|grp| grp.id)
        );
        let _ = self
            .connection_group_mut(&peer_addr)
            .map(|group| group.handle_new_message(peer_addr, msg))
            .or_else(|| {
                warn!("No connection group found for peer {:?}", peer_addr);
                None
            });
    }

    fn connection_group_mut(&mut self, peer_addr: &SocketAddr) -> Option<&mut ConnectionGroup> {
        self.groups
            .values_mut()
            .find(|group| group.has_peer(peer_addr))
    }
}

fn setup_quic_p2p_event_loop(
    inner: Arc<Mutex<Inner>>,
    event_rx: Receiver<Event>,
) -> JoinHandle<()> {
    let inner_weak = Arc::downgrade(&inner);

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
