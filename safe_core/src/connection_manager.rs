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

use crate::{client::NewFullId, event::NetworkTx, CoreError, CoreFuture};
use bytes::Bytes;
use connection_group::ConnectionGroup;
use crossbeam_channel::{self, Receiver};
use futures::{
    future::{self, IntoFuture},
    stream::Stream,
    sync::mpsc::{self, UnboundedReceiver},
    Future,
};
use quic_p2p::{self, Builder, Config as QuicP2pConfig, Event, NodeInfo, Peer, QuicP2p};
use safe_nd::{Message, PublicId, Response};
use std::{
    cell::RefCell,
    rc::Rc,
    thread,
    {
        collections::{hash_map::Entry, HashMap, HashSet},
        net::SocketAddr,
    },
};
use tokio::runtime::current_thread;

/// Initialises QuicP2p instance. Establishes new connections.
/// Contains a reference to crossbeam channel provided by quic-p2p for capturing the events.
pub struct ConnectionManager {
    inner: Rc<RefCell<Inner>>,
}

impl ConnectionManager {
    pub fn new(
        config: Option<&QuicP2pConfig>,
        net_tx: &NetworkTx,
        full_id: NewFullId,
    ) -> Result<Self, CoreError> {
        let (event_tx, event_rx) = crossbeam_channel::unbounded();
        let quic_p2p = Rc::new(RefCell::new(Builder::new(event_tx).build()?));
        let (qp2p_stream_tx, qp2p_stream_rx) = mpsc::unbounded();
        setup_quic_p2p_event_loop(event_rx, qp2p_stream_tx);

        // Create initial `ConnectionGroup` with no pending contacts.  This will be updated when
        // handling the `BootstrappedTo` event.
        let mut groups = HashMap::default();
        let _ = groups.insert(
            full_id.public_id(),
            ConnectionGroup::new(full_id, HashSet::default(), Rc::clone(&quic_p2p)),
        );

        let inner = Rc::new(RefCell::new(Inner { quic_p2p, groups }));
        let weak_inner = Rc::downgrade(&inner);
        let stream_future = qp2p_stream_rx.for_each(move |event| {
            weak_inner.upgrade().ok_or(()).map(|inner| {
                inner.borrow_mut().handle_quic_p2p_event(event);
            })
        });
        current_thread::spawn(stream_future);

        Ok(Self { inner })
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
        let mut inner = self.inner.borrow_mut();
        let mut conn_group = fry!(inner.groups.get_mut(&pub_id).ok_or_else(|| {
            CoreError::Unexpected("No connection group found - did you call `connect`?".to_string())
        }));

        conn_group.send(msg_id, msg)
    }

    pub fn connect(
        &mut self,
        full_id: NewFullId,
        elders: HashSet<NodeInfo>,
    ) -> impl Future<Item = (), Error = CoreError> {
        let quic_p2p = Rc::clone(&self.inner.borrow().quic_p2p);
        match self.inner.borrow_mut().groups.entry(full_id.public_id()) {
            Entry::Vacant(value) => {
                let _ = value.insert(ConnectionGroup::new(full_id, elders, quic_p2p));
            }
            Entry::Occupied(_) => return future::ok(()),
        }

        future::err(CoreError::Unexpected("unimplemented".to_string()))
    }
}

struct Inner {
    quic_p2p: Rc<RefCell<QuicP2p>>,
    groups: HashMap<PublicId, ConnectionGroup>,
}

impl Inner {
    fn handle_quic_p2p_event(&mut self, event: Event) {
        use Event::*;
        // should handle new messages sent by vault (assuming it's only the `Challenge::Request` for now)
        // if the message is found to be related to a certain `ConnectionGroup`, `connection_group.handle_response(sender, token, response)` should be called.
        match event {
            BootstrapFailure => unimplemented!(),
            BootstrappedTo { node } => self.handle_bootstrapped_to(node),
            ConnectionFailure { peer_addr, err } => unimplemented!(),
            SentUserMessage {
                peer_addr,
                msg,
                token,
            } => unimplemented!(),
            UnsentUserMessage {
                peer_addr,
                msg,
                token,
            } => unimplemented!(),
            ConnectedTo { peer } => (),
            NewMessage { peer_addr, msg } => self.handle_new_message(peer_addr, msg),
            Finish => unimplemented!(),
        }
    }

    fn handle_bootstrapped_to(&mut self, node: NodeInfo) {
        if let Some(group) = self.groups.values_mut().next() {
            group.handle_bootstrapped_to(node)
        }
    }

    fn handle_new_message(&mut self, peer_addr: SocketAddr, msg: Bytes) {
        let _ = self
            .connection_group_mut(&peer_addr)
            .map(|group| group.handle_new_message(peer_addr, msg));
    }

    fn connection_group_mut(&mut self, peer_addr: &SocketAddr) -> Option<&mut ConnectionGroup> {
        self.groups
            .values_mut()
            .find(|group| group.has_peer(peer_addr))
    }
}

fn setup_quic_p2p_event_loop(
    event_rx: Receiver<Event>,
    qp2p_stream_tx: mpsc::UnboundedSender<Event>,
) {
    let _ = thread::spawn(move || {
        while let Ok(event) = event_rx.recv() {
            // transfer event to the core event loop
            let _ = qp2p_stream_tx.unbounded_send(event);
        }
    });
}
