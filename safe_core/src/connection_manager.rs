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
use connection_group::ConnectionGroup;
use crossbeam_channel::{self, Receiver};
use futures::{
    future::{self, IntoFuture},
    stream::Stream,
    sync::mpsc,
    Future,
};
use quic_p2p::{self, Builder, Config as QuicP2pConfig, Event, NodeInfo, Peer, QuicP2p};
use safe_nd::{PublicId, Response};
use std::collections::HashMap;
use std::thread;
use std::{cell::RefCell, rc::Rc};
use tokio::runtime::current_thread;

/// Initialises QuicP2p instance. Establishes new connections.
/// Contains a reference to crossbeam channel provided by quic-p2p for capturing the events.
pub struct ConnectionManager {
    quic_p2p: QuicP2p,
    groups: Rc<RefCell<HashMap<PublicId, ConnectionGroup>>>,
}

impl ConnectionManager {
    pub fn new(config: Option<&QuicP2pConfig>, net_tx: &NetworkTx) -> Result<Self, CoreError> {
        // 1. build QuicP2p object.
        // 2. start an event loop passing quic-p2p events to the core event loop, triggering the future task.
        let (event_tx, event_rx) = crossbeam_channel::unbounded();

        let quic_p2p = Builder::new(event_tx).build()?;
        let groups = Rc::new(RefCell::new(HashMap::default()));

        let (qp2p_stream_tx, qp2p_stream_rx) = mpsc::unbounded();
        setup_quic_p2p_event_loop(event_rx.clone(), qp2p_stream_tx);

        let groups_ref = Rc::downgrade(&groups);

        let stream_fut = qp2p_stream_rx.for_each(move |event| {
            match event {
                Event::BootstrappedTo { node } => {
                    println!("BootstrappedTo -> {:?}", node);
                }
                Event::NewMessage { peer_addr, msg } => {
                    println!("NewMsg -> {:?}", peer_addr);
                }
                Event::Finish => return Err(()),
                ev => println!("{:?}", ev),
            }
            Ok(())

            // if let Some(grp) = groups_ref.upgrade() {
            //     let conn_group = grp.borrow_mut();
            //     conn_group.get(&sender_public_id).handle_response(event);
            // } else {
            //     // Shut down the message loop.
            //     return Err(());
            // }

            // network events go to:
            // net_tx: &NetworkTx,
        });

        current_thread::spawn(stream_fut);

        Ok(Self { quic_p2p, groups })
    }

    pub fn send(&mut self, pub_id: &PublicId, msg: &[u8]) -> Box<CoreFuture<Response>> {
        // 1. Get the connection group, either from `self.groups` or connect if need be.
        // 2. Call `group.send()`.
        let mut groups = self.groups.borrow_mut();

        let mut conn_group = fry!(groups.get_mut(&pub_id).ok_or_else(|| {
            CoreError::Unexpected("No connection group found - did you call `connect`?".to_string())
        }));

        conn_group.send(&mut self.quic_p2p, msg)
    }

    pub fn connect(&mut self, full_id: &NewFullId) -> impl Future<Item = (), Error = CoreError> {
        // 1. handle the initial handshake process (responding to the challenge etc.)
        // 2. return a new connection.
        //    it's is a no-op for already-established connections.
        let conn_group = ConnectionGroup::new();

        // TODO: check for an already existing connection
        let _ = self
            .groups
            .borrow_mut()
            .insert(full_id.public_id(), conn_group);

        future::err(CoreError::Unexpected("unimplemented".to_string()))
    }

    fn handle_quic_p2p_event(&mut self, event: Event) {
        // should handle new messages sent by vault (assuming it's only the `Challenge::Request` or `Response` for now)
        // if the message is found to be related to a certain `ConnectionGroup`, `connection_group.handle_response(sender, token, response)` should be called.
        unimplemented!();
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
