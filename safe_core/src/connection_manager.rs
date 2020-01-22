// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod connection_group;

use crate::{
    client::SafeKey, network_event::NetworkEvent, network_event::NetworkTx, CoreError, CoreFuture,
};
use crate::{fry, ok};
use connection_group::ConnectionGroup;
use futures::{future, Future};
use log::{error, trace};
use quic_p2p::Config as QuicP2pConfig;
use safe_nd::{Message, PublicId, Response};
use std::{
    cell::RefCell,
    collections::{hash_map::Entry, HashMap},
    rc::Rc,
    time::Duration,
};
use tokio::util::FutureExt;

const CONNECTION_TIMEOUT_SECS: u64 = 30;

/// Initialises `QuicP2p` instance. Establishes new connections.
/// Contains a reference to crossbeam channel provided by quic-p2p for capturing the events.
#[derive(Clone)]
pub struct ConnectionManager {
    inner: Rc<RefCell<Inner>>,
}

impl ConnectionManager {
    /// Create a new connection manager.
    pub fn new(mut config: QuicP2pConfig, net_tx: &NetworkTx) -> Result<Self, CoreError> {
        config.port = None; // Make sure we always use a random port for client connections.

        let inner = Rc::new(RefCell::new(Inner {
            config,
            groups: HashMap::default(),
            net_tx: net_tx.clone(),
        }));

        Ok(Self { inner })
    }

    /// Returns `true` if this connection manager is already connected to a Client Handlers
    /// group serving the provided public ID.
    pub fn has_connection_to(&self, pub_id: &PublicId) -> bool {
        let inner = self.inner.borrow();
        inner.groups.contains_key(&pub_id)
    }

    /// Send `message` via the `ConnectionGroup` specified by our given `pub_id`.
    pub fn send(&mut self, pub_id: &PublicId, msg: &Message) -> Box<CoreFuture<Response>> {
        self.inner.borrow_mut().send(pub_id, msg)
    }

    /// Connect to Client Handlers that manage the provided ID.
    pub fn bootstrap(&mut self, full_id: SafeKey) -> Box<CoreFuture<()>> {
        self.inner.borrow_mut().bootstrap(full_id)
    }

    /// Reconnect to the network.
    pub fn restart_network(&mut self) {
        unimplemented!();
    }

    /// Disconnect from a group.
    pub fn disconnect(&mut self, pub_id: &PublicId) -> Box<CoreFuture<()>> {
        self.inner.borrow_mut().disconnect(pub_id)
    }
}

struct Inner {
    config: QuicP2pConfig,
    groups: HashMap<PublicId, ConnectionGroup>,
    net_tx: NetworkTx,
}

impl Drop for Inner {
    fn drop(&mut self) {
        // Disconnect from all groups gracefully
        trace!("Dropped ConnectionManager - terminating gracefully");
        let _ = self.net_tx.unbounded_send(NetworkEvent::Disconnected);
    }
}

impl Inner {
    fn bootstrap(&mut self, full_id: SafeKey) -> Box<CoreFuture<()>> {
        trace!("Trying to bootstrap with group {:?}", full_id.public_id());

        let (connected_tx, connected_rx) = futures::oneshot();

        if let Entry::Vacant(value) = self.groups.entry(full_id.public_id()) {
            let _ = value.insert(fry!(ConnectionGroup::new(
                self.config.clone(),
                full_id,
                connected_tx,
                self.net_tx.clone(),
            )));
            Box::new(
                connected_rx
                    .map_err(|err| CoreError::from(format!("{}", err)))
                    .and_then(|res| res)
                    .timeout(Duration::from_secs(CONNECTION_TIMEOUT_SECS))
                    .map_err(|e| {
                        if let Some(err) = e.into_inner() {
                            // Do not swallow the original error in case if it's not a timeout.
                            err
                        } else {
                            CoreError::RequestTimeout
                        }
                    }),
            )
        } else {
            trace!("Group {} is already connected", full_id.public_id());
            ok!(())
        }
    }

    fn send(&mut self, pub_id: &PublicId, msg: &Message) -> Box<CoreFuture<Response>> {
        let msg_id = if let Message::Request { message_id, .. } = msg {
            *message_id
        } else {
            return Box::new(future::err(CoreError::Unexpected(
                "Not a Request".to_string(),
            )));
        };

        let conn_group = fry!(self.groups.get_mut(&pub_id).ok_or_else(|| {
            CoreError::Unexpected(
                "No connection group found - did you call `bootstrap`?".to_string(),
            )
        }));

        conn_group.send(msg_id, msg)
    }

    /// Disconnect from a group.
    pub fn disconnect(&mut self, pub_id: &PublicId) -> Box<CoreFuture<()>> {
        trace!("Disconnecting group {:?}", pub_id);

        let group = self.groups.remove(&pub_id);
        let _ = self.net_tx.unbounded_send(NetworkEvent::Disconnected);
        if let Some(mut group) = group {
            Box::new(group.close().map(move |res| {
                // Drop the group once it's disconnected
                let _ = group;
                res
            }))
        } else {
            error!("No group found for {}", pub_id); // FIXME: handle properly
            ok!(())
        }
    }
}
