// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod connection_group;
mod response_manager;
use tokio::time::timeout;

use crate::{
    client::SafeKey, network_event::NetworkEvent, network_event::NetworkTx, CoreError,
};
// use crate::{fry, ok};
use connection_group::ConnectionGroup;
use futures::future::{self, TryFutureExt};
use log::{error, trace};
use quic_p2p::Config as QuicP2pConfig;
use safe_nd::{Message, PublicId, Response};
use std::{
    cell::RefCell,
    collections::{hash_map::Entry, HashMap},
    rc::Rc,
    time::Duration,
    sync::{Mutex, Arc}
};

const CONNECTION_TIMEOUT_SECS: u64 = 30;

/// Initialises `QuicP2p` instance. Establishes new connections.
/// Contains a reference to crossbeam channel provided by quic-p2p for capturing the events.
#[derive(Clone)]
pub struct ConnectionManager {
    inner: Arc<Mutex<Inner>>,
}

impl ConnectionManager {
    /// Create a new connection manager.
    pub fn new(mut config: QuicP2pConfig, net_tx: &NetworkTx) -> Result<Self, CoreError> {
        config.port = Some(0); // Make sure we always use a random port for client connections.

        let inner = Arc::new(Mutex::new(Inner {
            config,
            groups: HashMap::default(),
            net_tx: net_tx.clone(),
        }));

        Ok(Self { inner })
    }

    /// Returns `true` if this connection manager is already connected to a Client Handlers
    /// group serving the provided public ID.
    pub fn has_connection_to(&self, pub_id: &PublicId) -> bool {
        match self.inner.lock() {
            Ok( inner ) => {

                inner.groups.contains_key(&pub_id)
            },
            Err(error) => false
        }
    }

    /// Send `message` via the `ConnectionGroup` specified by our given `pub_id`.
    pub async fn send(&mut self, pub_id: &PublicId, msg: &Message) -> Result<Response, CoreError> {
        self.inner.lock().unwrap().send(pub_id, msg).await
    }

    /// Connect to Client Handlers that manage the provided ID.
    pub async fn bootstrap(&mut self, full_id: SafeKey) -> Result<(),CoreError> {
        self.inner.lock().unwrap().bootstrap(full_id).await
    }

    /// Reconnect to the network.
    pub fn restart_network(&mut self) {
        unimplemented!();
    }

    /// Disconnect from a group.
    pub async fn disconnect(&mut self, pub_id: &PublicId) -> Result<(),CoreError> {
        self.inner.lock().unwrap().disconnect(pub_id).await
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
    async fn bootstrap(&mut self, full_id: SafeKey) -> Result<(),CoreError> {
        trace!("Trying to bootstrap with group {:?}", full_id.public_id());

        let (connected_tx, connected_rx) = futures::channel::oneshot::channel();

        if let Entry::Vacant(value) = self.groups.entry(full_id.public_id()) {
            let _ = value.insert(r#try!(ConnectionGroup::new(
                self.config.clone(),
                full_id,
                connected_tx
            )));

            match timeout( Duration::from_secs(CONNECTION_TIMEOUT_SECS), connected_rx ).await {
                Ok(response) => {
                    response.map_err(|err| {
                        CoreError::from(format!("{}", err))
    
                    })?
                }, 
                Err(_) => Err( CoreError::from(
                                "Connection timed out when bootstrapping to the network",
                            ))
            }
       
        } else {
            trace!("Group {} is already connected", full_id.public_id());
            Ok(())
        }
    }

    async fn send(&mut self, pub_id: &PublicId, msg: &Message) -> Result<Response, CoreError> {
        let msg_id = if let Message::Request { message_id, .. } = msg {
            *message_id
        } else {
            return Err(CoreError::Unexpected(
                "Not a Request".to_string(),
            ) );
        };

        let conn_group = r#try!(self.groups.get_mut(&pub_id).ok_or_else(|| {
            CoreError::Unexpected(
                "No connection group found - did you call `bootstrap`?".to_string(),
            )
        }));

        conn_group.send(msg_id, msg).await
    }

    /// Disconnect from a group.
    pub async fn disconnect(&mut self, pub_id: &PublicId) -> Result<(), CoreError> {
        trace!("Disconnecting group {:?}", pub_id);

        let group = self.groups.remove(&pub_id);

        if let Some(mut group) = group {
            group.close().await.map(move |res| {
                // Drop the group once it's disconnected
                let _ = group;
                res
            })
        } else {
            error!("No group found for {}", pub_id); // FIXME: handle properly
            Ok(())
        }
    }
}
