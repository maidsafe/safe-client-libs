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

use crate::{client::SafeKey, network_event::NetworkEvent, network_event::NetworkTx, CoreError};
use connection_group::ConnectionGroup;
use log::{error, trace};
use quic_p2p::Config as QuicP2pConfig;
use safe_nd::{Message, PublicId, Response};
use std::{
    collections::{hash_map::Entry, HashMap},
    time::Duration,
};

const CONNECTION_TIMEOUT_SECS: u64 = 30;

/// Initialises `QuicP2p` instance. Establishes new connections.
pub struct ConnectionManager {
    config: QuicP2pConfig,
    groups: HashMap<PublicId, ConnectionGroup>,
    net_tx: NetworkTx,
}

impl Drop for ConnectionManager {
    fn drop(&mut self) {
        trace!("Dropped ConnectionManager");
        let _ = self.net_tx.unbounded_send(NetworkEvent::Disconnected);
    }
}

impl ConnectionManager {
    /// Create a new connection manager.
    pub fn new(mut config: QuicP2pConfig, net_tx: &NetworkTx) -> Result<Self, CoreError> {
        config.port = Some(0); // Make sure we always use a random port for client connections.

        Ok(Self {
            config,
            groups: HashMap::default(),
            net_tx: net_tx.clone(),
        })
    }

    /// Returns `true` if this connection manager is already connected to a Client Handlers
    /// group serving the provided public ID.
    pub async fn has_connection_to(&self, pub_id: &PublicId) -> bool {
        self.groups.contains_key(&pub_id)
    }

    /// Connect to Client Handlers that manage the provided ID.
    pub async fn bootstrap(&mut self, full_id: SafeKey) -> Result<(), CoreError> {
        trace!("Trying to bootstrap with group {:?}", full_id.public_id());

        if let Entry::Vacant(value) = self.groups.entry(full_id.public_id()) {
            let mut conn_group = ConnectionGroup::new(self.config.clone(), full_id)?;
            match timeout(
                Duration::from_secs(CONNECTION_TIMEOUT_SECS),
                conn_group.bootstrap(),
            )
            .await
            {
                Ok(response) => {
                    response.map_err(|err| CoreError::from(format!("{}", err)))?;
                    let _ = value.insert(conn_group);
                }
                Err(_) => {
                    return Err(CoreError::from(
                        "Connection timed out when bootstrapping to the network",
                    ));
                }
            }
        } else {
            trace!("Group {} is already connected", full_id.public_id());
        }
        Ok(())
    }

    /// Send `message` via the `ConnectionGroup` specified by our given `pub_id`.
    pub async fn send(&mut self, pub_id: &PublicId, msg: &Message) -> Result<Response, CoreError> {
        if let Message::Request { .. } = msg {
            let conn_group = self.groups.get_mut(&pub_id).ok_or_else(|| {
                CoreError::Unexpected(
                    "No connection group found - did you call `bootstrap`?".to_string(),
                )
            })?;

            match timeout(
                Duration::from_secs(CONNECTION_TIMEOUT_SECS),
                conn_group.send(msg),
            )
            .await
            {
                Ok(response) => response.map_err(|err| CoreError::from(format!("{}", err))),
                Err(_) => Err(CoreError::RequestTimeout),
            }
        } else {
            return Err(CoreError::Unexpected("Not a Request".to_string()));
        }
    }

    /// Disconnect from a group.
    pub async fn disconnect(&mut self, pub_id: &PublicId) -> Result<(), CoreError> {
        trace!("Disconnecting group {:?}", pub_id);

        match self.groups.remove(&pub_id) {
            Some(_) => Ok(()),
            None => Err(CoreError::from(format!("No group found for {}", pub_id))),
        }
    }
}
