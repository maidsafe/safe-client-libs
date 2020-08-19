// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::CoreError;
use bincode::{deserialize, serialize};
use bytes::Bytes;
use futures::{future::join_all, lock::Mutex};
use log::{error, info, trace};
use quic_p2p::{self, Config as QuicP2pConfig, Connection, QuicP2pAsync};
use safe_nd::{
    BlsProof, ClientFullId, HandshakeRequest, HandshakeResponse, Message, MsgEnvelope, MsgSender,
    Proof, QueryResponse,
};
use std::{collections::HashMap, net::SocketAddr, sync::Arc};

/// Initialises `QuicP2p` instance which can bootstrap to the network, establish
/// connections and send messages to several nodes, as well as await responses from them.
#[derive(Clone)]
pub struct ConnectionManager {
    full_id: ClientFullId,
    quic_p2p: QuicP2pAsync,
    elders: Vec<Arc<Mutex<Connection>>>,
}

impl ConnectionManager {
    /// Create a new connection manager.
    pub fn new(mut config: QuicP2pConfig, full_id: ClientFullId) -> Result<Self, CoreError> {
        config.port = Some(0); // Make sure we always use a random port for client connections.
        let quic_p2p = QuicP2pAsync::with_config(Some(config), Default::default(), false)?;

        Ok(Self {
            full_id,
            quic_p2p,
            elders: Vec::default(),
        })
    }

    /// Bootstrap to the network maintaining connections to several nodes.
    pub async fn bootstrap(&mut self) -> Result<(), CoreError> {
        trace!(
            "Trying to bootstrap to the network with public_id: {:?}",
            self.full_id.public_id()
        );

        // Bootstrap and send a handshake request to receive
        // the list of Elders we can then connect to
        let elders_addrs = self.bootstrap_and_handshake().await?;

        // Let's now connect to all Elders
        self.connect_to_elders(elders_addrs).await
    }

    /// Send a `Message` to the network without awaiting for a response.
    pub async fn send_cmd(&mut self, msg: &Message) -> Result<(), CoreError> {
        info!("Sending command message {:?} w/ id: {:?}", msg, msg.id());
        let msg_bytes = self.serialise_in_envelope(msg)?;

        // Send message to all Elders concurrently
        trace!("Sending command to all Elders...");
        let mut tasks = Vec::default();
        for elder_conn in &self.elders {
            let msg_bytes_clone = msg_bytes.clone();
            let conn = Arc::clone(elder_conn);
            let task_handle =
                tokio::spawn(async move { conn.lock().await.send_only(msg_bytes_clone).await });
            tasks.push(task_handle);
        }

        // Let's await for all messages to be sent
        let _results = join_all(tasks).await;

        // TODO: return an error if we didn't successfully
        // sent it to at least a majority of Elders??

        Ok(())
    }

    /// Send a `Message` to the network awaiting for the response.
    pub async fn send_query(&mut self, msg: &Message) -> Result<QueryResponse, CoreError> {
        info!("Sending query message {:?} w/ id: {:?}", msg, msg.id());
        let msg_bytes = self.serialise_in_envelope(msg)?;

        // We send the same message to all Elders concurrently,
        // and we try to find a majority on the responses
        let mut tasks = Vec::default();
        for elder_conn in &self.elders {
            let msg_bytes_clone = msg_bytes.clone();
            let conn = Arc::clone(elder_conn);
            let task_handle = tokio::spawn(async move {
                let response = conn.lock().await.send(msg_bytes_clone).await?;
                match deserialize(&response) {
                    Ok(res) => {
                        trace!("Query response received");
                        Ok(res)
                    }
                    Err(e) => {
                        let err_msg = format!("Unexpected deserialisation error: {:?}", e);
                        error!("{}", err_msg);
                        Err(CoreError::Unexpected(err_msg))
                    }
                }
            });
            tasks.push(task_handle);
        }

        // Let's await for all responses
        // TODO: await only for a majority
        let responses = join_all(tasks).await;

        // Let's figure out what's the value which is in the majority of responses obtained
        let mut votes_map = HashMap::<QueryResponse, usize>::default();
        let mut winner: (Option<QueryResponse>, usize) = (None, 0);
        for join_result in responses.into_iter() {
            if let Ok(response_result) = join_result {
                let response: QueryResponse = response_result.map_err(|err| {
                    CoreError::from(format!(
                        "Failed to obtain a response from the network: {}",
                        err
                    ))
                })?;

                let counter = votes_map.entry(response.clone()).or_insert(0);
                *counter += 1;
                if *counter > winner.1 {
                    winner = (Some(response), *counter);
                }
            }
        }

        // TODO: return an error if we didn't successfully got enough number
        // of responses to represent a majority of Elders

        trace!(
            "Response obtained from majority {} of nodes: {:?}",
            winner.1,
            winner.0
        );
        winner.0.ok_or_else(|| {
            CoreError::from(format!("Failed to obtain a response from the network."))
        })
    }

    // Private helpers

    // Put a `Message` in an envelope so it can be sent to the network
    fn serialise_in_envelope(&self, message: &Message) -> Result<Bytes, CoreError> {
        trace!("Putting message in envelope: {:?}", message);
        let sign = self.full_id.sign(&serialize(message)?);
        let msg_proof = BlsProof {
            public_key: self.full_id.public_key().bls().unwrap(),
            signature: sign.into_bls().unwrap(),
        };

        let envelope = MsgEnvelope {
            message: message.clone(),
            origin: MsgSender::Client(Proof::Bls(msg_proof)),
            proxies: Default::default(),
        };

        let bytes = Bytes::from(serialize(&envelope)?);
        Ok(bytes)
    }

    // Bootstrap to the network to obtaining the list of
    // nodes we should establish connections with
    async fn bootstrap_and_handshake(&mut self) -> Result<Vec<SocketAddr>, CoreError> {
        trace!("Bootstrapping with contacts...");
        let mut node_connection = self.quic_p2p.bootstrap().await?;

        trace!("Sending handshake request to bootstrapped node...");
        let public_id = self.full_id.public_id();
        let handshake = HandshakeRequest::Bootstrap(*public_id.public_key());
        let msg = Bytes::from(serialize(&handshake)?);
        let response = node_connection.send(msg).await?;

        match deserialize(&response) {
            Ok(HandshakeResponse::Rebootstrap(_elders)) => {
                trace!("HandshakeResponse::Rebootstrap, trying again");
                // TODO: initialise `hard_coded_contacts` with received `elders`.
                unimplemented!();
            }
            Ok(HandshakeResponse::Join(elders)) => {
                trace!("HandshakeResponse::Join Elders: ({:?})", elders);

                // Obtain the addresses of the Elders
                let elders_addrs = elders.into_iter().map(|(_xor_name, ci)| ci).collect();
                Ok(elders_addrs)
            }
            Ok(_msg) => Err(CoreError::from(
                "Unexpected message type received while expecting list of Elders to join.",
            )),
            Err(e) => Err(CoreError::from(format!("Unexpected error {:?}", e))),
        }
    }

    // Connect to a set of Elders nodes which will be
    // the receipients of our messages on the network.
    async fn connect_to_elders(&mut self, elders_addrs: Vec<SocketAddr>) -> Result<(), CoreError> {
        // Connect to all Elders concurrently
        // We spawn a task per each node to connect to
        let mut tasks = Vec::default();
        for peer_addr in elders_addrs {
            let mut quic_p2p = self.quic_p2p.clone();
            let full_id = self.full_id.clone();
            let task_handle = tokio::spawn(async move {
                let mut conn = quic_p2p.connect_to(peer_addr).await?;
                let handshake = HandshakeRequest::Join(*full_id.public_id().public_key());
                let msg = Bytes::from(serialize(&handshake)?);
                let join_response = conn.send(msg).await?;
                match deserialize(&join_response) {
                    Ok(HandshakeResponse::Challenge(node_public_key, challenge)) => {
                        trace!(
                            "Got the challenge from {:?}, public id: {}",
                            peer_addr,
                            node_public_key
                        );
                        let response = HandshakeRequest::ChallengeResult(full_id.sign(&challenge));
                        let msg = Bytes::from(serialize(&response)?);
                        conn.send_only(msg).await?;
                        Ok(Arc::new(Mutex::new(conn)))
                    }
                    Ok(_) => Err(CoreError::from(format!(
                        "Unexpected message type while expeccting challenge from Elder."
                    ))),
                    Err(e) => Err(CoreError::from(format!("Unexpected error {:?}", e))),
                }
            });
            tasks.push(task_handle);
        }

        // Let's await for them to all successfully connect, or fail if at least one failed
        let conn_results = join_all(tasks).await;

        // We can now keep each of the connections in our instance
        for join_result in conn_results.into_iter() {
            if let Ok(conn_result) = join_result {
                let conn = conn_result.map_err(|err| {
                    CoreError::from(format!("Failed to connect to an Elder: {}", err))
                })?;

                self.elders.push(conn);
            }
        }

        trace!("Connected to {} Elders.", self.elders.len());
        Ok(())
    }
}
