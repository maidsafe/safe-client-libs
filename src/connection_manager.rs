// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::ClientError;
use bincode::{deserialize, serialize};
use bytes::Bytes;
use futures::{
    channel::oneshot::Sender,
    future::{join_all, select_all},
    lock::Mutex,
};
use log::{debug, error, info, trace, warn};
use qp2p::{self, Config as QuicP2pConfig, Connection, Endpoint, QuicP2p, RecvStream, SendStream};
use sn_data_types::{
    BlsProof, ClientFullId, DebitAgreementProof, HandshakeRequest, HandshakeResponse, Message,
    MessageId, MsgEnvelope, MsgSender, Proof, QueryResponse,
};
use std::{collections::HashMap, net::SocketAddr, sync::Arc};
use tokio::task::JoinHandle;
/// Simple map for correlating a response with votes from various elder responses.
type VoteMap = HashMap<QueryResponse, usize>;

// channel for sending result of transfer validation
type TransferValidationSender = Sender<Result<DebitAgreementProof, ClientError>>;

#[derive(Clone)]
struct ElderStream {
    send_stream: Arc<Mutex<SendStream>>,
    connection: Arc<Mutex<Connection>>,
    listener: Arc<Mutex<NetworkListenerHandle>>,
}

/// JoinHandle for recv stream listener thread
type NetworkListenerHandle = JoinHandle<Result<(), ClientError>>;
/// Initialises `QuicP2p` instance which can bootstrap to the network, establish
/// connections and send messages to several nodes, as well as await responses from them.
#[derive(Clone)]
pub struct ConnectionManager {
    full_id: ClientFullId,
    qp2p: QuicP2p,
    elders: Vec<ElderStream>,
    endpoint: Arc<Mutex<Endpoint>>,
    pending_transfer_validations: Arc<Mutex<HashMap<MessageId, TransferValidationSender>>>,
}

impl ConnectionManager {
    /// Create a new connection manager.
    pub fn new(mut config: QuicP2pConfig, full_id: ClientFullId) -> Result<Self, ClientError> {
        config.port = Some(0); // Make sure we always use a random port for client connections.
        let qp2p = QuicP2p::with_config(Some(config), Default::default(), false)?;
        let endpoint = qp2p.new_endpoint()?;

        Ok(Self {
            full_id,
            qp2p,
            elders: Vec::default(),
            endpoint: Arc::new(Mutex::new(endpoint)),
            pending_transfer_validations: Arc::new(Mutex::new(HashMap::default())),
        })
    }

    /// Bootstrap to the network maintaining connections to several nodes.
    pub async fn bootstrap(&mut self) -> Result<(), ClientError> {
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
    pub async fn send_cmd(&mut self, msg: &Message) -> Result<(), ClientError> {
        info!("Sending command message {:?} w/ id: {:?}", msg, msg.id());
        let msg_bytes = self.serialise_in_envelope(msg)?;

        // Send message to all Elders concurrently
        let mut tasks = Vec::default();
        for elder in &self.elders {
            let msg_bytes_clone = msg_bytes.clone();
            let connection = Arc::clone(&elder.connection);
            let task_handle = tokio::spawn(async move {
                let _ = connection.lock().await.send(msg_bytes_clone).await;
            });
            tasks.push(task_handle);
        }

        // Let's await for all messages to be sent
        let _results = join_all(tasks).await;

        // TODO: return an error if we didn't successfully
        // send it to at least a majority of Elders??

        Ok(())
    }

    /// Send a `Message` to the network without awaiting for a response.
    pub async fn send_transfer_validation(
        &mut self,
        msg: &Message,
        sender: Sender<Result<DebitAgreementProof, ClientError>>,
    ) -> Result<(), ClientError> {
        info!(
            "Sending transfer validation command {:?} w/ id: {:?}",
            msg,
            msg.id()
        );
        let msg_bytes = self.serialise_in_envelope(msg)?;

        let msg_id = msg.id();
        let _ = self
            .pending_transfer_validations
            .lock()
            .await
            .insert(msg_id, sender);

        // Send message to all Elders concurrently
        let mut tasks = Vec::default();
        for elder in &self.elders {
            let msg_bytes_clone = msg_bytes.clone();
            let connection = Arc::clone(&elder.connection);
            let task_handle = tokio::spawn(async move {
                let _ = connection.lock().await.send(msg_bytes_clone).await;
            });
            tasks.push(task_handle);
        }

        // Let's await for all messages to be sent
        let _results = join_all(tasks).await;

        // TODO: return an error if we didn't successfully
        // send it to at least a majority of Elders??

        Ok(())
    }

    /// Send a Query `Message` to the network awaiting for the response.
    pub async fn send_query(&mut self, msg: &Message) -> Result<QueryResponse, ClientError> {
        info!("Sending query message {:?} w/ id: {:?}", msg, msg.id());
        let msg_bytes = self.serialise_in_envelope(msg)?;

        // We send the same message to all Elders concurrently,
        // and we try to find a majority on the responses
        let mut tasks = Vec::default();
        for elder in &self.elders {
            let msg_bytes_clone = msg_bytes.clone();

            // Create a new stream here to not have to worry about filtering replies
            let connection = Arc::clone(&elder.connection);

            let task_handle = tokio::spawn(async move {
                let mut streams = connection.lock().await.send(msg_bytes_clone).await?;
                let response = streams.1.next().await?;
                match deserialize(&response) {
                    Ok(MsgEnvelope { message, .. }) => Ok(message),
                    Err(e) => {
                        let err_msg = format!("Unexpected deserialisation error: {:?}", e);
                        error!("{}", err_msg);
                        Err(ClientError::Unexpected(err_msg))
                    }
                }
            });

            tasks.push(task_handle);
        }

        // Let's figure out what's the value which is in the majority of responses obtained
        let mut vote_map = VoteMap::default();

        // TODO: make threshold dynamic based upon known elders
        let threshold = 2;
        let mut winner: (Option<QueryResponse>, usize) = (None, threshold);

        // Let's await for all responses
        let mut has_elected_a_response = false;

        let mut todo = tasks;

        while !has_elected_a_response {
            let (res, _idx, remaining_futures) = select_all(todo.into_iter()).await;
            todo = remaining_futures;

            if let Ok(res) = res {
                match res {
                    Ok(Message::QueryResponse { response, .. }) => {
                        trace!("QueryResponse is: {:?}", response);
                        let counter = vote_map.entry(response.clone()).or_insert(0);
                        *counter += 1;

                        // First, see if this latest response brings us above the threashold for any response
                        if *counter > threshold {
                            winner = (Some(response.clone()), *counter);
                            has_elected_a_response = true;
                        }

                        // Second, let's handle no winner on majority responses.
                        if !has_elected_a_response {
                            let mut number_of_responses = 0;
                            let mut most_popular_response = winner.clone();

                            for (message, votes) in vote_map.iter() {
                                number_of_responses += votes;

                                if most_popular_response.0 == None {
                                    most_popular_response = (Some(message.clone()), *votes);
                                }

                                if votes > &most_popular_response.1 {
                                    trace!("setting winner, with {:?} votes: {:?}", votes, message);

                                    most_popular_response = (Some(message.clone()), *votes)
                                }
                            }

                            if number_of_responses == self.elders.len() {
                                trace!("No clear response above the threshold ({:?}), so choosing most popular response with: {:?} votes: {:?}", threshold, most_popular_response.1, most_popular_response.0);
                                winner = most_popular_response;
                                has_elected_a_response = true;
                            }
                        }
                    }
                    _ => {
                        error!("Unexpected message in reply to Query: {:?}", res);
                    }
                }
            }
        }

        trace!(
            "Response obtained from majority {} of nodes: {:?}",
            winner.1,
            winner.0
        );

        winner
            .0
            .ok_or_else(|| ClientError::from("Failed to obtain a response from the network."))
    }

    // Private helpers

    // Put a `Message` in an envelope so it can be sent to the network
    fn serialise_in_envelope(&self, message: &Message) -> Result<Bytes, ClientError> {
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
    async fn bootstrap_and_handshake(&mut self) -> Result<Vec<SocketAddr>, ClientError> {
        trace!("Bootstrapping with contacts...");
        let (endpoint, conn) = self.qp2p.bootstrap().await?;
        self.endpoint = Arc::new(Mutex::new(endpoint));

        trace!("Sending handshake request to bootstrapped node...");
        let public_id = self.full_id.public_id();
        let handshake = HandshakeRequest::Bootstrap(*public_id.public_key());
        let msg = Bytes::from(serialize(&handshake)?);
        let mut streams = conn.send(msg).await?;
        let response = streams.1.next().await?;

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
            Ok(_msg) => Err(ClientError::from(
                "Unexpected message type received while expecting list of Elders to join.",
            )),
            Err(e) => Err(ClientError::from(format!("Unexpected error {:?}", e))),
        }
    }

    // Connect to a set of Elders nodes which will be
    // the receipients of our messages on the network.
    async fn connect_to_elders(
        &mut self,
        elders_addrs: Vec<SocketAddr>,
    ) -> Result<(), ClientError> {
        // Connect to all Elders concurrently
        // We spawn a task per each node to connect to
        let mut tasks = Vec::default();

        for peer_addr in elders_addrs {
            let full_id = self.full_id.clone();

            // We use one endpoint for all elders
            let endpoint = Arc::clone(&self.endpoint);

            let task_handle = tokio::spawn(async move {
                let connection = endpoint.lock().await.connect_to(&peer_addr).await?;

                let handshake = HandshakeRequest::Join(*full_id.public_id().public_key());
                let msg = Bytes::from(serialize(&handshake)?);
                let (_send_stream, mut recv_stream) = connection.send(msg).await?;
                let final_response = recv_stream.next().await?;

                match deserialize(&final_response) {
                    Ok(HandshakeResponse::Challenge(node_public_key, challenge)) => {
                        trace!(
                            "Got the challenge from {:?}, public id: {}",
                            peer_addr,
                            node_public_key
                        );
                        let response = HandshakeRequest::ChallengeResult(full_id.sign(&challenge));
                        let msg = Bytes::from(serialize(&response)?);
                        let (send_stream, recv_stream) = connection.send(msg).await?;

                        Ok((
                            Arc::new(Mutex::new(send_stream)),
                            Arc::new(Mutex::new(connection)),
                            recv_stream,
                        ))
                    }
                    Ok(_) => Err(ClientError::from(
                        "Unexpected message type while expeccting challenge from Elder.",
                    )),
                    Err(e) => Err(ClientError::from(format!("Unexpected error {:?}", e))),
                }
            });
            tasks.push(task_handle);
        }

        // Let's await for them to all successfully connect, or fail if at least one failed

        //TODO: Do we need a timeout here to check sufficient time has passed + or sufficient connections?
        let mut has_sufficent_connections = false;

        let mut todo = tasks;

        while !has_sufficent_connections {
            let (res, _idx, remaining_futures) = select_all(todo.into_iter()).await;

            if remaining_futures.is_empty() {
                has_sufficent_connections = true;
            }

            todo = remaining_futures;

            if let Ok(elder_result) = res {
                let (send_stream, connection, recv_stream) = elder_result.map_err(|err| {
                    ClientError::from(format!("Failed to connect to an Elder: {}", err))
                })?;

                let listener = self.listen_to_receive_stream(recv_stream).await?;
                // We can now keep this connections in our instance
                self.elders.push(ElderStream {
                    send_stream,
                    connection,
                    listener: Arc::new(Mutex::new(listener)),
                });
            }

            // TODO: this will effectively stop driving futures after we get 2...
            // We should still let all progress... just without blocking
            if self.elders.len() > 2 {
                has_sufficent_connections = true;
            }

            if self.elders.len() < 7 {
                warn!("Connected to only {:?} elders.", self.elders.len());
            }

            if self.elders.len() < 3 && has_sufficent_connections {
                return Err(ClientError::from("Could not connect to sufficient elders."));
            }
        }

        trace!("Connected to {} Elders.", self.elders.len());
        Ok(())
    }

    /// Listen for incoming messages via IncomingConnections.
    pub async fn listen_to_receive_stream(
        &mut self,
        mut receiver: RecvStream,
    ) -> Result<NetworkListenerHandle, ClientError> {
        trace!("Adding listener");

        let pending_transfer_validations = Arc::clone(&self.pending_transfer_validations);

        // Spawn a thread for all the connections
        let handle = tokio::spawn(async move {
            info!("Listening for incoming connections started");

            // this is recv stream used to send challenge response. Send
            while let Ok(bytes) = receiver.next().await {
                trace!("Listener message received");

                match deserialize::<MsgEnvelope>(&bytes) {
                    Ok(envelope) => {
                        debug!("Message received at listener: {:?}", &envelope.message);

                        match envelope.message.clone() {
                            Message::Event {
                                event: _,
                                correlation_id: _,
                                ..
                            } => {
                                // TODO: Send full event or error out to desired listener.
                                warn!("Event received {:?}", envelope.message);
                            }
                            Message::CmdError {
                                error,
                                correlation_id,
                                ..
                            } => {
                                error!("CmdError received {:?}", error);

                                if let Some(sender) = pending_transfer_validations
                                    .lock()
                                    .await
                                    .remove(&correlation_id)
                                {
                                    let _ = sender.send(Err(ClientError::from(format!(
                                        "CmdError received: {:?}",
                                        error
                                    ))));
                                };
                            }
                            _ => {
                                warn!("another message type received");
                            }
                        }
                    }
                    Err(_) => error!("Error deserializing network message"),
                };
            }

            error!("Receive stream listener stopped.");

            Ok::<(), ClientError>(())
        });

        Ok(handle)
    }
}
