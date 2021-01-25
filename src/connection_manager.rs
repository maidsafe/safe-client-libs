// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::Error;
use bincode::{deserialize, serialize};
use bytes::Bytes;
use futures::{
    future::{join_all, select_all},
    lock::Mutex,
};
use log::{debug, error, info, trace, warn};
use qp2p::{
    self, Config as QuicP2pConfig, Endpoint, IncomingMessages, Message as Qp2pMessage, QuicP2p,
};
use sn_data_types::{HandshakeRequest, HandshakeResponse, Keypair, TransferValidated};
use sn_messaging::{Event, Message, MessageId, MsgEnvelope, MsgSender, QueryResponse};
use std::{
    collections::{BTreeMap, HashMap},
    net::SocketAddr,
    sync::Arc,
};
use tokio::sync::mpsc::channel;
use tokio::sync::mpsc::Sender;
use tokio::sync::mpsc::UnboundedSender;
use tokio::task::JoinHandle;

static NUMBER_OF_RETRIES: usize = 3;
pub static STANDARD_ELDERS_COUNT: usize = 5;

/// Simple map for correlating a response with votes from various elder responses.
type VoteMap = HashMap<[u8; 32], (QueryResponse, usize)>;

// channel for sending result of transfer validation
type TransferValidationSender = Sender<Result<TransferValidated, Error>>;
type QueryResponseSender = Sender<Result<QueryResponse, Error>>;

type ElderConnectionMap = BTreeMap<SocketAddr, Arc<NetworkListenerHandle>>;

/// JoinHandle for recv stream listener thread
type NetworkListenerHandle = JoinHandle<Result<(), Error>>;
/// Initialises `QuicP2p` instance which can bootstrap to the network, establish
/// connections and send messages to several nodes, as well as await responses from them.
pub struct ConnectionManager {
    keypair: Arc<Keypair>,
    qp2p: QuicP2p,
    elders: ElderConnectionMap,
    endpoint: Option<Arc<Mutex<Endpoint>>>,
    pending_transfer_validations: Arc<Mutex<HashMap<MessageId, TransferValidationSender>>>,
    pending_query_responses: Arc<Mutex<HashMap<(SocketAddr, MessageId), QueryResponseSender>>>,
    notification_sender: UnboundedSender<Error>,
}

impl ConnectionManager {
    /// Create a new connection manager.
    pub async fn new(
        mut config: QuicP2pConfig,
        keypair: Arc<Keypair>,
        notification_sender: UnboundedSender<Error>,
    ) -> Result<Self, Error> {
        config.port = Some(0); // Make sure we always use a random port for client connections.
        let qp2p = QuicP2p::with_config(Some(config), Default::default(), false)?;

        Ok(Self {
            keypair,
            qp2p,
            elders: BTreeMap::default(),
            endpoint: None,
            pending_transfer_validations: Arc::new(Mutex::new(HashMap::default())),
            pending_query_responses: Arc::new(Mutex::new(HashMap::default())),
            notification_sender,
        })
    }

    /// Bootstrap to the network maintaining connections to several nodes.
    pub async fn bootstrap(&mut self) -> Result<(), Error> {
        trace!(
            "Trying to bootstrap to the network with public_key: {:?}",
            self.keypair.public_key()
        );

        // Bootstrap and send a handshake request to receive
        // the list of Elders we can then connect to
        let elders_addrs = self.bootstrap_and_handshake().await?;

        // Let's now connect to all Elders
        self.connect_to_elders(elders_addrs).await?;

        Ok(())
    }

    /// Send a `Message` to the network without awaiting for a response.
    pub async fn send_cmd(&mut self, msg: &Message) -> Result<(), Error> {
        let msg_id = msg.id();

        let endpoint = self.endpoint.clone().ok_or(Error::NotBootstrapped)?;
        let endpoint = endpoint.lock().await;
        let src_addr = endpoint.socket_addr().await?;
        info!(
            "Sending (from {}) command message {:?} w/ id: {:?}",
            src_addr, msg, msg_id
        );
        let msg_bytes = self.serialize_in_envelope(msg)?;

        // Send message to all Elders concurrently
        let mut tasks = Vec::default();

        let elders_addrs: Vec<SocketAddr> = self.elders.keys().cloned().collect();
        // clone elders as we want to update them in this process
        for socket in elders_addrs {
            let msg_bytes_clone = msg_bytes.clone();
            let (connection, incoming) = endpoint.connect_to(&socket).await?;

            if let Some(incoming_messages) = incoming {
                warn!(
                    "No listener existed for elder: {:?} (a listener will be added now)",
                    socket
                );
                self.listen_to_incoming_messages_for_elder(incoming_messages, socket)
                    .await?;
                info!("Elder listener was updated");
            }

            let task_handle: JoinHandle<Result<(), Error>> = tokio::spawn(async move {
                trace!("About to send cmd message {:?} to {:?}", msg_id, &socket);
                let (send_stream, _) = connection.send_bi(msg_bytes_clone).await?;
                let _ = send_stream.finish().await?;

                trace!(
                    "Sent cmd and finished the stream {:?} to {:?}",
                    msg_id,
                    &socket
                );
                Ok(())
            });
            tasks.push(task_handle);
        }

        // Let's await for all messages to be sent
        let results = join_all(tasks).await;

        let mut failures = 0;
        results.iter().for_each(|res| {
            if res.is_err() {
                failures += 1;
            }
        });

        if failures > 0 {
            error!("Sending the message to {} Elders failed", failures);
        }

        Ok(())
    }

    /// Remove a pending transfer sender from the listener map
    pub async fn remove_pending_transfer_sender(&self, msg_id: &MessageId) -> Result<(), Error> {
        trace!("Removing pending transfer sender");
        let mut listeners = self.pending_transfer_validations.lock().await;

        let _ = listeners
            .remove(msg_id)
            .ok_or(Error::NoTransferValidationListener)?;

        Ok(())
    }

    /// Send a transfer validation message to all Elder without awaiting for a response.
    pub async fn send_transfer_validation(
        &self,
        msg: &Message,
        sender: Sender<Result<TransferValidated, Error>>,
    ) -> Result<(), Error> {
        info!(
            "Sending transfer validation command {:?} w/ id: {:?}",
            msg,
            msg.id()
        );
        let msg_bytes = self.serialize_in_envelope(msg)?;

        let msg_id = msg.id();
        {
            let _ = self
                .pending_transfer_validations
                .lock()
                .await
                .insert(msg_id, sender);
        }

        // Send message to all Elders concurrently
        let mut tasks = Vec::default();
        for socket in self.elders.keys() {
            let msg_bytes_clone = msg_bytes.clone();

            let endpoint = self.endpoint.clone().ok_or(Error::NotBootstrapped)?;
            let endpoint = endpoint.lock().await;
            let (connection, _) = endpoint.connect_to(&socket).await?;

            let task_handle = tokio::spawn(async move {
                trace!(
                    "Sending transfer validation to Elder {}",
                    connection.remote_address()
                );
                let (send_stream, _) = connection.send_bi(msg_bytes_clone).await?;
                send_stream.finish().await
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
    pub async fn send_query(&mut self, msg: &Message) -> Result<QueryResponse, Error> {
        info!("sending query message {:?} w/ id: {:?}", msg, msg.id());
        let msg_bytes = self.serialize_in_envelope(&msg)?;

        // We send the same message to all Elders concurrently,
        // and we try to find a majority on the responses
        let mut tasks = Vec::default();

        let elders_addrs: Vec<SocketAddr> = self.elders.keys().cloned().collect();
        for socket in elders_addrs {
            let msg_bytes_clone = msg_bytes.clone();
            // Create a new stream here to not have to worry about filtering replies
            let msg_id = msg.id();

            let pending_query_responses = self.pending_query_responses.clone();

            let endpoint = self.endpoint.clone().ok_or(Error::NotBootstrapped)?;
            let endpoint = endpoint.lock().await;
            let (connection, incoming) = endpoint.connect_to(&socket).await?;

            if let Some(incoming_messages) = incoming {
                warn!(
                    "No listener existed for elder: {:?} (a listener will be added now)",
                    socket
                );
                self.listen_to_incoming_messages_for_elder(incoming_messages, socket)
                    .await?;
                info!("Elder listener was updated");
            }

            let task_handle = tokio::spawn(async move {
                // Retry queries that failed for connection issues
                let mut done_trying = false;
                let mut result = Err(Error::ElderQuery);
                let mut attempts: usize = 1;

                while !done_trying {
                    let msg_bytes_clone = msg_bytes_clone.clone();

                    let (sender, mut receiver) = channel::<Result<QueryResponse, Error>>(7);
                    {
                        let _ = pending_query_responses
                            .lock()
                            .await
                            .insert((socket, msg_id), sender);
                    }

                    // TODO: we need to remove the msg_id from
                    // pending_query_responses upon any failure below
                    match connection.send_bi(msg_bytes_clone).await {
                        Ok((send_stream, _)) => {
                            send_stream.finish().await?;

                            // TODO: receive response here.
                            result = match receiver.recv().await {
                                Some(result) => match result {
                                    Ok(response) => Ok(response),
                                    Err(_) => Err(Error::ReceivingQuery),
                                },
                                None => Err(Error::ReceivingQuery),
                            };
                        }
                        Err(_error) => {
                            result = {
                                // TODO: remove it from the pending_query_responses then
                                Err(Error::ReceivingQuery)
                            }
                        }
                    };

                    debug!(
                        "Try #{:?} @ {:?}. Got back response: {:?}",
                        attempts,
                        socket,
                        &result.is_ok()
                    );

                    if result.is_ok() || attempts > NUMBER_OF_RETRIES {
                        done_trying = true;
                    }

                    attempts += 1;
                }

                result
            });

            tasks.push(task_handle);
        }

        // Let's figure out what's the value which is in the majority of responses obtained
        let mut vote_map = VoteMap::default();
        let mut received_errors = 0;

        // 2/3 of known elders
        let threshold: usize = (self.elders.len() as f32 / 2_f32).ceil() as usize;

        trace!("Vote threshold is: {:?}", threshold);
        let mut winner: (Option<QueryResponse>, usize) = (None, threshold);

        // Let's await for all responses
        let mut has_elected_a_response = false;

        let mut todo = tasks;

        while !has_elected_a_response {
            if todo.is_empty() {
                warn!("No more connections to try");
                break;
            }

            let (res, _idx, remaining_futures) = select_all(todo.into_iter()).await;
            todo = remaining_futures;

            if let Ok(res) = res {
                match res {
                    Ok(response) => {
                        debug!("QueryResponse received is: {:#?}", response);

                        // bincode here as we're using the internal qr, without serialisation
                        // this is only used internally to sn_client
                        let key = tiny_keccak::sha3_256(&serialize(&response)?);
                        let (_, counter) = vote_map.entry(key).or_insert((response.clone(), 0));
                        *counter += 1;

                        // First, see if this latest response brings us above the threshold for any response
                        if *counter > threshold {
                            trace!("Enough votes to be above response threshold");

                            winner = (Some(response.clone()), *counter);
                            has_elected_a_response = true;
                        }
                    }
                    _ => {
                        warn!("Unexpected message in reply to query (retrying): {:?}", res);
                        received_errors += 1;
                    }
                }
            } else if let Err(error) = res {
                error!("Error spawning query task: {:?} ", error);
                received_errors += 1;
            }

            // Second, let's handle no winner if we have > threshold responses.
            if !has_elected_a_response {
                winner = self.select_best_of_the_rest_response(
                    winner,
                    threshold,
                    &vote_map,
                    received_errors,
                    &mut has_elected_a_response,
                )?;
            }
        }

        debug!(
            "Response obtained after querying {} nodes: {:?}",
            winner.1, winner.0
        );

        winner.0.ok_or(Error::NoResponse)
    }

    /// Choose the best response when no single responses passes the threshold
    fn select_best_of_the_rest_response(
        &self,
        current_winner: (Option<QueryResponse>, usize),
        threshold: usize,
        vote_map: &VoteMap,
        received_errors: usize,
        has_elected_a_response: &mut bool,
    ) -> Result<(Option<QueryResponse>, usize), Error> {
        trace!("No response selected yet, checking if fallback needed");
        let mut number_of_responses = 0;
        let mut most_popular_response = current_winner;

        for (_, (message, votes)) in vote_map.iter() {
            number_of_responses += votes;
            trace!(
                "Number of votes cast :{:?}. Threshold is: {:?} votes",
                number_of_responses,
                threshold
            );

            number_of_responses += received_errors;

            trace!(
                "Total number of responses (votes and errors) :{:?}",
                number_of_responses
            );

            if most_popular_response.0 == None {
                most_popular_response = (Some(message.clone()), *votes);
            }

            if votes > &most_popular_response.1 {
                trace!("Reselecting winner, with {:?} votes: {:?}", votes, message);

                most_popular_response = (Some(message.clone()), *votes)
            } else {
                // TODO: check w/ farming we get a proper history returned w /matching responses.
                if let QueryResponse::GetHistory(Ok(history)) = &message {
                    // if we're not more popular but in simu payout mode, check if we have more history...
                    if cfg!(feature = "simulated-payouts") && votes == &most_popular_response.1 {
                        if let Some(QueryResponse::GetHistory(res)) = &most_popular_response.0 {
                            if let Ok(popular_history) = res {
                                if history.len() > popular_history.len() {
                                    trace!("GetHistory response received in Simulated Payouts... choosing longest history. {:?}", history);
                                    most_popular_response = (Some(message.clone()), *votes)
                                }
                            }
                        }
                    }
                }
            }
        }

        if number_of_responses > threshold {
            trace!("No clear response above the threshold, so choosing most popular response with: {:?} votes: {:?}", most_popular_response.1, most_popular_response.0);
            *has_elected_a_response = true;
        }

        Ok(most_popular_response)
    }

    // Private helpers

    // Put a `Message` in an envelope so it can be sent to the network
    fn serialize_in_envelope(&self, message: &Message) -> Result<Bytes, Error> {
        trace!("Putting message in envelope: {:?}", message);
        let sign = self.keypair.sign(&message.serialize()?);

        let envelope = MsgEnvelope {
            message: message.clone(),
            origin: MsgSender::client(self.keypair.public_key(), sign)?,
            proxies: Default::default(),
        };

        let bytes = envelope.serialize()?;
        Ok(bytes)
    }

    // Bootstrap to the network to obtaining the list of
    // nodes we should establish connections with
    async fn bootstrap_and_handshake(&mut self) -> Result<Vec<SocketAddr>, Error> {
        trace!("Bootstrapping with contacts...");
        let (endpoint, conn, mut incoming_messages) = self.qp2p.bootstrap().await?;
        self.endpoint = Some(Arc::new(Mutex::new(endpoint)));

        trace!("Sending handshake request to bootstrapped node...");
        let public_key = self.keypair.public_key();
        let handshake = HandshakeRequest::Bootstrap(public_key);
        let msg = Bytes::from(serialize(&handshake)?);

        let result = match conn.send_bi(msg).await {
            Ok((send_stream, _)) => {
                send_stream.finish().await?;
                if let Some(message) = incoming_messages.next().await {
                    match message {
                        Qp2pMessage::BiStream { bytes, .. }
                        | Qp2pMessage::UniStream { bytes, .. } => {
                            match deserialize(&bytes) {
                                Ok(HandshakeResponse::Rebootstrap(_elders)) => {
                                    trace!("HandshakeResponse::Rebootstrap, trying again");
                                    // TODO: initialise `hard_coded_contacts` with received `elders`.
                                     Err(Error::UnexpectedMessageOnJoin("Client should re-bootstrap with a new set of Elders, but it's not yet supported.".to_string()))
                                }
                                Ok(HandshakeResponse::Join(elders)) => {
                                    trace!("HandshakeResponse::Join Elders: ({:?})", elders);
                                    // Obtain the addresses of the Elders
                                    let elders_addrs = elders
                                        .into_iter()
                                        .map(|(_, socket_addr)| socket_addr)
                                        .collect();

                                     Ok(elders_addrs)
                                }
                                Ok(HandshakeResponse::InvalidSection) =>  Err(Error::UnexpectedMessageOnJoin(
                                    "bootstrapping was rejected by since it's an invalid section to join.".to_string(),
                                )),
                                Err(e) =>  Err(e.into()),
                            }
                        }
                    }
                } else {
                    Err(Error::UnexpectedMessageOnJoin(
                        "bootstrapping was rejected by since it's an invalid section to join."
                            .to_string(),
                    ))
                }
            }
            Err(_error) => Err(Error::ReceivingQuery),
        };

        result
    }

    pub fn number_of_connected_elders(&self) -> usize {
        self.elders.len()
    }

    // Connect to a set of Elders nodes which will be
    // the receipients of our messages on the network.
    async fn connect_to_elders(&mut self, elders_addrs: Vec<SocketAddr>) -> Result<(), Error> {
        // Connect to all Elders concurrently
        // We spawn a task per each node to connect to
        let mut tasks = Vec::default();

        let endpoint = self.endpoint.clone().ok_or(Error::NotBootstrapped)?;
        for peer_addr in elders_addrs {
            let keypair = self.keypair.clone();

            let endpoint = endpoint.clone();
            let task_handle = tokio::spawn(async move {
                let mut result = Err(Error::ElderConnection);
                let mut connected = false;
                let mut attempts: usize = 0;
                while !connected && attempts <= NUMBER_OF_RETRIES {
                    let public_key = keypair.public_key();
                    attempts += 1;

                    let (connection, incoming_messages) = {
                        let endpoint = endpoint.lock().await;
                        endpoint.connect_to(&peer_addr).await?
                    };

                    let incoming = incoming_messages.ok_or(Error::NoElderListenerEstablished)?;

                    let handshake = HandshakeRequest::Join(public_key);
                    let msg = Bytes::from(serialize(&handshake)?);
                    let (send_stream, _) = connection.send_bi(msg).await?;
                    send_stream.finish().await?;

                    connected = true;

                    debug!(
                        "Elder conn attempt #{} @ {} is connected? : {:?}",
                        attempts, peer_addr, connected
                    );

                    result = Ok((incoming, peer_addr))
                }

                result
            });
            tasks.push(task_handle);
        }

        // TODO: Do we need a timeout here to check sufficient time has passed + or sufficient connections?
        let mut has_sufficent_connections = false;

        let mut todo = tasks;

        while !has_sufficent_connections {
            if todo.is_empty() {
                warn!("No more elder connections to try");
                break;
            }

            let (res, _idx, remaining_futures) = select_all(todo.into_iter()).await;

            if remaining_futures.is_empty() {
                has_sufficent_connections = true;
            }

            todo = remaining_futures;

            if let Ok(elder_result) = res {
                let res = elder_result.map_err(|err| {
                    // elder connection retires already occur above
                    warn!("Failed to connect to Elder @ : {}", err);
                });

                if let Ok((incoming_messages, socket_addr)) = res {
                    info!("Connected to elder: {:?}", socket_addr);

                    // save the listener connection for receiving responses
                    self.listen_to_incoming_messages_for_elder(incoming_messages, socket_addr)
                        .await?;
                }
            }

            // TODO: this will effectively stop driving futures after we get 2...
            // We should still let all progress... just without blocking
            if self.elders.len() >= STANDARD_ELDERS_COUNT {
                has_sufficent_connections = true;
            }

            if self.elders.len() < STANDARD_ELDERS_COUNT {
                warn!("Connected to only {:?} elders.", self.elders.len());
            }

            if self.elders.len() < STANDARD_ELDERS_COUNT - 2 && has_sufficent_connections {
                return Err(Error::InsufficientElderConnections);
            }
        }

        trace!("Connected to {} Elders.", self.elders.len());
        Ok(())
    }

    /// Listen for incoming messages on a connection
    pub async fn listen_to_incoming_messages_for_elder(
        &mut self,
        mut incoming_messages: IncomingMessages,
        elder_addr: SocketAddr,
    ) -> Result<(), Error> {
        debug!("Adding IncomingMessages listener for {:?}", elder_addr);

        let pending_transfer_validations = Arc::clone(&self.pending_transfer_validations);
        let notifier = self.notification_sender.clone();

        let pending_queries = self.pending_query_responses.clone();

        // Spawn a thread for all the connections
        let handle = tokio::spawn(async move {
            while let Some(message) = incoming_messages.next().await {
                warn!("Message received in qp2p listener");
                match message {
                    Qp2pMessage::BiStream { bytes, .. } | Qp2pMessage::UniStream { bytes, .. } => {
                        match MsgEnvelope::from(bytes) {
                            Ok(envelope) => {
                                warn!(
                                    "Message received at listener for {:?}: {:?}",
                                    &elder_addr, &envelope.message
                                );
                                match envelope.message.clone() {
                                    Message::QueryResponse {
                                        response,
                                        correlation_id,
                                        ..
                                    } => {
                                        trace!("Query response in: {:?}", response);

                                        if let Some(mut sender) = pending_queries
                                            .lock()
                                            .await
                                            .remove(&(elder_addr, correlation_id))
                                        {
                                            trace!("Sender channel found for query response");
                                            let _ = sender.send(Ok(response)).await;
                                        } else {
                                            error!("No matching pending query found for elder {:?}  and message {:?}", elder_addr, correlation_id);
                                        }
                                    }
                                    Message::Event {
                                        event,
                                        correlation_id,
                                        ..
                                    } => {
                                        if let Event::TransferValidated { event, .. } = event {
                                            if let Some(sender) = pending_transfer_validations
                                                .lock()
                                                .await
                                                .get_mut(&correlation_id)
                                            {
                                                info!("Accumulating SignatureShare");
                                                let _ = sender.send(Ok(event)).await;
                                            } else {
                                                warn!("No matching transfer validation event listener found for elder {:?} and message {:?}", elder_addr, correlation_id);
                                                warn!("It may be that this transfer is complete and the listener cleaned up already.");
                                                trace!("Event received was {:?}", event);
                                            }
                                        }
                                    }
                                    Message::CmdError {
                                        error,
                                        correlation_id,
                                        ..
                                    } => {
                                        if let Some(sender) = pending_transfer_validations
                                            .lock()
                                            .await
                                            .get_mut(&correlation_id)
                                        {
                                            debug!("Cmd Error was received, sending on channel to caller");
                                            let _ =
                                                sender.send(Err(Error::from(error.clone()))).await;
                                        } else {
                                            warn!("No sender subscribing and listening for errors relating to message {:?}. Error returned is: {:?}", correlation_id, error)
                                        }

                                        let _ = notifier.send(Error::from(error));
                                    }
                                    msg => {
                                        warn!("another message type received {:?}", msg);
                                    }
                                }
                            }
                            Err(_error) => {
                                error!("Could not deserialize MessageEnvelope");
                            }
                        }
                    }
                }
            }

            Ok::<(), Error>(())
        });

        // Some or None, not super important if this existed before...
        let _ = self.elders.insert(elder_addr, Arc::new(handle));

        Ok(())
    }
}
