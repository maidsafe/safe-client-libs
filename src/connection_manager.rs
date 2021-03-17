// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::Error;
use bincode::serialize;
use futures::{
    future::{join_all, select_all},
    lock::Mutex,
};
use log::{debug, error, info, trace, warn};
use qp2p::{self, Config as QuicP2pConfig, Endpoint, IncomingMessages, QuicP2p};
use sn_data_types::{Keypair, PublicKey, Signature, TransferValidated};
use sn_messaging::{
    client::{Event, Message, ProcessMsg, QueryResponse},
    section_info::{
        Error as SectionInfoError, GetSectionResponse, Message as SectionInfoMsg, SectionInfo,
    },
    MessageId, MessageType, WireMsg,
};
use std::{
    borrow::Borrow,
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    net::SocketAddr,
    sync::Arc,
};
use threshold_crypto::PublicKeySet;
use tiny_keccak::{Hasher, Sha3};
use tokio::{
    sync::mpsc::{channel, Sender, UnboundedSender},
    task::JoinHandle,
};
use xor_name::{Prefix, XorName};

static NUMBER_OF_RETRIES: usize = 3;

/// Simple map for correlating a response with votes from various elder responses.
type VoteMap = HashMap<[u8; 32], (QueryResponse, usize)>;

// channel for sending result of transfer validation
type TransferValidationSender = Sender<Result<TransferValidated, Error>>;
type QueryResponseSender = Sender<Result<QueryResponse, Error>>;

type PendingTransferValidations = Arc<Mutex<HashMap<MessageId, TransferValidationSender>>>;
type PendingQueryResponses = Arc<Mutex<HashMap<(SocketAddr, MessageId), QueryResponseSender>>>;

impl Session {
    /// Bootstrap to the network maintaining connections to several nodes.
    pub async fn bootstrap(&mut self) -> Result<(), Error> {
        trace!(
            "Trying to bootstrap to the network with public_key: {:?}",
            self.client_public_key()
        );

        let (
            endpoint,
            _incoming_connections,
            incoming_messages,
            mut disconnections,
            bootstrapped_peer,
        ) = self.qp2p.bootstrap().await?;

        self.endpoint = Some(endpoint.clone());
        let connected_elders = self.connected_elders.clone();
        let _ = tokio::spawn(async move {
            if let Some(disconnected_peer) = disconnections.next().await {
                let _ = connected_elders.lock().await.remove(&disconnected_peer);
            }
        });

        // Bootstrap and send a handshake request to
        self.send_get_section_query(Some(bootstrapped_peer)).await?;
        self.listen_to_incoming_messages(incoming_messages).await?;

        let mut we_have_keyset = false;

        // bootstrap is not complete until we have pk set...
        while !we_have_keyset {
            use tokio::time::{sleep, Duration};
            sleep(Duration::from_millis(500)).await;
            we_have_keyset = self.section_key_set.lock().await.is_some();
        }

        // Let's now connect to all Elders
        self.connect_to_elders().await?;

        Ok(())
    }

    /// Send a `Message` to the network without awaiting for a response.
    pub async fn send_cmd(
        &self,
        msg: ProcessMsg,
    ) -> Result<(), Error> {
        let msg_id = msg.id();
        let endpoint = self.endpoint()?.clone();

        let elders: Vec<SocketAddr> = self.connected_elders.lock().await.keys().cloned().collect();

        let src_addr = endpoint.socket_addr();
        trace!(
            "Sending (from {}) command message {:?} w/ id: {:?}",
            src_addr,
            msg,
            msg_id
        );

        let msg = Message::Process(msg);
        let section_pk = session
            .section_key()
            .await?
            .bls()
            .ok_or(Error::NoBlsSectionKey)?;
        let dest_section_name = XorName::from(session.client_public_key());
        let msg_bytes = msg.serialize(dest_section_name, section_pk)?;

        // Send message to all Elders concurrently
        let mut tasks = Vec::default();

        // clone elders as we want to update them in this process
        for socket in elders {
            let msg_bytes_clone = msg_bytes.clone();
            let endpoint = endpoint.clone();
            let task_handle: JoinHandle<Result<(), Error>> = tokio::spawn(async move {
                trace!("About to send cmd message {:?} to {:?}", msg_id, &socket);
                endpoint.connect_to(&socket).await?;
                endpoint.send_message(msg_bytes_clone, &socket).await?;

                trace!("Sent cmd with MsgId {:?}to {:?}", msg_id, &socket);
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
        let pending_transfers = self.pending_transfers.clone();
        debug!("Pending transfers at this point: {:?}", pending_transfers);
        let mut listeners = pending_transfers.lock().await;
        let _ = listeners
            .remove(msg_id)
            .ok_or(Error::NoTransferValidationListener)?;
        Ok(())
    }

    /// Send a transfer validation message to all Elder without awaiting for a response.
    pub async fn send_transfer_validation(
        &self,
        msg: ProcessMsg,
        sender: Sender<Result<TransferValidated, Error>>,
    ) -> Result<(), Error> {
        info!(
            "Sending transfer validation command {:?} w/ id: {:?}",
            msg,
            msg.id()
        );
        let endpoint = self.endpoint()?.clone();
        let elders: Vec<SocketAddr> = self.connected_elders.lock().await.keys().cloned().collect();

        let pending_transfers = self.pending_transfers.clone();

        let section_pk = session
            .section_key()
            .await?
            .bls()
            .ok_or(Error::NoBlsSectionKey)?;
        let dest_section_name = XorName::from(session.client_public_key());
        let msg = Message::Process(msg);
        let msg_bytes = msg.serialize(dest_section_name, section_pk)?;

        let msg_id = msg.id();

        // block off the lock to avoid long await calls
        {
            let _ = pending_transfers.lock().await.insert(msg_id, sender);
        }

        // Send message to all Elders concurrently
        let mut tasks = Vec::default();
        for socket in elders.iter() {
            let msg_bytes_clone = msg_bytes.clone();
            let socket = *socket;

            let endpoint = endpoint.clone();

            let task_handle = tokio::spawn(async move {
                endpoint.connect_to(&socket).await?;
                trace!("Sending transfer validation to Elder {}", &socket);
                endpoint.send_message(msg_bytes_clone, &socket).await?;
                Ok::<_, Error>(())
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
    pub async fn send_query(&self, msg: &Message) -> Result<QueryResponse, Error> {
        let endpoint = self.endpoint()?.clone();
        let elders: Vec<SocketAddr> = self.connected_elders.lock().await.keys().cloned().collect();

        let pending_queries = self.pending_queries.clone();

        info!("sending query message {:?} w/ id: {:?}", msg, msg.id());

        let msg = Message::Process(msg);
        let section_pk = session
            .section_key()
            .await?
            .bls()
            .ok_or(Error::NoBlsSectionKey)?;
        let dest_section_name = XorName::from(session.client_public_key());

        let msg_bytes = msg.serialize(dest_section_name, section_pk)?;

        // We send the same message to all Elders concurrently,
        // and we try to find a majority on the responses
        let mut tasks = Vec::default();

        for socket in elders.clone() {
            // Create a new stream here to not have to worry about filtering replies
            let msg_id = msg.id();
            let msg = msg.clone();
            let msg_bytes_clone = msg_bytes.clone();
            let pending_queries = pending_queries.clone();
            let endpoint = endpoint.clone();
            endpoint.connect_to(&socket).await?;

            let task_handle = tokio::spawn(async move {
                // Retry queries that failed for connection issues
                let mut done_trying = false;
                let mut result = Err(Error::ElderQuery);
                let mut attempts: usize = 1;

                while !done_trying {
                    let msg_bytes_clone = msg_bytes_clone.clone();

                    let (sender, mut receiver) = channel::<Result<QueryResponse, Error>>(7);
                    let _ = pending_queries
                        .lock()
                        .await
                        .insert((socket, msg_id), sender);

                    // TODO: we need to remove the msg_id from
                    // pending_queries upon any failure below
                    match endpoint.send_message(msg_bytes_clone, &socket).await {
                        Ok(()) => {
                            trace!(
                                "Message {:?} sent to {}. Waiting for response...",
                                msg.clone(),
                                &socket
                            );

                            if let Some(res) = receiver.recv().await {
                                return Ok(res?);
                            } else {
                                error!("Error from query response, non received");
                                return Err(Error::QueryReceiverError);
                            }
                        }
                        Err(_error) => {
                            result = {
                                error!("Error sending query message");
                                // TODO: remove it from the pending_query_responses then
                                Err(Error::SendingQuery)
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

        let threshold: usize = self.supermajority().await;

        trace!("Vote threshold is: {:?}", threshold);
        let connected_elders_count = self.connected_elders_count().await;
        if self.connected_elders_count().await < threshold {
            return Err(Error::InsufficientElderConnections(connected_elders_count));
        }

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
                        let mut key = [0; 32];
                        let mut hasher = Sha3::v256();
                        hasher.update(&serialize(&response)?);
                        hasher.finalize(&mut key);

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
                winner = select_best_of_the_rest_response(
                    winner,
                    threshold,
                    &vote_map,
                    received_errors,
                    &mut has_elected_a_response,
                );
            }
        }

        debug!(
            "Response obtained after querying {} nodes: {:?}",
            winner.1, winner.0
        );

        winner.0.ok_or(Error::NoResponse)
    }

    // Private helpers

    // Get section info. Optionally from one node (if we've just bootstrapped qp2p eg)
    // Otherwise we use all session nodes
    async fn send_get_section_query(&self, initial_peer: Option<SocketAddr>) -> Result<(), Error> {
        if self.is_connecting_to_new_elders {
            debug!("Already attempting elder connections, not sending section query until that is complete.");
            return Ok(());
        }
        let elders: Vec<SocketAddr> = self.all_known_elders.lock().await.keys().cloned().collect();

        // 1. We query the network for section info.
        trace!("Querying for section info from bootstrapped node...");

        // HACK: we don't know our section PK. We must supply a pk for now we do a random one...
        let random_section_pk = threshold_crypto::SecretKey::random().public_key();
        let dest_section_name = XorName::from(self.client_public_key());

        let msg = SectionInfoMsg::GetSectionQuery(self.client_public_key())
            .serialize(dest_section_name, random_section_pk)?;

        if let Some(bootstrapped_peer) = initial_peer {
            trace!("Bootstrapping with contact... {:?}", bootstrapped_peer);

            self.endpoint()?
                .send_message(msg, &bootstrapped_peer)
                .await?;
        } else {
            trace!("Bootstrapping with contacts... {:?}", elders);
            debug!(">>>>> connecting to session's elders");
            for socket in elders.clone() {
                let msg = msg.clone();
                let endpoint = self.endpoint.clone().ok_or(Error::NotBootstrapped)?;
                endpoint.connect_to(&socket).await?;
                endpoint.send_message(msg, &socket).await?
            }
        }

        Ok(())
    }

    fn disconnect_from_peers(&self, peers: Vec<SocketAddr>) -> Result<(), Error> {
        for elder in peers {
            self.endpoint()?.disconnect_from(&elder)?;
        }
        Ok(())
    }

    // Connect to a set of Elders nodes which will be
    // the receipients of our messages on the network.
    async fn connect_to_elders(&mut self) -> Result<(), Error> {
        self.is_connecting_to_new_elders = true;
        // Connect to all Elders concurrently
        // We spawn a task per each node to connect to
        let mut tasks = Vec::default();
        let supermajority = self.supermajority().await;

        if self.known_elders_count().await == 0 {
            warn!("Not attempted to connect, insufficient elders yet known");
            // this is not necessarily an error in case we didnt get elder info back yet
        }

        let endpoint = self.endpoint()?;
        let msg = self.bootstrap_cmd().await?;

        let peers;
        {
            peers = self.all_known_elders.lock().await.clone();
        }

        let peers_len = peers.len();

        debug!(
            "Sending bootstrap cmd from {} to {} peers.., supermajority would be {:?} nodes",
            endpoint.socket_addr(),
            peers_len,
            supermajority
        );

        for (peer_addr, name) in peers {
            let endpoint = endpoint.clone();
            let msg = msg.clone();
            let task_handle = tokio::spawn(async move {
                let mut result = Err(Error::ElderConnection);
                let mut connected = false;
                let mut attempts: usize = 0;
                while !connected && attempts <= NUMBER_OF_RETRIES {
                    attempts += 1;
                    endpoint.connect_to(&peer_addr).await?;
                    endpoint.send_message(msg.clone(), &peer_addr).await?;
                    connected = true;

                    debug!(
                        "Elder conn attempt #{} @ {} is connected? : {:?}",
                        attempts, peer_addr, connected
                    );

                    result = Ok((peer_addr, name))
                }

                result
            });
            tasks.push(task_handle);
        }

        // TODO: Do we need a timeout here to check sufficient time has passed + or sufficient connections?
        let mut has_attempted_all_connections = false;
        let mut todo = tasks;
        let mut new_elders = BTreeMap::new();

        while !has_attempted_all_connections {
            if todo.is_empty() {
                warn!("No more elder connections to try");
                break;
            }

            let (res, _idx, remaining_futures) = select_all(todo.into_iter()).await;
            if remaining_futures.is_empty() {
                has_attempted_all_connections = true;
            }

            todo = remaining_futures;

            if let Ok(elder_result) = res {
                let res = elder_result.map_err(|err| {
                    // elder connection retires already occur above
                    warn!("Failed to connect to Elder @ : {}", err);
                });

                if let Ok((name, socket)) = res {
                    info!("Connected to elder: {:?}", socket);
                    let _ = new_elders.insert(name, socket);
                }
            }

            if new_elders.len() >= peers_len {
                has_attempted_all_connections = true;
            }

            if new_elders.len() < peers_len {
                warn!("Connected to only {:?} new_elders.", new_elders.len());
            }

            if new_elders.len() < supermajority && has_attempted_all_connections {
                debug!("Attempted all connections and failed...");
                return Err(Error::InsufficientElderConnections(new_elders.len()));
            }
        }

        trace!("Connected to {} Elders.", new_elders.len());
        {
            let mut session_elders = self.connected_elders.lock().await;
            *session_elders = new_elders;
        }

        self.is_connecting_to_new_elders = false;

        Ok(())
    }

    /// Handle received network info messages
    async fn handle_sectioninfo_msg(
        &mut self,
        msg: SectionInfoMsg,
        src: SocketAddr,
    ) -> Result<(), Error> {
        trace!("Handling network info message {:?}", msg);

        match &msg {
            SectionInfoMsg::GetSectionResponse(GetSectionResponse::Success(info)) => {
                debug!("GetSectionResponse::Success!");
                self.update_session_info(info).await
            }
            SectionInfoMsg::RegisterEndUserError(error)
            | SectionInfoMsg::GetSectionResponse(GetSectionResponse::SectionInfoUpdate(error)) => {
                warn!("Message was interrupted due to {:?}. This will most likely need to be sent again.", error);

                if let SectionInfoError::InvalidBootstrap(_) = error {
                    debug!("Attempting to connect to elders again");
                    self.connect_to_elders().await?;
                }

                if let SectionInfoError::TargetSectionInfoOutdated(info) = error {
                    trace!("Updated network info: ({:?})", info);
                    self.update_session_info(info).await?;
                }
                Ok(())
            }
            SectionInfoMsg::GetSectionResponse(GetSectionResponse::Redirect(elders)) => {
                trace!("GetSectionResponse::Redirect, trying with provided elders");
                {
                    let mut session_elders = self.elders.lock().await;
                    *session_elders = elders.iter().copied().collect();
                }
                // Disconnect from peer that sent us the redirect, connect to the new elders provided and
                // request the section info again.
                self.disconnect_from_peers(vec![src])?;
                self.connect_to_elders().await?;
                self.send_get_section_query(None).await?;

                Ok(())
            }
            SectionInfoMsg::SectionInfoUpdate(update) => {
                let correlation_id = update.correlation_id;
                error!("MessageId {:?} was interrupted due to infrastructure updates. This will most likely need to be sent again. Update was : {:?}", correlation_id, update);
                if let SectionInfoError::TargetSectionInfoOutdated(info) = update.clone().error {
                    trace!("Updated network info: ({:?})", info);
                    self.update_session_info(&info).await?;
                }
                Ok(())
            }
            SectionInfoMsg::RegisterEndUserCmd { .. } | SectionInfoMsg::GetSectionQuery(_) => {
                Err(Error::UnexpectedMessageOnJoin(format!(
                    "bootstrapping failed since an invalid response ({:?}) was received",
                    msg
                )))
            }
        }
    }

    /// Apply updated info to a network session, and trigger connections
    async fn update_session_info(&mut self, info: &SectionInfo) -> Result<(), Error> {
        let original_known_elders;

        {
            original_known_elders = self.all_known_elders.lock().await.clone();
        }

        // Change this once sn_messaging is updated
        let received_elders = info
            .elders
            .iter()
            .map(|(name, addr)| (*addr, *name))
            .collect::<BTreeMap<_, _>>();

        // Obtain the addresses of the Elders
        trace!(
            "Updating session info! Received elders: ({:?})",
            received_elders
        );

        {
            // Update session key set
            let mut keyset = self.section_key_set.lock().await;
            if *keyset == Some(info.pk_set.clone()) {
                trace!("We have already received this info.");
                return Ok(());
            }
            *keyset = Some(info.pk_set.clone());
        }

        {
            // update section prefix
            let mut prefix = self.section_prefix.lock().await;
            *prefix = Some(info.prefix);
        }

        {
            // Update session elders
            let mut session_elders = self.all_known_elders.lock().await;
            *session_elders = received_elders.clone();
        }

        if original_known_elders != received_elders {
            debug!("Connecting to new elders");
            let new_elder_addresses = received_elders.keys().collect::<BTreeSet<_>>();
            let old_elders = original_known_elders
                .iter()
                .filter_map(|(peer_addr, _)| {
                    if !new_elder_addresses.contains(peer_addr) {
                        Some(*peer_addr)
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>();
            self.disconnect_from_peers(old_elders)?;
            self.connect_to_elders().await
        } else {
            Ok(())
        }
    }

    /// Handle messages intended for client consumption (re: queries + commands)
    async fn handle_client_msg(&self, msg: ProcessMsg, src: SocketAddr) {
        let notifier = self.notifier.clone();
        match msg.clone() {
            ProcessMsg::QueryResponse {
                response,
                correlation_id,
                ..
            } => {
                trace!("Query response in: {:?}", response);

                if let Some(sender) = self
                    .pending_queries
                    .lock()
                    .await
                    .remove(&(src, correlation_id))
                {
                    trace!("Sender channel found for query response");
                    let _ = sender.send(Ok(response)).await;
                } else {
                    warn!(
                        "No matching pending query found for elder {:?}  and message {:?}",
                        src, correlation_id
                    );
                }
            }
            ProcessMsg::Event {
                event,
                correlation_id,
                ..
            } => {
                if let Event::TransferValidated { event, .. } = event {
                    if let Some(sender) =
                        self.pending_transfers.lock().await.get_mut(&correlation_id)
                    {
                        info!("Accumulating SignatureShare");
                        let _ = sender.send(Ok(event)).await;
                    } else {
                        warn!("No matching transfer validation event listener found for elder {:?} and message {:?}", src, correlation_id);
                        warn!("It may be that this transfer is complete and the listener cleaned up already.");
                        trace!("Event received was {:?}", event);
                    }
                }
            }
            ProcessMsg::CmdError {
                error,
                correlation_id,
                ..
            } => {
                if let Some(sender) = self.pending_transfers.lock().await.get_mut(&correlation_id) {
                    debug!("Cmd Error was received, sending on channel to caller");
                    let _ = sender.send(Err(Error::from(error.clone()))).await;
                } else {
                    warn!("No sender subscribing and listening for errors relating to message {:?}. Error returned is: {:?}", correlation_id, error)
                }

                let _ = notifier.send(Error::from(error));
            }
            msg => {
                warn!("another message type received {:?}", msg);
            }
        };
    }
}

/// Choose the best response when no single responses passes the threshold
fn select_best_of_the_rest_response(
    current_winner: (Option<QueryResponse>, usize),
    threshold: usize,
    vote_map: &VoteMap,
    received_errors: usize,
    has_elected_a_response: &mut bool,
) -> (Option<QueryResponse>, usize) {
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
                    if let Some(QueryResponse::GetHistory(Ok(popular_history))) =
                        &most_popular_response.0
                    {
                        if history.len() > popular_history.len() {
                            trace!("GetHistory response received in Simulated Payouts... choosing longest history. {:?}", history);
                            most_popular_response = (Some(message.clone()), *votes)
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

    most_popular_response
}

#[derive(Clone)]
pub struct Session {
    pub qp2p: QuicP2p,
    pub notifier: UnboundedSender<Error>,
    pub pending_queries: PendingQueryResponses,
    pub pending_transfers: PendingTransferValidations,
    pub endpoint: Option<Endpoint>,
    /// elders we've managed to connect to
    pub connected_elders: Arc<Mutex<BTreeMap<SocketAddr, XorName>>>,
    /// all elders we know about from SectionInfo messages
    pub all_known_elders: Arc<Mutex<BTreeMap<SocketAddr, XorName>>>,
    pub section_key_set: Arc<Mutex<Option<PublicKeySet>>>,
    pub section_prefix: Arc<Mutex<Option<Prefix>>>,
    pub signer: Signer,
    pub is_connecting_to_new_elders: bool,
}

impl Session {
    pub fn new(
        qp2p_config: QuicP2pConfig,
        signer: Signer,
        notifier: UnboundedSender<Error>,
    ) -> Result<Self, Error> {
        debug!("QP2p config: {:?}", qp2p_config);

        let qp2p = qp2p::QuicP2p::with_config(Some(qp2p_config), Default::default(), false)?;
        Ok(Session {
            qp2p,
            notifier,
            pending_queries: Arc::new(Mutex::new(HashMap::default())),
            pending_transfers: Arc::new(Mutex::new(HashMap::default())),
            endpoint: None,
            section_key_set: Arc::new(Mutex::new(None)),
            connected_elders: Arc::new(Mutex::new(Default::default())),
            all_known_elders: Arc::new(Mutex::new(Default::default())),
            section_prefix: Arc::new(Mutex::new(None)),
            signer,
            is_connecting_to_new_elders: false,
        })
    }

    /// get the supermajority count based on number of known elders
    pub async fn supermajority(&self) -> usize {
        1 + self.known_elders_count().await * 2 / 3
    }

    pub async fn get_elder_names(&self) -> BTreeSet<XorName> {
        let elders = self.connected_elders.lock().await;
        elders.values().cloned().collect()
    }

    /// Get the elders count of our connected section
    pub async fn connected_elders_count(&self) -> usize {
        self.connected_elders.lock().await.len()
    }

    /// Get the elders count of our section elders as provided by SectionInfo
    pub async fn known_elders_count(&self) -> usize {
        self.all_known_elders.lock().await.len()
    }

    pub fn client_public_key(&self) -> PublicKey {
        self.signer.public_key()
    }

    /// Get section's prefix
    pub async fn section_prefix(&self) -> Option<Prefix> {
        self.section_prefix.lock().await.clone()
    }

    pub fn endpoint(&self) -> Result<&Endpoint, Error> {
        match self.endpoint.borrow() {
            Some(endpoint) => Ok(endpoint),
            None => {
                trace!("self.endpoint.borrow() was None");
                Err(Error::NotBootstrapped)
            }
        }
    }

    pub async fn section_key(&self) -> Result<PublicKey, Error> {
        let keys = self.section_key_set.lock().await.clone();

        match keys.borrow() {
            Some(section_key_set) => Ok(PublicKey::Bls(section_key_set.public_key())),
            None => {
                trace!("self.section_key_set.borrow() was None");
                Err(Error::NotBootstrapped)
            }
        }
    }

    pub async fn bootstrap_cmd(&self) -> Result<bytes::Bytes, Error> {
        let socketaddr_sig = self
            .signer
            .sign(&serialize(&self.endpoint()?.socket_addr())?)
            .await?;

        // TODO: Do we actually know our seciton PK here?

        // Hack: This is jsut a random bls pk, we dont know our section as yet, but right now
        // a target pk is needed on all msgs
        let random_section_pk = threshold_crypto::SecretKey::random().public_key();
        let dest_section_name = XorName::from(self.client_public_key());
        SectionInfoMsg::RegisterEndUserCmd {
            end_user: self.client_public_key(),
            socketaddr_sig,
        }
        .serialize(dest_section_name, random_section_pk)
        .map_err(Error::MessagingProtocol)
    }

    /// Listen for incoming messages on a connection
    pub async fn listen_to_incoming_messages(
        &self,
        mut incoming_messages: IncomingMessages,
    ) -> Result<(), Error> {
        debug!("Adding IncomingMessages listener");

        let mut session = self.clone();
        // Spawn a thread
        let _ = tokio::spawn(async move {
            while let Some((src, message)) = incoming_messages.next().await {
                let message_type = WireMsg::deserialize(message)?;
                warn!("Message received at listener from {:?}", &src);
                match message_type {
                    MessageType::SectionInfo(msg) => {
                        match session.handle_sectioninfo_msg(msg, src).await {
                            Ok(()) => (),
                            Err(error) => {
                                error!("Error handling network info message: {:?}", error);
                                // that's enough
                                // go back to using a clone of session before the error
                            }
                        }
                    }
                    MessageType::ClientMessage { msg, .. } => {
                        match msg {
                            Message::Process(msg) => {
                                session.handle_client_msg(msg, src).await
                            }
                            Message::ProcessingError(error) => {
                                warn!("Processing error received. {:?}", error);
                                // TODO: Handle lazy message errors

                                session
                            }
                        }
                    }
                    msg_type => {
                        warn!("Unexpected message type received: {:?}", msg_type);
                    }
                }
            }
            info!("IncomingMessages listener is closing now");
            Ok::<(), Error>(())
        });

        // Some or None, not super important if this existed before...
        Ok(())
    }
}

#[derive(Clone)]
pub struct Signer {
    keypair: Arc<Mutex<Keypair>>,
    public_key: PublicKey,
}

impl Signer {
    pub fn new(keypair: Keypair) -> Self {
        let public_key = keypair.public_key();
        Self {
            keypair: Arc::new(Mutex::new(keypair)),
            public_key,
        }
    }

    pub fn public_key(&self) -> PublicKey {
        self.public_key
    }

    pub async fn sign(&self, data: &[u8]) -> Result<Signature, Error> {
        Ok(self.keypair.lock().await.sign(data))
    }
}
