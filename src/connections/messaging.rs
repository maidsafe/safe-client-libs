// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{QueryResult, Session};
use crate::Error;
use bincode::serialize;
use futures::future::{join_all, select_all};
use itertools::Itertools;
use log::{debug, error, info, trace, warn};
use sn_data_types::{Blob, PrivateBlob, PublicBlob, TransferValidated};
use sn_messaging::{
    client::{BlobRead, ClientMsg, DataQuery, ProcessMsg, Query, QueryResponse},
    section_info::Message as SectionInfoMsg,
    MessageId,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::SocketAddr,
    time::Duration,
};
use tokio::{
    sync::mpsc::{channel, Sender},
    task::JoinHandle,
    time::timeout,
};
use xor_name::XorName;

// Number of attemps when retrying to send a message to a node
const NUMBER_OF_RETRIES: usize = 3;
// Number of Elders subset to send queries to
const NUM_OF_ELDERS_SUBSET_FOR_QUERIES: usize = 3;

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
            mut incoming_messages,
            mut disconnections,
            mut bootstrapped_peer,
        ) = self.qp2p.bootstrap().await?;

        self.endpoint = Some(endpoint.clone());
        let mut bootstrap_nodes = endpoint
            .bootstrap_nodes()
            .to_vec()
            .into_iter()
            .collect::<BTreeSet<_>>();
        let connected_elders = self.connected_elders.clone();
        let _ = tokio::spawn(async move {
            while let Some(disconnected_peer) = disconnections.next().await {
                let _ = connected_elders.lock().await.remove(&disconnected_peer);
            }
        });
        self.send_get_section_query(&bootstrapped_peer).await?;

        // Bootstrap and send a handshake request to the bootstrapped peer
        let mut we_have_keyset = false;
        while !we_have_keyset {
            // This means that the peer we bootstrapped to has responded with a SectionInfo Message
            if let Ok(Ok(true)) = timeout(
                Duration::from_secs(30),
                self.process_incoming_message(&mut incoming_messages),
            )
            .await
            {
                we_have_keyset = self.section_key_set.lock().await.is_some();
            } else {
                // Remove the unresponsive peer we boostrapped to and bootstrap again
                let _ = bootstrap_nodes.remove(&bootstrapped_peer);
                bootstrapped_peer = self
                    .qp2p
                    .rebootstrap(
                        &endpoint,
                        &bootstrap_nodes.iter().cloned().collect::<Vec<_>>(),
                    )
                    .await?;
            }
        }

        self.spawn_message_listener_thread(incoming_messages).await;

        Ok(())
    }

    /// Send a `ClientMsg` to the network without awaiting for a response.
    pub async fn send_cmd(&self, msg: ProcessMsg) -> Result<(), Error> {
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

        let msg = ClientMsg::Process(msg);

        let section_pk = self
            .section_key()
            .await?
            .bls()
            .ok_or(Error::NoBlsSectionKey)?;
        let dest_section_name = XorName::from(self.client_public_key());
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

        let section_pk = self
            .section_key()
            .await?
            .bls()
            .ok_or(Error::NoBlsSectionKey)?;
        let dest_section_name = XorName::from(self.client_public_key());
        let msg = ClientMsg::Process(msg);
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

    /// Send a Query `ClientMsg` to the network awaiting for the response.
    pub(crate) async fn send_query(&self, query: Query) -> Result<QueryResult, Error> {
        let data_name = query.dst_address();
        let endpoint = self.endpoint()?.clone();
        let pending_queries = self.pending_queries.clone();

        let chunk_addr = if let Query::Data(DataQuery::Blob(BlobRead::Get(address))) = query {
            Some(address)
        } else {
            None
        };

        let msg_id = MessageId::new();
        let msg = ClientMsg::Process(ProcessMsg::Query { query, id: msg_id });

        let section_pk = self
            .section_key()
            .await?
            .bls()
            .ok_or(Error::NoBlsSectionKey)?;
        let dest_section_name = XorName::from(self.client_public_key());

        let msg_bytes = msg.serialize(dest_section_name, section_pk)?;

        // We select the NUM_OF_ELDERS_SUBSET_FOR_QUERIES closest
        // connected Elders to the data we are querying
        let elders: Vec<SocketAddr> = self
            .connected_elders
            .lock()
            .await
            .clone()
            .into_iter()
            .sorted_by(|(_, lhs_name), (_, rhs_name)| data_name.cmp_distance(&lhs_name, &rhs_name))
            .take(NUM_OF_ELDERS_SUBSET_FOR_QUERIES)
            .map(|(addr, _)| addr)
            .collect();

        let elders_len = elders.len();
        if elders_len < NUM_OF_ELDERS_SUBSET_FOR_QUERIES {
            error!(
                "Not enough Elder connections: {}, minimum required: {}",
                elders_len, NUM_OF_ELDERS_SUBSET_FOR_QUERIES
            );
            return Err(Error::InsufficientElderConnections(elders_len));
        }

        info!(
            "Sending query message {:?}, to the {} Elders closest to data name: {:?}",
            msg, elders_len, elders
        );

        // We send the same message to all Elders concurrently
        let mut tasks = Vec::new();
        let (sender, mut receiver) = channel::<Result<QueryResponse, Error>>(7);
        let _ = pending_queries.lock().await.insert(msg_id, sender);

        // Set up response listeners
        for socket in elders {
            let endpoint = endpoint.clone();
            let msg_bytes = msg_bytes.clone();
            let task_handle = tokio::spawn(async move {
                endpoint.connect_to(&socket).await?;

                // Retry queries that failed due to connection issues only
                let mut result = Err(Error::ElderQuery);
                for attempt in 0..NUMBER_OF_RETRIES + 1 {
                    let msg_bytes_clone = msg_bytes.clone();

                    if let Err(err) = endpoint.send_message(msg_bytes_clone, &socket).await {
                        error!(
                            "Try #{:?} @ {:?}, failed sending query message: {:?}",
                            attempt + 1,
                            socket,
                            err
                        );
                        result = Err(Error::SendingQuery);
                    } else {
                        trace!("ClientMsg with {:?} sent to {}", &msg_id, &socket);
                        result = Ok(());
                        break;
                    }
                }
                result
            });

            tasks.push(task_handle);
        }

        // TODO:
        // We are now simply accepting the very first valid response we receive,
        // but we may want to revisit this to compare multiple responses and validate them,
        // similar to what we used to do up to the following commit:
        // https://github.com/maidsafe/sn_client/blob/9091a4f1f20565f25d3a8b00571cc80751918928/src/connection_manager.rs#L328
        //
        // For Chunk responses we already validate its hash matches the xorname requested from,
        // so we don't need more than one valid response to prevent from accepting invaid responses
        // from byzantine nodes, however for mutable data (non-Chunk esponses) we will
        // have to review the approach.
        let mut todo = tasks;
        let mut responses_discarded: usize = 0;

        // Send all queries first
        loop {
            let (task_result, _, remaining_futures) = select_all(todo.into_iter()).await;
            todo = remaining_futures;
            if let Err(error) = task_result {
                error!("Error spawning task to send query: {:?} ", error);
                responses_discarded += 1;
            }
            if todo.is_empty() {
                break;
            }
        }

        let response = loop {
            match (receiver.recv().await, chunk_addr) {
                (Some(Ok(QueryResponse::GetBlob(Ok(blob)))), Some(chunk_addr)) => {
                    // We are dealing with Chunk query responses, thus we validate its hash
                    // matches its xorname, if so, we don't need to await for more responses
                    debug!("Chunk QueryResponse received is: {:#?}", blob);

                    let xorname = match &blob {
                        Blob::Private(priv_chunk) => {
                            *PrivateBlob::new(priv_chunk.value().clone(), *priv_chunk.owner())
                                .name()
                        }
                        Blob::Public(pub_chunk) => {
                            *PublicBlob::new(pub_chunk.value().clone()).name()
                        }
                    };

                    if *chunk_addr.name() == xorname {
                        trace!("Valid Chunk received for {}", msg_id);
                        break Some(QueryResponse::GetBlob(Ok(blob)));
                    } else {
                        // the Chunk content doesn't match its Xorname,
                        // this is suspicious and it could be a byzantine node
                        warn!("We received an invalid Chunk response from one of the nodes");
                        responses_discarded += 1;
                    }
                }
                (Some(Ok(response)), _) => {
                    debug!("QueryResponse received is: {:#?}", response);
                    break Some(response);
                }
                (Some(other), _) => {
                    warn!(
                        "Unexpected message in reply to query (retrying): {:?}",
                        other
                    );
                    responses_discarded += 1;
                }
                (None, _) => {
                    debug!("QueryResponse channel closed.");
                    break None;
                }
            }
            if responses_discarded == elders_len {
                break None;
            }
        };

        debug!(
            "Response obtained for query w/id {:?}: {:?}",
            &msg_id, &response
        );

        // Remove the response sender
        let _ = pending_queries.lock().await.remove(&msg_id);

        response
            .map(|response| QueryResult { response, msg_id })
            .ok_or(Error::NoResponse)
    }

    // Get section info from the peer we have bootstrapped with.
    pub(crate) async fn send_get_section_query(
        &self,
        bootstrapped_peer: &SocketAddr,
    ) -> Result<(), Error> {
        if self.is_connecting_to_new_elders {
            // This should ideally be unreachable code. Leaving it while this is a WIP
            error!("Already attempting elder connections, not sending section query until that is complete.");
            return Ok(());
        }

        // 1. We query the network for section info.
        trace!("Querying for section info from bootstrapped node...");

        // FIXME: we don't know our section PK. We must supply a pk for now we do a random one...
        let random_section_pk = threshold_crypto::SecretKey::random().public_key();
        let dest_section_name = XorName::from(self.client_public_key());

        let msg = SectionInfoMsg::GetSectionQuery(self.client_public_key())
            .serialize(dest_section_name, random_section_pk)?;

        self.endpoint()?
            .send_message(msg, bootstrapped_peer)
            .await?;

        Ok(())
    }

    pub(crate) fn disconnect_from_peers(&self, peers: Vec<SocketAddr>) -> Result<(), Error> {
        for elder in peers {
            self.endpoint()?.disconnect_from(&elder)?;
        }

        Ok(())
    }

    // Connect to a set of Elders nodes which will be
    // the receipients of our messages on the network.
    pub(crate) async fn connect_to_elders(&mut self) -> Result<(), Error> {
        self.is_connecting_to_new_elders = true;
        // Connect to all Elders concurrently
        // We spawn a task per each node to connect to
        let mut tasks = Vec::default();
        let supermajority = self.super_majority().await;

        if self.known_elders_count().await == 0 {
            // this is not necessarily an error in case we didn't get elder info back yet
            warn!("Not attempted to connect, insufficient elders yet known");
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

        debug!(
            "Peers ({}) to be used for bootstrapping: {:?}",
            peers_len, peers
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
                    if let Ok(Ok(())) =
                        timeout(Duration::from_secs(30), endpoint.connect_to(&peer_addr)).await
                    {
                        endpoint.send_message(msg.clone(), &peer_addr).await?;
                        connected = true;

                        debug!("Elder conn attempt #{} @ {} SUCCESS", attempts, peer_addr);

                        result = Ok((peer_addr, name))
                    } else {
                        debug!("Elder conn attempt #{} @ {} FAILED", attempts, peer_addr);
                    }
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
                    warn!("Failed to connect to Elder @ : {:?}", err);
                });

                if let Ok((socket, name)) = res {
                    info!("Connected to elder: {:?}", socket);
                    let _ = new_elders.insert(socket, name);
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

    // Private helpers

    async fn bootstrap_cmd(&self) -> Result<bytes::Bytes, Error> {
        let socketaddr_sig = self
            .signer
            .sign(&serialize(&self.endpoint()?.socket_addr())?)
            .await?;

        // FIXME: Do we actually know our seciton PK here?

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
}
