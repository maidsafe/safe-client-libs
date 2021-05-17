// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::Session;
use crate::Error;
use log::{debug, error, info, trace, warn};
use qp2p::IncomingMessages;
use sn_messaging::{
    client::{ClientMsg, Event, ProcessMsg},
    section_info::{
        Error as SectionInfoError, GetSectionResponse, Message as SectionInfoMsg, SectionInfo,
    },
    MessageId, MessageType, WireMsg,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::SocketAddr,
};

impl Session {
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

    // Listen for incoming messages on a connection
    pub(crate) async fn spawn_message_listener_thread(
        &self,
        mut incoming_messages: IncomingMessages,
    ) {
        debug!("Listening for incoming messages");
        let mut session = self.clone();
        let _ = tokio::spawn(async move {
            loop {
                match session
                    .process_incoming_message(&mut incoming_messages)
                    .await
                {
                    Ok(true) => (),
                    Ok(false) => {
                        info!("IncomingMessages listener has closed.");
                        break;
                    }
                    Err(err) => {
                        error!("Error while processing incoming message: {:?}. Listening for next message...", err);
                    }
                }
            }
        });
    }

    pub(crate) async fn process_incoming_message(
        &mut self,
        incoming_messages: &mut IncomingMessages,
    ) -> Result<bool, Error> {
        if let Some((src, message)) = incoming_messages.next().await {
            let message_type = WireMsg::deserialize(message)?;
            trace!("Incoming message from {:?}", &src);
            match message_type {
                MessageType::SectionInfo { msg, .. } => {
                    if let Err(error) = self.handle_section_info_msg(msg, src).await {
                        error!("Error handling network info message: {:?}", error);
                    }
                }
                MessageType::Client { msg, .. } => {
                    match msg {
                        ClientMsg::Process(msg) => self.handle_client_msg(msg, src).await,
                        ClientMsg::ProcessingError(error) => {
                            warn!("Processing error received. {:?}", error);
                            // TODO: Handle lazy message errors
                        }
                        msg => warn!("SupportingInfo received: {:?}", msg),
                    }
                }
                msg_type => {
                    warn!("Unexpected message type received: {:?}", msg_type);
                }
            }
            Ok(true)
        } else {
            Ok(false)
        }
    }

    // Private helpers

    // Handle received network info messages
    async fn handle_section_info_msg(
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
                trace!("GetSectionResponse::Redirect, reboostrapping with provided peers");
                // Disconnect from peer that sent us the redirect, connect to the new elders provided and
                // request the section info again.
                self.disconnect_from_peers(vec![src])?;
                let endpoint = self.endpoint()?.clone();
                let new_elders_addrs: Vec<SocketAddr> =
                    elders.iter().map(|(_, addr)| *addr).collect();
                self.qp2p
                    .update_bootstrap_contacts(new_elders_addrs.as_slice());
                let boostrapped_peer = self
                    .qp2p
                    .rebootstrap(&endpoint, new_elders_addrs.as_slice())
                    .await?;
                self.send_get_section_query(&boostrapped_peer).await?;

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

    // Apply updated info to a network session, and trigger connections
    async fn update_session_info(&mut self, info: &SectionInfo) -> Result<(), Error> {
        let original_known_elders = self.all_known_elders.lock().await.clone();

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
                trace!("We have previously received the key set already.");
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
            debug!("Connecting to new set of Elders: {:?}", received_elders);
            let new_elder_addresses = received_elders.keys().cloned().collect::<BTreeSet<_>>();
            let updated_contacts = new_elder_addresses.iter().cloned().collect::<Vec<_>>();
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
            self.qp2p.update_bootstrap_contacts(&updated_contacts);
            self.connect_to_elders().await
        } else {
            Ok(())
        }
    }

    // Handle messages intended for client consumption (re: queries + commands)
    async fn handle_client_msg(&self, msg: ProcessMsg, src: SocketAddr) {
        match msg {
            ProcessMsg::QueryResponse {
                response,
                correlation_id,
                ..
            } => {
                trace!(
                    "Query response (correlation id: {}): {:?}",
                    correlation_id,
                    response
                );

                // Note that this doesn't remove the sender from here since multiple
                // responses corresponding to the same message ID might arrive.
                // Once we are satisfied with the response this is channel is discarded in
                // ConnectionManager::send_query
                if let Some(sender) = self.pending_queries.lock().await.get(&correlation_id) {
                    trace!(
                        "Sending response for query w/{} via channel.",
                        correlation_id
                    );
                    let _ = sender.send(Ok(response)).await;
                } else {
                    trace!("No channel found for {:?}", correlation_id);
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
                        let _ = sender.send(Ok(event)).await;
                    } else {
                        warn!(
                            "No transfer validation listener found for elder {:?} and message {:?}",
                            src, correlation_id
                        );
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
                debug!(
                    "Cmd Error was received for Message w/ID: {:?}, sending on error channel",
                    correlation_id
                );
                let _ = self.incoming_err_sender.send(error).await;
            }
            msg => {
                warn!("Ignoring unexpected message type received: {:?}", msg);
            }
        };
    }
}
