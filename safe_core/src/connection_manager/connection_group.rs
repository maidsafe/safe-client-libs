// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{client::SafeKey, CoreError};
use bincode::{deserialize, serialize};
use bytes::Bytes;
use log::{error, info, trace};
use quic_p2p::{self, Config as QuicP2pConfig, Connection, QuicP2pAsync};
use safe_nd::{HandshakeRequest, HandshakeResponse, Message, PublicId, Response};
use std::net::SocketAddr;

/// Encapsulates multiple QUIC connections with a group of nodes. Accumulates responses.
pub(super) struct ConnectionGroup {
    full_id: SafeKey,
    quic_p2p: QuicP2pAsync,
    elders: Vec<Connection>,
}

impl ConnectionGroup {
    pub fn new(config: QuicP2pConfig, full_id: SafeKey) -> Result<Self, CoreError> {
        let quic_p2p = QuicP2pAsync::with_config(Some(config), Default::default(), false)?;

        Ok(Self {
            full_id,
            quic_p2p,
            elders: Vec::default(),
        })
    }

    // Bootstrap to the network
    pub async fn bootstrap(&mut self) -> Result<(), CoreError> {
        trace!("Boostrapping...");

        // Bootstrap and send a handshake request to receive
        // the list of Elders we can then connect to
        let elders_addrs = self.bootstrap_and_handshake().await?;

        // Let's now connect to all Elders
        self.connect_to_elders(elders_addrs).await
    }

    async fn bootstrap_and_handshake(&mut self) -> Result<Vec<SocketAddr>, CoreError> {
        trace!("Bootstrapping with contacts...");
        let mut node_connection = self.quic_p2p.bootstrap().await?;

        trace!("Sending handshake request to bootstrapped node...");
        let public_id = self.full_id.public_id();
        let handshake = HandshakeRequest::Bootstrap(public_id);
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

    async fn connect_to_elders(&mut self, elders_addrs: Vec<SocketAddr>) -> Result<(), CoreError> {
        // TODO: connect to all Elders in parallel
        let peer_addr = elders_addrs[0];

        let mut conn = self.quic_p2p.connect_to(peer_addr).await?;

        let handshake = HandshakeRequest::Join(self.full_id.public_id());
        let msg = Bytes::from(serialize(&handshake)?);
        let join_response = conn.send(msg).await?;
        match deserialize(&join_response) {
            Ok(HandshakeResponse::Challenge(PublicId::Node(node_public_id), challenge)) => {
                trace!(
                    "Got the challenge from {:?}, public id: {}",
                    peer_addr,
                    node_public_id
                );
                let response = HandshakeRequest::ChallengeResult(self.full_id.sign(&challenge));
                let msg = Bytes::from(serialize(&response)?);
                conn.send_only(msg).await?;
                self.elders = vec![conn];
                Ok(())
            }
            Ok(_) => Err(CoreError::from(format!(
                "Unexpected message type while expeccting challenge from Elder."
            ))),
            Err(e) => Err(CoreError::from(format!("Unexpected error {:?}", e))),
        }
    }

    pub async fn send(&mut self, msg: &Message) -> Result<Response, CoreError> {
        trace!("Sending message to Elders...");
        let msg_bytes = Bytes::from(serialize(&msg)?);

        // TODO: send to all elders in parallel and find majority on responses
        let response = self.elders[0].send(msg_bytes).await?;

        match deserialize(&response) {
            Ok(Message::Response {
                response,
                message_id,
            }) => {
                trace!(
                    "Response received: msg_id: {:?}, resp: {:?}",
                    message_id,
                    response
                );
                Ok(response)
            }
            Ok(Message::Notification { notification }) => {
                let err_msg = format!(
                    "Unexpectedly received a transaction notification: {:?}",
                    notification
                );
                trace!("{}", err_msg);
                Err(CoreError::Unexpected(err_msg))
            }
            Ok(_) => {
                let err_msg = "Unexpected message type when expecting a 'Response'.".to_string();
                error!("{}", err_msg);
                Err(CoreError::Unexpected(err_msg))
            }
            Err(e) => {
                let err_msg = format!("Unexpected error: {:?}", e);
                error!("{}", err_msg);
                Err(CoreError::Unexpected(err_msg))
            }
        }
    }
}
/*

struct Connected {
    elders: HashMap<SocketAddr, Elder>,
    response_manager: ResponseManager,
}

impl Connected {
    fn new(old_state: Joining) -> Self {
        // trigger the connection future
        let _ = old_state.connection_hook.send(Ok(()));

        let response_threshold: usize = old_state.connected_elders.len() / 2 + 1;

        Self {
            response_manager: ResponseManager::new(response_threshold),
            elders: old_state
                .connected_elders
                .into_iter()
                .map(|(k, v)| (k, v.elder))
                .collect(),
        }
    }

    fn terminate(self, quic_p2p: &mut QuicP2pAsync) {
        for peer in self.elders.values().map(Elder::peer) {
            //quic_p2p.disconnect_from(peer.peer_addr());
        }
    }

    async fn send(
        &mut self,
        quic_p2p: &mut QuicP2pAsync,
        msg_id: MessageId,
        msg: &Message,
    ) -> Result<oneshot::Receiver<Response>, CoreError> {
        trace!("Sending message {:?}", msg_id);

        let (sender_future, response_future) = oneshot::channel();
        let expected_responses = if is_get_request(&msg) {
            self.elders.len()
        } else {
            self.elders.len() / 2 + 1
        };

        let _ = self
            .response_manager
            .await_responses(msg_id, (sender_future, expected_responses));

        let bytes = Bytes::from(unwrap!(serialize(msg)));
        {
            for peer in self.elders.values().map(Elder::peer) {
                let token = rand::random();
                quic_p2p.send(peer, bytes.clone(), token).await;
            }
        }

        Ok(response_future)
    }

    fn handle_new_message(
        &mut self,
        _quic_p2p: &mut QuicP2pAsync,
        peer_addr: SocketAddr,
        msg: Bytes,
    ) -> Transition {
        trace!("{}: Message: {}.", peer_addr, utils::bin_data_format(&msg),);

        match deserialize(&msg) {
            Ok(Message::Response {
                response,
                message_id,
            }) => {
                trace!(
                    "Response from: {:?}, msg_id: {:?}, resp: {:?}",
                    peer_addr,
                    message_id,
                    response
                );
                let _ = self.response_manager.handle_response(message_id, response);
            }
            Ok(Message::Notification { notification }) => {
                trace!("Got transaction notification: {:?}", notification);
            }
            Ok(_msg) => error!("Unexpected message type, expected response."),
            Err(e) => {
                error!("Unexpected error: {:?}", e);
            }
        }

        Transition::None
    }
}

// Returns true when a message holds a GET request.
fn is_get_request(msg: &Message) -> bool {
    if let Message::Request { request, .. } = msg {
        match request.get_type() {
            RequestType::PublicGet | RequestType::PrivateGet => true,
            _ => false,
        }
    } else {
        false
    }
}
*/
