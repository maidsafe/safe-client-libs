// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod listeners;
mod messaging;
mod signer;

pub use signer::Signer;

use crate::Error;
use futures::lock::Mutex;
use log::{debug, trace};
use qp2p::{Config as QuicP2pConfig, Endpoint, QuicP2p};
use sn_data_types::{PublicKey, TransferValidated};
use sn_messaging::client::CmdError;
use sn_messaging::{client::QueryResponse, MessageId};
use std::{
    borrow::Borrow,
    collections::{BTreeMap, BTreeSet, HashMap},
    net::SocketAddr,
    sync::Arc,
};
use threshold_crypto::PublicKeySet;
use tokio::sync::mpsc::Sender;
use xor_name::{Prefix, XorName};

// Channel for sending result of transfer validation
type TransferValidationSender = Sender<Result<TransferValidated, Error>>;
type QueryResponseSender = Sender<Result<QueryResponse, Error>>;

type PendingTransferValidations = Arc<Mutex<HashMap<MessageId, TransferValidationSender>>>;
type PendingQueryResponses = Arc<Mutex<HashMap<MessageId, QueryResponseSender>>>;

pub(crate) struct QueryResult {
    pub response: QueryResponse,
    pub msg_id: MessageId,
}

#[derive(Clone)]
pub struct Session {
    qp2p: QuicP2p,
    pending_queries: PendingQueryResponses,
    pending_transfers: PendingTransferValidations,
    incoming_err_sender: Sender<CmdError>,
    endpoint: Option<Endpoint>,
    /// elders we've managed to connect to
    connected_elders: Arc<Mutex<BTreeMap<SocketAddr, XorName>>>,
    /// all elders we know about from SectionInfo messages
    all_known_elders: Arc<Mutex<BTreeMap<SocketAddr, XorName>>>,
    pub section_key_set: Arc<Mutex<Option<PublicKeySet>>>,
    section_prefix: Arc<Mutex<Option<Prefix>>>,
    signer: Signer,
    is_connecting_to_new_elders: bool,
}

impl Session {
    pub fn new(
        qp2p_config: QuicP2pConfig,
        signer: Signer,
        err_sender: Sender<CmdError>,
    ) -> Result<Self, Error> {
        debug!("QP2p config: {:?}", qp2p_config);

        let qp2p = qp2p::QuicP2p::with_config(Some(qp2p_config), Default::default(), true)?;
        Ok(Self {
            qp2p,
            pending_queries: Arc::new(Mutex::new(HashMap::default())),
            pending_transfers: Arc::new(Mutex::new(HashMap::default())),
            incoming_err_sender: err_sender,
            endpoint: None,
            section_key_set: Arc::new(Mutex::new(None)),
            connected_elders: Arc::new(Mutex::new(Default::default())),
            all_known_elders: Arc::new(Mutex::new(Default::default())),
            section_prefix: Arc::new(Mutex::new(None)),
            signer,
            is_connecting_to_new_elders: false,
        })
    }

    /// Get the SuperMajority count based on number of known elders
    pub async fn super_majority(&self) -> usize {
        1 + self.known_elders_count().await * 2 / 3
    }

    pub async fn get_elder_names(&self) -> BTreeSet<XorName> {
        let elders = self.connected_elders.lock().await;
        elders.values().cloned().collect()
    }

    /// Get the elders count of our section elders as provided by SectionInfo
    pub async fn known_elders_count(&self) -> usize {
        self.all_known_elders.lock().await.len()
    }

    pub fn client_public_key(&self) -> PublicKey {
        self.signer.public_key()
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

    /// Get section's prefix
    pub async fn section_prefix(&self) -> Option<Prefix> {
        *self.section_prefix.lock().await
    }
}
