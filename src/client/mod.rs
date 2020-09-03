// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

/// `MapInfo` utilities.
pub mod map_info;

/// Map APIs
pub mod map_apis;

/// Blob APIs
pub mod blob_apis;

/// Safe Transfers wrapper, with Money APIs
pub mod transfer_actor;

/// Sequence APIs
pub mod sequence_apis;

mod blob_storage;

// sn_transfers wrapper
pub use self::map_info::MapInfo;
pub use self::transfer_actor::{ClientTransferValidator, SafeTransferActor};

use crate::config_handler::Config;
use crate::connection_manager::ConnectionManager;
use crate::errors::CoreError;

use crdts::Dot;
use futures::lock::Mutex;
use log::{debug, error, info, trace, warn};
use lru::LruCache;
use quic_p2p::Config as QuicP2pConfig;
use rand::thread_rng;
use safe_nd::{
    Blob, BlobAddress, ClientFullId, Cmd, Message, MessageId, Money, PublicId, PublicKey, Query,
    QueryResponse, Sequence, SequenceAddress,
};

#[cfg(feature = "simulated-payouts")]
use std::str::FromStr;

use std::sync::Arc;

use xor_name::XorName;

use std::{collections::HashSet, net::SocketAddr};
use threshold_crypto::{PublicKeySet, SecretKey};

/// Capacity of the immutable data cache.
pub const IMMUT_DATA_CACHE_SIZE: usize = 300;

/// Capacity of the Sequence CRDT local replica size.
pub const SEQUENCE_CRDT_REPLICA_SIZE: usize = 300;

/// Expected cost of mutation operations.
pub const COST_OF_PUT: Money = Money::from_nano(1);

/// Return the `crust::Config` associated with the `crust::Service` (if any).
pub fn bootstrap_config() -> Result<HashSet<SocketAddr>, CoreError> {
    Ok(Config::new().quic_p2p.hard_coded_contacts)
}

/// Client object
#[derive(Clone)]
pub struct Client {
    full_id: ClientFullId,
    blob_cache: Arc<Mutex<LruCache<BlobAddress, Blob>>>,
    /// Sequence CRDT replica
    sequence_cache: Arc<Mutex<LruCache<SequenceAddress, Sequence>>>,
    transfer_actor: Arc<Mutex<SafeTransferActor<ClientTransferValidator>>>,
    replicas_pk_set: PublicKeySet,
    simulated_farming_payout_dot: Dot<PublicKey>,
    connection_manager: ConnectionManager,
}

/// Easily manage connections to/from The Safe Network with the client and its APIs.
/// Use a random client for read-only or one-time operations.
/// Supply an existing, SecretKey which holds a SafeCoin balance to be able to perform
/// write operations.
impl Client {
    /// Create a Safe Network client instance. Either for an existing SecretKey (in which case) the client will attempt
    /// to retrieve the history of the key's balance in order to be ready for any Money operations. Or if no SecreteKey
    /// is passed, a random keypair will be used, which provides a client that can only perform Read operations (at
    /// least until the client's SecretKey receives some Money).
    ///
    /// # Examples
    ///
    /// Create a random client
    /// ```no_run
    /// # extern crate tokio; use safe_core::CoreError;
    /// use safe_core::Client;
    ///
    /// # #[tokio::main] async fn main() { let _: Result<(), CoreError> = futures::executor::block_on( async {
    ///
    /// let mut client = Client::new(None).await?;
    /// // Now for example you can perform read operations:
    /// let _some_balance = client.get_balance().await?;
    /// # Ok(()) } ); }
    /// ```
    pub async fn new(sk: Option<SecretKey>) -> Result<Self, CoreError> {
        crate::utils::init_log();

        #[cfg(feature = "simulated-payouts")]
        let mut is_random_client = true;

        let full_id = match sk {
            Some(sk) => {
                #[cfg(feature = "simulated-payouts")]
                {
                    is_random_client = false;
                }

                ClientFullId::from(sk)
            }
            None => {
                let mut rng = thread_rng();
                ClientFullId::new_bls(&mut rng)
            }
        };

        // Create the connection manager
        let mut connection_manager =
            attempt_bootstrap(&Config::new().quic_p2p, full_id.clone()).await?;

        let simulated_farming_payout_dot = Dot::new(*full_id.public_key(), 0);

        let replicas_pk_set =
            Self::get_replica_keys(full_id.clone(), &mut connection_manager).await?;

        let validator = ClientTransferValidator {};

        let transfer_actor = Arc::new(Mutex::new(SafeTransferActor::new(
            full_id.keypair().clone(),
            replicas_pk_set.clone(),
            validator,
        )));

        let mut full_client = Self {
            connection_manager,
            full_id,
            transfer_actor,
            replicas_pk_set,
            simulated_farming_payout_dot,
            blob_cache: Arc::new(Mutex::new(LruCache::new(IMMUT_DATA_CACHE_SIZE))),
            sequence_cache: Arc::new(Mutex::new(LruCache::new(SEQUENCE_CRDT_REPLICA_SIZE))),
        };

        #[cfg(feature = "simulated-payouts")]
        {
            // only trigger simulated payouts on new _random_ clients
            if is_random_client {
                // we're testing, and currently a lot of tests expect 10 money to start
                let _ = full_client
                    .trigger_simulated_farming_payout(Money::from_str("10")?)
                    .await?;
            }
        }

        let _ = full_client.get_history().await;

        //Start listening for Events
        full_client.listen_on_network().await;

        Ok(full_client)
    }

    /// Listen to network events.
    ///
    /// This can be useful to check for CmdErrors related to write operations, or to handle incoming TransferValidation events.
    ///
    async fn listen_on_network(&mut self) {
        let (tx, rx) = std::sync::mpsc::channel();
        loop {
            self.connection_manager.listen(tx.clone()).await;
            match rx.recv() {
                Ok(envelope) => {
                    let message = envelope.message;
                    match message {
                        Message::Event {
                            event,
                            // correlation_id: _,
                            ..
                        } => {
                            match self.handle_validation_event(event).await {
                                Ok(proof) => {
                                    match proof {
                                        Some(_debit) => {
                                            // TODO: store response against correlation ID,
                                            // use this id for retrieval in write apis.
                                            info!("DO SOMETHING WITH PROOF");
                                            // let _ = self.debit_cache.insert(debit.id(), debit);
                                        }
                                        None => warn!("Handled a validation Event"),
                                    }
                                }
                                Err(e) => {
                                    error!("Unexpected error while handling validation: {:?}", e)
                                }
                            }
                        }
                        m => error!("Unexpected message found while listening: {:?}", m),
                    }
                }
                Err(e) => error!("Error listening to Events from Quic-p2p: {:?}", e),
            }
        }
    }
    /*
        async fn check_debit_cache(&mut self, id: TransferId) -> DebitAgreementProof {
            loop {
                match self.debit_cache.get(&id) {
                    Some(proof) => return proof.clone(),
                    None => (),
                }
            }
        }
    */

    /// Return the client's FullId.
    ///
    /// Useful for retrieving the PublicKey or KeyPair in the event you need to _sign_ something
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # extern crate tokio; use safe_core::CoreError;
    /// use safe_core::Client;
    /// # #[tokio::main] async fn main() { let _: Result<(), CoreError> = futures::executor::block_on( async {
    /// let client = Client::new(None).await?;
    /// let _full_id = client.full_id().await;
    ///
    /// # Ok(()) } ); }
    /// ```
    pub async fn full_id(&self) -> ClientFullId {
        self.full_id.clone()
    }

    /// Return the client's PublicId.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # extern crate tokio; use safe_core::CoreError;
    /// use safe_core::Client;
    /// # #[tokio::main] async fn main() { let _: Result<(), CoreError> = futures::executor::block_on( async {
    /// let client = Client::new(None).await?;
    /// let _public_id = client.public_id().await;
    /// # Ok(()) } ); }
    /// ```
    pub async fn public_id(&self) -> PublicId {
        let id = self.full_id().await;
        PublicId::Client(id.public_id().clone())
    }

    /// Return the client's PublicKey.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # extern crate tokio; use safe_core::CoreError;
    /// use safe_core::Client;
    /// # #[tokio::main] async fn main() { let _: Result<(), CoreError> = futures::executor::block_on( async {
    /// let client = Client::new(None).await?;
    /// let _pk = client.public_key().await;
    /// # Ok(()) } ); }
    /// ```
    pub async fn public_key(&self) -> PublicKey {
        let id = self.full_id().await;

        *id.public_key()
    }

    /// Send a Query to the network and await a response
    async fn send_query(&mut self, query: Query) -> Result<QueryResponse, CoreError> {
        // `sign` should be false for GETs on published data, true otherwise.

        debug!("Sending QueryRequest: {:?}", query);

        let message = Self::create_query_message(query);
        self.connection_manager.send_query(&message).await
    }

    // Build and sign Cmd Message Envelope
    pub(crate) fn create_cmd_message(msg_contents: Cmd) -> Message {
        let random_xor = XorName::random();
        let id = MessageId(random_xor);
        trace!("Creating cmd message with id: {:?}", id);
        println!("cmd msg id: {:?}", id);

        Message::Cmd {
            cmd: msg_contents,
            id,
        }
    }

    // Build and sign Query Message Envelope
    pub(crate) fn create_query_message(msg_contents: Query) -> Message {
        let random_xor = XorName::random();
        let id = MessageId(random_xor);
        trace!("Creating query message qith id : {:?}", id);

        Message::Query {
            query: msg_contents,
            id,
        }
    }
}

/// Utility function that bootstraps a client to the network. If there is a failure then it retries.
/// After a maximum of three attempts if the boostrap process still fails, then an error is returned.
pub async fn attempt_bootstrap(
    qp2p_config: &QuicP2pConfig,
    full_id: ClientFullId,
) -> Result<ConnectionManager, CoreError> {
    let mut attempts: u32 = 0;

    loop {
        let mut connection_manager = ConnectionManager::new(qp2p_config.clone(), full_id.clone())?;
        let res = connection_manager.bootstrap().await;
        match res {
            Ok(()) => return Ok(connection_manager),
            Err(err) => {
                attempts += 1;
                if attempts < 3 {
                    trace!("Error connecting to network! Retrying... ({})", attempts);
                } else {
                    return Err(err);
                }
            }
        }
    }
}

#[allow(missing_docs)]
#[cfg(all(test, feature = "simulated-payouts"))]
pub mod exported_tests {
    use super::*;
    use crate::crypto::shared_box;

    pub async fn client_creation() -> Result<(), CoreError> {
        let _transfer_actor = Client::new(None).await?;

        Ok(())
    }

    pub async fn client_creation_for_existing_sk() -> Result<(), CoreError> {
        let (sk, _pk) = shared_box::gen_bls_keypair();
        let _transfer_actor = Client::new(Some(sk)).await?;

        Ok(())
    }
}

#[cfg(all(test, feature = "simulated-payouts"))]
mod tests {
    use super::exported_tests;
    use crate::CoreError;

    #[tokio::test]
    #[cfg(feature = "simulated-payouts")]
    pub async fn client_creation() -> Result<(), CoreError> {
        exported_tests::client_creation().await
    }

    #[tokio::test]
    #[cfg(feature = "simulated-payouts")]
    pub async fn client_creation_for_existing_sk() -> Result<(), CoreError> {
        exported_tests::client_creation_for_existing_sk().await
    }
}
