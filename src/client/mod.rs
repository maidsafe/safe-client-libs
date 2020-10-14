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

/// Blob storage for self encryption.
pub mod blob_storage;

// sn_transfers wrapper
pub use self::map_info::MapInfo;
pub use self::transfer_actor::{ClientTransferValidator, SafeTransferActor};

pub use blob_storage::{BlobStorage, BlobStorageDryRun};

use crate::config_handler::Config;
use crate::connection_manager::ConnectionManager;
use crate::errors::ClientError;

use crdts::Dot;
use futures::lock::Mutex;
#[cfg(feature = "simulated-payouts")]
use log::warn;
use log::{debug, info, trace};
use lru::LruCache;
use qp2p::Config as QuicP2pConfig;
use rand::rngs::OsRng;

use sn_data_types::{
    Blob, BlobAddress, ClientFullId, Cmd, Message, MessageId, Money, PublicId, PublicKey, Query,
    QueryResponse, Sequence, SequenceAddress,
};

#[cfg(feature = "simulated-payouts")]
use std::str::FromStr;

use std::{collections::HashSet, net::SocketAddr, sync::Arc};
use threshold_crypto::PublicKeySet;
use xor_name::XorName;

/// Capacity of the immutable data cache.
pub const IMMUT_DATA_CACHE_SIZE: usize = 300;

/// Capacity of the Sequence CRDT local replica size.
pub const SEQUENCE_CRDT_REPLICA_SIZE: usize = 300;

/// Expected cost of mutation operations.
pub const COST_OF_PUT: Money = Money::from_nano(1);

/// Return the `crust::Config` associated with the `crust::Service` (if any).
pub fn bootstrap_config() -> Result<HashSet<SocketAddr>, ClientError> {
    Ok(Config::new().qp2p.hard_coded_contacts)
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
    connection_manager: Arc<Mutex<ConnectionManager>>,
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
    /// # extern crate tokio; use sn_client::ClientError;
    /// use sn_client::Client;
    ///
    /// # #[tokio::main] async fn main() { let _: Result<(), ClientError> = futures::executor::block_on( async {
    ///
    /// let mut client = Client::new(None).await?;
    /// // Now for example you can perform read operations:
    /// let _some_balance = client.get_balance().await?;
    /// # Ok(()) } ); }
    /// ```
    pub async fn new(optional_id: Option<ClientFullId>) -> Result<Self, ClientError> {
        crate::utils::init_log();

        #[cfg(feature = "simulated-payouts")]
        let mut is_random_client = true;
        let mut rng = OsRng;

        let full_id = match optional_id {
            Some(id) => {
                #[cfg(feature = "simulated-payouts")]
                {
                    is_random_client = false;
                }

                id
            }
            None => ClientFullId::new_ed25519(&mut rng),
        };

        info!("Cliented started for pk: {:?}", full_id.public_key());

        // Create the connection manager
        let mut connection_manager =
            attempt_bootstrap(&Config::new().qp2p, full_id.clone()).await?;

        // random PK used for from payment
        let random_payment_id = ClientFullId::new_bls(&mut rng);
        let random_payment_pk = random_payment_id.public_key();

        let simulated_farming_payout_dot = Dot::new(*random_payment_pk, 0);

        let replicas_pk_set =
            Self::get_replica_keys(full_id.clone(), &mut connection_manager).await?;

        let validator = ClientTransferValidator {};

        let transfer_actor = Arc::new(Mutex::new(SafeTransferActor::new(
            full_id.keypair().clone(),
            replicas_pk_set.clone(),
            validator,
        )));

        let mut full_client = Self {
            connection_manager: Arc::new(Mutex::new(connection_manager)),
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
                debug!("Attempting to trigger simulated payout");
                // we're testing, and currently a lot of tests expect 10 money to start
                let _ = full_client
                    .trigger_simulated_farming_payout(Money::from_str("10")?)
                    .await?;
            } else {
                warn!("No automatic simulated payout occurs for clients created for pre-existing SecretKeys")
            }
        }

        let _ = full_client.get_history().await?;

        Ok(full_client)
    }

    /// Return the client's FullId.
    ///
    /// Useful for retrieving the PublicKey or KeyPair in the event you need to _sign_ something
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # extern crate tokio; use sn_client::ClientError;
    /// use sn_client::Client;
    /// # #[tokio::main] async fn main() { let _: Result<(), ClientError> = futures::executor::block_on( async {
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
    /// # extern crate tokio; use sn_client::ClientError;
    /// use sn_client::Client;
    /// # #[tokio::main] async fn main() { let _: Result<(), ClientError> = futures::executor::block_on( async {
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
    /// # extern crate tokio; use sn_client::ClientError;
    /// use sn_client::Client;
    /// # #[tokio::main] async fn main() { let _: Result<(), ClientError> = futures::executor::block_on( async {
    /// let client = Client::new(None).await?;
    /// let _pk = client.public_key().await;
    /// # Ok(()) } ); }
    /// ```
    pub async fn public_key(&self) -> PublicKey {
        let id = self.full_id().await;

        *id.public_key()
    }

    /// Send a Query to the network and await a response
    async fn send_query(&mut self, query: Query) -> Result<QueryResponse, ClientError> {
        // `sign` should be false for GETs on published data, true otherwise.

        debug!("Sending QueryRequest: {:?}", query);

        let message = Self::create_query_message(query);
        self.connection_manager
            .lock()
            .await
            .send_query(&message)
            .await
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
        trace!("Creating query message with id : {:?}", id);

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
) -> Result<ConnectionManager, ClientError> {
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
#[cfg(feature = "simulated-payouts")]
pub mod exported_tests {
    use super::*;
    use crate::crypto::shared_box;

    pub async fn client_creation() -> Result<(), ClientError> {
        let _transfer_actor = Client::new(None).await?;

        Ok(())
    }

    pub async fn client_creation_for_existing_sk() -> Result<(), ClientError> {
        let mut rng = OsRng;
        let fulld_id = ClientFullId::new_ed25519(&mut rng);
        let _transfer_actor = Client::new(Some(fulld_id)).await?;

        Ok(())
    }
}

#[cfg(all(test, feature = "simulated-payouts"))]
mod tests {
    use super::exported_tests;
    use crate::ClientError;

    #[tokio::test]
    #[cfg(feature = "simulated-payouts")]
    pub async fn client_creation() -> Result<(), ClientError> {
        exported_tests::client_creation().await
    }

    #[tokio::test]
    #[cfg(feature = "simulated-payouts")]
    pub async fn client_creation_for_existing_sk() -> Result<(), ClientError> {
        exported_tests::client_creation_for_existing_sk().await
    }
}
