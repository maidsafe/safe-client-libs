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
use crate::errors::Error;

use crdts::Dot;
use futures::lock::Mutex;
use log::{debug, info, trace, warn};
use qp2p::Config as QuicP2pConfig;
use rand::rngs::OsRng;
use std::str::FromStr;

use sn_data_types::{Keypair, Money, PublicKey};
use sn_messaging::{Cmd, DataCmd, Message, MessageId, Query, QueryResponse};

use std::{collections::HashSet, net::SocketAddr, sync::Arc};
use threshold_crypto::PublicKeySet;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use xor_name::XorName;

/// Elder size
pub const ELDER_SIZE: usize = 5;

/// Capacity of the immutable data cache.
pub const IMMUT_DATA_CACHE_SIZE: usize = 300;

/// Capacity of the Sequence CRDT local replica size.
pub const SEQUENCE_CRDT_REPLICA_SIZE: usize = 300;

/// Expected cost of mutation operations.
pub const COST_OF_PUT: Money = Money::from_nano(1);

/// Return the `crust::Config` associated with the `crust::Service` (if any).
pub fn bootstrap_config() -> Result<HashSet<SocketAddr>, Error> {
    Ok(Config::new().qp2p.hard_coded_contacts)
}

/// Client object
#[derive(Clone)]
pub struct Client {
    keypair: Arc<Keypair>,
    /// Sequence CRDT replica
    transfer_actor: Arc<Mutex<SafeTransferActor<ClientTransferValidator>>>,
    replicas_pk_set: PublicKeySet,
    simulated_farming_payout_dot: Dot<PublicKey>,
    connection_manager: Arc<Mutex<ConnectionManager>>,
    notification_receiver: Arc<Mutex<UnboundedReceiver<Error>>>,
}

impl Drop for Client {
    fn drop(&mut self) {
        
        futures::executor::block_on( async {
            debug!("££££££££££££££££££££££££££££££££££££££££££££££££££");
            debug!("££££££££££££££££££££££££££££££££££££££££££££££££££");
            debug!("££££££££££££££££££££££££££££££££££££££££££££££££££");
            debug!("££££££££££££££££££££££££££££££££££££££££££££££££££");
            debug!("££££££££££££££££££££££££££££££££££££££££££££££££££");
            debug!("dropping + closing conns");
            let res = self.connection_manager.lock().await.close_all_elder_connections().await;
            debug!("dropped + res {:?}", res);

        } );
    }
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
    /// # extern crate tokio; use sn_client::Error;
    /// use sn_client::Client;
    ///
    /// # #[tokio::main] async fn main() { let _: Result<(), Error> = futures::executor::block_on( async {
    ///
    /// let client = Client::new(None, None).await?;
    /// // Now for example you can perform read operations:
    /// let _some_balance = client.get_balance().await?;
    /// # Ok(()) } ); }
    /// ```
    pub async fn new(
        optional_keypair: Option<Arc<Keypair>>,
        bootstap_config: Option<HashSet<SocketAddr>>,
    ) -> Result<Self, Error> {
        crate::utils::init_log();
        let mut rng = OsRng;

        let (keypair, is_random_client) = match optional_keypair {
            Some(id) => {
                info!("Client started for specific pk: {:?}", id.public_key());
                (id, false)
            }
            None => {
                let keypair = Arc::new(Keypair::new_ed25519(&mut rng));
                info!(
                    "Client started for new randomly created pk: {:?}",
                    keypair.public_key()
                );
                (keypair, true)
            }
        };

        let (notification_sender, notification_receiver) = unbounded_channel::<Error>();
        // Create the connection manager
        let mut connection_manager = attempt_bootstrap(
            &Config::new().qp2p,
            keypair.clone(),
            notification_sender,
            bootstap_config,
        )
        .await?;

        // random PK used for from payment
        let random_payment_id = Keypair::new_bls(&mut rng);
        let random_payment_pk = random_payment_id.public_key();

        let simulated_farming_payout_dot = Dot::new(random_payment_pk, 0);

        let replicas_pk_set =
            Self::get_replica_keys(keypair.clone(), &mut connection_manager).await?;

        let validator = ClientTransferValidator {};

        let transfer_actor = Arc::new(Mutex::new(SafeTransferActor::new(
            keypair.clone(),
            replicas_pk_set.clone(),
            validator,
        )));

        let mut full_client = Self {
            connection_manager: Arc::new(Mutex::new(connection_manager)),
            keypair,
            transfer_actor,
            replicas_pk_set,
            simulated_farming_payout_dot,
            notification_receiver: Arc::new(Mutex::new(notification_receiver)),
        };

        if cfg!(feature = "simulated-payouts") {
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

        match full_client.get_history().await {
            Ok(_) => {}
            Err(error) => {
                let err = error.to_string();
                warn!("{:?}", &err);
            }
        };

        Ok(full_client)
    }

    /// Return the client's FullId.
    ///
    /// Useful for retrieving the PublicKey or KeyPair in the event you need to _sign_ something
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # extern crate tokio; use sn_client::Error;
    /// use sn_client::Client;
    /// # #[tokio::main] async fn main() { let _: Result<(), Error> = futures::executor::block_on( async {
    /// let client = Client::new(None, None).await?;
    /// let _keypair = client.keypair().await;
    ///
    /// # Ok(()) } ); }
    /// ```
    pub async fn keypair(&self) -> Arc<Keypair> {
        self.keypair.clone()
    }

    /// Return the client's PublicKey.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # extern crate tokio; use sn_client::Error;
    /// use sn_client::Client;
    /// # #[tokio::main] async fn main() { let _: Result<(), Error> = futures::executor::block_on( async {
    /// let client = Client::new(None, None).await?;
    /// let _pk = client.public_key().await;
    /// # Ok(()) } ); }
    /// ```
    pub async fn public_key(&self) -> PublicKey {
        let id = self.keypair().await;

        id.public_key()
    }

    /// Send a Query to the network and await a response
    async fn send_query(&self, query: Query) -> Result<QueryResponse, Error> {
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

    // Private helper to obtain payment proof for a data command, send it to the network,
    // and also apply the payment to local replica actor.
    async fn pay_and_send_data_command(&self, cmd: DataCmd) -> Result<(), Error> {
        // Payment for PUT
        let payment_proof = self.create_write_payment_proof(&cmd).await?;

        // The _actual_ message
        let msg_contents = Cmd::Data {
            cmd,
            payment: payment_proof.clone(),
        };
        let message = Self::create_cmd_message(msg_contents);
        let _ = self
            .connection_manager
            .lock()
            .await
            .send_cmd(&message)
            .await?;

        self.apply_write_payment_to_local_actor(payment_proof).await
    }
}

/// Utility function that bootstraps a client to the network. If there is a failure then it retries.
/// After a maximum of three attempts if the boostrap process still fails, then an error is returned.
pub async fn attempt_bootstrap(
    qp2p_config: &QuicP2pConfig,
    keypair: Arc<Keypair>,
    notification_sender: UnboundedSender<Error>,
    bootstrap_nodes: Option<HashSet<SocketAddr>>,
) -> Result<ConnectionManager, Error> {
    let mut attempts: u32 = 0;
    let mut qp2p_config = qp2p_config.clone();

    if let Some(contacts) = bootstrap_nodes {
        qp2p_config.hard_coded_contacts = contacts;
    }

    loop {
        let mut connection_manager = ConnectionManager::new(
            qp2p_config.clone(),
            keypair.clone(),
            notification_sender.clone(),
        )?;
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
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    pub async fn client_creation() -> Result<(), Error> {
        let _client = Client::new(None, None).await?;

        Ok(())
    }

    pub async fn client_nonsense_bootstrap_fails() -> Result<(), Error> {
        let mut nonsense_bootstrap = HashSet::new();
        let _ = nonsense_bootstrap.insert(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            3033,
        ));
        let setup = Client::new(None, Some(nonsense_bootstrap)).await;
        assert!(setup.is_err());
        Ok(())
    }

    pub async fn client_creation_with_existing_keypair() -> Result<(), Error> {
        let mut rng = OsRng;
        let full_id = Arc::new(Keypair::new_ed25519(&mut rng));
        let pk = full_id.public_key();

        let client = Client::new(Some(full_id), None).await?;
        assert_eq!(pk, client.public_key().await);

        Ok(())
    }

    pub async fn long_lived_connection_survives() -> Result<(), Error> {
        let client = Client::new(None, None).await?;
        tokio::time::delay_for(tokio::time::Duration::from_secs(40)).await;
        let balance = client.get_balance().await?;
        assert_ne!(balance, Money::from_nano(0));

        Ok(())
    }
}

#[cfg(all(test, feature = "simulated-payouts"))]
mod tests {
    use super::exported_tests;
    use crate::Error;

    #[tokio::test]
    #[cfg(feature = "simulated-payouts")]
    pub async fn client_creation() -> Result<(), Error> {
        exported_tests::client_creation().await
    }

    // #[tokio::test]
    // #[cfg(feature = "simulated-payouts")]
    // pub async fn client_nonsense_bootstrap_fails() -> Result<(), Error> {
    //     exported_tests::client_nonsense_bootstrap_fails().await
    // }

    #[tokio::test]
    #[cfg(feature = "simulated-payouts")]
    pub async fn client_creation_with_existing_keypair() -> Result<(), Error> {
        exported_tests::client_creation_with_existing_keypair().await
    }
    #[tokio::test]
    #[cfg(feature = "simulated-payouts")]
    pub async fn long_lived_connection_survives() -> Result<(), Error> {
        exported_tests::long_lived_connection_survives().await
    }
}
