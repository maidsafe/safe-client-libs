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

// safe-transfers wrapper
pub use self::map_info::MapInfo;
pub use self::transfer_actor::{ClientTransferValidator, SafeTransferActor};

use crate::config_handler::Config;
use crate::connection_manager::ConnectionManager;
use crate::errors::CoreError;

use crdts::Dot;
use futures::lock::Mutex;
use log::trace;
use lru::LruCache;
use quic_p2p::Config as QuicP2pConfig;
use safe_nd::{
    Blob, BlobAddress, ClientFullId, Cmd, Message, MessageId, Money, PublicId, PublicKey, Query,
    QueryResponse, Sequence, SequenceAddress,
};

use std::sync::Arc;

use xor_name::XorName;

use rand::thread_rng;
use std::{collections::HashSet, net::SocketAddr};
use threshold_crypto::{PublicKeySet, SecretKey};
use xor_name::XorName;

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

/// Trait providing an interface for self-authentication client implementations, so they can
/// interface all requests from high-level APIs to the actual routing layer and manage all
/// interactions with it. Clients are non-blocking, with an asynchronous API using the futures
/// abstraction from the futures-rs crate.
impl Client {
    /// This will create a basic Client object which is sufficient only for testing purposes.
    pub async fn new(sk: Option<SecretKey>) -> Result<Self, CoreError> {
        crate::utils::init_log();
        let full_id = match sk {
            Some(sk) => ClientFullId::from(sk),
            None => {
                let mut rng = thread_rng();

                //TODO: Q: should we even have different types of client full id?
                ClientFullId::new_bls(&mut rng)
            }
        };

        // Create the connection manager
        let mut connection_manager =
            attempt_bootstrap(&Config::new().quic_p2p, full_id.clone()).await?;

        let simulated_farming_payout_dot =
            Dot::new(PublicKey::from(SecretKey::random().public_key()), 0);

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

        full_client.get_history().await?;

        Ok(full_client)
    }

    #[cfg(feature = "simulated-payouts")]
    pub async fn new_no_initial_balance(sk: Option<SecretKey>) -> Result<Self, CoreError> {
        let full_id = match sk {
            Some(sk) => ClientFullId::from(sk),
            None => {
                let mut rng = thread_rng();

                //TODO: Q: should we even have different types of client full id?
                ClientFullId::new_bls(&mut rng)
            }
        };

        // Create the connection manager
        let mut connection_manager =
            attempt_bootstrap(&Config::new().quic_p2p, full_id.clone()).await?;

        // let mut the_actor = TransferActor::new(full_id.clone(), connection_manager).await?;
        // let transfer_actor = the_self.clone();

        // TODO: Do we need this again?
        // connection_manager
        // .bootstrap(maid_keys.client_safe_key())
        // .await?;

        let simulated_farming_payout_dot =
            Dot::new(PublicKey::from(SecretKey::random().public_key()), 0);

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

        full_client.get_history();

        Ok(full_client)
    }

    async fn full_id(&self) -> ClientFullId {
        self.full_id.clone()
    }

    /// Return the client's public ID.
    pub async fn public_id(&self) -> PublicId {
        let id = self.full_id().await;
        let pub_id = PublicId::Client(id.public_id().clone());

        pub_id
    }

    /// Returns the client's public key.
    pub async fn public_key(&self) -> PublicKey {
        let id = self.full_id().await;

        *id.public_key()
    }

    async fn send_query(&mut self, query: Query) -> Result<QueryResponse, CoreError> {
        // `sign` should be false for GETs on published data, true otherwise.

        println!("-->>Request going out: {:?}", query);

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

    /// Set the coin balance to a specific value for testing
    #[cfg(any(test, feature = "simulated-payouts"))]
    async fn test_simulate_farming_payout_client(&mut self, amount: Money) -> Result<(), CoreError>
    where
        Self: Sized,
    {
        use log::debug;
        debug!(
            "Set the coin balance of {:?} to {:?}",
            self.public_key().await,
            amount,
        );

        self.trigger_simulated_farming_payout(amount).await
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
#[cfg(any(test, feature = "simulated-payouts", feature = "testing"))]
pub mod exported_tests {
    use super::*;
    use crate::utils::{generate_random_vector, test_utils::calculate_new_balance};
    use safe_nd::{Error as SndError, Money, PublicBlob};
    use std::str::FromStr;
    use unwrap::unwrap;

    // 1. Create a client A with a wallet and allocate some test safecoin to it.
    // 2. Get the balance and verify it.
    // 3. Create another client B with a wallet holding some safecoin.
    // 4. Transfer some money from client B to client A and verify the new balance.
    // 5. Fetch the transfer using the transfer ID and verify the amount.
    // 6. Try to do a coin transfer without enough funds, it should return `InsufficientBalance`
    // 7. Try to do a coin transfer with the amount set to 0, it should return `InvalidOperation`
    // 8. Set the client's balance to zero and try to put data. It should fail.
    #[cfg(feature = "simulated-payouts")]
    pub async fn money_balance_transfer() -> Result<(), CoreError> {
        let mut client = Client::new(None).await?;

        // let wallet1: XorName =
        // TODO: fix this test and use another client w/ key
        let _owner_key = client.public_key().await;
        let wallet1 = client.public_key().await;

        client
            .test_simulate_farming_payout_client(unwrap!(Money::from_str("100.0")))
            .await
            .unwrap();
        let balance = client.get_balance(None).await.unwrap();
        assert_eq!(balance, unwrap!(Money::from_str("109.999999999"))); // 10 coins added automatically w/ farming sim on account creation. 1 nano paid.

        let mut client = Client::new(None).await?;
        let init_bal = unwrap!(Money::from_str("10"));
        let orig_balance = client.get_balance(None).await.unwrap();
        let _ = client
            .send_money(wallet1, unwrap!(Money::from_str("5.0")))
            .await
            .unwrap();
        let new_balance = client.get_balance(None).await.unwrap();
        assert_eq!(
            new_balance,
            unwrap!(orig_balance.checked_sub(unwrap!(Money::from_str("5.0")))),
        );

        let res = client
            .send_money(wallet1, unwrap!(Money::from_str("5000")))
            .await;
        match res {
            Err(CoreError::DataError(SndError::InsufficientBalance)) => (),
            res => panic!("Unexpected result: {:?}", res),
        };
        // Check if money is refunded
        let balance = client.get_balance(None).await.unwrap();
        let expected =
            calculate_new_balance(init_bal, Some(1), Some(unwrap!(Money::from_str("5"))));
        assert_eq!(balance, expected);

        let client_to_get_all_money = Client::new(None).await?;
        // send all our money elsewhere to make sure we fail the next put
        let _ = client
            .send_money(
                client_to_get_all_money.public_key().await,
                unwrap!(Money::from_str("4.999999999")),
            )
            .await
            .unwrap();
        let data = Blob::Public(PublicBlob::new(generate_random_vector::<u8>(10)));
        let res = client.store_blob(data).await;
        match res {
            Err(CoreError::DataError(SndError::InsufficientBalance)) => (),
            res => panic!(
                "Unexpected result in money transfer test, putting without balance: {:?}",
                res
            ),
        };

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::exported_tests;
    use super::*;

    #[tokio::test]
    #[cfg(feature = "simulated-payouts")]
    pub async fn money_balance_transfer() -> Result<(), CoreError> {
        exported_tests::money_balance_transfer().await
    }
}
