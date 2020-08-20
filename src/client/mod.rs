// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

/// `MapInfo` utilities.
pub mod map_info;

pub mod map_apis;

pub mod blob_apis;

/// Safe Transfers wrapper, with Money APIs
pub mod transfer_actor;

pub mod sequence_apis;

mod blob_storage;

// safe-transfers wrapper
pub use self::transfer_actor::{ClientTransferValidator, SafeTransferActor};

pub use self::map_info::MapInfo;

use crate::config_handler::Config;
use crate::connection_manager::ConnectionManager;

use crate::errors::CoreError;

use crdts::Dot;
use futures::lock::Mutex;
use log::trace;
use lru::LruCache;
use quic_p2p::Config as QuicP2pConfig;
use safe_nd::{
    AppPermissions, AuthQuery, Blob, BlobAddress, BlobRead, ClientFullId, Cmd, Data, DataQuery,
    Map, MapAddress, MapEntries, MapEntryActions, MapPermissionSet, MapRead, MapSeqEntries,
    MapSeqEntryActions, MapSeqValue, MapUnseqEntryActions, MapValue, MapValues, Message, MessageId,
    Money, PublicBlob, PublicId, PublicKey, Query, QueryResponse, SeqMap, Sequence, SequenceAction,
    SequenceAddress, SequenceEntries, SequenceEntry, SequenceIndex, SequenceOwner,
    SequencePrivUserPermissions, SequencePrivatePermissions, SequencePubUserPermissions,
    SequencePublicPermissions, SequenceRead, SequenceUser, SequenceUserPermissions, UnseqMap,
};

use std::sync::Arc;

use xor_name::XorName;

use rand::{thread_rng, Rng};
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

        // let cm = connection_manager.clone();
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

    // async fn public_encryption_key(&mut self) -> threshold_crypto::PublicKey {
    //     self.keys.enc_public_key
    // }

    // async fn secret_encryption_key(&mut self) -> shared_box::SecretKey {
    //     self.keys.enc_secret_key.clone()
    // }

    // async fn secret_symmetric_key(&mut self) -> shared_secretbox::Key {
    //     self.keys.enc_key.clone()
    // }

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

    // /// Return the public and secret encryption keys.
    // async fn encryption_keypair(&mut self) -> (threshold_crypto::PublicKey, shared_box::SecretKey) {
    //     let enc_key = self.public_encryption_key().await;
    //     let sec_key = self.secret_encryption_key().await;
    //     (enc_key, sec_key)
    // }

    async fn send_query(&mut self, query: Query) -> Result<QueryResponse, CoreError> {
        // `sign` should be false for GETs on published data, true otherwise.

        println!("-->>Request going out: {:?}", query);

        let message = Self::create_query_message(query);
        self.connection_manager.send_query(&message).await
    }

    // Build and sign Cmd Message Envelope
    pub(crate) fn create_cmd_message(msg_contents: Cmd) -> Message {
        trace!("Creating cmd message");
        let mut rng = thread_rng();
        let random_xor = rng.gen::<XorName>();
        let id = MessageId(random_xor);
        println!("cmd msg id: {:?}", id);

        Message::Cmd {
            cmd: msg_contents,
            id,
        }
    }

    // Build and sign Query Message Envelope
    pub(crate) fn create_query_message(msg_contents: Query) -> Message {
        trace!("Creating query message");

        let mut rng = thread_rng();
        let random_xor = rng.gen::<XorName>();
        let id = MessageId(random_xor);

        println!("query msg id: {:?}", id);
        Message::Query {
            query: msg_contents,
            id,
        }
    }

    /// Set the coin balance to a specific value for testing
    #[cfg(any(test, feature = "testing"))]
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

// /// Creates a throw-away client to execute requests sequentially.
// pub async fn temp_client<F, R>(full_id: &ClientFullId, mut func: F) -> Result<R, CoreError>
// where
//     F: FnMut(&mut ConnectionManager, &ClientFullId) -> Result<R, CoreError>,
// {
//     let (net_tx, _net_rx) = mpsc::unbounded();

//     let mut cm = attempt_bootstrap(&Config::new().quic_p2p, full_id.clone()).await?;

//     func(&mut cm, &full_id)
// }

/// Create a new mock balance at an arbitrary address.
// pub async fn test_create_balance(owner: &ClientFullId, amount: Money) -> Result<(), CoreError> {
//     trace!("Create test balance of {} for {:?}", amount, owner);

//     let full_id = owner.clone();

//     let (net_tx, _net_rx) = mpsc::unbounded();

//     let cm = attempt_bootstrap(&Config::new().quic_p2p, full_id.clone()).await?;

//     // actor starts with 10....
//     // let mut actor = SafeTransferActor::new(&full_id.clone(), cm).await?;

//     let public_id = full_id.public_id();

//     // TODO: Adjust this test... it's sending to itself?

//     // Create the balance for the client
//     let _new_balance_owner = public_id.public_key();

//     let public_key = *full_id.public_key();

//     actor
//         .trigger_simulated_farming_payout(public_key, amount)
//         .await?;

//     Ok(())
// }

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::{generate_random_vector, test_utils::calculate_new_balance};
    use safe_nd::{
        Error as SndError, MapAction, MapKind, Money, PrivateBlob, PublicBlob,
        SequencePrivUserPermissions,
    };
    use std::str::FromStr;
    use unwrap::unwrap;

    // TODO: Wallet only client doesn't currently exist.
    // 1. Create 2 accounts and create a wallet only for account A.
    // 2. Try to transfer money from A to inexistent wallet. This request should fail.
    // 3. Try to request balance of wallet B. This request should fail.
    // 4. Now create a wallet for account B and transfer some money to A. This should pass.
    // 5. Try to request transfer from wallet A using account B. This request should succeed
    // (because transfers are always open).
    // #[tokio::test]
    // #[ignore]
    // async fn money_permissions() {
    //     let mut client = Client::new(None).await?;
    //     let wallet_a_addr = client.public_key().await;
    //     let random_client_key = *ClientFullId::new_bls(&mut rand::thread_rng())
    //         .public_id()
    //         .public_key();
    //     let res = client
    //         .send_money(random_client_key, unwrap!(Money::from_str("5.0")))
    //         .await;
    //     match res {
    //         Err(CoreError::DataError(SndError::NoSuchBalance)) => (),
    //         res => panic!("Unexpected result: {:?}", res),
    //     }

    //     let mut client = Client::new(None).await?;
    //     let res = client.get_balance(None).await;
    //     // Subtract to cover the cost of inserting the login packet
    //     let expected_amt = unwrap!(Money::from_str("10")
    //         .ok()
    //         .and_then(|x| x.checked_sub(COST_OF_PUT)));
    //     match res {
    //         Ok(fetched_amt) => assert_eq!(expected_amt, fetched_amt),
    //         res => panic!("Unexpected result: {:?}", res),
    //     }
    //     client
    //         .test_simulate_farming_payout_client(unwrap!(Money::from_str("50.0")))
    //         .await
    //         .unwrap();
    //     let _ = client
    //         .send_money(wallet_a_addr, unwrap!(Money::from_str("10")))
    //         .await;

    //     let res = client.get_balance(None).await;
    //     let expected_amt = unwrap!(Money::from_str("40"));
    //     match res {
    //         Ok(fetched_amt) => assert_eq!(expected_amt, fetched_amt),
    //         res => panic!("Unexpected result: {:?}", res),
    //     }
    // }

    // TODO: Update when login packet is decided to sort out "anonymous" wallets (and eg key clients)
    // 1. Create a client with a wallet. Create an anonymous wallet preloading it from the client's wallet.
    // 2. Transfer some safecoin from the anonymous wallet to the client.
    // 3. Fetch the balances of both the wallets and verify them.
    // 5. Try to create a balance using an inexistent wallet. This should fail.

    // TODO: evaluate if test still valid
    // #[tokio::test]
    // async fn random_clients() -> Result<(),CoreError> {
    //     let mut client = Client::new(None).await?;
    //     // starter amount after creating login packet
    //     let wallet1 = client.public_key().await;
    //     let init_bal = unwrap!(Money::from_str("490.0")); // 500 in total

    //     let client2 = Client::new(None).await?;

    //     let bls_pk = client2.public_id().await.public_key();

    //     client
    //         .test_simulate_farming_payout_client(init_bal)
    //         .await
    //         .unwrap();
    //     assert_eq!(
    //         client.get_balance(None).await.unwrap(),
    //         unwrap!(Money::from_str("499.999999999"))
    //     ); // 500 - 1nano for encrypted-account-data

    //     let _ = client
    //         .create_balance(None, bls_pk, unwrap!(Money::from_str("100.0")))
    //         .await
    //         .unwrap();

    //     assert_eq!(
    //         client.get_balance(None).await.unwrap(),
    //         unwrap!(Money::from_str("399.999999999"))
    //     );
    //     assert_eq!(
    //         client2.get_balance(None).await.unwrap(),
    //         unwrap!(Money::from_str("109.999999999"))
    //     );

    //     let _ = client2
    //         .send_money(wallet1, unwrap!(Money::from_str("5.0")))
    //         .await
    //         .unwrap();

    //     let balance = client2.get_balance(None).await.unwrap();
    //     assert_eq!(balance, unwrap!(Money::from_str("104.999999999")));
    //     let balance = client.get_balance(None).await.unwrap();

    //     // we add ten when testing to created clients
    //     let initial_bal_with_default_ten = Money::from_str("500").unwrap();
    //     let expected = calculate_new_balance(
    //         initial_bal_with_default_ten,
    //         Some(1),
    //         Some(unwrap!(Money::from_str("95"))),
    //     );
    //     assert_eq!(balance, expected);
    //     let random_pk = gen_bls_keypair().public_key();

    //     let nonexistent_client = Client::new(None).await?;

    //     let res = nonexistent_client
    //         .create_balance(None, random_pk, unwrap!(Money::from_str("100.0")))
    //         .await;
    //     match res {
    //         Err(CoreError::DataError(e)) => {
    //             assert_eq!(e.to_string(), "Not enough money to complete this operation");
    //         }
    //         res => panic!("Unexpected result: {:?}", res),
    //     }

    //     Ok(())
    // }

    // 1. Create a client A with a wallet and allocate some test safecoin to it.
    // 2. Get the balance and verify it.
    // 3. Create another client B with a wallet holding some safecoin.
    // 4. Transfer some money from client B to client A and verify the new balance.
    // 5. Fetch the transfer using the transfer ID and verify the amount.
    // 6. Try to do a coin transfer without enough funds, it should return `InsufficientBalance`
    // 7. Try to do a coin transfer with the amount set to 0, it should return `InvalidOperation`
    // 8. Set the client's balance to zero and try to put data. It should fail.
    #[tokio::test]
    async fn money_balance_transfer() -> Result<(), CoreError> {
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

    // // 1. Create a random BLS key and create a wallet for it with some test safecoin.
    // // 2. Without a client object, try to get the balance, create new wallets and transfer safecoin.
    // #[tokio::test]
    // pub async fn wallet_transactions_without_client() -> Result<(), CoreError> {
    //     let client_id = gen_client_id();

    //     test_create_balance(&client_id, unwrap!(Coins::from_str("50"))).await?;

    //     let balance = wallet_get_balance(&client_id).await?;
    //     let ten_coins = unwrap!(Coins::from_str("10"));
    //     assert_eq!(balance, unwrap!(Coins::from_str("50")));

    //     let new_client_id = gen_client_id();
    //     let new_client_pk = new_client_id.public_id().public_key();
    //     let new_wallet: XorName = *new_client_id.public_id().name();
    //     let txn = wallet_create_balance(&client_id, *new_client_pk, ten_coins, None).await?;
    //     assert_eq!(txn.amount, ten_coins);
    //     let txn2 = wallet_transfer_coins(&client_id, new_wallet, ten_coins, None).await?;
    //     assert_eq!(txn2.amount, ten_coins);

    //     let client_balance = wallet_get_balance(&client_id).await?;
    //     let expected = unwrap!(Coins::from_str("30"));
    //     let expected = unwrap!(expected.checked_sub(COST_OF_PUT));
    //     assert_eq!(client_balance, expected);

    //     let new_client_balance = wallet_get_balance(&new_client_id).await?;
    //     assert_eq!(new_client_balance, unwrap!(Coins::from_str("20")));

    //     Ok(())
    // }
}
/*
fn wrap_blob_read(read: BlobRead) -> Query {
    Query::Data(DataQuery::Blob(read))
}

fn wrap_account_read(read: AccountRead) -> Query {
    Query::Data(DataQuery::Account(read))
}

fn wrap_client_auth_cmd(auth_cmd: AuthCmd) -> Cmd {
    Cmd::Auth(auth_cmd)
}
*/

// 1. Store different variants of unpublished data on the network.
// 2. Get the balance of the client.
// 3. Delete data from the network.
// 4. Verify that the balance has not changed since deletions are free.
// #[tokio::test]
// pub async fn deletions_should_be_free() -> Result<(), CoreError> {
//     let name = XorName(rand::random());
//     let tag = 10;
//     let mut client = Client::new(None).await?;

//     let blob = PrivateBlob::new(
//         unwrap!(generate_random_vector::<u8>(10)),
//         client.public_key().await,
//     );
//     let address = *blob.name();
//     client.store_blob(blob).await?;
//     let mut adata = PrivateSeqAppendOnlyData::new(name, tag);
//     let owner = ADataOwner {
//         public_key: client.public_key().await,
//         entries_index: 0,
//         permissions_index: 0,
//     };
//     unwrap!(adata.append_owner(owner, 0));
//     client.put_adata(adata.into()).await?;
//     let map = UnseqMap::new(name, tag, client.public_key().await);
//     client.put_unseq_mutable_data(map).await?;

// /// Insert a given login packet at the specified destination
// async fn insert_login_packet_for(
//     &mut self,
//     // client_id: Option<&ClientFullId>,
//     new_owner: PublicKey,
//     amount: Money,
//     new_login_packet: Account,
// ) -> Result<TransferRegistered, CoreError>
// where
//     Self: Sized,
// {
//     trace!(
//         "Insert a login packet for {:?} preloading the wallet with {} money.",
//         new_owner,
//         amount
//     );

//     let mut actor = self
//         .transfer_actor()
//         .await
//         .ok_or(CoreError::from("No TransferActor found for client."))?;

//     let response = actor
//         .create_login_for(new_owner, amount, new_login_packet)
//         .await;

//     match response {
//         Ok(res) => match res {
//             QueryResponse::TransferRegistration(result) => match result {
//                 Ok(transfer) => Ok(transfer),
//                 Err(error) => Err(CoreError::from(error)),
//             },
//             _ => Err(CoreError::ReceivedUnexpectedEvent),
//         },

//         Err(error) => Err(error),
//     }
// }
