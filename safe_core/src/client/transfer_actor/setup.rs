use safe_nd::{
    DebitAgreementProof, Message, MessageId, Money, PublicKey, ReplicaEvent, Request, Response,
    SignatureShare, SignedTransfer, Transfer, TransferPropagated, Transfers as MoneyRequest,
};
use safe_transfers::{ActorEvent, TransferActor as SafeTransferActor, TransfersSynched};

use std::str::FromStr;

use crate::client::ConnectionManager;
use crate::client::{Client, ClientTransferValidator, SafeKey, TransferActor};
use crate::errors::CoreError;
use crdts::Dot;

use futures::lock::Mutex;
use log::{info, trace};

use std::sync::Arc;
use threshold_crypto::{PublicKeySet, SecretKey};

// #[cfg(feature = "simulated-payouts")]
// #[cfg(feature = "simulated-payouts")]
// #[cfg(feature = "simulated-payouts")]

// pub mod write_apis;

/// Handle all Money transfers and Write API requests for a given ClientId.
impl TransferActor {
    /// Get our replica instance PK set
    pub async fn get_replica_keys(
        safe_key: SafeKey,
        mut cm: ConnectionManager,
    ) -> Result<PublicKeySet, CoreError> {
        trace!("Getting replica keys for {:?}", safe_key);

        let request = Self::wrap_money_request(MoneyRequest::GetReplicaKeys(safe_key.public_key()));

        let (message, message_id) =
            TransferActor::create_network_message(safe_key.clone(), request)?;

        let _bootstrapped = cm.bootstrap(safe_key.clone()).await;
        let res = cm.send(&safe_key.public_id(), &message).await?;

        let r = match res {
            Response::GetReplicaKeys(pk_set) => Ok(pk_set?),
            _ => Err(CoreError::from(format!(
                "Unexpected response when retrieving account replica keys for {:?}",
                safe_key.public_key()
            ))),
        };

        r
    }

    /// Create a new Transfer Actor for a previously unused public key
    pub async fn new(
        safe_key: SafeKey,
        connection_manager: ConnectionManager,
    ) -> Result<Self, CoreError> {
        info!(
            "Initiating Safe Transfer Actor for PK {:?}",
            safe_key.public_key()
        );
        let simulated_farming_payout_dot =
            Dot::new(PublicKey::from(SecretKey::random().public_key()), 0);

        let replicas_pk_set =
            TransferActor::get_replica_keys(safe_key.clone(), connection_manager.clone()).await?;

        let validator = ClientTransferValidator {};

        let transfer_actor = Arc::new(Mutex::new(SafeTransferActor::new(
            safe_key.clone(),
            replicas_pk_set.clone(),
            validator,
        )));

        let mut actor = Self {
            safe_key: safe_key.clone(),
            transfer_actor,
            connection_manager,
            replicas_pk_set,
            simulated_farming_payout_dot, // replicas_sk_set
        };

        #[cfg(feature = "simulated-payouts")]
        {
            match safe_key {
                SafeKey::Client(_) => {
                    // we're testing, and currently a lot of tests expect 10 money to start
                    let _ = actor
                        .trigger_simulated_farming_payout(
                            safe_key.public_key(),
                            Money::from_str("10")?,
                        )
                        .await?;
                }
                SafeKey::App(_) => {
                    let _ = actor
                        .trigger_simulated_farming_payout(
                            safe_key.public_key(),
                            // arbitrarily odd amount of money for apps, jsut so it's easier to see
                            Money::from_str("1.7")?,
                        )
                        .await?;
                }
            }
        }
        Ok(actor)
    }

    /// Create a Transfer Actor from an existing public key with an account history
    pub async fn for_existing_account(
        safe_key: SafeKey,
        // history: History,
        connection_manager: ConnectionManager,
    ) -> Result<Self, CoreError> {
        info!(
            "Setting up SafeTransferActor for existing PK : {:?}",
            safe_key.public_key()
        );
        let simulated_farming_payout_dot =
            Dot::new(PublicKey::from(SecretKey::random().public_key()), 0);

        let replicas_pk_set =
            TransferActor::get_replica_keys(safe_key.clone(), connection_manager.clone()).await?;

        let validator = ClientTransferValidator {};

        let transfer_actor =
            SafeTransferActor::new(safe_key.clone(), replicas_pk_set.clone(), validator);

        // let pending_validations: HashMap<MessageId, mpsc::UnboundedSender<DebitAgreementProof>> =
        //     HashMap::new();
        let mut full_actor = Self {
            safe_key,
            transfer_actor: Arc::new(Mutex::new(transfer_actor)),
            connection_manager,
            replicas_pk_set,
            simulated_farming_payout_dot, // replicas_sk_set
        };

        full_actor.get_history().await?;

        Ok(full_actor)
    }
}

// --------------------------------
// Tests
// ---------------------------------

// TODO: Do we need "new" to actually instantiate with a transfer?...
#[cfg(all(test, feature = "simulated-payouts"))]
mod tests {

    use super::*;
    use crate::client::transfer_actor::test_utils::get_keys_and_connection_manager;

    #[tokio::test]
    async fn transfer_actor_creation__() -> Result<(), CoreError> {
        let (safe_key, cm) = get_keys_and_connection_manager().await;
        let _transfer_actor = TransferActor::new(safe_key, cm.clone()).await?;

        assert!(true);

        Ok(())
    }

    #[tokio::test]
    async fn transfer_actor_creation_hydration_for_nonexistant_balance() -> Result<(), CoreError> {
        let (safe_key, cm) = get_keys_and_connection_manager().await;

        match TransferActor::for_existing_account(safe_key, cm.clone()).await {
            Ok(actor) => {
                assert_eq!(actor.get_local_balance().await, Money::from_str("0").unwrap() );
                Ok(())
            },
            Err(e) => panic!("Should not error for nonexistant keys, only create a new instance with no history, we got: {:?}" , e )
        }
    }

    // TODO: only do this for real vault until we a local replica bank
    #[tokio::test]
    #[cfg(not(feature = "mock-network"))]
    async fn transfer_actor_creation_hydration_for_existing_balance() -> Result<(), CoreError> {
        let (safe_key, _cm) = get_keys_and_connection_manager().await;
        let (safe_key_two, cm) = get_keys_and_connection_manager().await;

        let mut initial_actor = TransferActor::new(safe_key.clone(), cm.clone()).await?;

        let _ = initial_actor
            .trigger_simulated_farming_payout(safe_key_two.public_key(), Money::from_str("100")?)
            .await?;

        match TransferActor::for_existing_account(safe_key_two, cm.clone()).await {
            Ok(actor) => {
                assert_eq!(
                    actor.get_balance_from_network(None).await?,
                    Money::from_str("100")?
                );
                assert_eq!(actor.get_local_balance().await, Money::from_str("100")?);

                Ok(())
            }
            Err(e) => panic!("Account should exist {:?}", e),
        }
    }
}
