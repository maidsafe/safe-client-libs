use log::{debug, info, trace, warn};
use safe_nd::{
    ClientFullId, Cmd, DebitAgreementProof, Message, Money, PublicKey, Query, QueryResponse,
    TransferCmd, TransferId, TransferQuery,
};
use sn_transfers::{ActorEvent, ReplicaValidator, TransferInitiated};
use threshold_crypto::PublicKeySet;

/// Module for Money balance management
pub mod balance_management;
/// Module for simulating Money for testing
pub mod simulated_payouts;
/// Module containing all PUT apis
pub mod write_apis;

/// Actual Transfer Actor
pub use sn_transfers::TransferActor as SafeTransferActor;

use crate::client::ConnectionManager;
use crate::client::{Client, COST_OF_PUT};
use crate::errors::CoreError;

/// Simple client side validations
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientTransferValidator {}

impl ReplicaValidator for ClientTransferValidator {
    fn is_valid(&self, _replica_group: PublicKey) -> bool {
        true
    }
}

impl Client {
    /// Get the client's current coin balance from the network
    ///
    /// # Examples
    ///
    /// Retrieve an existing balance
    /// ```no_run
    /// # extern crate tokio; use safe_core::CoreError;
    /// use safe_core::Client;
    /// use safe_nd::Money;
    /// use std::str::FromStr;
    /// # #[tokio::main] async fn main() { let _: Result<(), CoreError> = futures::executor::block_on( async {
    /// // Let's check the balance of a client with a random sk.
    /// // (It should have 0 balance)
    /// let secret_key = threshold_crypto::SecretKey::random();
    ///
    /// let mut client = Client::new(Some(secret_key)).await?;
    /// let initial_balance = Money::from_str("0")?;
    /// let balance = client.get_balance().await?;
    /// assert_eq!(balance, initial_balance);
    /// # Ok(()) } ); }
    /// ```
    pub async fn get_balance(&mut self) -> Result<Money, CoreError>
    where
        Self: Sized,
    {
        trace!(
            "Getting balance for {:?}",
            self.full_id().await.public_key()
        );

        // we're a standard client grabbing our own key's balance
        self.get_balance_from_network(None).await
    }

    /// Get balance for a Public Key on the network.
    ///
    /// # Examples
    ///
    /// Retrieve an existing balance
    /// ```no_run
    /// # extern crate tokio; use safe_core::CoreError;
    /// use safe_core::Client;
    /// use safe_nd::{Money, PublicKey};
    /// use std::str::FromStr;
    /// # #[tokio::main] async fn main() { let _: Result<(), CoreError> = futures::executor::block_on( async {
    /// // Let's check the balance of a client with a random sk.
    /// // (It should have 0 balance)
    /// let secret_key = threshold_crypto::SecretKey::random();
    /// let pk = PublicKey::from(secret_key.public_key());
    ///
    /// // And we use a random client to do this
    /// let mut client = Client::new(None).await?;
    /// let initial_balance = Money::from_str("0")?;
    /// let balance = client.get_balance_for(pk).await?;
    /// assert_eq!(balance, initial_balance);
    /// # Ok(()) } ); }
    /// ```
    pub async fn get_balance_for(&mut self, public_key: PublicKey) -> Result<Money, CoreError>
    where
        Self: Sized,
    {
        trace!("Get balance for {:?}", public_key);
        self.get_balance_from_network(Some(public_key)).await
    }

    /// Retrieve the history of the account from the network and apply to our local client's AT2 actor.
    ///
    /// # Examples
    ///
    /// Retrieving an existing balance history
    /// ```no_run
    /// # extern crate tokio; use safe_core::CoreError;
    /// use safe_core::Client;
    /// # #[tokio::main] async fn main() { let _: Result<(), CoreError> = futures::executor::block_on( async {
    /// // Let's check the balance of a client with a random sk.
    /// let secret_key = threshold_crypto::SecretKey::random();
    ///
    /// // And we use a random client to do this
    /// let mut client = Client::new(Some(secret_key)).await?;
    /// // Upon calling, history is retrieved and applied to the local AT2 actor.
    /// let _ = client.get_history().await?;
    /// # Ok(()) } ); }
    /// ```
    pub async fn get_history(&mut self) -> Result<(), CoreError> {
        let public_key = *self.full_id.public_key();
        info!("Getting SnTransfers history for pk: {:?}", public_key);

        let msg_contents = Query::Transfer(TransferQuery::GetHistory {
            at: public_key,
            since_version: 0,
        });

        let message = Self::create_query_message(msg_contents);

        // This is a normal response manager request. We want quorum on this for now...
        let res = self.connection_manager.send_query(&message).await?;

        let history = match res {
            QueryResponse::GetHistory(history) => history.map_err(CoreError::from),
            _ => Err(CoreError::from(format!(
                "Unexpected response when retrieving account history {:?}",
                res
            ))),
        }?;

        let mut actor = self.transfer_actor.lock().await;
        match actor.synch(history) {
            Ok(synced_transfer_outcome) => {
                if let Some(transfers) = synced_transfer_outcome {
                    actor.apply(ActorEvent::TransfersSynched(transfers))?;
                }
            }
            Err(error) => {
                if !error
                    .to_string()
                    .contains("No credits or debits found to sync to actor")
                {
                    return Err(CoreError::from(error));
                }

                warn!(
                    "No new transfer history  by TransferActor for pk: {:?}",
                    public_key
                );

                warn!("current balance {:?}", actor.balance());
            }
        }

        Ok(())
    }

    /// Validates a tranction for paying store_cost
    pub(crate) async fn create_write_payment_proof(
        &mut self,
    ) -> Result<DebitAgreementProof, CoreError> {
        info!("Sending requests for payment for write operation");

        //set up message
        let _full_id = self.full_id.clone();

        self.get_history().await?;

        let section_key = PublicKey::Bls(self.replicas_pk_set.public_key());

        let signed_transfer = self
            .transfer_actor
            .lock()
            .await
            .transfer(COST_OF_PUT, section_key)?
            .ok_or_else(|| CoreError::from("No transfer produced by actor."))?
            .signed_transfer;

        let command = Cmd::Transfer(TransferCmd::ValidateTransfer(signed_transfer.clone()));

        debug!("Transfer to be sent: {:?}", &signed_transfer);

        let transfer_message = Self::create_cmd_message(command);

        self.transfer_actor
            .lock()
            .await
            .apply(ActorEvent::TransferInitiated(TransferInitiated {
                signed_transfer: signed_transfer.clone(),
            }))?;

        let payment_proof: DebitAgreementProof = self
            .await_validation(&transfer_message, signed_transfer.id())
            .await?;

        debug!("Payment proof retrieved");
        Ok(payment_proof)
    }

    /// Get our replica instance PK set
    pub(crate) async fn get_replica_keys(
        full_id: ClientFullId,
        cm: &mut ConnectionManager,
    ) -> Result<PublicKeySet, CoreError> {
        trace!("Getting replica keys for {:?}", full_id);

        let keys_query_msg = Query::Transfer(TransferQuery::GetReplicaKeys(*full_id.public_key()));

        let message = Self::create_query_message(keys_query_msg);

        let res = cm.send_query(&message).await?;

        match res {
            QueryResponse::GetReplicaKeys(pk_set) => Ok(pk_set?),
            _ => Err(CoreError::from(format!(
                "Unexpected response when retrieving account replica keys for {:?}",
                full_id.public_key()
            ))),
        }
    }

    /// Send message and await validation and constructing of DebitAgreementProof
    async fn await_validation(
        &mut self,
        _message: &Message,
        _id: TransferId,
    ) -> Result<DebitAgreementProof, CoreError> {
        info!("Awaiting transfer validation");
        // self.connection_manager.send_cmd(&message).await?;
        // let proof = self.check_debit_cache(id).await;
        // Ok(proof)
        unimplemented!()
    }
}

// --------------------------------
// Tests
// ---------------------------------

// TODO: Do we need "new" to actually instantiate with a transfer?...
#[cfg(all(test, feature = "simulated-payouts"))]
mod tests {

    use super::*;
    use crate::crypto::shared_box;
    use safe_nd::Money;
    use std::str::FromStr;

    #[tokio::test]
    async fn transfer_actor_creation_hydration_for_nonexistant_balance() -> Result<(), CoreError> {
        let (sk, _pk) = shared_box::gen_bls_keypair();

        match Client::new(Some(sk)).await {
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
        let (sk, _pk) = shared_box::gen_bls_keypair();
        let (sk2, _pk2) = shared_box::gen_bls_keypair();

        let mut initial_actor = Client::new(Some(sk)).await?;

        let _ = initial_actor
            .trigger_simulated_farming_payout(Money::from_str("100")?)
            .await?;

        match Client::new(Some(sk2)).await {
            Ok(mut client) => {
                assert_eq!(
                    client.get_balance_from_network(None).await?,
                    Money::from_str("100")?
                );
                assert_eq!(client.get_local_balance().await, Money::from_str("100")?);

                Ok(())
            }
            Err(e) => panic!("Account should exist {:?}", e),
        }
    }
}
