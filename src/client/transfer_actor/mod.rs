use bincode::serialize;
use log::{debug, error, info, trace, warn};
use sn_data_types::{
    Cmd, DataCmd, DebitAgreementProof, Keypair, Message, Money, PublicKey, Query, QueryResponse,
    TransferCmd, TransferId, TransferQuery, TransferValidated,
};
use sn_transfers::{ActorEvent, ReplicaValidator, TransferInitiated};
use std::sync::Arc;
use threshold_crypto::PublicKeySet;
use tokio::sync::mpsc::channel;

/// Module for Money balance management
pub mod balance_management;
/// Module for simulating Money for testing
pub mod simulated_payouts;
/// Module containing all PUT apis
pub mod write_apis;

/// Actual Transfer Actor
pub use sn_transfers::TransferActor as SafeTransferActor;

use crate::client::{Client, ConnectionManager};
use crate::errors::ClientError;

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
    /// # extern crate tokio; use sn_client::ClientError;
    /// use sn_client::Client;
    /// use sn_data_types::{Keypair, Money};
    /// use rand::rngs::OsRng;
    /// use std::str::FromStr;
    /// # #[tokio::main] async fn main() { let _: Result<(), ClientError> = futures::executor::block_on( async {
    /// // Let's check the balance of a client with a random id.
    /// // (It should have 0 balance)
    /// let id = std::sync::Arc::new(Keypair::new_ed25519(&mut OsRng));

    /// let mut client = Client::new(Some(id), None).await?;
    /// let initial_balance = Money::from_str("0")?;
    /// let balance = client.get_balance().await?;
    /// assert_eq!(balance, initial_balance);
    /// # Ok(()) } ); }
    /// ```
    pub async fn get_balance(&mut self) -> Result<Money, ClientError>
    where
        Self: Sized,
    {
        trace!("Getting balance for {:?}", self.public_key().await);

        // we're a standard client grabbing our own key's balance
        self.get_balance_from_network(None).await
    }

    /// Get balance for a Public Key on the network.
    ///
    /// # Examples
    ///
    /// Retrieve an existing balance
    /// ```no_run
    /// # extern crate tokio; use sn_client::ClientError;
    /// use sn_client::Client;
    /// use sn_data_types::{Keypair, Money};
    /// use std::str::FromStr;
    /// use rand::rngs::OsRng;
    /// # #[tokio::main] async fn main() { let _: Result<(), ClientError> = futures::executor::block_on( async {
    /// // Let's check the balance of a client with a random id.
    /// let id = std::sync::Arc::new(Keypair::new_ed25519(&mut OsRng));

    /// let pk = id.public_key();
    ///
    /// // And we use a random client to do this
    /// let mut client = Client::new(None, None).await?;
    /// let initial_balance = Money::from_str("0")?;
    /// let balance = client.get_balance_for(pk).await?;
    /// assert_eq!(balance, initial_balance);
    /// # Ok(()) } ); }
    /// ```
    pub async fn get_balance_for(&mut self, public_key: PublicKey) -> Result<Money, ClientError>
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
    /// # extern crate tokio; use sn_client::ClientError;
    /// use sn_client::Client;
    /// use sn_data_types::Keypair;
    /// use rand::rngs::OsRng;
    /// # #[tokio::main] async fn main() { let _: Result<(), ClientError> = futures::executor::block_on( async {
    /// // Let's check the balance of a random client.
    /// // And we use a random client id to do this
    /// let id = std::sync::Arc::new(Keypair::new_ed25519(&mut OsRng));

    /// let mut client = Client::new(Some(id), None).await?;
    /// // Upon calling, history is retrieved and applied to the local AT2 actor.
    /// let _ = client.get_history().await?;
    /// # Ok(()) } ); }
    /// ```
    pub async fn get_history(&mut self) -> Result<(), ClientError> {
        let public_key = self.public_key().await;
        info!("Getting SnTransfers history for pk: {:?}", public_key);

        let msg_contents = Query::Transfer(TransferQuery::GetHistory {
            at: public_key,
            since_version: 0,
        });

        let message = Self::create_query_message(msg_contents);

        // This is a normal response manager request. We want quorum on this for now...
        let res = self
            .connection_manager
            .lock()
            .await
            .send_query(&message)
            .await?;

        let history = match res {
            QueryResponse::GetHistory(history) => history.map_err(ClientError::from),
            _ => Err(ClientError::from(format!(
                "Unexpected response when retrieving account history {:?}",
                res
            ))),
        }?;

        trace!("Received history response is: {:?}", history);

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
                    return Err(ClientError::from(error));
                }

                warn!(
                    "No new transfer history  by TransferActor for pk: {:?}",
                    public_key
                );
            }
        }

        debug!("Current balance after GetHistory {:?}", actor.balance());

        Ok(())
    }

    /// Fetch latest StoreCost for given number of bytes from the network.
    pub async fn get_store_cost(&mut self, bytes: u64) -> Result<Money, ClientError> {
        info!("Sending Query for latest StoreCost");

        let public_key = self.public_key().await;

        let msg_contents = Query::Transfer(TransferQuery::GetStoreCost {
            requester: public_key,
            bytes,
        });

        let message = Self::create_query_message(msg_contents);

        // This is a normal response manager request. We want quorum on this for now...
        let res = self
            .connection_manager
            .lock()
            .await
            .send_query(&message)
            .await?;

        match res {
            QueryResponse::GetStoreCost(cost) => cost.map_err(ClientError::DataError),
            _ => Err(ClientError::from(format!(
                "Unexpected response when retrieving StoreCost {:?}",
                res
            ))),
        }
    }

    /// Validates a transaction for paying store_cost
    pub(crate) async fn create_write_payment_proof(
        &mut self,
        cmd: &DataCmd,
    ) -> Result<DebitAgreementProof, ClientError> {
        info!("Sending requests for payment for write operation");

        // Compute number of bytes
        let bytes = serialize(cmd)?.len() as u64;

        self.get_history().await?;

        let section_key = PublicKey::Bls(self.replicas_pk_set.public_key());

        let cost_of_put = self.get_store_cost(bytes).await?;

        let signed_transfer = self
            .transfer_actor
            .lock()
            .await
            .transfer(cost_of_put, section_key)?
            .ok_or_else(|| ClientError::from("No transfer produced by actor."))?
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
        keypair: Arc<Keypair>,
        cm: &mut ConnectionManager,
    ) -> Result<PublicKeySet, ClientError> {
        trace!("Getting replica keys for {:?}", keypair);
        let pk = keypair.public_key();
        let keys_query_msg = Query::Transfer(TransferQuery::GetReplicaKeys(pk));

        let message = Self::create_query_message(keys_query_msg);

        let res = cm.send_query(&message).await?;

        match res {
            QueryResponse::GetReplicaKeys(pk_set) => Ok(pk_set?),
            _ => Err(ClientError::from(format!(
                "Unexpected response when retrieving account replica keys for {:?}",
                pk
            ))),
        }
    }

    /// Send message and await validation and constructing of DebitAgreementProof
    async fn await_validation(
        &mut self,
        message: &Message,
        _id: TransferId,
    ) -> Result<DebitAgreementProof, ClientError> {
        info!("Awaiting transfer validation");

        let (sender, mut receiver) = channel::<Result<TransferValidated, ClientError>>(7);

        self.connection_manager
            .lock()
            .await
            .send_transfer_validation(&message, sender)
            .await?;

        loop {
            match receiver.recv().await {
                Some(event) => match event {
                    Ok(transfer_validated) => {
                        let mut actor = self.transfer_actor.lock().await;
                        match actor.receive(transfer_validated) {
                            Ok(result) => {
                                if let Some(validation) = result {
                                    actor.apply(ActorEvent::TransferValidationReceived(
                                        validation.clone(),
                                    ))?;
                                    info!("Transfer successfully validated.");
                                    if let Some(dap) = validation.proof {
                                        return Ok(dap);
                                    }
                                } else {
                                    info!("Aggregated given SignatureShare.");
                                }
                            }
                            Err(e) => error!("Error accumulating SignatureShare: {:?}", e),
                        }
                    }
                    Err(e) => error!("Error receiving SignatureShare: {:?}", e),
                },
                None => continue,
            }
        }
    }
}

// --------------------------------
// Tests
// ---------------------------------

#[allow(missing_docs)]
#[cfg(feature = "simulated-payouts")]
pub mod exported_tests {

    use super::*;
    use rand::rngs::OsRng;
    use sn_data_types::Money;
    use std::str::FromStr;

    pub async fn transfer_actor_creation_hydration_for_nonexistant_balance(
    ) -> Result<(), ClientError> {
        let keypair = Arc::new(Keypair::new_ed25519(&mut OsRng));

        match Client::new(Some(keypair), None).await {
            Ok(actor) => {
                assert_eq!(actor.get_local_balance().await, Money::from_str("0")? );
                Ok(())
            },
            Err(e) => panic!("Should not error for nonexistent keys, only create a new instance with no history, we got: {:?}" , e )
        }
    }

    pub async fn transfer_actor_creation_hydration_for_existing_balance() -> Result<(), ClientError>
    {
        let keypair = Arc::new(Keypair::new_ed25519(&mut OsRng));

        {
            let mut initial_actor = Client::new(Some(keypair.clone()), None).await?;
            let _ = initial_actor
                .trigger_simulated_farming_payout(Money::from_str("100")?)
                .await?;
        }

        let client_res = Client::new(Some(keypair.clone()), None).await;
        // TODO: get this working in a full test suite run
        // while client_res.is_err() {
        //     client_res = Client::new(Some(keypair.clone()), None).await;
        // }

        let mut client = client_res?;

        // Assert sender is debited.
        let mut new_balance = client.get_balance().await?;
        let desired_balance = Money::from_str("100")?;

        // loop until correct
        while new_balance != desired_balance {
            new_balance = client.get_balance().await?;
        }

        assert_eq!(client.get_local_balance().await, Money::from_str("100")?);

        Ok(())
    }
}

#[cfg(all(test, feature = "simulated-payouts"))]
mod tests {
    use super::exported_tests;
    use crate::ClientError;

    #[tokio::test]
    #[cfg(feature = "simulated-payouts")]
    pub async fn transfer_actor_creation_hydration_for_nonexistant_balance(
    ) -> Result<(), ClientError> {
        exported_tests::transfer_actor_creation_hydration_for_nonexistant_balance().await
    }

    #[tokio::test]
    #[cfg(feature = "simulated-payouts")]
    pub async fn transfer_actor_creation_hydration_for_existing_balance() -> Result<(), ClientError>
    {
        exported_tests::transfer_actor_creation_hydration_for_existing_balance().await
    }
}
