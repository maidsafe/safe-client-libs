use safe_nd::{
    ClientFullId, Cmd, DebitAgreementProof, Message, Money, PublicKey, Query, QueryResponse,
    TransferCmd, TransferId, TransferQuery,
};

use safe_transfers::{ActorEvent, ReplicaValidator, TransferInitiated};

use crate::client::{Client, COST_OF_PUT};
use crate::errors::CoreError;
pub use safe_transfers::TransferActor as SafeTransferActor;

use log::{debug, info, trace, warn};

/// Module for Money balance management
pub mod balance_management;
/// Module for setting up SafeTransferActor
pub mod setup;
/// Module for simulating Money for testing
pub mod simulated_payouts;
/// Module containing all PUT apis
pub mod write_apis;

/// Simple client side validations
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientTransferValidator {}

impl ReplicaValidator for ClientTransferValidator {
    fn is_valid(&self, _replica_group: PublicKey) -> bool {
        true
    }
}

impl Client {
    /// Get the current coin balance via TransferActor for this client.
    pub async fn get_balance(
        &mut self,
        client_id: Option<&ClientFullId>,
    ) -> Result<Money, CoreError>
    where
        Self: Sized,
    {
        trace!("Get balance for {:?}", client_id);

        // we're a standard client grabbing our own key's balance
        self.get_balance_from_network(None).await
    }

    /// Get a payment proof
    pub async fn get_payment_proof(&mut self) -> Result<DebitAgreementProof, CoreError> {
        // --------------------------
        // Payment for PUT
        // --------------------------
        self.create_write_payment_proof().await
    }

    /// Retrieve the history of the acocunt from the network and apply to our local actor
    pub async fn get_history(&mut self) -> Result<(), CoreError> {
        let public_key = *self.full_id.public_key();
        info!("Getting SafeTransfers history for pk: {:?}", public_key);

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
                    .clone()
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
        // let mut actor = self.transfer_actor.lock().await;

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

        debug!("payment proof retrieved");
        Ok(payment_proof)
    }

    /// Send message and await validation and constructing of DebitAgreementProof
    async fn await_validation(
        &mut self,
        message: &Message,
        id: TransferId,
    ) -> Result<DebitAgreementProof, CoreError> {
        info!("Awaiting transfer validation");
        // self.connection_manager.send_cmd(&message).await?;
        // let proof = self.check_debit_cache(id).await;
        // Ok(proof)
        unimplemented!()
    }
}
