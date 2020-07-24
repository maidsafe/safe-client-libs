use safe_nd::{
    Cmd, DebitAgreementProof, Event, Message, MessageId, Money, PublicKey, Query, QueryResponse,
    TransferCmd, TransferQuery,
};
use safe_transfers::{ActorEvent, TransferInitiated};

use crate::client::{create_cmd_message, create_query_message, Client, TransferActor};
use crate::errors::CoreError;

use log::{debug, info, trace};

/// Handle all Money transfers and Write API requests for a given ClientId.
impl TransferActor {
    /// Get the account balance without querying the network
    pub async fn get_local_balance(&self) -> Money {
        info!("Retrieving actor's local balance.");
        self.transfer_actor.lock().await.balance()
    }

    /// Handle a validation event.
    pub async fn handle_validation_event(
        &mut self,
        event: Event,
    ) -> Result<Option<DebitAgreementProof>, CoreError> {
        debug!("Handling validation event: {:?}", event);
        let validation = match event {
            Event::TransferValidated { client, event } => event,
            _ => {
                return Err(CoreError::from(format!(
                    "Unexpected event received at TransferActor, {:?}",
                    event
                )))
            }
        };
        let mut actor = self.transfer_actor.lock().await;
        let transfer_validation = match actor.receive(validation) {
            Ok(Some(validation)) => validation,
            Ok(None) => return Ok(None),
             Err(error) => {
                if !error
                    .clone()
                    .to_string()
                    .contains("Already received validation")
                {
                    return Err(CoreError::from(error));
                }

                return Ok(None);
            }
        };

        actor.apply(ActorEvent::TransferValidationReceived(
            transfer_validation.clone(),
        ));

        Ok(transfer_validation.proof)
    }

    /// Get the current balance for this TransferActor PK (by default) or any other...
    pub async fn get_balance_from_network(
        &self,
        pk: Option<PublicKey>,
    ) -> Result<Money, CoreError> {
        info!("Getting balance for {:?} or self", pk);
        let mut cm = self.connection_manager();

        let identity = self.safe_key.clone();
        let pub_id = identity.public_id();

        let public_key = pk.unwrap_or(identity.public_key());

        // let request = Self::wrap_money_request(Query::GetBalance(public_key));

        let msg_contents = Query::Transfer(TransferQuery::GetBalance(public_key));

        let message = create_query_message(identity.clone(), msg_contents);
        let _bootstrapped = cm.bootstrap(identity).await;

        match cm.send_query(&pub_id, &message).await? {
            QueryResponse::GetBalance(balance) => balance.map_err(CoreError::from),
            _ => Err(CoreError::from("Unexpected response when querying balance")),
        }
    }

    /// Send money
    pub async fn send_money(&mut self, to: PublicKey, amount: Money) -> Result<(), CoreError> {
        info!("Sending money");
        let mut cm = self.connection_manager();

        //set up message
        let safe_key = self.safe_key.clone();

        // first make sure our balance  history is up to date
        self.get_history().await?;

        // let mut actor = self.transfer_actor.lock().await;

        println!(
            "Debits form our actor at send: {:?}",
            self.transfer_actor.lock().await.debits_since(0)
        );

        let signed_transfer = self
            .transfer_actor
            .lock()
            .await
            .transfer(amount, to)?.ok_or_else(||CoreError::from("No transfer generated by the actor."))?
            .signed_transfer;

        println!(
            "Signed transfer for send money: {:?}",
            signed_transfer.transfer
        );
        let msg_contents = Cmd::Transfer(TransferCmd::ValidateTransfer(signed_transfer.clone()));

        let message = create_cmd_message(safe_key.clone(), msg_contents);

        self.transfer_actor
            .lock()
            .await
            .apply(ActorEvent::TransferInitiated(TransferInitiated {
                signed_transfer,
            }));

        let debit_proof: DebitAgreementProof = self
            .await_validation(&safe_key.public_id(), &message)
            .await?;

        // Register the transfer on the network.
        let msg_contents = Cmd::Transfer(TransferCmd::RegisterTransfer(debit_proof.clone()));

        let message = create_cmd_message(safe_key.clone(), msg_contents);
        let safe_key = self.safe_key.clone();
        trace!(
            "Debit proof received and to be sent in RegisterTransfer req: {:?}",
            debit_proof
        );

        let _ = cm.send_cmd(&safe_key.public_id(), &message).await?;

        let mut actor = self.transfer_actor.lock().await;
        // First register with local actor, then reply.
        let register_event = actor.register(debit_proof)?.ok_or_else(||CoreError::from("No transfer event to register locally"))?;

        actor.apply(ActorEvent::TransferRegistrationSent(register_event.clone()));

        Ok(())
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
    use std::str::FromStr;

    #[tokio::test]
    #[cfg(feature = "simulated-payouts")]
    async fn transfer_actor_can_send_money_and_thats_reflected_locally() -> Result<(), CoreError> {
        let (safe_key, cm) = get_keys_and_connection_manager().await;
        let (safe_key2, _cm) = get_keys_and_connection_manager().await;

        let mut initial_actor = TransferActor::new(safe_key.clone(), cm.clone()).await?;

        let _ = initial_actor
            .send_money(safe_key2.public_key(), Money::from_str("1")?)
            .await?;

        // initial 10 on creation from farming simulation minus 1
        assert_eq!(
            initial_actor.get_local_balance().await,
            Money::from_str("9")?
        );

        assert_eq!(
            initial_actor.get_balance_from_network(None).await?,
            Money::from_str("9")?
        );

        Ok(())
    }

    #[tokio::test]
    #[cfg(feature = "simulated-payouts")]
    async fn transfer_actor_can_send_several_transfers_and_thats_reflected_locally(
    ) -> Result<(), CoreError> {
        let (safe_key, cm) = get_keys_and_connection_manager().await;
        let (safe_key2, _cm) = get_keys_and_connection_manager().await;

        let mut initial_actor = TransferActor::new(safe_key.clone(), cm.clone()).await?;

        println!("starting.....");
        let _ = initial_actor
            .send_money(safe_key2.public_key(), Money::from_str("1")?)
            .await?;

        // initial 10 on creation from farming simulation minus 1
        assert_eq!(
            initial_actor.get_local_balance().await,
            Money::from_str("9")?
        );

        assert_eq!(
            initial_actor.get_balance_from_network(None).await?,
            Money::from_str("9")?
        );

        println!("FIRST DONE!!!!!!!!!!!!!!");

        let _ = initial_actor
            .send_money(safe_key2.public_key(), Money::from_str("2")?)
            .await?;

        // initial 10 on creation from farming simulation minus 3
        Ok(assert_eq!(
            initial_actor.get_local_balance().await,
            Money::from_str("7")?
        ))
    }

    // TODO: do we want to be able to send 0 transfer reqs? This should probably be an actor side check if not
    // #[tokio::test]
    // #[cfg(feature = "simulated-payouts")]
    // async fn transfer_actor_cannot_send_0_money_req() -> Result<(), CoreError> {
    //     let (safe_key, cm) = get_keys_and_connection_manager().await;
    //     let (safe_key2, _cm) = get_keys_and_connection_manager().await;

    //     let mut initial_actor = TransferActor::new(safe_key.clone(), cm.clone()).await?;

    //     let res = initial_actor
    //         .send_money(safe_key2.public_key(), Money::from_str("0")?)
    //         .await?;

    //     println!("res to send 0: {:?}", res);

    //     // initial 10 on creation from farming simulation minus 1
    //     assert_eq!(
    //         initial_actor.get_local_balance().await,
    //         Money::from_str("10")?
    //     );

    //     assert_eq!(
    //         initial_actor.get_balance_from_network(None).await?,
    //         Money::from_str("10")?
    //     );

    //     Ok(())
    // }
}