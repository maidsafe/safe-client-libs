use safe_nd::{
    DebitAgreementProof, Message, MessageId, Money, MoneyRequest, PublicKey, ReplicaEvent, Request,
    Response, SignatureShare, SignedTransfer, Transfer, TransferPropagated,
};
use safe_transfers::ActorEvent;

use crate::client::{Client, TransferActor};
use crate::errors::CoreError;

use log::{debug, info, trace};

// #[cfg(feature = "simulated-payouts")]
// #[cfg(feature = "simulated-payouts")]
// #[cfg(feature = "simulated-payouts")]

/// Handle all Money transfers and Write API requests for a given ClientId.
impl TransferActor {
    // TODO
    // Send as vs use this need to be sorted ooooot
    /// Get the account balance without querying the network
    pub async fn get_local_balance(&self) -> Money {
        info!("Retrieving actor's local balance.");
        self.transfer_actor.lock().await.balance()
    }

    /// Handle a validation request response.
    pub async fn handle_validation_response(
        &mut self,
        response: Response,
        _message_id: &MessageId,
    ) -> Result<Option<DebitAgreementProof>, CoreError> {
        debug!("Handling validation response: {:?}", response);
        let validation = match response {
            Response::TransferValidation(res) => res?,
            _ => {
                return Err(CoreError::from(format!(
                    "Unexpected response received at TransferActor, {:?}",
                    response
                )))
            }
        };
        let mut actor = self.transfer_actor.lock().await;
        let transfer_validation = match actor.receive(validation) {
            Ok(validation) => validation,
            Err(error) => {
                if !error
                    .clone()
                    .to_string()
                    .contains("Already received validation")
                {
                    return Err(CoreError::from(error));
                }

                //a DAP should already have been returned at this point
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

        let message_id = MessageId::new();

        let request = Request::Money(MoneyRequest::GetBalance(public_key));
        // TODO: remove this unwrap
        let signature = Some(self.safe_key.sign(&unwrap::unwrap!(bincode::serialize(&(
            &request, message_id
        )))));

        let message = Message::Request {
            request,
            message_id: message_id.clone(),
            signature,
        };

        let _bootstrapped = cm.bootstrap(identity).await;

        match cm.send(&pub_id, &message).await? {
            Response::GetBalance(balance) => balance.map_err(CoreError::from),
            _ => Err(CoreError::from("Unexpected response when querying balance")),
        }
    }

    /// Send money
    pub async fn send_money(
        &mut self,
        to: PublicKey,
        amount: Money,
    ) -> Result<Response, CoreError> {
        info!("Sending money");
        let mut cm = self.connection_manager();

        //set up message
        let safe_key = self.safe_key.clone();

        // first make sure our balance  history is up to date
        self.get_history().await?;

        debug!(
            "Debits form our actor at send: {:?}",
            self.transfer_actor.lock().await.debits_since(0)
        );

        let signed_transfer = self
            .transfer_actor
            .lock()
            .await
            .transfer(amount, to)?
            .signed_transfer;

        debug!(
            "Signed transfer for send money: {:?}",
            signed_transfer.transfer
        );
        let request = Request::Money(MoneyRequest::ValidateTransfer { signed_transfer });

        let (message, _message_id) = self.create_network_message(request)?;

        // TODO: make it clearer
        // #[cfg(feature = "mock-network")]
        // {
        //     // no waiting on validation needed for mock
        //     return cm.send(&safe_key.public_id(), &message).await;
        // }

        let debit_proof: DebitAgreementProof = self
            .await_validation(
                message.message_id().ok_or(CoreError::from(
                    "No message id for created transfer actor request",
                ))?,
                &safe_key.public_id(),
                &message,
            )
            .await?;

        // Register the transfer on the network.
        let register_transaction_request = Request::Money(MoneyRequest::RegisterTransfer {
            proof: debit_proof.clone(),
        });
        let (message, _message_id) = self.create_network_message(register_transaction_request)?;
        let safe_key = self.safe_key.clone();
        trace!(
            "Debit proof received and to be sent in RegisterTransfer req: {:?}",
            debit_proof
        );
        let response = cm.send(&safe_key.public_id(), &message).await?;

        // self.register_transfer_locally_on_ok(response, debit_proof).await
        match response.clone() {
            Response::TransferRegistration(result) => {
                match result {
                    Ok(_transfer_response) => {
                        let mut actor = self.transfer_actor.lock().await;
                        // First register with local actor, then reply.
                        let register_event = actor.register(debit_proof)?;

                        actor.apply(ActorEvent::TransferRegistrationSent(register_event.clone()));

                        Ok(response)
                    }
                    Err(error) => Err(CoreError::from(error)),
                }
            }
            _ => Err(CoreError::from(
                "Unexpected Reponse received to 'send money' request in ClientTransferActor",
            )),
        }
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
