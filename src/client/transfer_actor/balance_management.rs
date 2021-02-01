use sn_data_types::{PublicKey, SignedTransfer, Token, TransferAgreementProof};
use sn_messaging::{Cmd, Event, Query, QueryResponse, TransferCmd, TransferQuery};
use sn_transfers::{ActorEvent, TransferInitiated};

use crate::client::Client;
use crate::errors::Error;

use log::{debug, info, trace};

/// Handle all token transfers and Write API requests for a given ClientId.
impl Client {
    /// Get the current known account balance from the local actor. (ie. Without querying the network)
    ///
    /// # Examples
    ///
    /// Create a random client
    /// ```no_run
    /// # extern crate tokio;use sn_client::Error;
    /// use sn_client::Client;
    /// use std::str::FromStr;
    /// use sn_data_types::Token;
    /// # #[tokio::main]async fn main() {let _: Result<(), Error> = futures::executor::block_on( async {
    /// let client = Client::new(None, None).await?;
    /// // now we check the local balance
    /// let some_balance = client.get_local_balance().await;
    /// assert_eq!(some_balance, Token::from_str("0")?);
    /// # Ok(())} );}
    /// ```
    pub async fn get_local_balance(&self) -> Token {
        info!("Retrieving actor's local balance.");
        self.transfer_actor.lock().await.balance()
    }

    /// Handle a validation event.
    #[allow(dead_code)]
    pub(crate) async fn handle_validation_event(
        &self,
        event: Event,
    ) -> Result<Option<TransferAgreementProof>, Error> {
        debug!("Handling validation event: {:?}", event);
        let validation = match event {
            Event::TransferValidated { event, .. } => event,
            _ => return Err(Error::UnexpectedTransferEvent(event)),
        };
        let mut actor = self.transfer_actor.lock().await;
        let transfer_validation = match actor.receive(validation) {
            Ok(Some(validation)) => validation,
            Ok(None) => return Ok(None),
            Err(error) => {
                if !error.to_string().contains("Already received validation") {
                    return Err(Error::from(error));
                }

                return Ok(None);
            }
        };

        actor.apply(ActorEvent::TransferValidationReceived(
            transfer_validation.clone(),
        ))?;

        Ok(transfer_validation.proof)
    }

    /// Get the current balance for this TransferActor PK (by default) or any other...
    pub(crate) async fn get_balance_from_network(
        &self,
        pk: Option<PublicKey>,
    ) -> Result<Token, Error> {
        info!("Getting balance for {:?} or self", pk);
        let public_key = pk.unwrap_or(self.public_key().await);

        let msg_contents = Query::Transfer(TransferQuery::GetBalance(public_key));

        let message = Self::create_query_message(msg_contents);

        match self
            .connection_manager
            .lock()
            .await
            .send_query(&message)
            .await?
        {
            QueryResponse::GetBalance(balance) => balance.map_err(Error::from),
            another_response => Err(Error::UnexpectedQueryResponse(another_response)),
        }
    }

    /// Send token to another PublicKey.
    ///
    /// If the PublicKey does not exist as a balance on the network it will be created with the send amount.
    ///
    /// # Examples
    ///
    /// Send token to a PublickKey.
    /// (This test uses "simulated payouts" to generate test token. This of course would not be avaiable on a live network.)
    /// ```no_run
    /// # extern crate tokio;use sn_client::Error;
    /// use sn_client::Client;
    /// use sn_data_types::{PublicKey, Token};
    /// use std::str::FromStr;
    /// # #[tokio::main] async fn main() { let _: Result<(), Error> = futures::executor::block_on( async {
    /// // A random sk, to send token to
    /// let sk = threshold_crypto::SecretKey::random();
    /// let pk = PublicKey::from(sk.public_key());
    /// // Next we create a random client.
    /// let mut client = Client::new(None, None).await?;
    /// let target_balance = Token::from_str("100")?;
    /// // And trigger a simulated payout to our client's PublicKey, so we have token to send.
    /// let _ = client.trigger_simulated_farming_payout(target_balance).await?;
    ///
    /// // Now we have 100 token at our balance, we can send it elsewhere:
    /// let (count, sending_pk) = client.send_tokens( pk, target_balance ).await?;
    ///
    /// // Finally, we can see that the token has arrived:
    /// let received_balance = client.get_balance_for(pk).await?;
    ///
    /// assert_eq!(1, count);
    /// assert_ne!(pk, sending_pk);
    /// assert_eq!(received_balance, target_balance);
    /// # Ok(())} ); }
    /// ```
    pub async fn send_tokens(
        &self,
        to: PublicKey,
        amount: Token,
    ) -> Result<(u64, PublicKey), Error> {
        info!("Sending token");

        // first make sure our balance  history is up to date
        self.get_history().await?;

        info!(
            "Our actor balance at send: {:?}",
            self.transfer_actor.lock().await.balance()
        );

        let initiated = self
            .transfer_actor
            .lock()
            .await
            .transfer(amount, to, "asdf".to_string())?
            .ok_or(Error::NoTransferGenerated)?;

        let signed_transfer = SignedTransfer {
            debit: initiated.signed_debit,
            credit: initiated.signed_credit,
        };
        let dot = signed_transfer.id();
        let msg_contents = Cmd::Transfer(TransferCmd::ValidateTransfer(signed_transfer.clone()));

        let message = Self::create_cmd_message(msg_contents);

        self.transfer_actor
            .lock()
            .await
            .apply(ActorEvent::TransferInitiated(TransferInitiated {
                signed_debit: signed_transfer.debit.clone(),
                signed_credit: signed_transfer.credit.clone(),
            }))?;

        let transfer_proof: TransferAgreementProof = self
            .await_validation(&message, signed_transfer.id())
            .await?;

        // Register the transfer on the network.
        let msg_contents = Cmd::Transfer(TransferCmd::RegisterTransfer(transfer_proof.clone()));

        let message = Self::create_cmd_message(msg_contents);
        trace!(
            "Transfer proof received and to be sent in RegisterTransfer req: {:?}",
            transfer_proof
        );

        let _ = self
            .connection_manager
            .lock()
            .await
            .send_cmd(&message)
            .await?;

        let mut actor = self.transfer_actor.lock().await;
        // First register with local actor, then reply.
        let register_event = actor
            .register(transfer_proof)?
            .ok_or(Error::NoTransferEventsForLocalActor)?;

        actor.apply(ActorEvent::TransferRegistrationSent(register_event))?;

        Ok((dot.counter, dot.actor))
    }
}

// --------------------------------
// Tests
// ---------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::TransfersError;
    use crate::utils::{generate_random_vector, test_utils::calculate_new_balance};
    use anyhow::{anyhow, bail, Result};
    use rand::rngs::OsRng;
    use sn_data_types::{Keypair, Token};
    use std::str::FromStr;
    use tokio::time::{delay_for, Duration};

    #[tokio::test]
    pub async fn transfer_actor_can_send_tokens_and_thats_reflected_locally() -> Result<()> {
        let keypair = Keypair::new_ed25519(&mut OsRng);

        let client = Client::new(None, None).await?;

        let _ = client
            .send_tokens(keypair.public_key(), Token::from_str("1")?)
            .await?;

        // initial 10 on creation from farming simulation minus 1
        assert_eq!(client.get_local_balance().await, Token::from_str("9")?);

        assert_eq!(client.get_balance().await?, Token::from_str("9")?);

        Ok(())
    }

    #[tokio::test]
    pub async fn transfer_actor_can_send_several_transfers_and_thats_reflected_locally(
    ) -> Result<()> {
        let keypair2 = Keypair::new_ed25519(&mut OsRng);

        let client = Client::new(None, None).await?;

        let _ = client
            .send_tokens(keypair2.public_key(), Token::from_str("1")?)
            .await?;

        // Initial 10 token on creation from farming simulation minus 1
        // Assert locally
        assert_eq!(client.get_local_balance().await, Token::from_str("9")?);

        // Fetch balance from network and assert the same.
        assert_eq!(
            client.get_balance_from_network(None).await?,
            Token::from_str("9")?
        );

        let _ = client
            .send_tokens(keypair2.public_key(), Token::from_str("2")?)
            .await?;

        // Initial 10 on creation from farming simulation minus 3
        assert_eq!(client.get_local_balance().await, Token::from_str("7")?);

        // Fetch balance from network and assert the same.
        assert_eq!(
            client.get_balance_from_network(None).await?,
            Token::from_str("7")?
        );

        Ok(())
    }

    #[tokio::test]
    pub async fn transfer_actor_can_send_many_many_transfers_and_thats_reflected_locally_and_on_network(
    ) -> Result<()> {
        let keypair2 = Keypair::new_ed25519(&mut OsRng);

        let client = Client::new(None, None).await?;

        let _ = client
            .send_tokens(keypair2.public_key(), Token::from_str("1")?)
            .await?;

        // Initial 10 token on creation from farming simulation minus 1
        // Assert locally
        assert_eq!(client.get_local_balance().await, Token::from_str("9")?);

        // Fetch balance from network and assert the same.
        assert_eq!(client.get_balance().await?, Token::from_str("9")?);

        let _ = client
            .send_tokens(keypair2.public_key(), Token::from_str("1")?)
            .await?;

        // Initial 10 on creation from farming simulation minus 3
        assert_eq!(client.get_local_balance().await, Token::from_str("8")?);

        // Fetch balance from network and assert the same.
        assert_eq!(client.get_balance().await?, Token::from_str("8")?);

        let _ = client
            .send_tokens(keypair2.public_key(), Token::from_str("1")?)
            .await?;

        // Initial 10 on creation from farming simulation minus 3
        assert_eq!(client.get_local_balance().await, Token::from_str("7")?);

        // Fetch balance from network and assert the same.
        assert_eq!(client.get_balance().await?, Token::from_str("7")?);

        let _ = client
            .send_tokens(keypair2.public_key(), Token::from_str("1")?)
            .await?;

        // Initial 10 on creation from farming simulation minus 3
        assert_eq!(client.get_local_balance().await, Token::from_str("6")?);

        // Fetch balance from network and assert the same.
        assert_eq!(client.get_balance().await?, Token::from_str("6")?);

        Ok(())
    }

    #[tokio::test]
    pub async fn transfer_actor_cannot_send_0_token_req() -> Result<()> {
        let keypair2 = Keypair::new_ed25519(&mut OsRng);

        let client = Client::new(None, None).await?;

        // Send 0 token to a random PK.
        match client
            .send_tokens(keypair2.public_key(), Token::from_str("0")?)
            .await
        {
            Err(Error::Transfer(TransfersError::ZeroValueTransfer)) => Ok(()),
            result => Err(anyhow!(
                "Unexpected error. Zero-Value Transfers should not pass. Received: {:?}",
                result
            )),
        }?;

        // Unchanged balances - local and network.
        assert_eq!(client.get_local_balance().await, Token::from_str("10")?);

        assert_eq!(client.get_balance().await?, Token::from_str("10")?);

        Ok(())
    }

    // 1. Create a client A and allocate 100 token to it. (Clients start with 10 token by default on simulated-farming)
    // 2. Get the balance and verify it.
    // 3. Create another client B with a wallet holding 10 token on start.
    // 4. Transfer 11 token from client A to client B and verify the new balances.
    #[tokio::test]
    pub async fn balance_transfers_between_clients() -> Result<()> {
        let mut client = Client::new(None, None).await?;
        let receiving_client = Client::new(None, None).await?;

        let wallet1 = receiving_client.public_key().await;

        client
            .trigger_simulated_farming_payout(Token::from_str("100.0")?)
            .await?;

        let mut balance = client.get_balance().await?;

        while balance != Token::from_str("110")? {
            delay_for(Duration::from_millis(200)).await;

            balance = client.get_balance().await?;
        }
        // 11 here allows us to more easily debug repeat credits due w/ simulated payouts from each elder
        let _ = client
            .send_tokens(wallet1, Token::from_str("11.0")?)
            .await?;

        // Assert sender is debited.
        let mut new_balance = client.get_balance().await?;
        let desired_balance = calculate_new_balance(balance, None, Some(Token::from_str("11.0")?));

        // loop until correct
        while new_balance != desired_balance {
            delay_for(Duration::from_millis(200)).await;
            new_balance = client.get_balance().await?;
        }
        // Assert that the receiver has been credited.
        let mut receiving_bal = receiving_client.get_balance().await?;

        let target_tokens = Token::from_str("21.0")?;

        // loop until correct
        while receiving_bal != target_tokens {
            let _ = receiving_client.get_history().await?;
            delay_for(Duration::from_millis(200)).await;
            receiving_bal = receiving_client.get_balance().await?;

            if receiving_bal > target_tokens {
                continue;
            }
        }

        assert_eq!(receiving_bal, target_tokens);
        Ok(())
    }

    // 1. Create a sender client A w/10 token by default.
    // 2. Create a receiver client B w/10 token by default.
    // 3. Attempt to send 5000 token from A to B which should fail with 'InsufficientBalance'.
    // 4. Assert Client A's balance is unchanged.
    // 5. Assert Client B's balance is unchanged.
    #[tokio::test]
    pub async fn insufficient_balance_transfers() -> Result<()> {
        let client = Client::new(None, None).await?;
        let receiving_client = Client::new(None, None).await?;

        let wallet1 = receiving_client.public_key().await;

        // Try transferring token exceeding our balance.
        match client.send_tokens(wallet1, Token::from_str("5000")?).await {
            Err(Error::Transfer(TransfersError::InsufficientBalance)) => (),
            res => bail!("Unexpected result: {:?}", res),
        };

        // Assert if sender's token is unchanged.
        let balance = client.get_balance().await?;
        assert_eq!(balance, Token::from_str("10")?);

        // Assert no token is credited to receiver's bal accidentally by logic error.
        let receiving_bal = receiving_client.get_balance().await?;
        assert_eq!(receiving_bal, Token::from_str("10")?);

        Ok(())
    }

    #[tokio::test]
    pub async fn cannot_write_with_insufficient_balance() -> Result<()> {
        let client = Client::new(None, None).await?;
        let receiving_client = Client::new(None, None).await?;

        let wallet1 = receiving_client.public_key().await;

        let _ = client.send_tokens(wallet1, Token::from_str("10")?).await?;
        // Assert sender is debited.
        let mut new_balance = client.get_balance().await?;
        let desired_balance = Token::from_nano(0);

        // loop until correct
        while new_balance != desired_balance {
            delay_for(Duration::from_millis(200)).await;
            new_balance = client.get_balance().await?;
        }

        let data = generate_random_vector::<u8>(10);
        let res = client.store_public_blob(&data).await;
        match res {
            Err(Error::Transfer(TransfersError::InsufficientBalance)) => (),
            res => bail!(
                "Unexpected result in token transfer test, able to put data without balance: {:?}",
                res
            ),
        };

        Ok(())
    }
}
