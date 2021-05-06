// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

// Module for token balance management
mod balance_management;
// Module for simulating token for testing
mod simulated_payouts;
// Module containing all PUT apis
mod write_apis;

use crate::{Client, Error};
use bincode::serialize;
use log::{debug, error, info, trace, warn};
use sn_data_types::{
    DebitId, PublicKey, SignedTransfer, Token, TransferAgreementProof, TransferValidated,
};
use sn_messaging::client::{
    Cmd, DataCmd, Message, Query, QueryResponse, TransferCmd, TransferQuery,
};
use sn_transfers::{ActorEvent, TransferInitiated};
use tokio::sync::mpsc::channel;

/// Actual Transfer Actor
pub use sn_transfers::TransferActor as SafeTransferActor;

impl Client {
    /// Get the client's current coin balance from the network
    ///
    /// # Examples
    ///
    /// Retrieve an existing balance
    /// ```no_run
    /// # extern crate tokio; use anyhow::Result;
    /// # use sn_client::utils::test_utils::read_network_conn_info;
    /// use sn_client::Client;
    /// use sn_data_types::{Keypair, Token};
    /// use rand::rngs::OsRng;
    /// use std::str::FromStr;
    /// # #[tokio::main] async fn main() { let _: Result<()> = futures::executor::block_on( async {
    /// // Let's check the balance of a client with a random id.
    /// // (It should have 0 balance)
    /// let id = Keypair::new_ed25519(&mut OsRng);

    /// # let bootstrap_contacts = Some(read_network_conn_info()?);
    /// let client = Client::new(Some(id), None, bootstrap_contacts).await?;
    /// let initial_balance = Token::from_str("0")?;
    /// let balance = client.get_balance().await?;
    /// assert_eq!(balance, initial_balance);
    /// # Ok(()) } ); }
    /// ```
    pub async fn get_balance(&self) -> Result<Token, Error>
    where
        Self: Sized,
    {
        trace!("Getting balance for {:?}", self.public_key().await);

        // we're a standard client grabbing our own key's balance
        self.get_history().await?;
        self.get_balance_from_network(None).await
    }

    /// Get balance for a Public Key on the network.
    ///
    /// # Examples
    ///
    /// Retrieve an existing balance
    /// ```no_run
    /// # extern crate tokio; use anyhow::Result;
    /// # use sn_client::utils::test_utils::read_network_conn_info;
    /// use sn_client::Client;
    /// use sn_data_types::{Keypair, Token};
    /// use std::str::FromStr;
    /// use rand::rngs::OsRng;
    /// # #[tokio::main] async fn main() { let _: Result<()> = futures::executor::block_on( async {
    /// // Let's check the balance of a client with a random id.
    /// let id = Keypair::new_ed25519(&mut OsRng);

    /// let pk = id.public_key();
    ///
    /// // And we use a random client to do this
    /// # let bootstrap_contacts = Some(read_network_conn_info()?);
    /// let client = Client::new(None, None, bootstrap_contacts).await?;
    /// let initial_balance = Token::from_str("0")?;
    /// let balance = client.get_balance_for(pk).await?;
    /// assert_eq!(balance, initial_balance);
    /// # Ok(()) } ); }
    /// ```
    pub async fn get_balance_for(&self, public_key: PublicKey) -> Result<Token, Error>
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
    /// # extern crate tokio; use anyhow::Result;
    /// # use sn_client::utils::test_utils::read_network_conn_info;
    /// use sn_client::Client;
    /// use sn_data_types::Keypair;
    /// use rand::rngs::OsRng;
    /// # #[tokio::main] async fn main() { let _: Result<()> = futures::executor::block_on( async {
    /// // Let's check the balance of a random client.
    /// // And we use a random client id to do this
    /// let id = Keypair::new_ed25519(&mut OsRng);

    /// # let bootstrap_contacts = Some(read_network_conn_info()?);
    /// let client = Client::new(Some(id), None, bootstrap_contacts).await?;
    /// // Upon calling, history is retrieved and applied to the local AT2 actor.
    /// let _ = client.get_history().await?;
    /// # Ok(()) } ); }
    /// ```
    pub async fn get_history(&self) -> Result<(), Error> {
        let public_key = self.public_key().await;
        info!("Getting SnTransfers history for pk: {:?}", public_key);

        let query = Query::Transfer(TransferQuery::GetHistory {
            at: public_key,
            since_version: 0,
        });

        // This is a normal response manager request. We want quorum on this for now...
        let query_result = self.session.send_query(query).await?;
        let msg_id = query_result.msg_id;

        let history = match query_result.response {
            QueryResponse::GetHistory(history) => history.map_err(|err| Error::from((err, msg_id))),
            _ => Err(Error::UnexpectedHistoryResponse(query_result.response)),
        }?;

        let mut actor = self.transfer_actor.lock().await;
        match actor.from_history(history) {
            Ok(synced_transfer_outcome) => {
                if let Some(transfers) = synced_transfer_outcome {
                    actor.apply(ActorEvent::TransfersSynched(transfers))?;
                }
            }

            Err(sn_transfers::Error::NoActorHistory) => {
                warn!(
                    "No new transfer history  by TransferActor for pk: {:?}",
                    public_key
                );
            }
            Err(error) => return Err(Error::from(error)),
        }

        debug!("Current balance after GetHistory {:?}", actor.balance());

        Ok(())
    }

    /// Fetch latest StoreCost for given number of bytes from the network.
    pub async fn get_store_cost(&self, bytes: u64) -> Result<(u64, Token, PublicKey), Error> {
        info!("Sending Query for latest StoreCost");

        let public_key = self.public_key().await;

        let query = Query::Transfer(TransferQuery::GetStoreCost {
            requester: public_key,
            bytes,
        });

        // This is a normal response manager request. We want quorum on this for now...

        let query_result = self.session.send_query(query).await?;
        let msg_id = query_result.msg_id;

        match query_result.response {
            QueryResponse::GetStoreCost(cost) => cost.map_err(|err| Error::from((err, msg_id))),
            _ => Err(Error::UnexpectedStoreCostResponse(query_result.response)),
        }
    }

    /// Validates a transaction for paying store_cost
    pub(crate) async fn create_write_payment_proof(
        &self,
        cmd: &DataCmd,
    ) -> Result<TransferAgreementProof, Error> {
        info!("Sending requests for payment for write operation");

        // Compute number of bytes
        let bytes = serialize(cmd)?.len() as u64;

        self.get_history().await?;

        let (bytes, cost_of_put, section_key) = self.get_store_cost(bytes).await?;
        info!(
            "Current store cost for {} bytes reported by section {}: {}",
            bytes, section_key, cost_of_put
        );

        let initiated = self
            .transfer_actor
            .lock()
            .await
            .transfer(cost_of_put, section_key, "".to_string())?
            .ok_or(Error::NoTransferEventsForLocalActor)?;
        let signed_transfer = SignedTransfer {
            debit: initiated.signed_debit,
            credit: initiated.signed_credit,
        };

        let command = Cmd::Transfer(TransferCmd::ValidateTransfer(signed_transfer.clone()));

        debug!("Transfer to be sent: {:?}", &signed_transfer);

        let transfer_message = self.create_cmd_message(command).await?;

        self.transfer_actor
            .lock()
            .await
            .apply(ActorEvent::TransferInitiated(TransferInitiated {
                signed_debit: signed_transfer.debit.clone(),
                signed_credit: signed_transfer.credit.clone(),
            }))?;

        let payment_proof: TransferAgreementProof = self
            .await_validation(&transfer_message, signed_transfer.id())
            .await?;

        debug!("Payment proof retrieved");
        Ok(payment_proof)
    }

    /// Send message and await validation and constructing of TransferAgreementProof
    async fn await_validation(
        &self,
        msg: &Message,
        _id: DebitId,
    ) -> Result<TransferAgreementProof, Error> {
        info!("Awaiting transfer validation");

        let (sender, mut receiver) = channel::<Result<TransferValidated, Error>>(7);

        // let endpoint = self.session.endpoint()?.clone();
        // let elders = self.session.elders.iter().cloned().collect();
        // let pending_transfers = self.session.pending_transfers.clone();

        let _ = self.session.send_transfer_validation(&msg, sender).await?;

        let mut returned_errors = vec![];
        let mut response_count: usize = 0;
        let supermajority = self.session.supermajority().await;

        loop {
            match receiver.recv().await {
                Some(event) => match event {
                    Ok(transfer_validated) => {
                        response_count += 1;
                        let mut actor = self.transfer_actor.lock().await;
                        // pass the received validation in to our actor
                        match actor.receive(transfer_validated) {
                            Ok(result) => {
                                // it's valid
                                if let Some(validation) = result {
                                    actor.apply(ActorEvent::TransferValidationReceived(
                                        validation.clone(),
                                    ))?;
                                    info!("Transfer successfully validated.");
                                    if let Some(tap) = validation.proof {
                                        debug!("Transfer has proof.");
                                        self.session
                                            .remove_pending_transfer_sender(&msg.id())
                                            .await?;
                                        return Ok(tap);
                                    }
                                } else {
                                    info!("Aggregated given SignatureShare.");
                                }
                            }
                            Err(e) => error!("Error accumulating SignatureShare: {:?}", e),
                        }
                    }
                    Err(e) => {
                        response_count += 1;
                        error!("Error receiving SignatureShare: {:?}", e);
                        returned_errors.push(e);

                        if returned_errors.len() >= supermajority {
                            warn!(
                                "More than the supermajority of elders have errored re: transfer"
                            );
                            // TODO: Check + handle that errors are the same
                            let error = returned_errors.remove(0);
                            self.session
                                .remove_pending_transfer_sender(&msg.id())
                                .await?;
                            return Err(error);
                        }

                        continue;
                    }
                },
                None => continue,
            }

            // at any point if we've had enough responses in, let's clean up
            if response_count >= supermajority {
                // remove pending listener
                let _ = self
                    .session
                    .remove_pending_transfer_sender(&msg.id())
                    .await?;
            }
        }
    }
}

// --------------------------------
// Tests
// ---------------------------------

#[cfg(test)]
mod tests {
    use crate::utils::test_utils::{create_test_client, create_test_client_with};
    use anyhow::{anyhow, Result};
    use rand::rngs::OsRng;
    use sn_data_types::Token;
    use std::str::FromStr;
    use tokio::time::{sleep, Duration};

    #[tokio::test]
    pub async fn transfer_actor_creation_hydration_for_nonexistant_balance() -> Result<()> {
        let keypair = sn_data_types::Keypair::new_ed25519(&mut OsRng);

        match create_test_client_with(Some(keypair)).await {
            Ok(actor) => {
                assert_eq!(actor.get_local_balance().await, Token::from_str("0")? );
                Ok(())
            },
            Err(e) => Err(anyhow!("Should not error for nonexistent keys, only create a new instance with no history, we got: {:?}" , e))
        }
    }

    #[tokio::test]
    pub async fn transfer_actor_client_random_creation_gets_initial_balance() -> Result<()> {
        let actor = create_test_client().await
            .map_err(|err| anyhow!("Should not error for random client, only create a new instance with 10 token, we got: {:?}" , err))?;

        let mut bal = actor.get_balance().await;
        while bal.is_err() {
            sleep(Duration::from_millis(200)).await;

            bal = actor.get_balance().await;
        }

        let mut tokens = bal?;
        while tokens != Token::from_str("10")? {
            sleep(Duration::from_millis(200)).await;

            tokens = actor.get_balance().await?;
        }

        Ok(())
    }

    #[tokio::test]
    pub async fn transfer_actor_creation_hydration_for_existing_balance() -> Result<()> {
        // small delay for starting this test, which seems to have a problem when nodes are under stress..
        // sleep(Duration::from_millis(200)).await;

        let keypair = sn_data_types::Keypair::new_ed25519(&mut OsRng);

        {
            let mut initial_actor = create_test_client_with(Some(keypair.clone())).await?;
            let _ = initial_actor
                .trigger_simulated_farming_payout(Token::from_str("100")?)
                .await?;
        }

        let client_res = create_test_client_with(Some(keypair.clone())).await;

        // while client_res.is_err() {
        //     sleep(Duration::from_millis(200)).await;

        //     client_res = create_test_client_with(Some(keypair.clone())).await;
        // }

        let client = client_res?;

        // Assert sender is debited.
        let mut _new_balance = client.get_balance().await?;
        let _desired_balance = Token::from_str("100")?;

        // loop until correct
        // while new_balance != desired_balance {
        //     sleep(Duration::from_millis(200)).await;
        //     new_balance = client.get_balance().await?;
        // }

        assert_eq!(client.get_local_balance().await, Token::from_str("100")?);

        Ok(())
    }
}
