use sn_data_types::Money;

#[cfg(feature = "simulated-payouts")]
use sn_data_types::{Cmd, Transfer, TransferCmd};

use crate::client::Client;
use crate::errors::ClientError;

#[cfg(feature = "simulated-payouts")]
use log::info;

/// Handle all Money transfers and Write API requests for a given ClientId.
impl Client {
    #[cfg(not(feature = "simulated-payouts"))]
    /// Placeholder for simulate farming payout. Will always error if client or network are not built for "simulated-payouts"
    pub async fn trigger_simulated_farming_payout(
        &mut self,
        _amount: Money,
    ) -> Result<(), ClientError> {
        Err(ClientError::from(
            "Simulated payouts not available without 'simulated-payouts' feature flag",
        ))
    }

    #[cfg(feature = "simulated-payouts")]
    /// Simulate a farming payout & add a balance to the client's PublicKey.
    ///
    /// Useful for testing to generate initial balances needed for sending transfer requests, which is in turn required for performing write operations.
    ///
    /// This also keeps the client transfer actor up to date.
    ///
    /// # Examples
    ///
    /// Add 100 money to a client
    ///
    /// ```no_run
    /// # extern crate tokio; use sn_client::ClientError;
    /// use sn_client::Client;
    /// use sn_data_types::{ClientFullId, Money};
    /// use std::str::FromStr;
    /// use rand::rngs::OsRng;
    /// # #[tokio::main] async fn main() { let _: Result<(), ClientError> = futures::executor::block_on( async {
    /// let id = ClientFullId::new_ed25519(&mut OsRng);
    /// // Start our client
    /// let mut client = Client::new(Some(id)).await?;
    /// let target_balance = Money::from_str("100")?;
    /// let _ = client.trigger_simulated_farming_payout(target_balance).await?;
    ///
    /// let balance = client.get_balance().await?;
    /// assert_eq!(balance, target_balance);
    /// # Ok(())} );}
    /// ```
    pub async fn trigger_simulated_farming_payout(
        &mut self,
        amount: Money,
    ) -> Result<(), ClientError> {
        let pk = *self.full_id().await.public_key();
        info!("Triggering a simulated farming payout to: {:?}", pk);
        self.simulated_farming_payout_dot.apply_inc();

        let simulated_transfer = Transfer {
            to: pk,
            amount,
            id: self.simulated_farming_payout_dot,
        };

        let simluated_farming_cmd =
            Cmd::Transfer(TransferCmd::SimulatePayout(simulated_transfer.clone()));

        let message = Self::create_cmd_message(simluated_farming_cmd);

        let _ = self
            .connection_manager
            .lock()
            .await
            .send_cmd(&message)
            .await?;

        // If we're getting the payout for our own actor, update it here
        info!("Applying simulated payout locally, via query for history...");

        // get full history from network and apply locally
        self.get_history().await?;

        Ok(())
    }
}

// --------------------------------
// Tests
// ---------------------------------

#[cfg(all(test, feature = "simulated-payouts"))]
mod tests {

    use super::*;
    use std::str::FromStr;

    #[tokio::test]
    #[cfg(feature = "simulated-payouts")]
    async fn transfer_actor_can_receive_simulated_farming_payout() -> Result<(), ClientError> {
        let mut initial_actor = Client::new(None).await?;

        let _ = initial_actor
            .trigger_simulated_farming_payout(Money::from_str("100")?)
            .await?;

        // 100 sent
        assert_eq!(
            initial_actor.get_local_balance().await,
            Money::from_str("100")?
        );

        assert_eq!(
            initial_actor.get_balance_from_network(None).await?,
            Money::from_str("100")?
        );

        Ok(())
    }
}
