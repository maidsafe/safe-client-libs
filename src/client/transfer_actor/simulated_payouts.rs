use sn_data_types::Money;

#[cfg(feature = "simulated-payouts")]
use sn_data_types::Transfer;

#[cfg(feature = "simulated-payouts")]
use sn_messaging::{Cmd, TransferCmd};

use crate::client::Client;
use crate::errors::Error;

#[cfg(feature = "simulated-payouts")]
use log::info;

/// Handle all Money transfers and Write API requests for a given ClientId.
impl Client {
    #[cfg(not(feature = "simulated-payouts"))]
    /// Placeholder for simulate farming payout. Will always error if client or network are not built for "simulated-payouts"
    pub async fn trigger_simulated_farming_payout(&mut self, _amount: Money) -> Result<(), Error> {
        Err(Error::NotBuiltWithSimulatedPayouts)
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
    /// # extern crate tokio; use sn_client::Error;
    /// use sn_client::Client;
    /// use sn_data_types::{Keypair, Money};
    /// use std::str::FromStr;
    /// use rand::rngs::OsRng;
    /// # #[tokio::main] async fn main() { let _: Result<(), Error> = futures::executor::block_on( async {
    /// let id = std::sync::Arc::new(Keypair::new_ed25519(&mut OsRng));

    /// // Start our client
    /// let mut client = Client::new(Some(id), None).await?;
    /// let target_balance = Money::from_str("100")?;
    /// let _ = client.trigger_simulated_farming_payout(target_balance).await?;
    ///
    /// let balance = client.get_balance().await?;
    /// assert_eq!(balance, target_balance);
    /// # Ok(())} );}
    /// ```
    pub async fn trigger_simulated_farming_payout(&mut self, amount: Money) -> Result<(), Error> {
        let pk = self.public_key().await;
        info!("Triggering a simulated farming payout to: {:?}", pk);
        self.simulated_farming_payout_dot.apply_inc();

        let simulated_transfer = Transfer {
            to: pk,
            amount,
            debit_id: self.simulated_farming_payout_dot,
            msg: "asdf".to_string(),
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
    use tokio::time::{delay_for, Duration};

    #[tokio::test]
    #[cfg(feature = "simulated-payouts")]
    async fn transfer_actor_can_receive_simulated_farming_payout() -> Result<(), Error> {
        let mut client = Client::new(None, None).await?;

        let _ = client
            .trigger_simulated_farming_payout(Money::from_str("100")?)
            .await?;

        let mut money = client.get_balance_from_network(None).await?;
        while money != Money::from_str("110")? {
            delay_for(Duration::from_millis(200)).await;
            money = client.get_balance_from_network(None).await?;
        }

        Ok(())
    }
}
