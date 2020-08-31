use safe_nd::{Cmd, Money};

#[cfg(feature = "simulated-payouts")]
use safe_nd::{Transfer, TransferCmd};

use crate::client::Client;
use crate::errors::CoreError;

#[cfg(feature = "simulated-payouts")]
use log::info;

/// Handle all Money transfers and Write API requests for a given ClientId.
impl Client {
    #[cfg(not(feature = "simulated-payouts"))]
    /// Simulate a farming payout
    pub async fn trigger_simulated_farming_payout(
        &mut self,
        _amount: Money,
    ) -> Result<(), CoreError> {
        Err(CoreError::from(
            "Simulated payouts not available without 'simulated-payouts' feature flag",
        ))
    }

    #[cfg(feature = "simulated-payouts")]
    /// Simulate a farming payout
    pub async fn trigger_simulated_farming_payout(
        &mut self,
        amount: Money,
    ) -> Result<(), CoreError> {
        let pk = self.full_id().await.public_key().clone();
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

        let _ = self.connection_manager.send_cmd(&message).await?;

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

// TODO: Do we need "new" to actually instantiate with a transfer?...
#[cfg(all(test, feature = "simulated-payouts"))]
mod tests {

    use super::*;

    use crate::crypto::shared_box;
    use std::str::FromStr;

    #[tokio::test]
    #[cfg(feature = "simulated-payouts")]
    async fn transfer_actor_can_receive_simulated_farming_payout() -> Result<(), CoreError> {
        let (sk, _pk) = shared_box::gen_bls_keypair();
        let mut initial_actor = Client::new(Some(sk.clone())).await?;

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
