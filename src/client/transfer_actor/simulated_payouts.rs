// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use sn_data_types::Token;

#[cfg(feature = "simulated-payouts")]
use sn_data_types::Transfer;

#[cfg(feature = "simulated-payouts")]
use sn_messaging::client::{Cmd, TransferCmd};

use crate::{client::Client, errors::Error};

#[cfg(feature = "simulated-payouts")]
use log::info;

/// Handle all token transfers and Write API requests for a given ClientId.
impl Client {
    #[cfg(not(feature = "simulated-payouts"))]
    /// Placeholder for simulate farming payout. Will always error if client or network are not built for "simulated-payouts"
    pub async fn trigger_simulated_farming_payout(&mut self, _amount: Token) -> Result<(), Error> {
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
    /// Add 100 token to a client
    ///
    /// ```no_run
    /// # extern crate tokio; use anyhow::Result;
    /// # use sn_client::utils::test_utils::read_network_conn_info;
    /// use sn_client::Client;
    /// use sn_data_types::{Keypair, Token};
    /// use std::str::FromStr;
    /// use rand::rngs::OsRng;
    /// # #[tokio::main] async fn main() { let _: Result<()> = futures::executor::block_on( async {
    /// let id = Keypair::new_ed25519(&mut OsRng);

    /// // Start our client
    /// # let bootstrap_contacts = Some(read_network_conn_info()?);
    /// let mut client = Client::new(Some(id), None, bootstrap_contacts).await?;
    /// let target_balance = Token::from_str("100")?;
    /// let _ = client.trigger_simulated_farming_payout(target_balance).await?;
    ///
    /// let balance = client.get_balance().await?;
    /// assert_eq!(balance, target_balance);
    /// # Ok(())} );}
    /// ```
    pub async fn trigger_simulated_farming_payout(&mut self, amount: Token) -> Result<(), Error> {
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

        let message = self.create_cmd_message(simluated_farming_cmd).await?;

        let _ = self.session.send_cmd(&message).await?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::create_test_client;
    use anyhow::Result;
    use std::str::FromStr;
    use tokio::time::{sleep, Duration};

    #[tokio::test]
    #[cfg(feature = "simulated-payouts")]
    async fn transfer_actor_can_receive_simulated_farming_payout() -> Result<()> {
        let mut client = create_test_client().await?;

        let _ = client
            .trigger_simulated_farming_payout(Token::from_str("100")?)
            .await?;

        let mut tokens = client.get_balance_from_network(None).await?;
        while tokens != Token::from_str("110")? {
            sleep(Duration::from_millis(200)).await;
            tokens = client.get_balance_from_network(None).await?;
        }

        Ok(())
    }
}
