// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::client::{Client, COST_OF_PUT};
use anyhow::{anyhow, Result};
use sn_data_types::{Keypair, Token};
use std::{collections::HashSet, net::SocketAddr, sync::Once};
use tracing_subscriber::{fmt, EnvFilter};

static INIT: Once = Once::new();

/// Create a test client without providing any specific keypair or bootstrap_config
pub async fn create_test_client() -> Result<Client> {
    create_test_client_with(None, None).await
}

/// Create a test client optionally providing keypair and/or bootstrap_config
pub async fn create_test_client_with(
    optional_keypair: Option<Keypair>,
    bootstap_config: Option<HashSet<SocketAddr>>,
) -> Result<Client> {
    // Setup logger for tests that is only run once, even if called multiple times.
    INIT.call_once(|| {
        fmt()
            // NOTE: comment out this line for more compact (but less readable) log output.
            .pretty()
            .with_env_filter(EnvFilter::from_default_env())
            .with_target(false)
            .init()
    });

    let client = Client::new(optional_keypair, bootstap_config).await?;
    Ok(client)
}

/// Generates a random BLS secret and public keypair.
#[cfg(feature = "simulated-payouts")]
pub fn gen_ed_keypair() -> Keypair {
    let mut rng = rand::thread_rng();
    Keypair::new_ed25519(&mut rng)
}

/// Helper function to calculate the total cost of expenditure by adding number of mutations and
/// amount of transferred coins if any.
#[cfg(feature = "simulated-payouts")]
pub fn calculate_new_balance(
    mut balance: Token,
    mutation_count: Option<u64>,
    transferred_coins: Option<Token>,
) -> Result<Token> {
    if let Some(x) = mutation_count {
        let amount = Token::from_nano(x * COST_OF_PUT.as_nano());
        balance = balance.checked_sub(amount).ok_or_else(|| {
            anyhow!(
                "Failed to substract {} tokens amount from {}",
                amount,
                balance
            )
        })?;
    }
    if let Some(coins) = transferred_coins {
        balance = balance.checked_sub(coins).ok_or_else(|| {
            anyhow!(
                "Failed to substract {} tokens amount from {}",
                coins,
                balance
            )
        })?;
    }

    Ok(balance)
}
