// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

#[cfg(test)]
mod test_client;
#[cfg(feature = "simulated-payouts")]
mod tokens;

use anyhow::{anyhow, Context, Result};
use dirs_next::home_dir;
use std::{collections::HashSet, fs::File, io::BufReader, net::SocketAddr};
#[cfg(test)]
pub use test_client::{create_test_client, create_test_client_with, init_logger};
#[cfg(feature = "simulated-payouts")]
pub use tokens::{calculate_new_balance, gen_ed_keypair};

// Relative path from $HOME where to read the genesis node connection information from
const GENESIS_CONN_INFO_FILEPATH: &str = ".safe/node/node_connection_info.config";

/// Read local network bootstrapping/connection information
pub fn read_network_conn_info() -> Result<HashSet<SocketAddr>> {
    let user_dir = home_dir().ok_or_else(|| anyhow!("Could not fetch home directory"))?;
    let conn_info_path = user_dir.join(GENESIS_CONN_INFO_FILEPATH);

    let file = File::open(&conn_info_path).with_context(|| {
        format!(
            "Failed to open node connection information file at '{}'",
            conn_info_path.display(),
        )
    })?;
    let reader = BufReader::new(file);
    let contacts: HashSet<SocketAddr> = serde_json::from_reader(reader).with_context(|| {
        format!(
            "Failed to parse content of node connection information file at '{}'",
            conn_info_path.display(),
        )
    })?;

    Ok(contacts)
}

#[cfg(test)]
#[macro_export]
/// Helper for tests to retry an operation awaiting for a successful response result
macro_rules! retry_loop {
    ($async_func:expr) => {
        loop {
            match $async_func.await {
                Ok(val) => break val,
                Err(_) => tokio::time::sleep(std::time::Duration::from_millis(200)).await,
            }
        }
    };
}

#[cfg(test)]
#[macro_export]
/// Helper for tests to retry an operation awaiting for a specific result
macro_rules! retry_loop_for_pattern {
    ($async_func:expr, $pattern:pat $(if $cond:expr)?) => {
        loop {
            let result = $async_func.await;
            match &result {
                $pattern $(if $cond)? => break result,
                Ok(_) | Err(_) => tokio::time::sleep(std::time::Duration::from_millis(200)).await,
            }
        }
    };
}
