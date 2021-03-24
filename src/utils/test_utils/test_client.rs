// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::read_network_conn_info;
use crate::client::Client;
use anyhow::Result;
use sn_data_types::Keypair;
use std::sync::Once;
use tracing_subscriber::{fmt, EnvFilter};

static INIT: Once = Once::new();

/// Initialise logger for tests, this is run only once, even if called multiple times.
pub fn init_logger() {
    INIT.call_once(|| {
        fmt()
            // NOTE: comment out this line for more compact (but less readable) log output.
            .pretty()
            .with_thread_names(true)
            .with_env_filter(EnvFilter::from_default_env())
            .with_target(false)
            .init()
    });
}

/// Create a test client without providing any specific keypair or bootstrap_config
pub async fn create_test_client() -> Result<Client> {
    create_test_client_with(None).await
}

/// Create a test client optionally providing keypair and/or bootstrap_config
pub async fn create_test_client_with(optional_keypair: Option<Keypair>) -> Result<Client> {
    init_logger();
    let contact_info = read_network_conn_info()?;
    let client = Client::new(optional_keypair, None, Some(contact_info)).await?;
    Ok(client)
}
