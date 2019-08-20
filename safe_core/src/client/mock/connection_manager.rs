// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::vault::{self, Vault};
use crate::config_handler::{get_config, Config};
use crate::{
    client::SafeKey,
    event::{NetworkEvent, NetworkTx},
    CoreError, CoreFuture,
};
use maidsafe_utilities::serialisation::serialise;
use quic_p2p::{self, Config as QuicP2pConfig};
use safe_nd::{Coins, Message, PublicId, PublicKey, Request, Response, XorName};
use std::collections::HashSet;
use std::env;
use std::sync::{Arc, Mutex};

lazy_static! {
    static ref VAULT: Arc<Mutex<Vault>> = Arc::new(Mutex::new(Vault::new(get_config())));
}

/// Function that is used to tap into routing requests and return preconditioned responses.
pub type RequestHookFn = dyn FnMut(&Request) -> Option<Response> + 'static;

/// Function that is used to modify responses before they are sent.
pub type ResponseHookFn = dyn FnMut(Response) -> Response + 'static;

/// Initialises QuicP2p instance. Establishes new connections.
/// Contains a reference to crossbeam channel provided by quic-p2p for capturing the events.
#[allow(unused)]
#[derive(Clone)]
pub struct ConnectionManager {
    vault: Arc<Mutex<Vault>>,
    request_hook: Option<Arc<RequestHookFn>>,
    response_hook: Option<Arc<ResponseHookFn>>,
    groups: Arc<Mutex<HashSet<PublicId>>>,
    net_tx: NetworkTx,
}

impl ConnectionManager {
    /// Create a new connection manager.
    pub fn new(_config: QuicP2pConfig, net_tx: &NetworkTx) -> Result<Self, CoreError> {
        Ok(Self {
            vault: clone_vault(),
            request_hook: None,
            response_hook: None,
            groups: Arc::new(Mutex::new(HashSet::default())),
            net_tx: net_tx.clone(),
        })
    }

    /// Returns `true` if this connection manager is already connected to a Client Handlers
    /// group serving the provided public ID.
    pub fn has_connection_to(&self, pub_id: &PublicId) -> bool {
        unwrap!(self.groups.lock()).contains(&pub_id)
    }

    /// Send `message` via the `ConnectionGroup` specified by our given `pub_id`.
    pub fn send(&mut self, pub_id: &PublicId, msg: &Message) -> Box<CoreFuture<Response>> {
        let msg: Message = {
            let mut vault = vault::lock(&self.vault, true);
            unwrap!(vault.process_request(pub_id.clone(), &unwrap!(serialise(&msg))))
        };

        // Send response back to a client
        if let Message::Response { response, .. } = msg {
            ok!(response)
        } else {
            err!(CoreError::Unexpected(
                "Logic error: Vault error returned invalid response".to_string()
            ))
        }
    }

    /// Bootstrap to any known contact.
    pub fn bootstrap(&mut self, full_id: SafeKey) -> Box<CoreFuture<()>> {
        let _ = unwrap!(self.groups.lock()).insert(full_id.public_id());
        ok!(())
    }

    /// Restart the connection to the groups.
    pub fn restart_network(&mut self) {
        // Do nothing
    }

    /// Disconnect from a group.
    pub fn disconnect(&mut self, pub_id: &PublicId) -> Box<CoreFuture<()>> {
        let mut groups = unwrap!(self.groups.lock());
        let _ = groups.remove(pub_id);
        if groups.is_empty() {
            trace!("Disconnected from the network; sending the notification.");
            let _ = self.net_tx.unbounded_send(NetworkEvent::Disconnected);
        }
        ok!(())
    }

    /// Add some coins to a wallet's PublicKey
    pub fn allocate_test_coins(
        &self,
        coin_balance_name: &XorName,
        amount: Coins,
    ) -> Result<(), safe_nd::Error> {
        let mut vault = vault::lock(&self.vault, true);
        vault.mock_increment_balance(coin_balance_name, amount)
    }

    /// Create coin balance in the mock network arbitrarily.
    pub fn create_balance(&self, owner: PublicKey, amount: Coins) {
        let mut vault = vault::lock(&self.vault, true);
        vault.mock_create_balance(owner, amount);
    }

    /// Simulates network disconnect
    pub fn simulate_disconnect(&self) {
        let mut groups = unwrap!(self.groups.lock());
        trace!("Simulating disconnect. Connected groups: {:?}", groups);

        if !groups.is_empty() {
            trace!("Disconnecting everyone");
            groups.clear();
            let _ = self.net_tx.unbounded_send(NetworkEvent::Disconnected);
        }
    }

    /// Simulates network timeouts
    pub fn set_simulate_timeout(&mut self, _enable: bool) {
        unimplemented!()
        // self.timeout_simulation = enable;
    }

    /// Sets a maximum number of operations
    pub fn set_network_limits(&mut self, _max_ops_count: Option<u64>) {
        unimplemented!()
        // self.max_ops_countdown = max_ops_count.map(Cell::new)
    }
}

#[cfg(any(feature = "testing", test))]
impl ConnectionManager {
    /*
        fn intercept_request<F>(
            &mut self,
            delay_ms: u64,
            src: Authority<XorName>,
            dst: Authority<XorName>,
            request: F,
        ) -> bool
        where
            F: FnOnce() -> Request,
        {
            let response = if let Some(ref mut hook) = self.request_hook {
                hook(&request())
            } else {
                None
            };

            if let Some(response) = response {
                self.send_response(delay_ms, src, dst, response);
                return true;
            }

            if self.timeout_simulation {
                return true;
            }

            false
        }
    */

    /// Set hook function to override response before request is processed, for test purposes.
    pub fn set_request_hook<F>(&mut self, hook: F)
    where
        F: FnMut(&Request) -> Option<Response> + 'static,
    {
        let hook: Arc<RequestHookFn> = Arc::new(hook);
        self.request_hook = Some(hook);
    }

    /// Set hook function to override response after request is processed, for test purposes.
    pub fn set_response_hook<F>(&mut self, hook: F)
    where
        F: FnMut(Response) -> Response + 'static,
    {
        let hook: Arc<ResponseHookFn> = Arc::new(hook);
        self.response_hook = Some(hook);
    }

    /// Removes hook function to override response results
    pub fn remove_request_hook(&mut self) {
        self.request_hook = None;
    }
}

/// Creates a thread-safe reference-counted pointer to the global vault.
pub fn clone_vault() -> Arc<Mutex<Vault>> {
    VAULT.clone()
}

pub fn unlimited_muts(config: &Config) -> bool {
    match env::var("SAFE_MOCK_UNLIMITED_MUTATIONS") {
        Ok(_) => true,
        Err(_) => match config.dev {
            Some(ref dev) => dev.mock_unlimited_mutations,
            None => false,
        },
    }
}
