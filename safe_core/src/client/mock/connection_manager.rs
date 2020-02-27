// Copyright 2020 MaidSafe.net limited.
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
    network_event::{NetworkEvent, NetworkTx},
    CoreError, CoreFuture,
};
use crate::{err, ok};
use lazy_static::lazy_static;
use log::trace;
use quic_p2p::{self, Config as QuicP2pConfig};
use safe_nd::{Coins, Message, PublicId, PublicKey, Request, RequestType, Response, XorName};
use std::collections::HashSet;
use std::env;
use std::sync::{Arc, Mutex};
use unwrap::unwrap;

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

    /// Create a new connection manager with the vault instance created from the provided config.
    pub fn new_with_vault(vault_config: Config, net_tx: &NetworkTx) -> Result<Self, CoreError> {
        Ok(Self {
            vault: Arc::new(Mutex::new(Vault::new(vault_config))),
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
        #[cfg(any(feature = "testing", test))]
        {
            if let Some(resp) = self.intercept_request(msg.clone()) {
                return ok!(resp);
            }
        }

        let msg: Message = {
            let writing = match msg {
                Message::Request { request, .. } => {
                    let req_type = request.get_type();
                    req_type == RequestType::Mutation || req_type == RequestType::Transaction
                }
                _ => false,
            };
            let mut vault = vault::lock(&self.vault, writing);
            unwrap!(vault.process_request(pub_id.clone(), &msg))
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
    fn intercept_request(&mut self, message: Message) -> Option<Response> {
        if let Message::Request { request, .. } = message {
            if let Some(hook) = Arc::get_mut(self.request_hook.as_mut()?) {
                if let Some(response) = hook(&request) {
                    return Some(response);
                }
            }
        }
        None
    }

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

pub fn unlimited_coins(config: &Config) -> bool {
    match env::var("SAFE_MOCK_UNLIMITED_COINS") {
        Ok(_) => true,
        Err(_) => match config.dev {
            Some(ref dev) => dev.mock_unlimited_coins,
            None => false,
        },
    }
}
