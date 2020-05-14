// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::client::account::{Account as ClientAccount, ClientKeys};
#[cfg(feature = "mock-network")]
use crate::client::mock::ConnectionManager;
use crate::client::{
    attempt_bootstrap, req, AuthActions, Client, Inner, SafeKey, IMMUT_DATA_CACHE_SIZE,
};
use crate::config_handler::Config;
#[cfg(not(feature = "mock-network"))]
use crate::connection_manager::ConnectionManager;
use crate::crypto::{shared_box, shared_secretbox};
use crate::errors::CoreError;
use crate::event_loop::CoreMsgTx;
use crate::ipc::BootstrapConfig;
use crate::network_event::NetworkTx;
use crate::utils;
use log::trace;
use lru_cache::LruCache;
use rand::rngs::StdRng;
use rand::{thread_rng, SeedableRng};
use safe_nd::{
    ClientFullId, LoginPacket, LoginPacketRequest, Money, MoneyRequest, PublicKey, Request,
    Response,
};
use std::cell::RefCell;
use std::rc::Rc;
use std::str::FromStr;
use std::time::Duration;
use tiny_keccak::sha3_256;
use tokio::runtime::current_thread::{block_on_all, Handle};
use unwrap::unwrap;

/// Barebones Client object used for testing purposes.
pub struct CoreClient {
    inner: Rc<RefCell<Inner<CoreClient, ()>>>,
    keys: ClientKeys,
}

impl CoreClient {
    /// This will create a basic Client object which is sufficient only for testing purposes.
    pub fn new(
        acc_locator: &str,
        acc_password: &str,
        el_handle: Handle,
        core_tx: CoreMsgTx<Self, ()>,
        net_tx: NetworkTx,
    ) -> Result<Self, CoreError> {
        Self::new_impl(
            acc_locator.as_bytes(),
            acc_password.as_bytes(),
            el_handle,
            core_tx,
            net_tx,
            |cm| cm,
        )
    }

    fn new_impl<F>(
        acc_locator: &[u8],
        acc_password: &[u8],
        el_handle: Handle,
        core_tx: CoreMsgTx<Self, ()>,
        net_tx: NetworkTx,
        connection_manager_wrapper_fn: F,
    ) -> Result<Self, CoreError>
    where
        F: Fn(ConnectionManager) -> ConnectionManager,
    {
        trace!("Creating an account.");

        let (password, keyword, pin) = utils::derive_secrets(acc_locator, acc_password);

        let acc_loc = ClientAccount::generate_network_id(&keyword, &pin)?;
        let maid_keys = ClientKeys::new(&mut thread_rng());
        let acc = ClientAccount::new(maid_keys.clone())?;
        let acc_ciphertext = acc.encrypt(&password, &pin)?;

        let (client_pk, client_full_id) = {
            let mut seeder: Vec<u8> = Vec::with_capacity(acc_locator.len() + acc_password.len());
            seeder.extend_from_slice(acc_locator);
            seeder.extend_from_slice(acc_password);

            let seed = sha3_256(&seeder);
            let mut rng = StdRng::from_seed(seed);

            let client_full_id = ClientFullId::new_bls(&mut rng);
            (
                *client_full_id.public_id().public_key(),
                SafeKey::client(client_full_id),
            )
        };

        let sig = client_full_id.sign(&acc_ciphertext);
        let new_login_packet = LoginPacket::new(acc_loc, client_pk, acc_ciphertext, sig)?;

        let balance_client_id = maid_keys.client_id.clone();
        let to = *balance_client_id.public_id().public_key();
        let from = client_full_id.public_id().public_key();

        let balance_client_id = SafeKey::client(balance_client_id);
        let balance_pub_id = balance_client_id.public_id();

        // Create the connection manager
        let mut connection_manager =
            attempt_bootstrap(&Config::new().quic_p2p, &net_tx, balance_client_id.clone())?;

        connection_manager = connection_manager_wrapper_fn(connection_manager);

        {
            // Create the balance for the client
            let response = req(
                &mut connection_manager,
                Request::Money(MoneyRequest::CreateBalance {
                    to,
                    from,
                    amount: unwrap!(Money::from_str("10")),
                    transaction_id: rand::random(),
                }),
                &balance_client_id,
            )?;
            let _ = match response {
                Response::TransferReceipt(res) => res?,
                _ => return Err(CoreError::from("Unexpected response")),
            };

            let response = req(
                &mut connection_manager,
                Request::LoginPacket(LoginPacketRequest::Create(new_login_packet)),
                &balance_client_id,
            )?;

            match response {
                Response::Mutation(res) => res?,
                _ => return Err(CoreError::from("Unexpected response")),
            };

            block_on_all(connection_manager.disconnect(&balance_pub_id))?;
        }

        block_on_all(connection_manager.bootstrap(maid_keys.client_safe_key()))?;

        Ok(Self {
            inner: Rc::new(RefCell::new(Inner {
                el_handle,
                connection_manager,
                cache: LruCache::new(IMMUT_DATA_CACHE_SIZE),
                timeout: Duration::from_secs(180), // REQUEST_TIMEOUT_SECS), // FIXME
                net_tx,
                core_tx,
            })),
            keys: maid_keys,
        })
    }
}

impl Client for CoreClient {
    type Context = ();

    fn full_id(&self) -> SafeKey {
        self.keys.client_safe_key()
    }

    fn owner_key(&self) -> PublicKey {
        self.public_key()
    }

    fn config(&self) -> Option<BootstrapConfig> {
        None
    }

    fn inner(&self) -> Rc<RefCell<Inner<Self, Self::Context>>> {
        self.inner.clone()
    }

    fn public_encryption_key(&self) -> threshold_crypto::PublicKey {
        self.keys.enc_public_key
    }

    fn secret_encryption_key(&self) -> shared_box::SecretKey {
        self.keys.enc_secret_key.clone()
    }

    fn secret_symmetric_key(&self) -> shared_secretbox::Key {
        self.keys.enc_key.clone()
    }
}

impl AuthActions for CoreClient {}

impl Clone for CoreClient {
    fn clone(&self) -> Self {
        CoreClient {
            inner: Rc::clone(&self.inner),
            keys: self.keys.clone(),
        }
    }
}
