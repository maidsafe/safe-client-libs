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
    attempt_bootstrap, req, AuthActions, Client, Inner, SafeKey, TransferActor,
    IMMUT_DATA_CACHE_SIZE,
};
use crate::config_handler::Config;
#[cfg(not(feature = "mock-network"))]
use crate::connection_manager::ConnectionManager;
use crate::crypto::{shared_box, shared_secretbox};
use crate::errors::CoreError;
use crate::ipc::BootstrapConfig;
use crate::network_event::NetworkTx;
use crate::utils;
use async_trait::async_trait;
use futures::lock::Mutex;
use log::trace;
use lru_cache::LruCache;
use rand::rngs::StdRng;
use rand::{thread_rng, SeedableRng};
use safe_nd::{ClientFullId, LoginPacket, LoginPacketRequest, PublicKey, Request, Response};

use std::sync::Arc;
use std::time::Duration;
use tiny_keccak::sha3_256;

/// Barebones Client object used for testing purposes.
pub struct CoreClient {
    inner: Arc<Mutex<Inner>>,
    keys: ClientKeys,
    transfer_actor: Option<TransferActor>,
}

impl CoreClient {
    /// This will create a basic Client object which is sufficient only for testing purposes.
    pub async fn new(
        acc_locator: &str,
        acc_password: &str,
        net_tx: NetworkTx,
    ) -> Result<Self, CoreError> {
        Self::new_impl(
            acc_locator.as_bytes(),
            acc_password.as_bytes(),
            net_tx,
            |cm| cm,
        )
        .await
    }

    async fn new_impl<F>(
        acc_locator: &[u8],
        acc_password: &[u8],
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
        let _new_balance_owner = *balance_client_id.public_id().public_key();

        let balance_client_id = SafeKey::client(balance_client_id);
        let balance_pub_id = balance_client_id.public_id();

        // Create the connection manager
        let mut connection_manager =
            attempt_bootstrap(&Config::new().quic_p2p, &net_tx, balance_client_id.clone()).await?;

        connection_manager = connection_manager_wrapper_fn(connection_manager);

        let transfer_actor =
            Some(TransferActor::new(balance_client_id.clone(), connection_manager.clone()).await?);

        let response = req(
            &mut connection_manager,
            Request::LoginPacket(LoginPacketRequest::Create(new_login_packet)),
            &balance_client_id,
        )
        .await?;

        match response {
            Response::Mutation(res) => res?,
            _ => return Err(CoreError::from("Unexpected response")),
        };

        connection_manager.disconnect(&balance_pub_id).await?;

        connection_manager
            .bootstrap(maid_keys.client_safe_key())
            .await?;

        Ok(Self {
            inner: Arc::new(Mutex::new(Inner {
                connection_manager,
                cache: LruCache::new(IMMUT_DATA_CACHE_SIZE),
                timeout: Duration::from_secs(180), // REQUEST_TIMEOUT_SECS), // FIXME
                net_tx,
            })),
            keys: maid_keys,
            transfer_actor,
        })
    }
}

#[async_trait]
impl Client for CoreClient {
    type Context = ();

    async fn full_id(&self) -> SafeKey {
        self.keys.client_safe_key()
    }

    async fn owner_key(&self) -> PublicKey {
        self.public_key().await
    }

    async fn config(&self) -> Option<BootstrapConfig> {
        None
    }

    fn inner(&self) -> Arc<Mutex<Inner>> {
        self.inner.clone()
    }

    async fn public_encryption_key(&self) -> threshold_crypto::PublicKey {
        self.keys.enc_public_key
    }

    async fn secret_encryption_key(&self) -> shared_box::SecretKey {
        self.keys.enc_secret_key.clone()
    }

    async fn secret_symmetric_key(&self) -> shared_secretbox::Key {
        self.keys.enc_key.clone()
    }

    /// Return the TransferActor for this client
    async fn transfer_actor(&self) -> Option<TransferActor> {
        self.transfer_actor.clone()
    }
}

// #[async_trait]
impl AuthActions for CoreClient {}

impl Clone for CoreClient {
    fn clone(&self) -> Self
    where
        Self: Sized,
    {
        CoreClient {
            inner: Arc::clone(&self.inner),
            keys: self.keys.clone(),
            transfer_actor: self.transfer_actor.clone(),
        }
    }
}
