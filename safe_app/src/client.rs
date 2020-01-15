// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::errors::AppError;
use crate::{AppContext, AppMsgTx};
use log::trace;
use lru_cache::LruCache;
use rand::thread_rng;
use safe_core::client::{Inner, SafeKey, IMMUT_DATA_CACHE_SIZE};
use safe_core::config_handler::Config;
use safe_core::core_structs::AppKeys;
use safe_core::crypto::{shared_box, shared_secretbox};
use safe_core::ipc::BootstrapConfig;
use safe_core::{Client, ConnectionManager, NetworkTx};
use safe_nd::{ClientFullId, PublicKey};
use std::cell::RefCell;
use std::fmt;
use std::rc::Rc;
use std::time::Duration;
use tokio::runtime::current_thread::{block_on_all, Handle};

/// Client object used by `safe_app`.
pub struct AppClient {
    inner: Rc<RefCell<Inner<AppClient, AppContext>>>,
    app_inner: Rc<RefCell<AppInner>>,
}

impl AppClient {
    /// This is a getter-only Gateway function to the Maidsafe network. It will create an
    /// unregistered random client which can do a very limited set of operations, such as a
    /// Network-Get.
    pub(crate) fn unregistered(
        el_handle: Handle,
        core_tx: AppMsgTx,
        net_tx: NetworkTx,
        config: Option<BootstrapConfig>,
    ) -> Result<Self, AppError> {
        trace!("Creating unregistered client.");

        let client_id = ClientFullId::new_bls(&mut thread_rng());
        let app_keys = AppKeys::new(client_id.public_id().clone());
        let pk = app_keys.public_key();

        let mut qp2p_config = Config::new().quic_p2p;
        if let Some(additional_contacts) = config.clone() {
            qp2p_config.hard_coded_contacts = qp2p_config
                .hard_coded_contacts
                .union(&additional_contacts)
                .cloned()
                .collect();
        }

        let mut connection_manager = ConnectionManager::new(qp2p_config, &net_tx.clone())?;
        block_on_all(connection_manager.bootstrap(app_keys.app_safe_key()))?;

        Ok(Self {
            inner: Rc::new(RefCell::new(Inner::new(
                el_handle,
                connection_manager,
                LruCache::new(IMMUT_DATA_CACHE_SIZE),
                // FIXME
                Duration::from_secs(180), // REQUEST_TIMEOUT_SECS),
                core_tx,
                net_tx,
            ))),
            app_inner: Rc::new(RefCell::new(AppInner::new(app_keys, pk, config))),
        })
    }

    /// This is a Gateway function to the Maidsafe network. This will help
    /// apps to authorise using an existing pair of keys.
    pub(crate) fn from_keys(
        keys: AppKeys,
        owner: PublicKey,
        el_handle: Handle,
        core_tx: AppMsgTx,
        net_tx: NetworkTx,
        config: BootstrapConfig,
    ) -> Result<Self, AppError> {
        Self::from_keys_impl(keys, owner, el_handle, core_tx, net_tx, config, |routing| {
            routing
        })
    }

    /// Allows customising the mock Routing client before logging in using client keys.
    #[cfg(any(
        all(test, feature = "mock-network"),
        all(feature = "testing", feature = "mock-network")
    ))]
    pub(crate) fn from_keys_with_hook<F>(
        keys: AppKeys,
        owner: PublicKey,
        el_handle: Handle,
        core_tx: AppMsgTx,
        net_tx: NetworkTx,
        config: BootstrapConfig,
        connection_manager_wrapper_fn: F,
    ) -> Result<Self, AppError>
    where
        F: Fn(ConnectionManager) -> ConnectionManager,
    {
        Self::from_keys_impl(
            keys,
            owner,
            el_handle,
            core_tx,
            net_tx,
            config,
            connection_manager_wrapper_fn,
        )
    }

    fn from_keys_impl<F>(
        keys: AppKeys,
        owner: PublicKey,
        el_handle: Handle,
        core_tx: AppMsgTx,
        net_tx: NetworkTx,
        config: BootstrapConfig,
        connection_manager_wrapper_fn: F,
    ) -> Result<Self, AppError>
    where
        F: Fn(ConnectionManager) -> ConnectionManager,
    {
        trace!("Attempting to log into an acc using client keys.");

        let mut qp2p_config = Config::new().quic_p2p;
        qp2p_config.hard_coded_contacts = qp2p_config
            .hard_coded_contacts
            .union(&config)
            .cloned()
            .collect();

        let mut connection_manager = ConnectionManager::new(qp2p_config, &net_tx.clone())?;
        let _ = block_on_all(connection_manager.bootstrap(keys.app_safe_key()));

        connection_manager = connection_manager_wrapper_fn(connection_manager);

        Ok(Self {
            inner: Rc::new(RefCell::new(Inner::new(
                el_handle,
                connection_manager,
                LruCache::new(IMMUT_DATA_CACHE_SIZE),
                Duration::from_secs(180), // REQUEST_TIMEOUT_SECS), // FIXME
                core_tx,
                net_tx,
            ))),
            app_inner: Rc::new(RefCell::new(AppInner::new(keys, owner, Some(config)))),
        })
    }
}

impl Client for AppClient {
    type Context = AppContext;

    fn full_id(&self) -> SafeKey {
        let app_inner = self.app_inner.borrow();
        app_inner.keys.app_safe_key()
    }

    fn owner_key(&self) -> PublicKey {
        self.app_inner.borrow().owner_key
    }

    fn config(&self) -> Option<BootstrapConfig> {
        let app_inner = self.app_inner.borrow();
        app_inner.config.clone()
    }

    fn inner(&self) -> Rc<RefCell<Inner<Self, Self::Context>>> {
        self.inner.clone()
    }

    fn public_encryption_key(&self) -> threshold_crypto::PublicKey {
        let app_inner = self.app_inner.borrow();
        app_inner.keys.clone().enc_public_key
    }

    fn secret_encryption_key(&self) -> shared_box::SecretKey {
        let app_inner = self.app_inner.borrow();
        app_inner.keys.clone().enc_secret_key
    }

    fn secret_symmetric_key(&self) -> shared_secretbox::Key {
        let app_inner = self.app_inner.borrow();
        app_inner.keys.clone().enc_key
    }
}

impl Clone for AppClient {
    fn clone(&self) -> Self {
        Self {
            inner: Rc::clone(&self.inner),
            app_inner: Rc::clone(&self.app_inner),
        }
    }
}

impl fmt::Debug for AppClient {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Safe App Client")
    }
}

struct AppInner {
    keys: AppKeys,
    owner_key: PublicKey,
    config: Option<BootstrapConfig>,
}

impl AppInner {
    pub fn new(keys: AppKeys, owner_key: PublicKey, config: Option<BootstrapConfig>) -> Self {
        Self {
            keys,
            owner_key,
            config,
        }
    }
}
