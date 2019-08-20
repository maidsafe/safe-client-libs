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
use lru_cache::LruCache;
use routing::FullId;
use rust_sodium::crypto::{box_, sign};
use safe_core::client::{ClientInner, NewFullId, IMMUT_DATA_CACHE_SIZE}; //, REQUEST_TIMEOUT_SECS};
use safe_core::config_handler::Config;
use safe_core::crypto::{shared_box, shared_secretbox, shared_sign};
use safe_core::ipc::BootstrapConfig;
use safe_core::{Client, ClientKeys, ConnectionManager, NetworkTx};
use safe_nd::{AppFullId, Message, MessageId, PublicId, PublicKey, Request, Signature};
use std::cell::RefCell;
use std::fmt;
use std::rc::Rc;
use std::time::Duration;
use tokio::runtime::current_thread::{block_on_all, Handle};

/// Client object used by safe_app.
pub struct AppClient {
    inner: Rc<RefCell<ClientInner<AppClient, AppContext>>>,
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

        let client_keys = ClientKeys::new(None);
        let client_pk = PublicKey::from(client_keys.bls_pk);

        let mut connection_manager =
            ConnectionManager::new(Config::new().quic_p2p, &net_tx.clone())?;
        block_on_all(connection_manager.bootstrap(NewFullId::app(
            client_keys.clone().into_app_full_id(client_pk),
        )))?;

        // let (routing, routing_rx) = setup_routing(
        //     None,
        //     PublicId::Client(ClientPublicId::new(client_pk.into(), client_pk)),
        //     config,
        // )?;
        // let joiner = spawn_routing_thread(routing_rx, core_tx.clone(), net_tx.clone());

        Ok(Self {
            inner: Rc::new(RefCell::new(ClientInner::new(
                el_handle,
                connection_manager,
                LruCache::new(IMMUT_DATA_CACHE_SIZE),
                Duration::from_secs(180), // REQUEST_TIMEOUT_SECS), // FIXMe
                core_tx,
                net_tx,
            ))),
            app_inner: Rc::new(RefCell::new(AppInner::new(client_keys, client_pk, config))),
        })
    }

    /// This is a Gateway function to the Maidsafe network. This will help
    /// apps to authorise using an existing pair of keys.
    pub(crate) fn from_keys(
        keys: ClientKeys,
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
        keys: ClientKeys,
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
        keys: ClientKeys,
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

        let mut connection_manager =
            ConnectionManager::new(Config::new().quic_p2p, &net_tx.clone())?;
        let _ = block_on_all(
            connection_manager.bootstrap(NewFullId::app(keys.clone().into_app_full_id(owner))),
        );

        // let (mut routing, routing_rx) = setup_routing(
        //     Some(keys.clone().into()),
        //     PublicId::App(
        //         AppFullId::with_keys(keys.bls_sk.clone(), owner)
        //             .public_id()
        //             .clone(),
        //     ),
        //     Some(config),
        // )?;
        connection_manager = connection_manager_wrapper_fn(connection_manager);

        Ok(Self {
            inner: Rc::new(RefCell::new(ClientInner::new(
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
    type MsgType = AppContext;

    fn full_id(&self) -> Option<FullId> {
        let app_inner = self.app_inner.borrow();
        Some(app_inner.keys.clone()).map(Into::into)
    }

    fn public_id(&self) -> PublicId {
        PublicId::App(
            AppFullId::with_keys(self.secret_bls_key(), self.owner_key())
                .public_id()
                .clone(),
        )
    }

    fn config(&self) -> Option<BootstrapConfig> {
        let app_inner = self.app_inner.borrow();
        app_inner.config
    }

    fn inner(&self) -> Rc<RefCell<ClientInner<Self, Self::MsgType>>> {
        self.inner.clone()
    }

    fn public_signing_key(&self) -> sign::PublicKey {
        let app_inner = self.app_inner.borrow();
        app_inner.keys.clone().sign_pk
    }

    fn secret_signing_key(&self) -> shared_sign::SecretKey {
        let app_inner = self.app_inner.borrow();
        app_inner.keys.clone().sign_sk
    }

    fn public_encryption_key(&self) -> box_::PublicKey {
        let app_inner = self.app_inner.borrow();
        app_inner.keys.clone().enc_pk
    }

    fn secret_encryption_key(&self) -> shared_box::SecretKey {
        let app_inner = self.app_inner.borrow();
        app_inner.keys.clone().enc_sk
    }

    fn secret_symmetric_key(&self) -> shared_secretbox::Key {
        let app_inner = self.app_inner.borrow();
        app_inner.keys.clone().enc_key
    }

    fn public_bls_key(&self) -> threshold_crypto::PublicKey {
        let app_inner = self.app_inner.borrow();
        app_inner.keys.clone().bls_pk
    }

    fn secret_bls_key(&self) -> threshold_crypto::SecretKey {
        let app_inner = self.app_inner.borrow();
        app_inner.keys.clone().bls_sk
    }

    fn owner_key(&self) -> PublicKey {
        let app_inner = self.app_inner.borrow();
        app_inner.owner_key
    }

    fn public_key(&self) -> PublicKey {
        self.public_bls_key().into()
    }

    fn compose_message(&self, request: Request, sign: bool) -> Message {
        let message_id = MessageId::new();

        let signature = if sign {
            let sig = self
                .secret_bls_key()
                .sign(&unwrap!(bincode::serialize(&(&request, message_id))));
            Some(Signature::from(sig))
        } else {
            None
        };

        Message::Request {
            request,
            message_id,
            signature,
        }
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
    keys: ClientKeys,
    owner_key: PublicKey,
    config: Option<BootstrapConfig>,
}

impl AppInner {
    pub fn new(keys: ClientKeys, owner_key: PublicKey, config: Option<BootstrapConfig>) -> Self {
        Self {
            keys,
            owner_key,
            config,
        }
    }
}
