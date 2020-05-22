// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

//! SAFE App.

#![doc(
    html_logo_url = "https://raw.githubusercontent.com/maidsafe/QA/master/Images/
maidsafe_logo.png",
    html_favicon_url = "http://maidsafe.net/img/favicon.ico",
    test(attr(forbid(warnings)))
)]
// For explanation of lint checks, run `rustc -W help`.
#![deny(unsafe_code)]
#![warn(
    missing_docs,
    trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    unused_results
)]

// Public exports. See https://github.com/maidsafe/safe_client_libs/wiki/Export-strategy.

// Re-export functions used in FFI so that they are accessible through the Rust API.
use std::sync::{Arc, Mutex};

pub use safe_core::core_structs::AppKeys;
pub use safe_core::{
    app_container_name, immutable_data, ipc, mdata_info, utils, Client, ClientKeys, CoreError,
    MDataInfo, DIR_TAG, MAIDSAFE_TAG,
};
pub use safe_nd::PubImmutableData;

// Export public app interface.

pub use crate::errors::AppError;
pub use client::AppClient;

pub mod cipher_opt;
pub mod permissions;

/// Utility functions to test apps functionality.
#[cfg(any(test, feature = "testing"))]
pub mod test_utils;

mod client;
pub mod errors;
#[cfg(test)]
mod tests;

use bincode::deserialize;
use futures::{
    channel::{mpsc as futures_mpsc, mpsc::UnboundedSender},
    future::FutureExt,
    Future,
};

#[cfg(feature = "mock-network")]
use safe_core::ConnectionManager;
use safe_core::{
    core_structs::{access_container_enc_key, AccessContInfo, AccessContainerEntry},
    crypto::shared_secretbox,
    ipc::{AuthGranted, BootstrapConfig},
    NetworkEvent,
};
use std::{collections::HashMap, pin::Pin};

/// Network observer for diconnection notifications
type AppNetworkDisconnectFuture = Pin<Box<dyn Future<Output = Result<(), ()>>>>;

/// Handle to an application instance.
pub struct App {
    /// Client to perform the operations against the network
    pub client: AppClient,
    /// Application context, i.e. registered or unregistered app
    pub context: AppContext,
    /// Network disconnection events observer
    pub network_observer: AppNetworkDisconnectFuture,
}

impl App {
    /// Create unregistered app.
    pub async fn unregistered<N>(
        disconnect_notifier: N,
        config: Option<BootstrapConfig>,
    ) -> Result<Self, AppError>
    where
        N: FnMut() + Send + 'static,
    {
        let (_net_tx, network_observer) = Self::setup_network_observer(disconnect_notifier);
        let client = AppClient::unregistered(_net_tx, config).await?;
        let context = AppContext::unregistered();
        Ok(Self {
            client,
            context,
            network_observer,
        })
    }

    /// Create registered app.
    pub async fn registered<N>(
        app_id: String,
        auth_granted: AuthGranted,
        disconnect_notifier: N,
    ) -> Result<Self, AppError>
    where
        N: FnMut() + Send + 'static,
    {
        let (net_tx, network_observer) = Self::setup_network_observer(disconnect_notifier);

        let AuthGranted {
            app_keys,
            access_container_info,
            bootstrap_config,
            ..
        } = auth_granted;
        let enc_key = app_keys.enc_key.clone();
        let owner_key = *app_keys.app_full_id.public_id().owner().public_key();

        let client = AppClient::from_keys(app_keys, owner_key, net_tx, bootstrap_config).await?;
        let context = AppContext::registered(app_id, enc_key, access_container_info);

        Ok(Self {
            client,
            context,
            network_observer,
        })
    }

    fn setup_network_observer<N>(
        mut disconnect_notifier: N,
    ) -> (UnboundedSender<NetworkEvent>, AppNetworkDisconnectFuture)
    where
        N: FnMut() + Send + 'static,
    {
        let (net_tx, mut net_rx) = futures_mpsc::unbounded();

        let observer = async move {
            if let Ok(Some(NetworkEvent::Disconnected)) = net_rx.try_next() {
                disconnect_notifier();
            };
            Ok(())
        }
        .boxed();

        (net_tx, observer)
    }

    /// Allows customising the mock Connection Manager before registering a new account.
    #[cfg(feature = "mock-network")]
    pub fn registered_with_hook<N, F>(
        app_id: String,
        auth_granted: AuthGranted,
        disconnect_notifier: N,
        connection_manager_wrapper_fn: F,
    ) -> Result<Self, AppError>
    where
        N: FnMut() + Send + 'static,
        F: Fn(ConnectionManager) -> ConnectionManager + Send + 'static,
    {
        let AuthGranted {
            app_keys,
            access_container_info,
            bootstrap_config,
            ..
        } = auth_granted;
        let enc_key = app_keys.enc_key.clone();
        let owner_key = *app_keys.app_full_id.public_id().owner().public_key();

        let (_net_tx, network_observer) = Self::setup_network_observer(disconnect_notifier);

        let client = futures::executor::block_on(AppClient::from_keys_with_hook(
            app_keys,
            owner_key,
            _net_tx,
            bootstrap_config,
            connection_manager_wrapper_fn,
        ))?;

        let context = AppContext::registered(app_id, enc_key, access_container_info);

        Ok(Self {
            client,
            context,
            network_observer,
        })
    }
}

/// Application context (data associated with the app).
#[derive(Clone)]
pub enum AppContext {
    /// Context of unregistered app.
    Unregistered(Arc<Unregistered>),
    /// Context of registered app.
    Registered(Arc<Registered>),
}

#[allow(missing_docs)]
pub struct Unregistered {}

#[allow(missing_docs)]
pub struct Registered {
    app_id: String,
    sym_enc_key: shared_secretbox::Key,
    access_container_info: AccessContInfo,
    access_info: Mutex<AccessContainerEntry>,
}

impl AppContext {
    fn unregistered() -> Self {
        Self::Unregistered(Arc::new(Unregistered {}))
    }

    fn registered(
        app_id: String,
        sym_enc_key: shared_secretbox::Key,
        access_container_info: AccessContInfo,
    ) -> Self {
        Self::Registered(Arc::new(Registered {
            app_id,
            sym_enc_key,
            access_container_info,
            access_info: Mutex::new(HashMap::new()),
        }))
    }

    /// Symmetric encryption/decryption key.
    pub fn sym_enc_key(&self) -> Result<&shared_secretbox::Key, AppError> {
        Ok(&self.as_registered()?.sym_enc_key)
    }

    /// Refresh access info by fetching it from the network.
    pub async fn refresh_access_info(&self, client: &AppClient) -> Result<(), AppError> {
        let reg = Arc::clone(self.as_registered()?);
        refresh_access_info(reg, client).await
    }

    /// Fetch a list of containers that this app has access to
    pub async fn get_access_info(
        &self,
        client: &AppClient,
    ) -> Result<AccessContainerEntry, AppError> {
        let reg: Arc<Registered> = self.as_registered()?.clone();
        // let reg = Arc::clone(self.as_registered()?);

        fetch_access_info(Arc::clone(&reg), client).await?;
        let access_info = reg.access_info.lock().unwrap();
        Ok(access_info.clone())
    }

    fn as_registered(&self) -> Result<&Arc<Registered>, AppError> {
        match *self {
            Self::Registered(ref a) => Ok(a),
            Self::Unregistered(_) => Err(AppError::OperationForbidden),
        }
    }
}

async fn refresh_access_info(context: Arc<Registered>, client: &AppClient) -> Result<(), AppError> {
    let entry_key = access_container_enc_key(
        &context.app_id,
        &context.sym_enc_key,
        &context.access_container_info.nonce,
    )?;

    let value = client
        .get_seq_mdata_value(
            context.access_container_info.id,
            context.access_container_info.tag,
            entry_key,
        )
        .await?;

    let encoded = utils::symmetric_decrypt(&value.data, &context.sym_enc_key)?;
    let decoded = deserialize(&encoded)?;

    *context.access_info.lock().unwrap() = decoded;

    Ok(())
}

async fn fetch_access_info(context: Arc<Registered>, client: &AppClient) -> Result<(), AppError> {
    if context.access_info.lock().unwrap().is_empty() {
        refresh_access_info(context, client).await
    } else {
        Ok(())
    }
}
