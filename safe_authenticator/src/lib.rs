// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! SAFE Authenticator

#![doc(
    html_logo_url = "https://raw.githubusercontent.com/maidsafe/QA/master/Images/maidsafe_logo.png",
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
#![allow(
    // Our unsafe FFI functions are missing safety documentation. It is probably not necessary for
    // us to provide this for every single function as that would be repetitive and verbose.
    clippy::missing_safety_doc,
)]

// Public exports. See https://github.com/maidsafe/safe_client_libs/wiki/Export-strategy.

// Export public auth interface.
pub use self::errors::AuthError;
pub use client::AuthClient;
pub use errors::Result as AuthResult;
pub mod access_container;
pub mod app_auth;
pub mod app_container;
pub mod apps;
pub mod config;
pub mod errors;
pub mod ipc;
pub mod revocation;
/// default dir
pub mod std_dirs;
#[cfg(any(test, feature = "testing"))]
pub mod test_utils;

mod client;
#[cfg(test)]
mod tests;

use futures::{channel::mpsc, channel::mpsc::UnboundedSender, Future};

#[cfg(any(test, feature = "testing"))]
use safe_core::utils::test_utils::gen_client_id;
#[cfg(feature = "mock-network")]
use safe_core::ConnectionManager;
use safe_core::NetworkEvent;
use safe_nd::ClientFullId;
use std::pin::Pin;

/// Network observer for diconnection notifications
type AppNetworkDisconnectFuture = Pin<Box<dyn Future<Output = Result<(), ()>> + Sync + Send>>;

/// Authenticator instance which manages client and disconnect notifier.
pub struct Authenticator {
    /// AuthClient instance
    pub client: AuthClient,
    /// Network connection notifier
    pub network_observer: AppNetworkDisconnectFuture,
}

impl Authenticator {
    /// Create a new account.
    pub async fn create_client_with_acc<S, N>(
        locator: S,
        password: S,
        client_id: ClientFullId,
        disconnect_notifier: N,
    ) -> Result<Self, AuthError>
    where
        N: FnMut() + Send + Sync + 'static,
        S: Into<String>,
    {
        let locator = locator.into();
        let password = password.into();

        let (net_tx, network_observer) = Self::setup_network_observer(disconnect_notifier);

        let client = AuthClient::registered(&locator, &password, client_id, net_tx).await?;

        std_dirs::create(&client)
            .await
            .map_err(|error| AuthError::AccountContainersCreation(error.to_string()))?;

        Ok(Self {
            client,
            network_observer,
        })
    }

    fn setup_network_observer<N>(
        mut disconnect_notifier: N,
    ) -> (UnboundedSender<NetworkEvent>, AppNetworkDisconnectFuture)
    where
        N: FnMut() + Send + Sync + 'static,
    {
        let (net_tx, mut net_rx) = mpsc::unbounded();

        let observer = Box::pin(async move {
            if let Ok(Some(NetworkEvent::Disconnected)) = net_rx.try_next() {
                disconnect_notifier();
            };
            Ok(())
        });

        (net_tx, observer)
    }

    /// Log in to an existing account
    pub async fn login<S, N>(
        locator: S,
        password: S,
        disconnect_notifier: N,
    ) -> Result<Self, AuthError>
    where
        S: Into<String>,
        N: FnMut() + Send + Sync + 'static,
    {
        let locator = locator.into();
        let password = password.into();

        let (net_tx, network_observer) = Self::setup_network_observer(disconnect_notifier);

        let client: AuthClient = AuthClient::login(&locator, &password, net_tx).await?;
        if !client.std_dirs_created().await {
            let cloned_client = client.clone();

            std_dirs::create(&cloned_client).await?;
        }

        Ok(Self {
            client,
            network_observer,
        })
    }
}

#[cfg(any(test, feature = "testing"))]
impl Authenticator {
    /// Create a new account with given seed.
    pub async fn create_acc_with_seed<S, N>(
        seed: S,
        disconnect_notifier: N,
    ) -> Result<Self, AuthError>
    where
        S: Into<String>,
        N: FnMut() + Send + Sync + 'static,
    {
        let seed = seed.into();
        let client_id = gen_client_id();

        let (net_tx, network_observer) = Self::setup_network_observer(disconnect_notifier);

        let client = AuthClient::registered_with_seed(&seed, client_id, net_tx).await?;

        if !client.std_dirs_created().await {
            let cloned_client = client.clone();

            std_dirs::create(&cloned_client).await?;
        }

        Ok(Self {
            client,
            network_observer,
        })
    }

    /// Login to an existing account using the same seed that was used during account creation.
    pub async fn login_with_seed<S, N>(seed: S, disconnect_notifier: N) -> Result<Self, AuthError>
    where
        S: Into<String>,
        N: FnMut() + Send + Sync + 'static,
    {
        let seed = seed.into();

        let (net_tx, network_observer) = Self::setup_network_observer(disconnect_notifier);

        let client = AuthClient::login_with_seed(&seed, net_tx).await?;

        if !client.std_dirs_created().await {
            let cloned_client = client.clone();

            std_dirs::create(&cloned_client).await?;
        }

        Ok(Self {
            client,
            network_observer,
        })
    }
}

#[cfg(feature = "mock-network")]
impl Authenticator {
    #[allow(unused)]
    async fn create_acc_with_hook<F, S, N>(
        locator: S,
        password: S,
        client_id: ClientFullId,
        mut disconnect_notifier: N,
        connection_manager_wrapper_fn: F,
    ) -> Result<Self, AuthError>
    where
        N: FnMut() + Send + Sync + 'static,
        F: Fn(ConnectionManager) -> ConnectionManager + Send + Sync + 'static,
        S: Into<String>,
    {
        let locator = locator.into();
        let password = password.into();

        let (net_tx, network_observer) = Self::setup_network_observer(disconnect_notifier);

        let client = AuthClient::registered_with_hook(
            &locator,
            &password,
            client_id,
            net_tx,
            connection_manager_wrapper_fn,
        )
        .await?;

        std_dirs::create(&client)
            .await
            .map_err(|error| AuthError::AccountContainersCreation(error.to_string()))?;

        Ok(Self {
            client,
            network_observer,
        })
    }

    #[allow(unused)]
    async fn login_with_hook<F, S, N>(
        locator: S,
        password: S,
        disconnect_notifier: N,
        connection_manager_wrapper_fn: F,
    ) -> Result<Self, AuthError>
    where
        S: Into<String>,
        F: Fn(ConnectionManager) -> ConnectionManager + Send + Sync + 'static,
        N: FnMut() + Send + Sync + 'static,
    {
        let locator = locator.into();
        let password = password.into();

        let (net_tx, network_observer) = Self::setup_network_observer(disconnect_notifier);

        let client =
            AuthClient::login_with_hook(&locator, &password, net_tx, connection_manager_wrapper_fn)
                .await?;

        if !client.std_dirs_created().await {
            std_dirs::create(&client)
                .await
                .map_err(|error| AuthError::AccountContainersCreation(error.to_string()))?;
        }

        Ok(Self {
            client,
            network_observer,
        })
    }
}
