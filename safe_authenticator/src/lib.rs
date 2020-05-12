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
use futures_util::future::FutureExt;
use futures_util::future::TryFutureExt;
pub mod access_container;
pub mod app_auth;
pub mod app_container;
pub mod apps;
pub mod config;
pub mod errors;
pub mod ipc;
pub mod revocation;
use core::pin::Pin;
/// default dir
pub mod std_dirs;
#[cfg(any(test, feature = "testing"))]
pub mod test_utils;

mod client;
#[cfg(test)]
mod tests;

use futures::channel::mpsc;

use futures::{future::BoxFuture, Future};
use futures_util::stream::StreamExt;

#[cfg(any(test, feature = "testing"))]
use safe_core::utils::test_utils::gen_client_id;
#[cfg(feature = "mock-network")]
use safe_core::ConnectionManager;
use safe_core::{NetworkEvent, NetworkTx};
use safe_nd::ClientFullId;

/// Future type specialised with `AuthError` as an error type.
pub type AuthFuture<T> = dyn Future<Output = Result<T, AuthError>>;

/// Authenticator instance which manages client and disconnect notifier.
pub struct Authenticator {
    /// AuthClient instance
    pub client: AuthClient,
    /// Network connection notifier
    pub network_observer: Pin<Box<dyn Future<Output = Result<(), ()>>>>,
}

impl Authenticator {
    /// Create a new account.
    pub async fn create_client_with_acc<S, N>(
        locator: S,
        password: S,
        client_id: ClientFullId,
        mut disconnect_notifier: N,
    ) -> Result<Self, AuthError>
    where
        N: FnMut() + Send + 'static,
        S: Into<String>,
    {
        let locator = locator.into();
        let password = password.into();

        let (net_tx, mut net_rx) = mpsc::unbounded::<NetworkEvent>();

        let network_observer: BoxFuture<Result<(), ()>> = async move {
            if let Ok(Some(NetworkEvent::Disconnected)) = net_rx.try_next() {
                disconnect_notifier();
            };
            Ok(())
        }
        .boxed();

        let client = AuthClient::registered(&locator, &password, client_id, net_tx).await?;

        std_dirs::create(&client)
            .await
            .map_err(|error| AuthError::AccountContainersCreation(error.to_string()))?;

        Ok(Self {
            client,
            network_observer,
        })
    }

    /// Log in to an existing account
    pub async fn login<S, N>(
        locator: S,
        password: S,
        disconnect_notifier: N,
    ) -> Result<Self, AuthError>
    where
        S: Into<String>,
        N: FnMut() + Send + 'static,
    {
        let locator = locator.into();
        let password = password.into();

        Self::authenticator_login_impl(
            move |net_tx| {
                // block so as not to require future on this helper impl
                futures::executor::block_on(AuthClient::login(&locator, &password, net_tx))
            },
            disconnect_notifier,
        )
        .await
    }

    /// Log in to an existing account.
    pub async fn authenticator_login_impl<F: Send + 'static, N>(
        create_client_fn: F,
        mut disconnect_notifier: N,
    ) -> Result<Self, AuthError>
    where
        F: FnOnce(NetworkTx) -> Result<AuthClient, AuthError>,
        N: FnMut() + Send + 'static,
    {
        let (net_tx, mut net_rx) = mpsc::unbounded::<NetworkEvent>();
        let network_observer: BoxFuture<Result<(), ()>> = Box::pin(async move {
            if let Ok(Some(NetworkEvent::Disconnected)) = net_rx.try_next() {
                disconnect_notifier();
            };
            Ok(())
        });

        let client: AuthClient = create_client_fn(net_tx)?;

        if !client.std_dirs_created() {
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
        N: FnMut() + Send + 'static,
    {
        let seed = seed.into();
        let client_id = gen_client_id();

        Self::authenticator_login_impl(
            move |net_tx| {
                // Block as rng seed cannot be sent between threads
                let client = futures::executor::block_on(AuthClient::registered_with_seed(
                    &seed, client_id, net_tx,
                ))?;

                Ok(client)
            },
            disconnect_notifier,
        )
        .await
    }

    /// Login to an existing account using the same seed that was used during account creation.
    pub async fn login_with_seed<S, N>(seed: S, disconnect_notifier: N) -> Result<Self, AuthError>
    where
        S: Into<String>,
        N: FnMut() + Send + 'static,
    {
        let seed = seed.into();

        Self::authenticator_login_impl(
            // block on due to seed's being non x-thread
            move |net_tx| {
                futures::executor::block_on(AuthClient::login_with_seed(&seed.clone(), net_tx))
            },
            disconnect_notifier,
        )
        .await
    }
}

#[cfg(feature = "mock-network")]
impl Authenticator {
    #[allow(unused)]
    async fn create_acc_with_hook<F, S, N>(
        locator: S,
        password: S,
        client_id: ClientFullId,
        disconnect_notifier: N,
        connection_manager_wrapper_fn: F,
    ) -> Result<AuthClient, AuthError>
    where
        N: FnMut() + Send + 'static,
        F: Fn(ConnectionManager) -> ConnectionManager + Send + 'static,
        S: Into<String>,
    {
        let locator = locator.into();
        let password = password.into();

        let (net_tx, net_rx) = mpsc::unbounded::<NetworkEvent>();

        let network_observer: BoxFuture<Result<(), ()>> = async {
            if let Ok(Some(NetworkEvent::Disconnected)) = net_rx.try_next() {
                disconnect_notifier();
            };
            Ok(())
        }
        .boxed();

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
    fn login_with_hook<F, S, N>(
        locator: S,
        password: S,
        disconnect_notifier: N,
        connection_manager_wrapper_fn: F,
    ) -> Result<Self, AuthError>
    where
        S: Into<String>,
        F: Fn(ConnectionManager) -> ConnectionManager + Send + 'static,
        N: FnMut() + Send + 'static,
    {
        let locator = locator.into();
        let password = password.into();

        Self::authenticator_login_impl(
            move |net_tx| {
                AuthClient::login_with_hook(
                    &locator,
                    &password,
                    net_tx,
                    connection_manager_wrapper_fn,
                )
            },
            disconnect_notifier,
        )
    }
}
