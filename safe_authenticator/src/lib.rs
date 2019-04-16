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
// For explanation of lint checks, run `rustc -W help` or see
// https://github.com/maidsafe/QA/blob/master/Documentation/Rust%20Lint%20Checks.md
#![forbid(
    exceeding_bitshifts,
    mutable_transmutes,
    no_mangle_const_items,
    unknown_crate_types,
    warnings
)]
#![deny(
    bad_style,
    deprecated,
    improper_ctypes,
    missing_docs,
    non_shorthand_field_patterns,
    overflowing_literals,
    plugin_as_library,
    stable_features,
    unconditional_recursion,
    unknown_lints,
    unused,
    unused_allocation,
    unused_attributes,
    unused_comparisons,
    unused_features,
    unused_parens,
    while_true
)]
#![warn(
    trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    unused_results
)]
#![allow(
    box_pointers,
    missing_copy_implementations,
    missing_debug_implementations,
    variant_size_differences
)]
#![cfg_attr(
    feature = "cargo-clippy",
    deny(
        clippy::all,
        clippy::unicode_not_nfc,
        clippy::wrong_pub_self_convention,
        clippy::option_unwrap_used
    )
)]
#![cfg_attr(
    feature = "cargo-clippy",
    allow(clippy::implicit_hasher, clippy::too_many_arguments, clippy::use_debug)
)]

extern crate config_file_handler;
#[macro_use]
extern crate ffi_utils;
extern crate futures;
#[macro_use]
extern crate log;
extern crate lru_cache;
extern crate maidsafe_utilities;
extern crate routing;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate rust_sodium;
#[macro_use]
extern crate safe_core;
extern crate tiny_keccak;
extern crate tokio_core;
#[macro_use]
extern crate unwrap;
#[cfg(any(test, feature = "testing"))]
extern crate rand;

/// FFI routines.
pub mod ffi;

pub use ffi::apps::*;
pub use ffi::ipc::*;
pub use ffi::logging::*;
pub use ffi::*;

mod access_container;
mod app_auth;
mod app_container;
mod client;
mod config;
mod errors;
mod ipc;
mod revocation;
mod std_dirs;

/// Provides utilities to test the authenticator functionality.
#[cfg(any(test, feature = "testing"))]
#[macro_use]
pub mod test_utils;
#[cfg(test)]
mod tests;

pub use self::errors::AuthError;
pub use client::AuthClient;

use futures::stream::Stream;
use futures::sync::mpsc;
use futures::Future;
use maidsafe_utilities::thread::{self, Joiner};
#[cfg(feature = "use-mock-routing")]
use safe_core::MockRouting;
use safe_core::{event_loop, CoreMsg, CoreMsgTx, FutureExt, NetworkEvent, NetworkTx};
use std::sync::mpsc::sync_channel;
use std::sync::Mutex;
use tokio_core::reactor::{Core, Handle};

/// Future type specialised with `AuthError` as an error type.
pub type AuthFuture<T> = Future<Item = T, Error = AuthError>;
/// Transmitter of AuthClient messages.
pub type AuthMsgTx = CoreMsgTx<AuthClient, ()>;

macro_rules! try_tx {
    ($result:expr, $tx:ident) => {
        match $result {
            Ok(res) => res,
            Err(e) => {
                return unwrap!($tx.send(Err((None, AuthError::from(e)))));
            }
        }
    };
}

/// Authenticator instance.
pub struct Authenticator {
    /// Channel to communicate with the core event loop.
    pub core_tx: Mutex<AuthMsgTx>,
    _core_joiner: Joiner,
}

impl Authenticator {
    /// Send a message to the authenticator event loop.
    pub fn send<F>(&self, f: F) -> Result<(), AuthError>
    where
        F: FnOnce(&AuthClient) -> Option<Box<Future<Item = (), Error = ()>>> + Send + 'static,
    {
        let msg = CoreMsg::new(|client, _| f(client));
        let core_tx = unwrap!(self.core_tx.lock());
        core_tx.unbounded_send(msg).map_err(AuthError::from)
    }

    /// Create a new account.
    pub fn create_acc<S, N>(
        locator: S,
        password: S,
        invitation: S,
        disconnect_notifier: N,
    ) -> Result<Self, AuthError>
    where
        N: FnMut() + Send + 'static,
        S: Into<String>,
    {
        let locator = locator.into();
        let password = password.into();
        let invitation = invitation.into();

        Self::create_acc_impl(
            move |el_h, core_tx, net_tx| {
                AuthClient::registered(&locator, &password, &invitation, el_h, core_tx, net_tx)
            },
            disconnect_notifier,
        )
    }

    /// Create a new account.
    fn create_acc_impl<F: 'static + Send, N>(
        create_client_fn: F,
        mut disconnect_notifier: N,
    ) -> Result<Self, AuthError>
    where
        N: FnMut() + Send + 'static,
        F: FnOnce(Handle, AuthMsgTx, NetworkTx) -> Result<AuthClient, AuthError>,
    {
        let (tx, rx) = sync_channel(0);

        let joiner = thread::named("Core Event Loop", move || {
            let el = try_tx!(Core::new(), tx);
            let el_h = el.handle();

            let (core_tx, core_rx) = mpsc::unbounded();
            let core_tx2 = core_tx.clone();
            let (net_tx, net_rx) = mpsc::unbounded::<NetworkEvent>();

            let net_obs_fut = net_rx
                .then(move |net_event| {
                    if let Ok(NetworkEvent::Disconnected) = net_event {
                        disconnect_notifier();
                    }
                    ok!(())
                })
                .for_each(|_| Ok(()));
            el_h.spawn(net_obs_fut);

            let client = try_tx!(create_client_fn(el_h, core_tx.clone(), net_tx), tx);

            unwrap!(core_tx.unbounded_send(CoreMsg::new(move |client, &()| {
                std_dirs::create(client)
                    .map_err(|error| AuthError::AccountContainersCreation(error.to_string()))
                    .then(move |res| {
                        match res {
                            Ok(_) => unwrap!(tx.send(Ok(core_tx2))),
                            Err(error) => unwrap!(tx.send(Err((Some(core_tx2), error)))),
                        }

                        Ok(())
                    })
                    .into_box()
                    .into()
            })));

            event_loop::run(el, &client, &(), core_rx);
        });

        let core_tx = match rx.recv()? {
            Ok(core_tx) => core_tx,
            Err((None, e)) => return Err(e),
            Err((Some(core_tx), e)) => {
                // Make sure to shut down the event loop
                core_tx.unbounded_send(CoreMsg::build_terminator())?;
                return Err(e);
            }
        };

        Ok(Authenticator {
            core_tx: Mutex::new(core_tx),
            _core_joiner: joiner,
        })
    }

    /// Log in to an existing account
    pub fn login<S, N>(locator: S, password: S, disconnect_notifier: N) -> Result<Self, AuthError>
    where
        S: Into<String>,
        N: FnMut() + Send + 'static,
    {
        let locator = locator.into();
        let password = password.into();

        Self::login_impl(
            move |el_h, core_tx, net_tx| {
                AuthClient::login(&locator, &password, el_h, core_tx, net_tx)
            },
            disconnect_notifier,
        )
    }

    /// Log in to an existing account.
    pub fn login_impl<F: Send + 'static, N>(
        create_client_fn: F,
        mut disconnect_notifier: N,
    ) -> Result<Self, AuthError>
    where
        F: FnOnce(Handle, AuthMsgTx, NetworkTx) -> Result<AuthClient, AuthError>,
        N: FnMut() + Send + 'static,
    {
        let (tx, rx) = sync_channel(0);

        let joiner = thread::named("Core Event Loop", move || {
            let el = try_tx!(Core::new(), tx);
            let el_h = el.handle();

            let (core_tx, core_rx) = mpsc::unbounded();
            let (net_tx, net_rx) = mpsc::unbounded::<NetworkEvent>();
            let core_tx_clone = core_tx.clone();

            let net_obs_fut = net_rx
                .then(move |net_event| {
                    if let Ok(NetworkEvent::Disconnected) = net_event {
                        disconnect_notifier();
                    }
                    ok!(())
                })
                .for_each(|_| Ok(()));
            el_h.spawn(net_obs_fut);

            let client = try_tx!(create_client_fn(el_h, core_tx_clone, net_tx), tx);

            if !client.std_dirs_created() {
                // Standard directories haven't been created during
                // the user account registration - retry it again.
                let tx2 = tx.clone();
                let core_tx2 = core_tx.clone();
                let core_tx3 = core_tx.clone();

                unwrap!(core_tx.unbounded_send(CoreMsg::new(move |client, &()| {
                    std_dirs::create(client)
                        .map(move |()| {
                            unwrap!(tx.send(Ok(core_tx2)));
                        })
                        .map_err(move |e| {
                            unwrap!(tx2.send(Err((Some(core_tx3), e))));
                        })
                        .into_box()
                        .into()
                })));
            } else {
                unwrap!(tx.send(Ok(core_tx)));
            }

            event_loop::run(el, &client, &(), core_rx);
        });

        let core_tx = match rx.recv()? {
            Ok(core_tx) => core_tx,
            Err((None, e)) => return Err(e),
            Err((Some(core_tx), e)) => {
                // Make sure to shut down the event loop
                core_tx.unbounded_send(CoreMsg::build_terminator())?;
                return Err(e);
            }
        };

        Ok(Authenticator {
            core_tx: Mutex::new(core_tx),
            _core_joiner: joiner,
        })
    }
}

#[cfg(any(test, feature = "testing"))]
impl Authenticator {
    /// Create a new account with given seed.
    pub fn create_acc_with_seed<S, N>(seed: S, disconnect_notifier: N) -> Result<Self, AuthError>
    where
        S: Into<String>,
        N: FnMut() + Send + 'static,
    {
        let seed = seed.into();
        Self::login_impl(
            move |el_h, core_tx, net_tx| {
                AuthClient::registered_with_seed(&seed, el_h, core_tx, net_tx)
            },
            disconnect_notifier,
        )
    }

    /// Login to an existing account using the same seed that was used during account creation.
    pub fn login_with_seed<S, N>(seed: S, disconnect_notifier: N) -> Result<Self, AuthError>
    where
        S: Into<String>,
        N: FnMut() + Send + 'static,
    {
        let seed = seed.into();
        Self::login_impl(
            move |el_h, core_tx, net_tx| AuthClient::login_with_seed(&seed, el_h, core_tx, net_tx),
            disconnect_notifier,
        )
    }
}

#[cfg(feature = "use-mock-routing")]
impl Authenticator {
    #[allow(unused)]
    fn create_acc_with_hook<F, S, N>(
        locator: S,
        password: S,
        invitation: S,
        disconnect_notifier: N,
        routing_wrapper_fn: F,
    ) -> Result<Self, AuthError>
    where
        N: FnMut() + Send + 'static,
        F: Fn(MockRouting) -> MockRouting + Send + 'static,
        S: Into<String>,
    {
        let locator = locator.into();
        let password = password.into();
        let invitation = invitation.into();

        Self::create_acc_impl(
            move |el_h, core_tx_clone, net_tx| {
                AuthClient::registered_with_hook(
                    &locator,
                    &password,
                    &invitation,
                    el_h,
                    core_tx_clone,
                    net_tx,
                    routing_wrapper_fn,
                )
            },
            disconnect_notifier,
        )
    }

    #[allow(unused)]
    fn login_with_hook<F, S, N>(
        locator: S,
        password: S,
        disconnect_notifier: N,
        routing_wrapper_fn: F,
    ) -> Result<Self, AuthError>
    where
        S: Into<String>,
        F: Fn(MockRouting) -> MockRouting + Send + 'static,
        N: FnMut() + Send + 'static,
    {
        let locator = locator.into();
        let password = password.into();

        Self::login_impl(
            move |el_h, core_tx, net_tx| {
                AuthClient::login_with_hook(
                    &locator,
                    &password,
                    el_h,
                    core_tx,
                    net_tx,
                    routing_wrapper_fn,
                )
            },
            disconnect_notifier,
        )
    }
}

impl Drop for Authenticator {
    fn drop(&mut self) {
        debug!("Authenticator is now being dropped.");

        let core_tx = unwrap!(self.core_tx.lock());
        let msg = CoreMsg::build_terminator();

        if let Err(e) = core_tx.unbounded_send(msg) {
            info!("Unexpected error in drop: {:?}", e);
        }
    }
}
