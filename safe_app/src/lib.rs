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
#![allow(
    // Our unsafe FFI functions are missing safety documentation. It is probably not necessary for
    // us to provide this for every single function as that would be repetitive and verbose.
    clippy::missing_safety_doc,
)]

#[macro_use]
extern crate ffi_utils;
#[macro_use]
extern crate log;
#[cfg(test)]
extern crate rand;
#[macro_use]
extern crate safe_core;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate unwrap;

// Re-export functions used in FFI so that they are accessible through the Rust API.

pub use safe_core::ipc::AppKeys;
pub use safe_core::{
    app_container_name, immutable_data, ipc, mdata_info, nfs, utils, Client, ClientKeys, CoreError,
    CoreFuture, FutureExt, MDataInfo, DIR_TAG, MAIDSAFE_TAG,
};
pub use safe_nd::PubImmutableData;

// Export FFI interface.

pub use crate::ffi::access_container::*;
pub use crate::ffi::cipher_opt::*;
pub use crate::ffi::crypto::*;
pub use crate::ffi::errors::codes::*;
pub use crate::ffi::immutable_data::*;
pub use crate::ffi::ipc::*;
pub use crate::ffi::logging::*;
pub use crate::ffi::mdata_info::*;
pub use crate::ffi::mutable_data::entries::*;
pub use crate::ffi::mutable_data::entry_actions::*;
pub use crate::ffi::mutable_data::metadata::*;
pub use crate::ffi::mutable_data::permissions::*;
pub use crate::ffi::mutable_data::*;
pub use crate::ffi::nfs::*;
pub use crate::ffi::object_cache::*;
#[cfg(any(test, feature = "testing"))]
pub use crate::ffi::test_utils::*;
pub use crate::ffi::*;

// Export public app objects.

pub use crate::errors::AppError;
pub use client::AppClient;

pub mod cipher_opt;
pub mod ffi;
pub mod object_cache;
pub mod permissions;

/// Utility functions to test apps functionality.
#[cfg(any(test, feature = "testing"))]
pub mod test_utils;

mod client;
pub mod errors;
#[cfg(test)]
mod tests;

use self::object_cache::ObjectCache;
use crate::ffi::errors::{Error as FfiError, Result as FfiResult};
use bincode::deserialize;
use futures::stream::Stream;
use futures::sync::mpsc as futures_mpsc;
use futures::{future, Future, IntoFuture};
use safe_core::crypto::shared_secretbox;
use safe_core::ipc::resp::{access_container_enc_key, AccessContainerEntry};
use safe_core::ipc::{AccessContInfo, AuthGranted, BootstrapConfig};
#[cfg(feature = "mock-network")]
use safe_core::ConnectionManager;
use safe_core::{event_loop, CoreMsg, CoreMsgTx, NetworkEvent, NetworkTx};
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::mpsc;
use std::sync::Mutex;
use std::thread::{self, JoinHandle};
use tokio::runtime::current_thread::{Handle, Runtime};

macro_rules! try_tx {
    ($result:expr, $tx:ident) => {
        match $result {
            Ok(res) => res,
            Err(e) => return unwrap!($tx.send(Err(AppError::from(e)))),
        }
    };
}

type AppFuture<T> = dyn Future<Item = T, Error = AppError>;
type AppMsgTx = CoreMsgTx<AppClient, AppContext>;

/// Handle to an application instance.
pub struct App {
    core_tx: Mutex<AppMsgTx>,
    _core_joiner: JoinHandle<()>,
}

impl App {
    /// Send a message to app's event loop.
    pub fn send<F>(&self, f: F) -> FfiResult<()>
    where
        F: FnOnce(&AppClient, &AppContext) -> Option<Box<dyn Future<Item = (), Error = ()>>>
            + Send
            + 'static,
    {
        let msg = CoreMsg::new(f);
        let core_tx = unwrap!(self.core_tx.lock());
        core_tx.unbounded_send(msg).map_err(FfiError::from)
    }

    /// Create unregistered app.
    pub fn unregistered<N>(
        disconnect_notifier: N,
        config: Option<BootstrapConfig>,
    ) -> Result<Self, AppError>
    where
        N: FnMut() + Send + 'static,
    {
        Self::new(disconnect_notifier, move |el_h, core_tx, net_tx| {
            let client = AppClient::unregistered(el_h, core_tx, net_tx, config)?;
            let context = AppContext::unregistered();
            Ok((client, context))
        })
    }

    /// Create registered app.
    pub fn registered<N>(
        app_id: String,
        auth_granted: AuthGranted,
        disconnect_notifier: N,
    ) -> Result<Self, AppError>
    where
        N: FnMut() + Send + 'static,
    {
        Self::registered_impl(app_id, auth_granted, disconnect_notifier)
    }

    fn registered_impl<N>(
        app_id: String,
        auth_granted: AuthGranted,
        disconnect_notifier: N,
    ) -> Result<Self, AppError>
    where
        N: FnMut() + Send + 'static,
    {
        let AuthGranted {
            app_keys,
            access_container_info,
            bootstrap_config,
            ..
        } = auth_granted;
        let enc_key = app_keys.enc_key.clone();
        let owner_key = *app_keys.app_full_id.public_id().owner().public_key();

        Self::new(disconnect_notifier, move |el_h, core_tx, net_tx| {
            let client =
                AppClient::from_keys(app_keys, owner_key, el_h, core_tx, net_tx, bootstrap_config)?;
            let context = AppContext::registered(app_id, enc_key, access_container_info);
            Ok((client, context))
        })
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

        Self::new(disconnect_notifier, move |el_h, core_tx, net_tx| {
            let client = AppClient::from_keys_with_hook(
                app_keys,
                owner_key,
                el_h,
                core_tx,
                net_tx,
                bootstrap_config,
                connection_manager_wrapper_fn,
            )?;
            let context = AppContext::registered(app_id, enc_key, access_container_info);
            Ok((client, context))
        })
    }

    fn new<N, F>(mut disconnect_notifier: N, setup: F) -> Result<Self, AppError>
    where
        N: FnMut() + Send + 'static,
        F: FnOnce(Handle, AppMsgTx, NetworkTx) -> Result<(AppClient, AppContext), AppError>
            + Send
            + 'static,
    {
        let (tx, rx) = mpsc::sync_channel(0);

        let joiner = thread::Builder::new()
            .name(String::from("App Event Loop"))
            .spawn(move || {
                let mut el = try_tx!(Runtime::new(), tx);
                let el_h = el.handle();

                let (core_tx, core_rx) = futures_mpsc::unbounded();
                let (net_tx, net_rx) = futures_mpsc::unbounded();

                let _ = el.spawn(
                    net_rx
                        .map(move |event| {
                            if let NetworkEvent::Disconnected = event {
                                disconnect_notifier()
                            }
                        })
                        .for_each(|_| Ok(())),
                );

                let core_tx_clone = core_tx.clone();

                let (client, context) = try_tx!(setup(el_h, core_tx_clone, net_tx), tx);
                unwrap!(tx.send(Ok(core_tx)));

                event_loop::run(el, &client, &context, core_rx);
            })
            .map_err(AppError::from)?;

        let core_tx = rx.recv()??;

        Ok(Self {
            core_tx: Mutex::new(core_tx),
            _core_joiner: joiner,
        })
    }
}

impl Drop for App {
    fn drop(&mut self) {
        let core_tx = match self.core_tx.lock() {
            Ok(core_tx) => core_tx,
            Err(err) => {
                info!("Unexpected error in drop: {:?}", err);
                return;
            }
        };

        let msg = CoreMsg::build_terminator();
        if let Err(err) = core_tx.unbounded_send(msg) {
            info!("Unexpected error in drop: {:?}", err);
        }
    }
}

/// Application context (data associated with the app).
#[derive(Clone)]
pub enum AppContext {
    /// Context of unregistered app.
    Unregistered(Rc<Unregistered>),
    /// Context of registered app.
    Registered(Rc<Registered>),
}

#[allow(missing_docs)]
pub struct Unregistered {
    object_cache: ObjectCache,
}

#[allow(missing_docs)]
pub struct Registered {
    object_cache: ObjectCache,
    app_id: String,
    sym_enc_key: shared_secretbox::Key,
    access_container_info: AccessContInfo,
    access_info: RefCell<AccessContainerEntry>,
}

impl AppContext {
    fn unregistered() -> Self {
        Self::Unregistered(Rc::new(Unregistered {
            object_cache: ObjectCache::new(),
        }))
    }

    fn registered(
        app_id: String,
        sym_enc_key: shared_secretbox::Key,
        access_container_info: AccessContInfo,
    ) -> Self {
        Self::Registered(Rc::new(Registered {
            object_cache: ObjectCache::new(),
            app_id,
            sym_enc_key,
            access_container_info,
            access_info: RefCell::new(HashMap::new()),
        }))
    }

    /// Object cache
    pub fn object_cache(&self) -> &ObjectCache {
        match *self {
            Self::Unregistered(ref context) => &context.object_cache,
            Self::Registered(ref context) => &context.object_cache,
        }
    }

    /// Symmetric encryption/decryption key.
    pub fn sym_enc_key(&self) -> Result<&shared_secretbox::Key, AppError> {
        Ok(&self.as_registered()?.sym_enc_key)
    }

    /// Refresh access info by fetching it from the network.
    pub fn refresh_access_info(&self, client: &AppClient) -> Box<AppFuture<()>> {
        let reg = Rc::clone(fry!(self.as_registered()));
        refresh_access_info(reg, client)
    }

    /// Fetch a list of containers that this app has access to
    pub fn get_access_info(&self, client: &AppClient) -> Box<AppFuture<AccessContainerEntry>> {
        let reg = Rc::clone(fry!(self.as_registered()));

        fetch_access_info(Rc::clone(&reg), client)
            .map(move |_| {
                let access_info = reg.access_info.borrow();
                access_info.clone()
            })
            .into_box()
    }

    fn as_registered(&self) -> Result<&Rc<Registered>, AppError> {
        match *self {
            Self::Registered(ref a) => Ok(a),
            Self::Unregistered(_) => Err(AppError::OperationForbidden),
        }
    }
}

/// Helper to execute a future by blocking the thread until the result arrives.
pub fn run<F, I, T>(app: &App, f: F) -> FfiResult<T>
where
    F: FnOnce(&AppClient, &AppContext) -> I + Send + 'static,
    I: IntoFuture<Item = T, Error = AppError> + 'static,
    T: Send + 'static,
{
    let (tx, rx) = mpsc::channel();
    app.send(move |client, context| {
        let future = f(client, context)
            .into_future()
            .then(move |result| {
                unwrap!(tx.send(result));
                Ok(())
            })
            .into_box();
        Some(future)
    })?;
    rx.recv()?.map_err(crate::ffi::errors::Error::from)
}

fn refresh_access_info(context: Rc<Registered>, client: &AppClient) -> Box<AppFuture<()>> {
    let entry_key = fry!(access_container_enc_key(
        &context.app_id,
        &context.sym_enc_key,
        &context.access_container_info.nonce,
    ));

    client
        .get_seq_mdata_value(
            context.access_container_info.id,
            context.access_container_info.tag,
            entry_key,
        )
        .map_err(AppError::from)
        .and_then(move |value| {
            let encoded = utils::symmetric_decrypt(&value.data, &context.sym_enc_key)?;
            let decoded = deserialize(&encoded)?;

            *context.access_info.borrow_mut() = decoded;

            Ok(())
        })
        .into_box()
}

fn fetch_access_info(context: Rc<Registered>, client: &AppClient) -> Box<AppFuture<()>> {
    if context.access_info.borrow().is_empty() {
        refresh_access_info(context, client)
    } else {
        future::ok(()).into_box()
    }
}
