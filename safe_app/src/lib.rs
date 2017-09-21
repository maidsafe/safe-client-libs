// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement.  This, along with the Licenses can be
// found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

//! SAFE App
#![doc(html_logo_url = "https://raw.githubusercontent.com/maidsafe/QA/master/Images/
maidsafe_logo.png",
      html_favicon_url = "http://maidsafe.net/img/favicon.ico",
      html_root_url = "http://maidsafe.github.io/safe_app")]
// For explanation of lint checks, run `rustc -W help` or see
// https://github.com/maidsafe/QA/blob/master/Documentation/Rust%20Lint%20Checks.md
#![forbid(exceeding_bitshifts, mutable_transmutes, no_mangle_const_items, unknown_crate_types,
         warnings)]
#![deny(bad_style, deprecated, improper_ctypes, missing_docs, non_shorthand_field_patterns,
       overflowing_literals, plugin_as_library, private_no_mangle_fns, private_no_mangle_statics,
       stable_features, unconditional_recursion, unknown_lints, unsafe_code, unused,
       unused_allocation, unused_attributes, unused_comparisons, unused_features, unused_parens,
       while_true)]
#![warn(trivial_casts, trivial_numeric_casts, unused_extern_crates, unused_import_braces,
       unused_qualifications, unused_results)]
#![allow(box_pointers, fat_ptr_transmutes, missing_copy_implementations,
        missing_debug_implementations, variant_size_differences)]
#![cfg_attr(feature = "cargo-clippy",
           deny(clippy, unicode_not_nfc, wrong_pub_self_convention, option_unwrap_used))]
#![cfg_attr(feature = "cargo-clippy", allow(use_debug, too_many_arguments))]

extern crate config_file_handler;
#[macro_use]
extern crate ffi_utils;
extern crate futures;
#[macro_use]
extern crate log;
extern crate maidsafe_utilities;
#[cfg(test)]
extern crate rand;
extern crate routing;
extern crate rust_sodium;
#[cfg(any(test, feature = "testing"))]
extern crate safe_authenticator;
#[macro_use]
extern crate safe_core;
extern crate self_encryption;
#[macro_use]
extern crate serde_derive;
extern crate tiny_keccak;
extern crate tokio_core;
#[macro_use]
extern crate unwrap;

pub mod ffi;

pub use ffi::*;
pub use ffi::access_container::*;
pub use ffi::cipher_opt::*;
pub use ffi::crypto::*;
pub use ffi::immutable_data::*;
pub use ffi::ipc::*;
pub use ffi::logging::*;
pub use ffi::mdata_info::*;
pub use ffi::mutable_data::*;
pub use ffi::mutable_data::entries::*;
pub use ffi::mutable_data::entry_actions::*;
pub use ffi::mutable_data::metadata::*;
pub use ffi::mutable_data::permissions::*;
pub use ffi::nfs::*;

pub mod object_cache;
mod errors;
/// Utility functions to test apps functionality
#[cfg(any(test, feature = "testing"))]
pub mod test_utils;

pub use self::errors::*;
use self::object_cache::ObjectCache;
use futures::{Future, future};
use futures::stream::Stream;
use futures::sync::mpsc as futures_mpsc;
use maidsafe_utilities::serialisation::deserialise;
use maidsafe_utilities::thread::{self, Joiner};
use safe_core::{Client, ClientKeys, CoreMsg, CoreMsgTx, FutureExt, NetworkEvent, NetworkTx,
                event_loop, utils};
#[cfg(feature = "use-mock-routing")]
use safe_core::MockRouting as Routing;
use safe_core::crypto::shared_secretbox;
use safe_core::ipc::{AccessContInfo, AppKeys, AuthGranted, BootstrapConfig};
use safe_core::ipc::resp::{AccessContainerEntry, access_container_enc_key};
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::Mutex;
use std::sync::mpsc as std_mpsc;
#[cfg(feature = "testing")]
pub use test_utils::{test_create_app, test_create_app_with_access};
use tokio_core::reactor::{Core, Handle};

macro_rules! try_tx {
    ($result:expr, $tx:ident) => {
        match $result {
            Ok(res) => res,
            Err(e) => return unwrap!($tx.send(Err(AppError::from(e)))),
        }
    }
}

type AppFuture<T> = Future<Item = T, Error = AppError>;

/// Handle to an application instance.
pub struct App {
    core_tx: Mutex<CoreMsgTx<AppContext>>,
    _core_joiner: Joiner,
}

impl App {
    /// Create unregistered app.
    pub fn unregistered<N>(
        network_observer: N,
        config: Option<BootstrapConfig>,
    ) -> Result<Self, AppError>
    where
        N: FnMut(Result<NetworkEvent, AppError>) + Send + 'static,
    {
        Self::new(network_observer, |el_h, core_tx, net_tx| {
            let client = Client::unregistered(el_h, core_tx, net_tx, config)?;
            let context = AppContext::unregistered();
            Ok((client, context))
        })
    }

    /// Create registered app.
    pub fn registered<N>(
        app_id: String,
        auth_granted: AuthGranted,
        network_observer: N,
    ) -> Result<Self, AppError>
    where
        N: FnMut(Result<NetworkEvent, AppError>) + Send + 'static,
    {
        Self::registered_impl(app_id, auth_granted, network_observer)
    }

    fn registered_impl<N>(
        app_id: String,
        auth_granted: AuthGranted,
        network_observer: N,
    ) -> Result<Self, AppError>
    where
        N: FnMut(Result<NetworkEvent, AppError>) + Send + 'static,
    {
        let AuthGranted {
            app_keys: AppKeys {
                owner_key,
                enc_key,
                enc_pk,
                enc_sk,
                sign_pk,
                sign_sk,
            },
            access_container_info,
            bootstrap_config,
            ..
        } = auth_granted;

        let client_keys = ClientKeys {
            sign_pk,
            sign_sk,
            enc_pk,
            enc_sk,
            enc_key: enc_key.clone(),
        };

        Self::new(network_observer, move |el_h, core_tx, net_tx| {
            let client = Client::from_keys(
                client_keys,
                owner_key,
                el_h,
                core_tx,
                net_tx,
                bootstrap_config,
            )?;
            let context = AppContext::registered(app_id, enc_key, access_container_info);
            Ok((client, context))
        })
    }


    /// Allows customising the mock Routing client before registering a new account
    #[cfg(feature = "use-mock-routing")]
    pub fn registered_with_hook<N, F>(
        app_id: String,
        auth_granted: AuthGranted,
        network_observer: N,
        routing_wrapper_fn: F,
    ) -> Result<Self, AppError>
    where
        N: FnMut(Result<NetworkEvent, AppError>) + Send + 'static,
        F: Fn(Routing) -> Routing + Send + 'static,
    {
        let AuthGranted {
            app_keys: AppKeys {
                owner_key,
                enc_key,
                enc_pk,
                enc_sk,
                sign_pk,
                sign_sk,
            },
            access_container_info,
            bootstrap_config,
            ..
        } = auth_granted;

        let client_keys = ClientKeys {
            sign_pk,
            sign_sk,
            enc_pk,
            enc_sk,
            enc_key: enc_key.clone(),
        };

        Self::new(network_observer, move |el_h, core_tx, net_tx| {
            let client = Client::from_keys_with_hook(
                client_keys,
                owner_key,
                el_h,
                core_tx,
                net_tx,
                bootstrap_config,
                routing_wrapper_fn,
            )?;
            let context = AppContext::registered(app_id, enc_key, access_container_info);
            Ok((client, context))
        })
    }

    fn new<N, F>(mut network_observer: N, setup: F) -> Result<Self, AppError>
    where
        N: FnMut(Result<NetworkEvent, AppError>) + Send + 'static,
        F: FnOnce(Handle, CoreMsgTx<AppContext>, NetworkTx)
               -> Result<(Client<AppContext>, AppContext), AppError>
            + Send
            + 'static,
    {
        let (tx, rx) = std_mpsc::sync_channel(0);

        let joiner = thread::named("App Event Loop", move || {
            let el = try_tx!(Core::new(), tx);
            let el_h = el.handle();

            let (core_tx, core_rx) = futures_mpsc::unbounded();
            let (net_tx, net_rx) = futures_mpsc::unbounded();

            el_h.spawn(
                net_rx
                    .map(move |event| network_observer(Ok(event)))
                    .for_each(|_| Ok(())),
            );

            let core_tx_clone = core_tx.clone();

            let (client, context) = try_tx!(setup(el_h, core_tx_clone, net_tx), tx);
            unwrap!(tx.send(Ok(core_tx)));

            event_loop::run(el, &client, &context, core_rx);
        });

        let core_tx = rx.recv()??;

        Ok(App {
            core_tx: Mutex::new(core_tx),
            _core_joiner: joiner,
        })
    }

    /// Send a message to app's event loop
    pub fn send<F>(&self, f: F) -> Result<(), AppError>
    where
        F: FnOnce(&Client<AppContext>, &AppContext) -> Option<Box<Future<Item = (), Error = ()>>>
            + Send
            + 'static,
    {
        let msg = CoreMsg::new(f);
        let core_tx = unwrap!(self.core_tx.lock());
        core_tx.unbounded_send(msg).map_err(AppError::from)
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
        AppContext::Unregistered(Rc::new(Unregistered { object_cache: ObjectCache::new() }))
    }

    fn registered(
        app_id: String,
        sym_enc_key: shared_secretbox::Key,
        access_container_info: AccessContInfo,
    ) -> Self {
        AppContext::Registered(Rc::new(Registered {
            object_cache: ObjectCache::new(),
            app_id: app_id,
            sym_enc_key: sym_enc_key,
            access_container_info: access_container_info,
            access_info: RefCell::new(HashMap::new()),
        }))
    }

    /// Object cache
    pub fn object_cache(&self) -> &ObjectCache {
        match *self {
            AppContext::Unregistered(ref context) => &context.object_cache,
            AppContext::Registered(ref context) => &context.object_cache,
        }
    }

    /// Symmetric encryption/decryption key.
    pub fn sym_enc_key(&self) -> Result<&shared_secretbox::Key, AppError> {
        Ok(&self.as_registered()?.sym_enc_key)
    }

    /// Refresh access info by fetching it from the network.
    pub fn refresh_access_info(&self, client: &Client<AppContext>) -> Box<AppFuture<()>> {
        let reg = fry!(self.as_registered()).clone();
        refresh_access_info(reg, client)
    }

    /// Fetch a list of containers that this app has access to
    pub fn get_access_info(
        &self,
        client: &Client<AppContext>,
    ) -> Box<AppFuture<AccessContainerEntry>> {
        let reg = fry!(self.as_registered()).clone();

        fetch_access_info(reg.clone(), client)
            .map(move |_| {
                let access_info = reg.access_info.borrow();
                access_info.clone()
            })
            .into_box()
    }

    fn as_registered(&self) -> Result<&Rc<Registered>, AppError> {
        match *self {
            AppContext::Registered(ref a) => Ok(a),
            AppContext::Unregistered(_) => Err(AppError::OperationForbidden),
        }
    }
}

fn refresh_access_info(context: Rc<Registered>, client: &Client<AppContext>) -> Box<AppFuture<()>> {
    let entry_key = fry!(access_container_enc_key(
        &context.app_id,
        &context.sym_enc_key,
        &context.access_container_info.nonce,
    ));

    client
        .get_mdata_value(
            context.access_container_info.id,
            context.access_container_info.tag,
            entry_key,
        )
        .map_err(AppError::from)
        .and_then(move |value| {
            let encoded = utils::symmetric_decrypt(&value.content, &context.sym_enc_key)?;
            let decoded = deserialise(&encoded)?;

            *context.access_info.borrow_mut() = decoded;

            Ok(())
        })
        .into_box()
}

fn fetch_access_info(context: Rc<Registered>, client: &Client<AppContext>) -> Box<AppFuture<()>> {
    if context.access_info.borrow().is_empty() {
        refresh_access_info(context, client)
    } else {
        future::ok(()).into_box()
    }
}

#[cfg(test)]
mod tests {
    use App;
    use futures::Future;
    #[cfg(feature = "use-mock-routing")]
    use routing::{ClientError, Request, Response};
    use safe_authenticator::Authenticator;
    use safe_authenticator::test_utils as authenticator;
    use safe_authenticator::test_utils::revoke;
    #[cfg(feature = "use-mock-routing")]
    use safe_core::MockRouting;
    use safe_core::ipc::Permission;
    use safe_core::ipc::req::AppExchangeInfo;
    use safe_core::ipc::req::AuthReq;
    use std::collections::HashMap;
    use test_utils::{create_app_with_access, run};
    use test_utils::gen_app_exchange_info;

    // Test refreshing access info by fetching it from the network.
    #[test]
    fn refresh_access_info() {
        // Shared container
        let mut container_permissions = HashMap::new();
        let _ = container_permissions.insert(
            "_videos".to_string(),
            btree_set![Permission::Read, Permission::Insert],
        );

        let app = create_app_with_access(container_permissions.clone());

        run(&app, move |client, context| {
            let reg = unwrap!(context.as_registered()).clone();
            assert!(reg.access_info.borrow().is_empty());

            context.refresh_access_info(client).then(move |result| {
                unwrap!(result);
                let access_info = reg.access_info.borrow();
                assert_eq!(
                    unwrap!(access_info.get("_videos")).1,
                    *unwrap!(container_permissions.get("_videos"))
                );

                Ok(())
            })
        });
    }

    // Test fetching containers that an app has access to.
    #[test]
    fn get_access_info() {
        let mut container_permissions = HashMap::new();
        let _ = container_permissions.insert("_videos".to_string(), btree_set![Permission::Read]);
        let _ =
            container_permissions.insert("_downloads".to_string(), btree_set![Permission::Insert]);

        let app = create_app_with_access(container_permissions);

        run(&app, move |client, context| {
            context.get_access_info(client).then(move |res| {
                let info = unwrap!(res);
                assert!(info.contains_key(&"_videos".to_string()));
                assert!(info.contains_key(&"_downloads".to_string()));
                assert_eq!(info.len(), 3); // third item is the app container

                let (ref _md_info, ref perms) = info["_videos"];
                assert_eq!(perms, &btree_set![Permission::Read]);

                let (ref _md_info, ref perms) = info["_downloads"];
                assert_eq!(perms, &btree_set![Permission::Insert]);

                Ok(())
            })
        });
    }

    // Make sure we can login to a registered app with low balance.
    #[cfg(feature = "use-mock-routing")]
    #[test]
    pub fn login_registered_with_low_balance() {
        // Register a hook prohibiting mutations and login
        let routing_hook = move |mut routing: MockRouting| -> MockRouting {
            routing.set_request_hook(move |req| {
                match *req {
                    Request::PutIData { msg_id, .. } => Some(Response::PutIData {
                        res: Err(ClientError::LowBalance),
                        msg_id,
                    }),
                    Request::PutMData { msg_id, .. } => Some(Response::PutMData {
                        res: Err(ClientError::LowBalance),
                        msg_id,
                    }),
                    Request::MutateMDataEntries { msg_id, .. } => {
                        Some(Response::MutateMDataEntries {
                            res: Err(ClientError::LowBalance),
                            msg_id,
                        })
                    }
                    Request::SetMDataUserPermissions { msg_id, .. } => {
                        Some(Response::SetMDataUserPermissions {
                            res: Err(ClientError::LowBalance),
                            msg_id,
                        })
                    }
                    Request::DelMDataUserPermissions { msg_id, .. } => {
                        Some(Response::DelMDataUserPermissions {
                            res: Err(ClientError::LowBalance),
                            msg_id,
                        })
                    }
                    Request::ChangeMDataOwner { msg_id, .. } => Some(Response::ChangeMDataOwner {
                        res: Err(ClientError::LowBalance),
                        msg_id,
                    }),
                    Request::InsAuthKey { msg_id, .. } => Some(Response::InsAuthKey {
                        res: Err(ClientError::LowBalance),
                        msg_id,
                    }),
                    Request::DelAuthKey { msg_id, .. } => Some(Response::DelAuthKey {
                        res: Err(ClientError::LowBalance),
                        msg_id,
                    }),
                    // Pass-through
                    _ => None,
                }
            });
            routing
        };

        // Login to the client
        let auth = authenticator::create_account_and_login();

        // Register and login to the app
        let app_info = gen_app_exchange_info();
        let app_id = app_info.id.clone();

        let auth_granted = unwrap!(authenticator::register_app(
            &auth,
            &AuthReq {
                app: app_info,
                app_container: false,
                containers: HashMap::new(),
            },
        ));

        let _app = unwrap!(App::registered_with_hook(
            app_id,
            auth_granted,
            |_network_event| (),
            routing_hook,
        ));
    }

    // Authorise an app with `app_container`.
    fn authorise_app(
        auth: &Authenticator,
        app_info: &AppExchangeInfo,
        app_id: &str,
        app_container: bool,
    ) -> App {
        let auth_granted = unwrap!(authenticator::register_app(
            auth,
            &AuthReq {
                app: app_info.clone(),
                app_container: app_container,
                containers: HashMap::new(),
            },
        ));

        unwrap!(App::registered(
            String::from(app_id),
            auth_granted,
            |_network_event| (),
        ))
    }

    // Get the number of containers for `app`
    fn num_containers(app: &App) -> usize {
        run(app, move |client, context| {
            context.get_access_info(client).then(move |res| {
                let info = unwrap!(res);
                Ok(info.len())
            })
        })
    }

    // Test app container creation under the following circumstances:
    // 1. An app is authorised for the first time with `app_container` set to `true`.
    // 2. If an app is authorised for the first time with `app_container` set to `false`,
    // then any subsequent authorisation with `app_container` set to `true` should trigger
    // the creation of the app's own container.
    // 3. Make sure that the app's own container is also created when it's re-authorised
    // with `app_container` set to `true` after it's been revoked.
    #[test]
    fn app_container_creation() {
        // Authorise an app for the first time with `app_container` set to `true`.
        let auth = authenticator::create_account_and_login();

        let app_info = gen_app_exchange_info();
        let app_id = app_info.id.clone();
        let app = authorise_app(&auth, &app_info, &app_id, true);

        assert_eq!(num_containers(&app), 1); // should only contain app container

        // Authorise a new app with `app_container` set to `false`.
        let auth = authenticator::create_account_and_login();

        let app_info = gen_app_exchange_info();
        let app_id = app_info.id.clone();
        let app = authorise_app(&auth, &app_info, &app_id, false);

        assert_eq!(num_containers(&app), 0); // should be empty

        // Re-authorise the app with `app_container` set to `true`.
        let app = authorise_app(&auth, &app_info, &app_id, true);

        assert_eq!(num_containers(&app), 1); // should only contain app container

        // Authorise a new app with `app_container` set to `false`.
        let auth = authenticator::create_account_and_login();

        let app_info = gen_app_exchange_info();
        let app_id = app_info.id.clone();
        let app = authorise_app(&auth, &app_info, &app_id, false);

        assert_eq!(num_containers(&app), 0); // should be empty

        // Revoke the app
        revoke(&auth, &app_id);

        // Re-authorise the app with `app_container` set to `true`.
        let app = authorise_app(&auth, &app_info, &app_id, true);

        assert_eq!(num_containers(&app), 1); // should only contain app container
    }
}
