// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net
// Commercial License, version 1.0 or later, or (2) The General Public License
// (GPL), version 3, depending on which licence you accepted on initial access
// to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project
// generally, you agree to be bound by the terms of the MaidSafe Contributor
// Agreement, version 1.0.
// This, along with the Licenses can be found in the root directory of this
// project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network
// Software distributed under the GPL Licence is distributed on an "AS IS"
// BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
//
// Please review the Licences for the specific language governing permissions
// and limitations relating to use of the SAFE Network Software.

//! SAFE App

#![doc(html_logo_url =
           "https://raw.githubusercontent.com/maidsafe/QA/master/Images/maidsafe_logo.png",
       html_favicon_url = "http://maidsafe.net/img/favicon.ico",
       html_root_url = "http://maidsafe.github.io/safe_app")]

// For explanation of lint checks, run `rustc -W help` or see
// https://github.com/maidsafe/QA/blob/master/Documentation/Rust%20Lint%20Checks.md
#![forbid(exceeding_bitshifts, mutable_transmutes, no_mangle_const_items,
          unknown_crate_types, warnings)]
#![deny(bad_style, deprecated, improper_ctypes, missing_docs,
        non_shorthand_field_patterns, overflowing_literals, plugin_as_library,
        private_no_mangle_fns, private_no_mangle_statics, stable_features,
        unconditional_recursion, unknown_lints, unsafe_code, unused,
        unused_allocation, unused_attributes, unused_comparisons, unused_features,
        unused_parens, while_true)]
#![warn(trivial_casts, trivial_numeric_casts, unused_extern_crates, unused_import_braces,
        unused_qualifications, unused_results)]
#![allow(box_pointers, fat_ptr_transmutes, missing_copy_implementations,
         missing_debug_implementations, variant_size_differences)]

#![cfg_attr(feature="cargo-clippy", deny(clippy, unicode_not_nfc, wrong_pub_self_convention,
                                         option_unwrap_used))]
#![cfg_attr(feature="cargo-clippy", allow(use_debug, too_many_arguments))]

#[macro_use]
extern crate ffi_utils;
extern crate futures;
#[macro_use]
extern crate log;
extern crate lru_cache;
extern crate maidsafe_utilities;
#[cfg(test)]
extern crate rand;
extern crate routing;
extern crate rustc_serialize;
extern crate rust_sodium;
#[cfg(any(test, feature="testing"))]
extern crate safe_authenticator;
#[macro_use]
extern crate safe_core;
extern crate self_encryption;
extern crate tokio_core;
#[macro_use]
extern crate unwrap;

pub mod ffi;
pub mod object_cache;

mod errors;
/// Utility functions to test apps functionality
#[cfg(any(test, feature="testing"))]
pub mod test_utils;

pub use self::errors::*;
use self::object_cache::ObjectCache;
use futures::{Future, future};
use futures::stream::Stream;
use futures::sync::mpsc as futures_mpsc;
use maidsafe_utilities::serialisation::deserialise;
use maidsafe_utilities::thread::{self, Joiner};
use rust_sodium::crypto::secretbox;
use safe_core::{Client, ClientKeys, CoreMsg, CoreMsgTx, FutureExt, MDataInfo, NetworkEvent,
                NetworkTx, event_loop, utils};
use safe_core::ipc::{AccessContInfo, AppKeys, AuthGranted, Permission};
use safe_core::ipc::resp::access_container_enc_key;
use std::cell::RefCell;
use std::collections::{BTreeSet, HashMap};
use std::rc::Rc;
use std::sync::Mutex;
use std::sync::mpsc as std_mpsc;
#[cfg(feature="testing")]
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
    /// TODO: add a `BootstrapConfig` argument to this function and
    /// figure out what to pass to it.
    pub fn unregistered<N>(network_observer: N) -> Result<Self, AppError>
        where N: FnMut(Result<NetworkEvent, AppError>) + Send + 'static
    {
        Self::new(network_observer, |el_h, core_tx, net_tx| {
            let client = Client::unregistered(el_h, core_tx, net_tx)?;
            let context = AppContext::unregistered();
            Ok((client, context))
        })
    }

    /// Create registered app.
    pub fn registered<N>(app_id: String,
                         auth_granted: AuthGranted,
                         network_observer: N)
                         -> Result<Self, AppError>
        where N: FnMut(Result<NetworkEvent, AppError>) + Send + 'static
    {
        let AuthGranted {
            app_keys: AppKeys { owner_key, enc_key, enc_pk, enc_sk, sign_pk, sign_sk },
            access_container,
            bootstrap_config,
        } = auth_granted;

        let client_keys = ClientKeys {
            sign_pk: sign_pk,
            sign_sk: sign_sk,
            enc_pk: enc_pk,
            enc_sk: enc_sk,
        };

        Self::new(network_observer, move |el_h, core_tx, net_tx| {
            let client = Client::from_keys(client_keys,
                                           owner_key,
                                           el_h,
                                           core_tx,
                                           net_tx,
                                           bootstrap_config)?;
            let context = AppContext::registered(app_id, enc_key, access_container);
            Ok((client, context))
        })
    }

    fn new<N, F>(mut network_observer: N, setup: F) -> Result<Self, AppError>
        where N: FnMut(Result<NetworkEvent, AppError>) + Send + 'static,
              F: FnOnce(Handle, CoreMsgTx<AppContext>, NetworkTx)
                        -> Result<(Client, AppContext), AppError> + Send + 'static
    {
        let (tx, rx) = std_mpsc::sync_channel(0);

        let joiner = thread::named("App Event Loop", move || {
            let el = try_tx!(Core::new(), tx);
            let el_h = el.handle();

            let (core_tx, core_rx) = futures_mpsc::unbounded();
            let (net_tx, net_rx) = futures_mpsc::unbounded();

            el_h.spawn(net_rx.map(move |event| network_observer(Ok(event))).for_each(|_| Ok(())));

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
        where F: FnOnce(&Client, &AppContext) -> Option<Box<Future<Item=(), Error=()>>>
                 + Send + 'static
    {
        let msg = CoreMsg::new(f);
        let core_tx = unwrap!(self.core_tx.lock());
        core_tx.send(msg).map_err(AppError::from)
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
        if let Err(err) = core_tx.send(msg) {
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
    sym_enc_key: secretbox::Key,
    access_container_info: AccessContInfo,
    access_info: RefCell<HashMap<String, (MDataInfo, BTreeSet<Permission>)>>,
}

impl AppContext {
    fn unregistered() -> Self {
        AppContext::Unregistered(Rc::new(Unregistered { object_cache: ObjectCache::new() }))
    }

    fn registered(app_id: String,
                  sym_enc_key: secretbox::Key,
                  access_container_info: AccessContInfo)
                  -> Self {
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
    pub fn sym_enc_key(&self) -> Result<&secretbox::Key, AppError> {
        Ok(&self.as_registered()?.sym_enc_key)
    }

    /// Refresh access info by fetching it from the network.
    pub fn refresh_access_info(&self, client: &Client) -> Box<AppFuture<()>> {
        let reg = fry!(self.as_registered()).clone();
        refresh_access_info(reg, client)
    }

    /// Fetch a list of container names that this app has access to
    pub fn get_container_names(&self, client: &Client) -> Box<AppFuture<BTreeSet<String>>> {
        let reg = fry!(self.as_registered()).clone();

        fetch_access_info(reg.clone(), client)
            .map(move |_| {
                     let access_info = reg.access_info.borrow();
                     access_info.keys().cloned().collect()
                 })
            .into_box()
    }

    /// Fetch mdata_info for the given container name.
    pub fn get_container_mdata_info<T: Into<String>>(&self,
                                                     client: &Client,
                                                     name: T)
                                                     -> Box<AppFuture<MDataInfo>> {
        let reg = fry!(self.as_registered()).clone();
        let name = name.into();

        fetch_access_info(reg.clone(), client)
            .and_then(move |_| {
                          let access_info = reg.access_info.borrow();
                          access_info.get(&name)
                              .map(|&(ref mdata_info, _)| mdata_info.clone())
                              .ok_or(AppError::NoSuchContainer)
                      })
            .into_box()
    }

    /// Check the given permission for the given directory.
    pub fn is_permitted<T: Into<String>>(&self,
                                         client: &Client,
                                         name: T,
                                         permission: Permission)
                                         -> Box<AppFuture<bool>> {
        let reg = fry!(self.as_registered()).clone();
        let name = name.into();

        fetch_access_info(reg.clone(), client)
            .and_then(move |_| {
                          let access_info = reg.access_info.borrow();
                          access_info.get(&name)
                              .map(|&(_, ref permissions)| permissions.contains(&permission))
                              .ok_or(AppError::NoSuchContainer)
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

#[cfg_attr(rustfmt, rustfmt_skip)]
fn refresh_access_info(context: Rc<Registered>, client: &Client) -> Box<AppFuture<()>> {
    let entry_key = fry!(access_container_enc_key(&context.app_id,
                                                  &context.sym_enc_key,
                                                  &context.access_container_info.nonce));

    client.get_mdata_value(context.access_container_info.id,
                           context.access_container_info.tag,
                           entry_key)
        .map_err(AppError::from)
        .and_then(move |value| {
            let encoded = utils::symmetric_decrypt(&value.content, &context.sym_enc_key)?;
            let decoded = deserialise(&encoded)?;

            *context.access_info.borrow_mut() = decoded;

            Ok(())
        })
        .into_box()
}

fn fetch_access_info(context: Rc<Registered>, client: &Client) -> Box<AppFuture<()>> {
    if context.access_info.borrow().is_empty() {
        refresh_access_info(context, client)
    } else {
        future::ok(()).into_box()
    }
}

#[cfg(test)]
mod tests {
    use futures::Future;
    use safe_core::ipc::Permission;
    use std::collections::HashMap;
    use test_utils::{create_app_with_access, run};

    #[test]
    fn refresh_access_info() {
        // Shared container
        let mut container_permissions = HashMap::new();
        let _ =
            container_permissions.insert("_videos".to_string(),
                                         btree_set![Permission::Read, Permission::Insert]);

        let app = create_app_with_access(container_permissions.clone());

        run(&app, move |client, context| {
            let reg = unwrap!(context.as_registered()).clone();
            assert!(reg.access_info.borrow().is_empty());

            context.refresh_access_info(client).then(move |result| {
                unwrap!(result);
                let access_info = reg.access_info.borrow();
                assert_eq!(unwrap!(access_info.get("_videos")).1,
                           *unwrap!(container_permissions.get("_videos")));

                Ok(())
            })
        });
    }

    #[test]
    fn get_container_mdata_info() {
        // Shared container
        let cont_name = "_videos".to_string();

        let mut container_permissions = HashMap::new();
        let _ = container_permissions.insert(cont_name.clone(), btree_set![Permission::Read]);

        let app = create_app_with_access(container_permissions);

        run(&app, move |client, context| {
            context.get_container_mdata_info(client, cont_name).then(move |res| {
                                                                         let _info = unwrap!(res);
                                                                         Ok(())
                                                                     })
        });
    }

    #[test]
    fn get_container_names() {
        let mut container_permissions = HashMap::new();
        let _ = container_permissions.insert("_videos".to_string(), btree_set![Permission::Read]);
        let _ = container_permissions.insert("_downloads".to_string(),
                                             btree_set![Permission::Read]);

        let app = create_app_with_access(container_permissions);

        run(&app, move |client, context| {
            context.get_container_names(client).then(move |res| {
                let info = unwrap!(res);
                assert!(info.contains(&"_videos".to_string()));
                assert!(info.contains(&"_downloads".to_string()));
                assert_eq!(info.len(), 3); // third item is the app container
                Ok(())
            })
        });
    }

    #[test]
    fn is_permitted() {
        // Shared container
        let cont_name = "_videos".to_string();

        let mut container_permissions = HashMap::new();
        let _ = container_permissions.insert(cont_name.clone(), btree_set![Permission::Read]);

        let app = create_app_with_access(container_permissions);

        run(&app, move |client, context| {
            let f1 = context.is_permitted(client, cont_name.clone(), Permission::Read)
                .then(move |res| {
                          assert!(unwrap!(res));
                          Ok(())
                      });

            let f2 = context.is_permitted(client, cont_name.clone(), Permission::Insert)
                .then(move |res| {
                          assert!(!unwrap!(res));
                          Ok(())
                      });

            f1.join(f2).map(|_| ())
        });

    }
}
