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

//! SAFE Authenticator

#![doc(html_logo_url =
           "https://raw.githubusercontent.com/maidsafe/QA/master/Images/maidsafe_logo.png",
       html_favicon_url = "http://maidsafe.net/img/favicon.ico",
       html_root_url = "http://maidsafe.github.io/safe_authenticator")]

// For explanation of lint checks, run `rustc -W help` or see
// https://github.com/maidsafe/QA/blob/master/Documentation/Rust%20Lint%20Checks.md
#![forbid(exceeding_bitshifts, mutable_transmutes, no_mangle_const_items,
          unknown_crate_types, warnings)]
#![deny(bad_style, deprecated, improper_ctypes, missing_docs,
        non_shorthand_field_patterns, overflowing_literals, plugin_as_library,
        private_no_mangle_fns, private_no_mangle_statics, stable_features,
        unconditional_recursion, unknown_lints, unused,
        unused_allocation, unused_attributes, unused_comparisons, unused_features,
        unused_parens, while_true)]
#![warn(trivial_casts, trivial_numeric_casts, unused_extern_crates, unused_import_braces,
        unused_qualifications, unused_results)]
#![allow(box_pointers, fat_ptr_transmutes, missing_copy_implementations,
         missing_debug_implementations, variant_size_differences)]

#![cfg_attr(feature="clippy", feature(plugin))]
#![cfg_attr(feature="clippy", plugin(clippy))]
#![cfg_attr(feature="clippy", deny(clippy, unicode_not_nfc, wrong_pub_self_convention,
                                   option_unwrap_used))]
#![cfg_attr(feature="clippy", allow(use_debug, too_many_arguments))]

#[macro_use]
extern crate ffi_utils;
extern crate futures;
#[macro_use]
extern crate log;
extern crate maidsafe_utilities;
extern crate routing;
extern crate rustc_serialize;
extern crate rust_sodium;
#[macro_use]
extern crate safe_core;
extern crate tokio_core;
#[macro_use]
extern crate unwrap;

/// FFI routines
pub mod ffi;
/// Authenticator communication with apps
pub mod ipc;
/// Public ID routines
pub mod public_id;

mod errors;
mod access_container;

#[cfg(test)]
mod test_utils;
#[cfg(test)]
mod tests;

use futures::Future;
use futures::stream::Stream;
use futures::sync::mpsc;
use maidsafe_utilities::serialisation::serialise;
use maidsafe_utilities::thread::{self, Joiner};
use routing::EntryActions;
use safe_core::{Client, CoreMsg, CoreMsgTx, FutureExt, MDataInfo, NetworkEvent, event_loop,
                mdata_info};
use safe_core::ipc::Permission;
use safe_core::nfs::{create_dir, create_std_dirs};
pub use self::errors::AuthError;
use std::collections::{BTreeSet, HashMap};
use std::sync::Mutex;
use std::sync::mpsc::sync_channel;
use tokio_core::reactor::Core;

/// Future type specialised with `AuthError` as an error type
pub type AuthFuture<T> = Future<Item = T, Error = AuthError>;

/// Represents an entry for a single app in the access container
pub type AccessContainerEntry = HashMap<String, (MDataInfo, BTreeSet<Permission>)>;

macro_rules! try_tx {
    ($result:expr, $tx:ident) => {
        match $result {
            Ok(res) => res,
            Err(e) => { return unwrap!($tx.send(Err(AuthError::from(e)))); }
        }
    }
}

/// Authenticator instance
pub struct Authenticator {
    /// Channel to communicate with the core event loop
    pub core_tx: Mutex<CoreMsgTx<()>>,
    _core_joiner: Joiner,
}

impl Authenticator {
    /// Send a message to the authenticator event loop
    pub fn send<F>(&self, f: F) -> Result<(), AuthError>
        where F: FnOnce(&Client) -> Option<Box<Future<Item = (), Error = ()>>> + Send + 'static
    {
        let msg = CoreMsg::new(|client, _| f(client));
        let core_tx = unwrap!(self.core_tx.lock());
        core_tx.send(msg).map_err(AuthError::from)
    }

    /// Create a new account
    pub fn create_acc<S, NetObs>(locator: S,
                                 password: S,
                                 mut network_observer: NetObs)
                                 -> Result<Self, AuthError>
        where S: Into<String>,
              NetObs: FnMut(Result<NetworkEvent, ()>) + Send + 'static
    {
        let (tx, rx) = sync_channel(0);

        let locator = locator.into();
        let password = password.into();

        let joiner = thread::named("Core Event Loop", move || {
            let el = try_tx!(Core::new(), tx);
            let el_h = el.handle();

            let (core_tx, core_rx) = mpsc::unbounded();
            let (net_tx, net_rx) = mpsc::unbounded::<NetworkEvent>();
            let core_tx_clone = core_tx.clone();

            let net_obs_fut = net_rx.then(move |net_event| Ok(network_observer(net_event)))
                .for_each(|_| Ok(()));
            el_h.spawn(net_obs_fut);

            let client =
                try_tx!(Client::registered(&locator, &password, el_h, core_tx_clone, net_tx),
                        tx);

            let tx2 = tx.clone();
            let core_tx2 = core_tx.clone();
            unwrap!(core_tx.send(CoreMsg::new(move |client, &()| {
                let client = client.clone();
                create_std_dirs(client.clone()).map_err(AuthError::from).and_then(move |()| {
                    create_dir(&client, false).map_err(AuthError::from).and_then(move |dir| {
                        let config_dir = unwrap!(client.config_root_dir());

                        let actions = EntryActions::new()
                            .ins(b"authenticator-config".to_vec(), Vec::new(), 0)
                            .ins(b"access-container".to_vec(), serialise(&dir)?, 0)
                            .into();
                        let actions = mdata_info::encrypt_entry_actions(&config_dir, &actions)?;

                        Ok(client.mutate_mdata_entries(config_dir.name,
                                                       config_dir.type_tag,
                                                       actions))
                    }).and_then(move |fut| {
                        fut.map_err(AuthError::from)
                    }).map(move |()| {
                        unwrap!(tx.send(Ok(core_tx2)));
                    })
                }).map_err(move |e| {
                    unwrap!(tx2.send(Err(AuthError::from(e))));
                }).into_box().into()
            })));

            event_loop::run(el, client, (), core_rx);
        });

        let core_tx = rx.recv()??;

        Ok(Authenticator {
            core_tx: Mutex::new(core_tx),
            _core_joiner: joiner,
        })
    }

    /// Log in to an existing account
    pub fn login<S, NetObs>(locator: S,
                            password: S,
                            mut network_observer: NetObs)
                            -> Result<Self, AuthError>
        where S: Into<String>,
              NetObs: FnMut(Result<NetworkEvent, ()>) + Send + 'static
    {
        let (tx, rx) = sync_channel(0);

        let locator = locator.into();
        let password = password.into();

        let joiner = thread::named("Core Event Loop", move || {
            let el = try_tx!(Core::new(), tx);
            let el_h = el.handle();

            let (core_tx, core_rx) = mpsc::unbounded();
            let (net_tx, net_rx) = mpsc::unbounded::<NetworkEvent>();
            let core_tx_clone = core_tx.clone();

            let net_obs_fut = net_rx.then(move |net_event| Ok(network_observer(net_event)))
                .for_each(|_| Ok(()));
            el_h.spawn(net_obs_fut);

            let client = try_tx!(Client::login(&locator, &password, el_h, core_tx_clone, net_tx),
                                 tx);

            unwrap!(tx.send(Ok(core_tx)));

            event_loop::run(el, client, (), core_rx);
        });

        let core_tx = rx.recv()??;

        Ok(Authenticator {
            core_tx: Mutex::new(core_tx),
            _core_joiner: joiner,
        })
    }
}

impl Drop for Authenticator {
    fn drop(&mut self) {
        debug!("Authenticator is now being dropped.");

        let core_tx = unwrap!(self.core_tx.lock());
        let msg = CoreMsg::build_terminator();

        if let Err(e) = core_tx.send(msg) {
            info!("Unexpected error in drop: {:?}", e);
        }
    }
}
