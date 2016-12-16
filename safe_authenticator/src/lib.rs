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
       html_root_url = "http://maidsafe.github.io/safe_core")]

// For explanation of lint checks, run `rustc -W help` or see
// https://github.
// com/maidsafe/QA/blob/master/Documentation/Rust%20Lint%20Checks.md
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
/// Authenticator errors
mod errors;

use ffi_utils::{FfiString, OpaqueCtx, catch_unwind_error_code};
use futures::Future;
use futures::stream::Stream;
use futures::sync::mpsc::{self, SendError};
use maidsafe_utilities::serialisation::serialise;
use maidsafe_utilities::thread::{self, Joiner};
use routing::{EntryAction, Value};
use safe_core::{Client, CoreMsg, CoreMsgTx, FutureExt, MDataInfo, NetworkEvent, event_loop};
use safe_core::ipc::Permission;
use safe_core::nfs::{create_dir, create_std_dirs};
pub use self::errors::AuthError;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::os::raw::c_void;
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
    pub fn send<F>(&self, f: F) -> Result<(), SendError<CoreMsg<()>>>
        where F: FnOnce(&Client) -> Option<Box<Future<Item = (), Error = ()>>> + Send + 'static
    {
        let msg = CoreMsg::new(|client, _| f(client));
        let mut core_tx = unwrap!(self.core_tx.lock());
        core_tx.send(msg)
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

            let (mut core_tx, core_rx) = mpsc::unbounded();
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
                let cl2 = client.clone();
                create_std_dirs(client.clone()).map_err(AuthError::from).and_then(move |()| {
                    let cl3 = cl2.clone();
                    create_dir(&cl2, false).map_err(AuthError::from).and_then(move |dir| {
                        let config_dir = unwrap!(cl3.config_root_dir());
                        let mut actions = BTreeMap::new();
                        let encrypted_key
                            = config_dir.enc_entry_key(b"authenticator-config")?;
                        let _ = actions.insert(encrypted_key,
                                               EntryAction::Ins(Value {
                                                   content: vec![],
                                                   entry_version: 0,
                                               }));

                        let serialised_dir = serialise(&dir)?;
                        let encrypted_key = config_dir
                            .enc_entry_key(b"access-container")?;
                        let encrypted_value = config_dir.enc_entry_value(&serialised_dir)?;

                        let _ = actions.insert(encrypted_key,
                                               EntryAction::Ins(Value {
                                                   content: encrypted_value,
                                                   entry_version: 0,
                                               }));

                        Ok(cl3.mutate_mdata_entries(dir.name, dir.type_tag, actions))
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

        let mut core_tx = unwrap!(self.core_tx.lock());
        let msg = CoreMsg::build_terminator();

        if let Err(e) = core_tx.send(msg) {
            info!("Unexpected error in drop: {:?}", e);
        }
    }
}

/// Create a registered client. This or any one of the other companion
/// functions to get an authenticator instance must be called before initiating any
/// operation allowed by this module. `auth_handle` is a pointer to a pointer and must
/// point to a valid pointer not junk, else the consequences are undefined.
#[no_mangle]
pub unsafe extern "C" fn create_acc(account_locator: FfiString,
                                    account_password: FfiString,
                                    auth_handle: *mut *mut Authenticator,
                                    user_data: *mut c_void,
                                    o_network_obs_cb: unsafe extern "C" fn(*mut c_void, i32, i32))
                                    -> i32 {
    let user_data = OpaqueCtx(user_data);

    catch_unwind_error_code(|| -> Result<(), AuthError> {
        trace!("Authenticator - create a client account.");

        let acc_locator = account_locator.as_str()?;
        let acc_password = account_password.as_str()?;

        let authenticator =
            Authenticator::create_acc(acc_locator, acc_password, move |net_event| {
                let user_data: *mut c_void = user_data.into();

                match net_event {
                    Ok(event) => o_network_obs_cb(user_data, 0, event.into()),
                    Err(()) => o_network_obs_cb(user_data, -1, 0),
                }
            })?;

        *auth_handle = Box::into_raw(Box::new(authenticator));

        Ok(())
    })
}

/// Log into a registered account. This or any one of the other companion
/// functions to get an authenticator instance must be called before initiating
/// any operation allowed for authenticator. `auth_handle` is a pointer to a pointer
/// and must point to a valid pointer not junk, else the consequences are undefined.
#[no_mangle]
pub unsafe extern "C" fn login(account_locator: FfiString,
                               account_password: FfiString,
                               auth_handle: *mut *mut Authenticator,
                               user_data: *mut c_void,
                               o_network_obs_cb: unsafe extern "C" fn(*mut c_void, i32, i32))
                               -> i32 {
    let user_data = OpaqueCtx(user_data);

    catch_unwind_error_code(|| -> Result<(), AuthError> {
        trace!("Authenticator - log in a registererd client.");

        let acc_locator = account_locator.as_str()?;
        let acc_password = account_password.as_str()?;

        let authenticator = Authenticator::login(acc_locator, acc_password, move |net_event| {
            let user_data: *mut c_void = user_data.into();

            match net_event {
                Ok(event) => o_network_obs_cb(user_data, 0, event.into()),
                Err(()) => o_network_obs_cb(user_data, -1, 0),
            }
        })?;

        *auth_handle = Box::into_raw(Box::new(authenticator));

        Ok(())
    })
}

/// Discard and clean up the previously allocated authenticator instance.
/// Use this only if the authenticator is obtained from one of the auth
/// functions in this crate (`create_acc`, `login`, `create_unregistered`).
/// Using `auth` after a call to this functions is undefined behaviour.
#[no_mangle]
pub unsafe extern "C" fn authenticator_free(auth: *mut Authenticator) {
    let _ = Box::from_raw(auth);
}

#[cfg(test)]
mod tests {
    use ffi_utils::FfiString;
    use safe_core::utils;
    use std::os::raw::c_void;
    use std::ptr;
    use super::*;

    #[test]
    fn create_account_and_login() {
        let acc_locator = unwrap!(utils::generate_random_string(10));
        let acc_password = unwrap!(utils::generate_random_string(10));

        {
            let mut auth_h: *mut Authenticator = ptr::null_mut();

            unsafe {
                let auth_h_ptr = &mut auth_h;

                assert_eq!(create_acc(FfiString::from_str(&acc_locator),
                                      FfiString::from_str(&acc_password),
                                      auth_h_ptr,
                                      ptr::null_mut(),
                                      net_event_cb),
                           0);
            }

            assert!(!auth_h.is_null());

            unsafe { authenticator_free(auth_h) };
        }

        {
            let mut auth_h: *mut Authenticator = ptr::null_mut();

            unsafe {
                let auth_h_ptr = &mut auth_h;

                assert_eq!(login(FfiString::from_str(&acc_locator),
                                 FfiString::from_str(&acc_password),
                                 auth_h_ptr,
                                 ptr::null_mut(),
                                 net_event_cb),
                           0);
            }

            assert!(!auth_h.is_null());
            unsafe { authenticator_free(auth_h) };
        }

        unsafe extern "C" fn net_event_cb(_user_data: *mut c_void, err_code: i32, _event: i32) {
            assert_eq!(err_code, 0);
        }
    }
}
