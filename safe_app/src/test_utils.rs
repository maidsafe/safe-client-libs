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

use super::{App, AppContext};
use super::errors::AppError;
use ffi_utils::catch_unwind_error_code;
use futures::{Future, IntoFuture};
use safe_authenticator::test_utils as authenticator;
use safe_core::{Client, FutureExt, utils};
use safe_core::ipc::{AppExchangeInfo, Permission};
use safe_core::ipc::req::{AuthReq, containers_from_repr_c, ffi};
use std::collections::{BTreeSet, HashMap};
use std::sync::mpsc;

/// Generates an `AppExchangeInfo` structure for a mock application
pub fn gen_app_exchange_info() -> AppExchangeInfo {
    AppExchangeInfo {
        id: unwrap!(utils::generate_random_string(10)),
        scope: None,
        name: unwrap!(utils::generate_random_string(10)),
        vendor: unwrap!(utils::generate_random_string(10)),
    }
}

/// Run the given closure inside the app's event loop. The return value of
/// the closure is returned immediately.
pub fn run_now<F, R>(app: &App, f: F) -> R
where
    F: FnOnce(&Client<AppContext>, &AppContext) -> R + Send + 'static,
    R: Send + 'static,
{
    let (tx, rx) = mpsc::channel();

    unwrap!(app.send(move |client, context| {
        unwrap!(tx.send(f(client, context)));
        None
    }));

    unwrap!(rx.recv())
}

/// Run the given closure inside the app event loop. The closure should
/// return a future which will then be driven to completion and its result
/// returned.
pub fn run<F, I, T>(app: &App, f: F) -> T
where
    F: FnOnce(&Client<AppContext>, &AppContext) -> I + Send + 'static,
    I: IntoFuture<Item = T, Error = AppError> + 'static,
    T: Send + 'static,
{
    let (tx, rx) = mpsc::channel();

    unwrap!(app.send(move |client, app| {
        let future = f(client, app)
            .into_future()
            .then(move |result| {
                unwrap!(tx.send(result));
                Ok(())
            })
            .into_box();

        Some(future)
    }));

    unwrap!(unwrap!(rx.recv()))
}

/// Create registered app.
pub fn create_app() -> App {
    let auth = authenticator::create_account_and_login();

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

    unwrap!(App::registered(app_id, auth_granted, |_network_event| ()))
}

/// Create app and grant it access to the specified containers.
pub fn create_app_with_access(access_info: HashMap<String, BTreeSet<Permission>>) -> App {
    let auth = authenticator::create_account_and_login();

    let app_info = gen_app_exchange_info();
    let app_id = app_info.id.clone();

    let auth_granted = unwrap!(authenticator::register_app(
        &auth,
        &AuthReq {
            app: app_info,
            app_container: true,
            containers: access_info,
        },
    ));

    unwrap!(App::registered(app_id, auth_granted, |_network_event| ()))
}

/// Creates a random app instance for testing
#[no_mangle]
#[allow(unsafe_code)]
#[cfg_attr(feature = "cargo-clippy", allow(not_unsafe_ptr_arg_deref))]
pub extern "C" fn test_create_app(o_app: *mut *mut App) -> i32 {
    catch_unwind_error_code(|| -> Result<(), AppError> {
        let app = create_app();
        unsafe {
            *o_app = Box::into_raw(Box::new(app));
        }
        Ok(())
    })
}

/// Create a random app instance for testing, with access to containers
#[no_mangle]
#[allow(unsafe_code)]
#[cfg_attr(feature = "cargo-clippy", allow(not_unsafe_ptr_arg_deref))]
pub extern "C" fn test_create_app_with_access(
    access_info: *const ffi::ContainerPermissions,
    access_info_len: usize,
    o_app: *mut *mut App,
) -> i32 {
    catch_unwind_error_code(|| -> Result<(), AppError> {
        let containers = unsafe { containers_from_repr_c(access_info, access_info_len)? };
        let app = create_app_with_access(containers);
        unsafe {
            *o_app = Box::into_raw(Box::new(app));
        }
        Ok(())
    })
}
