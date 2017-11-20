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
use ffi_utils::{FFI_RESULT_OK, FfiResult, catch_unwind_cb, from_c_str};
use futures::{Future, IntoFuture};
use safe_authenticator::test_utils as authenticator;
use safe_core::{Client, FutureExt, utils};
use safe_core::ffi::ipc::req::ContainerPermissions as FfiContainerPermissions;
use safe_core::ipc::AppExchangeInfo;
use safe_core::ipc::req::{AuthReq, ContainerPermissions, containers_from_repr_c};
use std::collections::HashMap;
use std::os::raw::{c_char, c_void};
use std::sync::mpsc;

/// Generates an `AppExchangeInfo` structure for a mock application.
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

// Create registered app with optional app id and access info.
fn create_app_with_id_or_access(
    app_id: Option<String>,
    access_info: Option<HashMap<String, ContainerPermissions>>,
) -> App {
    let auth = authenticator::create_account_and_login();

    let mut app_info = gen_app_exchange_info();
    if let Some(app_id) = app_id {
        app_info.id = app_id;
    }
    let app_id = app_info.id.clone();

    let (app_container, containers) = match access_info {
        Some(access_info) => (true, access_info),
        None => (false, HashMap::new()),
    };

    let auth_granted = unwrap!(authenticator::register_app(
        &auth,
        &AuthReq {
            app: app_info,
            app_container,
            containers,
        },
    ));

    unwrap!(App::registered(app_id, auth_granted, || ()))
}

/// Create registered app with a random id.
pub fn create_app() -> App {
    create_app_with_id_or_access(None, None)
}

/// Create registered app with a random id and grant it access to the specified containers.
pub fn create_app_with_access(access_info: HashMap<String, ContainerPermissions>) -> App {
    create_app_with_id_or_access(None, Some(access_info))
}

/// Creates a random app instance for testing.
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn test_create_app(
    app_id: *const c_char,
    user_data: *mut c_void,
    o_cb: extern "C" fn(user_data: *mut c_void,
                        result: *const FfiResult,
                        app: *mut App),
) {
    catch_unwind_cb(user_data, o_cb, || -> Result<(), AppError> {
        let app_id = from_c_str(app_id)?;
        let app = create_app_with_id_or_access(Some(app_id), None);
        o_cb(user_data, FFI_RESULT_OK, Box::into_raw(Box::new(app)));
        Ok(())
    })
}

/// Create a random app instance for testing, with access to containers.
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn test_create_app_with_access(
    app_id: *const c_char,
    access_info: *const FfiContainerPermissions,
    access_info_len: usize,
    user_data: *mut c_void,
    o_cb: extern "C" fn(user_data: *mut c_void,
                        result: *const FfiResult,
                        o_app: *mut App),
) {
    catch_unwind_cb(user_data, o_cb, || -> Result<(), AppError> {
        let app_id = from_c_str(app_id)?;
        let containers = containers_from_repr_c(access_info, access_info_len)?;
        let app = create_app_with_id_or_access(Some(app_id), Some(containers));
        o_cb(user_data, FFI_RESULT_OK, Box::into_raw(Box::new(app)));
        Ok(())
    })
}
