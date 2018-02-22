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

use super::{App, AppContext, AppError};
use futures::{Future, IntoFuture};
use safe_authenticator::AuthError;
use safe_authenticator::test_utils as authenticator;
use safe_core::{Client, FutureExt, utils};
use safe_core::ipc::AppExchangeInfo;
use safe_core::ipc::req::{AuthReq as NativeAuthReq, ContainerPermissions};
use std::collections::HashMap;
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

/// Create a random app
pub fn create_app() -> App {
    unwrap!(create_app_by_req(&create_random_auth_req()))
}

/// Create a random app given an app authorisation request
pub fn create_app_by_req(auth_req: &NativeAuthReq) -> Result<App, AppError> {
    let auth = authenticator::create_account_and_login();
    let auth_granted = authenticator::register_app(&auth, auth_req).map_err(
        |error| {
            match error {
                AuthError::NoSuchContainer(name) => AppError::NoSuchContainer(name),
                _ => AppError::Unexpected(format!("{}", error)),
            }
        },
    )?;
    App::registered(auth_req.app.id.clone(), auth_granted, || ())
}

/// Create an app authorisation request with optional app id and access info.
pub fn create_auth_req(
    app_id: Option<String>,
    access_info: Option<HashMap<String, ContainerPermissions>>,
) -> NativeAuthReq {
    let mut app_info = gen_app_exchange_info();
    if let Some(app_id) = app_id {
        app_info.id = app_id;
    }

    let (app_container, containers) = match access_info {
        Some(access_info) => (true, access_info),
        None => (false, HashMap::default()),
    };

    NativeAuthReq {
        app: app_info,
        app_container,
        containers,
    }
}

/// Create registered app with a random id.
pub fn create_random_auth_req() -> NativeAuthReq {
    create_auth_req(None, None)
}

/// Create registered app with a random id and grant it access to the specified containers.
pub fn create_auth_req_with_access(
    access_info: HashMap<String, ContainerPermissions>,
) -> NativeAuthReq {
    create_auth_req(None, Some(access_info))
}
