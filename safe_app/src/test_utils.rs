// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use super::{App, AppError};
use safe_authenticator::test_utils as authenticator;
use safe_authenticator::AuthError;
use safe_core::ipc::req::{AuthReq as NativeAuthReq, ContainerPermissions};
use safe_core::ipc::AppExchangeInfo;
use safe_core::utils;
use std::collections::HashMap;

/// Generates an `AppExchangeInfo` structure for a mock application.
pub fn gen_app_exchange_info() -> AppExchangeInfo {
    AppExchangeInfo {
        id: unwrap!(utils::generate_random_string(10)),
        scope: None,
        name: unwrap!(utils::generate_random_string(10)),
        vendor: unwrap!(utils::generate_random_string(10)),
    }
}

/// Create a random app.
pub fn create_app() -> App {
    unwrap!(create_app_by_req(&create_random_auth_req()))
}

/// Create a random app given an app authorisation request.
pub fn create_app_by_req(auth_req: &NativeAuthReq) -> Result<App, AppError> {
    let auth = authenticator::create_account_and_login();
    let auth_granted =
        authenticator::register_app(&auth, auth_req).map_err(|error| match error {
            AuthError::NoSuchContainer(name) => AppError::NoSuchContainer(name),
            _ => AppError::Unexpected(format!("{}", error)),
        })?;
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

/// Create an app authorisation request with a random id.
pub fn create_random_auth_req() -> NativeAuthReq {
    create_auth_req(None, None)
}

/// Create an app authorisation request with a random id and grant it access to the specified
/// containers.
pub fn create_auth_req_with_access(
    access_info: HashMap<String, ContainerPermissions>,
) -> NativeAuthReq {
    create_auth_req(None, Some(access_info))
}
