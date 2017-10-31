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

use super::AccessContainerEntry;
use Authenticator;
use access_container;
use app_auth;
use config;
use errors::AuthError;
use futures::{Future, IntoFuture};
use futures::future;
use ipc::decode_ipc_msg;
use rand::{self, Rng};
use revocation;
use routing::User;
use rust_sodium::crypto::sign;
use safe_core::{Client, FutureExt, MDataInfo};
#[cfg(feature = "use-mock-routing")]
use safe_core::MockRouting;
use safe_core::ipc::{self, AppExchangeInfo, AuthGranted, AuthReq, IpcMsg, IpcReq};
use safe_core::ipc::req::{ContainerPermissions, container_perms_into_permission_set};
use safe_core::nfs::{File, Mode, file_helper};
use std::collections::HashMap;
use std::sync::mpsc;

#[macro_export]
macro_rules! assert_match {
    ($e:expr, $p:pat) => {
        match $e {
            $p => (),
            x => panic!("Unexpected {:?} (expecting {})", x, stringify!($p)),
        }
    }
}

/// Creates a new random account for authenticator. Returns the `Authenticator`
/// instance and the locator and password strings.
pub fn create_authenticator() -> (Authenticator, String, String) {
    let mut rng = rand::thread_rng();

    let locator: String = rng.gen_ascii_chars().take(10).collect();
    let password: String = rng.gen_ascii_chars().take(10).collect();
    let invitation: String = rng.gen_ascii_chars().take(10).collect();

    let auth = unwrap!(Authenticator::create_acc(
        locator.clone(),
        password.clone(),
        invitation,
        |_| (),
    ));

    (auth, locator, password)
}

/// Create a random authenticator and login using the same credentials.
pub fn create_account_and_login() -> Authenticator {
    let (_, locator, password) = create_authenticator();
    unwrap!(Authenticator::login(locator, password, |_| ()))
}

/// Revoke an app, returning an error on failure
pub fn try_revoke(authenticator: &Authenticator, app_id: &str) -> Result<(), AuthError> {
    let app_id = app_id.to_string();

    try_run(authenticator, move |client| {
        revocation::revoke_app(client, &app_id)
    })
}

/// Revoke an app, panicking on failure
pub fn revoke(authenticator: &Authenticator, app_id: &str) {
    match try_revoke(authenticator, app_id) {
        Ok(_) => (),
        x => panic!("Unexpected {:?}", x),
    }
}

/// Create a random authenticator and login using the same credentials.
/// Attaches a hook to the Routing to override responses.
#[cfg(all(any(test, feature = "testing"), feature = "use-mock-routing"))]
pub fn create_account_and_login_with_hook<F>(hook: F) -> Authenticator
where
    F: Fn(MockRouting) -> MockRouting + Send + 'static,
{
    let (_, locator, password) = create_authenticator();
    unwrap!(Authenticator::login_with_hook(
        locator,
        password,
        |_| (),
        hook,
    ))
}

/// Returns `AppInfo` iff the app is listed in the authenticator config.
pub fn get_app_or_err(
    authenticator: &Authenticator,
    app_id: &str,
) -> Result<config::AppInfo, AuthError> {
    let app_id = app_id.to_string();

    try_run(
        authenticator,
        move |client| config::get_app(client, &app_id),
    )
}

/// Registers a mock application using a given `AuthReq`.
pub fn register_app(
    authenticator: &Authenticator,
    auth_req: &AuthReq,
) -> Result<AuthGranted, AuthError> {
    let req_id = ipc::gen_req_id();
    let msg = IpcMsg::Req {
        req_id: req_id,
        req: IpcReq::Auth(auth_req.clone()),
    };

    // Invoke `decode_ipc_msg` and expect to get AuthReq back.
    let ipc_req = run(authenticator, move |client| decode_ipc_msg(client, msg));
    match ipc_req {
        Ok(IpcMsg::Req { req: IpcReq::Auth(_), .. }) => (),
        x => return Err(AuthError::Unexpected(format!("Unexpected {:?}", x))),
    }

    let auth_req = auth_req.clone();
    try_run(authenticator, move |client| {
        app_auth::authenticate(client, auth_req)
    })
}

/// Register random app. Returns the id of the app and the `AuthGranted` struct.
pub fn register_rand_app(
    authenticator: &Authenticator,
    app_container: bool,
    containers_req: HashMap<String, ContainerPermissions>,
) -> Result<(String, AuthGranted), AuthError> {
    let auth_req = AuthReq {
        app: rand_app(),
        app_container: app_container,
        containers: containers_req,
    };

    let auth_granted = register_app(authenticator, &auth_req)?;
    let app_id = auth_req.app.id;

    Ok((app_id, auth_granted))
}

/// Run the given closure inside the event loop of the authenticator. The closure
/// should return a future which will then be driven to completion and its result
/// returned.
pub fn try_run<F, I, T>(authenticator: &Authenticator, f: F) -> Result<T, AuthError>
where
    F: FnOnce(&Client<()>) -> I + Send + 'static,
    I: IntoFuture<Item = T, Error = AuthError> + 'static,
    T: Send + 'static,
{
    let (tx, rx) = mpsc::channel();

    unwrap!(authenticator.send(move |client| {
        let future = f(client)
            .into_future()
            .then(move |result| {
                unwrap!(tx.send(result));
                Ok(())
            })
            .into_box();

        Some(future)
    }));

    unwrap!(rx.recv())
}

/// Like `try_run`, but expects success.
pub fn run<F, I, T>(authenticator: &Authenticator, f: F) -> T
where
    F: FnOnce(&Client<()>) -> I + Send + 'static,
    I: IntoFuture<Item = T, Error = AuthError> + 'static,
    T: Send + 'static,
{
    unwrap!(try_run(authenticator, f))
}

/// Creates a random `AppExchangeInfo`
pub fn rand_app() -> AppExchangeInfo {
    let mut rng = rand::thread_rng();

    AppExchangeInfo {
        id: rng.gen_ascii_chars().take(10).collect(),
        scope: None,
        name: rng.gen_ascii_chars().take(10).collect(),
        vendor: rng.gen_ascii_chars().take(10).collect(),
    }
}

/// Create file in the given container, with the given name and content.
pub fn create_file<T: Into<String>>(
    authenticator: &Authenticator,
    container_info: MDataInfo,
    name: T,
    content: Vec<u8>,
) -> Result<(), AuthError> {
    let name = name.into();
    try_run(authenticator, |client| {
        let c2 = client.clone();

        file_helper::write(
            client.clone(),
            File::new(vec![]),
            Mode::Overwrite,
            container_info.enc_key().cloned(),
        ).then(move |res| {
            let writer = unwrap!(res);
            writer.write(&content).and_then(move |_| writer.close())
        })
            .then(move |file| {
                file_helper::insert(c2, container_info, name, &unwrap!(file))
            })
            .map_err(From::from)
    })
}

/// Fetches file from the given directory by given name
pub fn fetch_file<T: Into<String>>(
    authenticator: &Authenticator,
    container_info: MDataInfo,
    name: T,
) -> Result<File, AuthError> {
    let name = name.into();
    try_run(authenticator, |client| {
        file_helper::fetch(client.clone(), container_info, name)
            .map(|(_, file)| file)
            .map_err(From::from)
    })
}

/// Fetch the access container entry for the app.
pub fn access_container<S: Into<String>>(
    authenticator: &Authenticator,
    app_id: S,
    auth_granted: AuthGranted,
) -> AccessContainerEntry {
    unwrap!(
        try_access_container(authenticator, app_id, auth_granted),
        "Access container entry is empty"
    )
}

/// Fetch the access container entry for the app.
pub fn try_access_container<S: Into<String>>(
    authenticator: &Authenticator,
    app_id: S,
    auth_granted: AuthGranted,
) -> Option<AccessContainerEntry> {
    let app_keys = auth_granted.app_keys;
    let app_id = app_id.into();
    run(authenticator, move |client| {
        access_container::fetch_entry(client, &app_id, app_keys).map(move |(_, entry)| entry)
    })
}

/// Get the container `MDataInfo` from the authenticator entry in the access container.
pub fn get_container_from_authenticator_entry(
    authenticator: &Authenticator,
    container: &str,
) -> Result<MDataInfo, AuthError> {
    let container = String::from(container);

    try_run(authenticator, move |client| {
        access_container::fetch_authenticator_entry(client).and_then(move |(_, mut ac_entries)| {
            ac_entries.remove(&container).ok_or_else(|| {
                AuthError::from(format!("'{}' not found in the access container", container))
            })
        })
    })
}

/// Check that the given permission set is contained in the access container
pub fn compare_access_container_entries(
    authenticator: &Authenticator,
    app_sign_pk: sign::PublicKey,
    mut access_container: AccessContainerEntry,
    expected: HashMap<String, ContainerPermissions>,
) {
    let results = run(authenticator, move |client| {
        let mut reqs = Vec::new();
        let user = User::Key(app_sign_pk);

        for (container, expected_perms) in expected {
            // Check the requested permissions in the access container.
            let expected_perm_set = container_perms_into_permission_set(&expected_perms);
            let (md_info, perms) = unwrap!(
                access_container.remove(&container),
                "No '{}' in access container {:?}",
                container,
                access_container
            );
            assert_eq!(perms, expected_perms);

            let fut = client
                .list_mdata_user_permissions(md_info.name, md_info.type_tag, user)
                .map(move |perms| (perms, expected_perm_set));

            reqs.push(fut);
        }

        future::join_all(reqs).map_err(AuthError::from)
    });

    // Check the permission on the the mutable data for each of the above directories.
    for (perms, expected) in results {
        assert_eq!(perms, expected);
    }
}
