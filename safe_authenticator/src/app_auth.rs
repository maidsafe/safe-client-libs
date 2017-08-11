// Copyright 2017 MaidSafe.net limited.
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

//! App authentication routines

use super::{AuthError, AuthFuture};
use access_container::{access_container, access_container_entry, put_access_container_entry};
use app_container;
use config::{self, AppInfo, Apps};
use futures::Future;
use ipc::update_container_perms;
use routing::ClientError;
use safe_core::{Client, CoreError, FutureExt, recovery};
use safe_core::ipc::req::AuthReq;
use safe_core::ipc::req::ffi::Permission;
use safe_core::ipc::resp::{AccessContInfo, AppKeys, AuthGranted};
use std::collections::{BTreeSet, HashMap};
use tiny_keccak::sha3_256;

/// Represents current app state
#[derive(Debug, Eq, PartialEq)]
pub enum AppState {
    /// Exists in the authenticator config, access container, and registered in MaidManagers
    Authenticated,
    /// Exists in the authenticator config but not in access container and MaidManagers
    Revoked,
    /// Doesn't exist in the authenticator config
    NotAuthenticated,
}

/// Returns a current app state (`Authenticated` if it has an entry
/// in the config file AND the access container, `Revoked` if it has
/// an entry in the config but not in the access container, and `NotAuthenticated`
/// if it's not registered anywhere).
pub fn app_state(client: &Client<()>, apps: &Apps, app_id: String) -> Box<AuthFuture<AppState>> {
    let c2 = client.clone();
    let app_id_hash = sha3_256(app_id.clone().as_bytes());

    if let Some(app) = apps.get(&app_id_hash) {
        let app_keys = app.keys.clone();
        access_container(client)
            .and_then(move |dir| {
                access_container_entry(&c2, &dir, &app_id, app_keys)
            })
            .then(move |res| {
                match res {
                    Ok((_version, Some(_))) => Ok(AppState::Authenticated),
                    Ok((_, None)) |
                        Err(AuthError::CoreError(
                            CoreError::RoutingClientError(
                                ClientError::NoSuchEntry))) => {
                            // App is not in access container, so it is revoked
                            Ok(AppState::Revoked)
                        }
                    Err(e) => Err(e),
                }
            })
            .into_box()
    } else {
        ok!(AppState::NotAuthenticated)
    }
}

/// Authenticates an app request
///
/// First, this function searches for an app info in the access container.
/// If the app is found, then the `AppGranted` struct is returned based on that information.
/// If the app is not found in the access container, then it will be authenticated.
pub fn authenticate(client: &Client<()>, auth_req: AuthReq) -> Box<AuthFuture<AuthGranted>> {
    let app_id = auth_req.app.id.clone();
    let permissions = auth_req.containers.clone();
    let app_container = auth_req.app_container;

    let c2 = client.clone();
    let c3 = client.clone();
    let c4 = client.clone();

    config::list_apps(client)
        .join(check_revocation(client, app_id.clone()))
        .and_then(move |((apps_version, apps), ())| {
            app_state(&c2, &apps, app_id.clone())
                .map(move |app_state| {
                    (apps_version, apps, app_state, app_id)
                })
        })
        .and_then(move |(apps_version, mut apps, app_state, app_id)| {
            // Determine an app state. If it's revoked we can reuse existing
            // keys stored in the config. And if it is authorised, we just
            // return the app info from the config.
            match app_state {
                AppState::NotAuthenticated => {
                    let owner_key = fry!(c3.owner_key().map_err(AuthError::from));
                    let keys = AppKeys::random(owner_key);
                    let app = AppInfo {
                        info: auth_req.app,
                        keys: keys,
                    };
                    config::insert_app(
                        &c3,
                        apps,
                        config::next_version(apps_version),
                        app.clone()
                    )
                        .map(move |_| (app, app_state))
                        .into_box()
                }
                AppState::Authenticated | AppState::Revoked => {
                    let app_entry_name = sha3_256(app_id.as_bytes());
                    if let Some(app) = apps.remove(&app_entry_name) {
                        ok!((app, app_state))
                    } else {
                        err!(AuthError::from(
                            "Logical error - couldn't find a revoked app in config"
                        ))
                    }
                }
            }
        })
        .and_then(move |(app, app_state)| {
            match app_state {
                AppState::Authenticated => {
                    // Return info of the already registered app
                    let app_keys = app.keys.clone();
                    let bootstrap_config = fry!(Client::<()>::bootstrap_config());

                    access_container(&c4)
                        .and_then(move |dir| {
                            let access_container = AccessContInfo::from_mdata_info(dir)?;
                            Ok(AuthGranted {
                                app_keys: app_keys,
                                bootstrap_config: bootstrap_config,
                                access_container: access_container,
                            })
                        })
                        .into_box()
                }
                AppState::NotAuthenticated |
                AppState::Revoked => {
                    // Register a new app or restore a previously registered app
                    authenticate_new_app(&c4, app, app_container, permissions)
                }
            }
        })
        .into_box()
}

/// Registers a new or revoked app in Maid Managers and in the access container.
///
/// 1. Insert app's key to Maid Managers
/// 2. Update container permissions for requested containers
/// 3. Create the app container (if it's been requested)
/// 4. Insert or update the access container entry for an app
/// 5. Return `AuthGranted`
fn authenticate_new_app(
    client: &Client<()>,
    app: AppInfo,
    app_container: bool,
    permissions: HashMap<String, BTreeSet<Permission>>,
) -> Box<AuthFuture<AuthGranted>> {
    let c2 = client.clone();
    let c3 = client.clone();
    let c4 = client.clone();
    let c5 = client.clone();
    let c6 = client.clone();
    let c7 = client.clone();

    let sign_pk = app.keys.sign_pk;
    let app_keys = app.keys.clone();
    let app_info = app.info.clone();
    let app_id = app_info.id.clone();

    client
        .list_auth_keys_and_version()
        .and_then(move |(_, version)| {
            recovery::ins_auth_key(&c2, app.keys.sign_pk, version + 1)
        })
        .map_err(AuthError::from)
        .and_then(move |_| if permissions.is_empty() {
            ok!(Default::default())
        } else {
            update_container_perms(&c3, permissions, sign_pk)
        })
        .and_then(move |perms| if app_container {
            app_container::fetch(c4, app_id, sign_pk)
                .map(move |mdata_info| (Some(mdata_info), perms))
                .into_box()
        } else {
            ok!((None, perms))
        })
        .and_then(move |(app_container, perms)| {
            // Update access_container
            access_container(&c5).map(move |dir| (dir, app_container, perms))
        })
        .and_then(move |(dir, app_container, mut perms)| {
            if let Some(mdata_info) = app_container {
                // Store info about the app's dedicated container in the access container
                let access =
                    btree_set![
                    Permission::Read,
                    Permission::Insert,
                    Permission::Update,
                    Permission::Delete,
                    Permission::ManagePermissions,
                ];
                let _ = perms.insert(format!("apps/{}", app_info.id), (mdata_info, access));
            };
            access_container_entry(&c6, &dir, &app_info.id, app_keys.clone()).then(move |res| {
                let version = match res {
                    // Updating an existing entry
                    Ok((version, _)) => version + 1,
                    // Adding a new access container entry
                    Err(AuthError::CoreError(
                            CoreError::RoutingClientError(
                                ClientError::NoSuchEntry))) => 0,
                    // Error has occurred while trying to get an existing entry
                    Err(e) => return Err(e),
                };
                Ok((version, app_info, app_keys, dir, perms))
            })
        })
        .and_then(move |(version, app_info, app_keys, dir, perms)| {
            put_access_container_entry(&c7, &dir, &app_info.id, &app_keys, &perms, version)
                .map(move |_| (dir, app_keys))
        })
        .and_then(move |(dir, app_keys)| {
            Ok(AuthGranted {
                app_keys: app_keys,
                bootstrap_config: Client::<()>::bootstrap_config()?,
                access_container: AccessContInfo::from_mdata_info(dir)?,
            })
        })
        .into_box()
}

fn check_revocation(client: &Client<()>, app_id: String) -> Box<AuthFuture<()>> {
    config::get_app_revocation_queue(client)
        .and_then(move |(_, queue)| if queue.contains(&app_id) {
            Err(AuthError::from(
                "Couldn't authenticate app that is pending revocation",
            ))
        } else {
            Ok(())
        })
        .into_box()
}
