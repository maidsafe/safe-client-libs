// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! App authentication routines

use super::{AuthError, AuthFuture};
use crate::access_container;
use crate::client::AuthClient;
use crate::config::{self, AppInfo, Apps};
use crate::containers::create_containers;
use crate::ipc::update_container_perms;
use futures::future;
use futures::Future;
use safe_core::client;
use safe_core::ipc::req::{AuthReq, ContainerPermissions};
use safe_core::ipc::resp::{AccessContInfo, AccessContainerEntry, AppKeys, AuthGranted};
use safe_core::{client::AuthActions, identify_existing_containers, recovery, Client, FutureExt};
use safe_nd::{AppPermissions, PublicKey};
use std::collections::HashMap;
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

/// Return a current app state (`Authenticated` if it has an entry
/// in the config file AND the access container, `Revoked` if it has
/// an entry in the config but not in the access container, and `NotAuthenticated`
/// if it's not registered anywhere).
pub fn app_state(client: &AuthClient, apps: &Apps, app_id: &str) -> Box<AuthFuture<AppState>> {
    let app_id_hash = sha3_256(app_id.as_bytes());

    if let Some(app) = apps.get(&app_id_hash) {
        let app_keys = app.keys.clone();

        access_container::fetch_entry(client, app_id, app_keys)
            .then(move |res| {
                match res {
                    Ok((_version, Some(_))) => Ok(AppState::Authenticated),
                    Ok((_, None)) => {
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

fn update_access_container(
    client: &AuthClient,
    app: &AppInfo,
    permissions: AccessContainerEntry,
) -> Box<AuthFuture<()>> {
    let c2 = client.clone();

    let app_id = app.info.id.clone();
    let app_keys = app.keys.clone();

    trace!("Updating access container entry for app {}...", app_id);
    access_container::fetch_entry(client, &app_id, app_keys.clone())
        .then(move |res| {
            let version = match res {
                // Updating an existing entry
                Ok((version, Some(_))) => version + 1,
                // Adding a new access container entry
                Ok((_, None)) => 0,
                // Error has occurred while trying to get an existing entry
                Err(e) => return Err(e),
            };
            Ok((version, app_keys, permissions))
        })
        .and_then(move |(version, app_keys, permissions)| {
            access_container::put_entry(&c2, &app_id, &app_keys, &permissions, version)
        })
        .into_box()
}

/// Authenticate an app request.
///
/// First, this function searches for an app info in the access container.
/// If the app is found, then the `AuthGranted` struct is returned based on that information.
/// If the app is not found in the access container, then it will be authenticated.
pub fn authenticate(client: &AuthClient, auth_req: AuthReq) -> Box<AuthFuture<AuthGranted>> {
    let app_id = auth_req.app.id.clone();
    let permissions = auth_req.containers.clone();
    let AuthReq {
        app_permissions, ..
    } = auth_req;

    let c2 = client.clone();
    let c3 = client.clone();
    let c4 = client.clone();

    config::list_apps(client)
        .join(check_revocation(client, app_id.clone()))
        .and_then(move |((apps_version, apps), ())| {
            app_state(&c2, &apps, &app_id)
                .map(move |app_state| (apps_version, apps, app_state, app_id))
        })
        .and_then(move |(apps_version, mut apps, app_state, app_id)| {
            // Determine an app state. If it's revoked we can reuse existing
            // keys stored in the config. And if it is authorised, we just
            // return the app info from the config.
            match app_state {
                AppState::NotAuthenticated => {
                    let owner_key = c3.owner_key();
                    let keys = AppKeys::random(owner_key);
                    let app = AppInfo {
                        info: auth_req.app,
                        keys,
                    };
                    config::insert_app(&c3, apps, config::next_version(apps_version), app.clone())
                        .map(move |_| (app, app_state, app_id))
                        .into_box()
                }
                AppState::Authenticated | AppState::Revoked => {
                    let app_entry_name = sha3_256(app_id.as_bytes());
                    if let Some(app) = apps.remove(&app_entry_name) {
                        ok!((app, app_state, app_id))
                    } else {
                        err!(AuthError::from(
                            "Logical error - couldn't find a revoked app in config"
                        ))
                    }
                }
            }
        })
        .and_then(move |(app, app_state, app_id)| {
            match app_state {
                AppState::Authenticated => {
                    // Return info of the already registered app
                    authenticated_app(&c4, app, app_id, app_permissions)
                }
                AppState::NotAuthenticated | AppState::Revoked => {
                    // Register a new app or restore a previously registered app
                    authenticate_new_app(&c4, app, app_permissions, permissions)
                }
            }
        })
        .into_box()
}

/// Return info of an already registered app.
fn authenticated_app(
    client: &AuthClient,
    app: AppInfo,
    app_id: String,
    _app_permissions: AppPermissions,
) -> Box<AuthFuture<AuthGranted>> {
    let c2 = client.clone();

    let app_keys = app.keys.clone();
    let bootstrap_config = fry!(client::bootstrap_config());

    access_container::fetch_entry(client, &app_id, app_keys.clone())
        .and_then(move |(_version, perms)| {
            let perms = perms.unwrap_or_else(AccessContainerEntry::default);

            // TODO: check if we need to update app permissions

            future::ok(perms)
        })
        .and_then(move |perms| {
            let access_container_info = c2.access_container();
            let access_container_info = AccessContInfo::from_mdata_info(&access_container_info)?;

            Ok(AuthGranted {
                app_keys,
                bootstrap_config,
                access_container_info,
                access_container_entry: perms,
            })
        })
        .into_box()
}

/// Register a new or revoked app in the Client Handlers and in the access container.
///
/// 1. Insert app's key to Client Handlers
/// 4. Insert or update the access container entry for an app
/// 5. Return `AuthGranted`
fn authenticate_new_app(
    client: &AuthClient,
    app: AppInfo,
    app_permissions: AppPermissions,
    permissions: HashMap<String, ContainerPermissions>,
) -> Box<AuthFuture<AuthGranted>> {
    let c2 = client.clone();
    let c3 = client.clone();
    let c4 = client.clone();
    let c5 = client.clone();
    let c6 = client.clone();
    let c7 = client.clone();

    let sign_pk = PublicKey::from(app.keys.bls_pk);
    let app_keys = app.keys.clone();
    let app_keys_auth = app.keys.clone();
    let access_container_info = client.access_container();
    let access_container_addr = safe_nd::MDataAddress::from_kind(
        safe_nd::MDataKind::Seq,
        access_container_info.name(),
        access_container_info.type_tag(),
    );

    client
        .list_auth_keys_and_version()
        .map_err(AuthError::from)
        .and_then(move |(_, version)| {
            recovery::ins_auth_key(
                &c2,
                PublicKey::from(app_keys.bls_pk),
                app_permissions,
                version + 1,
            )
            .map_err(AuthError::from)
        })
        .and_then(move |_| {
            if permissions.is_empty() {
                ok!((AccessContainerEntry::default(), app))
            } else {
                identify_existing_containers(permissions, c6, access_container_addr)
                    .map_err(AuthError::from)
                    .and_then(move |requested_containers| {
                        let update_containers_future =
                            update_container_perms(&c3, requested_containers.existing, sign_pk);
                        let create_containers_future =
                            create_containers(&c7, requested_containers.new, sign_pk);
                        future::join_all(vec![update_containers_future, create_containers_future])
                            .into_box()
                    })
                    .and_then(|mut results| {
                        let mut updated_containers: AccessContainerEntry =
                            results.pop().unwrap_or_default();
                        let new_containers: AccessContainerEntry =
                            results.pop().unwrap_or_default();
                        // Combine both the new and updated containers and store it in the access container
                        updated_containers.extend(new_containers.into_iter());
                        Ok((updated_containers, app))
                    })
                    .into_box()
            }
        })
        .and_then(move |(perms, app)| {
            update_access_container(&c4, &app, perms.clone())
                .map(move |_| perms)
                .map_err(AuthError::from)
        })
        .and_then(move |access_container_entry| {
            let access_container_info = c5.access_container();
            let access_container_info = AccessContInfo::from_mdata_info(&access_container_info)?;

            Ok(AuthGranted {
                app_keys: app_keys_auth,
                bootstrap_config: client::bootstrap_config()?,
                access_container_info,
                access_container_entry,
            })
        })
        .into_box()
}

fn check_revocation(client: &AuthClient, app_id: String) -> Box<AuthFuture<()>> {
    config::get_app_revocation_queue(client)
        .and_then(move |(_, queue)| {
            if queue.contains(&app_id) {
                Err(AuthError::PendingRevocation)
            } else {
                Ok(())
            }
        })
        .into_box()
}
