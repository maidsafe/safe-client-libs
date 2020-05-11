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
use crate::access_container::update_container_perms;
use crate::app_container;
use crate::client::AuthClient;
use crate::config::{self, AppInfo, Apps};
use futures::future::{self, Either};
use futures::Future;
use futures_util::future::FutureExt;
use log::trace;
use safe_core::btree_set;
use safe_core::client;
use safe_core::core_structs::{AccessContInfo, AccessContainerEntry, AppKeys};
use safe_core::ipc::req::{AuthReq, ContainerPermissions, Permission};
use safe_core::ipc::resp::AuthGranted;
use safe_core::{app_container_name, client::AuthActions, recoverable_apis, Client, MDataInfo};
use safe_nd::AppPermissions;
use std::collections::HashMap;
use tiny_keccak::sha3_256;
use unwrap::unwrap;

// use futures::future::FutureExt;

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
pub async fn app_state(
    client: &AuthClient,
    apps: &Apps,
    app_id: &str,
) -> Result<AppState, AuthError> {
    let app_id_hash = sha3_256(app_id.as_bytes());

    if let Some(app) = apps.get(&app_id_hash) {
        let app_keys = app.keys.clone();

        let res = access_container::fetch_entry(client.clone(), app_id.to_string(), app_keys).await;

        match res {
            Ok((_version, Some(_))) => Ok(AppState::Authenticated),
            Ok((_, None)) => {
                // App is not in access container, so it is revoked
                Ok(AppState::Revoked)
            }
            Err(e) => Err(e),
        }
    } else {
        Ok(AppState::NotAuthenticated)
    }
}

/// Check whether `permissions` has an app container entry for `app_id` and that all permissions are
/// set.
fn app_container_exists(permissions: &AccessContainerEntry, app_id: &str) -> bool {
    match permissions.get(&app_container_name(app_id)) {
        Some(&(_, ref access)) => {
            *access
                == btree_set![
                    Permission::Read,
                    Permission::Insert,
                    Permission::Update,
                    Permission::Delete,
                    Permission::ManagePermissions,
                ]
        }
        None => false,
    }
}

/// Insert info about the app's dedicated container into the access container entry
fn insert_app_container(
    mut permissions: AccessContainerEntry,
    app_id: &str,
    app_container_info: MDataInfo,
) -> AccessContainerEntry {
    let access = btree_set![
        Permission::Read,
        Permission::Insert,
        Permission::Update,
        Permission::Delete,
        Permission::ManagePermissions,
    ];
    let _ = permissions.insert(app_container_name(app_id), (app_container_info, access));
    permissions
}

async fn update_access_container(
    client: &AuthClient,
    app: &AppInfo,
    permissions: AccessContainerEntry,
) -> Result<(), AuthError> {
    let c2 = client.clone();

    let app_id = app.info.id.clone();
    let app_keys = app.keys.clone();

    trace!("Updating access container entry for app {}...", app_id);
    let res = access_container::fetch_entry(client.clone(), app_id.clone(), app_keys.clone()).await;

    let version = match res {
        // Updating an existing entry
        Ok((version, Some(_))) => version + 1,
        // Adding a new access container entry
        Ok((_, None)) => 0,
        // Error has occurred while trying to get an existing entry
        Err(e) => return Err(e),
    };

    access_container::put_entry(&c2, &app_id, &app_keys, &permissions, version).await
}

/// Authenticate an app request.
///
/// First, this function searches for an app info in the access container.
/// If the app is found, then the `AuthGranted` struct is returned based on that information.
/// If the app is not found in the access container, then it will be authenticated.
pub async fn authenticate(
    client: &AuthClient,
    auth_req: AuthReq,
) -> Result<AuthGranted, AuthError> {
    let app_id = auth_req.app.id.clone();
    let permissions = auth_req.containers.clone();
    let AuthReq {
        app_container,
        app_permissions,
        ..
    } = auth_req;

    let c2 = client.clone();
    let c3 = client.clone();
    let c4 = client.clone();

    let (apps_version, mut apps) = config::list_apps(client).await?;
    check_revocation(client, app_id.clone()).await?;

    let app_state = app_state(&c2, &apps, &app_id).await?;

    // Determine an app state. If it's revoked we can reuse existing
    // keys stored in the config. And if it is authorised, we just
    // return the app info from the config.
    let (app, app_state, app_id) = match app_state {
        AppState::NotAuthenticated => {
            let public_id = c3.public_id();
            // Safe to unwrap as the auth client will have a client public id.
            let keys = AppKeys::new(unwrap!(public_id.client_public_id()).clone());
            let app = AppInfo {
                info: auth_req.app,
                keys,
            };
            config::insert_app(&c3, apps, config::next_version(apps_version), app.clone()).await?;
            (app, app_state, app_id)
        }
        AppState::Authenticated | AppState::Revoked => {
            let app_entry_name = sha3_256(app_id.as_bytes());
            if let Some(app) = apps.remove(&app_entry_name) {
                (app, app_state, app_id)
            } else {
                return Err(AuthError::from(
                    "Logical error - couldn't find a revoked app in config",
                ));
            }
        }
    };

    match app_state {
        AppState::Authenticated => {
            // Return info of the already registered app
            authenticated_app(&c4, app, app_id, app_container, app_permissions).await
        }
        AppState::NotAuthenticated | AppState::Revoked => {
            // Register a new app or restore a previously registered app
            authenticate_new_app(&c4, app, app_container, app_permissions, permissions).await
        }
    }
}

/// Return info of an already registered app.
/// If `app_container` is `true` then we also create/update the dedicated container.
async fn authenticated_app(
    client: &AuthClient,
    app: AppInfo,
    app_id: String,
    app_container: bool,
    _app_permissions: AppPermissions,
) -> Result<AuthGranted, AuthError> {
    let c2 = client.clone();
    let c3 = client.clone();

    let app_keys = app.keys.clone();
    let app_pk = app.keys.public_key();
    let bootstrap_config = client::bootstrap_config()?;

    let (_version, perms) =
        access_container::fetch_entry(client.clone(), app_id.clone(), app_keys.clone()).await?;

    let perms = perms.unwrap_or_else(AccessContainerEntry::default);

    // TODO: check if we need to update app permissions

    // Check whether we need to create/update dedicated container
    if app_container && !app_container_exists(&perms, &app_id) {
        let mdata_info = app_container::fetch_or_create(&c2, &app_id, app_pk).await?;
        let perms = insert_app_container(perms.clone(), &app_id, mdata_info);
        update_access_container(&c2, &app, perms.clone())
            .map(move |_| perms)
            .await;
    }

    let access_container_info = c3.access_container();
    let access_container_info = AccessContInfo::from_mdata_info(&access_container_info)?;

    Ok(AuthGranted {
        app_keys,
        bootstrap_config,
        access_container_info,
        access_container_entry: perms,
    })
}

/// Register a new or revoked app in Maid Managers and in the access container.
///
/// 1. Insert app's key to Maid Managers
/// 2. Update container permissions for requested containers
/// 3. Create the app container (if it's been requested)
/// 4. Insert or update the access container entry for an app
/// 5. Return `AuthGranted`
async fn authenticate_new_app(
    client: &AuthClient,
    app: AppInfo,
    app_container: bool,
    app_permissions: AppPermissions,
    permissions: HashMap<String, ContainerPermissions>,
) -> Result<AuthGranted, AuthError> {
    let c2 = client.clone();
    let c3 = client.clone();
    let c4 = client.clone();
    let c5 = client.clone();
    let c6 = client.clone();

    let app_pk = app.keys.public_key();
    let app_keys = app.keys.clone();
    let app_keys_auth = app.keys.clone();
    let app_id = app.info.id.clone();

    let (_, version) = client.list_auth_keys_and_version().await?;

    recoverable_apis::ins_auth_key_to_client_h(
        &c2,
        app_keys.public_key(),
        app_permissions,
        version + 1,
    )
    .await?;

    let (mut perms, app_pk) = if permissions.is_empty() {
        (Default::default(), app_pk)
    } else {
        let mut perms = update_container_perms(&c3, permissions, app_pk).await?;
        (perms, app_pk)
    };

    if app_container {
        let mdata_info = app_container::fetch_or_create(&c4, &app_id, app_pk).await?;

        perms = insert_app_container(perms, &app_id, mdata_info);
    }

    update_access_container(&c5, &app, perms.clone()).await?;

    let access_container_entry = perms;

    let access_container_info = c6.access_container();
    let access_container_info = AccessContInfo::from_mdata_info(&access_container_info)?;

    Ok(AuthGranted {
        app_keys: app_keys_auth,
        bootstrap_config: client::bootstrap_config()?,
        access_container_info,
        access_container_entry,
    })
}

async fn check_revocation(client: &AuthClient, app_id: String) -> Result<(), AuthError> {
    let (_, queue) = config::get_app_revocation_queue(client).await?;

    if queue.contains(&app_id) {
        Err(AuthError::PendingRevocation)
    } else {
        Ok(())
    }
}
