// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! App management functions

use super::config;
use crate::app_auth::{app_state, AppState};
use crate::client::AuthClient;
use crate::{app_container, AuthError};
use bincode::deserialize;

use futures_util::future::FutureExt;
use safe_core::client::{AuthActions, Client};
use safe_core::core_structs::{access_container_enc_key, AccessContainerEntry, AppAccess};
use safe_core::ipc::req::ContainerPermissions;
use safe_core::ipc::{AppExchangeInfo, IpcError};
use safe_core::utils::symmetric_decrypt;
use safe_nd::{AppPermissions, MDataAddress, XorName};
use std::collections::HashMap;
/// Represents an application that is registered with the Authenticator.
#[derive(Debug)]
pub struct RegisteredApp {
    /// Unique application identifier.
    pub app_info: AppExchangeInfo,
    /// List of containers that this application has access to.
    /// Maps from the container name to the set of permissions.
    pub containers: HashMap<String, ContainerPermissions>,
    /// Permissions allowed for the app
    pub app_perms: AppPermissions,
}

/// Removes an application from the list of revoked apps.
pub async fn remove_revoked_app(client: &AuthClient, app_id: String) -> Result<(), AuthError> {
    let client = client.clone();
    let c2 = client.clone();
    let c3 = client.clone();
    let c4 = client.clone();

    let app_id2 = app_id.clone();
    let app_id3 = app_id.clone();

    let (apps_version, apps) = config::list_apps(&client).await?;
    let app_state = app_state(&c2, &apps, &app_id).await?;
    let (apps, apps_version) = match app_state {
        AppState::Revoked => (apps, apps_version),
        AppState::Authenticated => return Err(AuthError::from("App is not revoked")),
        AppState::NotAuthenticated => return Err(AuthError::IpcError(IpcError::UnknownApp)),
    };
    config::remove_app(&c3, apps, config::next_version(apps_version), &app_id2).await?;

    app_container::remove(c4, &app_id3).await?;

    Ok(())
}

/// Returns a list of applications that have been revoked.
pub async fn list_revoked(client: &AuthClient) -> Result<Vec<AppExchangeInfo>, AuthError> {
    let c2 = client.clone();
    let c3 = client.clone();

    let (_, auth_cfg) = config::list_apps(client).await?;
    let access_container = c2.access_container();
    let entries = c3
        .list_seq_mdata_entries(access_container.name(), access_container.type_tag())
        .await?;
    let mut apps = Vec::new();
    let nonce = access_container
        .nonce()
        .ok_or_else(|| AuthError::from("No nonce on access container's MDataInfo"))?;

    for app in auth_cfg.values() {
        let key = access_container_enc_key(&app.info.id, &app.keys.enc_key, nonce)?;

        // If the app is not in the access container, or if the app entry has
        // been deleted (is empty), then it's revoked.
        let revoked = entries
            .get(&key)
            .map_or(true, |entry| entry.data.is_empty());

        if revoked {
            apps.push(app.info.clone());
        }
    }
    Ok(apps)
}

/// Return the list of applications that are registered with the Authenticator.
pub async fn list_registered(client: &AuthClient) -> Result<Vec<RegisteredApp>, AuthError> {
    let c2 = client.clone();
    let c3 = client.clone();
    let c4 = client.clone();

    let (_, auth_cfg) = config::list_apps(client).await?;
    let access_container = c2.access_container();
    let entries = c3
        .list_seq_mdata_entries(access_container.name(), access_container.type_tag())
        .await?;
    let (mut authorised_keys, _version) = c4.list_auth_keys_and_version().await?;
    let mut apps = Vec::new();
    let nonce = access_container
        .nonce()
        .ok_or_else(|| AuthError::from("No nonce on access container's MDataInfo"))?;

    for app in auth_cfg.values() {
        let key = access_container_enc_key(&app.info.id, &app.keys.enc_key, nonce)?;

        // Empty entry means it has been deleted
        let entry = match entries.get(&key) {
            Some(entry) if !entry.data.is_empty() => Some(entry),
            _ => None,
        };

        if let Some(entry) = entry {
            let plaintext = symmetric_decrypt(&entry.data, &app.keys.enc_key)?;
            let app_access = deserialize::<AccessContainerEntry>(&plaintext)?;

            let mut containers = HashMap::new();

            for (container_name, (_, permission_set)) in app_access {
                let _ = containers.insert(container_name, permission_set);
            }

            let app_public_key = app.keys.public_key();
            let app_perms = authorised_keys.remove(&app_public_key).unwrap_or_default();

            let registered_app = RegisteredApp {
                app_info: app.info.clone(),
                containers,
                app_perms,
            };

            apps.push(registered_app);
        }
    }
    Ok(apps)
}

/// Returns a list of applications that have access to the specified Mutable Data.
pub async fn apps_accessing_mutable_data(
    client: &AuthClient,
    name: XorName,
    type_tag: u64,
) -> Result<Vec<AppAccess>, AuthError> {
    let c2 = client.clone();

    let permissions = client
        .list_mdata_permissions(MDataAddress::Seq {
            name,
            tag: type_tag,
        })
        .await?;

    let (_, apps) = config::list_apps(&c2).await?;

    let apps = apps
        .into_iter()
        .map(|(_, app_info)| (app_info.keys.public_key(), app_info.info))
        .collect::<HashMap<_, _>>();

    // Map the list of keys retrieved from MD to a list of registered apps (even if
    // they're in the Revoked state) and create a new `AppAccess` struct object
    let mut app_access_vec: Vec<AppAccess> = Vec::new();
    for (user, perm_set) in permissions {
        let app_access = match apps.get(&user) {
            Some(app_info) => AppAccess {
                sign_key: user,
                permissions: perm_set,
                name: Some(app_info.name.clone()),
                app_id: Some(app_info.id.clone()),
            },
            None => {
                // If an app is listed in the MD permissions list, but is not
                // listed in the registered apps list in Authenticator, then set
                // the app_id and app_name fields to None, but provide
                // the public sign key and the list of permissions.
                AppAccess {
                    sign_key: user,
                    permissions: perm_set,
                    name: None,
                    app_id: None,
                }
            }
        };
        app_access_vec.push(app_access);
    }
    Ok(app_access_vec)
}
