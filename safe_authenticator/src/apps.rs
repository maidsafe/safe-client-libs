// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! App management functions

use super::{config, AuthFuture};
use crate::app_auth::{app_state, AppState};
use crate::client::AuthClient;
use crate::ffi::apps as ffi;
use crate::ffi::apps::RegisteredApp as FfiRegisteredApp;
use crate::{app_container, AuthError};
use ffi_utils::{vec_into_raw_parts, ReprC};
use futures::future::Future;
use maidsafe_utilities::serialisation::deserialise;
use routing::XorName;
use safe_core::client::Client;
use safe_core::ipc::req::{containers_from_repr_c, containers_into_vec, ContainerPermissions};
use safe_core::ipc::resp::{AccessContainerEntry, AppAccess};
use safe_core::ipc::{access_container_enc_key, AppExchangeInfo, IpcError};
use safe_core::utils::symmetric_decrypt;
use safe_core::FutureExt;
use safe_nd::{MDataAddress, PublicKey};
use std::collections::HashMap;

/// Represents an application that is registered with the Authenticator.
#[derive(Debug)]
pub struct RegisteredApp {
    /// Unique application identifier.
    pub app_info: AppExchangeInfo,
    /// List of containers that this application has access to.
    /// Maps from the container name to the set of permissions.
    pub containers: HashMap<String, ContainerPermissions>,
}

impl RegisteredApp {
    /// Construct FFI wrapper for the native Rust object, consuming self.
    pub fn into_repr_c(self) -> Result<FfiRegisteredApp, IpcError> {
        let RegisteredApp {
            app_info,
            containers,
        } = self;

        let container_permissions_vec = containers_into_vec(containers.into_iter())?;

        let (containers_ptr, containers_len, containers_cap) =
            vec_into_raw_parts(container_permissions_vec);

        Ok(FfiRegisteredApp {
            app_info: app_info.into_repr_c()?,
            containers: containers_ptr,
            containers_len,
            containers_cap,
        })
    }
}

impl ReprC for RegisteredApp {
    type C = *const ffi::RegisteredApp;
    type Error = IpcError;

    unsafe fn clone_from_repr_c(repr_c: Self::C) -> Result<Self, Self::Error> {
        Ok(Self {
            app_info: AppExchangeInfo::clone_from_repr_c(&(*repr_c).app_info)?,
            containers: containers_from_repr_c((*repr_c).containers, (*repr_c).containers_len)?,
        })
    }
}

/// Removes an application from the list of revoked apps.
pub fn remove_revoked_app(client: &AuthClient, app_id: String) -> Box<AuthFuture<()>> {
    let client = client.clone();
    let c2 = client.clone();
    let c3 = client.clone();
    let c4 = client.clone();

    let app_id = app_id.clone();
    let app_id2 = app_id.clone();
    let app_id3 = app_id.clone();

    config::list_apps(&client)
        .and_then(move |(apps_version, apps)| {
            app_state(&c2, &apps, &app_id).map(move |app_state| (app_state, apps, apps_version))
        })
        .and_then(move |(app_state, apps, apps_version)| match app_state {
            AppState::Revoked => Ok((apps, apps_version)),
            AppState::Authenticated => Err(AuthError::from("App is not revoked")),
            AppState::NotAuthenticated => Err(AuthError::IpcError(IpcError::UnknownApp)),
        })
        .and_then(move |(apps, apps_version)| {
            config::remove_app(&c3, apps, config::next_version(apps_version), &app_id2)
        })
        .and_then(move |_| app_container::remove(c4, &app_id3).map(move |_res| ()))
        .into_box()
}

/// Returns a list of applications that have been revoked.
pub fn list_revoked(client: &AuthClient) -> Box<AuthFuture<Vec<AppExchangeInfo>>> {
    let c2 = client.clone();
    let c3 = client.clone();

    config::list_apps(client)
        .map(move |(_, auth_cfg)| (c2.access_container(), auth_cfg))
        .and_then(move |(access_container, auth_cfg)| {
            c3.list_seq_mdata_entries(access_container.name(), access_container.type_tag())
                .map_err(From::from)
                .map(move |entries| (access_container, entries, auth_cfg))
        })
        .and_then(move |(access_container, entries, auth_cfg)| {
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
                    .map(|entry| entry.data.is_empty())
                    .unwrap_or(true);

                if revoked {
                    apps.push(app.info.clone());
                }
            }
            Ok(apps)
        })
        .into_box()
}

/// Return the list of applications that are registered with the Authenticator.
pub fn list_registered(client: &AuthClient) -> Box<AuthFuture<Vec<RegisteredApp>>> {
    let c2 = client.clone();
    let c3 = client.clone();

    config::list_apps(client)
        .map(move |(_, auth_cfg)| (c2.access_container(), auth_cfg))
        .and_then(move |(access_container, auth_cfg)| {
            c3.list_seq_mdata_entries(access_container.name(), access_container.type_tag())
                .map_err(From::from)
                .map(move |entries| (access_container, entries, auth_cfg))
        })
        .and_then(move |(access_container, entries, auth_cfg)| {
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
                    let app_access = deserialise::<AccessContainerEntry>(&plaintext)?;

                    let mut containers = HashMap::new();

                    for (container_name, (_, permission_set)) in app_access {
                        let _ = containers.insert(container_name, permission_set);
                    }

                    let registered_app = RegisteredApp {
                        app_info: app.info.clone(),
                        containers,
                    };

                    apps.push(registered_app);
                }
            }
            Ok(apps)
        })
        .into_box()
}

/// Returns a list of applications that have access to the specified Mutable Data.
pub fn apps_accessing_mutable_data(
    client: &AuthClient,
    name: XorName,
    type_tag: u64,
) -> Box<AuthFuture<Vec<AppAccess>>> {
    let c2 = client.clone();

    client
        .list_mdata_permissions(MDataAddress::Seq {
            name,
            tag: type_tag,
        })
        .map_err(AuthError::from)
        .join(config::list_apps(&c2).map(|(_, apps)| {
            apps.into_iter()
                .map(|(_, app_info)| (PublicKey::from(app_info.keys.bls_pk), app_info.info))
                .collect::<HashMap<_, _>>()
        }))
        .and_then(move |(permissions, apps)| {
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
        })
        .into_box()
}
