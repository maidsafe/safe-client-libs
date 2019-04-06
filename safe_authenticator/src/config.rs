// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{AuthError, AuthFuture};
use crate::client::AuthClient;
use futures::future::{self, Either, Loop};
use futures::Future;
use maidsafe_utilities::serialisation::{deserialise, serialise};
use routing::{ClientError, EntryActions, EntryError};
use safe_core::ipc::req::AppExchangeInfo;
use safe_core::ipc::resp::AppKeys;
use safe_core::ipc::IpcError;
use safe_core::{Client, CoreError, FutureExt};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::collections::{HashMap, VecDeque};
use tiny_keccak::sha3_256;

/// App data stored in the authenticator configuration.
///
/// We need to store it even for revoked apps because we need to
/// preserve the app keys. An app can encrypt data and create mutable data
/// instances on its own, so we need to make sure that the app can
/// access the encrypted data in future, even if the app was revoked
/// at some point.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppInfo {
    /// Application info (id, name, vendor, etc.)
    pub info: AppExchangeInfo,
    /// Application keys
    pub keys: AppKeys,
}

/// Config file key under which the list of registered apps is stored.
pub const KEY_APPS: &[u8] = b"apps";

/// Config file key under which the revocation queue is stored.
pub const KEY_APP_REVOCATION_QUEUE: &[u8] = b"revocation-queue";

/// Maps from a SHA-3 hash of an app ID to app info.
pub type Apps = HashMap<[u8; 32], AppInfo>;
/// Contains a queue of revocations that are currently running or have failed.
/// String refers to `app_id`.
pub type RevocationQueue = VecDeque<String>;

/// Bump the current version to obtain new version.
pub fn next_version(version: Option<u64>) -> u64 {
    version.map(|v| v + 1).unwrap_or(0)
}

/// Retrieves apps registered with the authenticator.
pub fn list_apps(client: &AuthClient) -> Box<AuthFuture<(Option<u64>, Apps)>> {
    get_entry(client, KEY_APPS)
}

/// Retrieves an app info by the given app ID.
pub fn get_app(client: &AuthClient, app_id: &str) -> Box<AuthFuture<AppInfo>> {
    let app_id_hash = sha3_256(app_id.as_bytes());
    list_apps(client)
        .and_then(move |(_, config)| {
            config
                .get(&app_id_hash)
                .cloned()
                .ok_or_else(|| AuthError::IpcError(IpcError::UnknownApp))
        }).into_box()
}

/// Register the given app with authenticator.
pub fn insert_app(
    client: &AuthClient,
    apps: Apps,
    new_version: u64,
    app: AppInfo,
) -> Box<AuthFuture<(u64, Apps)>> {
    let client = client.clone();
    let hash = sha3_256(app.info.id.as_bytes());

    mutate_entry(&client, KEY_APPS, apps, new_version, move |apps| {
        apps.insert(hash, app.clone()).is_none()
    })
}

/// Remove the given app from the list of registered apps.
pub fn remove_app(
    client: &AuthClient,
    apps: Apps,
    new_version: u64,
    app_id: &str,
) -> Box<AuthFuture<(u64, Apps)>> {
    let hash = sha3_256(app_id.as_bytes());
    mutate_entry(client, KEY_APPS, apps, new_version, move |apps| {
        apps.remove(&hash).is_some()
    })
}

/// Get authenticator's revocation queue.
/// Returns version and the revocation queue in a tuple.
/// If the queue is not found on the config file, returns `None`.
pub fn get_app_revocation_queue(
    client: &AuthClient,
) -> Box<AuthFuture<(Option<u64>, RevocationQueue)>> {
    get_entry(client, KEY_APP_REVOCATION_QUEUE)
}

/// Push new `app_id` into the revocation queue and put it onto the network.
/// Does nothing if the queue already contains `app_id`.
pub fn push_to_app_revocation_queue(
    client: &AuthClient,
    queue: RevocationQueue,
    new_version: u64,
    app_id: &str,
) -> Box<AuthFuture<(u64, RevocationQueue)>> {
    trace!("Pushing app to revocation queue with ID {}...", app_id);

    let app_id = app_id.to_string();
    mutate_entry(
        client,
        KEY_APP_REVOCATION_QUEUE,
        queue,
        new_version,
        move |queue| {
            if !queue.contains(&app_id) {
                queue.push_back(app_id.clone());
                true
            } else {
                false
            }
        },
    )
}

/// Remove `app_id` from the revocation queue.
/// Does nothing if the queue doesn't contain `app_id`.
pub fn remove_from_app_revocation_queue(
    client: &AuthClient,
    queue: RevocationQueue,
    new_version: u64,
    app_id: &str,
) -> Box<AuthFuture<(u64, RevocationQueue)>> {
    trace!("Removing app from revocation queue with ID {}...", app_id);

    let app_id = app_id.to_string();
    mutate_entry(
        client,
        KEY_APP_REVOCATION_QUEUE,
        queue,
        new_version,
        move |queue| {
            if let Some(index) = queue.iter().position(|item| *item == app_id) {
                let _ = queue.remove(index);
                true
            } else {
                false
            }
        },
    )
}

/// Moves `app_id` to the back of the revocation queue.
/// Does nothing if the queue doesn't contain `app_id`.
pub fn repush_to_app_revocation_queue(
    client: &AuthClient,
    queue: RevocationQueue,
    new_version: u64,
    app_id: &str,
) -> Box<AuthFuture<(u64, RevocationQueue)>> {
    let app_id = app_id.to_string();
    mutate_entry(
        client,
        KEY_APP_REVOCATION_QUEUE,
        queue,
        new_version,
        move |queue| {
            if let Some(index) = queue.iter().position(|item| *item == app_id) {
                match queue.remove(index) {
                    Some(app_id) => {
                        queue.push_back(app_id);
                        true
                    }
                    None => false,
                }
            } else {
                false
            }
        },
    )
}

fn get_entry<T>(client: &AuthClient, key: &[u8]) -> Box<AuthFuture<(Option<u64>, T)>>
where
    T: Default + DeserializeOwned + Serialize + 'static,
{
    let parent = client.config_root_dir();
    let key = fry!(parent.enc_entry_key(key));

    client
        .get_mdata_value(parent.name, parent.type_tag, key)
        .and_then(move |value| {
            let decoded = parent.decrypt(&value.content)?;
            let decoded = if !decoded.is_empty() {
                deserialise(&decoded)?
            } else {
                Default::default()
            };

            Ok((Some(value.entry_version), decoded))
        }).or_else(|error| match error {
            CoreError::RoutingClientError(ClientError::NoSuchEntry) => {
                Ok((None, Default::default()))
            }
            _ => Err(AuthError::from(error)),
        }).into_box()
}

fn update_entry<T>(
    client: &AuthClient,
    key: &[u8],
    content: &T,
    new_version: u64,
) -> Box<AuthFuture<()>>
where
    T: Serialize,
{
    let parent = client.config_root_dir();

    let key = fry!(parent.enc_entry_key(key));
    let encoded = fry!(serialise(content));
    let encoded = fry!(parent.enc_entry_value(&encoded));

    let actions = if new_version == 0 {
        EntryActions::new().ins(key.clone(), encoded, 0)
    } else {
        EntryActions::new().update(key.clone(), encoded, new_version)
    };

    client
        .mutate_mdata_entries(parent.name, parent.type_tag, actions.into())
        .or_else(move |error| {
            // As we are mutating only one entry, let's make the common errors
            // more convenient to handle.
            if let CoreError::RoutingClientError(ClientError::InvalidEntryActions(ref errors)) =
                error
            {
                if let Some(error) = errors.get(&key) {
                    match *error {
                        EntryError::InvalidSuccessor(version)
                        | EntryError::EntryExists(version) => {
                            return Err(CoreError::RoutingClientError(
                                ClientError::InvalidSuccessor(version),
                            ));
                        }
                        _ => (),
                    }
                }
            }

            Err(error)
        }).map_err(From::from)
        .into_box()
}

/// Atomically mutate the given value and store it in the network.
fn mutate_entry<T, F>(
    client: &AuthClient,
    key: &[u8],
    item: T,
    new_version: u64,
    f: F,
) -> Box<AuthFuture<(u64, T)>>
where
    T: Default + DeserializeOwned + Serialize + 'static,
    F: Fn(&mut T) -> bool + 'static,
{
    let client = client.clone();
    let key = key.to_vec();

    future::loop_fn(
        (key, new_version, item),
        move |(key, new_version, mut item)| {
            let c2 = client.clone();
            let c3 = client.clone();

            if f(&mut item) {
                let f = update_entry(&c2, &key, &item, new_version)
                    .map(move |_| Loop::Break((new_version, item)))
                    .or_else(move |error| match error {
                        AuthError::CoreError(CoreError::RoutingClientError(
                            ClientError::InvalidSuccessor(_),
                        )) => {
                            let f = get_entry(&c3, &key).map(move |(version, item)| {
                                Loop::Continue((key, next_version(version), item))
                            });
                            Either::A(f)
                        }
                        _ => Either::B(future::err(error)),
                    });
                Either::A(f)
            } else {
                Either::B(future::ok(Loop::Break((new_version - 1, item))))
            }
        },
    ).into_box()
}
