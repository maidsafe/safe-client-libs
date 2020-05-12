// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! Functionality relating to the Authenticator configuration, including things related to app info
//! and the revocation queue.

use super::AuthError;
use crate::client::AuthClient;
use bincode::{deserialize, serialize};

use futures_util::future::TryFutureExt;
use log::trace;
use safe_core::core_structs::AppKeys;
use safe_core::ipc::req::AppExchangeInfo;
use safe_core::ipc::IpcError;
use safe_core::{Client, CoreError};
use safe_nd::{EntryError, Error as SndError, MDataSeqEntryActions};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
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
    version.map_or(0, |v| v + 1)
}

/// Retrieves apps registered with the authenticator.
pub async fn list_apps(client: &AuthClient) -> Result<(Option<u64>, Apps), AuthError> {
    get_entry(client, KEY_APPS).await
}

/// Retrieves an app info by the given app ID.
pub async fn get_app(client: &AuthClient, app_id: &str) -> Result<AppInfo, AuthError> {
    let app_id_hash = sha3_256(app_id.as_bytes());
    let (_, config) = list_apps(client).await?;
    config
        .get(&app_id_hash)
        .cloned()
        .ok_or_else(|| AuthError::IpcError(IpcError::UnknownApp))
}

/// Register the given app with authenticator.
pub async fn insert_app(
    client: &AuthClient,
    apps: Apps,
    new_version: u64,
    app: AppInfo,
) -> Result<(u64, Apps), AuthError> {
    let client = client.clone();
    let hash = sha3_256(app.info.id.as_bytes());

    mutate_entry(&client, KEY_APPS, apps, new_version, move |apps| {
        apps.insert(hash, app.clone()).is_none()
    })
    .await
}

/// Remove the given app from the list of registered apps.
pub async fn remove_app(
    client: &AuthClient,
    apps: Apps,
    new_version: u64,
    app_id: &str,
) -> Result<(u64, Apps), AuthError> {
    let hash = sha3_256(app_id.as_bytes());
    mutate_entry(client, KEY_APPS, apps, new_version, move |apps| {
        apps.remove(&hash).is_some()
    })
    .await
}

/// Get authenticator's revocation queue.
/// Returns version and the revocation queue in a tuple.
/// If the queue is not found on the config file, returns `None`.
pub async fn get_app_revocation_queue(
    client: &AuthClient,
) -> Result<(Option<u64>, RevocationQueue), AuthError> {
    get_entry(client, KEY_APP_REVOCATION_QUEUE).await
}

/// Push new `app_id` into the revocation queue and put it onto the network.
/// Does nothing if the queue already contains `app_id`.
pub async fn push_to_app_revocation_queue(
    client: &AuthClient,
    queue: RevocationQueue,
    new_version: u64,
    app_id: &str,
) -> Result<(u64, RevocationQueue), AuthError> {
    trace!("Pushing app to revocation queue with ID {}...", app_id);

    let app_id = app_id.to_string();
    mutate_entry(
        client,
        KEY_APP_REVOCATION_QUEUE,
        queue,
        new_version,
        move |queue| {
            if queue.contains(&app_id) {
                false
            } else {
                queue.push_back(app_id.clone());
                true
            }
        },
    )
    .await
}

/// Remove `app_id` from the revocation queue.
/// Does nothing if the queue doesn't contain `app_id`.
pub async fn remove_from_app_revocation_queue(
    client: &AuthClient,
    queue: RevocationQueue,
    new_version: u64,
    app_id: &str,
) -> Result<(u64, RevocationQueue), AuthError> {
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
    .await
}

/// Moves `app_id` to the back of the revocation queue.
/// Does nothing if the queue doesn't contain `app_id`.
pub async fn repush_to_app_revocation_queue(
    client: &AuthClient,
    queue: RevocationQueue,
    new_version: u64,
    app_id: &str,
) -> Result<(u64, RevocationQueue), AuthError> {
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
    .await
}

async fn get_entry<T>(client: &AuthClient, key: &[u8]) -> Result<(Option<u64>, T), AuthError>
where
    T: Default + DeserializeOwned + Serialize + 'static,
{
    let parent = client.config_root_dir();
    let key = parent.enc_entry_key(key)?;

    match client
        .get_seq_mdata_value(parent.name(), parent.type_tag(), key)
        .await
    {
        Ok(value) => {
            let decoded = parent.decrypt(&value.data)?;
            let decoded = if decoded.is_empty() {
                Default::default()
            } else {
                deserialize(&decoded)?
            };

            Ok((Some(value.version), decoded))
        }
        Err(error) => match error {
            CoreError::DataError(SndError::NoSuchEntry) => Ok((None, Default::default())),
            _ => Err(AuthError::from(error)),
        },
    }
}

async fn update_entry<T>(
    client: &AuthClient,
    key: &[u8],
    content: &T,
    new_version: u64,
) -> Result<(), AuthError>
where
    T: Serialize,
{
    let parent = client.config_root_dir();

    let key = parent.enc_entry_key(key)?;
    let encoded = serialize(content)?;
    let encoded = parent.enc_entry_value(&encoded)?;

    let actions = if new_version == 0 {
        MDataSeqEntryActions::new().ins(key.clone(), encoded, 0)
    } else {
        MDataSeqEntryActions::new().update(key.clone(), encoded, new_version)
    };

    client
        .mutate_seq_mdata_entries(parent.name(), parent.type_tag(), actions)
        .await
        .or_else(move |error| {
            // As we are mutating only one entry, let's make the common errors
            // more convenient to handle.
            if let CoreError::DataError(SndError::InvalidEntryActions(ref errors)) = error {
                if let Some(error) = errors.get(&key) {
                    match *error {
                        EntryError::InvalidSuccessor(version)
                        | EntryError::EntryExists(version) => {
                            return Err(CoreError::DataError(SndError::InvalidSuccessor(
                                version.into(),
                            )));
                        }
                        _ => (),
                    }
                }
            }

            Err(error)
        })
        .map_err(From::from)
}

/// Atomically mutate the given value and store it in the network.
async fn mutate_entry<T, F>(
    client: &AuthClient,
    key: &[u8],
    item: T,
    new_version: u64,
    f: F,
) -> Result<(u64, T), AuthError>
where
    T: Default + DeserializeOwned + Serialize + 'static + Clone,
    F: Fn(&mut T) -> bool + 'static,
{
    let client = client.clone();
    let key = key.to_vec();
    let mut new_version = new_version;
    let mut done_trying = false;
    let f = f;
    let mut the_item: T = item;

    let mut result: Result<(), AuthError> = Ok(());

    while !done_trying {
        let c2 = client.clone();
        let c3 = client.clone();

        if f(&mut the_item) {
            match update_entry(&c2, &key, &the_item, new_version).await {
                Ok(_thing) => {
                    // go with version / item we have
                    done_trying = true;
                }
                Err(error) => {
                    match error {
                        AuthError::CoreError(CoreError::DataError(SndError::InvalidSuccessor(
                            _,
                        ))) => {
                            let (version, item) = match get_entry(&c3, &key).await {
                                Ok(v_item_tuple) => v_item_tuple,
                                Err(error) => {
                                    done_trying = true;
                                    result = Err(error);

                                    //just for compiling out of this for now. Not to actually be used.
                                    (None, the_item.clone())
                                }
                            };

                            new_version = next_version(version);
                            the_item = item;
                        }

                        _ => {
                            result = Err(error);
                            done_trying = true;
                        }
                    }
                }
            };
        } else {
            done_trying = true;
            new_version = new_version - 1;
            result = Ok(());
        }
    }

    match result {
        Ok(_) => Ok((new_version, the_item)),
        Err(error) => Err(error),
    }
}
