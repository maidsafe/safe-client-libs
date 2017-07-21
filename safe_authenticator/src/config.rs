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

use super::{AuthError, AuthFuture};
use futures::Future;
use futures::future::{self, Either};
use ipc::AppInfo;
use maidsafe_utilities::serialisation::{deserialise, serialise};
use routing::{ClientError, EntryActions};
use safe_core::{Client, CoreError, FutureExt, recovery};
use safe_core::ipc::IpcError;
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::collections::{HashMap, VecDeque};
use tiny_keccak::sha3_256;

// TODO: remove the `allow(unused)` attributes.

/// Config file key under which the list of registered apps is stored.
pub const KEY_APPS: &'static [u8] = b"apps";

/// Key under which the access container info is stored.
pub const KEY_ACCESS_CONTAINER: &'static [u8] = b"access-container";

/// Config file key under which the operation queue is stored.
#[allow(unused)]
pub const KEY_OPERATION_QUEUE: &'static [u8] = b"operation-queue";

/// Maps from a SHA-3 hash of an app ID to app info
pub type Apps = HashMap<[u8; 32], AppInfo>;

/// Ongoing composite operation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Operation {
    /// Ongoing revocation of app with the given id.
    AppRevocation { app_id: String },
}

/// Retrieves apps registered with the authenticator
pub fn list_apps(client: &Client<()>) -> Box<AuthFuture<(u64, Apps)>> {
    get_entry(client, KEY_APPS)
}

/// Retrieves an app info by the given app ID.
pub fn get_app(client: &Client<()>, app_id: &str) -> Box<AuthFuture<AppInfo>> {
    let app_id_hash = sha3_256(app_id.as_bytes());
    list_apps(client)
        .and_then(move |(_, config)| {
                      config
                          .get(&app_id_hash)
                          .cloned()
                          .ok_or_else(|| AuthError::IpcError(IpcError::UnknownApp))
                  })
        .into_box()
}

/// Updates the list of apps registered with authenticator.
pub fn update_apps(client: &Client<()>, apps: &Apps, version: u64) -> Box<AuthFuture<()>> {
    update_entry(client, KEY_APPS, apps, version)
}

/// Register the given app with authenticator.
pub fn insert_app(client: &Client<()>, app: AppInfo) -> Box<AuthFuture<()>> {
    let c2 = client.clone();

    list_apps(client)
        .and_then(move |(version, mut apps)| {
                      // Add app info to the authenticator config
                      let hash = sha3_256(app.info.id.as_bytes());
                      let _ = apps.insert(hash, app);
                      update_apps(&c2, &apps, version + 1)
                  })
        .into_box()
}


/// Push a new operation to the operation queue.
#[allow(unused)]
pub fn push_to_operation_queue(client: &Client<()>, op: Operation) -> Box<AuthFuture<()>> {
    let client = client.clone();
    get_operation_queue(&client)
        .then(move |res| {
            let (version, mut queue) = match res {
                Ok(value) => value,
                Err(AuthError::CoreError(
                    CoreError::RoutingClientError(ClientError::NoSuchEntry)
                )) => {
                    (0, Default::default())
                }
                Err(error) => return future::err(error).into_box(),
            };

            queue.push_back(op);
            update_operation_queue(&client, &queue, version + 1)
        })
        .into_box()
}

/// Pop from the operation queue.
#[allow(unused)]
pub fn pop_from_operation_queue(client: &Client<()>) -> Box<AuthFuture<Option<Operation>>> {
    let client = client.clone();
    get_operation_queue(&client)
        .then(move |res| {
            let (version, mut queue) = match res {
                Ok(value) => value,
                Err(AuthError::CoreError(
                    CoreError::RoutingClientError(ClientError::NoSuchEntry)
                )) => {
                    return Either::A(future::ok(None));
                }
                Err(error) => return Either::A(future::err(error)),
            };

            let op = queue.pop_front();
            Either::B(update_operation_queue(&client, &queue, version + 1).map(move |_| op))
        })
        .into_box()
}

/// Get authenticator's operation queue.
#[allow(unused)]
pub fn get_operation_queue(client: &Client<()>) -> Box<AuthFuture<(u64, VecDeque<Operation>)>> {
    get_entry(client, KEY_OPERATION_QUEUE)
}

/// Update authenticator's operation queue.
#[allow(unused)]
pub fn update_operation_queue(client: &Client<()>,
                              queue: &VecDeque<Operation>,
                              version: u64)
                              -> Box<AuthFuture<()>> {
    update_entry(client, KEY_OPERATION_QUEUE, queue, version)
}

fn get_entry<T>(client: &Client<()>, key: &[u8]) -> Box<AuthFuture<(u64, T)>>
    where T: Default + DeserializeOwned + Serialize + 'static
{
    let parent = fry!(client.config_root_dir());
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

            Ok((value.entry_version, decoded))
        })
        .map_err(From::from)
        .into_box()
}

fn update_entry<T>(client: &Client<()>,
                   key: &[u8],
                   content: &T,
                   version: u64)
                   -> Box<AuthFuture<()>>
    where T: Serialize
{
    let parent = fry!(client.config_root_dir());

    let key = fry!(parent.enc_entry_key(key));
    let encoded = fry!(serialise(content));
    let encoded = fry!(parent.enc_entry_value(&encoded));

    let actions = if version == 0 {
        EntryActions::new().ins(key, encoded, 0)
    } else {
        EntryActions::new().update(key, encoded, version)
    };

    recovery::mutate_mdata_entries(&client, parent.name, parent.type_tag, actions.into())
        .map_err(From::from)
        .into_box()
}
