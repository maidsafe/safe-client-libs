// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! App revocation functions

use super::{AuthError, AuthFuture};
use crate::access_container;
use crate::client::AuthClient;
use crate::config::{self, AppInfo, RevocationQueue};
use futures::future::{self, Either, Loop};
use futures::Future;
use safe_core::recovery;
use safe_core::{client::AuthActions, Client, CoreError, FutureExt, MDataInfo};
use safe_nd::{Error as SndError, PublicKey};
use std::collections::HashMap;

type Containers = HashMap<String, MDataInfo>;

/// Revoke app access using a revocation queue.
pub fn revoke_app(client: &AuthClient, app_id: &str) -> Box<AuthFuture<()>> {
    let app_id = app_id.to_string();
    let client = client.clone();
    let c2 = client.clone();

    config::get_app_revocation_queue(&client)
        .and_then(move |(version, queue)| {
            config::push_to_app_revocation_queue(
                &client,
                queue,
                config::next_version(version),
                &app_id,
            )
        })
        .and_then(move |(version, queue)| flush_app_revocation_queue_impl(&c2, queue, version + 1))
        .into_box()
}

/// Revoke all apps currently in the revocation queue.
pub fn flush_app_revocation_queue(client: &AuthClient) -> Box<AuthFuture<()>> {
    let client = client.clone();

    config::get_app_revocation_queue(&client)
        .and_then(move |(version, queue)| {
            if let Some(version) = version {
                flush_app_revocation_queue_impl(&client, queue, version + 1)
            } else {
                future::ok(()).into_box()
            }
        })
        .into_box()
}

// Try to revoke all apps in the revocation queue. If app revocation results in an error, move the
// app to the back of the queue. Keep track of failed apps and if one fails again after moving to
// the end of the queue, return its error. In other words, we revoke all the apps that we can and
// return an error for the first app that fails twice.
//
// The exception to this is if we encounter a `SymmetricDecipherFailure` error, which we know is
// irrecoverable, so in this case we remove the app from the queue and return an error immediately.
fn flush_app_revocation_queue_impl(
    client: &AuthClient,
    queue: RevocationQueue,
    version: u64,
) -> Box<AuthFuture<()>> {
    let client = client.clone();
    let moved_apps = Vec::new();

    future::loop_fn(
        (queue, version, moved_apps),
        move |(queue, version, mut moved_apps)| {
            let c2 = client.clone();
            let c3 = client.clone();

            if let Some(app_id) = queue.front().cloned() {
                let f = revoke_single_app(&c2, &app_id)
                    .then(move |result| match result {
                        Ok(_) => {
                            config::remove_from_app_revocation_queue(&c3, queue, version, &app_id)
                                .map(|(version, queue)| (version, queue, moved_apps))
                                .into_box()
                        }
                        Err(AuthError::CoreError(CoreError::SymmetricDecipherFailure)) => {
                            // The app entry can't be decrypted. No way to revoke app, so just
                            // remove it from the queue and return an error.
                            config::remove_from_app_revocation_queue(&c3, queue, version, &app_id)
                                .and_then(|_| {
                                    err!(AuthError::CoreError(CoreError::SymmetricDecipherFailure))
                                })
                                .into_box()
                        }
                        Err(error) => {
                            if moved_apps.contains(&app_id) {
                                // If this app has already been moved to the back of the queue,
                                // return the error.
                                err!(error)
                            } else {
                                // Move the app to the end of the queue.
                                moved_apps.push(app_id.clone());
                                config::repush_to_app_revocation_queue(&c3, queue, version, &app_id)
                                    .map(|(version, queue)| (version, queue, moved_apps))
                                    .into_box()
                            }
                        }
                    })
                    .and_then(move |(version, queue, moved_apps)| {
                        Ok(Loop::Continue((queue, version + 1, moved_apps)))
                    });
                Either::A(f)
            } else {
                Either::B(future::ok(Loop::Break(())))
            }
        },
    )
    .into_box()
}

// Revoke access for a single app
fn revoke_single_app(client: &AuthClient, app_id: &str) -> Box<AuthFuture<()>> {
    trace!("Revoking app with ID {}...", app_id);

    let c2 = client.clone();
    let c3 = client.clone();
    let c4 = client.clone();

    // 1. Delete the app key from the Client Handlers
    // 2. Remove the app key from containers permissions
    // 3. Refresh the containers info from the user's root dir (as the access
    //    container entry is not updated with the new keys info - so we have to
    //    make sure that we use correct encryption keys if the previous revoke
    //    attempt has failed)
    // 4. Remove the revoked app from the access container
    config::get_app(client, app_id)
        .and_then(move |app| {
            delete_app_auth_key(&c2, PublicKey::from(app.keys.bls_pk)).map(move |_| app)
        })
        .and_then(move |app| {
            access_container::fetch_entry(&c3, &app.info.id, app.keys.clone()).and_then(
                move |(version, ac_entry)| {
                    match ac_entry {
                        Some(ac_entry) => {
                            let containers: Containers = ac_entry
                                .into_iter()
                                .map(|(name, (mdata_info, _))| (name, mdata_info))
                                .collect();

                            clear_from_access_container_entry(&c4, app, version, containers)
                        }
                        // If the access container entry was not found, the entry must have been
                        // deleted with the app having stayed on the revocation queue.
                        None => ok!(()),
                    }
                },
            )
        })
        .into_box()
}

// Delete the app auth key from the Maid Manager - this prevents the app from
// performing any more mutations.
fn delete_app_auth_key(client: &AuthClient, key: PublicKey) -> Box<AuthFuture<()>> {
    let client = client.clone();

    client
        .list_auth_keys_and_version()
        .and_then(move |(listed_keys, version)| {
            if listed_keys.contains_key(&key) {
                client.del_auth_key(key, version + 1)
            } else {
                // The key has been removed already
                ok!(())
            }
        })
        .or_else(|error| match error {
            CoreError::DataError(SndError::NoSuchKey) => Ok(()),
            error => Err(AuthError::from(error)),
        })
        .into_box()
}

fn clear_from_access_container_entry(
    client: &AuthClient,
    app: AppInfo,
    ac_entry_version: u64,
    containers: Containers,
) -> Box<AuthFuture<()>> {
    let c2 = client.clone();

    revoke_container_perms(client, &containers, PublicKey::from(app.keys.bls_pk))
        .map(move |_| (app, ac_entry_version))
        .and_then(move |(app, version)| {
            access_container::delete_entry(&c2, &app.info.id, &app.keys, version + 1)
        })
        .into_box()
}

// Revoke containers permissions
fn revoke_container_perms(
    client: &AuthClient,
    containers: &Containers,
    pk: PublicKey,
) -> Box<AuthFuture<()>> {
    let reqs: Vec<_> = containers
        .values()
        .map(|mdata_info| {
            let mdata_info = mdata_info.clone();
            let c2 = client.clone();

            client
                .clone()
                .get_mdata_version(*mdata_info.address())
                .and_then(move |version| {
                    recovery::del_mdata_user_permissions(
                        &c2,
                        *mdata_info.address(),
                        pk,
                        version + 1,
                    )
                })
                .map_err(From::from)
        })
        .collect();

    future::join_all(reqs).map(move |_| ()).into_box()
}
