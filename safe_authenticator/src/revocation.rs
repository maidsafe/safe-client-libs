// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! App revocation functions

use super::AuthError;
use crate::access_container;
use crate::client::AuthClient;
use crate::config::{self, AppInfo, RevocationQueue};

use log::trace;
use safe_core::recoverable_apis;
use safe_core::{client::AuthActions, Client, CoreError, MDataInfo};
use safe_nd::{Error as SndError, PublicKey};
use std::collections::HashMap;

type Containers = HashMap<String, MDataInfo>;

/// Revoke app access using a revocation queue.
pub async fn revoke_app(client: &AuthClient, app_id: &str) -> Result<(), AuthError> {
    let app_id = app_id.to_string();
    let client = client.clone();
    let c2 = client.clone();

    let (version, queue) = config::get_app_revocation_queue(&client).await?;
    let (version, queue) = config::push_to_app_revocation_queue(
        &client,
        queue,
        config::next_version(version),
        &app_id,
    )
    .await?;

    flush_app_revocation_queue_impl(&c2, queue, version + 1).await
}

/// Revoke all apps currently in the revocation queue.
pub async fn flush_app_revocation_queue(client: &AuthClient) -> Result<(), AuthError> {
    let client = client.clone();

    let (version, queue) = config::get_app_revocation_queue(&client).await?;
    if let Some(version) = version {
        flush_app_revocation_queue_impl(&client, queue, version + 1).await
    } else {
        Ok(())
    }
}

// Try to revoke all apps in the revocation queue. If app revocation results in an error, move the
// app to the back of the queue. Keep track of failed apps and if one fails again after moving to
// the end of the queue, return its error. In other words, we revoke all the apps that we can and
// return an error for the first app that fails twice.
//
// The exception to this is if we encounter a `SymmetricDecipherFailure` error, which we know is
// irrecoverable, so in this case we remove the app from the queue and return an error immediately.
async fn flush_app_revocation_queue_impl(
    client: &AuthClient,
    queue: RevocationQueue,
    version: u64,
) -> Result<(), AuthError> {
    let client = client.clone();
    let mut moved_apps = Vec::new();

    let mut the_queue = queue;
    let mut version_to_try = version;
    let mut done_trying = false;
    let mut response: Result<(), AuthError> = Ok(());

    while !done_trying {
        let c2 = client.clone();
        let c3 = client.clone();

        if let Some(app_id) = the_queue.front().cloned() {
            match revoke_single_app(&c2, &app_id).await {
                Ok(_) => {
                    let (version, queue) =
                        config::remove_from_app_revocation_queue(&c3, the_queue, version, &app_id)
                            .await?;

                    version_to_try = version;
                    the_queue = queue;
                }
                Err(AuthError::CoreError(CoreError::SymmetricDecipherFailure)) => {
                    // The app entry can't be decrypted. No way to revoke app, so just
                    // remove it from the queue and return an error.
                    let (_version, queue) =
                        config::remove_from_app_revocation_queue(&c3, the_queue, version, &app_id)
                            .await?;

                    the_queue = queue;

                    // are we?
                    done_trying = true;
                    response = Err(AuthError::CoreError(CoreError::SymmetricDecipherFailure))
                }
                Err(error) => {
                    if moved_apps.contains(&app_id) {
                        // If this app has already been moved to the back of the queue,
                        // return the error.
                        response = Err(error)
                    } else {
                        // Move the app to the end of the queue.
                        moved_apps.push(app_id.clone());
                        let (version, queue) = config::repush_to_app_revocation_queue(
                            &c3, the_queue, version, &app_id,
                        )
                        .await?;
                        version_to_try = version;
                        the_queue = queue;
                    }
                }
            }

            version_to_try = version + 1;
        } else {
            done_trying = true;
            response = Ok(())
        }
    }

    response
}

// Revoke access for a single app
async fn revoke_single_app(client: &AuthClient, app_id: &str) -> Result<(), AuthError> {
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
    let app = config::get_app(client, app_id).await?;

    delete_app_auth_key(&c2, app.keys.public_key()).await?;

    let (version, ac_entry) =
        access_container::fetch_entry(c3, app.info.id.clone(), app.keys.clone()).await?;

    if let Some(ac_entry) = ac_entry {
        let containers: Containers = ac_entry
            .into_iter()
            .map(|(name, (mdata_info, _))| (name, mdata_info))
            .collect();

        clear_from_access_container_entry(&c4, app, version, containers).await
    } else {
        // If the access container entry was not found, the entry must have been
        // deleted with the app having stayed on the revocation queue.
        Ok(())
    }
}

// Delete the app auth key from the Maid Manager - this prevents the app from
// performing any more mutations.
async fn delete_app_auth_key(client: &AuthClient, key: PublicKey) -> Result<(), AuthError> {
    let client = client.clone();

    match client.list_auth_keys_and_version().await {
        Ok((listed_keys, version)) => {
            if listed_keys.contains_key(&key) {
                client
                    .del_auth_key(key, version + 1)
                    .await
                    .map_err(AuthError::from)
            } else {
                // The key has been removed already
                Ok(())
            }
        }
        Err(error) => match error {
            CoreError::DataError(SndError::NoSuchKey) => Ok(()),
            error => Err(AuthError::from(error)),
        },
    }
}

async fn clear_from_access_container_entry(
    client: &AuthClient,
    app: AppInfo,
    ac_entry_version: u64,
    containers: Containers,
) -> Result<(), AuthError> {
    let c2 = client.clone();

    revoke_container_perms(client, &containers, app.keys.public_key()).await?;

    access_container::delete_entry(&c2, &app.info.id, &app.keys, ac_entry_version + 1).await
}

// Revoke containers permissions
async fn revoke_container_perms(
    client: &AuthClient,
    containers: &Containers,
    pk: PublicKey,
) -> Result<(), AuthError> {
    for mdata_info in containers.values() {
        let mdata_info = mdata_info.clone();
        let c2 = client.clone();

        let version = client
            .clone()
            .get_mdata_version(*mdata_info.address())
            .await?;

        recoverable_apis::del_mdata_user_permissions(c2, *mdata_info.address(), pk, version + 1)
            .await?;
    }
    Ok(())
}
