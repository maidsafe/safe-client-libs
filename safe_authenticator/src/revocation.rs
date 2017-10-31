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
use access_container::{self, AUTHENTICATOR_ENTRY};
use config::{self, AppInfo, RevocationQueue};
use futures::Future;
use futures::future::{self, Either, Loop};
use routing::{ClientError, EntryActions, User, Value};
use rust_sodium::crypto::sign;
use safe_core::{Client, CoreError, FutureExt, MDataInfo};
use safe_core::ipc::IpcError;
use safe_core::recovery;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::collections::hash_map::Entry;

type MDataEntries = BTreeMap<Vec<u8>, Value>;
type Containers = HashMap<String, MDataInfo>;

/// Revokes app access using a revocation queue
pub fn revoke_app(client: &Client<()>, app_id: &str) -> Box<AuthFuture<()>> {
    let app_id = app_id.to_string();
    let client = client.clone();
    let c2 = client.clone();

    config::get_app_revocation_queue(&client)
        .and_then(move |(version, queue)| {
            config::push_to_app_revocation_queue(
                &client,
                queue,
                config::next_version(version),
                app_id,
            )
        })
        .and_then(move |(version, queue)| {
            flush_app_revocation_queue_impl(&c2, queue, version + 1)
        })
        .into_box()
}

/// Revoke all apps currently in the revocation queue.
pub fn flush_app_revocation_queue(client: &Client<()>) -> Box<AuthFuture<()>> {
    let client = client.clone();

    config::get_app_revocation_queue(&client)
        .and_then(move |(version, queue)| if let Some(version) = version {
            flush_app_revocation_queue_impl(&client, queue, version + 1)
        } else {
            future::ok(()).into_box()
        })
        .into_box()
}

fn flush_app_revocation_queue_impl(
    client: &Client<()>,
    queue: RevocationQueue,
    version: u64,
) -> Box<AuthFuture<()>> {
    let client = client.clone();

    future::loop_fn((queue, version), move |(queue, version)| {
        let c2 = client.clone();
        let c3 = client.clone();

        if let Some(app_id) = queue.front().cloned() {
            let f = revoke_single_app(&c2, &app_id)
                .and_then(move |_| {
                    config::remove_from_app_revocation_queue(&c3, queue, version, app_id)
                })
                .and_then(move |(version, queue)| {
                    Ok(Loop::Continue((queue, version + 1)))
                });
            Either::A(f)
        } else {
            Either::B(future::ok(Loop::Break(())))
        }
    }).into_box()
}

/// Revoke access for a single app
fn revoke_single_app(client: &Client<()>, app_id: &str) -> Box<AuthFuture<()>> {
    let c2 = client.clone();
    let c4 = client.clone();
    let c5 = client.clone();
    let c7 = client.clone();
    let c8 = client.clone();

    // 1. Put the provided app_id into the revocation queue
    // 2. Delete the app key from MaidManagers
    // 3. Remove the app key from containers permissions
    // 4. Refresh the containers info from the user's root dir (as the access
    //    container entry is not updated with the new keys info - so we have to
    //    make sure that we use correct encryption keys if the previous revoke\
    //    attempt has failed)
    // 4. Re-encrypt private containers that the app had access to
    // 5. Remove the revoked app from the access container
    config::get_app(client, app_id)
        .and_then(move |app| {
            delete_app_auth_key(&c2, app.keys.sign_pk).map(move |_| app)
        })
        .and_then(move |app| {
            access_container::fetch_entry(&c4, &app.info.id, app.keys.clone())
                .and_then(move |(version, ac_entry)| {
                    let containers: Containers = ac_entry
                        .ok_or(AuthError::IpcError(IpcError::UnknownApp))?
                        .into_iter()
                        .map(|(name, (mdata_info, _))| (name, mdata_info))
                        .collect();

                    Ok((app, version, containers))
                })
        })
        .and_then(move |(app, ac_entry_version, containers)| {
            revoke_container_perms(&c5, &containers, app.keys.sign_pk)
                .map(move |_| (app, ac_entry_version, containers))
        })
        .and_then(move |(app, ac_entry_version, containers)| {
            let container_names = containers.into_iter().map(|(name, _)| name).collect();
            reencrypt_containers_and_update_access_container(&c7, container_names, &app)
                .map(move |_| (app, ac_entry_version))
        })
        .and_then(move |(app, version)| {
            access_container::delete_entry(&c8, &app.info.id, &app.keys, version + 1)
        })
        .into_box()
}

/// Delete the app auth key from the Maid Manager - this prevents the app from
/// performing any more mutations.
fn delete_app_auth_key(client: &Client<()>, key: sign::PublicKey) -> Box<AuthFuture<()>> {
    let client = client.clone();

    client
        .list_auth_keys_and_version()
        .and_then(move |(listed_keys, version)| if listed_keys.contains(
            &key,
        )
        {
            client.del_auth_key(key, version + 1)
        } else {
            // The key has been removed already
            ok!(())
        })
        .or_else(|error| match error {
            CoreError::RoutingClientError(ClientError::NoSuchKey) => Ok(()),
            error => Err(AuthError::from(error)),
        })
        .into_box()
}

// Revokes containers permissions
fn revoke_container_perms(
    client: &Client<()>,
    containers: &Containers,
    sign_pk: sign::PublicKey,
) -> Box<AuthFuture<()>> {
    let reqs: Vec<_> = containers
        .values()
        .map(|mdata_info| {
            let mdata_info = mdata_info.clone();
            let c2 = client.clone();

            client
                .clone()
                .get_mdata_version(mdata_info.name, mdata_info.type_tag)
                .and_then(move |version| {
                    recovery::del_mdata_user_permissions(
                        &c2,
                        mdata_info.name,
                        mdata_info.type_tag,
                        User::Key(sign_pk),
                        version + 1,
                    )
                })
                .map_err(From::from)
        })
        .collect();

    future::join_all(reqs).map(move |_| ()).into_box()
}

// Re-encrypts private containers for a revoked app
fn reencrypt_containers_and_update_access_container(
    client: &Client<()>,
    container_names: HashSet<String>,
    revoked_app: &AppInfo,
) -> Box<AuthFuture<()>> {
    // 1. Make sure to get the latest containers info from the root dir (as it
    //    could have been updated on the previous failed revocation)
    // 2. Generate new encryption keys for all the containers to be re-encrypted.
    // 3. Update the user root dir and the access container to use the new keys.
    // 4. Perform the actual re-encryption of the containers.
    // 5. Update the user root dir and access container again, committing or aborting
    //    the encryption keys change, depending on whether the re-encryption of the
    //    corresponding container succeeded or failed.
    let c2 = client.clone();
    let c3 = client.clone();
    let c4 = client.clone();

    let ac_info = fry!(client.access_container().map_err(AuthError::from));
    let app_key = fry!(access_container::enc_key(
        &ac_info,
        &revoked_app.info.id,
        &revoked_app.keys.enc_key,
    ));

    fetch_access_container_entries(client, &ac_info, app_key.clone())
        .and_then(move |ac_entries| {
            update_access_container(
                &c2,
                ac_info.clone(),
                ac_entries,
                container_names.clone(),
                MDataInfoAction::Start,
            ).map(move |(ac_entries, containers)| {
                (ac_info, ac_entries, containers, container_names)
            })
        })
        .and_then(move |(ac_info, ac_entries, containers, container_names)| {
            reencrypt_containers(&c3, containers).map(move |_| {
                (ac_info, ac_entries, container_names)
            })
        })
        .and_then(move |(ac_info, ac_entries, container_names)| {
            update_access_container(
                &c4,
                ac_info,
                ac_entries,
                container_names,
                MDataInfoAction::Commit,
            )
        })
        .map(|_| ())
        .into_box()
}

// Fetch all entries of the access container except the one for the app being revoked
// (because it doesn't need to re-encrypted).
fn fetch_access_container_entries(
    client: &Client<()>,
    ac_info: &MDataInfo,
    revoked_app_key: Vec<u8>,
) -> Box<AuthFuture<BTreeMap<Vec<u8>, Value>>> {
    client
        .list_mdata_entries(ac_info.name, ac_info.type_tag)
        .map_err(From::from)
        .map(move |mut entries| {
            let _ = entries.remove(&revoked_app_key);
            entries
        })
        .into_box()
}

// Update `MDataInfo`s of the given containers in all the entries of the access
// container.
fn update_access_container(
    client: &Client<()>,
    ac_info: MDataInfo,
    mut ac_entries: MDataEntries,
    container_names: HashSet<String>,
    mdata_info_action: MDataInfoAction,
) -> Box<AuthFuture<(MDataEntries, Containers)>> {
    let c2 = client.clone();
    let c3 = client.clone();

    let auth_key = {
        let sk = fry!(client.secret_symmetric_key());
        fry!(access_container::enc_key(
            &ac_info,
            AUTHENTICATOR_ENTRY,
            &sk,
        ))
    };

    config::list_apps(client)
        .map(|(_, apps)| apps)
        .and_then(move |apps| {
            let mut actions = EntryActions::new();
            let mut cache = Containers::with_capacity(container_names.len());

            // Update the authenticator entry
            if let Some(raw) = ac_entries.get_mut(&auth_key) {
                let sk = c2.secret_symmetric_key()?;
                let mut decoded = access_container::decode_authenticator_entry(&raw.content, &sk)?;

                for name in &container_names {
                    if let Some(mut entry) = decoded.get_mut(name) {
                        mdata_info_action.apply(name.clone(), &mut entry, &mut cache);
                    }
                }

                raw.content = access_container::encode_authenticator_entry(&decoded, &sk)?;
                raw.entry_version += 1;
                actions = actions.update(auth_key, raw.content.clone(), raw.entry_version);
            }

            // Update apps' entries
            for app in apps.values() {
                let key = access_container::enc_key(&ac_info, &app.info.id, &app.keys.enc_key)?;

                if let Some(raw) = ac_entries.get_mut(&key) {
                    // Skip deleted entries.
                    if raw.content.is_empty() {
                        continue;
                    }

                    let mut decoded =
                        access_container::decode_app_entry(&raw.content, &app.keys.enc_key)?;

                    for name in &container_names {
                        if let Some(entry) = decoded.get_mut(name) {
                            mdata_info_action.apply(name.clone(), &mut entry.0, &mut cache);
                        }
                    }

                    raw.content = access_container::encode_app_entry(&decoded, &app.keys.enc_key)?;
                    raw.entry_version += 1;
                    actions = actions.update(key, raw.content.clone(), raw.entry_version);
                }
            }

            Ok((ac_info, ac_entries, actions, cache))
        })
        .and_then(move |(ac_info, ac_entries, actions, containers)| {
            c3.mutate_mdata_entries(ac_info.name, ac_info.type_tag, actions.into())
                .map(move |_| (ac_entries, containers))
                .map_err(From::from)
        })
        .into_box()
}

// Action to be performed on `MDataInfo` during access container update.
enum MDataInfoAction {
    // Start new enc info.
    Start,
    // Commit new enc info.
    Commit,
}

impl MDataInfoAction {
    fn apply(&self, container_name: String, mdata_info: &mut MDataInfo, cache: &mut Containers) {
        match cache.entry(container_name) {
            Entry::Occupied(entry) => {
                *mdata_info = entry.get().clone();
            }
            Entry::Vacant(entry) => {
                match *self {
                    MDataInfoAction::Start => mdata_info.start_new_enc_info(),
                    MDataInfoAction::Commit => mdata_info.commit_new_enc_info(),
                }

                let _ = entry.insert(mdata_info.clone());
            }
        }
    }
}

// Re-encrypt the given `containers` using the `new_enc_info` in the corresponding
// `MDataInfo`. Returns modified `containers` where the enc info regeneration is either
// committed or aborted, depending on if the re-encryption succeeded or failed.
fn reencrypt_containers(client: &Client<()>, containers: Containers) -> Box<AuthFuture<()>> {
    let c2 = client.clone();

    let fs = containers.into_iter().map(move |(_, mdata_info)| {
        let c3 = c2.clone();

        c2.list_mdata_entries(mdata_info.name, mdata_info.type_tag)
            .and_then(move |entries| {
                let mut actions = EntryActions::new();

                for (old_key, value) in entries {
                    // Skip deleted entries.
                    if value.content.is_empty() {
                        continue;
                    }

                    let plain_key = mdata_info.decrypt(&old_key)?;
                    let new_key = mdata_info.enc_entry_key(&plain_key)?;

                    let plain_content = mdata_info.decrypt(&value.content)?;
                    let new_content = mdata_info.enc_entry_value(&plain_content)?;

                    if old_key == new_key {
                        // The entry is already re-encrypted.
                        if value.content != new_content {
                            // It's very unlikely that the key would be already re-encrypted,
                            // but the value not. But let's handle this case anyway, just to
                            // be sure.
                            actions = actions.update(new_key, new_content, value.entry_version + 1);
                        }
                    } else {
                        // Delete the old entry with the old key and
                        // insert the re-encrypted entry with a new key
                        actions = actions.del(old_key, value.entry_version + 1).ins(
                            new_key,
                            new_content,
                            0,
                        );
                    }
                }

                Ok((mdata_info, actions))
            })
            .and_then(move |(mdata_info, actions)| {
                c3.mutate_mdata_entries(mdata_info.name, mdata_info.type_tag, actions.into())
            })
            .map_err(From::from)
    });

    future::join_all(fs).map(|_| ()).into_box()
}
