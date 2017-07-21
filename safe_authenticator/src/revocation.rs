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

use super::{AccessContainerEntry, AuthError, AuthFuture};
use access_container::{access_container, access_container_entry, access_container_key,
                       delete_access_container_entry};
use config;
use futures::{Future, future};
use ipc::AppInfo;
use maidsafe_utilities::serialisation::{deserialise, serialise};
use routing::{EntryActions, User};
use rust_sodium::crypto::sign;
use safe_core::{Client, FutureExt, MDataInfo};
use safe_core::ipc::IpcError;
use safe_core::recovery;
use safe_core::utils::{symmetric_decrypt, symmetric_encrypt};

/// Revoke app access
pub fn revoke_app(client: &Client<()>, app_id: &str) -> Box<AuthFuture<String>> {
    let c2 = client.clone();
    let c3 = client.clone();
    let c4 = client.clone();
    let c5 = client.clone();
    let c6 = client.clone();
    let c7 = client.clone();

    config::get_app(client, app_id)
        .and_then(move |app| delete_app_auth_key(&c2, app.keys.sign_pk).map(move |_| app))
        .and_then(move |app| {
                      access_container(&c3).map(move |access_container| (app, access_container))
                  })
        .and_then(move |(app, access_container)| {
            access_container_entry(&c4, &access_container, &app.info.id, app.keys.clone())
                .and_then(move |(version, permissions)| {
                              Ok((app,
                                  access_container,
                                  version,
                                  permissions
                                      .ok_or(AuthError::IpcError(IpcError::UnknownApp))?))
                          })
        })
        .and_then(move |(app, access_container, version, permissions)| {
                      delete_access_container_entry(&c5,
                                                    &access_container,
                                                    &app.info.id,
                                                    &app.keys,
                                                    version + 1)
                              .map(move |_| (app, access_container, permissions))
                  })
        .and_then(move |(app, access_container, permissions)| {
                      revoke_container_perms(&c6, &permissions, app.keys.sign_pk)
                          .map(move |_| (app, access_container, permissions))
                  })
        .and_then(move |(app, access_container, permissions)| {
                      reencrypt_private_containers(&c7, access_container, permissions, &app)
                          .map(move |_| app.info.id)
                  })
        .into_box()
}

// Delete the app's auth key from the MaidManager - this prevents the app from
// performing any more mutations.
fn delete_app_auth_key(client: &Client<()>, key: sign::PublicKey) -> Box<AuthFuture<()>> {
    let client = client.clone();

    client
        .list_auth_keys_and_version()
        .and_then(move |(_, version)| client.del_auth_key(key, version + 1))
        .map_err(From::from)
        .into_box()
}

// Revokes containers permissions
fn revoke_container_perms(client: &Client<()>,
                          permissions: &AccessContainerEntry,
                          sign_pk: sign::PublicKey)
                          -> Box<AuthFuture<()>> {
    let reqs: Vec<_> = permissions
        .values()
        .map(|&(ref mdata_info, _)| {
            let mdata_info = mdata_info.clone();
            let c2 = client.clone();

            client
                .clone()
                .get_mdata_version(mdata_info.name, mdata_info.type_tag)
                .and_then(move |version| {
                              recovery::del_mdata_user_permissions(&c2,
                                                                   mdata_info.name,
                                                                   mdata_info.type_tag,
                                                                   User::Key(sign_pk),
                                                                   version + 1)
                          })
                .map_err(From::from)
        })
        .collect();

    future::join_all(reqs).map(move |_| ()).into_box()
}

// Re-encrypts private containers for a revoked app
fn reencrypt_private_containers(client: &Client<()>,
                                access_container: MDataInfo,
                                containers: AccessContainerEntry,
                                revoked_app: &AppInfo)
                                -> Box<AuthFuture<()>> {
    // 1. Generate new encryption keys for all the containers to be reencrypted.
    // 2. Update the user root dir and the access container to use the new keys.
    // 3. Perform the actual reencryption of the containers.
    // 4. Update the user root dir and access container again, commiting or aborting
    //    the encryption keys change, depending on whether the re-encryption of the
    //    corresponding container succeeded or failed.

    let c2 = client.clone();
    let c3 = client.clone();

    let containers = start_new_containers_enc_info(containers);
    let app_key =
        fry!(access_container_key(&access_container, &revoked_app.info.id, &revoked_app.keys));

    let f0 = update_user_root_dir(client, containers.clone());
    let f1 = update_access_container(client,
                                     access_container.clone(),
                                     containers.clone(),
                                     app_key.clone());

    f0.join(f1)
        .and_then(move |_| reencrypt_containers(&c2, containers))
        .and_then(move |containers| {
                      let f0 = update_user_root_dir(&c3, containers.clone());
                      let f1 = update_access_container(&c3, access_container, containers, app_key);

                      f0.join(f1).map(|_| ())
                  })
        .into_box()
}

fn start_new_containers_enc_info(containers: AccessContainerEntry) -> Vec<(String, MDataInfo)> {
    containers
        .into_iter()
        .map(|(container, (mut mdata_info, _))| {
                 mdata_info.start_new_enc_info();
                 (container, mdata_info)
             })
        .collect()
}

fn update_user_root_dir(client: &Client<()>,
                        containers: Vec<(String, MDataInfo)>)
                        -> Box<AuthFuture<()>> {
    let c2 = client.clone();
    let user_root = fry!(client.user_root_dir());

    client
        .list_mdata_entries(user_root.name, user_root.type_tag)
        .and_then(move |entries| {
            let mut actions = EntryActions::new();

            for (container, mdata_info) in containers {
                let key = user_root.enc_entry_key(container.as_bytes())?;
                let encoded = serialise(&mdata_info)?;
                let encoded = user_root.enc_entry_value(&encoded)?;

                if let Some(old_value) = entries.get(&key) {
                    actions = actions.update(key, encoded, old_value.entry_version + 1);
                } else {
                    actions = actions.ins(key, encoded, 0);
                }
            }

            Ok((user_root, actions))
        })
        .and_then(move |(user_root, actions)| {
                      recovery::mutate_mdata_entries(&c2,
                                                     user_root.name,
                                                     user_root.type_tag,
                                                     actions.into())
                  })
        .map_err(From::from)
        .into_box()
}

fn update_access_container(client: &Client<()>,
                           access_container: MDataInfo,
                           mut containers: Vec<(String, MDataInfo)>,
                           revoked_app_key: Vec<u8>)
                           -> Box<AuthFuture<()>> {
    let c2 = client.clone();

    let f_config = config::list_apps(client).map(|(_, apps)| apps);
    let f_entries = client
        .list_mdata_entries(access_container.name, access_container.type_tag)
        .map_err(From::from)
        .map(move |mut entries| {
                 // Remove the revoked app entry from the access container
                 // because we don't need it to be reencrypted.
                 let _ = entries.remove(&revoked_app_key);
                 entries
             });

    f_config
        .join(f_entries)
        .and_then(move |(apps, entries)| {
            let mut actions = EntryActions::new();

            for app in apps.values() {
                let key = access_container_key(&access_container, &app.info.id, &app.keys)?;

                if let Some(raw) = entries.get(&key) {
                    // Skip deleted entries.
                    if raw.content.is_empty() {
                        continue;
                    }

                    let decoded = symmetric_decrypt(&raw.content, &app.keys.enc_key)?;
                    let mut decoded: AccessContainerEntry = deserialise(&decoded)?;

                    for &mut (ref container, ref mdata_info) in &mut containers {
                        if let Some(entry) = decoded.get_mut(container) {
                            entry.0 = mdata_info.clone();
                        }
                    }

                    let encoded = serialise(&decoded)?;
                    let encoded = symmetric_encrypt(&encoded, &app.keys.enc_key, None)?;

                    actions = actions.update(key, encoded, raw.entry_version + 1);
                }
            }

            Ok((access_container, actions))
        })
        .and_then(move |(access_container, actions)| {
                      recovery::mutate_mdata_entries(&c2,
                                                     access_container.name,
                                                     access_container.type_tag,
                                                     actions.into())
                              .map_err(From::from)
                  })
        .into_box()
}

// Re-encrypt the given `containers` using the `new_enc_info` in the corresponding
// `MDataInfo`. Returns modified `containers` where the enc info regeneration is either
// commited or aborted, depending on if the re-encryption succeeded or failed.
fn reencrypt_containers(client: &Client<()>,
                        containers: Vec<(String, MDataInfo)>)
                        -> Box<AuthFuture<Vec<(String, MDataInfo)>>> {
    let c2 = client.clone();
    let fs = containers
        .into_iter()
        .map(move |(container, mdata_info)| {
            let mut mdata_info2 = mdata_info.clone();
            let c3 = c2.clone();

            c2.list_mdata_entries(mdata_info.name, mdata_info.type_tag)
                .and_then(move |entries| {
                    let mut actions = EntryActions::new();

                    for (old_key, value) in entries {
                        // Skip deleted entries.
                        if value.content.is_empty() {
                            continue;
                        }

                        let new_key = mdata_info.reencrypt_entry_key(&old_key)?;
                        let new_content = mdata_info.reencrypt_entry_value(&value.content)?;

                        // Delete the old entry with the old key and
                        // insert the re-encrypted entry with a new key
                        actions = actions
                            .del(old_key, value.entry_version + 1)
                            .ins(new_key, new_content, 0);
                    }

                    Ok((mdata_info, actions))
                })
                .and_then(move |(mdata_info, actions)| {
                              recovery::mutate_mdata_entries(&c3,
                                                             mdata_info.name,
                                                             mdata_info.type_tag,
                                                             actions.into())
                                      .map_err(From::from)
                          })
                .then(move |res| {
                    // If the mutation succeeded, commit the enc_info regeneration,
                    // otherwise abort it.

                    if res.is_ok() {
                        mdata_info2.commit_new_enc_info();
                    } else {
                        // TODO: consider logging the error.
                        mdata_info2.abort_new_enc_info();
                    }

                    Ok((container, mdata_info2))
                })
        });

    future::join_all(fs).into_box()
}
