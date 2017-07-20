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
use access_container::{access_container, access_container_entry, access_container_nonce,
                       delete_access_container_entry};
use futures::{Future, future};
use ipc::{app_info, get_config};
use maidsafe_utilities::serialisation::{deserialise, serialise};
use routing::{EntryActions, User, Value};
use rust_sodium::crypto::sign;
use safe_core::{Client, FutureExt, MDataInfo};
use safe_core::ipc::{IpcError, access_container_enc_key};
use safe_core::utils::{symmetric_decrypt, symmetric_encrypt};
use std::collections::BTreeMap;

/// Revoke app access
pub fn revoke_app(client: &Client<()>, app_id: &str) -> Box<AuthFuture<String>> {
    let c2 = client.clone();
    let c3 = client.clone();
    let c4 = client.clone();
    let c5 = client.clone();
    let c6 = client.clone();
    let c7 = client.clone();
    let c8 = client.clone();

    app_info(client, app_id)
        .and_then(move |app| Ok(app.ok_or(AuthError::IpcError(IpcError::UnknownApp))?))
        .and_then(move |app| delete_app_auth_key(&c2, app.keys.sign_pk).map(move |_| app))
        .and_then(move |app| {
                      access_container(&c3).map(move |access_container| (app, access_container))
                  })
        .and_then(move |(app, access_container)| {
            // Get an access container entry for the app being revoked
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
                    .map(move |app_entry_name| (app, access_container, permissions, app_entry_name))
        })
        .and_then(move |(app, access_container, permissions, app_entry_name)| {
                      // Remove app key from container permissions
                      revoke_container_perms(&c6, &permissions, app.keys.sign_pk)
                          .map(move |_| (app, access_container, permissions, app_entry_name))
                  })
        .and_then(move |(app, access_container, permissions, app_entry_name)| {
            // Re-encrypt private containers
            c7.list_mdata_entries(access_container.name, access_container.type_tag)
                .map_err(From::from)
                .map(move |mut entries| {
                         // Remove the revoked app entry from the access container
                         // because we don't need it to be reencrypted.
                         let _ = entries.remove(&app_entry_name);
                         (app, access_container, permissions, entries)
                     })
        })
        .and_then(move |(app, access_container, permissions, entries)| {
                      reencrypt_private_containers(&c8, permissions, access_container, entries)
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
                              c2.del_mdata_user_permissions(mdata_info.name,
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
                                permissions: AccessContainerEntry,
                                access_cont: MDataInfo,
                                access_cont_entries: BTreeMap<Vec<u8>, Value>)
                                -> Box<AuthFuture<()>> {
    let mut reqs = Vec::new();
    let c2 = client.clone();
    let c3 = client.clone();
    let c4 = client.clone();
    let c5 = client.clone();

    for (container, (mdata_info, _)) in permissions {
        // Check if the container is encrypted
        if mdata_info.enc_info.is_some() {
            let c3 = client.clone();
            let old_mdata = mdata_info.clone();
            let mut new_mdata = fry!(MDataInfo::random_private(mdata_info.type_tag));
            new_mdata.name = mdata_info.name;

            reqs.push(c2.list_mdata_entries(mdata_info.name, mdata_info.type_tag)
                          .and_then(move |entries| {
                let mut mutations = EntryActions::new();

                for (old_key, val) in entries {
                    // Skip deleted entries.
                    // TODO: we need more robust way to detect deleted entries.
                    if val.content.is_empty() {
                        continue;
                    }

                    let key = old_mdata.decrypt(&old_key)?;
                    let content = old_mdata.decrypt(&val.content)?;

                    let new_key = new_mdata.enc_entry_key(&key)?;
                    let new_content = new_mdata.enc_entry_value(&content)?;

                    // Delete the old entry with the old key and
                    // insert the re-encrypted entry with a new key
                    mutations = mutations
                        .del(old_key, val.entry_version + 1)
                        .ins(new_key, new_content, 0);
                }

                Ok((new_mdata, mutations))
            })
                          .and_then(move |(new_mdata, mutations)| {
                                        c3.mutate_mdata_entries(new_mdata.name,
                                                                new_mdata.type_tag,
                                                                mutations.into())
                                            .map_err(From::from)
                                            .map(move |_| (container, new_mdata))
                                    })
                          .map_err(From::from));
        }
    }

    future::join_all(reqs)
        .and_then(move |updated_containers| {
                      get_config(&c3).map(move |(_ver, config)| (config, updated_containers))
                  })
        .and_then(move |(config, updated_containers)| {
            // Updating user root container with new MDataInfo
            let user_root = fry!(c4.user_root_dir());
            let mut reqs = Vec::new();

            for &(ref container, ref new_mdata) in &updated_containers {
                let entry_name = fry!(user_root.enc_entry_key(container.as_bytes()));

                let plaintext = fry!(serialise(new_mdata));
                let new_content = fry!(user_root.enc_entry_value(&plaintext));

                reqs.push(c4.clone()
                              .get_mdata_value(user_root.name,
                                               user_root.type_tag,
                                               entry_name.clone())
                              .map(move |value| {
                                       (entry_name, value.entry_version, new_content)
                                   }));
            }

            let c5 = c4.clone();

            future::join_all(reqs)
                .and_then(move |values| {
                    let mut mutations = EntryActions::new();
                    for (key, version, new_content) in values {
                        mutations = mutations.update(key, new_content, version + 1);
                    }
                    c5.mutate_mdata_entries(user_root.name, user_root.type_tag, mutations.into())
                })
                .map_err(From::from)
                .map(move |_| (config, updated_containers))
                .into_box()
        })
        .and_then(move |(config, updated_containers)| {
            // Updating the access container to give apps access to the re-encrypted MData
            let mut mutations = EntryActions::new();

            for app in config.values() {
                let nonce = fry!(access_container_nonce(&access_cont));
                let entry_name =
                    fry!(access_container_enc_key(&app.info.id, &app.keys.enc_key, nonce));

                if let Some(raw) = access_cont_entries.get(&entry_name) {
                    if raw.content.is_empty() {
                        continue;
                    }

                    let plaintext = fry!(symmetric_decrypt(&raw.content, &app.keys.enc_key));
                    let mut access_cont_entry =
                        fry!(deserialise::<AccessContainerEntry>(&plaintext));

                    for &(ref container, ref new_mdata) in &updated_containers {
                        if let Some(entry) = access_cont_entry.get_mut(container) {
                            let perms = {
                                let &mut (_, ref perms) = entry;
                                perms.clone()
                            };
                            *entry = (new_mdata.clone(), perms);
                        }
                    }

                    let updated_plaintext = fry!(serialise(&access_cont_entry));
                    let ciphertext =
                        fry!(symmetric_encrypt(&updated_plaintext, &app.keys.enc_key, None));

                    mutations = mutations.update(entry_name, ciphertext, raw.entry_version + 1);
                }
            }

            c5.mutate_mdata_entries(access_cont.name, access_cont.type_tag, mutations.into())
                .map_err(From::from)
                .into_box()
        })
        .into_box()
}
