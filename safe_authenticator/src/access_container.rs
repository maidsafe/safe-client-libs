// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net
// Commercial License, version 1.0 or later, or (2) The General Public License
// (GPL), version 3, depending on which licence you accepted on initial access
// to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project
// generally, you agree to be bound by the terms of the MaidSafe Contributor
// Agreement, version 1.0.
// This, along with the Licenses can be found in the root directory of this
// project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network
// Software distributed under the GPL Licence is distributed on an "AS IS"
// BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
//
// Please review the Licences for the specific language governing permissions
// and limitations relating to use of the SAFE Network Software.

use super::{AccessContainerEntry, AuthError, AuthFuture};
use futures::Future;
use maidsafe_utilities::serialisation::{deserialise, serialise};
use routing::EntryActions;
use rust_sodium::crypto::secretbox;
use safe_core::{Client, FutureExt, MDataInfo};
use safe_core::ipc::AppKeys;
use safe_core::ipc::resp::access_container_enc_key;
use safe_core::utils::{symmetric_decrypt, symmetric_encrypt};

/// Retrieves the authenticator configuration file
pub fn access_container(client: &Client) -> Box<AuthFuture<MDataInfo>> {
    let parent = fry!(client.config_root_dir());
    let key = fry!(parent.enc_entry_key(b"access-container"));

    client.get_mdata_value(parent.name, parent.type_tag, key)
        .map_err(From::from)
        .and_then(move |val| {
                      let content = parent.decrypt(&val.content)?;
                      deserialise(&content).map_err(From::from)
                  })
        .into_box()
}

/// Gets the nonce from the access container mdata info.
pub fn access_container_nonce(access_container: &MDataInfo)
                              -> Result<&secretbox::Nonce, AuthError> {
    if let Some((_, Some(ref nonce))) = access_container.enc_info {
        Ok(nonce)
    } else {
        // No valid nonce for the MDataInfo could be found
        Err(AuthError::from("No valid nonce for access container"))
    }
}

/// Gets an access container entry
pub fn access_container_entry(client: &Client,
                              access_container: &MDataInfo,
                              app_id: &str,
                              app_keys: AppKeys)
                              -> Box<AuthFuture<(u64, AccessContainerEntry)>> {
    let nonce = fry!(access_container_nonce(access_container));
    let key = fry!(access_container_enc_key(app_id, &app_keys.enc_key, nonce));

    client.get_mdata_value(access_container.name, access_container.type_tag, key)
        .and_then(move |value| {
                      let plaintext = symmetric_decrypt(&value.content, &app_keys.enc_key)?;
                      Ok((value.entry_version, deserialise(&plaintext)?))
                  })
        .map_err(From::from)
        .into_box()
}

/// Adds a new entry to the authenticator access container
pub fn put_access_container_entry(client: &Client,
                                  access_container: &MDataInfo,
                                  app_id: &str,
                                  app_keys: &AppKeys,
                                  permissions: &AccessContainerEntry,
                                  version: Option<u64>)
                                  -> Box<AuthFuture<()>> {
    let nonce = fry!(access_container_nonce(access_container));
    let key = fry!(access_container_enc_key(app_id, &app_keys.enc_key, nonce));
    let plaintext = fry!(serialise(&permissions));
    let ciphertext = fry!(symmetric_encrypt(&plaintext, &app_keys.enc_key, None));

    let actions = if let Some(version) = version {
        EntryActions::new().update(key, ciphertext, version)
    } else {
        EntryActions::new().ins(key, ciphertext, 0)
    };

    client.mutate_mdata_entries(access_container.name,
                                access_container.type_tag,
                                actions.into())
        .map_err(From::from)
        .into_box()
}
