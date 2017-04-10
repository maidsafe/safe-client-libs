// Copyright 2016 MaidSafe.net limited.
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

use AuthFuture;
use errors::AuthError;
use futures::{Future, IntoFuture};
use maidsafe_utilities::serialisation::serialise;
use routing::{ClientError, EntryActions, MutableData, XorName};
use rust_sodium::crypto::hash::sha256;
use safe_core::{Client, CoreError, FutureExt, MDataInfo, PUBLIC_ID_TAG};

// TODO: could we use the same value for both of these?
const PUBLIC_ID_USER_ROOT_ENTRY_KEY: &'static [u8] = b"_publicId";
const PUBLIC_ID_CONFIG_ROOT_ENTRY_KEY: &'static [u8] = b"public-id";

/// Create mutable data for Public ID.
pub fn create<T: Into<String>>(client: &Client, public_id: T) -> Box<AuthFuture<()>> {
    // TODO: This could be optimized by executing the operations in parallel.
    // The operations to parallelise are:
    //     1. Insert the Public ID mdata info into the user root.
    //     2. Put the Public ID mdata onto the network.
    //     3. Insert the Public ID name into the config root.
    // However, care must be taken to properly handle failure - that is, if at least
    // one of the above operations fails, the others must be undone.

    let client2 = client.clone();
    let client3 = client.clone();
    let client4 = client.clone();
    let client5 = client.clone();
    let client6 = client.clone();

    let public_id = public_id.into();
    let name = XorName(sha256::hash(public_id.as_bytes()).0);

    client.user_root_dir()
        .and_then(|user_root_dir| {
            let owner_key = client.owner_key()?;
            let key = user_root_dir.enc_entry_key(PUBLIC_ID_USER_ROOT_ENTRY_KEY)?;

            Ok((owner_key, user_root_dir, key))
        })
        .map_err(AuthError::from)
        .into_future()
        // Check that the public id doesn't exist yet.
        .and_then(move |(owner_key, user_root_dir, key)| {
            client2.get_mdata_value(user_root_dir.name, user_root_dir.type_tag, key.clone())
                .then(move |res| {
                    match res {
                        Ok(_) => Err(AuthError::PublicIdExists),
                        Err(CoreError::RoutingClientError(ClientError::NoSuchEntry)) => {
                            Ok((owner_key, user_root_dir, key))
                        }
                        Err(err) => Err(AuthError::from(err)),
                    }
                })
        })
        // Create the mutable data and mdata info for the public id.
        .and_then(move |(owner_key, user_root_dir, key)| {
            let info = MDataInfo::new_public(name, PUBLIC_ID_TAG);
            let data = MutableData::new(info.name,
                                        info.type_tag,
                                        Default::default(),
                                        Default::default(),
                                        btree_set![owner_key]).map_err(CoreError::from)
                .map_err(AuthError::from)?;

            Ok((user_root_dir, key, info, data))
        })
        // Put the public id mutable data onto the network.
        .and_then(move |(user_root_dir, key, info, data)| {
            client3.put_mdata(data)
                .map(move |_| (user_root_dir, key, info))
                .map_err(From::from)
        })
        // Insert the public id mdata info into the user root.
        .and_then(|(user_root_dir, key, info)| {
            let value = serialise(&info)?;
            let value = user_root_dir.enc_entry_value(&value)?;

            Ok((user_root_dir, key, value))
        })
        .and_then(move |(user_root_dir, key, value)| {
            let actions = EntryActions::new()
                .ins(key, value, 0)
                .into();
            client4.mutate_mdata_entries(user_root_dir.name, user_root_dir.type_tag, actions)
                .map_err(From::from)
        })
        // Insert the public id name into the config root.
        .and_then(move |_| {
            let config_root_dir = client5.config_root_dir()?;
            let key = config_root_dir.enc_entry_key(PUBLIC_ID_CONFIG_ROOT_ENTRY_KEY)?;
            let value = config_root_dir.enc_entry_value(public_id.as_bytes())?;

            Ok((config_root_dir, key, value))
        })
        .and_then(move |(config_root_dir, key, value)| {
            let actions = EntryActions::new()
                .ins(key, value, 0)
                .into();
            client6.mutate_mdata_entries(config_root_dir.name, config_root_dir.type_tag, actions)
                .map_err(From::from)
        })
        .into_box()
}

/// Retrieve the Public ID string.
pub fn get(client: &Client) -> Box<AuthFuture<String>> {
    let client = client.clone();

    client
        .config_root_dir()
        .and_then(|config_root_dir| {
                      let key = config_root_dir
                          .enc_entry_key(PUBLIC_ID_CONFIG_ROOT_ENTRY_KEY)?;
                      Ok((config_root_dir, key))
                  })
        .map_err(AuthError::from)
        .into_future()
        .and_then(move |(config_root_dir, key)| {
            client
                .get_mdata_value(config_root_dir.name, config_root_dir.type_tag, key)
                .map_err(|err| match err {
                             CoreError::RoutingClientError(ClientError::NoSuchEntry) => {
                                 AuthError::NoSuchPublicId
                             }
                             _ => AuthError::from(err),
                         })
                .map(move |value| (config_root_dir, value))
        })
        .and_then(|(config_root_dir, value)| {
                      let value = config_root_dir.decrypt(&value.content)?;
                      let value = String::from_utf8(value)?;

                      Ok(value)
                  })
        .into_box()
}
