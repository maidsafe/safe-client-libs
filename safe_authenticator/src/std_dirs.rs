// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::access_container::{self, AUTHENTICATOR_ENTRY};
use crate::client::AuthClient;
use crate::config::KEY_APPS;
use futures::{future, Future};
use maidsafe_utilities::serialisation::serialise;
use routing::{ClientError, Value};
use safe_core::ipc::access_container_enc_key;
use safe_core::mdata_info;
use safe_core::nfs::create_dir;
use safe_core::utils::symmetric_encrypt;
use safe_core::{Client, CoreError, FutureExt, MDataInfo, DIR_TAG};
use std::collections::HashMap;
use crate::{AuthError, AuthFuture};

/// Default directories to be created at registration.
pub static DEFAULT_PRIVATE_DIRS: [&'static str; 6] = [
    "_documents",
    "_downloads",
    "_music",
    "_pictures",
    "_videos",
    "_publicNames",
];

/// Publicly accessible default directories to be created upon registration.
pub static DEFAULT_PUBLIC_DIRS: [&'static str; 1] = ["_public"];

/// Create the root directories and the standard directories for the access container.
pub fn create(client: &AuthClient) -> Box<AuthFuture<()>> {
    let c2 = client.clone();
    let c3 = client.clone();
    let c4 = client.clone();

    // Initialise standard directories
    let access_container = client.access_container();
    let config_dir = client.config_root_dir();

    // Try to get default dirs from the access container
    let access_cont_fut = access_container::fetch_authenticator_entry(&c2)
        .then(move |res| {
            match res {
                Ok((_, default_containers)) => {
                    // Make sure that all default dirs have been created
                    create_std_dirs(&c3, &default_containers)
                }
                Err(AuthError::CoreError(CoreError::RoutingClientError(
                    ClientError::NoSuchData,
                ))) => {
                    // Access container hasn't been created yet
                    let access_cont_value = fry!(random_std_dirs())
                        .into_iter()
                        .map(|(name, md_info)| (String::from(name), md_info))
                        .collect();
                    let std_dirs_fut = create_std_dirs(&c3, &access_cont_value);
                    let access_cont_fut =
                        create_access_container(&c3, &access_container, &access_cont_value);

                    future::join_all(vec![std_dirs_fut, access_cont_fut])
                        .map(|_| ())
                        .into_box()
                }
                Err(e) => err!(e),
            }
        }).into_box();

    future::join_all(vec![access_cont_fut, create_config_dir(&c2, &config_dir)])
        .map_err(From::from)
        .and_then(move |_| {
            // Update account packet - root directories have been created successfully
            // (so we don't have to recover them after login).
            c4.set_std_dirs_created(true);
            c4.update_account_packet().map_err(From::from).into_box()
        }).into_box()
}

fn create_config_dir(client: &AuthClient, config_dir: &MDataInfo) -> Box<AuthFuture<()>> {
    let config_dir_entries =
        btree_map![KEY_APPS.to_vec() => Value { content: Vec::new(), entry_version: 0 }];

    let config_dir_entries = fry!(mdata_info::encrypt_entries(config_dir, &config_dir_entries));

    create_dir(client, config_dir, config_dir_entries, btree_map![])
        .map_err(From::from)
        .into_box()
}

fn create_access_container(
    client: &AuthClient,
    access_container: &MDataInfo,
    default_entries: &HashMap<String, MDataInfo>,
) -> Box<AuthFuture<()>> {
    let enc_key = fry!(
        client
            .secret_symmetric_key()
            .ok_or_else(|| AuthError::Unexpected("Secret symmetric key not found".to_string()))
    );

    // Create access container
    let authenticator_key = fry!(
        access_container_enc_key(
            AUTHENTICATOR_ENTRY,
            &enc_key,
            fry!(access_container.nonce().ok_or_else(|| AuthError::from(
                "Expected to have nonce on access container MDataInfo"
            ))),
        ).map_err(AuthError::from)
    );
    let access_cont_value = fry!(symmetric_encrypt(
        &fry!(serialise(default_entries)),
        &enc_key,
        None,
    ));

    create_dir(
        client,
        access_container,
        btree_map![
            authenticator_key => Value { entry_version: 0, content: access_cont_value }
        ],
        btree_map![],
    ).map_err(From::from)
    .into_box()
}

/// Generates a list of `MDataInfo` for standard dirs.
/// Returns a collection of standard dirs along with respective `MDataInfo`s.
/// Doesn't actually put data onto the network.
pub fn random_std_dirs() -> Result<Vec<(&'static str, MDataInfo)>, CoreError> {
    let pub_dirs = DEFAULT_PUBLIC_DIRS
        .iter()
        .map(|name| MDataInfo::random_public(DIR_TAG).map(|dir| (*name, dir)));
    let priv_dirs = DEFAULT_PRIVATE_DIRS
        .iter()
        .map(|name| MDataInfo::random_private(DIR_TAG).map(|dir| (*name, dir)));
    priv_dirs.chain(pub_dirs).collect()
}

/// A registration helper function to create the set of default dirs in the users root directory.
pub fn create_std_dirs(
    client: &AuthClient,
    md_infos: &HashMap<String, MDataInfo>,
) -> Box<AuthFuture<()>> {
    let client = client.clone();
    let creations: Vec<_> = md_infos
        .iter()
        .map(|(_, md_info)| {
            create_dir(&client, md_info, btree_map![], btree_map![]).map_err(AuthError::from)
        }).collect();
    future::join_all(creations).map(|_| ()).into_box()
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::Future;
    use crate::test_utils::{create_account_and_login, run};

    // Test creation of default dirs.
    #[test]
    fn creates_default_dirs() {
        let auth = create_account_and_login();

        run(&auth, |client| {
            let client = client.clone();

            create_std_dirs(
                &client,
                &unwrap!(random_std_dirs())
                    .into_iter()
                    .map(|(k, v)| (k.to_owned(), v))
                    .collect(),
            ).then(move |res| {
                assert!(res.is_ok());

                access_container::fetch_authenticator_entry(&client)
            }).then(move |res| {
                let (_, mdata_entries) = unwrap!(res);
                assert_eq!(
                    mdata_entries.len(),
                    DEFAULT_PUBLIC_DIRS.len() + DEFAULT_PRIVATE_DIRS.len()
                );

                for key in DEFAULT_PUBLIC_DIRS
                    .iter()
                    .chain(DEFAULT_PRIVATE_DIRS.iter())
                {
                    // let's check whether all our entries have been created properly
                    assert!(mdata_entries.contains_key(*key));
                }

                Ok(())
            })
        });
    }
}
