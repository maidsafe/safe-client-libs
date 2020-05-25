// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    access_container::{self, AUTHENTICATOR_ENTRY},
    client::AuthClient,
    config::KEY_APPS,
    AuthError,
};
use bincode::serialize;
use safe_core::{
    btree_map, core_structs::access_container_enc_key, mdata_info, nfs::create_directory,
    utils::symmetric_encrypt, Client, CoreError, MDataInfo, DIR_TAG,
};
use safe_nd::{Error as SndError, MDataKind, MDataSeqValue};
use std::collections::HashMap;

/// Default directories to be created at registration.
pub static DEFAULT_PRIVATE_DIRS: [&str; 6] = [
    "_documents",
    "_downloads",
    "_music",
    "_pictures",
    "_videos",
    "_publicNames",
];

/// Publicly accessible default directories to be created upon registration.
pub static DEFAULT_PUBLIC_DIRS: [&str; 1] = ["_public"];

/// Create the root directories and the standard directories for the access container.
pub async fn create(client: &AuthClient) -> Result<(), AuthError> {
    // Initialise standard directories
    let access_container = client.access_container().await;
    let config_dir = client.config_root_dir().await;

    // Try to get default dirs from the access container
    let res = access_container::fetch_authenticator_entry(&client).await;
    let _access_cont = match res {
        Ok((_, default_containers)) => {
            // Make sure that all default dirs have been created
            create_std_dirs(&client, &default_containers).await
        }
        Err(AuthError::CoreError(CoreError::DataError(SndError::NoSuchData))) => {
            // Access container hasn't been created yet
            let access_cont_value = random_std_dirs()?
                .into_iter()
                .map(|(name, md_info)| (String::from(name), md_info))
                .collect();
            create_std_dirs(&client, &access_cont_value).await?;
            create_access_container(&client, &access_container, &access_cont_value).await?;

            Ok(())
        }
        Err(e) => Err(e),
    };

    create_config_dir_on_network(&client, &config_dir).await?;

    // Update account packet - root directories have been created successfully
    // (so we don't have to recover them after login).
    client.set_std_dirs_created(true).await;
    client.update_account_packet().await.map_err(From::from)
}

async fn create_config_dir_on_network(
    client: &AuthClient,
    config_dir: &MDataInfo,
) -> Result<(), AuthError> {
    let config_dir_entries =
        btree_map![KEY_APPS.to_vec() => MDataSeqValue { data: Vec::new(), version: 0 }];

    let config_dir_entries = mdata_info::encrypt_entries(config_dir, &config_dir_entries)?;

    create_directory(client, config_dir, config_dir_entries, btree_map![])
        .await
        .map_err(From::from)
}

async fn create_access_container(
    client: &AuthClient,
    access_container: &MDataInfo,
    default_entries: &HashMap<String, MDataInfo>,
) -> Result<(), AuthError> {
    let enc_key = client.secret_symmetric_key().await;

    let access_container_nonce = access_container
        .nonce()
        .ok_or_else(|| AuthError::from("Expected to have nonce on access container MDataInfo"))?;
    // Create access container
    let authenticator_key =
        access_container_enc_key(AUTHENTICATOR_ENTRY, &enc_key, access_container_nonce)?;

    let access_cont_value = symmetric_encrypt(&serialize(default_entries)?, &enc_key, None)?;

    create_directory(
        client,
        access_container,
        btree_map![
            authenticator_key => MDataSeqValue { version: 0, data: access_cont_value }
        ],
        btree_map![],
    )
    .await
    .map_err(From::from)
}

/// Generates a list of `MDataInfo` for standard dirs.
/// Returns a collection of standard dirs along with respective `MDataInfo`s.
/// Doesn't actually put data onto the network.
pub fn random_std_dirs() -> Result<Vec<(&'static str, MDataInfo)>, CoreError> {
    let pub_dirs = DEFAULT_PUBLIC_DIRS
        .iter()
        .map(|name| MDataInfo::random_public(MDataKind::Seq, DIR_TAG).map(|dir| (*name, dir)));
    let priv_dirs = DEFAULT_PRIVATE_DIRS
        .iter()
        .map(|name| MDataInfo::random_private(MDataKind::Seq, DIR_TAG).map(|dir| (*name, dir)));
    priv_dirs.chain(pub_dirs).collect()
}

/// A registration helper function to create the set of default dirs in the users root directory.
#[allow(clippy::implicit_hasher)]
pub async fn create_std_dirs(
    client: &AuthClient,
    md_infos: &HashMap<String, MDataInfo>,
) -> Result<(), AuthError> {
    let client = client.clone();

    for md_info in md_infos.values() {
        create_directory(&client, md_info, btree_map![], btree_map![]).await?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::create_account_and_login;
    use unwrap::unwrap;

    // Test creation of default dirs.
    #[tokio::test]
    async fn creates_default_dirs() -> Result<(), AuthError> {
        let auth = create_account_and_login().await;
        let client = auth.client;

        let _ = create_std_dirs(
            &client,
            &unwrap!(random_std_dirs())
                .into_iter()
                .map(|(k, v)| (k.to_owned(), v))
                .collect(),
        )
        .await?;

        let (_, mdata_entries) = access_container::fetch_authenticator_entry(&client).await?;
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
    }
}
