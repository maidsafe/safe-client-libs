// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! Routines to handle an app's dedicated containers.

use crate::access_container;
use crate::client::AuthClient;
use crate::{AuthError, AuthFuture};
use futures::Future;
// use futures_util::future::TryFutureExt;
use futures_util::future::FutureExt;
use safe_core::btree_map;
use safe_core::{app_container_name, Client, MDataInfo, DIR_TAG};
use safe_nd::{
    MDataAction, MDataKind, MDataPermissionSet, MDataSeqEntries, MDataSeqEntryActions, PublicKey,
};

use safe_core::CoreError;

use log::trace;
use safe_nd::{Error as SndError, SeqMutableData};
use std::collections::BTreeMap;

/// Returns an app's dedicated container if available and stored in the access container,
/// `None` otherwise.
#[cfg(any(test, feature = "testing"))]
pub async fn fetch(client: &AuthClient, app_id: &str) -> Result<Option<MDataInfo>, AuthError> {
    let app_cont_name = app_container_name(app_id);

    let (_, mut ac_entries) = access_container::fetch_authenticator_entry(client).await?;
    // .and_then(move |(_, mut ac_entries)|
    Ok(ac_entries.remove(&app_cont_name))
    // )
    // .into_box()
}

/// Checks if an app's dedicated container is available and stored in the access container.
/// If no previously created container has been found, then it will be created.
pub async fn fetch_or_create(
    client: &AuthClient,
    app_id: &str,
    app_pk: PublicKey,
) -> Result<MDataInfo, AuthError> {
    let c2 = client.clone();
    let c3 = client.clone();
    let app_cont_name = app_container_name(app_id);

    let (ac_entry_version, mut ac_entries) =
        access_container::fetch_authenticator_entry(client).await?;
    // .and_then(move |(ac_entry_version, mut ac_entries)| {
    match ac_entries.remove(&app_cont_name) {
        Some(mdata_info) => {
            // Reuse the already existing app container and update
            // permissions for it
            let ps = MDataPermissionSet::new()
                .allow(MDataAction::Read)
                .allow(MDataAction::Insert)
                .allow(MDataAction::Update)
                .allow(MDataAction::Delete)
                .allow(MDataAction::ManagePermissions);

            let version = c2.get_mdata_version(*mdata_info.address()).await?;
            // .and_then(move |version| {
            c2.set_mdata_user_permissions(*mdata_info.address(), app_pk, ps, version + 1)
                .await?;

            Ok(mdata_info)
            // .map(move |_| mdata_info)
            // .map_err(From::from)
            // })
            // .into_box()
        }
        None => {
            // If the container is not found, create it
            let md_info = create(&c2, app_pk).await?;
            // .and_then(move |md_info| {
            let _ = ac_entries.insert(app_cont_name, md_info.clone());

            access_container::put_authenticator_entry(&c3, &ac_entries, ac_entry_version + 1)
                .await?;
            // .map(move |()| md_info)

            Ok(md_info)
            // })
            // .into_box()
        }
    }
    // })
    // .into_box()
}

/// Removes an app's dedicated container if it's available and stored in the user's root dir.
/// Returns `true` if it was removed successfully and `false` if it wasn't found in the parent dir.
pub async fn remove(client: AuthClient, app_id: &str) -> Result<bool, AuthError> {
    let c2 = client.clone();
    let app_cont_name = app_container_name(app_id);

    let (ac_entry_version, mut ac_entries) =
        access_container::fetch_authenticator_entry(&client).await?;

    // .and_then(move |(ac_entry_version, mut ac_entries)| {
    match ac_entries.remove(&app_cont_name) {
        None => {
            // App container doesn't exist
            Ok(false)
        }
        Some(mdata_info) => {
            let c3 = c2.clone();

            let entries = c2
                .list_seq_mdata_entries(mdata_info.name(), mdata_info.type_tag())
                .await?;
            // .and_then(move |entries| {
            // Remove all entries in MData
            let actions = entries
                .iter()
                .fold(MDataSeqEntryActions::new(), |actions, (entry_name, val)| {
                    actions.del(entry_name.clone(), val.version + 1)
                });

            c3.mutate_seq_mdata_entries(mdata_info.name(), mdata_info.type_tag(), actions)
                .await?;
            // })
            // .map_err(From::from);

            // .and_then(move |_| {
            // Remove MDataInfo from the access container
            access_container::put_authenticator_entry(&client, &ac_entries, ac_entry_version + 1)
                .await?;

            Ok(true)

            // TODO(nbaksalyar): when MData deletion is implemented properly,
            // also delete the actual MutableData related to app
            // }).await
            // .map_err(From::from)
            // .map(move |_| true)
            // .into_box()
        }
    }
    // })
    // .into_box()
}

/// Create a new directory based on the provided `MDataInfo`.
/// The Old NFS impl for vrevity
async fn create_directory(
    client: &impl Client,
    dir: &MDataInfo,
    contents: MDataSeqEntries,
    perms: BTreeMap<PublicKey, MDataPermissionSet>,
) -> Result<(), AuthError> {
    let pub_key = client.owner_key();

    let dir_md =
        SeqMutableData::new_with_data(dir.name(), dir.type_tag(), contents, perms, pub_key);

    trace!("Creating new directory: {:?}", dir);
    client
        .put_seq_mutable_data(dir_md)
        .await
        .or_else(move |err| {
            trace!("Error: {:?}", err);
            match err {
                // This dir has been already created
                CoreError::DataError(SndError::DataExists) => Ok(()),
                e => Err(e),
            }
        })
        .map_err(AuthError::from)
    // .into_box()
}

// Creates a new app's dedicated container
async fn create(client: &AuthClient, app_pk: PublicKey) -> Result<MDataInfo, AuthError> {
    let dir = MDataInfo::random_private(MDataKind::Seq, DIR_TAG).map_err(AuthError::from)?;
    create_directory(
        client,
        &dir,
        btree_map![],
        btree_map![app_pk => MDataPermissionSet::new()
                .allow(MDataAction::Read)
                .allow(MDataAction::Insert)
                .allow(MDataAction::Update)
                .allow(MDataAction::Delete)
                .allow(MDataAction::ManagePermissions)],
    )
    .await;

    Ok(dir)

    // .map(move |()| dir)
    // .map_err(From::from)
    // .into_box()
}
