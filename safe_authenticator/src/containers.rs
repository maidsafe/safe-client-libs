// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{AuthError, AuthFuture};
use crate::access_container;
use crate::client::AuthClient;
use futures::{future, Future};
use safe_core::ipc::req::{container_perms_into_mdata_perms, ContainerPermissions};
use safe_core::ipc::resp::AccessContainerEntry;
use safe_core::nfs::create_dir;
use safe_core::{FutureExt, MDataInfo, DIR_TAG};
use safe_nd::{MDataKind, PublicKey};
use std::collections::HashMap;

/// Creates the given list of containers giving the specified key some permissions.
/// To create the containers as the authentication pass `None` to the app_pk field.
pub fn create_containers(
    client: &AuthClient,
    containers: HashMap<String, ContainerPermissions>,
    app_pk: Option<PublicKey>,
) -> Box<AuthFuture<AccessContainerEntry>> {
    println!("Creating new containers: {:?}", containers);
    let client = client.clone();

    let ac_entry: AccessContainerEntry = fry!(containers
        .into_iter()
        .map(|(name, permissions)| {
            MDataInfo::random_private(MDataKind::Seq, DIR_TAG)
                .map_err(AuthError::from)
                .map(|container_info| (name, (container_info, permissions)))
        })
        .collect());
    let creations: Vec<_> = ac_entry
        .iter()
        .map(|(_name, (container_info, permissions))| {
            let mut permission_set = btree_map![];
            if let Some(key) = app_pk {
                let _ = permission_set
                    .insert(key, container_perms_into_mdata_perms(permissions.clone()));
            };
            create_dir(&client, &container_info, btree_map![], permission_set)
                .map_err(AuthError::from)
        })
        .collect();

    let ac_entry2 = ac_entry.clone();
    future::join_all(creations)
        .map_err(From::from)
        .and_then(move |_| {
            // If the containers are being created by the authenticator,
            // update the access container.
            if app_pk.is_none() {
                let new_containers = ac_entry2
                    .into_iter()
                    .map(|(name, (md_info, _permissions))| (name, md_info))
                    .collect();
                access_container::update_authenticator_entry(&client, &new_containers)
            } else {
                ok!(())
            }
        })
        .and_then(move |_| Ok(ac_entry))
        .into_box()
}
