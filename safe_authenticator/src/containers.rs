// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

/// Creates the given list of containers giving the specified key some permissions
use super::{AuthError, AuthFuture};
use crate::client::AuthClient;
use futures::{future, Future};
use safe_core::ipc::req::{container_perms_into_mdata_perms, ContainerPermissions};
use safe_core::ipc::resp::AccessContainerEntry;
use safe_core::nfs::create_dir;
use safe_core::{FutureExt, MDataInfo, DIR_TAG};
use safe_nd::{MDataKind, PublicKey};
use std::collections::HashMap;

pub fn create_containers(
    client: &AuthClient,
    containers: HashMap<String, ContainerPermissions>,
    app_pk: PublicKey,
) -> Box<AuthFuture<AccessContainerEntry>> {
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
            create_dir(
                &client,
                &container_info,
                btree_map![],
                btree_map![app_pk => container_perms_into_mdata_perms(permissions.clone())],
            )
            .map_err(AuthError::from)
        })
        .collect();

    future::join_all(creations).map(|_| ac_entry).into_box()
}
