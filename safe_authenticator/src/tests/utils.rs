// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::access_container::{fetch_authenticator_entry, put_authenticator_entry};
use crate::client::AuthClient;
use futures::Future;
use rust_sodium::crypto::secretbox;
use safe_core::crypto::shared_secretbox;
use safe_core::ipc::req::{ContainerPermissions, Permission};
use safe_core::FutureExt;
use std::collections::HashMap;
use crate::AuthFuture;

// Creates a containers request asking for "documents with permission to
// insert", and "videos with all the permissions possible".
pub fn create_containers_req() -> HashMap<String, ContainerPermissions> {
    let mut containers = HashMap::new();
    let _ = containers.insert("_documents".to_owned(), btree_set![Permission::Insert]);
    let _ = containers.insert(
        "_videos".to_owned(),
        btree_set![
            Permission::Read,
            Permission::Insert,
            Permission::Update,
            Permission::Delete,
            Permission::ManagePermissions,
        ],
    );
    containers
}

/// Corrupt an access container entry by overriding its secret key.
pub fn corrupt_container(client: &AuthClient, container_id: &str) -> Box<AuthFuture<()>> {
    trace!("Corrupting access container entry {}...", container_id);

    let c2 = client.clone();
    let container_id = container_id.to_owned();

    fetch_authenticator_entry(client)
        .and_then(move |(version, mut ac_entry)| {
            {
                let entry = unwrap!(ac_entry.get_mut(&container_id));
                entry.enc_info = Some((shared_secretbox::gen_key(), secretbox::gen_nonce()));
            }
            // Update the old entry.
            put_authenticator_entry(&c2, &ac_entry, version + 1)
        }).into_box()
}
