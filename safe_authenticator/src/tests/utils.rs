// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    access_container::{fetch_authenticator_entry, put_authenticator_entry},
    client::AuthClient,
    AuthError,
};
use log::trace;
use safe_core::{
    btree_set,
    crypto::shared_secretbox,
    ipc::req::{ContainerPermissions, Permission},
    utils,
};
use std::collections::HashMap;

/// Creates a containers request asking for "documents with permission to
/// insert", and "videos with all the permissions possible".
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
pub async fn corrupt_container(client: &AuthClient, container_id: &str) -> Result<(), AuthError> {
    trace!("Corrupting access container entry {}...", container_id);

    let c2 = client.clone();
    let container_id = container_id.to_owned();

    let (version, mut ac_entry) = fetch_authenticator_entry(client).await?;
    let entry = ac_entry.get_mut(&container_id).ok_or_else(|| {
        AuthError::Unexpected("Failed to obtained mutable entry from account container".to_string())
    })?;
    entry.enc_info = Some((shared_secretbox::gen_key(), utils::generate_nonce()));

    // Update the old entry.
    put_authenticator_entry(&c2, &ac_entry, version + 1).await
}
