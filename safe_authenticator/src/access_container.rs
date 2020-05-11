// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! Routines that control the access container.
//!
//! Access container is stored in the user's session packet.

use super::AuthError;
use crate::client::AuthClient;
use bincode::{deserialize, serialize};
use log::trace;
use safe_core::core_structs::{access_container_enc_key, AccessContainerEntry, AppKeys};
use safe_core::ipc::req::{container_perms_into_permission_set, ContainerPermissions};
use safe_core::utils::{symmetric_decrypt, symmetric_encrypt, SymEncKey};
use safe_core::{recoverable_apis, Client, CoreError, MDataInfo};
use safe_nd::{
    Error as SndError, MDataAction, MDataPermissionSet, MDataSeqEntryActions, PublicKey,
};
use std::collections::HashMap;

/// Key of the authenticator entry in the access container.
pub const AUTHENTICATOR_ENTRY: &str = "authenticator";

/// Updates containers permissions (adds a given key to the permissions set)
#[allow(clippy::implicit_hasher)]
pub async fn update_container_perms(
    client: &AuthClient,
    permissions: HashMap<String, ContainerPermissions>,
    app_pk: PublicKey,
) -> Result<AccessContainerEntry, AuthError> {
    let c2 = client.clone();

    let (_, mut root_containers) = fetch_authenticator_entry(client).await?;
    let mut perms = Vec::new();
    let client = c2.clone();

    for (container_key, access) in permissions {
        let c2 = client.clone();
        let mdata_info = root_containers
            .remove(&container_key)
            .ok_or_else(|| AuthError::NoSuchContainer(container_key.clone()))?;
        let perm_set = container_perms_into_permission_set(&access);

        let version = client.get_mdata_version(*mdata_info.address()).await?;

        let req = recoverable_apis::set_mdata_user_permissions(
            c2,
            *mdata_info.address(),
            app_pk,
            perm_set,
            version + 1,
        )
        .await?;

        perms.push((container_key, mdata_info, access));
    }

    Ok(perms
        .into_iter()
        .map(|(container_key, dir, access)| (container_key, (dir, access)))
        .collect::<AccessContainerEntry>())
}

/// Gets access container entry key corresponding to the given app.
pub fn enc_key(
    access_container: &MDataInfo,
    app_id: &str,
    secret_key: &SymEncKey,
) -> Result<Vec<u8>, AuthError> {
    let nonce = access_container
        .nonce()
        .ok_or_else(|| AuthError::from("No valid nonce for access container"))?;
    Ok(access_container_enc_key(app_id, secret_key, nonce)?)
}

/// Decodes raw authenticator entry.
pub fn decode_authenticator_entry(
    encoded: &[u8],
    enc_key: &SymEncKey,
) -> Result<HashMap<String, MDataInfo>, AuthError> {
    let plaintext = symmetric_decrypt(encoded, enc_key)?;
    Ok(deserialize(&plaintext)?)
}

/// Encodes authenticator entry into raw mdata content.
#[allow(clippy::implicit_hasher)]
pub fn encode_authenticator_entry(
    decoded: &HashMap<String, MDataInfo>,
    enc_key: &SymEncKey,
) -> Result<Vec<u8>, AuthError> {
    let plaintext = serialize(decoded)?;
    Ok(symmetric_encrypt(&plaintext, enc_key, None)?)
}

/// Gets an authenticator entry from the access container
pub async fn fetch_authenticator_entry(
    client: &AuthClient,
) -> Result<(u64, HashMap<String, MDataInfo>), AuthError> {
    let c2 = client.clone();
    let access_container = client.access_container();

    let key = {
        let sk = client.secret_symmetric_key();
        enc_key(&access_container, AUTHENTICATOR_ENTRY, &sk)?
    };

    client
        .get_seq_mdata_value(access_container.name(), access_container.type_tag(), key)
        .await
        .map_err(From::from)
        .and_then(move |value| {
            let enc_key = c2.secret_symmetric_key();
            decode_authenticator_entry(&value.data, &enc_key)
                .map(|decoded| (value.version, decoded))
        })
}

/// Updates the authenticator entry.
#[allow(clippy::implicit_hasher)]
pub async fn put_authenticator_entry(
    client: &AuthClient,
    new_value: &HashMap<String, MDataInfo>,
    version: u64,
) -> Result<(), AuthError> {
    let access_container = client.access_container();
    let (key, ciphertext) = {
        let sk = client.secret_symmetric_key();
        let key = enc_key(&access_container, AUTHENTICATOR_ENTRY, &sk)?;
        let ciphertext = encode_authenticator_entry(new_value, &sk)?;

        (key, ciphertext)
    };

    let actions = if version == 0 {
        MDataSeqEntryActions::new().ins(key, ciphertext, 0)
    } else {
        MDataSeqEntryActions::new().update(key, ciphertext, version)
    };

    match recoverable_apis::mutate_mdata_entries(
        client.clone(),
        *access_container.address(),
        actions,
    )
    .await
    {
        Ok(result) => Ok(result),
        Err(err) => Err(AuthError::from(err)),
    }
}

/// Decodes raw app entry.
pub fn decode_app_entry(
    encoded: &[u8],
    enc_key: &SymEncKey,
) -> Result<AccessContainerEntry, AuthError> {
    let plaintext = symmetric_decrypt(encoded, enc_key)?;
    Ok(deserialize(&plaintext)?)
}

/// Encodes app entry into raw mdata content.
pub fn encode_app_entry(
    decoded: &AccessContainerEntry,
    enc_key: &SymEncKey,
) -> Result<Vec<u8>, AuthError> {
    let plaintext = serialize(decoded)?;
    Ok(symmetric_encrypt(&plaintext, enc_key, None)?)
}

/// Gets an access container entry
pub async fn fetch_entry(
    client: AuthClient,
    app_id: String,
    app_keys: AppKeys,
) -> Result<(u64, Option<AccessContainerEntry>), AuthError> {
    trace!(
        "Fetching access container entry for app with ID {}...",
        app_id
    );
    let access_container = client.access_container();
    let key = enc_key(&access_container, &app_id, &app_keys.enc_key)?;
    trace!("Fetching entry using entry key {:?}", key);

    let result = client
        .get_seq_mdata_value(access_container.name(), access_container.type_tag(), key)
        .await;

    match result {
        Err(CoreError::DataError(SndError::NoSuchEntry)) => Ok((0, None)),
        Err(err) => Err(AuthError::from(err)),
        Ok(value) => {
            let decoded = Some(decode_app_entry(&value.data, &app_keys.enc_key)?);
            Ok((value.version, decoded))
        }
    }
}

/// Adds a new entry to the authenticator access container
pub async fn put_entry(
    client: &AuthClient,
    app_id: &str,
    app_keys: &AppKeys,
    permissions: &AccessContainerEntry,
    version: u64,
) -> Result<(), AuthError> {
    trace!("Putting access container entry for app {}...", app_id);

    let client2 = client.clone();
    let client3 = client.clone();
    let access_container = client.access_container();
    let acc_cont_info = access_container.clone();
    let key = r#try!(enc_key(&access_container, app_id, &app_keys.enc_key));
    let ciphertext = r#try!(encode_app_entry(permissions, &app_keys.enc_key));

    let actions = if version == 0 {
        MDataSeqEntryActions::new().ins(key, ciphertext, 0)
    } else {
        MDataSeqEntryActions::new().update(key, ciphertext, version)
    };

    let app_pk: PublicKey = app_keys.public_key();

    let shell_version = client
        .get_mdata_version(*access_container.address())
        .await?;
    client2
        .set_mdata_user_permissions(
            *acc_cont_info.address(),
            app_pk,
            MDataPermissionSet::new().allow(MDataAction::Read),
            shell_version + 1,
        )
        .await?;

    recoverable_apis::mutate_mdata_entries(client3, *access_container.address(), actions)
        .await
        .map_err(AuthError::from)
}

/// Deletes entry from the access container.
pub async fn delete_entry(
    client: &AuthClient,
    app_id: &str,
    app_keys: &AppKeys,
    version: u64,
) -> Result<(), AuthError> {
    // TODO: make sure this can't be called for authenticator Entry-0

    let access_container = client.access_container();
    let acc_cont_info = access_container.clone();
    let key = enc_key(&access_container, app_id, &app_keys.enc_key)?;
    let client2 = client.clone();
    let client3 = client.clone();
    let actions = MDataSeqEntryActions::new().del(key, version);
    let app_pk: PublicKey = app_keys.public_key();

    let shell_version = client
        .get_mdata_version(*access_container.address())
        .await?;
    client2
        .del_mdata_user_permissions(*acc_cont_info.address(), app_pk, shell_version + 1)
        .await?;

    recoverable_apis::mutate_mdata_entries(client3, *access_container.address(), actions)
        .await
        .map_err(AuthError::from)
}
