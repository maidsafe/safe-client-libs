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
use crate::{AuthError, AuthFuture};
use bincode::serialize;
use futures::{future, Future};
use safe_core::ipc::access_container_enc_key;
use safe_core::mdata_info;
use safe_core::nfs::create_dir;
use safe_core::{client::CONTAINERS_ENTRY, Client, CoreError, FutureExt, MDataInfo};
use safe_nd::{Error as SndError, MDataSeqValue};

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
                Ok(_) => {
                    // Access container is already created.
                    future::ok(()).into_box()
                }
                Err(AuthError::CoreError(CoreError::DataError(SndError::NoSuchData))) => {
                    // Access container hasn't been created yet.
                    create_access_container(&c3, &access_container).into_box()
                }
                Err(e) => err!(e),
            }
        })
        .into_box();

    future::join_all(vec![access_cont_fut, create_config_dir(&c2, &config_dir)])
        .map_err(From::from)
        .and_then(move |_| {
            // Update account packet - root directories have been created successfully
            // (so we don't have to recover them after login).
            c4.set_std_dirs_created(true);
            c4.update_account_packet().map_err(From::from).into_box()
        })
        .into_box()
}

fn create_config_dir(client: &AuthClient, config_dir: &MDataInfo) -> Box<AuthFuture<()>> {
    let config_dir_entries =
        btree_map![KEY_APPS.to_vec() => MDataSeqValue { data: Vec::new(), version: 0 }];

    let config_dir_entries = fry!(mdata_info::encrypt_entries(config_dir, &config_dir_entries));

    create_dir(client, config_dir, config_dir_entries, btree_map![])
        .map_err(From::from)
        .into_box()
}

fn create_access_container(
    client: &AuthClient,
    access_container: &MDataInfo,
) -> Box<AuthFuture<()>> {
    let enc_key = client.secret_symmetric_key();

    // Create access container
    let authenticator_key = fry!(access_container_enc_key(
        AUTHENTICATOR_ENTRY,
        &enc_key,
        fry!(access_container.nonce().ok_or_else(|| AuthError::from(
            "Expected to have nonce on access container MDataInfo"
        ))),
    )
    .map_err(AuthError::from));

    let containers_key = CONTAINERS_ENTRY.as_bytes().to_vec();

    create_dir(
        client,
        access_container,
        btree_map![
            authenticator_key => MDataSeqValue { version: 0, data: Vec::new() },
            containers_key => MDataSeqValue { version: 0, data: Vec::new() },
        ],
        btree_map![],
    )
    .map_err(From::from)
    .into_box()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::run;
    use crate::test_utils::create_account_and_login;
    use futures::Future;

    // Test creation of default dirs.
    #[test]
    fn creates_root_dirs() {
        let auth = create_account_and_login();

        unwrap!(run(&auth, |client| {
            let client = client.clone();

            create(&client)
                .then(move |res| {
                    unwrap!(res);

                    access_container::fetch_authenticator_entry(&client)
                })
                .then(move |res| {
                    let (_, mdata_entries) = unwrap!(res);
                    assert_eq!(mdata_entries.len(), 0);
                    Ok(())
                })
        }));
    }
}
