// Copyright 2017 MaidSafe.net limited.
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

//! These tests ensure binary compatibility between different versions of `safe_client_libs`.

#![cfg(feature = "use-mock-routing")]

use AccessContainerEntry;
use AuthError;
use AuthFuture;
use Authenticator;
use access_container;
use app_auth::{self, AppState};
use config;
use futures::{Future, future};
use rand::{Rng, SeedableRng, XorShiftRng};
use revocation;
use safe_core::{Client, FutureExt, MDataInfo};
use safe_core::{config_handler, mock_vault_path};
use safe_core::ipc::{AppExchangeInfo, AuthReq, Permission};
use safe_core::ipc::req::ContainerPermissions;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std_dirs::{DEFAULT_PRIVATE_DIRS, DEFAULT_PUBLIC_DIRS};

#[test]
#[ignore]
fn write_data() {
    let (stash, vault_path) = setup();

    // Clear the vault store.
    unwrap!(fs::remove_file(vault_path));

    let auth =
        unwrap!(Authenticator::create_acc(
        stash.locator.clone(),
        stash.password.clone(),
        stash.invitation.clone(),
        |_| (),
    ));

    unwrap!(auth.send(move |client| {
        let client = client.clone();

        app_auth::authenticate(&client, stash.auth_req0.clone())
            .then(move |res| {
                // authenticate app 0
                let _ = unwrap!(res);
                app_auth::authenticate(&client, stash.auth_req0.clone())
                    .map(move |_| (client, stash))
            })
            .then(move |res| {
                // authenticate app 1
                let (client, stash) = unwrap!(res);
                app_auth::authenticate(&client, stash.auth_req1.clone())
                    .map(move |_| (client, stash))
            })
            .then(move |res| {
                // revoke app 1
                let (client, stash) = unwrap!(res);
                revocation::revoke_app(&client, &stash.auth_req1.app.id)
            })
            .then(|res| {
                unwrap!(res);
                Ok(())
            })
            .into_box()
            .into()
    }));
}

#[test]
#[ignore]
fn read_data() {
    let (stash, _) = setup();

    let auth = unwrap!(Authenticator::login(
        stash.locator.clone(),
        stash.password.clone(),
        |_| (),
    ));

    unwrap!(auth.send(move |client| {
        let client = client.clone();

        // Read access container and ensure all standard containers exists.
        access_container::fetch_authenticator_entry(&client)
            .then(move |res| {
                let (_, containers) = unwrap!(res);
                verify_std_dirs(&client, &containers).map(move |_| client)
            })
            .then(move |res| {
                let client = unwrap!(res);
                config::get_app(&client, &stash.auth_req0.app.id).map(
                    move |app_info| (client, stash, app_info),
                )
            })
            .then(move |res| {
                let (client, stash, app_info) = unwrap!(res);
                assert_eq!(app_info.info, stash.auth_req0.app);

                access_container::fetch_entry(&client, &app_info.info.id, app_info.keys)
                    .map(move |(_, ac_entry)| (client, stash, ac_entry))
            })
            .then(move |res| {
                let (client, stash, ac_entry) = unwrap!(res);
                let ac_entry = unwrap!(ac_entry);
                verify_access_container_entry(&ac_entry, &stash.auth_req0.containers);

                Ok::<_, AuthError>((client, stash))
            })
            .then(move |res| {
                let (client, stash) = unwrap!(res);
                config::list_apps(&client).map(move |(_, apps)| (client, stash, apps))
            })
            .then(move |res| {
                let (client, stash, apps) = unwrap!(res);
                app_auth::app_state(&client, &apps, &stash.auth_req1.app.id)
            })
            .then(move |res| {
                let state = unwrap!(res);
                assert_eq!(state, AppState::Revoked);
                Ok(())
            })
            .into_box()
            .into()
    }));
}

fn verify_std_dirs(
    client: &Client<()>,
    actual_containers: &HashMap<String, MDataInfo>,
) -> Box<AuthFuture<()>> {
    let futures: Vec<_> = DEFAULT_PUBLIC_DIRS
        .iter()
        .chain(DEFAULT_PRIVATE_DIRS.iter())
        .map(|expected_container| {
            let mi = unwrap!(actual_containers.get(*expected_container));
            client.get_mdata_version(mi.name, mi.type_tag)
        })
        .collect();

    future::join_all(futures)
        .map_err(AuthError::from)
        .then(|res| {
            let _ = unwrap!(res);
            Ok(())
        })
        .into_box()
}

fn verify_access_container_entry(
    actual_entry: &AccessContainerEntry,
    requested_containers: &HashMap<String, ContainerPermissions>,
) {
    assert_eq!(actual_entry.len(), requested_containers.len());

    for (name, expected_perms) in requested_containers {
        let &(_, ref actual_perms) = unwrap!(actual_entry.get(name));
        assert_eq!(actual_perms, expected_perms);
    }
}

struct Stash {
    locator: String,
    password: String,
    invitation: String,
    auth_req1: AuthReq,
    auth_req0: AuthReq,
}

fn setup() -> (Stash, PathBuf) {
    // File store is required.
    let config = config_handler::get_config();
    let has_file_store = config
        .dev
        .as_ref()
        .map(|dev| dev.mock_in_memory_storage == false)
        .unwrap_or(true);

    assert!(
        has_file_store,
        "This test requires file-backed vault store."
    );

    // IMPORTANT: Use constant seed for repeatability.
    let mut rng = XorShiftRng::from_seed([0, 1, 2, 3]);

    let mut containers = HashMap::new();
    let _ = containers.insert(
        "_documents".to_string(),
        btree_set![
            Permission::Read,
            Permission::Insert,
            Permission::Update,
            Permission::Delete,
        ],
    );

    let auth_req0 = {
        let app_exchange_info = AppExchangeInfo {
            id: random_string(&mut rng, 16),
            scope: None,
            name: "test-app-0".to_string(),
            vendor: "test-vendor-0".to_string(),
        };

        AuthReq {
            app: app_exchange_info,
            app_container: false,
            containers: containers.clone(),
        }
    };

    let auth_req1 = {
        let app_exchange_info = AppExchangeInfo {
            id: random_string(&mut rng, 16),
            scope: None,
            name: "test-app-1".to_string(),
            vendor: "test-vendor-1".to_string(),
        };

        AuthReq {
            app: app_exchange_info,
            app_container: false,
            containers: containers.clone(),
        }
    };

    let stash = Stash {
        locator: random_string(&mut rng, 16),
        password: random_string(&mut rng, 16),
        invitation: String::new(),
        auth_req0,
        auth_req1,
    };

    (stash, mock_vault_path(&config))
}

fn random_string<R: Rng>(rng: &mut R, len: usize) -> String {
    rng.gen_ascii_chars().take(len).collect()
}
