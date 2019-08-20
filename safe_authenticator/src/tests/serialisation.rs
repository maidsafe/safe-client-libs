// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! These tests ensure binary compatibility between different versions of `safe_client_libs`.

#![cfg(feature = "mock-network")]

use crate::app_auth::{self, AppState};
use crate::client::AuthClient;
use crate::std_dirs::{DEFAULT_PRIVATE_DIRS, DEFAULT_PUBLIC_DIRS};
use crate::{access_container, config, revocation};
use crate::{AuthError, AuthFuture, Authenticator};
use futures::{future, Future};
use rand::{Rng, SeedableRng, XorShiftRng};
use safe_core::config_handler;
use safe_core::ipc::req::ContainerPermissions;
use safe_core::ipc::{AccessContainerEntry, AppExchangeInfo, AuthReq, Permission};
use safe_core::mock_vault_path;
use safe_core::{test_create_balance, Client, FutureExt, MDataInfo};
use safe_nd::Coins;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::str::FromStr;

#[test]
#[ignore]
fn serialisation_write_data() {
    let (stash, vault_path) = setup();

    // Clear the vault store.
    if vault_path.exists() {
        unwrap!(fs::remove_file(vault_path));
    }

    let auth = unwrap!(Authenticator::create_acc(
        stash.locator.clone(),
        stash.password.clone(),
        stash.balance_sk.clone(),
        || (),
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
fn serialisation_read_data() {
    let (stash, _) = setup();

    let auth = unwrap!(Authenticator::login(
        stash.locator.clone(),
        stash.password.clone(),
        || (),
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
                config::get_app(&client, &stash.auth_req0.app.id)
                    .map(move |app_info| (client, stash, app_info))
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
    client: &AuthClient,
    actual_containers: &HashMap<String, MDataInfo>,
) -> Box<AuthFuture<()>> {
    let futures: Vec<_> = DEFAULT_PUBLIC_DIRS
        .iter()
        .chain(DEFAULT_PRIVATE_DIRS.iter())
        .map(|expected_container| {
            let mi = unwrap!(actual_containers.get(*expected_container));
            client.get_mdata_version(*mi.address())
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
    balance_sk: threshold_crypto::SecretKey,
    auth_req1: AuthReq,
    auth_req0: AuthReq,
}

fn setup() -> (Stash, PathBuf) {
    let config = config_handler::get_config();

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
            app_permissions: Default::default(),
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
            app_permissions: Default::default(),
            containers: containers.clone(),
        }
    };
    let balance_sk = threshold_crypto::SecretKey::random();
    unwrap!(test_create_balance(
        &balance_sk,
        unwrap!(Coins::from_str("10"))
    ));

    let stash = Stash {
        locator: random_string(&mut rng, 16),
        password: random_string(&mut rng, 16),
        balance_sk,
        auth_req0,
        auth_req1,
    };

    (stash, mock_vault_path(&config))
}

fn random_string<R: Rng>(rng: &mut R, len: usize) -> String {
    rng.gen_ascii_chars().take(len).collect()
}
