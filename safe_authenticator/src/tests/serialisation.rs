// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! These tests ensure binary compatibility between different versions of `safe_client_libs`.
//!
//! First, `scripts/build-binary` must be run with the reference version. Then, run
//! `scripts/test-binary` with the updated version you wish to test.

#![cfg(feature = "mock-network")]

use crate::app_auth::{self, AppState};
use crate::client::AuthClient;
use crate::std_dirs::{DEFAULT_PRIVATE_DIRS, DEFAULT_PUBLIC_DIRS};
use crate::{access_container, config, revocation};
use crate::{AuthError, Authenticator};
use rand::rngs::StdRng;
use rand::SeedableRng;
use safe_core::btree_set;
use safe_core::config_handler;
use safe_core::core_structs::AccessContainerEntry;
use safe_core::ipc::req::ContainerPermissions;
use safe_core::ipc::{AppExchangeInfo, AuthReq, Permission};
use safe_core::utils::test_utils::gen_client_id;
use safe_core::{mock_vault_path, utils};
use safe_core::{test_create_balance, Client, MDataInfo};
use safe_nd::{ClientFullId, Coins};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::str::FromStr;
use unwrap::unwrap;

#[tokio::test]
#[ignore]
async fn serialisation_write_data() -> Result<(), AuthError> {
    let vault_path = get_vault_path();
    println!("vault_path: {:?}", vault_path);

    if vault_path.exists() {
        // Clear the vault store.
        fs::remove_file(vault_path.clone())?;

        if vault_path.exists() {
            panic!("Vault file {:?} was not removed successfully!", vault_path);
        }
    }

    // Set up a fresh mock vault.
    let stash = setup().await;

    let auth = Authenticator::create_client_with_acc(
        stash.locator.clone(),
        stash.password.clone(),
        stash.client_id.clone(),
        || (),
    )
    .await?;

    let client = auth.client.clone();

    let _ = app_auth::authenticate(&client, stash.auth_req0.clone()).await?;

    // authenticate app 0
    let _ = app_auth::authenticate(&client, stash.auth_req0.clone()).await?;
    // authenticate app 1
    let _ = app_auth::authenticate(&client, stash.auth_req1.clone()).await?;
    // revoke app 1
    let _ = revocation::revoke_app(&client, &stash.auth_req1.app.id).await?;

    Ok(())
}

#[tokio::test]
#[ignore]
async fn serialisation_read_data() -> Result<(), AuthError> {
    let vault_path = get_vault_path();
    println!("vault_path: {:?}", vault_path);

    if !vault_path.exists() {
        panic!(
            "Vault file {:?} does not exist! Have you run `serialisation_write_data`?",
            vault_path
        );
    }

    // Set up the mock vault, assuming the previous mock vault file still exists.
    let stash = setup().await;

    let auth = Authenticator::login(stash.locator.clone(), stash.password.clone(), || ()).await?;
    let client = auth.client.clone();

    // Read access container and ensure all standard containers exists.
    let (_, containers) = access_container::fetch_authenticator_entry(&client).await?;
    verify_std_dirs(&client, &containers).await?;
    let app_info = config::get_app(&client, &stash.auth_req0.app.id).await?;
    assert_eq!(app_info.info, stash.auth_req0.app);
    let (_, ac_entry) =
        access_container::fetch_entry(client.clone(), app_info.info.id, app_info.keys).await?;
    let ac_entry = unwrap!(ac_entry);
    verify_access_container_entry(&ac_entry, &stash.auth_req0.containers);
    let (_, apps) = config::list_apps(&client).await?;
    let state = app_auth::app_state(&client, &apps, &stash.auth_req1.app.id).await?;
    assert_eq!(state, AppState::Revoked);

    Ok(())
}

async fn verify_std_dirs(
    client: &AuthClient,
    actual_containers: &HashMap<String, MDataInfo>,
) -> Result<(), AuthError> {
    let default_containers = DEFAULT_PUBLIC_DIRS
        .iter()
        .chain(DEFAULT_PRIVATE_DIRS.iter());

    for expected_container in default_containers {
        let mi = unwrap!(actual_containers.get(*expected_container));
        let _ = client
            .get_mdata_version(*mi.address())
            .await
            .map_err(AuthError::from)?;
    }

    Ok(())
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
    client_id: ClientFullId,
    auth_req1: AuthReq,
    auth_req0: AuthReq,
}

fn get_vault_path() -> PathBuf {
    let config = config_handler::get_config();
    mock_vault_path(&config)
}

async fn setup() -> Stash {
    // IMPORTANT: Use constant seed for repeatability.
    let mut rng = StdRng::seed_from_u64(1);

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
            id: utils::generate_random_string_rng(&mut rng, 16),
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
            id: utils::generate_random_string_rng(&mut rng, 16),
            scope: None,
            name: "test-app-1".to_string(),
            vendor: "test-vendor-1".to_string(),
        };

        AuthReq {
            app: app_exchange_info,
            app_container: false,
            app_permissions: Default::default(),
            containers,
        }
    };
    let client_id = gen_client_id();
    unwrap!(test_create_balance(&client_id, unwrap!(Coins::from_str("10"))).await);

    Stash {
        locator: utils::generate_random_string_rng(&mut rng, 16),
        password: utils::generate_random_string_rng(&mut rng, 16),
        client_id,
        auth_req0,
        auth_req1,
    }
}
