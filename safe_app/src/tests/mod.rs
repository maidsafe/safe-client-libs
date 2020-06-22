// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

mod coins;
mod sequence;
mod unpublished_mutable_data;

use crate::test_utils::{create_app, create_random_auth_req, gen_app_exchange_info};
use crate::test_utils::{create_app_by_req, create_auth_req_with_access};
use crate::{App, AppError};
use log::trace;
use safe_authenticator::test_utils as authenticator_test_utils;
use safe_authenticator::Authenticator;
use safe_core::btree_set;
use safe_core::ipc::req::{AppExchangeInfo, AuthReq};
use safe_core::ipc::Permission;
use safe_core::utils;
use safe_core::utils::test_utils::random_client;
#[cfg(feature = "mock-network")]
use safe_core::ConnectionManager;
use safe_core::{client::COST_OF_PUT, Client, CoreError};
use safe_nd::{AppPermissions, Coins, Error as SndError, IData, PubImmutableData, XorName};
#[cfg(feature = "mock-network")]
use safe_nd::{RequestType, Response};
use std::collections::{BTreeMap, HashMap};
use unwrap::unwrap;

// Test refreshing access info by fetching it from the network.
#[tokio::test]
async fn refresh_access_info() -> Result<(), AppError> {
    // Shared container
    let mut container_permissions = HashMap::new();
    let _ = container_permissions.insert(
        "_videos".to_string(),
        btree_set![Permission::Read, Permission::Insert],
    );

    let app =
        create_app_by_req(&create_auth_req_with_access(container_permissions.clone())).await?;
    let client = app.client;
    let reg = app.context.as_registered()?;
    assert!(reg.access_info.lock().await.is_empty());

    app.context.refresh_access_info(&client).await?;
    let access_info = reg.access_info.lock().await;
    assert_eq!(
        unwrap!(access_info.get("_videos")).1,
        *unwrap!(container_permissions.get("_videos"))
    );

    Ok(())
}

// Test fetching containers that an app has access to.
#[tokio::test]
async fn get_access_info() -> Result<(), AppError> {
    let mut container_permissions = HashMap::new();
    let _ = container_permissions.insert("_videos".to_string(), btree_set![Permission::Read]);
    let _ = container_permissions.insert("_downloads".to_string(), btree_set![Permission::Insert]);

    // Login to the client
    let auth = authenticator_test_utils::create_account_and_login().await;

    // Register and login to the app
    let app_info = gen_app_exchange_info();
    let app_id = app_info.id.clone();

    let auth_granted = authenticator_test_utils::register_app(
        &auth,
        &AuthReq {
            app: app_info,
            app_container: true,
            app_permissions: AppPermissions {
                transfer_coins: true,
                perform_mutations: true,
                get_balance: true,
            },
            containers: container_permissions,
        },
    )
    .await
    .map_err(|_| AppError::Unexpected("failed to obtain a registered app".to_string()))?;

    let app = App::registered(app_id, auth_granted, || ()).await?;
    let client = app.client;
    let info = app.context.get_access_info(&client).await?;
    assert!(info.contains_key(&"_videos".to_string()));
    assert!(info.contains_key(&"_downloads".to_string()));
    assert_eq!(info.len(), 3); // third item is the app container

    let (ref _md_info, ref perms) = info["_videos"];
    assert_eq!(perms, &btree_set![Permission::Read]);

    let (ref _md_info, ref perms) = info["_downloads"];
    assert_eq!(perms, &btree_set![Permission::Insert]);

    Ok(())
}

// Make sure we can login to a registered app with low balance.
#[cfg(feature = "mock-network")]
#[tokio::test]
pub async fn login_registered_with_low_balance() -> Result<(), AppError> {
    // Register a hook prohibiting mutations and login
    let cm_hook = move |mut cm: ConnectionManager| -> ConnectionManager {
        cm.set_request_hook(move |req| {
            if req.get_type() == RequestType::Mutation {
                Some(Response::Mutation(Err(SndError::InsufficientBalance)))
            } else {
                // Pass-through
                None
            }
        });
        cm
    };

    // Login to the client
    let auth = authenticator_test_utils::create_account_and_login().await;

    // Register and login to the app
    let app_info = gen_app_exchange_info();
    let app_id = app_info.id.clone();

    let auth_granted = authenticator_test_utils::register_app(
        &auth,
        &AuthReq {
            app: app_info,
            app_container: false,
            app_permissions: Default::default(),
            containers: HashMap::new(),
        },
    )
    .await
    .map_err(|_| AppError::Unexpected("failed to obtain a registered app".to_string()))?;

    let _app = App::registered_with_hook(app_id, auth_granted, || (), cm_hook)?;
    Ok(())
}

// Authorise an app with `app_container`.
async fn authorise_app(
    auth: &Authenticator,
    app_info: &AppExchangeInfo,
    app_id: &str,
    app_container: bool,
) -> Result<App, AppError> {
    let auth_granted = authenticator_test_utils::register_app(
        auth,
        &AuthReq {
            app: app_info.clone(),
            app_container,
            app_permissions: AppPermissions {
                transfer_coins: true,
                perform_mutations: true,
                get_balance: true,
            },
            containers: HashMap::new(),
        },
    )
    .await
    .map_err(|_| AppError::Unexpected("failed to obtain a registered app".to_string()))?;

    App::registered(String::from(app_id), auth_granted, || ()).await
}

// Get the number of containers for `app`
async fn num_containers(app: &App) -> Result<usize, AppError> {
    trace!("Getting the number of containers.");

    let info = app.context.get_access_info(&app.client).await?;
    Ok(info.len())
}

// Test app container creation under the following circumstances:
// 1. An app is authorised for the first time with `app_container` set to `true`.
// 2. If an app is authorised for the first time with `app_container` set to `false`,
// then any subsequent authorisation with `app_container` set to `true` should trigger
// the creation of the app's own container.
// 3. If an app is authorised with `app_container` set to `true`, then subsequent
// authorisation should not use up any mutations.
// 4. Make sure that the app's own container is also created when it's re-authorised
// with `app_container` set to `true` after it's been revoked.
#[tokio::test]
async fn app_container_creation() -> Result<(), AppError> {
    trace!("Authorising an app for the first time with `app_container` set to `true`.");

    {
        let auth = authenticator_test_utils::create_account_and_login().await;

        let app_info = gen_app_exchange_info();
        let app_id = app_info.id.clone();
        let app = authorise_app(&auth, &app_info, &app_id, true).await?;

        assert_eq!(num_containers(&app).await?, 1); // should only contain app container
    }

    trace!("Authorising a new app with `app_container` set to `false`.");
    let auth = authenticator_test_utils::create_account_and_login().await;
    let app_info = gen_app_exchange_info();
    let app_id = app_info.id.clone();

    {
        let app = authorise_app(&auth, &app_info, &app_id, false).await?;
        assert_eq!(num_containers(&app).await?, 0); // should be empty
    }

    trace!("Re-authorising the app with `app_container` set to `true`.");
    {
        let app = authorise_app(&auth, &app_info, &app_id, true).await?;
        assert_eq!(num_containers(&app).await?, 1); // should only contain app container
    }

    trace!("Making sure no mutations are done when re-authorising the app now.");
    let orig_balance: Coins = auth.client.get_balance(None).await?;

    let _ = authorise_app(&auth, &app_info, &app_id, true);

    let new_balance: Coins = auth.client.get_balance(None).await?;

    assert_eq!(orig_balance, new_balance);

    trace!("Authorising a new app with `app_container` set to `false`.");
    let auth = authenticator_test_utils::create_account_and_login().await;

    let app_info = gen_app_exchange_info();
    let app_id = app_info.id.clone();

    {
        let app = authorise_app(&auth, &app_info, &app_id, false).await?;
        assert_eq!(num_containers(&app).await?, 0); // should be empty
    }

    trace!("Revoking the app.");
    authenticator_test_utils::revoke(&auth, &app_id).await;

    trace!("Re-authorising the app with `app_container` set to `true`.");
    {
        let app = authorise_app(&auth, &app_info, &app_id, true).await?;
        assert_eq!(num_containers(&app).await?, 1); // should only contain app container
    }

    Ok(())
}

// Test unregistered clients.
// 1. Have a registered clients put public immutable and public append-only data on the network.
// 2. Try to read them as unregistered.
#[tokio::test]
async fn unregistered_client() -> Result<(), AppError> {
    let pub_idata_content = utils::generate_random_vector(30)?;

    // Registered Client PUTs something onto the network.
    let (pub_idata_addr, pub_sdata_addr, priv_sdata_addr) = {
        let client = random_client()?;
        let pub_idata = PubImmutableData::new(pub_idata_content.clone());
        let pub_idata_addr = *pub_idata.address();
        client.put_idata(pub_idata).await?;

        let name: XorName = rand::random();
        let tag = 15002;
        let owner = client.owner_key().await;
        let pub_sdata_addr = client
            .store_pub_sdata(name, tag, owner, BTreeMap::default())
            .await?;
        let priv_sdata_addr = client
            .store_priv_sdata(name, tag, owner, BTreeMap::default())
            .await?;

        (pub_idata_addr, pub_sdata_addr, priv_sdata_addr)
    };

    // Unregistered Client should be able to retrieve the data.
    let app = App::unregistered(|| (), None).await?;
    let data = app.client.get_idata(pub_idata_addr).await?;
    assert_eq!(data, IData::Pub(PubImmutableData::new(pub_idata_content)));
    let data = app.client.get_sdata(pub_sdata_addr).await?;
    assert_eq!(*data.address(), pub_sdata_addr);
    match app.client.get_sdata(priv_sdata_addr).await {
        Err(CoreError::DataError(SndError::AccessDenied)) => (),
        res => panic!("Unexpected result {:?}", res),
    }
    Ok(())
}

// Test PUTs by unregistered clients.
// 1. Have a unregistered client put public immutable. This should fail by returning Error
// as they are not allowed to PUT data into the network.
#[tokio::test]
async fn unregistered_client_put() -> Result<(), AppError> {
    let pub_idata = PubImmutableData::new(utils::generate_random_vector(30)?);

    let app = App::unregistered(|| (), None).await?;
    // Unregistered Client should not be able to PUT data.
    let client = app.client;
    match client.put_idata(pub_idata).await {
        Err(CoreError::DataError(SndError::AccessDenied)) => {}
        Ok(()) => panic!("Unexpected Success"),
        Err(e) => panic!("Unexpected Error: {}", e),
    }
    Ok(())
}

// Verify that public data can be accessed by both unregistered clients and clients that are not
// in the permission set.
#[tokio::test]
async fn public_data_access() -> Result<(), AppError> {
    let pub_idata_content = utils::generate_random_vector(30)?;

    // Create a random client and store some data
    let (pub_idata_addr, pub_sdata_addr) = {
        let client = random_client()?;

        let pub_idata = PubImmutableData::new(pub_idata_content.clone());
        let pub_idata_addr = *pub_idata.address();
        client.put_idata(pub_idata).await?;

        let name: XorName = rand::random();
        let tag = 15002;
        let owner = client.owner_key().await;
        let perms = BTreeMap::default();
        let pub_sdata_addr = client.store_pub_sdata(name, tag, owner, perms).await?;

        (pub_idata_addr, pub_sdata_addr)
    };

    // Unregistered apps should be able to read the data
    {
        let app = App::unregistered(|| (), None).await?;
        let client = app.client;

        let data = client.get_idata(pub_idata_addr).await?;
        assert_eq!(
            data,
            IData::Pub(PubImmutableData::new(pub_idata_content.clone()))
        );
        let data = client.get_sdata(pub_sdata_addr).await?;
        assert_eq!(*data.address(), pub_sdata_addr);
    }

    // Apps authorised by a different client be able to read the data too
    let app = create_app().await;
    let data = app.client.get_idata(pub_idata_addr).await?;
    assert_eq!(data, IData::Pub(PubImmutableData::new(pub_idata_content)));
    let data = app.client.get_sdata(pub_sdata_addr).await?;
    assert_eq!(*data.address(), pub_sdata_addr);
    Ok(())
}

// Test account usage statistics before and after a mutation.
#[tokio::test]
async fn account_info() -> Result<(), AppError> {
    // Create an app that can access the owner's coin balance and mutate data on behalf of user.
    let mut app_auth_req = create_random_auth_req();
    app_auth_req.app_permissions = AppPermissions {
        transfer_coins: false,
        perform_mutations: true,
        get_balance: true,
    };

    let app = create_app_by_req(&app_auth_req).await?;
    let client = app.client;
    let orig_balance: Coins = client.get_balance(None).await?;

    client
        .put_idata(PubImmutableData::new(vec![1, 2, 3]))
        .await?;

    let new_balance: Coins = client.get_balance(None).await?;

    assert_eq!(
        new_balance,
        orig_balance
            .checked_sub(COST_OF_PUT)
            .ok_or_else(|| AppError::Unexpected("failed to substract cost of put".to_string()))?
    );
    Ok(())
}
