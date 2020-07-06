// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::test_utils::{create_app, create_random_auth_req};
use crate::{App, AppError};
use safe_authenticator::test_utils::{create_authenticator, register_app};
use safe_core::utils::test_utils::random_client;
use safe_core::{Client, CoreError};
use safe_nd::{
    Error as SndError, PublicKey, SDataAddress, SDataIndex, SDataPrivUserPermissions,
    SDataPubUserPermissions, SDataUser,
};
use std::collections::BTreeMap;
use xor_name::XorName;

// Sequence created by app. App lists its own public key in owners field. Put should fail - Rejected at
// the client handlers. Should pass when it lists the owner's public key instead.
#[tokio::test]
async fn data_created_by_an_app() -> Result<(), AppError> {
    let app = create_app().await;
    let name: XorName = rand::random();
    let tag = 15_002;

    let invalid_owner = app.client.public_key().await;
    let valid_owner = app.client.owner_key().await;

    match app
        .client
        .store_pub_sdata(name, tag, invalid_owner, BTreeMap::default())
        .await
    {
        Err(CoreError::DataError(SndError::InvalidOwners)) => (),
        Ok(_) => panic!("Unexpected success storing public sequence"),
        Err(err) => panic!("Unexpected error when storing public sequence {:?}", err),
    }

    match app
        .client
        .store_priv_sdata(name, tag, invalid_owner, BTreeMap::default())
        .await
    {
        Err(CoreError::DataError(SndError::InvalidOwners)) => (),
        Ok(_) => panic!("Unexpected success storing public sequence"),
        Err(err) => panic!("Unexpected error when storing public sequence {:?}", err),
    }

    let _ = app
        .client
        .store_pub_sdata(name, tag, valid_owner, BTreeMap::default())
        .await?;
    let _ = app
        .client
        .store_priv_sdata(name, tag, valid_owner, BTreeMap::default())
        .await?;

    Ok(())
}

// Public Sequence created by owner and given to a permitted App. Owner has listed that app is allowed to read and append.
// App tries to read - should pass. App tries to append - should pass. App tries to change
// permission to allow itself to update - should fail. Owner then allows the App to manage permissions.
// App give another key permissions to append - should pass.
#[tokio::test]
async fn managing_pub_permissions_for_an_app() -> Result<(), AppError> {
    let client_app = create_app().await.client;
    let app_pk = client_app.public_key().await;

    // Create a Public Sequence with a client who owns it, but give append perms to app_pk
    let client_owner = random_client()?;
    let name: XorName = rand::random();
    let tag = 15_002;
    let mut permissions = BTreeMap::new();
    let _ = permissions.insert(
        SDataUser::Key(app_pk),
        SDataPubUserPermissions::new(true, None),
    );
    let owner = client_owner.public_key().await;

    let address = client_owner
        .store_pub_sdata(name, tag, owner, permissions)
        .await?;
    let _ = client_owner.sdata_append(address, vec![1]).await?;
    let _ = client_owner.sdata_append(address, vec![1, 2]).await?;
    let _ = client_owner.sdata_append(address, vec![1, 2, 3]).await?;

    // App should be able to read and append
    let entries = client_app
        .get_sdata_range(address, (SDataIndex::FromStart(0), SDataIndex::FromEnd(0)))
        .await?;
    let expected_entries = vec![vec![1], vec![1, 2], vec![1, 2, 3]];
    assert_eq!(entries.len(), expected_entries.len());
    assert_eq!(entries, expected_entries);

    let _ = client_app.sdata_append(address, vec![1, 2, 3, 4]).await?;

    let mut permissions = BTreeMap::new();
    let _ = permissions.insert(
        SDataUser::Key(app_pk),
        SDataPubUserPermissions::new(true, true),
    );

    match client_app
        .sdata_set_pub_permissions(address, permissions.clone())
        .await
    {
        Err(CoreError::DataError(SndError::AccessDenied)) => (),
        res => panic!("Unexpected result: {:?}", res),
    }

    // Let's now give the app permissions to ManagePermissions with the owner client
    let _ = client_owner
        .sdata_set_pub_permissions(address, permissions)
        .await?;

    // App should now be able to change permissions
    // FIXME: issue https://github.com/maidsafe/safe-client-libs/issues/1217 should be
    // resolved before we can enable this part of the test
    /*
    let random_app = PublicKey::from(threshold_crypto::SecretKey::random().public_key());
    let mut permissions = BTreeMap::new();
    let _ = permissions.insert(
        SDataUser::Key(app_pk),
        SDataPubUserPermissions::new(true, true),
    );
    let _ = permissions.insert(
        SDataUser::Key(random_app),
        SDataPubUserPermissions::new(true, None),
    );
    let _ = client_app
        .sdata_set_pub_permissions(address, permissions)
        .await?;
        */

    client_app
        .sdata_append(address, vec![1, 2, 3, 4, 5])
        .await?;

    let entries = client_app
        .get_sdata_range(address, (SDataIndex::FromStart(0), SDataIndex::FromEnd(0)))
        .await?;
    assert_eq!(entries.len(), 5);

    Ok(())
}

// Private Sequence created by owner and given to a permitted App.
// Test same scenario as previous test managing_pub_permissions_for_an_app
#[tokio::test]
async fn managing_priv_permissions_for_an_app() -> Result<(), AppError> {
    let client_app = create_app().await.client;
    let app_pk = client_app.public_key().await;

    // Create a Public Sequence with a client who owns it, but give append perms to app_pk
    let client_owner = random_client()?;
    let name: XorName = rand::random();
    let tag = 15_002;
    let mut permissions = BTreeMap::new();
    let _ = permissions.insert(app_pk, SDataPrivUserPermissions::new(true, true, false));
    let owner = client_owner.public_key().await;

    let address = client_owner
        .store_priv_sdata(name, tag, owner, permissions)
        .await?;
    let _ = client_owner.sdata_append(address, vec![1]).await?;
    let _ = client_owner.sdata_append(address, vec![1, 2]).await?;
    let _ = client_owner.sdata_append(address, vec![1, 2, 3]).await?;

    // App should be able to read and append
    let entries = client_app
        .get_sdata_range(address, (SDataIndex::FromStart(0), SDataIndex::FromEnd(0)))
        .await?;
    let expected_entries = vec![vec![1], vec![1, 2], vec![1, 2, 3]];
    assert_eq!(entries.len(), expected_entries.len());
    assert_eq!(entries, expected_entries);

    let _ = client_app.sdata_append(address, vec![1, 2, 3, 4]).await?;

    let mut permissions = BTreeMap::new();
    let _ = permissions.insert(app_pk, SDataPrivUserPermissions::new(true, true, true));

    match client_app
        .sdata_set_priv_permissions(address, permissions.clone())
        .await
    {
        Err(CoreError::DataError(SndError::AccessDenied)) => (),
        res => panic!("Unexpected result: {:?}", res),
    }

    // Let's now give the app permissions to ManagePermissions with the owner client
    let _ = client_owner
        .sdata_set_priv_permissions(address, permissions)
        .await?;

    // App should now be able to change permissions
    // FIXME: issue https://github.com/maidsafe/safe-client-libs/issues/1217 should be
    // resolved before we can enable this part of the test
    /*
    let random_app = PublicKey::from(threshold_crypto::SecretKey::random().public_key());
    let mut permissions = BTreeMap::new();
    let _ = permissions.insert(app_pk, SDataPrivUserPermissions::new(true, true, true));
    let _ = permissions.insert(random_app, SDataPrivUserPermissions::new(true, true, false));
    let _ = client_app
        .sdata_set_priv_permissions(address, permissions)
        .await?;
    */

    client_app
        .sdata_append(address, vec![1, 2, 3, 4, 5])
        .await?;

    let entries = client_app
        .get_sdata_range(address, (SDataIndex::FromStart(0), SDataIndex::FromEnd(0)))
        .await?;
    assert_eq!(entries.len(), 5);

    Ok(())
}

// Sequence created by a random client. A random application tries to read the data - should pass if data is published.
// The client adds the app's key to its list of apps and to the permissions list of the data
// giving it read and append permissions. The app should now be able and read and append to the data.
// The client then revokes the app by removing it from its list of authorised apps. The app should not
// be able to append to the data anymore. But it should still be able to read the data since if it is published.
// The client tries to delete the data. It should pass if the data is unpublished. Deleting published data should fail.
#[tokio::test]
async fn restricted_access_and_deletion() -> Result<(), AppError> {
    // First create a registered app
    let (authenticator, _, _) = create_authenticator().await;
    let auth_req = create_random_auth_req();
    let auth_granted = register_app(&authenticator, &auth_req)
        .await
        .map_err(|_| AppError::Unexpected("failed to create registered app".to_string()))?;
    let app = App::registered(auth_req.app.id, auth_granted, || ()).await?;
    let client_app = app.client;
    let app_pk = client_app.public_key().await;

    // Create a Public Sequence with a client who owns it
    let client_owner = random_client()?;
    let name: XorName = rand::random();
    let tag = 15_002;
    let owner = client_owner.public_key().await;

    let address = client_owner
        .store_pub_sdata(name, tag, owner, BTreeMap::default())
        .await?;
    let _ = client_owner.sdata_append(address, vec![1]).await?;
    let _ = client_owner.sdata_append(address, vec![1, 2]).await?;

    // App should be able to read Sequence
    let sdata = client_app.get_sdata(address).await?;
    assert!(sdata.is_pub());
    assert_eq!(*sdata.address(), address);
    assert_eq!(sdata.entries_index(), 2);

    // Give app append permissions
    let mut permissions = BTreeMap::new();
    let _ = permissions.insert(
        SDataUser::Key(app_pk),
        SDataPubUserPermissions::new(true, None),
    );
    client_owner
        .sdata_set_pub_permissions(address, permissions)
        .await?;

    // App should be able to appen now
    // FIXME: issue https://github.com/maidsafe/safe-client-libs/issues/1217 should be
    // resolved before we can enable this part of the test
    // let _ = client_app.sdata_append(address, vec![1, 2, 3]).await?;

    // App now should fail to append data
    match client_app.sdata_append(address, vec![1, 2, 3, 4]).await {
        Err(CoreError::DataError(SndError::AccessDenied)) => (),
        res => panic!("Unexpected result: {:?}", res),
    }

    Ok(())
}

// A client publishes some data giving permissions for ANYONE to append to the data and an app to manage permissions.
// The app should be able to append to the permissions and entries list. Random clients should be able to append and read the entries.
// The client then specifically denies the application permission to append entries and permissions.
// The app attempts to append permissions and entries - should fail. App tries to read data - should pass.
// Random clients should still be able to read and append entries.
#[tokio::test]
async fn public_permissions_with_app_restrictions() -> Result<(), AppError> {
    let app = create_app().await;
    let client_app = app.client.clone();
    let app_pk = client_app.public_key().await;

    // Create a Public Sequence with a client who owns it, but give ManagePermissions to app_pk,
    // and append perms to ANYONE
    let client_owner = random_client()?;
    let name: XorName = rand::random();
    let tag = 15_002;
    let mut permissions = BTreeMap::new();
    let _ = permissions.insert(
        SDataUser::Key(app_pk),
        SDataPubUserPermissions::new(None, true),
    );
    let _ = permissions.insert(SDataUser::Anyone, SDataPubUserPermissions::new(true, None));
    let owner = client_owner.public_key().await;

    let address = client_owner
        .store_pub_sdata(name, tag, owner, permissions)
        .await?;
    let _ = client_owner.sdata_append(address, vec![1]).await?;
    let _ = client_owner.sdata_append(address, vec![1, 2]).await?;
    let _ = client_owner.sdata_append(address, vec![1, 2, 3]).await?;

    // Random client is able to append
    let client_random = create_app().await.client;
    let data = client_random.get_sdata(address).await?;
    assert_eq!(*data.address(), address);
    client_random
        .sdata_append(address, vec![1, 2, 3, 4])
        .await?;

    // App should be able to change permissions
    let mut permissions = BTreeMap::new();
    let random_app = PublicKey::from(threshold_crypto::SecretKey::random().public_key());
    let _ = permissions.insert(
        SDataUser::Key(app_pk),
        SDataPubUserPermissions::new(true, true),
    );
    let _ = permissions.insert(
        SDataUser::Key(random_app),
        SDataPubUserPermissions::new(true, true),
    );
    let _ = permissions.insert(SDataUser::Anyone, SDataPubUserPermissions::new(true, false));
    client_app
        .sdata_set_pub_permissions(address, permissions)
        .await?;

    random_app_access(address).await?;

    // Remove the app from the data's permissions
    let mut permissions = BTreeMap::new();
    let _ = permissions.insert(
        SDataUser::Key(app_pk),
        SDataPubUserPermissions::new(false, false),
    );
    let _ = permissions.insert(SDataUser::Anyone, SDataPubUserPermissions::new(true, false));
    client_app
        .sdata_set_pub_permissions(address, permissions)
        .await?;

    // App should fail to append
    match client_app.sdata_append(address, vec![1, 2, 3, 4, 5]).await {
        Err(CoreError::DataError(SndError::AccessDenied)) => (),
        res => panic!("Unexpected result: {:?}", res),
    }

    let permissions = BTreeMap::new();
    match client_app
        .sdata_set_pub_permissions(address, permissions)
        .await
    {
        Err(CoreError::DataError(SndError::AccessDenied)) => (),
        res => panic!("Unexpected result: {:?}", res),
    }

    let data = client_app.get_sdata(address).await?;
    assert_eq!(*data.address(), address);
    random_app_access(address).await?;

    Ok(())
}

// Ensures that a random client has access to data at an address.
async fn random_app_access(address: SDataAddress) -> Result<(), AppError> {
    let app = create_app().await;
    let client = app.client;

    let data = client.get_sdata(address).await?;
    assert_eq!(*data.address(), address);

    let _ = client.sdata_append(address, vec![100]).await?;

    let index = data.entries_index() + 1;
    let entries = client
        .get_sdata_range(address, (SDataIndex::FromStart(0), SDataIndex::FromEnd(0)))
        .await?;
    assert_eq!(entries.len() as u64, index);
    Ok(())
}
