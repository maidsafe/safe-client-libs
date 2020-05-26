// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::test_utils::create_app;
use rand::rngs::StdRng;
use rand::{FromEntropy, Rng};
use safe_core::utils::test_utils::random_client;
use safe_core::{client::AuthActions, Client, CoreError, DIR_TAG};
use safe_nd::{Error, PublicKey, XorName};
use safe_nd::{
    MDataAction, MDataAddress, MDataPermissionSet, MDataSeqEntryActions, MDataSeqValue,
    MDataUnseqEntryActions, SeqMutableData, UnseqMutableData,
};
use std::collections::BTreeMap;
use threshold_crypto::SecretKey;
use tokio::{sync::mpsc, task::LocalSet};
use unwrap::unwrap;

// MD created by owner and given to a permitted App. Owner has listed that app is allowed to insert
// only. App tries to insert - should pass. App tries to update - should fail. App tries to change
// permission to allow itself to update - should fail to change permissions.
#[tokio::test]
async fn md_created_by_app_1() -> Result<(), CoreError> {
    let app = create_app().await;
    let (mut app_keys_tx, mut app_keys_rx) = mpsc::channel(1);
    let (mut name_tx, mut name_rx) = mpsc::channel(1);
    let client = app.client;

    let local = LocalSet::new();
    let _ = local.spawn_local(async move {
        let app_pk = client.public_key().await;
        app_keys_tx
            .send(app_pk)
            .await
            .map_err(|_| CoreError::Unexpected("failed to send on channel".to_string()))?;

        let bls_pk = client.owner_key().await;
        let name: XorName = name_rx
            .recv()
            .await
            .ok_or_else(|| CoreError::Unexpected("failed to receive from channel".to_string()))?;
        let entry_actions = MDataSeqEntryActions::new().ins(vec![1, 2, 3, 4], vec![2, 3, 5], 0);
        client
            .mutate_seq_mdata_entries(name, DIR_TAG, entry_actions)
            .await?;
        let entry_actions = MDataSeqEntryActions::new().update(vec![1, 2, 3, 4], vec![2, 8, 5], 1);
        match client
            .mutate_seq_mdata_entries(name, DIR_TAG, entry_actions)
            .await
        {
            Ok(()) => panic!("It should fail"),
            Err(CoreError::DataError(Error::AccessDenied)) => (),
            Err(x) => panic!("Expected Error::AccessDenied. Got {:?}", x),
        }
        let user = bls_pk;
        let permissions = MDataPermissionSet::new().allow(MDataAction::Update);
        match client
            .set_mdata_user_permissions(
                MDataAddress::Seq { name, tag: DIR_TAG },
                user,
                permissions,
                2,
            )
            .await
        {
            Ok(()) => panic!("It should fail"),
            Err(CoreError::DataError(Error::AccessDenied)) => (),
            Err(x) => panic!("Expected Error::AccessDenied. Got {:?}", x),
        }

        Ok::<(), CoreError>(())
    });

    let _ = local.spawn_local(async move {
        // Alt client
        let client = random_client()?;
        let app_pk = app_keys_rx
            .recv()
            .await
            .ok_or_else(|| CoreError::Unexpected("failed to receive from channel".to_string()))?;
        let mut rng = StdRng::from_entropy();

        let mut permissions = BTreeMap::new();
        let _ = permissions.insert(
            app_pk,
            MDataPermissionSet::new()
                .allow(MDataAction::Insert)
                .allow(MDataAction::Read),
        );

        let name: XorName = XorName(rng.gen());

        let mdata = SeqMutableData::new_with_data(
            name,
            DIR_TAG,
            BTreeMap::new(),
            permissions,
            client.owner_key().await,
        );

        let (_, version) = client.list_auth_keys_and_version().await?;
        client
            .ins_auth_key(app_pk, Default::default(), version + 1)
            .await?;
        client.put_seq_mutable_data(mdata).await?;
        name_tx
            .send(name)
            .await
            .map_err(|_| CoreError::Unexpected("failed to send on channel".to_string()))?;
        Ok::<(), CoreError>(())
    });

    local.await;

    Ok(())
}

// MD created by owner and given to a permitted App. Owner has listed that app is allowed to
// manage-permissions only. App tries to insert - should fail. App tries to update - should fail.
// App tries to change permission to allow itself to insert and delete - should pass to change
// permissions. Now App tires to insert again - should pass. App tries to update. Should fail. App
// tries to delete - should pass.
#[tokio::test]
async fn md_created_by_app_2() -> Result<(), CoreError> {
    let app = create_app().await;
    let (mut app_keys_tx, mut app_keys_rx) = mpsc::channel(1);
    let (mut name_tx, mut name_rx) = mpsc::channel(1);
    let client = app.client;

    let local = LocalSet::new();
    let _ = local.spawn_local(async move {
        let app_pk = client.public_key().await;
        app_keys_tx
            .send(app_pk)
            .await
            .map_err(|_| CoreError::Unexpected("failed to send on channel".to_string()))?;

        let name: XorName = name_rx
            .recv()
            .await
            .ok_or_else(|| CoreError::Unexpected("failed to receive from channel".to_string()))?;
        let entry_actions = MDataUnseqEntryActions::new().ins(vec![1, 2, 3, 4], vec![2, 3, 5]);

        match client
            .mutate_unseq_mdata_entries(name, DIR_TAG, entry_actions)
            .await
        {
            Ok(()) => panic!("It should fail"),
            Err(CoreError::DataError(Error::AccessDenied)) => (),
            Err(x) => panic!("Expected Error::AccessDenied. Got {:?}", x),
        }

        let entry_actions = MDataUnseqEntryActions::new().update(vec![1, 8, 3, 4], vec![2, 8, 5]);

        match client
            .mutate_unseq_mdata_entries(name, DIR_TAG, entry_actions)
            .await
        {
            Ok(()) => panic!("It should fail"),
            Err(CoreError::DataError(Error::AccessDenied)) => (),
            Err(x) => panic!("Expected Error::AccessDenied. Got {:?}", x),
        }

        let user = app_pk;
        let permissions = MDataPermissionSet::new()
            .allow(MDataAction::Insert)
            .allow(MDataAction::Delete);
        client
            .set_mdata_user_permissions(
                MDataAddress::Unseq { name, tag: DIR_TAG },
                user,
                permissions,
                1,
            )
            .await?;
        let entry_actions = MDataUnseqEntryActions::new().ins(vec![1, 2, 3, 4], vec![2, 3, 5]);
        client
            .mutate_unseq_mdata_entries(name, DIR_TAG, entry_actions)
            .await?;
        let entry_actions = MDataUnseqEntryActions::new().update(vec![1, 2, 3, 4], vec![2, 8, 5]);
        match client
            .mutate_unseq_mdata_entries(name, DIR_TAG, entry_actions)
            .await
        {
            Ok(()) => panic!("It should fail"),
            Err(CoreError::DataError(Error::AccessDenied)) => (),
            Err(x) => panic!("Expected Error::AccessDenied. Got {:?}", x),
        }
        let entry_actions = MDataUnseqEntryActions::new().del(vec![1, 2, 3, 4]);
        client
            .mutate_unseq_mdata_entries(name, DIR_TAG, entry_actions)
            .await?;

        Ok::<(), CoreError>(())
    });

    let _ = local.spawn_local(async move {
        // Alt client
        let client = random_client()?;
        let app_pk = app_keys_rx
            .recv()
            .await
            .ok_or_else(|| CoreError::Unexpected("failed to receive from channel".to_string()))?;
        let mut rng = StdRng::from_entropy();

        let mut permissions = BTreeMap::new();
        let _ = permissions.insert(
            app_pk,
            MDataPermissionSet::new().allow(MDataAction::ManagePermissions),
        );

        let mut data = BTreeMap::new();
        let _ = data.insert(vec![1, 8, 3, 4], vec![1]);

        let name: XorName = XorName(rng.gen());

        let mdata = UnseqMutableData::new_with_data(
            name,
            DIR_TAG,
            data,
            permissions,
            client.owner_key().await,
        );

        let (_, version) = client.list_auth_keys_and_version().await?;
        client
            .ins_auth_key(app_pk, Default::default(), version + 1)
            .await?;
        client.put_unseq_mutable_data(mdata).await?;
        name_tx
            .send(name)
            .await
            .map_err(|_| CoreError::Unexpected("failed to send on channel".to_string()))?;

        Ok::<(), CoreError>(())
    });

    local.await;

    Ok(())
}

// MD created by App. App lists its own public key in owners field: Put should fail - Rejected by
// Client handlers. Should pass when it lists the owner's public key instead.
#[tokio::test]
async fn md_created_by_app_3() -> Result<(), CoreError> {
    let app = create_app().await;
    let client = app.client;
    let owners = client.public_key().await;
    let name: XorName = rand::random();
    let mdata =
        SeqMutableData::new_with_data(name, DIR_TAG, BTreeMap::new(), BTreeMap::new(), owners);

    match client.put_seq_mutable_data(mdata).await {
        Ok(()) => panic!("Put should be rejected by MaidManagers"),
        Err(CoreError::DataError(Error::InvalidOwners)) => (),
        Err(x) => panic!("Expected ClientError::InvalidOwners. Got {:?}", x),
    }

    let owners = client.owner_key().await;
    let mdata =
        SeqMutableData::new_with_data(name, DIR_TAG, BTreeMap::new(), BTreeMap::new(), owners);
    client.put_seq_mutable_data(mdata).await?;
    Ok(())
}

// MD created by App1, with permission to insert for App2 and permission to manage-permissions only
// for itself - should pass. App2 created via another random client2 tries to insert (going via
// client2's MM) into MD of App1 - should Pass. App1 should be able to read the data - should pass.
// App1 changes permission to remove the anyone access - should pass. App2 tries to insert another
// data in MD - should fail. App1 tries to get all data from MD - should pass and should have no
// change (since App2 failed to insert).
#[tokio::test]
async fn multiple_apps() -> Result<(), CoreError> {
    let app1 = create_app().await;
    let app2 = create_app().await;

    let (mut app2_key_tx, mut app2_key_rx) = mpsc::channel(1);
    let (mut name_tx, mut name_rx) = mpsc::channel(1);
    let (mut entry_tx, mut entry_rx) = mpsc::channel(1);
    let (mut mutate_again_tx, mut mutate_again_rx) = mpsc::channel(1);

    let client = app1.client;
    let local = LocalSet::new();
    let _ = local.spawn_local(async move {
        let mut rng = StdRng::from_entropy();
        let bls_pk = client.owner_key().await;
        let app_bls_key = client.public_key().await;
        let mut permissions = BTreeMap::new();
        let app2_bls_pk = app2_key_rx
            .recv()
            .await
            .ok_or_else(|| CoreError::Unexpected("failed to receive from channel".to_string()))?;
        let _ = permissions.insert(
            app2_bls_pk,
            MDataPermissionSet::new().allow(MDataAction::Insert),
        );
        let _ = permissions.insert(
            app_bls_key,
            MDataPermissionSet::new()
                .allow(MDataAction::ManagePermissions)
                .allow(MDataAction::Read),
        );

        let name: XorName = XorName(rng.gen());
        let mdata =
            SeqMutableData::new_with_data(name, DIR_TAG, BTreeMap::new(), permissions, bls_pk);
        client.put_seq_mutable_data(mdata).await?;
        name_tx
            .send(name)
            .await
            .map_err(|_| CoreError::Unexpected("failed to send on channel".to_string()))?;

        let entry_key: Vec<u8> = entry_rx
            .recv()
            .await
            .ok_or_else(|| CoreError::Unexpected("failed to receive from channel".to_string()))?;

        let value = client
            .get_seq_mdata_value(name, DIR_TAG, entry_key.clone())
            .await?;
        assert_eq!(
            value,
            MDataSeqValue {
                data: vec![8, 9, 9],
                version: 0
            }
        );
        client
            .del_mdata_user_permissions(MDataAddress::Seq { name, tag: DIR_TAG }, app2_bls_pk, 1)
            .await?;

        mutate_again_tx
            .send(())
            .await
            .map_err(|_| CoreError::Unexpected("failed to send on channel".to_string()))?;

        let keys = client
            .list_mdata_keys(MDataAddress::Seq { name, tag: DIR_TAG })
            .await?;
        assert_eq!(keys.len(), 1);
        assert!(keys.contains(&entry_key));
        Ok::<(), CoreError>(())
    });

    let _ = local.spawn_local(async move {
        let client2 = app2.client;
        app2_key_tx
            .send(client2.public_key().await)
            .await
            .map_err(|_| CoreError::Unexpected("failed to send on channel".to_string()))?;

        let name = name_rx
            .recv()
            .await
            .ok_or_else(|| CoreError::Unexpected("failed to receive form channel".to_string()))?;
        let entry_key = vec![1, 2, 3];
        let entry_actions = MDataSeqEntryActions::new().ins(entry_key.clone(), vec![8, 9, 9], 0);

        client2
            .mutate_seq_mdata_entries(name, DIR_TAG, entry_actions)
            .await?;
        entry_tx
            .send(entry_key)
            .await
            .map_err(|_| CoreError::Unexpected("failed to send on channel".to_string()))?;

        mutate_again_rx
            .recv()
            .await
            .ok_or_else(|| CoreError::Unexpected("failed to receive from channel".to_string()))?;

        let entry_actions = MDataSeqEntryActions::new().ins(vec![2, 2, 2], vec![21], 0);
        match client2
            .mutate_seq_mdata_entries(name, DIR_TAG, entry_actions)
            .await
        {
            Ok(()) => panic!("It should fail"),
            Err(CoreError::DataError(Error::AccessDenied)) => (),
            Err(x) => panic!("Expected Error::AccessDenied. Got {:?}", x),
        }

        Ok::<(), CoreError>(())
    });

    local.await;

    Ok(())
}

// MD created by App with itself allowed to manage-permissions. Insert permission to allow a
// random-key to perform update operation - should pass. Delete this permission without incrementing
// version of MD - should fail version check. Query the permissions list - should continue to have
// the listed permission for the random-key. Query the version of the MD in network - should pass.
// Send request to delete that permission again with properly incremented version from info from the
// fetched version - should pass. Query the permissions list - should no longer have the listed
// permission for the random-key.
#[tokio::test]
async fn permissions_and_version() -> Result<(), CoreError> {
    let app = create_app().await;
    let client = app.client;
    let mut rng = StdRng::from_entropy();
    let bls_pk = client.owner_key().await;
    let app_bls_key = client.public_key().await;
    let random_key = SecretKey::random().public_key();

    let mut permissions = BTreeMap::new();
    let _ = permissions.insert(
        app_bls_key,
        MDataPermissionSet::new()
            .allow(MDataAction::ManagePermissions)
            .allow(MDataAction::Read),
    );

    let name: XorName = XorName(rng.gen());
    let mdata =
        UnseqMutableData::new_with_data(name, DIR_TAG, BTreeMap::new(), permissions, bls_pk);

    client.put_unseq_mutable_data(mdata).await?;

    let permissions = MDataPermissionSet::new().allow(MDataAction::Update);
    client
        .set_mdata_user_permissions(
            MDataAddress::Unseq { name, tag: DIR_TAG },
            PublicKey::from(random_key),
            permissions,
            1,
        )
        .await?;

    match client
        .del_mdata_user_permissions(
            MDataAddress::Unseq { name, tag: DIR_TAG },
            PublicKey::from(random_key),
            1,
        )
        .await
    {
        Ok(()) => panic!("It should fail with invalid successor"),
        Err(CoreError::DataError(Error::InvalidSuccessor(..))) => (),
        Err(x) => panic!("Expected Error::InvalidSuccessor. Got {:?}", x),
    }

    let permissions = client
        .list_mdata_permissions(MDataAddress::Unseq { name, tag: DIR_TAG })
        .await?;
    assert_eq!(permissions.len(), 2);
    assert!(!unwrap!(permissions.get(&app_bls_key)).is_allowed(MDataAction::Insert));
    assert!(unwrap!(permissions.get(&app_bls_key)).is_allowed(MDataAction::Read));
    assert!(!unwrap!(permissions.get(&app_bls_key)).is_allowed(MDataAction::Update));
    assert!(!unwrap!(permissions.get(&app_bls_key)).is_allowed(MDataAction::Delete));
    assert!(unwrap!(permissions.get(&app_bls_key)).is_allowed(MDataAction::ManagePermissions));
    assert!(!unwrap!(permissions.get(&PublicKey::from(random_key))).is_allowed(MDataAction::Insert));
    assert!(!unwrap!(permissions.get(&PublicKey::from(random_key))).is_allowed(MDataAction::Read));
    assert!(unwrap!(permissions.get(&PublicKey::from(random_key))).is_allowed(MDataAction::Update));
    assert!(!unwrap!(permissions.get(&PublicKey::from(random_key))).is_allowed(MDataAction::Delete));
    assert!(!unwrap!(permissions.get(&PublicKey::from(random_key)))
        .is_allowed(MDataAction::ManagePermissions));
    let v = client
        .get_mdata_version(MDataAddress::Unseq { name, tag: DIR_TAG })
        .await?;
    assert_eq!(v, 1);
    client
        .del_mdata_user_permissions(
            MDataAddress::Unseq { name, tag: DIR_TAG },
            PublicKey::from(random_key),
            v + 1,
        )
        .await?;
    let permissions = client
        .list_mdata_permissions(MDataAddress::Unseq { name, tag: DIR_TAG })
        .await?;
    assert_eq!(permissions.len(), 1);
    assert!(!unwrap!(permissions.get(&app_bls_key)).is_allowed(MDataAction::Insert));
    assert!(unwrap!(permissions.get(&app_bls_key)).is_allowed(MDataAction::Read));
    assert!(!unwrap!(permissions.get(&app_bls_key)).is_allowed(MDataAction::Update));
    assert!(!unwrap!(permissions.get(&app_bls_key)).is_allowed(MDataAction::Delete));
    assert!(unwrap!(permissions.get(&app_bls_key)).is_allowed(MDataAction::ManagePermissions));

    Ok(())
}

// The usual test to insert, update, delete and list all permissions. Put in some permissions, fetch
// (list) all of them, add some more, list again, delete one or two, list again - all should pass
// and do the expected (i.e. after list do assert that it contains all the expected stuff, don't
// just pass test if the list was successful).
#[tokio::test]
async fn permissions_crud() -> Result<(), CoreError> {
    let app = create_app().await;
    let client = app.client;

    let mut rng = StdRng::from_entropy();
    let bls_pk = client.owner_key().await;
    let app_bls_key = client.public_key().await;
    let random_key_a = SecretKey::random().public_key();
    let random_key_b = SecretKey::random().public_key();

    let mut permissions = BTreeMap::new();
    let _ = permissions.insert(
        app_bls_key,
        MDataPermissionSet::new()
            .allow(MDataAction::ManagePermissions)
            .allow(MDataAction::Read),
    );

    let name: XorName = XorName(rng.gen());
    let mdata =
        UnseqMutableData::new_with_data(name, DIR_TAG, BTreeMap::new(), permissions, bls_pk);

    client.put_unseq_mutable_data(mdata).await?;
    let permissions = MDataPermissionSet::new()
        .allow(MDataAction::Insert)
        .allow(MDataAction::Delete);
    client
        .set_mdata_user_permissions(
            MDataAddress::Unseq { name, tag: DIR_TAG },
            PublicKey::from(random_key_a),
            permissions,
            1,
        )
        .await?;
    let permissions = client
        .list_mdata_permissions(MDataAddress::Unseq { name, tag: DIR_TAG })
        .await?;
    assert_eq!(permissions.len(), 2);
    assert!(!unwrap!(permissions.get(&app_bls_key)).is_allowed(MDataAction::Insert));
    assert!(!unwrap!(permissions.get(&app_bls_key)).is_allowed(MDataAction::Update));
    assert!(!unwrap!(permissions.get(&app_bls_key)).is_allowed(MDataAction::Delete));
    assert!(unwrap!(permissions.get(&app_bls_key)).is_allowed(MDataAction::Read));
    assert!(unwrap!(permissions.get(&app_bls_key)).is_allowed(MDataAction::ManagePermissions));
    assert!(
        unwrap!(permissions.get(&PublicKey::from(random_key_a))).is_allowed(MDataAction::Insert)
    );
    assert!(!unwrap!(permissions.get(&PublicKey::from(random_key_a))).is_allowed(MDataAction::Read));
    assert!(
        !unwrap!(permissions.get(&PublicKey::from(random_key_a))).is_allowed(MDataAction::Update)
    );
    assert!(
        unwrap!(permissions.get(&PublicKey::from(random_key_a))).is_allowed(MDataAction::Delete)
    );
    assert!(!unwrap!(permissions.get(&PublicKey::from(random_key_a)))
        .is_allowed(MDataAction::ManagePermissions));

    let permissions = MDataPermissionSet::new().allow(MDataAction::Delete);
    client
        .set_mdata_user_permissions(
            MDataAddress::Unseq { name, tag: DIR_TAG },
            PublicKey::from(random_key_b),
            permissions,
            2,
        )
        .await?;
    let permissions = client
        .list_mdata_permissions(MDataAddress::Unseq { name, tag: DIR_TAG })
        .await?;
    assert_eq!(permissions.len(), 3);
    assert!(!unwrap!(permissions.get(&app_bls_key)).is_allowed(MDataAction::Insert));
    assert!(!unwrap!(permissions.get(&app_bls_key)).is_allowed(MDataAction::Update));
    assert!(!unwrap!(permissions.get(&app_bls_key)).is_allowed(MDataAction::Delete));
    assert!(unwrap!(permissions.get(&app_bls_key)).is_allowed(MDataAction::Read));
    assert!(unwrap!(permissions.get(&app_bls_key)).is_allowed(MDataAction::ManagePermissions));
    assert!(
        unwrap!(permissions.get(&PublicKey::from(random_key_a))).is_allowed(MDataAction::Insert)
    );
    assert!(
        !unwrap!(permissions.get(&PublicKey::from(random_key_a))).is_allowed(MDataAction::Update)
    );
    assert!(
        unwrap!(permissions.get(&PublicKey::from(random_key_a))).is_allowed(MDataAction::Delete)
    );
    assert!(!unwrap!(permissions.get(&PublicKey::from(random_key_a)))
        .is_allowed(MDataAction::ManagePermissions));
    assert!(
        !unwrap!(permissions.get(&PublicKey::from(random_key_b))).is_allowed(MDataAction::Insert)
    );
    assert!(
        !unwrap!(permissions.get(&PublicKey::from(random_key_b))).is_allowed(MDataAction::Update)
    );
    assert!(
        unwrap!(permissions.get(&PublicKey::from(random_key_b))).is_allowed(MDataAction::Delete)
    );
    assert!(!unwrap!(permissions.get(&PublicKey::from(random_key_b)))
        .is_allowed(MDataAction::ManagePermissions));

    let permissions = MDataPermissionSet::new().allow(MDataAction::Insert);
    client
        .set_mdata_user_permissions(
            MDataAddress::Unseq { name, tag: DIR_TAG },
            PublicKey::from(random_key_b),
            permissions,
            3,
        )
        .await?;
    client
        .del_mdata_user_permissions(
            MDataAddress::Unseq { name, tag: DIR_TAG },
            PublicKey::from(random_key_a),
            4,
        )
        .await?;
    let permissions = client
        .list_mdata_permissions(MDataAddress::Unseq { name, tag: DIR_TAG })
        .await?;
    assert_eq!(permissions.len(), 2);
    assert!(!unwrap!(permissions.get(&app_bls_key)).is_allowed(MDataAction::Insert));
    assert!(!unwrap!(permissions.get(&app_bls_key)).is_allowed(MDataAction::Update));
    assert!(!unwrap!(permissions.get(&app_bls_key)).is_allowed(MDataAction::Delete));
    assert!(unwrap!(permissions.get(&app_bls_key)).is_allowed(MDataAction::Read));
    assert!(unwrap!(permissions.get(&app_bls_key)).is_allowed(MDataAction::ManagePermissions));
    assert!(
        unwrap!(permissions.get(&PublicKey::from(random_key_b))).is_allowed(MDataAction::Insert)
    );
    assert!(
        !unwrap!(permissions.get(&PublicKey::from(random_key_b))).is_allowed(MDataAction::Update)
    );
    assert!(
        !unwrap!(permissions.get(&PublicKey::from(random_key_b))).is_allowed(MDataAction::Delete)
    );
    assert!(!unwrap!(permissions.get(&PublicKey::from(random_key_b)))
        .is_allowed(MDataAction::ManagePermissions));

    let permissions = MDataPermissionSet::new()
        .allow(MDataAction::Insert)
        .allow(MDataAction::Delete);
    client
        .set_mdata_user_permissions(
            MDataAddress::Unseq { name, tag: DIR_TAG },
            PublicKey::from(random_key_b),
            permissions,
            5,
        )
        .await?;
    let permissions = client
        .list_mdata_permissions(MDataAddress::Unseq { name, tag: DIR_TAG })
        .await?;
    assert_eq!(permissions.len(), 2);
    assert!(!unwrap!(permissions.get(&app_bls_key)).is_allowed(MDataAction::Insert));
    assert!(!unwrap!(permissions.get(&app_bls_key)).is_allowed(MDataAction::Update));
    assert!(!unwrap!(permissions.get(&app_bls_key)).is_allowed(MDataAction::Delete));
    assert!(unwrap!(permissions.get(&app_bls_key)).is_allowed(MDataAction::Read));
    assert!(unwrap!(permissions.get(&app_bls_key)).is_allowed(MDataAction::ManagePermissions));
    assert!(
        unwrap!(permissions.get(&PublicKey::from(random_key_b))).is_allowed(MDataAction::Insert)
    );
    assert!(
        !unwrap!(permissions.get(&PublicKey::from(random_key_b))).is_allowed(MDataAction::Update)
    );
    assert!(
        unwrap!(permissions.get(&PublicKey::from(random_key_b))).is_allowed(MDataAction::Delete)
    );
    assert!(!unwrap!(permissions.get(&PublicKey::from(random_key_b)))
        .is_allowed(MDataAction::ManagePermissions));

    Ok(())
}

// The usual test to insert, update, delete and list all entry-keys/values. Same thing from
// `permissions_crud` with entry-key/value. After deleting an entry the key is also removed so we
// should be allowed to re-insert this with version 0.
#[tokio::test]
async fn sequenced_entries_crud() -> Result<(), CoreError> {
    let app = create_app().await;
    let client = app.client;

    let mut rng = StdRng::from_entropy();
    let bls_pk = client.owner_key().await;
    let app_bls_key = client.public_key().await;
    let mut permissions = BTreeMap::new();
    let _ = permissions.insert(
        app_bls_key,
        MDataPermissionSet::new()
            .allow(MDataAction::Read)
            .allow(MDataAction::Insert)
            .allow(MDataAction::Update)
            .allow(MDataAction::Delete),
    );

    let mut data = BTreeMap::new();
    let _ = data.insert(
        vec![0, 0, 1],
        MDataSeqValue {
            data: vec![1],
            version: 0,
        },
    );
    let _ = data.insert(
        vec![0, 1, 0],
        MDataSeqValue {
            data: vec![2, 8],
            version: 0,
        },
    );

    let name: XorName = XorName(rng.gen());
    let mdata = SeqMutableData::new_with_data(name, DIR_TAG, data, permissions, bls_pk);

    client.put_seq_mutable_data(mdata).await?;
    let entry_actions = MDataSeqEntryActions::new()
        .ins(vec![0, 1, 1], vec![2, 3, 17], 0)
        .update(vec![0, 1, 0], vec![2, 8, 64], 1)
        .del(vec![0, 0, 1], 1);
    client
        .mutate_seq_mdata_entries(name, DIR_TAG, entry_actions)
        .await?;
    let entries = client.list_seq_mdata_entries(name, DIR_TAG).await?;
    assert_eq!(entries.len(), 2);
    assert!(entries.get(&vec![0, 0, 1]).is_none());
    assert_eq!(
        *unwrap!(entries.get(&vec![0, 1, 0])),
        MDataSeqValue {
            data: vec![2, 8, 64],
            version: 1,
        }
    );
    assert_eq!(
        *unwrap!(entries.get(&vec![0, 1, 1])),
        MDataSeqValue {
            data: vec![2, 3, 17],
            version: 0,
        }
    );
    let entry_actions = MDataSeqEntryActions::new()
        .ins(vec![1, 0, 0], vec![4, 4, 4, 4], 0)
        .update(vec![0, 1, 0], vec![64, 8, 1], 2)
        .del(vec![0, 1, 1], 1);
    client
        .mutate_seq_mdata_entries(name, DIR_TAG, entry_actions)
        .await?;
    let entries = client.list_seq_mdata_entries(name, DIR_TAG).await?;
    assert_eq!(entries.len(), 2);
    assert!(entries.get(&vec![0, 0, 1]).is_none());
    assert_eq!(
        *unwrap!(entries.get(&vec![0, 1, 0])),
        MDataSeqValue {
            data: vec![64, 8, 1],
            version: 2,
        }
    );
    assert!(entries.get(&vec![0, 1, 1]).is_none());
    assert_eq!(
        *unwrap!(entries.get(&vec![1, 0, 0])),
        MDataSeqValue {
            data: vec![4, 4, 4, 4],
            version: 0,
        }
    );
    Ok(())
}

#[tokio::test]
async fn unsequenced_entries_crud() -> Result<(), CoreError> {
    let app = create_app().await;
    let client = app.client;

    let mut rng = StdRng::from_entropy();
    let bls_pk = client.owner_key().await;
    let app_bls_key = client.public_key().await;
    let mut permissions = BTreeMap::new();
    let _ = permissions.insert(
        app_bls_key,
        MDataPermissionSet::new()
            .allow(MDataAction::Read)
            .allow(MDataAction::Insert)
            .allow(MDataAction::Update)
            .allow(MDataAction::Delete),
    );

    let mut data = BTreeMap::new();
    let _ = data.insert(vec![0, 0, 1], vec![1]);
    let _ = data.insert(vec![0, 1, 0], vec![2, 8]);

    let name: XorName = XorName(rng.gen());
    let mdata = UnseqMutableData::new_with_data(name, DIR_TAG, data, permissions, bls_pk);

    client.put_unseq_mutable_data(mdata).await?;

    let entry_actions = MDataUnseqEntryActions::new()
        .ins(vec![0, 1, 1], vec![2, 3, 17])
        .update(vec![0, 1, 0], vec![2, 8, 64])
        .del(vec![0, 0, 1]);

    client
        .mutate_unseq_mdata_entries(name, DIR_TAG, entry_actions)
        .await?;
    let entries = client.list_unseq_mdata_entries(name, DIR_TAG).await?;
    assert_eq!(entries.len(), 2);
    assert!(entries.get(&vec![0, 0, 1]).is_none());
    assert_eq!(*unwrap!(entries.get(&vec![0, 1, 0])), vec![2, 8, 64]);
    assert_eq!(*unwrap!(entries.get(&vec![0, 1, 1])), vec![2, 3, 17],);
    let entry_actions = MDataUnseqEntryActions::new()
        .ins(vec![1, 0, 0], vec![4, 4, 4, 4])
        .update(vec![0, 1, 0], vec![64, 8, 1])
        .del(vec![0, 1, 1]);
    client
        .mutate_unseq_mdata_entries(name, DIR_TAG, entry_actions)
        .await?;

    let entries = client.list_unseq_mdata_entries(name, DIR_TAG).await?;
    assert_eq!(entries.len(), 2);
    assert!(entries.get(&vec![0, 0, 1]).is_none());
    assert_eq!(*unwrap!(entries.get(&vec![0, 1, 0])), vec![64, 8, 1]);
    assert!(entries.get(&vec![0, 1, 1]).is_none());
    assert_eq!(*unwrap!(entries.get(&vec![1, 0, 0])), vec![4, 4, 4, 4]);

    Ok(())
}
