// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::utils::{corrupt_container, create_containers_req};
use crate::{
    app_auth::{app_state, AppState},
    assert_match,
    client::AuthClient,
    config::{self, get_app_revocation_queue, push_to_app_revocation_queue},
    errors::AuthError,
    revocation,
    
    test_utils::{
        access_container, create_account_and_login, create_authenticator, create_file, fetch_file,
        get_container_from_authenticator_entry, rand_app, register_app, register_rand_app, revoke,
        try_access_container, try_revoke,
    },
    {access_container, Authenticator},
};
use log::debug;
use safe_core::{
    app_container_name, btree_set,
    client::AuthActions,
    core_structs::AccessContainerEntry,
    ipc::req::container_perms_into_permission_set,
    ipc::{AuthReq, Permission},
    Client, CoreError, MDataInfo,
};
use safe_nd::{AppPermissions, Error as SndError, MDataAddress, MDataSeqEntryActions};
use std::collections::HashMap;
use tiny_keccak::sha3_256;
use tokio::task::LocalSet;

use unwrap::unwrap;

async fn verify_app_is_revoked(
    client: &AuthClient,
    app_id: String,
    prev_ac_entry: AccessContainerEntry,
) -> Result<(), AuthError> {
    let (_, apps) = config::list_apps(client).await?;

    let (auth_keys, _) = client.list_auth_keys_and_version().await?;
    let state = app_state(&client, &apps, &app_id).await?;

    let app_hash = sha3_256(app_id.as_bytes());
    let app_key = unwrap!(apps.get(&app_hash)).keys.public_key();

    // Verify the app is no longer authenticated.
    if auth_keys.contains_key(&app_key) {
        return Err(AuthError::Unexpected("App is still authenticated".into()));
    }

    // Verify its state is `Revoked` (meaning it has no entry in the access container).
    assert_match!(state, AppState::Revoked);

    for (_, (mdata_info, _)) in prev_ac_entry.into_iter() {
        // Verify the app has no permissions in the containers.
        let res = client
            .list_mdata_user_permissions(*mdata_info.address(), app_key)
            .await;
        assert_match!(res, Err(CoreError::DataError(SndError::NoSuchKey)));
    }

    Ok(())
}

async fn verify_app_is_authenticated(
    client: &AuthClient,
    app_id: String,
    expected_permissions: AppPermissions,
) -> Result<(), AuthError> {
    let (_, mut apps) = config::list_apps(client).await?;

    let app_hash = sha3_256(app_id.as_bytes());
    let app_keys = unwrap!(apps.remove(&app_hash)).keys;

    let (auth_keys, _) = client.list_auth_keys_and_version().await?;
    let app_key = app_keys.public_key();

    // Verify the app is authenticated with the expected permissions.
    match auth_keys.get(&app_key) {
        Some(app_permissions) => assert_eq!(*app_permissions, expected_permissions),
        None => panic!("App is not authenticated"),
    }

    // Fetch the access container entry
    let (_, entry) = access_container::fetch_entry(client.clone(), app_id, app_keys).await?;

    let user = app_key;
    let ac_entry = unwrap!(entry);

    for (_, (mdata_info, permissions)) in ac_entry.into_iter() {
        // Verify the app has the permissions set according to the access container.
        let expected_perms = container_perms_into_permission_set(&permissions);
        let perms = client
            .list_mdata_user_permissions(*mdata_info.address(), user)
            .await?;
        assert_eq!(perms, expected_perms);

        // Verify the app can decrypt the content of the containers.
        let entries = client
            .list_seq_mdata_entries(mdata_info.name(), mdata_info.type_tag())
            .await?;

        for (key, value) in entries {
            if value.data.is_empty() {
                continue;
            }

            let _ = unwrap!(mdata_info.decrypt(&key));
            let _ = unwrap!(mdata_info.decrypt(&value.data));
        }
    }

    Ok(())
}

#[cfg(feature = "mock-network")]
mod mock_routing {
    use super::*;
    use crate::test_utils::{
        get_container_from_authenticator_entry, register_rand_app, simulate_revocation_failure,
        try_revoke,
    };
    use rand::rngs::StdRng;
    use rand::FromEntropy;
    use safe_core::client::AuthActions;
    use safe_core::ipc::{IpcError, Permission};
    use safe_core::utils::test_utils::Synchronizer;
    use std::{
        collections::HashMap,
        iter,
        sync::{Arc, Barrier},
    };

    // Test operation recovery for app revocation
    //
    // 1. Create a test app and authenticate it.
    // 2. Grant access to some of the default containers (e.g. `_video`, `_documents`).
    // 3. Put several files with a known content in both containers (e.g. `_videos/video.mp4` and
    //    `_documents/test.doc`).
    // 4. Revoke the app access from the authenticator.
    // 5. Verify that the `_documents` and `_videos` containers are still accessible using the
    //    previous `MDataInfo`.
    // 7. Check that the app key is not listed in MaidManagers.
    // 8. Repeat step 1.4 (the revoke operation for the app). It should pass.
    // 9. Verify that the app is still revoked.
    #[tokio::test]
    async fn app_revocation() -> Result<(), AuthError> {
        let (auth, locator, password) = create_authenticator().await;
        let client = auth.client.clone();

        // Create a test app and authenticate it.
        // Grant access to some of the default containers (e.g. `_video`, `_documents`).
        let auth_req = AuthReq {
            app: rand_app(),
            app_container: false,
            app_permissions: Default::default(),
            containers: create_containers_req(),
        };
        let app_id = auth_req.app.id.clone();
        let auth_granted = register_app(&auth, &auth_req).await?;

        // Put several files with a known content in both containers
        let mut ac_entries = access_container(&auth, app_id.clone(), auth_granted.clone()).await?;
        let (videos_md, _) = unwrap!(ac_entries.remove("_videos"));
        let (docs_md, _) = unwrap!(ac_entries.remove("_documents"));

        create_file(&auth, videos_md.clone(), "video.mp4", vec![1; 10], true).await?;
        create_file(&auth, docs_md.clone(), "test.doc", vec![2; 10], true).await?;

        let auth = Authenticator::login(locator.clone(), password.clone(), || ()).await?;

        // Revoke the app.
        try_revoke(&auth, &app_id).await?;

        // Verify that the `_documents` and `_videos` containers are still accessible.
        let _ = fetch_file(&auth, docs_md, "test.doc").await?;

        let new_videos_md = get_container_from_authenticator_entry(&client, "_videos").await?;
        let _ = fetch_file(&auth, new_videos_md, "video.mp4").await?;

        // Verify that we can still access the file using the old info.
        let _ = fetch_file(&auth, videos_md, "video.mp4").await?;

        // Ensure that the app key has been removed from MaidManagers
        let (auth_keys, _version) = client.list_auth_keys_and_version().await?;
        assert!(!auth_keys.contains_key(&auth_granted.app_keys.public_key()));

        // Login and revoke the app again.
        let auth = Authenticator::login(locator, password, || ()).await?;

        // App revocation should succeed
        revoke(&auth, &app_id).await;

        // Check that the app is now revoked.
        let app_id = app_id;
        verify_app_is_revoked(&client, app_id, ac_entries).await?;

        Ok(())
    }

    // Test app cannot be (re)authenticated while it's being revoked.
    //
    // 1. Create an app.
    // 2. Initiate a revocation of the app, but simulate a network failure to prevent it
    //    from finishing.
    // 3. Try to re-authenticate the app and assert that it fails (as the app is in the
    //    middle of its revocation process)
    // 4. Re-try the revocation with no simulated failures to let it finish successfully.
    // 5. Try to re-authenticate the app again. This time it will succeed.
    #[tokio::test]
    async fn app_authentication_during_pending_revocation() -> Result<(), AuthError> {
        // Create account.
        let (auth, locator, password) = create_authenticator().await;

        // Authenticate the app.
        let auth_req = AuthReq {
            app: rand_app(),
            app_container: false,
            app_permissions: Default::default(),
            containers: create_containers_req(),
        };

        let app_id = auth_req.app.id.clone();
        let _ = register_app(&auth, &auth_req).await?;

        // Attempt to revoke it which fails due to simulated network failure.
        simulate_revocation_failure(&locator, &password, iter::once(&app_id)).await;

        // Attempt to re-authenticate the app fails, because revocation is pending.
        match register_app(&auth, &auth_req).await {
            Err(AuthError::PendingRevocation) => (),
            x => panic!("Unexpected: {:?}", x),
        }

        // Retry the app revocation. This time it succeeds.
        revoke(&auth, &app_id).await;

        // Re-authentication now succeeds.
        let _ = register_app(&auth, &auth_req).await?;

        Ok(())
    }

    // Test one app being revoked by multiple authenticator concurrently.
    #[tokio::test]
    async fn concurrent_revocation_of_single_app() -> Result<(), AuthError> {
        let mut rng = StdRng::from_entropy();

        // Number of concurrent operations.
        let concurrency = 2;

        // Create account.
        let (auth, locator, password) = create_authenticator().await;
        let client = auth.client.clone();

        // Create two apps with dedicated containers + access to one shared container.
        let mut containers_req = HashMap::new();
        let _ = containers_req.insert(
            "_documents".to_owned(),
            btree_set![
                Permission::Read,
                Permission::Insert,
                Permission::Update,
                Permission::Delete,
            ],
        );

        let (app_id_0, auth_granted_0) =
            register_rand_app(&auth, true, containers_req.clone()).await?;
        let (app_id_1, _) = register_rand_app(&auth, true, containers_req).await?;

        let ac_entries_0 = access_container(&auth, app_id_0.clone(), auth_granted_0).await?;

        // Put a file into the shared container.
        let info = get_container_from_authenticator_entry(&client, "_documents").await?;
        create_file(&auth, info, "shared.txt", vec![0; 10], true).await?;

        // Put a file into the dedicated container of each app.
        for app_id in &[&app_id_0, &app_id_1] {
            let info = get_container_from_authenticator_entry(&client, &app_container_name(app_id))
                .await?;
            create_file(&auth, info, "private.txt", vec![0; 10], true).await?;
        }

        // Try to revoke the app concurrently using multiple authenticators (running
        // in separate threads).

        // This barrier makes sure the revocations are started only after all
        // the authenticators are fully initialized.
        let barrier = Arc::new(Barrier::new(concurrency));
        let sync = Synchronizer::new(&mut rng);
        let mut success = false;
        let local = LocalSet::new();
        for _ in 0..concurrency {
            let locator = locator.clone();
            let password = password.clone();
            let app_id = app_id_0.clone();
            let barrier = Arc::clone(&barrier);
            let sync = sync.clone();

            let _ = local.spawn_local(async move {
                let auth = Authenticator::login_with_hook(
                    locator,
                    password,
                    || (),
                    move |routing| sync.hook(routing),
                )
                .await?;

                let _ = barrier;
                match try_revoke(&auth, &app_id).await {
                    Ok(_) | Err(AuthError::IpcError(IpcError::UnknownApp)) => success = true,
                    _ => {}
                }
                Ok::<_, AuthError>(())
            });
        }

        local.await;

        // If none of the concurrently running revocations succeeded, let's give it
        // one more try, but this time using only one authenticator.
        // The idea behind this is that it's OK if revocation fails when run concurrently,
        // but it should always succeed when run non-concurrently - that is, the
        // concurrent runs should never leave things in inconsistent state.
        if !success {
            try_revoke(&auth, &app_id_0).await?;
        }

        // Check that the first app is now revoked, but the second app is not.
        let _ = verify_app_is_revoked(&client, app_id_0, ac_entries_0).await?;
        let expected_permissions = AppPermissions {
            get_balance: true,
            transfer_coins: true,
            perform_mutations: true,
        };
        let _ = verify_app_is_authenticated(&client, app_id_1, expected_permissions).await?;

        Ok(())
    }

    // Test multiple apps being revoked concurrently.
    #[tokio::test]
    async fn concurrent_revocation_of_multiple_apps() -> Result<(), AuthError> {
        let mut rng = StdRng::from_entropy();

        // Create account.
        let (auth, locator, password) = create_authenticator().await;
        let client = auth.client.clone();

        // Create apps with dedicated containers + access to one shared container.
        let mut containers_req = HashMap::new();
        let _ = containers_req.insert(
            "_documents".to_owned(),
            btree_set![
                Permission::Read,
                Permission::Insert,
                Permission::Update,
                Permission::Delete,
            ],
        );

        let (app_id_0, auth_granted_0) =
            register_rand_app(&auth, true, containers_req.clone()).await?;
        let (app_id_1, auth_granted_1) =
            register_rand_app(&auth, true, containers_req.clone()).await?;
        let (app_id_2, _) = register_rand_app(&auth, true, containers_req).await?;

        let ac_entries_0 = access_container(&auth, app_id_0.clone(), auth_granted_0).await?;
        let ac_entries_1 = access_container(&auth, app_id_1.clone(), auth_granted_1).await?;

        // Put a file into the shared container.
        let info = get_container_from_authenticator_entry(&client, "_documents").await?;
        create_file(&auth, info, "shared.txt", vec![0; 10], true).await?;

        // Put a file into the dedicated container of each app.
        for app_id in &[&app_id_0, &app_id_1, &app_id_2] {
            let info = get_container_from_authenticator_entry(&client, &app_container_name(app_id))
                .await?;
            create_file(&auth, info, "private.txt", vec![0; 10], true).await?;
        }

        // Revoke the first two apps, concurrently.
        let apps_to_revoke = [app_id_0.clone(), app_id_1.clone()];

        // This barrier makes sure the revocations are started only after all
        // the authenticators are fully initialized.
        let barrier = Arc::new(Barrier::new(apps_to_revoke.len()));
        let sync = Synchronizer::new(&mut rng);
        let local = LocalSet::new();
        for app_id in apps_to_revoke.iter() {
            let locator = locator.clone();
            let password = password.clone();
            let app_id = app_id.to_string();
            let barrier = Arc::clone(&barrier);
            let sync = sync.clone();

            let _ = local.spawn_local(async move {
                let auth = Authenticator::login_with_hook(
                    locator,
                    password,
                    || (),
                    move |routing| sync.hook(routing),
                )
                .await?;

                let _ = barrier;
                if try_revoke(&auth, &app_id).await.is_err() {
                    // Retry
                    match try_revoke(&auth, &app_id).await {
                        Ok(_) | Err(AuthError::IpcError(IpcError::UnknownApp)) => (),
                        Err(error) => panic!("Unexpected revocation failure: {:?}", error),
                    }
                }
                Ok::<_, AuthError>(())
            });
        }

        local.await;

        // Check that the first two apps are now revoked, but the other one is not.
        verify_app_is_revoked(&client, app_id_0, ac_entries_0).await?;
        verify_app_is_revoked(&client, app_id_1, ac_entries_1).await?;
        let expected_permissions = AppPermissions {
            get_balance: true,
            transfer_coins: true,
            perform_mutations: true,
        };
        verify_app_is_authenticated(&client, app_id_2, expected_permissions).await?;

        Ok(())
    }
}

// The app revocation and re-authorisation workflow.
#[tokio::test]
async fn app_revocation_and_reauth() -> Result<(), AuthError> {
    let authenticator = create_account_and_login().await;
    let client = authenticator.client.clone();

    // Create and authorise two apps.
    let auth_req1 = AuthReq {
        app: rand_app(),
        app_container: false,
        app_permissions: Default::default(),
        containers: create_containers_req(),
    };
    let app_id1 = auth_req1.app.id.clone();
    let auth_granted1 = register_app(&authenticator, &auth_req1).await?;

    let mut auth_req2 = AuthReq {
        app: rand_app(),
        app_container: true,
        app_permissions: Default::default(),
        containers: create_containers_req(),
    };
    let app_id2 = auth_req2.app.id.clone();
    let auth_granted2 = register_app(&authenticator, &auth_req2).await?;

    // Put one file by each app into a shared container.
    let mut ac_entries =
        access_container(&authenticator, app_id1.clone(), auth_granted1.clone()).await?;
    let (videos_md1, _) = unwrap!(ac_entries.remove("_videos"));
    create_file(
        &authenticator,
        videos_md1.clone(),
        "1.mp4",
        vec![1; 10],
        true,
    )
    .await?;

    let mut ac_entries =
        access_container(&authenticator, app_id2.clone(), auth_granted2.clone()).await?;
    let (videos_md2, _) = unwrap!(ac_entries.remove("_videos"));
    create_file(
        &authenticator,
        videos_md2.clone(),
        "2.mp4",
        vec![1; 10],
        true,
    )
    .await?;

    let app_container_name = app_container_name(&app_id2);
    let (app_container_md, _) = unwrap!(ac_entries.remove(&app_container_name));
    create_file(&authenticator, app_container_md, "3.mp4", vec![1; 10], true).await?;

    // There should be 2 entries.
    assert_eq!(
        count_mdata_entries(&authenticator, videos_md1.clone()).await?,
        2
    );

    // Both apps can access both files.
    let _ = fetch_file(&authenticator, videos_md1.clone(), "1.mp4").await?;
    let _ = fetch_file(&authenticator, videos_md1.clone(), "2.mp4").await?;

    let _ = fetch_file(&authenticator, videos_md2.clone(), "1.mp4").await?;
    let _ = fetch_file(&authenticator, videos_md2.clone(), "2.mp4").await?;

    // Revoke the first app.
    revoke(&authenticator, &app_id1).await;

    // There should now be 2 entries.
    assert_eq!(count_mdata_entries(&authenticator, videos_md1).await?, 2);

    // The first app is no longer in the access container.
    let ac = try_access_container(&authenticator, app_id1.clone(), auth_granted1.clone()).await?;
    assert!(ac.is_none());

    // Container permissions include only the second app.
    let (name, tag) = (videos_md2.name(), videos_md2.type_tag());
    let perms = client
        .list_mdata_permissions(MDataAddress::Seq { name, tag })
        .await?;
    assert!(!perms.contains_key(&auth_granted1.app_keys.public_key()));
    assert!(perms.contains_key(&auth_granted2.app_keys.public_key()));

    // Check that the first app is now revoked, but the second app is not.
    let (app_id1_clone, app_id2_clone) = (app_id1.clone(), app_id2.clone());
    verify_app_is_revoked(&client, app_id1_clone, ac_entries).await?;
    verify_app_is_authenticated(&client, app_id2_clone, Default::default()).await?;

    // The second app can still access both files after re-fetching the access container.
    let mut ac_entries =
        access_container(&authenticator, app_id2.clone(), auth_granted2.clone()).await?;
    let (videos_md2, _) = unwrap!(ac_entries.remove("_videos"));

    let _ = fetch_file(&authenticator, videos_md2.clone(), "1.mp4").await?;
    let _ = fetch_file(&authenticator, videos_md2.clone(), "2.mp4").await?;

    // Re-authorise the first app.
    let auth_granted1 = register_app(&authenticator, &auth_req1).await?;
    let mut ac_entries = access_container(&authenticator, app_id1.clone(), auth_granted1).await?;
    let (videos_md1, _) = unwrap!(ac_entries.remove("_videos"));

    // The first app can access the files again.
    let _ = fetch_file(&authenticator, videos_md1.clone(), "1.mp4").await?;
    let _ = fetch_file(&authenticator, videos_md1.clone(), "2.mp4").await?;

    // The second app as well.
    let _ = fetch_file(&authenticator, videos_md2.clone(), "1.mp4").await?;
    let _ = fetch_file(&authenticator, videos_md2, "2.mp4").await?;

    // Revoke the first app again. Only the second app can access the files.
    revoke(&authenticator, &app_id1).await;

    // There should now be 2 entries.
    assert_eq!(count_mdata_entries(&authenticator, videos_md1).await?, 2);

    // Check that the first app is now revoked, but the second app is not.
    let (app_id1_clone, app_id2_clone) = (app_id1.clone(), app_id2.clone());
    verify_app_is_revoked(&client, app_id1_clone, ac_entries).await?;
    verify_app_is_authenticated(&client, app_id2_clone, Default::default()).await?;

    let mut ac_entries = access_container(&authenticator, app_id2.clone(), auth_granted2).await?;
    let (videos_md2, _) = unwrap!(ac_entries.remove("_videos"));
    let _ = fetch_file(&authenticator, videos_md2.clone(), "1.mp4").await?;
    let _ = fetch_file(&authenticator, videos_md2, "2.mp4").await?;

    // Revoke the second app that has created its own app container.
    revoke(&authenticator, &app_id2).await;

    // Check that the first and second apps are both revoked.
    let (app_id1_clone, app_id2_clone) = (app_id1, app_id2.clone());
    verify_app_is_revoked(&client, app_id1_clone, ac_entries.clone()).await?;
    verify_app_is_revoked(&client, app_id2_clone, ac_entries).await?;

    // Try to reauthorise and revoke the second app again - as it should have reused its
    // app container, the subsequent reauthorisation + revocation should work correctly too.
    // Update the `AppPermissions` this time to allow it to read the user's balance.
    let new_app_permissions = AppPermissions {
        get_balance: true,
        perform_mutations: false,
        transfer_coins: false,
    };
    auth_req2.app_permissions = new_app_permissions;
    let auth_granted2 = register_app(&authenticator, &auth_req2).await?;

    // The second app should be able to access data from its own container,
    let mut ac_entries = access_container(&authenticator, app_id2.clone(), auth_granted2).await?;
    let (app_container_md, _) = unwrap!(ac_entries.remove(&app_container_name));

    assert_eq!(
        count_mdata_entries(&authenticator, app_container_md.clone()).await?,
        1
    );
    let _ = fetch_file(&authenticator, app_container_md, "3.mp4").await?;

    // Check that the second app is authenticated with the required permissions.
    let app_id2_clone = app_id2.clone();
    verify_app_is_authenticated(&client, app_id2_clone, new_app_permissions).await?;

    revoke(&authenticator, &app_id2).await;

    // Check that the second app is now revoked again.
    verify_app_is_revoked(&client, app_id2, ac_entries).await?;

    Ok(())
}

// Test that corrupting an app's entry before trying to revoke it results in a
// `SymmetricDecipherFailure` error and immediate return, without revoking more apps.
// TODO: Alter/Deprecate this test as the new impl does not perform re-encryption
#[tokio::test]
#[ignore]
async fn revocation_symmetric_decipher_failure() -> Result<(), AuthError> {
    let authenticator = create_account_and_login().await;
    let client = authenticator.client.clone();

    // Create a containers request for the entry to be corrupted
    let mut corrupt_containers = HashMap::new();
    let _ = corrupt_containers.insert(
        "_downloads".to_owned(),
        btree_set![Permission::Read, Permission::Insert],
    );

    // Create and authorise three apps, which we will put on the revocation queue.
    let auth_req1 = AuthReq {
        app: rand_app(),
        app_container: false,
        app_permissions: Default::default(),
        containers: create_containers_req(),
    };
    let app_id1 = auth_req1.app.id.clone();
    debug!("Registering app 1 with ID {}...", app_id1);
    let auth_granted1 = register_app(&authenticator, &auth_req1).await?;

    let auth_req2 = AuthReq {
        app: rand_app(),
        app_container: true,
        app_permissions: Default::default(),
        containers: corrupt_containers,
    };
    let app_id2 = auth_req2.app.id.clone();
    debug!("Registering app 2 with ID {}...", app_id2);
    let auth_granted2 = register_app(&authenticator, &auth_req2).await?;

    let auth_req3 = AuthReq {
        app: rand_app(),
        app_container: false,
        app_permissions: Default::default(),
        containers: create_containers_req(),
    };
    let app_id3 = auth_req3.app.id.clone();
    debug!("Registering app 3 with ID {}...", app_id3);
    let _auth_granted3 = register_app(&authenticator, &auth_req3).await?;

    // Put a file into the _downloads container.
    let mut ac_entries = access_container(&authenticator, app_id2.clone(), auth_granted2).await?;
    let (downloads_md, _) = unwrap!(ac_entries.remove("_downloads"));

    create_file(&authenticator, downloads_md, "video.mp4", vec![1; 10], true).await?;

    // Push apps 1 and 2 to the revocation queue.
    {
        let app_id1 = app_id1.clone();
        let app_id2 = app_id2.clone();
        let app_id2_clone = app_id2;

        let c2 = client.clone();
        let c3 = client.clone();
        let c4 = client.clone();
        let c5 = client.clone();

        let (version, queue) = get_app_revocation_queue(&client).await?;
        let _ = push_to_app_revocation_queue(&c2, queue, config::next_version(version), &app_id1)
            .await?;
        let (version, queue) = get_app_revocation_queue(&c3).await?;
        let _ =
            push_to_app_revocation_queue(&c4, queue, config::next_version(version), &app_id2_clone)
                .await?;
        corrupt_container(&c5, "_downloads").await?;
    }

    // Try to revoke app3.
    match try_revoke(&authenticator, &app_id3).await {
        // Ok(_) => panic!("Revocation succeeded with corrupted encryption key!"),
        // Revocation does not perform re-encryption
        Ok(()) => (),
        Err(AuthError::CoreError(CoreError::SymmetricDecipherFailure)) => (),
        Err(x) => panic!("An unexpected error occurred: {:?}", x),
    }

    let (_, queue) = unwrap!(get_app_revocation_queue(&client).await);

    // Verify app1 was revoked, app2 is not in the revocation queue,
    // app3 is not in the revocation queue. (Above revocation does not fail)
    let ac = unwrap!(try_access_container(&authenticator, app_id1.clone(), auth_granted1).await);
    assert!(ac.is_none());
    assert!(!queue.contains(&app_id1));
    assert!(!queue.contains(&app_id2));
    assert!(!queue.contains(&app_id3));

    Ok(())
}

// Test that flushing app revocation queue that is empty does not cause any
// mutation requests to be sent and subsequently does not charge the account
// balance.
#[tokio::test]
async fn flushing_empty_app_revocation_queue_does_not_mutate_network() -> Result<(), AuthError> {
    // Create account.
    let (auth, ..) = create_authenticator().await;
    let client = auth.client.clone();
    let balance_0 = unwrap!(client.get_balance(None).await);

    // There are no apps, so the queue is empty.
    revocation::flush_app_revocation_queue(&client).await?;

    let balance_1 = client.get_balance(None).await?;
    assert_eq!(balance_0, balance_1);

    // Now create an app and revoke it. Then flush the queue again and observe
    // the account balance did not change.
    let auth_req = AuthReq {
        app: rand_app(),
        app_container: false,
        app_permissions: Default::default(),
        containers: create_containers_req(),
    };
    let _ = unwrap!(register_app(&auth, &auth_req).await);
    let app_id = auth_req.app.id;

    revoke(&auth, &app_id).await;

    let balance_2 = client.get_balance(None).await?;

    // The queue is empty again.
    revocation::flush_app_revocation_queue(&client).await?;
    let balance_3 = client.get_balance(None).await?;
    assert_eq!(balance_2, balance_3);
    Ok(())
}

#[tokio::test]
async fn revocation_with_unencrypted_container_entries() -> Result<(), AuthError> {
    let (auth, ..) = create_authenticator().await;
    let client = auth.client.clone();

    let mut containers_req = HashMap::new();
    let _ = containers_req.insert(
        "_documents".to_owned(),
        btree_set![Permission::Read, Permission::Insert,],
    );

    let (app_id, _) = unwrap!(register_rand_app(&auth, true, containers_req).await);

    let shared_info = unwrap!(get_container_from_authenticator_entry(&client, "_documents").await);
    let shared_info2 = shared_info.clone();
    let shared_key = b"shared-key".to_vec();
    let shared_content = b"shared-value".to_vec();
    let shared_actions =
        MDataSeqEntryActions::new().ins(shared_key.clone(), shared_content.clone(), 0);

    let dedicated_info = unwrap!(
        get_container_from_authenticator_entry(&client, &app_container_name(&app_id),).await
    );
    let dedicated_info2 = dedicated_info.clone();
    let dedicated_key = b"dedicated-key".to_vec();
    let dedicated_content = b"dedicated-value".to_vec();
    let dedicated_actions =
        MDataSeqEntryActions::new().ins(dedicated_key.clone(), dedicated_content.clone(), 0);

    // Insert unencrypted stuff into the shared container and the dedicated container.
    let _ = client
        .mutate_seq_mdata_entries(shared_info.name(), shared_info.type_tag(), shared_actions)
        .await?;
    let _ = client
        .mutate_seq_mdata_entries(
            dedicated_info.name(),
            dedicated_info.type_tag(),
            dedicated_actions,
        )
        .await?;

    // Revoke the app.
    revoke(&auth, &app_id).await;

    // Verify that the unencrypted entries remain unencrypted after the revocation.
    let shared_value = client
        .get_seq_mdata_value(shared_info2.name(), shared_info2.type_tag(), shared_key)
        .await?;
    let dedicated_value = client
        .get_seq_mdata_value(
            dedicated_info2.name(),
            dedicated_info2.type_tag(),
            dedicated_key,
        )
        .await?;

    assert_eq!(shared_value.data, shared_content);
    assert_eq!(dedicated_value.data, dedicated_content);

    Ok(())
}

async fn count_mdata_entries(
    authenticator: &Authenticator,
    info: MDataInfo,
) -> Result<usize, AuthError> {
    let entries = authenticator
        .client
        .list_seq_mdata_entries(info.name(), info.type_tag())
        .await?;
    Ok(entries.len())
}
