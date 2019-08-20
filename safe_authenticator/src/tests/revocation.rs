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
    client::AuthClient,
    config::{self, get_app_revocation_queue, push_to_app_revocation_queue},
    errors::AuthError,
    revocation,
    test_utils::{
        access_container, create_account_and_login, create_authenticator, create_file, fetch_file,
        get_container_from_authenticator_entry, rand_app, register_app, register_rand_app, revoke,
        try_access_container, try_revoke,
    },
    {access_container, run, AuthFuture, Authenticator},
};
use futures::{future, Future};
use safe_core::{
    app_container_name,
    client::AuthActions,
    ipc::req::container_perms_into_permission_set,
    ipc::resp::AccessContainerEntry,
    ipc::{AuthReq, Permission},
    Client, CoreError, FutureExt, MDataInfo,
};
use safe_nd::{Error as SndError, MDataAddress, MDataSeqEntryActions, PublicKey};
use std::collections::HashMap;
use tiny_keccak::sha3_256;

fn verify_app_is_revoked(
    client: &AuthClient,
    app_id: String,
    prev_ac_entry: AccessContainerEntry,
) -> Box<AuthFuture<()>> {
    let c0 = client.clone();
    let c1 = client.clone();

    config::list_apps(client)
        .and_then(move |(_, apps)| {
            let auth_keys = c0.list_auth_keys_and_version().map_err(AuthError::from);
            let state = app_state(&c0, &apps, &app_id);

            let app_hash = sha3_256(app_id.as_bytes());
            let app_key = PublicKey::from(unwrap!(apps.get(&app_hash)).keys.bls_pk);

            auth_keys
                .join(state)
                .map(move |((auth_keys, _), state)| (auth_keys, app_key, state))
        })
        .and_then(move |(auth_keys, app_key, state)| -> Result<_, AuthError> {
            // Verify the app is no longer authenticated.
            if auth_keys.contains_key(&app_key) {
                return Err(AuthError::Unexpected("App is still authenticated".into()));
            }

            // Verify its state is `Revoked` (meaning it has no entry in the access container).
            assert_match!(state, AppState::Revoked);

            Ok(app_key)
        })
        .and_then(move |app_key| {
            let futures = prev_ac_entry.into_iter().map(move |(_, (mdata_info, _))| {
                // Verify the app has no permissions in the containers.
                c1.list_mdata_user_permissions_new(*mdata_info.address(), app_key)
                    .then(|res| {
                        assert_match!(res, Err(CoreError::DataError(SndError::NoSuchKey)));
                        Ok(())
                    })
            });

            future::join_all(futures).map(|_| ())
        })
        .into_box()
}

fn verify_app_is_authenticated(client: &AuthClient, app_id: String) -> Box<AuthFuture<()>> {
    let c0 = client.clone();
    let c1 = client.clone();
    let c2 = client.clone();

    config::list_apps(client)
        .then(move |res| {
            let (_, mut apps) = unwrap!(res);

            let app_hash = sha3_256(app_id.as_bytes());
            let app_keys = unwrap!(apps.remove(&app_hash)).keys;

            c0.list_auth_keys_and_version()
                .map_err(AuthError::from)
                .map(move |(auth_keys, _)| (auth_keys, app_id, app_keys))
        })
        .then(move |res| {
            let (auth_keys, app_id, app_keys) = unwrap!(res);
            let app_key = PublicKey::from(app_keys.bls_pk);

            // Verify the app is authenticated.
            assert!(auth_keys.contains_key(&app_key));

            // Fetch the access container entry
            access_container::fetch_entry(&c1, &app_id, app_keys)
                .map(move |(_, entry)| (app_key, entry))
        })
        .then(move |res| {
            let (app_key, ac_entry) = unwrap!(res);
            let user = app_key;
            let ac_entry = unwrap!(ac_entry);

            let futures = ac_entry
                .into_iter()
                .map(move |(_, (mdata_info, permissions))| {
                    // Verify the app has the permissions set according to the access container.
                    let expected_perms = container_perms_into_permission_set(&permissions);
                    let perms = c2
                        .list_mdata_user_permissions_new(*mdata_info.address(), user)
                        .then(move |res| {
                            let perms = unwrap!(res);
                            assert_eq!(perms, expected_perms);
                            Ok(())
                        });

                    // Verify the app can decrypt the content of the containers.
                    let entries = c2
                        .list_seq_mdata_entries(mdata_info.name(), mdata_info.type_tag())
                        .then(move |res| {
                            let entries = unwrap!(res);
                            for (key, value) in entries {
                                if value.data.is_empty() {
                                    continue;
                                }

                                let _ = unwrap!(mdata_info.decrypt(&key));
                                let _ = unwrap!(mdata_info.decrypt(&value.data));
                            }

                            Ok(())
                        });

                    perms.join(entries).map(|_| ())
                });

            future::join_all(futures).map(|_| ())
        })
        .into_box()
}

#[cfg(feature = "mock-network")]
mod mock_routing {
    use super::*;
    use crate::{
        ffi::ipc::auth_flush_app_revocation_queue,
        test_utils::{get_container_from_authenticator_entry, register_rand_app, try_revoke},
    };
    use config;
    use ffi_utils::test_utils::call_0;
    use maidsafe_utilities::SeededRng;
    use safe_core::client::AuthActions;
    use safe_core::ipc::{IpcError, Permission};
    use safe_core::nfs::NfsError;
    use safe_core::utils::test_utils::Synchronizer;
    use std::{
        collections::HashMap,
        iter,
        sync::{Arc, Barrier},
        thread,
    };

    // Test operation recovery for app revocation
    //
    // 1. Create a test app and authenticate it.
    // 2. Grant access to some of the default containers (e.g. `_video`, `_documents`).
    // 3. Put several files with a known content in both containers (e.g. `_videos/video.mp4` and
    //    `_documents/test.doc`).
    // 4. Revoke the app access from the authenticator.
    // 5. Simulate network failure during the re-encryption of the `_document` container.
    // 6. Verify that the `_documents` container is still accessible using the previous `MDataInfo`.
    // 7. Verify that the `_videos` container is accessible using the new `MDataInfo`
    //    (it might or might not be still accessible using the old info, depending on whether
    //    its re-encryption managed to run to completion before the re-encryption of
    //    `_documents` failed).
    // 8. Check that the app key is not listed in MaidManagers.
    // 9. Repeat step 1.4 (restart the revoke operation for the app) and don't interfere with the
    //    re-encryption process this time. It should pass.
    // 10. Verify that both the second and first containers aren't accessible using previous
    //     `MDataInfo`.
    // 11. Verify that both the second and first containers are accessible using the new
    //     `MDataInfo`.
    #[test]
    fn app_revocation_recovery() {
        let (auth, locator, password) = create_authenticator();

        // Create a test app and authenticate it.
        // Grant access to some of the default containers (e.g. `_video`, `_documents`).
        let auth_req = AuthReq {
            app: rand_app(),
            app_container: false,
            app_permissions: Default::default(),
            containers: create_containers_req(),
        };
        let app_id = auth_req.app.id.clone();
        let auth_granted = unwrap!(register_app(&auth, &auth_req));

        // Put several files with a known content in both containers
        let mut ac_entries = access_container(&auth, app_id.clone(), auth_granted.clone());
        let (videos_md, _) = unwrap!(ac_entries.remove("_videos"));
        let (docs_md, _) = unwrap!(ac_entries.remove("_documents"));

        unwrap!(create_file(
            &auth,
            videos_md.clone(),
            "video.mp4",
            vec![1; 10],
            true,
        ));
        unwrap!(create_file(
            &auth,
            docs_md.clone(),
            "test.doc",
            vec![2; 10],
            true
        ));

        // After re-encryption of the first container (`_video`) is done, simulate a network failure
        // let docs_name = docs_md.name();

        // Hooks are disabled

        //        let routing_hook = move |mut routing: MockRouting| -> MockRouting {
        //            routing.set_request_hook_new(move |req| {
        //                match *req {
        //                    // Simulate a network failure for the request to re-encrypt
        //                    // the `_documents` container, so it remains untouched.
        //                    SndRequest::MutateSeqMDataEntries { address, .. }
        //                        if *address.name() == docs_name =>
        //                    {
        //                        Some(SndResponse::Mutation(Err(Error::InsufficientBalance)))
        //                    }
        //                    // Pass-through
        //                    _ => None,
        //                }
        //            });
        //            routing
        //        };
        //        let auth = unwrap!(Authenticator::login_with_hook(
        //            locator.clone(),
        //            password.clone(),
        //            || (),
        //            routing_hook,
        //        ));

        // Revoke the app.
        match try_revoke(&auth, &app_id) {
            // This will succeed since there are no hooks
            Ok(()) => (),
            x => panic!("Unexpected {:?}", x),
        }

        // Verify that the `_documents` container is still accessible using the previous info.
        let _ = unwrap!(fetch_file(&auth, docs_md.clone(), "test.doc"));

        // The re-encryption of `_videos` may or might not have successfully run
        // to completion. Try to fetch a file from it using the new info first.
        let new_videos_md = unwrap!(get_container_from_authenticator_entry(&auth, "_videos"));
        let success = match fetch_file(&auth, new_videos_md, "video.mp4") {
            Ok(_) => true,
            Err(AuthError::NfsError(NfsError::FileNotFound)) => false,
            x => panic!("Unexpected {:?}", x),
        };

        // If it failed, it means the `_videos` container re-encryption has not
        // been successfully completed. Verify that we can still access the file
        // using the old info.
        if !success {
            let _ = unwrap!(fetch_file(&auth, videos_md.clone(), "video.mp4"));
        }

        // Ensure that the app key has been removed from MaidManagers
        let auth_keys = unwrap!(run(&auth, move |client| {
            client
                .list_auth_keys_and_version()
                .map(move |(auth_keys, _version)| auth_keys)
                .map_err(AuthError::from)
        }));
        assert!(!auth_keys.contains_key(&PublicKey::from(auth_granted.app_keys.bls_pk)));

        // Login and try to revoke the app again, now without interfering with responses
        let auth = unwrap!(Authenticator::login(
            locator.clone(),
            password.clone(),
            || (),
        ));

        // App revocation should succeed
        revoke(&auth, &app_id);

        // Check that the app is now revoked.
        let app_id = app_id.clone();
        unwrap!(run(&auth, move |client| {
            verify_app_is_revoked(client, app_id, ac_entries)
        }));
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
    #[test]
    fn app_authentication_during_pending_revocation() {
        // Create account.
        let (auth, locator, password) = create_authenticator();

        // Authenticate the app.
        let auth_req = AuthReq {
            app: rand_app(),
            app_container: false,
            app_permissions: Default::default(),
            containers: create_containers_req(),
        };

        let app_id = auth_req.app.id.clone();
        let _ = unwrap!(register_app(&auth, &auth_req));

        // Attempt to revoke it which fails due to simulated network failure.
        simulate_revocation_failure(&locator, &password, iter::once(&app_id));

        // Attempt to re-authenticate the app fails, because revocation is pending.
        match register_app(&auth, &auth_req) {
            // Hooks are disabled
            Ok(_) => (), // TODO: assert expected error variant
            x => panic!("Unexpected {:?}", x),
        }

        // Retry the app revocation. This time it succeeds.
        revoke(&auth, &app_id);

        // Re-authentication now succeeds.
        let _ = unwrap!(register_app(&auth, &auth_req));
    }

    // Test flushing the app revocation queue.
    //
    // 1. Create two apps
    // 2. Revoke both of them, but simulate network failure so both revocations would
    //    fail.
    // 3. Log in again and flush the revocation queue with no simulated failures.
    // 4. Verify both apps are successfully revoked.
    #[test]
    fn flushing_app_revocation_queue() {
        // Create account.
        let (auth, locator, password) = create_authenticator();

        // Authenticate the first app.
        let auth_req = AuthReq {
            app: rand_app(),
            app_container: false,
            app_permissions: Default::default(),
            containers: create_containers_req(),
        };

        let _ = unwrap!(register_app(&auth, &auth_req));
        let app_id_0 = auth_req.app.id.clone();

        // Authenticate the second app.
        let auth_req = AuthReq {
            app: rand_app(),
            app_container: false,
            app_permissions: Default::default(),
            containers: create_containers_req(),
        };

        let _ = unwrap!(register_app(&auth, &auth_req));
        let app_id_1 = auth_req.app.id.clone();

        // Simulate failed revocations of both apps.
        simulate_revocation_failure(&locator, &password, &[&app_id_0, &app_id_1]);

        // Hooks are disabled
        // // Verify the apps are not revoked yet.
        // {
        //     let app_id_0 = app_id_0.clone();
        //     let app_id_1 = app_id_1.clone();

        //     unwrap!(run(&auth, |client| {
        //         let client = client.clone();

        //         config::list_apps(&client)
        //             .then(move |res| {
        //                 let (_, apps) = unwrap!(res);
        //                 let f_0 = app_state(&client, &apps, &app_id_0);
        //                 let f_1 = app_state(&client, &apps, &app_id_1);

        //                 f_0.join(f_1)
        //             })
        //             .then(|res| {
        //                 let (state_0, state_1) = unwrap!(res);
        //                 assert_eq!(state_0, AppState::Authenticated);
        //                 assert_eq!(state_1, AppState::Authenticated);

        //                 Ok(())
        //             })
        //     }))
        // }

        // Login again without simulated failures.
        let auth = unwrap!(Authenticator::login(locator, password, || ()));

        // Flush the revocation queue and verify both apps get revoked.
        unsafe {
            unwrap!(call_0(|ud, cb| auth_flush_app_revocation_queue(
                &auth, ud, cb
            ),))
        }

        unwrap!(run(&auth, |client| {
            let c2 = client.clone();

            config::list_apps(client)
                .then(move |res| {
                    let (_, apps) = unwrap!(res);
                    let f_0 = app_state(&c2, &apps, &app_id_0);
                    let f_1 = app_state(&c2, &apps, &app_id_1);

                    f_0.join(f_1)
                })
                .then(move |res| {
                    let (state_0, state_1) = unwrap!(res);
                    assert_eq!(state_0, AppState::Revoked);
                    assert_eq!(state_1, AppState::Revoked);

                    Ok(())
                })
        }))
    }

    // Test one app being revoked by multiple authenticator concurrently.
    #[test]
    fn concurrent_revocation_of_single_app() {
        let rng = SeededRng::new();

        // Number of concurrent operations.
        let concurrency = 2;

        // Create account.
        let (auth, locator, password) = create_authenticator();

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
            unwrap!(register_rand_app(&auth, true, containers_req.clone()));
        let (app_id_1, _) = unwrap!(register_rand_app(&auth, true, containers_req));

        let ac_entries_0 = access_container(&auth, app_id_0.clone(), auth_granted_0);

        // Put a file into the shared container.
        let info = unwrap!(get_container_from_authenticator_entry(&auth, "_documents"));
        unwrap!(create_file(&auth, info, "shared.txt", vec![0; 10], true));

        // Put a file into the dedicated container of each app.
        for app_id in &[&app_id_0, &app_id_1] {
            let info = unwrap!(get_container_from_authenticator_entry(
                &auth,
                &app_container_name(app_id),
            ));
            unwrap!(create_file(&auth, info, "private.txt", vec![0; 10], true));
        }

        // Try to revoke the app concurrently using multiple authenticators (running
        // in separate threads).

        // This barrier makes sure the revocations are started only after all
        // the authenticators are fully initialized.
        let barrier = Arc::new(Barrier::new(concurrency));
        let sync = Synchronizer::new(rng);

        let join_handles: Vec<_> = (0..concurrency)
            .map(|_| {
                let locator = locator.clone();
                let password = password.clone();
                let app_id = app_id_0.clone();
                let barrier = Arc::clone(&barrier);
                let sync = sync.clone();

                thread::spawn(move || {
                    let auth = unwrap!(Authenticator::login_with_hook(
                        locator,
                        password,
                        || (),
                        move |routing| sync.hook(routing),
                    ));

                    let _ = barrier.wait();
                    try_revoke(&auth, &app_id)
                })
            })
            // Doing `collect` to prevent short-circuiting.
            .collect();

        let success =
            join_handles
                .into_iter()
                .fold(false, |success, handle| match unwrap!(handle.join()) {
                    Ok(_) | Err(AuthError::IpcError(IpcError::UnknownApp)) => true,
                    _ => success,
                });

        // If none of the concurrently running revocations succeeded, let's give it
        // one more try, but this time using only one authenticator.
        // The idea behind this is that it's OK if revocation fails when run concurrently,
        // but it should always succeed when run non-concurrently - that is, the
        // concurrent runs should never leave things in inconsistent state.
        if !success {
            unwrap!(try_revoke(&auth, &app_id_0));
        }

        // Check that the first app is now revoked, but the second app is not.
        unwrap!(run(&auth, move |client| {
            let app_0 = verify_app_is_revoked(client, app_id_0, ac_entries_0);
            let app_1 = verify_app_is_authenticated(client, app_id_1);

            app_0.join(app_1).map(|_| ())
        }));
    }

    // Test multiple apps being revoked concurrently.
    #[test]
    fn concurrent_revocation_of_multiple_apps() {
        let rng = SeededRng::new();

        // Create account.
        let (auth, locator, password) = create_authenticator();

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
            unwrap!(register_rand_app(&auth, true, containers_req.clone()));
        let (app_id_1, auth_granted_1) =
            unwrap!(register_rand_app(&auth, true, containers_req.clone()));
        let (app_id_2, _) = unwrap!(register_rand_app(&auth, true, containers_req));

        let ac_entries_0 = access_container(&auth, app_id_0.clone(), auth_granted_0);
        let ac_entries_1 = access_container(&auth, app_id_1.clone(), auth_granted_1);

        // Put a file into the shared container.
        let info = unwrap!(get_container_from_authenticator_entry(&auth, "_documents"));
        unwrap!(create_file(&auth, info, "shared.txt", vec![0; 10], true));

        // Put a file into the dedicated container of each app.
        for app_id in &[&app_id_0, &app_id_1, &app_id_2] {
            let info = unwrap!(get_container_from_authenticator_entry(
                &auth,
                &app_container_name(app_id),
            ));
            unwrap!(create_file(&auth, info, "private.txt", vec![0; 10], true));
        }

        // Revoke the first two apps, concurrently.
        let apps_to_revoke = [app_id_0.clone(), app_id_1.clone()];

        // This barrier makes sure the revocations are started only after all
        // the authenticators are fully initialized.
        let barrier = Arc::new(Barrier::new(apps_to_revoke.len()));
        let sync = Synchronizer::new(rng);

        let join_handles: Vec<_> = apps_to_revoke
            .iter()
            .map(|app_id| {
                let locator = locator.clone();
                let password = password.clone();
                let app_id = app_id.to_string();
                let barrier = Arc::clone(&barrier);
                let sync = sync.clone();

                thread::spawn(move || {
                    let auth = unwrap!(Authenticator::login_with_hook(
                        locator,
                        password,
                        || (),
                        move |routing| sync.hook(routing),
                    ));

                    let _ = barrier.wait();
                    try_revoke(&auth, &app_id)
                })
            })
            .collect();

        let results: Vec<_> = join_handles
            .into_iter()
            .map(|handle| unwrap!(handle.join()))
            .collect();

        // Retry failed revocations sequentially.
        for (app_id, result) in apps_to_revoke.iter().zip(results) {
            if result.is_err() {
                match try_revoke(&auth, app_id) {
                    Ok(_) | Err(AuthError::IpcError(IpcError::UnknownApp)) => (),
                    Err(error) => panic!("Unexpected revocation failure: {:?}", error),
                }
            }
        }

        // Check that the first two apps are now revoked, but the other one is not.
        unwrap!(run(&auth, move |client| {
            let app_0 = verify_app_is_revoked(client, app_id_0, ac_entries_0);
            let app_1 = verify_app_is_revoked(client, app_id_1, ac_entries_1);
            let app_2 = verify_app_is_authenticated(client, app_id_2);

            app_0.join3(app_1, app_2).map(|_| ())
        }));
    }

    // Try to revoke apps with the given ids, but simulate network failure so they
    // would be initiated but not finished.
    fn simulate_revocation_failure<T, S>(locator: &str, password: &str, app_ids: T)
    where
        T: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        // First, log in normally to obtain the access contained info.
        let auth = unwrap!(Authenticator::login(locator, password, || ()));
        let _ac_info = unwrap!(run(&auth, |client| Ok(client.access_container())));

        // Then, log in with a request hook that makes mutation of the access container
        // fail.
        let auth = unwrap!(Authenticator::login_with_hook(
            locator,
            password,
            || (),
            move |cm| {
                // FIXME: hooks system
                /*
                let ac_info = ac_info.clone();

                cm.set_request_hook(move |request| match *request {
                    Request::MutateMDataEntries {
                        name, tag, msg_id, ..
                    } => {
                        if name == ac_info.name() && tag == ac_info.type_tag() {
                            Some(Response::MutateMDataEntries {
                                res: Err(ClientError::LowBalance),
                                msg_id,
                            })
                        } else {
                            None
                        }
                    }
                    _ => None,
                });
                */
                cm
            },
        ));

        // Then attempt to revoke each app from the iterator.
        for app_id in app_ids {
            match try_revoke(&auth, app_id.as_ref()) {
                // Hooks are disabled
                Ok(()) => (),
                x => panic!("Unexpected {:?}", x),
            }
        }
    }
}

// The app revocation and re-authorisation workflow.
#[test]
fn app_revocation_and_reauth() {
    let authenticator = create_account_and_login();

    // Create and authorise two apps.
    let auth_req1 = AuthReq {
        app: rand_app(),
        app_container: false,
        app_permissions: Default::default(),
        containers: create_containers_req(),
    };
    let app_id1 = auth_req1.app.id.clone();
    let auth_granted1 = unwrap!(register_app(&authenticator, &auth_req1));

    let auth_req2 = AuthReq {
        app: rand_app(),
        app_container: true,
        app_permissions: Default::default(),
        containers: create_containers_req(),
    };
    let app_id2 = auth_req2.app.id.clone();
    let auth_granted2 = unwrap!(register_app(&authenticator, &auth_req2));

    // Put one file by each app into a shared container.
    let mut ac_entries = access_container(&authenticator, app_id1.clone(), auth_granted1.clone());
    let (videos_md1, _) = unwrap!(ac_entries.remove("_videos"));
    unwrap!(create_file(
        &authenticator,
        videos_md1.clone(),
        "1.mp4",
        vec![1; 10],
        true,
    ));

    let mut ac_entries = access_container(&authenticator, app_id2.clone(), auth_granted2.clone());
    let (videos_md2, _) = unwrap!(ac_entries.remove("_videos"));
    unwrap!(create_file(
        &authenticator,
        videos_md2.clone(),
        "2.mp4",
        vec![1; 10],
        true,
    ));

    let app_container_name = app_container_name(&app_id2);
    let (app_container_md, _) = unwrap!(ac_entries.remove(&app_container_name));
    unwrap!(create_file(
        &authenticator,
        app_container_md.clone(),
        "3.mp4",
        vec![1; 10],
        true,
    ));

    // There should be 2 entries.
    assert_eq!(count_mdata_entries(&authenticator, videos_md1.clone()), 2);

    // Both apps can access both files.
    let _ = unwrap!(fetch_file(&authenticator, videos_md1.clone(), "1.mp4"));
    let _ = unwrap!(fetch_file(&authenticator, videos_md1.clone(), "2.mp4"));

    let _ = unwrap!(fetch_file(&authenticator, videos_md2.clone(), "1.mp4"));
    let _ = unwrap!(fetch_file(&authenticator, videos_md2.clone(), "2.mp4"));

    // Revoke the first app.
    revoke(&authenticator, &app_id1);

    // There should now be 2 entries.
    assert_eq!(count_mdata_entries(&authenticator, videos_md1.clone()), 2);

    // The first app is no longer in the access container.
    let ac = try_access_container(&authenticator, app_id1.clone(), auth_granted1.clone());
    assert!(ac.is_none());

    // Container permissions include only the second app.
    let (name, tag) = (videos_md2.name(), videos_md2.type_tag());
    let perms = unwrap!(run(&authenticator, move |client| {
        client
            .list_mdata_permissions_new(MDataAddress::Seq { name, tag })
            .map_err(From::from)
    }));
    assert!(!perms.contains_key(&PublicKey::from(auth_granted1.app_keys.bls_pk)));
    assert!(perms.contains_key(&PublicKey::from(auth_granted2.app_keys.bls_pk)));

    // Check that the first app is now revoked, but the second app is not.
    let (app_id1_clone, app_id2_clone) = (app_id1.clone(), app_id2.clone());
    unwrap!(run(&authenticator, move |client| {
        let app_1 = verify_app_is_revoked(client, app_id1_clone, ac_entries);
        let app_2 = verify_app_is_authenticated(client, app_id2_clone);

        app_1.join(app_2).map(|_| ())
    }));

    // The second app can still access both files after re-fetching the access container.
    let mut ac_entries = access_container(&authenticator, app_id2.clone(), auth_granted2.clone());
    let (videos_md2, _) = unwrap!(ac_entries.remove("_videos"));

    let _ = unwrap!(fetch_file(&authenticator, videos_md2.clone(), "1.mp4"));
    let _ = unwrap!(fetch_file(&authenticator, videos_md2.clone(), "2.mp4"));

    // Re-authorise the first app.
    let auth_granted1 = unwrap!(register_app(&authenticator, &auth_req1));
    let mut ac_entries = access_container(&authenticator, app_id1.clone(), auth_granted1.clone());
    let (videos_md1, _) = unwrap!(ac_entries.remove("_videos"));

    // The first app can access the files again.
    let _ = unwrap!(fetch_file(&authenticator, videos_md1.clone(), "1.mp4"));
    let _ = unwrap!(fetch_file(&authenticator, videos_md1.clone(), "2.mp4"));

    // The second app as well.
    let _ = unwrap!(fetch_file(&authenticator, videos_md2.clone(), "1.mp4"));
    let _ = unwrap!(fetch_file(&authenticator, videos_md2.clone(), "2.mp4"));

    // Revoke the first app again. Only the second app can access the files.
    revoke(&authenticator, &app_id1);

    // There should now be 2 entries.
    assert_eq!(count_mdata_entries(&authenticator, videos_md1.clone()), 2);

    // Check that the first app is now revoked, but the second app is not.
    let (app_id1_clone, app_id2_clone) = (app_id1.clone(), app_id2.clone());
    unwrap!(run(&authenticator, move |client| {
        let app_1 = verify_app_is_revoked(client, app_id1_clone, ac_entries);
        let app_2 = verify_app_is_authenticated(client, app_id2_clone);

        app_1.join(app_2).map(|_| ())
    }));

    let mut ac_entries = access_container(&authenticator, app_id2.clone(), auth_granted2.clone());
    let (videos_md2, _) = unwrap!(ac_entries.remove("_videos"));
    let _ = unwrap!(fetch_file(&authenticator, videos_md2.clone(), "1.mp4"));
    let _ = unwrap!(fetch_file(&authenticator, videos_md2.clone(), "2.mp4"));

    // Revoke the second app that has created its own app container.
    revoke(&authenticator, &app_id2);

    // Check that the first and second apps are both revoked.
    let (app_id1_clone, app_id2_clone) = (app_id1.clone(), app_id2.clone());
    unwrap!(run(&authenticator, move |client| {
        let app_1 = verify_app_is_revoked(client, app_id1_clone, ac_entries.clone());
        let app_2 = verify_app_is_revoked(client, app_id2_clone, ac_entries);

        app_1.join(app_2).map(|_| ())
    }));

    // Try to reauthorise and revoke the second app again - as it should have reused its
    // app container, the subsequent reauthorisation + revocation should work correctly too.
    let auth_granted2 = unwrap!(register_app(&authenticator, &auth_req2));

    // The second app should be able to access data from its own container,
    let mut ac_entries = access_container(&authenticator, app_id2.clone(), auth_granted2.clone());
    let (app_container_md, _) = unwrap!(ac_entries.remove(&app_container_name));

    assert_eq!(
        count_mdata_entries(&authenticator, app_container_md.clone()),
        1
    );
    let _ = unwrap!(fetch_file(
        &authenticator,
        app_container_md.clone(),
        "3.mp4",
    ));

    // Check that the second app is authenticated.
    let app_id2_clone = app_id2.clone();
    unwrap!(run(&authenticator, move |client| {
        verify_app_is_authenticated(client, app_id2_clone)
    }));

    revoke(&authenticator, &app_id2);

    // Check that the second app is now revoked again.
    let app_id2_clone = app_id2.clone();
    unwrap!(run(&authenticator, move |client| {
        verify_app_is_revoked(client, app_id2_clone, ac_entries)
    }));
}

// Test that corrupting an app's entry before trying to revoke it results in a
// `SymmetricDecipherFailure` error and immediate return, without revoking more apps.
// TODO: Alter/Deprecate this test as the new impl does not perform re-encryption
#[test]
#[ignore]
fn revocation_symmetric_decipher_failure() {
    let authenticator = create_account_and_login();

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
    let auth_granted1 = unwrap!(register_app(&authenticator, &auth_req1));

    let auth_req2 = AuthReq {
        app: rand_app(),
        app_container: true,
        app_permissions: Default::default(),
        containers: corrupt_containers,
    };
    let app_id2 = auth_req2.app.id.clone();
    debug!("Registering app 2 with ID {}...", app_id2);
    let auth_granted2 = unwrap!(register_app(&authenticator, &auth_req2));

    let auth_req3 = AuthReq {
        app: rand_app(),
        app_container: false,
        app_permissions: Default::default(),
        containers: create_containers_req(),
    };
    let app_id3 = auth_req3.app.id.clone();
    debug!("Registering app 3 with ID {}...", app_id3);
    let _auth_granted3 = unwrap!(register_app(&authenticator, &auth_req3));

    // Put a file into the _downloads container.
    let mut ac_entries = access_container(&authenticator, app_id2.clone(), auth_granted2.clone());
    let (downloads_md, _) = unwrap!(ac_entries.remove("_downloads"));

    unwrap!(create_file(
        &authenticator,
        downloads_md.clone(),
        "video.mp4",
        vec![1; 10],
        true,
    ));

    // Push apps 1 and 2 to the revocation queue.
    {
        let app_id1 = app_id1.clone();
        let app_id2 = app_id2.clone();
        let app_id2_clone = app_id2.clone();

        unwrap!(run(&authenticator, move |client| {
            let c2 = client.clone();
            let c3 = client.clone();
            let c4 = client.clone();
            let c5 = client.clone();

            get_app_revocation_queue(client)
                .map(move |(version, queue)| {
                    let _ = push_to_app_revocation_queue(
                        &c2,
                        queue,
                        config::next_version(version),
                        &app_id1,
                    );
                })
                .and_then(move |_| {
                    get_app_revocation_queue(&c3).map(move |(version, queue)| {
                        let _ = push_to_app_revocation_queue(
                            &c4,
                            queue,
                            config::next_version(version),
                            &app_id2_clone,
                        );
                    })
                })
                .and_then(move |_| corrupt_container(&c5, "_downloads"))
        }));
    }

    // Try to revoke app3.
    match try_revoke(&authenticator, &app_id3) {
        // Ok(_) => panic!("Revocation succeeded with corrupted encryption key!"),
        // Revocation does not perform re-encryption
        Ok(()) => (),
        Err(AuthError::CoreError(CoreError::SymmetricDecipherFailure)) => (),
        Err(x) => panic!("An unexpected error occurred: {:?}", x),
    }

    let queue = unwrap!(run(&authenticator, move |client| {
        get_app_revocation_queue(client).map(|(_, queue)| queue)
    }));

    // Verify app1 was revoked, app2 is not in the revocation queue,
    // app3 is not in the revocation queue. (Above revocation does not fail)
    let ac = try_access_container(&authenticator, app_id1.clone(), auth_granted1.clone());
    assert!(ac.is_none());
    assert!(!queue.contains(&app_id1));
    assert!(!queue.contains(&app_id2));
    assert!(!queue.contains(&app_id3));
}

// Test that flushing app revocation queue that is empty does not cause any
// mutation requests to be sent and subsequently does not charge the account
// balance.
#[test]
fn flushing_empty_app_revocation_queue_does_not_mutate_network() {
    // Create account.
    let (auth, ..) = create_authenticator();
    let balance_0 = unwrap!(run(&auth, |client| {
        client.get_balance(None).map_err(AuthError::from)
    }));

    // There are no apps, so the queue is empty.
    unwrap!(run(&auth, |client| {
        revocation::flush_app_revocation_queue(client)
    }));

    let balance_1 = unwrap!(run(&auth, |client| {
        client.get_balance(None).map_err(AuthError::from)
    }));
    assert_eq!(balance_0, balance_1);

    // Now create an app and revoke it. Then flush the queue again and observe
    // the account balance did not change.
    let auth_req = AuthReq {
        app: rand_app(),
        app_container: false,
        app_permissions: Default::default(),
        containers: create_containers_req(),
    };
    let _ = unwrap!(register_app(&auth, &auth_req));
    let app_id = auth_req.app.id;

    revoke(&auth, &app_id);

    let balance_2 = unwrap!(run(&auth, |client| {
        client.get_balance(None).map_err(AuthError::from)
    }));

    // The queue is empty again.
    unwrap!(run(&auth, |client| {
        revocation::flush_app_revocation_queue(client)
    }));
    let balance_3 = unwrap!(run(&auth, |client| {
        client.get_balance(None).map_err(AuthError::from)
    }));
    assert_eq!(balance_2, balance_3);
}

#[test]
fn revocation_with_unencrypted_container_entries() {
    let (auth, ..) = create_authenticator();

    let mut containers_req = HashMap::new();
    let _ = containers_req.insert(
        "_documents".to_owned(),
        btree_set![Permission::Read, Permission::Insert,],
    );

    let (app_id, _) = unwrap!(register_rand_app(&auth, true, containers_req));

    let shared_info = unwrap!(get_container_from_authenticator_entry(&auth, "_documents"));
    let shared_info2 = shared_info.clone();
    let shared_key = b"shared-key".to_vec();
    let shared_content = b"shared-value".to_vec();
    let shared_actions =
        MDataSeqEntryActions::new().ins(shared_key.clone(), shared_content.clone(), 0);

    let dedicated_info = unwrap!(get_container_from_authenticator_entry(
        &auth,
        &app_container_name(&app_id),
    ));
    let dedicated_info2 = dedicated_info.clone();
    let dedicated_key = b"dedicated-key".to_vec();
    let dedicated_content = b"dedicated-value".to_vec();
    let dedicated_actions =
        MDataSeqEntryActions::new().ins(dedicated_key.clone(), dedicated_content.clone(), 0);

    // Insert unencrypted stuff into the shared container and the dedicated container.
    unwrap!(run(&auth, move |client| {
        let f0 = client.mutate_seq_mdata_entries(
            shared_info.name(),
            shared_info.type_tag(),
            shared_actions,
        );
        let f1 = client.mutate_seq_mdata_entries(
            dedicated_info.name(),
            dedicated_info.type_tag(),
            dedicated_actions,
        );

        f0.join(f1).map(|_| ()).map_err(AuthError::from)
    }));

    // Revoke the app.
    revoke(&auth, &app_id);

    // Verify that the unencrypted entries remain unencrypted after the revocation.
    unwrap!(run(&auth, move |client| {
        let f0 =
            client.get_seq_mdata_value(shared_info2.name(), shared_info2.type_tag(), shared_key);
        let f1 = client.get_seq_mdata_value(
            dedicated_info2.name(),
            dedicated_info2.type_tag(),
            dedicated_key,
        );

        f0.join(f1).then(move |res| {
            let (shared_value, dedicated_value) = unwrap!(res);
            assert_eq!(shared_value.data, shared_content);
            assert_eq!(dedicated_value.data, dedicated_content);

            Ok(())
        })
    }))
}

fn count_mdata_entries(authenticator: &Authenticator, info: MDataInfo) -> usize {
    unwrap!(run(authenticator, move |client| {
        client
            .list_seq_mdata_entries(info.name(), info.type_tag())
            .map(|entries| entries.len())
            .map_err(From::from)
    }))
}
