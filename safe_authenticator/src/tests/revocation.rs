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

use super::utils::create_containers_req;
use Authenticator;
use app_container;
use errors::AuthError;
use futures::Future;
use revocation;
use routing::{AccountInfo, User};
use safe_core::{CoreError, MDataInfo};
use safe_core::ipc::AuthReq;
use safe_core::nfs::NfsError;
use test_utils::{access_container, create_account_and_login, create_authenticator, create_file,
                 fetch_file, rand_app, register_app, revoke, run, try_access_container};

#[cfg(feature = "use-mock-routing")]
mod mock_routing {
    use super::*;
    use AccessContainerEntry;
    use AuthFuture;
    use access_container;
    use app_auth::{AppState, app_state};
    use config;
    use ffi_utils::test_utils::call_0;
    use futures::future;
    use ipc::auth_flush_app_revocation_queue;
    use rand::{self, Rng};
    use routing::{ClientError, Request, Response};
    use safe_core::{Client, FutureExt};
    use safe_core::MockRouting;
    use safe_core::ipc::{IpcError, Permission};
    use safe_core::ipc::req::container_perms_into_permission_set;
    use std::collections::HashMap;
    use std::iter;
    use std::thread;
    use std::time::Duration;
    use test_utils::{get_container_from_root, register_rand_app, try_revoke};
    use tiny_keccak::sha3_256;

    // Test operation recovery for app revocation
    //
    // 1. Create a test app and authenticate it.
    // 2. Grant access to some of the default containers (e.g. `_video`, `_documents`).
    // 3. Put several files with a known content in both containers (e.g. `_video/test.txt` and
    //    `_documents/test2.txt`).
    // 4. Revoke the app access from the authenticator.
    // 5. After re-encryption of the `_document` container is done, simulate a network failure
    //    for the `_video` container encryption step.
    // 6. Verify that the `_videos` container is still accessible using the previous encryption key.
    // 7. Verify that the `_documents` container is not accessible using the current key, but is
    //    accessible using the new key.
    // 8. Check that the app's key is not listed in MaidManagers.
    // 9. Repeat step 1.4 (restart the revoke operation for the app) and don't interfere with the
    //    re-encryption process this time. It should pass.
    // 10. Verify that both the second and first containers aren't accessible using previous keys.
    // 11. Verify that both the second and first containers are accesible using the new keys.
    #[test]
    fn app_revocation_recovery() {
        let (auth, locator, password) = create_authenticator();

        // Create a test app and authenticate it.
        // Grant access to some of the default containers (e.g. `_video`, `_documents`).
        let auth_req = AuthReq {
            app: rand_app(),
            app_container: false,
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
        ));
        unwrap!(create_file(&auth, docs_md.clone(), "test.doc", vec![2; 10]));

        // After re-encryption of the first container (`_video`) is done, simulate a network failure
        let docs_name = docs_md.name;

        let access_container_md = run(&auth, move |client| {
            client.access_container().map_err(AuthError::from)
        });
        let access_cont_name = access_container_md.name;

        let routing_hook = move |mut routing: MockRouting| -> MockRouting {
            let mut fail_ac_update = false;

            routing.set_request_hook(move |req| {
                match *req {
                    // Simulate a network failure for a second request to re-encrypt containers
                    // so that the _videos container should remain untouched
                    Request::MutateMDataEntries { name, msg_id, .. }
                        if name == docs_name || (name == access_cont_name && fail_ac_update) => {
                        fail_ac_update = true;

                        Some(Response::MutateMDataEntries {
                            msg_id,
                            res: Err(ClientError::LowBalance),
                        })
                    }
                    // Pass-through
                    _ => None,
                }
            });
            routing
        };
        let auth = unwrap!(Authenticator::login_with_hook(
            locator.clone(),
            password.clone(),
            |_| (),
            routing_hook,
        ));

        // Revoke the app.
        match try_revoke(&auth, &app_id) {
            Err(AuthError::CoreError(CoreError::RoutingClientError(ClientError::LowBalance))) => (),
            x => panic!("Unexpected {:?}", x),
        }

        // Verify that the `_documents` container is still accessible using the previous key.
        let _ = unwrap!(fetch_file(&auth, docs_md.clone(), "test.doc"));

        // Verify that the `_videos` container is not accessible using the previous key,
        // but is accessible using the new key.
        match fetch_file(&auth, videos_md.clone(), "video.mp4") {
            Err(AuthError::NfsError(NfsError::CoreError(CoreError::EncodeDecodeError(..)))) => (),
            x => panic!("Unexpected {:?}", x),
        }

        // We'd need to get that new key from the root container though, as the access container
        // entry for the app hasn't been updated at this point.
        let mut reencrypted_videos_md = unwrap!(get_container_from_root(&auth, "_videos"));

        // The container has been reencrypted now, swap the old enc info
        reencrypted_videos_md.commit_new_enc_info();
        let _ = unwrap!(fetch_file(
            &auth,
            reencrypted_videos_md.clone(),
            "video.mp4",
        ));

        // Ensure that the app's key has been removed from MaidManagers
        let auth_keys = run(&auth, move |client| {
            client
                .list_auth_keys_and_version()
                .map(move |(auth_keys, _version)| auth_keys)
                .map_err(AuthError::from)
        });
        assert!(!auth_keys.contains(&auth_granted.app_keys.sign_pk));

        // Login and try to revoke the app again, now without interfering with responses
        let auth = unwrap!(Authenticator::login(
            locator.clone(),
            password.clone(),
            |_| (),
        ));

        // App revocation should succeed
        revoke(&auth, &app_id);

        // Try to access both files using previous keys - they shouldn't be accessible
        match fetch_file(&auth, docs_md.clone(), "test.doc") {
            Err(AuthError::NfsError(NfsError::CoreError(CoreError::EncodeDecodeError(..)))) => (),
            x => panic!("Unexpected {:?}", x),
        }
        match fetch_file(&auth, videos_md.clone(), "video.mp4") {
            Err(AuthError::NfsError(NfsError::CoreError(CoreError::EncodeDecodeError(..)))) => (),
            x => panic!("Unexpected {:?}", x),
        }

        // Get the new encryption info from the user's root dir (as the access container has been
        // removed now). Both containers should be accessible with the new keys without any extra
        // effort
        let ac_entries = try_access_container(&auth, app_id.clone(), auth_granted.clone());
        assert!(ac_entries.is_none());

        let reencrypted_docs_md = unwrap!(get_container_from_root(&auth, "_documents"));
        let reencrypted_videos_md = unwrap!(get_container_from_root(&auth, "_videos"));

        let _ = unwrap!(fetch_file(&auth, reencrypted_docs_md.clone(), "test.doc"));
        let _ = unwrap!(fetch_file(
            &auth,
            reencrypted_videos_md.clone(),
            "video.mp4",
        ));
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
            containers: create_containers_req(),
        };

        let app_id = auth_req.app.id.clone();
        let _ = unwrap!(register_app(&auth, &auth_req));

        // Attempt to revoke it which fails due to simulated network failure.
        simulate_revocation_failure(&locator, &password, iter::once(&app_id));

        // Attempt to re-authenticate the app fails, because revocation is pending.
        match register_app(&auth, &auth_req) {
            Err(_) => (), // TODO: assert expected error variant
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
            containers: create_containers_req(),
        };

        let _ = unwrap!(register_app(&auth, &auth_req));
        let app_id_0 = auth_req.app.id.clone();

        // Authenticate the second app.
        let auth_req = AuthReq {
            app: rand_app(),
            app_container: false,
            containers: create_containers_req(),
        };

        let _ = unwrap!(register_app(&auth, &auth_req));
        let app_id_1 = auth_req.app.id.clone();

        // Simulate failed revocations of both apps.
        simulate_revocation_failure(&locator, &password, &[&app_id_0, &app_id_1]);

        // Verify the apps are not revoked yet.
        {
            let app_id_0 = app_id_0.clone();
            let app_id_1 = app_id_1.clone();

            run(&auth, |client| {
                let client = client.clone();

                config::list_apps(&client)
                    .then(move |res| {
                        let (_, apps) = unwrap!(res);
                        let f_0 = app_state(&client, &apps, &app_id_0);
                        let f_1 = app_state(&client, &apps, &app_id_1);

                        f_0.join(f_1)
                    })
                    .then(|res| {
                        let (state_0, state_1) = unwrap!(res);
                        assert_eq!(state_0, AppState::Authenticated);
                        assert_eq!(state_1, AppState::Authenticated);

                        Ok(())
                    })
            })
        }

        // Login again without simulated failures.
        let auth = unwrap!(Authenticator::login(locator, password, |_| ()));

        // Flush the revocation queue and verify both apps get revoked.
        unsafe {
            unwrap!(call_0(
                |ud, cb| auth_flush_app_revocation_queue(&auth, ud, cb),
            ))
        }

        run(&auth, |client| {
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
        })
    }

    // Test one app being revoked by multiple authenticator concurrently.
    #[test]
    fn concurrent_revocation_of_single_app() {
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
        let info = unwrap!(get_container_from_root(&auth, "_documents"));
        unwrap!(create_file(&auth, info, "shared.txt", vec![0; 10]));

        // Put a file into the dedicated container of each app.
        for app_id in &[&app_id_0, &app_id_1] {
            let info = unwrap!(get_container_from_root(&auth, &app_container::name(app_id)));
            unwrap!(create_file(&auth, info, "private.txt", vec![0; 10]));
        }

        // Try to revoke the app concurrently using multiple authenticators (running
        // in separate threads).
        // (NOTE: doing `collect` after every step to prevent short-circuiting)
        let auths: Vec<_> = (0..concurrency)
            .map(|_| {
                // Insert random delays to prevent the operations from silently being
                // executed sequentially due to being too quick.
                unwrap!(login_authenticator_with_random_delays(
                    locator.clone(),
                    password.clone(),
                ))
            })
            .collect();

        let join_handles: Vec<_> = auths
            .into_iter()
            .map(|auth| {
                let app_id = app_id_0.clone();
                thread::spawn(move || try_revoke(&auth, &app_id))
            })
            .collect();

        let success = join_handles.into_iter().fold(
            false,
            |success, handle| match unwrap!(
                handle.join()
            ) {
                Ok(_) |
                Err(AuthError::IpcError(IpcError::UnknownApp)) => true,
                _ => success,
            },
        );

        // If none of the concurrently running revocations succeeded, let's give it
        // one more try, but this time using only one authenticator.
        // The idea behind this is that it's OK if revocation fails when run concurrently,
        // but it should always succeed when run non-concurrently - that is, the
        // concurrent runs should never leave things in inconsistent state.
        if !success {
            unwrap!(try_revoke(&auth, &app_id_0));
        }

        // Check that the first app is now revoked, but the second app is not.
        run(&auth, move |client| {
            let app_0 = verify_app_is_revoked(client, app_id_0, ac_entries_0);
            let app_1 = verify_app_is_authenticated(client, app_id_1);

            app_0.join(app_1).map(|_| ())
        });
    }

    // Test multiple apps being revoked concurrently.
    #[test]
    fn concurrent_revocation_of_multiple_apps() {
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
        let info = unwrap!(get_container_from_root(&auth, "_documents"));
        unwrap!(create_file(&auth, info, "shared.txt", vec![0; 10]));

        // Put a file into the dedicated container of each app.
        for app_id in &[&app_id_0, &app_id_1, &app_id_2] {
            let info = unwrap!(get_container_from_root(&auth, &app_container::name(app_id)));
            unwrap!(create_file(&auth, info, "private.txt", vec![0; 10]));
        }

        // Revoke the first two apps, concurrently.
        let apps_to_revoke = [app_id_0.clone(), app_id_1.clone()];
        let auths: Vec<_> = apps_to_revoke
            .iter()
            .map(|app_id| {
                let auth = unwrap!(login_authenticator_with_random_delays(
                    locator.clone(),
                    password.clone(),
                ));

                (auth, app_id.to_string())
            })
            .collect();

        let join_handles: Vec<_> = auths
            .into_iter()
            .map(|(auth, app_id)| {
                thread::spawn(move || try_revoke(&auth, &app_id))
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
                    Ok(_) |
                    Err(AuthError::IpcError(IpcError::UnknownApp)) => (),
                    Err(error) => panic!("Unexpected revocation failure: {:?}", error),
                }
            }
        }

        // Check that the first two apps are now revoked, but the other one is not.
        run(&auth, move |client| {
            let app_0 = verify_app_is_revoked(client, app_id_0, ac_entries_0);
            let app_1 = verify_app_is_revoked(client, app_id_1, ac_entries_1);
            let app_2 = verify_app_is_authenticated(client, app_id_2);

            app_0.join3(app_1, app_2).map(|_| ())
        });
    }


    // Try to revoke apps with the given ids, but simulate network failure so they
    // would be initiated but not finished.
    fn simulate_revocation_failure<T, S>(locator: &str, password: &str, app_ids: T)
    where
        T: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        // First, log in normally to obtain the access contained info.
        let auth = unwrap!(Authenticator::login(locator, password, |_| ()));
        let ac_info = run(&auth, |client| Ok(unwrap!(client.access_container())));

        // Then, log in with a request hook that makes mutation of the access container
        // fail.
        let auth = unwrap!(Authenticator::login_with_hook(
            locator,
            password,
            |_| (),
            move |mut routing| {
                let ac_info = ac_info.clone();

                routing.set_request_hook(move |request| match *request {
                    Request::MutateMDataEntries { name, tag, msg_id, .. } => {
                        if name == ac_info.name && tag == ac_info.type_tag {
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

                routing
            },
        ));

        // Then attempt to revoke each app from the iterator.
        for app_id in app_ids {
            match try_revoke(&auth, app_id.as_ref()) {
                Err(_) => (),
                x => panic!("Unexpected {:?}", x),
            }
        }
    }

    fn verify_app_is_revoked(
        client: &Client<()>,
        app_id: String,
        prev_ac_entry: AccessContainerEntry,
    ) -> Box<AuthFuture<()>> {
        let c0 = client.clone();
        let c1 = client.clone();

        config::list_apps(client)
            .then(move |res| {
                let (_, apps) = unwrap!(res);

                let auth_keys = c0.list_auth_keys_and_version().map_err(AuthError::from);
                let state = app_state(&c0, &apps, &app_id);

                let app_hash = sha3_256(app_id.as_bytes());
                let app_key = unwrap!(apps.get(&app_hash)).keys.sign_pk;

                auth_keys.join(state).map(move |((auth_keys, _), state)| {
                    (auth_keys, app_key, state)
                })
            })
            .then(move |res| -> Result<_, AuthError> {
                let (auth_keys, app_key, state) = unwrap!(res);

                // Verify the app is no longer authenticated.
                assert!(!auth_keys.contains(&app_key));

                // Verify its state is `Revoked` (meaning it has no entry in the
                // access container)
                assert_match!(state, AppState::Revoked);

                Ok(app_key)
            })
            .then(move |res| {
                let app_key = unwrap!(res);
                let futures = prev_ac_entry.into_iter().map(move |(_, (mdata_info, _))| {
                    // Verify the app has no permissions in the containers.
                    let perms = c1.list_mdata_user_permissions(
                        mdata_info.name,
                        mdata_info.type_tag,
                        User::Key(app_key),
                    ).then(|res| {
                            assert_match!(
                            res,
                            Err(CoreError::RoutingClientError(ClientError::NoSuchKey))
                        );
                            Ok(())
                        });

                    // Verify the app can't decrypt the content of the containers.
                    let entries = c1.list_mdata_entries(mdata_info.name, mdata_info.type_tag)
                        .then(move |res| {
                            let entries = unwrap!(res);
                            for (key, value) in entries {
                                if value.content.is_empty() {
                                    continue;
                                }

                                assert_match!(mdata_info.decrypt(&key), Err(_));
                                assert_match!(mdata_info.decrypt(&value.content), Err(_));
                            }

                            Ok(())
                        });

                    perms.join(entries).map(|_| ())
                });

                future::join_all(futures).map(|_| ())
            })
            .into_box()
    }

    fn verify_app_is_authenticated(client: &Client<()>, app_id: String) -> Box<AuthFuture<()>> {
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
                let app_key = app_keys.sign_pk;

                // Verify the app is authenticated.
                assert!(auth_keys.contains(&app_key));

                // Fetch the access container entry
                access_container::fetch_entry(&c1, &app_id, app_keys).map(
                    move |(_, entry)| (app_key, entry),
                )
            })
            .then(move |res| {
                let (app_key, ac_entry) = unwrap!(res);
                let user = User::Key(app_key);
                let ac_entry = unwrap!(ac_entry);

                let futures = ac_entry.into_iter().map(
                    move |(_, (mdata_info, permissions))| {
                        // Verify the app has the permissions set according to the access container.
                        let expected_perms = container_perms_into_permission_set(&permissions);
                        let perms = c2.list_mdata_user_permissions(
                            mdata_info.name,
                            mdata_info.type_tag,
                            user,
                        ).then(move |res| {
                                let perms = unwrap!(res);
                                assert_eq!(perms, expected_perms);
                                Ok(())
                            });

                        // Verify the app can decrypt the content of the containers.
                        let entries = c2.list_mdata_entries(mdata_info.name, mdata_info.type_tag)
                            .then(move |res| {
                                let entries = unwrap!(res);
                                for (key, value) in entries {
                                    if value.content.is_empty() {
                                        continue;
                                    }

                                    let _ = unwrap!(mdata_info.decrypt(&key));
                                    let _ = unwrap!(mdata_info.decrypt(&value.content));
                                }

                                Ok(())
                            });

                        perms.join(entries).map(|_| ())
                    },
                );

                future::join_all(futures).map(|_| ())
            })
            .into_box()
    }

    // Create authenticator instance that will randomly delay before each request.
    fn login_authenticator_with_random_delays(
        locator: String,
        password: String,
    ) -> Result<Authenticator, AuthError> {
        let hook = move |mut routing: MockRouting| -> MockRouting {
            routing.set_request_hook(move |_| {
                let mut rng = rand::thread_rng();
                let delay_ms = rng.gen_range(0, 200);
                thread::sleep(Duration::from_millis(delay_ms));

                None
            });
            routing
        };

        Authenticator::login_with_hook(locator, password, |_| (), hook)
    }
}

// The app revocation and re-authorization workflow.
#[test]
fn app_revocation() {
    let authenticator = create_account_and_login();

    // Create and authorise two apps.
    let auth_req1 = AuthReq {
        app: rand_app(),
        app_container: false,
        containers: create_containers_req(),
    };
    let app_id1 = auth_req1.app.id.clone();
    let auth_granted1 = unwrap!(register_app(&authenticator, &auth_req1));

    let auth_req2 = AuthReq {
        app: rand_app(),
        app_container: true,
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
    ));

    let mut ac_entries = access_container(&authenticator, app_id2.clone(), auth_granted2.clone());
    let (videos_md2, _) = unwrap!(ac_entries.remove("_videos"));
    unwrap!(create_file(
        &authenticator,
        videos_md2.clone(),
        "2.mp4",
        vec![1; 10],
    ));

    let app_container_name = app_container::name(&app_id2);
    let (app_container_md, _) = unwrap!(ac_entries.remove(&app_container_name));
    unwrap!(create_file(
        &authenticator,
        app_container_md.clone(),
        "3.mp4",
        vec![1; 10],
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

    // There should now be 4 entries - 2 deleted previous entries, 2 new,
    // re-encrypted entries.
    assert_eq!(count_mdata_entries(&authenticator, videos_md1.clone()), 4);

    // The first app is no longer be in the access container.
    let ac = try_access_container(&authenticator, app_id1.clone(), auth_granted1.clone());
    assert!(ac.is_none());

    // Container permissions includes only the second app.
    let (name, tag) = (videos_md2.name, videos_md2.type_tag);
    let perms = run(&authenticator, move |client| {
        client.list_mdata_permissions(name, tag).map_err(From::from)
    });
    assert!(!perms.contains_key(
        &User::Key(auth_granted1.app_keys.sign_pk),
    ));
    assert!(perms.contains_key(
        &User::Key(auth_granted2.app_keys.sign_pk),
    ));

    // The first app can no longer access the files.
    match fetch_file(&authenticator, videos_md1.clone(), "1.mp4") {
        Err(AuthError::NfsError(NfsError::CoreError(CoreError::EncodeDecodeError(..)))) => (),
        x => panic!("Unexpected {:?}", x),
    }

    match fetch_file(&authenticator, videos_md1.clone(), "2.mp4") {
        Err(AuthError::NfsError(NfsError::CoreError(CoreError::EncodeDecodeError(..)))) => (),
        x => panic!("Unexpected {:?}", x),
    }

    // The second app can still access both files after re-fetching the access container.
    let mut ac_entries = access_container(&authenticator, app_id2.clone(), auth_granted2.clone());
    let (videos_md2, _) = unwrap!(ac_entries.remove("_videos"));

    let _ = unwrap!(fetch_file(&authenticator, videos_md2.clone(), "1.mp4"));
    let _ = unwrap!(fetch_file(&authenticator, videos_md2.clone(), "2.mp4"));

    // Re-authorize the first app.
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

    // There should now be 6 entries (4 deleted, 2 new).
    assert_eq!(count_mdata_entries(&authenticator, videos_md1.clone()), 6);

    match fetch_file(&authenticator, videos_md1.clone(), "1.mp4") {
        Err(AuthError::NfsError(NfsError::CoreError(CoreError::EncodeDecodeError(..)))) => (),
        x => panic!("Unexpected {:?}", x),
    }

    match fetch_file(&authenticator, videos_md1.clone(), "2.mp4") {
        Err(AuthError::NfsError(NfsError::CoreError(CoreError::EncodeDecodeError(..)))) => (),
        x => panic!("Unexpected {:?}", x),
    }

    let mut ac_entries = access_container(&authenticator, app_id2.clone(), auth_granted2.clone());
    let (videos_md2, _) = unwrap!(ac_entries.remove("_videos"));
    let _ = unwrap!(fetch_file(&authenticator, videos_md2.clone(), "1.mp4"));
    let _ = unwrap!(fetch_file(&authenticator, videos_md2.clone(), "2.mp4"));

    // Revoke the second app that has created its own app container.
    revoke(&authenticator, &app_id2);

    match fetch_file(&authenticator, videos_md2.clone(), "1.mp4") {
        Err(AuthError::NfsError(NfsError::CoreError(CoreError::EncodeDecodeError(..)))) => (),
        x => panic!("Unexpected {:?}", x),
    }

    // Try to reauthorise and revoke the second app again - as it should have reused its
    // app container, the subsequent reauthorisation + revocation should work correctly too.
    let auth_granted2 = unwrap!(register_app(&authenticator, &auth_req2));

    // The second app should be able to access data from its own container,
    let mut ac_entries = access_container(&authenticator, app_id2.clone(), auth_granted2.clone());
    let (app_container_md, _) = unwrap!(ac_entries.remove(&app_container_name));

    assert_eq!(
        count_mdata_entries(&authenticator, app_container_md.clone()),
        2
    );
    let _ = unwrap!(fetch_file(
        &authenticator,
        app_container_md.clone(),
        "3.mp4",
    ));

    revoke(&authenticator, &app_id2);
}

// Test that flushing app revocation queue that is empty does not cause any
// mutation requests to be sent and subsequently does not charge the account
// balance.
#[test]
fn flushing_empty_app_revocation_queue_does_not_mutate_network() {
    // Create account.
    let (auth, ..) = create_authenticator();
    let account_info_0 = get_account_info(&auth);

    // There are no apps, so the queue is empty.
    run(
        &auth,
        |client| revocation::flush_app_revocation_queue(client),
    );

    let account_info_1 = get_account_info(&auth);
    assert_eq!(account_info_0, account_info_1);

    // Now create an app and revoke it. Then flush the queue again and observe
    // the account balance did not change.
    let auth_req = AuthReq {
        app: rand_app(),
        app_container: false,
        containers: create_containers_req(),
    };
    let _ = unwrap!(register_app(&auth, &auth_req));
    let app_id = auth_req.app.id;

    revoke(&auth, &app_id);

    let account_info_2 = get_account_info(&auth);

    // The queue is empty again.
    run(
        &auth,
        |client| revocation::flush_app_revocation_queue(client),
    );

    let account_info_3 = get_account_info(&auth);
    assert_eq!(account_info_2, account_info_3);
}

fn count_mdata_entries(authenticator: &Authenticator, info: MDataInfo) -> usize {
    run(authenticator, move |client| {
        client
            .list_mdata_entries(info.name, info.type_tag)
            .map(|entries| entries.len())
            .map_err(From::from)
    })
}

fn get_account_info(authenticator: &Authenticator) -> AccountInfo {
    run(authenticator, |client| {
        client.get_account_info().map_err(AuthError::from)
    })
}
