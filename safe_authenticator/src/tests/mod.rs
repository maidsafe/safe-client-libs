// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

#![allow(unsafe_code)]

mod revocation;
mod serialisation;
mod utils;

use crate::access_container as access_container_tools;
use crate::config::KEY_APPS;
use crate::errors::AuthError;
use crate::run;
use crate::std_dirs::{DEFAULT_PRIVATE_DIRS, DEFAULT_PUBLIC_DIRS};
use crate::test_utils::{self};
use futures::{future, Future};
use safe_core::{mdata_info, Client};
use unwrap::unwrap;

#[cfg(feature = "mock-network")]
mod mock_routing {
    use super::utils;
    use crate::access_container as access_container_tools;
    use crate::errors::AuthError;
    use crate::run;
    use crate::std_dirs::{DEFAULT_PRIVATE_DIRS, DEFAULT_PUBLIC_DIRS};
    use crate::{test_utils, Authenticator};
    use futures::Future;
    use safe_core::ipc::AuthReq;
    use safe_core::nfs::NfsError;
    use safe_core::utils::generate_random_string;
    use safe_core::utils::test_utils::gen_client_id;
    use safe_core::{
        app_container_name, test_create_balance, Client, ConnectionManager, CoreError,
    };
    use safe_nd::{
        ClientRequest, Coins, Error as SndError, MDataRequest, Request, RequestType, Response,
    };
    use std::str::FromStr;
    use unwrap::unwrap;

    // Test operation recovery for std dirs creation.
    // 1. Try to create a new user's account using `safe_authenticator::Authenticator::create_acc`
    // 2. Simulate a network disconnection [1] for a randomly selected `PutMData` operation
    //    with a type_tag == `safe_core::DIR_TAG` (in the range from 3rd request to
    //    `safe_core::nfs::DEFAULT_PRIVATE_DIRS.len()`). This will meddle with creation of
    //    default directories.
    // 3. Try to log in using the same credentials that have been provided for `create_acc`.
    //    The log in operation should be successful.
    // 4. Check that after logging in the remaining default directories have been created
    //    (= operation recovery worked after log in)
    // 5. Check the access container entry in the user's config root - it must be accessible
    #[test]
    fn std_dirs_recovery() {
        // Add a request hook to forbid root dir modification. In this case
        // account creation operation will be failed, but login still should
        // be possible afterwards.
        let locator = unwrap!(generate_random_string(10));
        let password = unwrap!(generate_random_string(10));
        let client_id = gen_client_id();

        unwrap!(test_create_balance(
            &client_id,
            unwrap!(Coins::from_str("10"))
        ));

        {
            let cm_hook = move |mut cm: ConnectionManager| -> ConnectionManager {
                let mut put_mdata_counter = 0;

                cm.set_request_hook(move |req| {
                    match req {
                        Request::MData(MDataRequest::Put(data))
                            if data.tag() == safe_core::DIR_TAG =>
                        {
                            put_mdata_counter += 1;

                            if put_mdata_counter > 4 {
                                Some(Response::Mutation(Err(SndError::InsufficientBalance)))
                            } else {
                                None
                            }
                        }
                        // Pass-through
                        _ => None,
                    }
                });
                cm
            };

            let authenticator = Authenticator::create_acc_with_hook(
                locator.clone(),
                password.clone(),
                client_id,
                || (),
                cm_hook,
            );

            // This operation should fail
            match authenticator {
                Err(AuthError::AccountContainersCreation(_)) => (),
                Err(x) => panic!("Unexpected error {:?}", x),
                Ok(_) => panic!("Unexpected success"),
            }
        }

        // Log in using the same credentials
        let authenticator = unwrap!(Authenticator::login(locator, password, || ()));

        // Make sure that all default directories have been created after log in.
        let std_dir_names: Vec<_> = DEFAULT_PRIVATE_DIRS
            .iter()
            .cloned()
            .chain(DEFAULT_PUBLIC_DIRS.iter().cloned())
            .collect();

        // Verify that the access container has been created and
        // fetch the entries of the root authenticator entry.
        let (_entry_version, entries) = unwrap!(run(&authenticator, |client| {
            access_container_tools::fetch_authenticator_entry(client).map_err(AuthError::from)
        }));

        // Verify that all the std dirs are there.
        for name in std_dir_names {
            assert!(entries.contains_key(name));
        }
    }

    // Ensure that users can log in with low account balance.
    #[test]
    fn login_with_low_balance() {
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

        // Make sure we can log in
        let _authenticator = test_utils::create_account_and_login_with_hook(cm_hook);
    }

    // Test operation recovery for app authentication.
    //
    // 1. Create a test app and try to authenticate it (with `app_container` set to true).
    //
    // 2. Simulate a network failure after the `mutate_mdata_entries` operation (relating to the
    //    addition of the app to the user's config dir) - it should leave the app in the
    //    `Revoked` state (as it is listen in the config root, but not in the access
    //    container)
    // 3. Try to authenticate the app again, it should continue without errors
    //
    // 4. Simulate a network failure after the `ins_auth_key` operation.
    //    The authentication op should fail.
    // 5. Try to authenticate the app again, it should continue without errors
    //
    // 6. Simulate a network failure for the `set_mdata_user_permissions` operation
    //    (relating to the app's container - so that it will be created successfuly, but fail
    //    at the permissions set stage).
    // 7. Try to authenticate the app again, it should continue without errors.
    //
    // 8. Simulate a network failure for the `mutate_mdata_entries` operation
    //    (relating to update of the access container).
    // 9. Try to authenticate the app again, it should succeed now.
    //
    // 10. Check that the app's container has been created.
    // 11. Check that the app's container has required permissions.
    // 12. Check that the app's container is listed in the access container entry for
    //     the app.
    #[test]
    fn app_authentication_recovery() {
        let locator = unwrap!(generate_random_string(10));
        let password = unwrap!(generate_random_string(10));
        let client_id = gen_client_id();

        unwrap!(test_create_balance(
            &client_id,
            unwrap!(Coins::from_str("10"))
        ));

        let cm_hook = move |mut cm: ConnectionManager| -> ConnectionManager {
            cm.set_request_hook(move |req| {
                match *req {
                    // Simulate a network failure after
                    // the `mutate_mdata_entries` operation (relating to
                    // the addition of the app to the user's config dir)
                    Request::Client(ClientRequest::InsAuthKey { .. }) => {
                        Some(Response::Mutation(Err(SndError::InsufficientBalance)))
                    }
                    // Pass-through
                    _ => None,
                }
            });
            cm
        };
        let auth = unwrap!(Authenticator::create_acc_with_hook(
            locator.clone(),
            password.clone(),
            client_id,
            || (),
            cm_hook,
        ));

        // Create a test app and try to authenticate it (with `app_container` set to true).
        let auth_req = AuthReq {
            app: test_utils::rand_app(),
            app_container: true,
            app_permissions: Default::default(),
            containers: utils::create_containers_req(),
        };
        let app_id = auth_req.app.id.clone();

        // App authentication request should fail and leave the app in the
        // `Revoked` state (as it is listed in the config root, but not in the access
        // container)
        match test_utils::register_app(&auth, &auth_req) {
            Err(AuthError::CoreError(CoreError::DataError(SndError::InsufficientBalance))) => (),
            x => panic!("Unexpected {:?}", x),
        }

        // Simulate a network failure for the `update_container_perms` step -
        // it should fail at the second container (`_videos`)
        let cm_hook = move |mut cm: ConnectionManager| -> ConnectionManager {
            let mut reqs_counter = 0;

            cm.set_request_hook(move |req| {
                match *req {
                    Request::MData(MDataRequest::SetUserPermissions { .. }) => {
                        reqs_counter += 1;

                        if reqs_counter == 2 {
                            Some(Response::Mutation(Err(SndError::InsufficientBalance)))
                        } else {
                            None
                        }
                    }
                    // Pass-through
                    _ => None,
                }
            });
            cm
        };
        let auth = unwrap!(Authenticator::login_with_hook(
            locator.clone(),
            password.clone(),
            || (),
            cm_hook,
        ));
        match test_utils::register_app(&auth, &auth_req) {
            Err(AuthError::CoreError(CoreError::DataError(SndError::InsufficientBalance))) => (),
            x => panic!("Unexpected {:?}", x),
        }

        // Simulate a network failure for the `app_container` setup step -
        // it should fail at the third request for `SetMDataPermissions` (after
        // setting permissions for 2 requested containers, `_video` and `_documents`)
        let cm_hook = move |mut cm: ConnectionManager| -> ConnectionManager {
            cm.set_request_hook(move |req| {
                match *req {
                    Request::MData(MDataRequest::Put { .. }) => {
                        Some(Response::Mutation(Err(SndError::InsufficientBalance)))
                    }

                    // Pass-through
                    _ => None,
                }
            });
            cm
        };
        let auth = unwrap!(Authenticator::login_with_hook(
            locator.clone(),
            password.clone(),
            || (),
            cm_hook,
        ));
        match test_utils::register_app(&auth, &auth_req) {
            Err(AuthError::NfsError(NfsError::CoreError(CoreError::DataError(
                SndError::InsufficientBalance,
            )))) => (),
            x => panic!("Unexpected {:?}", x),
        }

        // Simulate a network failure for the `MutateMDataEntries` request, which
        // is supposed to setup the access container entry for the app
        let cm_hook = move |mut cm: ConnectionManager| -> ConnectionManager {
            cm.set_request_hook(move |req| {
                match *req {
                    Request::MData(MDataRequest::MutateEntries { .. }) => {
                        Some(Response::Mutation(Err(SndError::InsufficientBalance)))
                    }

                    // Pass-through
                    _ => None,
                }
            });
            cm
        };
        let auth = unwrap!(Authenticator::login_with_hook(
            locator.clone(),
            password.clone(),
            || (),
            cm_hook,
        ));
        match test_utils::register_app(&auth, &auth_req) {
            Err(AuthError::CoreError(CoreError::DataError(SndError::InsufficientBalance))) => (),
            x => panic!("Unexpected {:?}", x),
        }

        // Now try to authenticate the app without network failure simulation -
        // it should succeed.
        let auth = unwrap!(Authenticator::login(locator, password, || (),));
        let auth_granted = match test_utils::register_app(&auth, &auth_req) {
            Ok(auth_granted) => auth_granted,
            x => panic!("Unexpected {:?}", x),
        };

        // Check that the app's container has been created and that the access container
        // contains info about all of the requested containers.
        let mut ac_entries =
            test_utils::access_container(&auth, app_id.clone(), auth_granted.clone());
        let (_videos_md, _) = unwrap!(ac_entries.remove("_videos"));
        let (_documents_md, _) = unwrap!(ac_entries.remove("_documents"));
        let (app_container, _) = unwrap!(ac_entries.remove(&app_container_name(&app_id)));

        let app_pk = auth_granted.app_keys.public_key();

        unwrap!(run(&auth, move |client| {
            let c2 = client.clone();

            client
                .get_mdata_version(*app_container.address())
                .then(move |res| {
                    let version = unwrap!(res);
                    assert_eq!(version, 0);

                    // Check that the app's container has required permissions.
                    c2.list_mdata_permissions(*app_container.address())
                })
                .then(move |res| {
                    let perms = unwrap!(res);
                    assert!(perms.contains_key(&app_pk));
                    assert_eq!(perms.len(), 1);

                    Ok(())
                })
        }));
    }
}

// Test creation and content of std dirs after account creation.
#[test]
fn test_access_container() {
    let authenticator = test_utils::create_account_and_login();
    let std_dir_names: Vec<_> = DEFAULT_PRIVATE_DIRS
        .iter()
        .chain(DEFAULT_PUBLIC_DIRS.iter())
        .collect();

    // Fetch the entries of the access container.
    let entries = unwrap!(run(&authenticator, |client| {
        access_container_tools::fetch_authenticator_entry(client).map(|(_version, entries)| entries)
    }));

    // Verify that all the std dirs are there.
    for name in &std_dir_names {
        assert!(entries.contains_key(**name));
    }

    // Fetch all the dirs under user root dir and verify they are empty.
    let dirs = unwrap!(run(&authenticator, move |client| {
        let fs: Vec<_> = entries
            .into_iter()
            .map(|(_, dir)| {
                let f1 = client.list_seq_mdata_entries(dir.name(), dir.type_tag());
                let f2 = client.list_mdata_permissions(*dir.address());

                f1.join(f2).map_err(AuthError::from)
            })
            .collect();

        future::join_all(fs)
    }));

    assert_eq!(dirs.len(), std_dir_names.len());

    for (entries, permissions) in dirs {
        assert!(entries.is_empty());
        assert!(permissions.is_empty());
    }
}

// Test creation and content of config dir after account creation.
#[test]
fn config_root_dir() {
    let authenticator = test_utils::create_account_and_login();

    // Fetch the entries of the config root dir.
    let (dir, entries) = unwrap!(run(&authenticator, |client| {
        let dir = client.config_root_dir();
        client
            .list_seq_mdata_entries(dir.name(), dir.type_tag())
            .map(move |entries| (dir, entries))
            .map_err(AuthError::from)
    }));

    let entries = unwrap!(mdata_info::decrypt_entries(&dir, &entries));

    // Verify it contains the required entries.
    let config = unwrap!(entries.get(KEY_APPS));
    assert!(config.data.is_empty());
}
