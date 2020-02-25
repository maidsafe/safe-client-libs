// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

#[cfg(feature = "mock-network")]
mod mock_routing {
    use crate::auth_flush_app_revocation_queue;
    use ffi_utils::test_utils::call_0;
    use safe_authenticator::test_utils::{create_authenticator, rand_app};
    use safe_authenticator::{
        app_auth::{app_state, AppState},
        client::AuthClient,
        config,
        test_utils::register_app,
        {run, Authenticator},
    };
    use unwrap::unwrap;

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
        let app_id_0 = auth_req.app.id;

        // Authenticate the second app.
        let auth_req = AuthReq {
            app: rand_app(),
            app_container: false,
            app_permissions: Default::default(),
            containers: create_containers_req(),
        };

        let _ = unwrap!(register_app(&auth, &auth_req));
        let app_id_1 = auth_req.app.id;

        // Simulate failed revocations of both apps.
        simulate_revocation_failure(&locator, &password, &[&app_id_0, &app_id_1]);

        // Verify the apps are not revoked yet.
        {
            let app_id_0 = app_id_0.clone();
            let app_id_1 = app_id_1.clone();

            unwrap!(run(&auth, |client| {
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
            }))
        }

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
}
