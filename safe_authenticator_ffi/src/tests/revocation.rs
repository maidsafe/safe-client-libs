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
    use crate::tests::utils::create_containers_req;
    use ffi_utils::test_utils::call_0;
    use safe_authenticator::{
        app_auth::{app_state, AppState},
        config,
        test_utils::{create_authenticator, rand_app, register_app, simulate_revocation_failure},
        AuthError, Authenticator,
    };
    use safe_core::ipc::AuthReq;
    use unwrap::unwrap;

    // Test flushing the app revocation queue.
    //
    // 1. Create two apps
    // 2. Revoke both of them, but simulate network failure so both revocations would
    //    fail.
    // 3. Log in again and flush the revocation queue with no simulated failures.
    // 4. Verify both apps are successfully revoked.
    #[tokio::test]
    async fn flushing_app_revocation_queue() -> Result<(), AuthError> {
        // Create account.
        let (auth, locator, password) = create_authenticator().await;

        // Authenticate the first app.
        let auth_req = AuthReq {
            app: rand_app(),
            app_container: false,
            app_permissions: Default::default(),
            containers: create_containers_req(),
        };

        let _ = register_app(&auth, &auth_req).await?;
        let app_id_0 = auth_req.app.id;

        // Authenticate the second app.
        let auth_req = AuthReq {
            app: rand_app(),
            app_container: false,
            app_permissions: Default::default(),
            containers: create_containers_req(),
        };

        let _ = register_app(&auth, &auth_req).await?;
        let app_id_1 = auth_req.app.id;

        // Simulate failed revocations of both apps.
        simulate_revocation_failure(&locator, &password, &[&app_id_0, &app_id_1]).await;

        let client = &auth.client;
        // Verify the apps are not revoked yet.
        {
            let app_id_0 = app_id_0.clone();
            let app_id_1 = app_id_1.clone();

            let (_, apps) = config::list_apps(&client).await?;
            let state_0 = app_state(&client, &apps, &app_id_0).await?;
            let state_1 = app_state(&client, &apps, &app_id_1).await?;

            assert_eq!(state_0, AppState::Authenticated);
            assert_eq!(state_1, AppState::Authenticated);
        }

        // Login again without simulated failures.
        let auth = Authenticator::login(locator, password, || ()).await?;

        // Flush the revocation queue and verify both apps get revoked.
        unsafe {
            unwrap!(call_0(|ud, cb| auth_flush_app_revocation_queue(
                &auth, ud, cb
            ),))
        }

        let c2 = client.clone();

        let (_, apps) = config::list_apps(&c2).await?;
        let state_0 = app_state(&c2, &apps, &app_id_0).await?;
        let state_1 = app_state(&c2, &apps, &app_id_1).await?;

        assert_eq!(state_0, AppState::Revoked);
        assert_eq!(state_1, AppState::Revoked);

        Ok(())
    }
}
