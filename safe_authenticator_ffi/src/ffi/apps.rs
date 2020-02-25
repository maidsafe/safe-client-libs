// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::ffi::errors::{Error, Result};
use ffi_utils::call_result_cb;
use ffi_utils::{
    catch_unwind_cb, vec_from_raw_parts, vec_into_raw_parts, FfiResult, OpaqueCtx, ReprC, SafePtr,
    FFI_RESULT_OK,
};
use futures::Future;
use safe_authenticator::apps::{
    apps_accessing_mutable_data, list_registered, list_revoked, remove_revoked_app,
    RegisteredApp as NativeRegisteredApp,
};
use safe_authenticator::{AuthResult, Authenticator};
use safe_core::core_structs::AppAccess as NativeAppAccess;
use safe_core::ffi::arrays::XorNameArray;
use safe_core::ffi::ipc::req::{AppExchangeInfo, ContainerPermissions};
use safe_core::ffi::ipc::resp::AppAccess;
use safe_core::ipc::req::containers_into_vec;
use safe_core::ipc::req::AppExchangeInfo as NativeAppExchangeInfo;
use safe_core::ipc::IpcError;
use safe_core::FutureExt;
use safe_nd::XorName;
use std::convert::TryFrom;
use std::os::raw::{c_char, c_void};

impl TryFrom<NativeRegisteredApp> for RegisteredApp {
    type Error = IpcError;

    fn try_from(app: NativeRegisteredApp) -> std::result::Result<Self, IpcError> {
        let NativeRegisteredApp {
            app_info,
            containers,
            app_perms,
        } = app;

        let container_permissions_vec = containers_into_vec(containers.into_iter())?;

        let (containers_ptr, containers_len) = vec_into_raw_parts(container_permissions_vec);

        let ffi_app_perms = AppPermissions {
            transfer_coins: app_perms.transfer_coins,
            get_balance: app_perms.get_balance,
            perform_mutations: app_perms.perform_mutations,
        };

        Ok(Self {
            app_info: app_info.into_repr_c()?,
            containers: containers_ptr,
            containers_len,
            app_permissions: ffi_app_perms,
        })
    }
}
/// Application registered in the authenticator.
#[repr(C)]
pub struct RegisteredApp {
    /// Unique application identifier.
    pub app_info: AppExchangeInfo,
    /// List of containers that this application has access to.
    pub containers: *const ContainerPermissions,
    /// Length of the containers array.
    pub containers_len: usize,
    /// Permissions allowed for the application
    pub app_permissions: AppPermissions,
}

impl Drop for RegisteredApp {
    fn drop(&mut self) {
        unsafe {
            let _ = vec_from_raw_parts(
                self.containers as *mut ContainerPermissions,
                self.containers_len,
            );
        }
    }
}

/// Permission for Apps
#[repr(C)]
#[derive(Clone, Copy)]
pub struct AppPermissions {
    /// Whether this app has permissions to transfer coins.
    pub transfer_coins: bool,
    /// Whether this app has permissions to perform mutations.
    pub perform_mutations: bool,
    /// Whether this app has permissions to read the coin balance.
    pub get_balance: bool,
}

/// Remove a revoked app from the authenticator config.
#[no_mangle]
pub unsafe extern "C" fn auth_rm_revoked_app(
    auth: *const Authenticator,
    app_id: *const c_char,
    user_data: *mut c_void,
    o_cb: extern "C" fn(user_data: *mut c_void, result: *const FfiResult),
) {
    let user_data = OpaqueCtx(user_data);

    catch_unwind_cb(user_data.0, o_cb, || -> AuthResult<_> {
        let app_id = String::clone_from_repr_c(app_id)?;

        (*auth).send(move |client| {
            remove_revoked_app(client, app_id)
                .then(move |res| {
                    call_result_cb!(res.map_err(Error::from), user_data, o_cb);
                    Ok(())
                })
                .into_box()
                .into()
        })
    });
}

/// Get a list of apps revoked from authenticator.
#[no_mangle]
pub unsafe extern "C" fn auth_revoked_apps(
    auth: *const Authenticator,
    user_data: *mut c_void,
    o_cb: extern "C" fn(
        user_data: *mut c_void,
        result: *const FfiResult,
        app_exchange_info: *const AppExchangeInfo,
        app_exchange_info_len: usize,
    ),
) {
    let user_data = OpaqueCtx(user_data);
    catch_unwind_cb(user_data.0, o_cb, || -> Result<_> {
        (*auth).send(move |client| {
            list_revoked(client)
                .and_then(move |apps| {
                    let app_list: Vec<_> = apps
                        .into_iter()
                        .map(NativeAppExchangeInfo::into_repr_c)
                        .collect::<std::result::Result<_, _>>()?;
                    o_cb(
                        user_data.0,
                        FFI_RESULT_OK,
                        app_list.as_safe_ptr(),
                        app_list.len(),
                    );

                    Ok(())
                })
                .map_err(move |e| {
                    call_result_cb!(Err::<(), _>(Error::from(e)), user_data, o_cb);
                })
                .into_box()
                .into()
        })?;

        Ok(())
    });
}

/// Get a list of apps registered in authenticator.
#[no_mangle]
pub unsafe extern "C" fn auth_registered_apps(
    auth: *const Authenticator,
    user_data: *mut c_void,
    o_cb: extern "C" fn(
        user_data: *mut c_void,
        result: *const FfiResult,
        registered_app: *const RegisteredApp,
        registered_app_len: usize,
    ),
) {
    let user_data = OpaqueCtx(user_data);

    catch_unwind_cb(user_data.0, o_cb, || -> Result<_> {
        (*auth).send(move |client| {
            list_registered(client)
                .and_then(move |registered_apps| {
                    let apps: Vec<_> = registered_apps
                        .into_iter()
                        .map(RegisteredApp::try_from)
                        .collect::<std::result::Result<_, _>>()?;
                    o_cb(user_data.0, FFI_RESULT_OK, apps.as_safe_ptr(), apps.len());

                    Ok(())
                })
                .map_err(move |e| {
                    call_result_cb!(Err::<(), _>(Error::from(e)), user_data, o_cb);
                })
                .into_box()
                .into()
        })?;

        Ok(())
    })
}

/// Return a list of apps having access to an arbitrary MD object.
/// `md_name` and `md_type_tag` together correspond to a single MD.
#[no_mangle]
pub unsafe extern "C" fn auth_apps_accessing_mutable_data(
    auth: *const Authenticator,
    md_name: *const XorNameArray,
    md_type_tag: u64,
    user_data: *mut c_void,
    o_cb: extern "C" fn(
        user_data: *mut c_void,
        result: *const FfiResult,
        app_access: *const AppAccess,
        app_access_len: usize,
    ),
) {
    let user_data = OpaqueCtx(user_data);
    let name = XorName(*md_name);

    catch_unwind_cb(user_data.0, o_cb, || -> Result<_> {
        (*auth).send(move |client| {
            apps_accessing_mutable_data(client, name, md_type_tag)
                .and_then(move |apps_with_access| {
                    let app_access_vec: Vec<_> = apps_with_access
                        .into_iter()
                        .map(NativeAppAccess::into_repr_c)
                        .collect::<std::result::Result<_, _>>()?;
                    o_cb(
                        user_data.0,
                        FFI_RESULT_OK,
                        app_access_vec.as_safe_ptr(),
                        app_access_vec.len(),
                    );

                    Ok(())
                })
                .map_err(move |e| {
                    call_result_cb!(Err::<(), _>(Error::from(e)), user_data, o_cb);
                })
                .into_box()
                .into()
        })?;

        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use crate::ffi::errors::{ERR_UNEXPECTED, ERR_UNKNOWN_APP};
    use ffi_utils::test_utils::call_0;
    use safe_authenticator::app_auth::{app_state, AppState};
    use safe_authenticator::app_container::fetch;
    use safe_authenticator::errors::AuthError;
    use safe_authenticator::revocation::revoke_app;
    use safe_authenticator::test_utils::{
        create_account_and_login, create_file, fetch_file, get_app_or_err, rand_app, register_app,
    };
    use safe_authenticator::{config, run};
    use safe_core::ipc::{AuthReq, IpcError};
    use std::collections::HashMap;
    use unwrap::unwrap;

    use super::*;

    // Negative test - non-existing app:
    // 1. Try to call `auth_rm_revoked_app` with a random, non-existing app_id
    // 2. Verify that `IpcError::UnknownApp` is returned
    #[test]
    fn rm_revoked_nonexisting() {
        let auth = create_account_and_login();
        let app_info = rand_app();
        let app_info_ffi = unwrap!(app_info.into_repr_c());

        let result =
            unsafe { call_0(|ud, cb| auth_rm_revoked_app(&auth, app_info_ffi.id, ud, cb)) };

        match result {
            Err(ERR_UNKNOWN_APP) => (),
            Err(x) => panic!("Unexpected {:?}", x),
            Ok(()) => panic!("Unexpected successful removal of non-existing app"),
        };
    }

    // Negative test - authorised app:
    // 1. Authorise a new app A
    // 2. Try to call `auth_rm_revoked_app` with an app id corresponding to the app A
    // 3. Verify that an error is returned (app is not revoked)
    // 4. Verify that `app_state` for the app A is still `AppState::Authenticated`
    #[test]
    fn rm_revoked_authorised() {
        let auth = create_account_and_login();
        let app_info = rand_app();
        let app_id = app_info.id.clone();

        let _ = unwrap!(register_app(
            &auth,
            &AuthReq {
                app: app_info.clone(),
                app_container: false,
                app_permissions: Default::default(),
                containers: HashMap::new(),
            },
        ));

        let app_info_ffi = unwrap!(app_info.into_repr_c());
        let result =
            unsafe { call_0(|ud, cb| auth_rm_revoked_app(&auth, app_info_ffi.id, ud, cb)) };

        match result {
            Err(ERR_UNEXPECTED) => (),
            Err(x) => panic!("Unexpected {:?}", x),
            Ok(()) => panic!("Unexpected successful removal of non-existing app"),
        };

        // Verify that the app is still authenticated
        unwrap!(run(&auth, |client| {
            let c2 = client.clone();

            config::list_apps(client)
                .and_then(move |(_, apps)| app_state(&c2, &apps, &app_id))
                .and_then(move |res| match res {
                    AppState::Authenticated => Ok(()),
                    _ => panic!("App state changed after failed revocation"),
                })
        }));
    }

    // Test complete app removal
    // 1. Authorise a new app A with `app_container` set to `true`.
    // 2. Put a file with predefined content into app A's own container.
    // 3. Revoke app A
    // 4. Verify that app A is still listed in the authenticator config.
    // 5. Verify that the app A container is still accessible.
    // 6. Call `auth_rm_revoked_app` with an app id corresponding to app A.
    // The operation should succeed.
    // 7. Verify that the app A is not listed anywhere in the authenticator config.
    // 8. Verify that the app A's container entry corresponding to the file created
    // at the step 2 is emptied out/removed.
    // 9. Try to authorise app A again as app A2 (app_container set to `true`)
    // 10. Verify that the app A2 is listed in the authenticator config.
    // 11. Verify that the app A2 keys are different from the set of the app A keys
    // (i.e. the app keys should have been regenerated rather than reused).
    // 12. Verify that the app A2 container does not contain the file created at step 2.
    #[test]
    fn rm_revoked_complete() {
        let auth = create_account_and_login();
        let app_info = rand_app();
        let app_id = app_info.id.clone();
        let app_id2 = app_id.clone();
        let app_id3 = app_id.clone();
        let app_id4 = app_id.clone();
        let app_id5 = app_id.clone();

        // Authorise app A with `app_container` set to `true`.
        let auth_granted1 = unwrap!(register_app(
            &auth,
            &AuthReq {
                app: app_info.clone(),
                app_container: true,
                app_permissions: Default::default(),
                containers: HashMap::new(),
            },
        ));

        // Put a file with predefined content into app A's own container.
        let mdata_info = unwrap!({ unwrap!(run(&auth, move |client| fetch(client, &app_id3))) });
        unwrap!(create_file(
            &auth,
            mdata_info.clone(),
            "test",
            vec![1; 10],
            true
        ));

        // Revoke app A
        {
            unwrap!(run(&auth, move |client| revoke_app(client, &app_id2)))
        }

        // Verify that app A is still listed in the authenticator config.
        assert!(get_app_or_err(&auth, &app_id).is_ok());

        // Verify that the app A container is still accessible.
        {
            unwrap!(run(&auth, move |client| {
                fetch(client, &app_id4).and_then(move |res| match res {
                    Some(_) => Ok(()),
                    None => panic!("App container not accessible"),
                })
            }))
        }

        // Call `auth_rm_revoked_app` with an app id corresponding to app A.
        let app_info_ffi = unwrap!(app_info.clone().into_repr_c());
        unsafe {
            unwrap!(call_0(|ud, cb| auth_rm_revoked_app(
                &auth,
                app_info_ffi.id,
                ud,
                cb
            ),))
        };
        // Verify that the app A is not listed anywhere in the authenticator config.
        let res = get_app_or_err(&auth, &app_id);
        match res {
            Err(AuthError::IpcError(IpcError::UnknownApp)) => (),
            Err(x) => panic!("Unexpected {:?}", x),
            Ok(_) => panic!("App still listed in the authenticator config"),
        };

        // Verify that the app A's container entry corresponding to the file created
        // at step 2 is emptied out/removed.
        let res = fetch_file(&auth, mdata_info, "test");
        match res {
            Err(_) => (),
            Ok(_) => panic!("File not removed"),
        }

        // Try to authorise app A again as app A2 (app_container set to `true`)
        let auth_granted2 = unwrap!(register_app(
            &auth,
            &AuthReq {
                app: app_info,
                app_container: true,
                app_permissions: Default::default(),
                containers: HashMap::new(),
            },
        ));

        // Verify that the app A2 is listed in the authenticator config.
        assert!(get_app_or_err(&auth, &app_id).is_ok());

        // Verify that the app A2 keys are different from the set of the app A keys
        // (i.e. the app keys should have been regenerated rather than reused).
        assert_ne!(auth_granted1.app_keys, auth_granted2.app_keys);

        // Verify that the app A2 container does not contain the file created at step 2.
        let mdata_info = unwrap!({ unwrap!(run(&auth, move |client| fetch(client, &app_id5))) });
        let res = fetch_file(&auth, mdata_info, "test");
        match res {
            Err(_) => (),
            Ok(_) => panic!("File not removed"),
        }
    }
}
