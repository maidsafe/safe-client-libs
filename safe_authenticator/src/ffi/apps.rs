// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use std::os::raw::{c_char, c_void};

use ffi_utils::{catch_unwind_cb, from_c_str, FfiResult, OpaqueCtx, SafePtr, FFI_RESULT_OK};
use futures::Future;
use routing::XorName;

use apps::{
    apps_accessing_mutable_data, list_registered, list_revoked, remove_revoked_app,
    RegisteredApp as NativeRegisteredApp,
};
use safe_core::ffi::arrays::XorNameArray;
use safe_core::ffi::ipc::req::{AppExchangeInfo, ContainerPermissions};
use safe_core::ffi::ipc::resp::AppAccess;
use safe_core::ipc::req::AppExchangeInfo as NativeAppExchangeInfo;
use safe_core::ipc::resp::AppAccess as NativeAppAccess;
use safe_core::FutureExt;
use AuthError;
use Authenticator;

/// Application registered in the authenticator
#[repr(C)]
pub struct RegisteredApp {
    /// Unique application identifier
    pub app_info: AppExchangeInfo,
    /// List of containers that this application has access to
    pub containers: *const ContainerPermissions,
    /// Length of the containers array
    pub containers_len: usize,
    /// Capacity of the containers array. Internal data required
    /// for the Rust allocator.
    pub containers_cap: usize,
}

impl Drop for RegisteredApp {
    fn drop(&mut self) {
        unsafe {
            let _ = Vec::from_raw_parts(
                self.containers as *mut ContainerPermissions,
                self.containers_len,
                self.containers_cap,
            );
        }
    }
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

    catch_unwind_cb(user_data.0, o_cb, || -> Result<_, AuthError> {
        let app_id = from_c_str(app_id)?;

        (*auth).send(move |client| {
            remove_revoked_app(client, app_id)
                .then(move |res| {
                    call_result_cb!(res, user_data, o_cb);
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

    catch_unwind_cb(user_data.0, o_cb, || -> Result<_, AuthError> {
        (*auth).send(move |client| {
            list_revoked(client)
                .and_then(move |apps| {
                    let app_list: Vec<_> = apps
                        .into_iter()
                        .map(NativeAppExchangeInfo::into_repr_c)
                        .collect::<Result<_, _>>()?;
                    o_cb(
                        user_data.0,
                        FFI_RESULT_OK,
                        app_list.as_safe_ptr(),
                        app_list.len(),
                    );

                    Ok(())
                })
                .map_err(move |e| {
                    call_result_cb!(Err::<(), _>(e), user_data, o_cb);
                })
                .into_box()
                .into()
        })?;

        Ok(())
    })
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

    catch_unwind_cb(user_data.0, o_cb, || -> Result<_, AuthError> {
        (*auth).send(move |client| {
            list_registered(client)
                .and_then(move |registered_apps| {
                    let apps: Vec<_> = registered_apps
                        .into_iter()
                        .map(NativeRegisteredApp::into_repr_c)
                        .collect::<Result<_, _>>()?;
                    o_cb(user_data.0, FFI_RESULT_OK, apps.as_safe_ptr(), apps.len());

                    Ok(())
                })
                .map_err(move |e| {
                    call_result_cb!(Err::<(), _>(e), user_data, o_cb);
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

    catch_unwind_cb(user_data.0, o_cb, || -> Result<_, AuthError> {
        (*auth).send(move |client| {
            apps_accessing_mutable_data(client, name, md_type_tag)
                .and_then(move |apps_with_access| {
                    let app_access_vec: Vec<_> = apps_with_access
                        .into_iter()
                        .map(NativeAppAccess::into_repr_c)
                        .collect::<Result<_, _>>()?;
                    o_cb(
                        user_data.0,
                        FFI_RESULT_OK,
                        app_access_vec.as_safe_ptr(),
                        app_access_vec.len(),
                    );

                    Ok(())
                })
                .map_err(move |e| {
                    call_result_cb!(Err::<(), _>(e), user_data, o_cb);
                })
                .into_box()
                .into()
        })?;

        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use ffi_utils::test_utils::call_0;

    use app_auth::{app_state, AppState};
    use app_container::fetch;
    use config;
    use errors::{ERR_UNEXPECTED, ERR_UNKNOWN_APP};
    use revocation::revoke_app;
    use safe_core::ipc::{AuthReq, IpcError};
    use test_utils::{
        create_account_and_login, create_file, fetch_file, get_app_or_err, rand_app, register_app,
        run,
    };

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
        run(&auth, |client| {
            let c2 = client.clone();

            config::list_apps(client)
                .and_then(move |(_, apps)| app_state(&c2, &apps, &app_id))
                .and_then(move |res| match res {
                    AppState::Authenticated => Ok(()),
                    _ => panic!("App state changed after failed revocation"),
                })
        });
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
                containers: HashMap::new(),
            },
        ));

        // Put a file with predefined content into app A's own container.
        let mdata_info = unwrap!({ run(&auth, move |client| fetch(client, &app_id3)) });
        unwrap!(create_file(&auth, mdata_info.clone(), "test", vec![1; 10]));

        // Revoke app A
        {
            run(&auth, move |client| revoke_app(client, &app_id2))
        }

        // Verify that app A is still listed in the authenticator config.
        assert!(get_app_or_err(&auth, &app_id).is_ok());

        // Verify that the app A container is still accessible.
        {
            run(&auth, move |client| {
                fetch(client, &app_id4).and_then(move |res| match res {
                    Some(_) => Ok(()),
                    None => panic!("App container not accessible"),
                })
            })
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
                containers: HashMap::new(),
            },
        ));

        // Verify that the app A2 is listed in the authenticator config.
        assert!(get_app_or_err(&auth, &app_id).is_ok());

        // Verify that the app A2 keys are different from the set of the app A keys
        // (i.e. the app keys should have been regenerated rather than reused).
        assert_ne!(auth_granted1.app_keys, auth_granted2.app_keys);

        // Verify that the app A2 container does not contain the file created at step 2.
        let mdata_info = unwrap!({ run(&auth, move |client| fetch(client, &app_id5)) });
        let res = fetch_file(&auth, mdata_info, "test");
        match res {
            Err(_) => (),
            Ok(_) => panic!("File not removed"),
        }
    }
}
