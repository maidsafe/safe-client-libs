// Copyright 2016 MaidSafe.net limited.
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

use {App, AppError};
use ffi_utils::{FFI_RESULT_OK, FfiResult, OpaqueCtx, SafePtr, catch_unwind_cb, from_c_str};
use futures::Future;
use object_cache::MDataInfoHandle;
use safe_core::FutureExt;
use safe_core::ffi::ipc::req::ContainerPermissions;
use safe_core::ipc::req::containers_into_vec;
use std::os::raw::{c_char, c_void};

/// Fetch access info from the network.
///
/// Callback parameters: user data, error code
#[no_mangle]
pub unsafe extern "C" fn access_container_refresh_access_info(
    app: *const App,
    user_data: *mut c_void,
    o_cb: extern "C" fn(user_data: *mut c_void, result: FfiResult),
) {
    catch_unwind_cb(user_data, o_cb, || {
        let user_data = OpaqueCtx(user_data);

        (*app).send(move |client, context| {
            context
                .refresh_access_info(client)
                .then(move |res| {
                    call_result_cb!(res, user_data, o_cb);
                    Ok(())
                })
                .into_box()
                .into()
        })
    })
}

/// Retrieve a list of container names that an app has access to.
///
/// Callback parameters: user data, error code, container permissions vector, vector size
#[no_mangle]
pub unsafe extern "C" fn access_container_fetch(
    app: *const App,
    user_data: *mut c_void,
    o_cb: extern "C" fn(user_data: *mut c_void,
                        result: FfiResult,
                        container_perms_ptr: *const ContainerPermissions,
                        container_perms_len: usize),
) {
    catch_unwind_cb(user_data, o_cb, || {
        let user_data = OpaqueCtx(user_data);

        (*app).send(move |client, context| {
            context
                .get_access_info(client)
                .and_then(move |containers| {
                    let ffi_containers = containers_into_vec(containers.into_iter().map(
                        |(key, (_, value))| (key, value),
                    ))?;
                    o_cb(
                        user_data.0,
                        FFI_RESULT_OK,
                        ffi_containers.as_safe_ptr(),
                        ffi_containers.len(),
                    );
                    Ok(())
                })
                .map_err(move |e| {
                    call_result_cb!(Err::<(), _>(e), user_data, o_cb);
                })
                .into_box()
                .into()
        })
    })
}

/// Retrieve `MDataInfo` for the given container name from the access container.
///
/// Callback parameters: user data, error code, mdata info handle
#[no_mangle]
pub unsafe extern "C" fn access_container_get_container_mdata_info(
    app: *const App,
    name: *const c_char,
    user_data: *mut c_void,
    o_cb: extern "C" fn(user_data: *mut c_void,
                        result: FfiResult,
                        mdata_info_h: MDataInfoHandle),
) {
    catch_unwind_cb(user_data, o_cb, || {
        let user_data = OpaqueCtx(user_data);
        let name = from_c_str(name)?;

        (*app).send(move |client, context| {
            let context = context.clone();

            context
                .get_access_info(client)
                .map(move |containers| if let Some(&(ref mdata_info, _)) =
                    containers.get(&name)
                {
                    let handle = context.object_cache().insert_mdata_info(mdata_info.clone());
                    o_cb(user_data.0, FFI_RESULT_OK, handle);
                } else {
                    call_result_cb!(Err::<(), _>(AppError::NoSuchContainer), user_data, o_cb);
                })
                .map_err(move |err| {
                    call_result_cb!(Err::<(), _>(err), user_data, o_cb);
                })
                .into_box()
                .into()
        })
    })
}

#[cfg(test)]
mod tests {
    use errors::AppError;
    use ffi::access_container::*;
    use ffi_utils::{ReprC, from_c_str};
    use ffi_utils::test_utils::{call_0, call_1, call_vec};
    use safe_core::DIR_TAG;
    use safe_core::ipc::req::{Permission, container_perms_from_repr_c};
    use std::collections::{BTreeSet, HashMap};
    use std::ffi::CString;
    use std::rc::Rc;
    use test_utils::{create_app_with_access, run, run_now};

    // Test refreshing access info by fetching it from the network.
    #[test]
    fn refresh_access_info() {
        // Shared container
        let mut container_permissions = HashMap::new();
        let _ = container_permissions.insert(
            "_videos".to_string(),
            btree_set![Permission::Read, Permission::Insert],
        );

        let app = create_app_with_access(container_permissions.clone());

        run(&app, move |_client, context| {
            let reg = Rc::clone(unwrap!(context.as_registered()));
            assert!(reg.access_info.borrow().is_empty());
            Ok(())
        });

        unsafe {
            unwrap!(call_0(
                |ud, cb| access_container_refresh_access_info(&app, ud, cb),
            ))
        }

        run(&app, move |_client, context| {
            let reg = Rc::clone(unwrap!(context.as_registered()));
            assert!(!reg.access_info.borrow().is_empty());

            let access_info = reg.access_info.borrow();
            assert_eq!(
                unwrap!(access_info.get("_videos")).1,
                *unwrap!(container_permissions.get("_videos"))
            );

            Ok(())
        });
    }

    // Test getting info about access containers and their mutable data.
    #[test]
    fn get_access_info() {
        let mut container_permissions = HashMap::new();
        let _ = container_permissions.insert("_videos".to_string(), btree_set![Permission::Read]);
        let app = create_app_with_access(container_permissions);

        // Get access container info
        let perms: Vec<PermSet> =
            unsafe { unwrap!(call_vec(|ud, cb| access_container_fetch(&app, ud, cb))) };

        let perms: HashMap<String, BTreeSet<Permission>> =
            perms.into_iter().map(|val| (val.0, val.1)).collect();

        assert_eq!(perms["_videos"], btree_set![Permission::Read]);
        assert_eq!(perms.len(), 2);

        // Get MD info
        let md_info_h = {
            let videos_str = unwrap!(CString::new("_videos"));
            unsafe {
                unwrap!(call_1(|ud, cb| {
                    access_container_get_container_mdata_info(&app, videos_str.as_ptr(), ud, cb)
                }))
            }
        };

        run_now(&app, move |_, context| {
            let info = unwrap!(context.object_cache().get_mdata_info(md_info_h));
            assert_eq!(info.type_tag, DIR_TAG);
        })
    }

    struct PermSet(String, BTreeSet<Permission>);

    impl ReprC for PermSet {
        type C = *const ContainerPermissions;
        type Error = AppError;

        unsafe fn clone_from_repr_c(c_repr: Self::C) -> Result<Self, Self::Error> {
            Ok(PermSet(
                from_c_str((*c_repr).cont_name)?,
                container_perms_from_repr_c((*c_repr).access)?,
            ))
        }
    }

}
