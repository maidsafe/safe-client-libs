// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net
// Commercial License, version 1.0 or later, or (2) The General Public License
// (GPL), version 3, depending on which licence you accepted on initial access
// to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project
// generally, you agree to be bound by the terms of the MaidSafe Contributor
// Agreement, version 1.0.
// This, along with the Licenses can be found in the root directory of this
// project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network
// Software distributed under the GPL Licence is distributed on an "AS IS"
// BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
//
// Please review the Licences for the specific language governing permissions
// and limitations relating to use of the SAFE Network Software.

use ffi_utils::{FfiString, OpaqueCtx, catch_unwind_cb, ffi_string_free};
use futures::Future;
use maidsafe_utilities::serialisation::deserialise;
use safe_core::FutureExt;
use safe_core::ipc::req::ffi::{ContainerPermissions, ContainerPermissionsArray, PermissionArray,
                               container_permissions_array_free};
use safe_core::utils::symmetric_decrypt;
use std::{mem, ptr};
use std::os::raw::c_void;
use super::{AccessContainerEntry, AuthError, Authenticator};
use super::ipc::{access_container, access_container_key, get_config};

/// Application registered in the authenticator
#[repr(C)]
pub struct RegisteredApp {
    /// Unique application identifier
    pub app_id: FfiString,
    /// List of containers that this application has access to
    pub containers: ContainerPermissionsArray,
}

/// Get a list of apps registered in authenticator
#[no_mangle]
pub unsafe extern "C" fn authenticator_registered_apps(auth: *mut Authenticator,
                                                       user_data: *mut c_void,
                                                       o_cb: extern "C" fn(*mut c_void,
                                                                           i32,
                                                                           *mut RegisteredApp,
                                                                           usize,
                                                                           usize))
                                                       -> i32 {
    let user_data = OpaqueCtx(user_data);

    catch_unwind_cb(user_data.0, o_cb, || -> Result<_, AuthError> {
        (*auth).send(move |client| {
                let c2 = client.clone();
                let c3 = client.clone();

                get_config(client.clone())
                    .and_then(move |(_, auth_cfg)| {
                        access_container(c2)
                            .map(move |access_container| (access_container, auth_cfg))
                    })
                    .and_then(move |(access_container, auth_cfg)| {
                        c3.list_mdata_entries(access_container.name, access_container.type_tag)
                            .map_err(From::from)
                            .map(move |entries| (access_container, entries, auth_cfg))
                    })
                    .and_then(move |(access_container, entries, auth_cfg)| {
                        let mut apps = Vec::new();

                        for app in auth_cfg.values() {
                            let key =
                                access_container_key(&access_container, &app.info.id, &app.keys)?;

                            if let Some(entry) = entries.get(&key) {
                                let plaintext = symmetric_decrypt(&entry.content,
                                                                  &app.keys.enc_key)?;
                                let app_access = deserialise::<AccessContainerEntry>(&plaintext)?;

                                let mut containers = Vec::new();

                                for (key, (_, perms)) in app_access {
                                    let perms = perms.iter().cloned().collect::<Vec<_>>();

                                    containers.push(ContainerPermissions {
                                        cont_name: FfiString::from_string(key),
                                        access: PermissionArray::from_vec(perms),
                                    });
                                }

                                let reg_app = RegisteredApp {
                                    app_id: FfiString::from_string(app.info.id.clone()),
                                    containers: ContainerPermissionsArray::from_vec(containers),
                                };

                                apps.push(reg_app);
                            }
                        }

                        let p = apps.as_mut_ptr();
                        let len = apps.len();
                        let cap = apps.capacity();
                        mem::forget(apps);

                        o_cb(user_data.0, 0, p, len, cap);
                        Ok(())
                    })
                    .map_err(move |e| {
                        o_cb(user_data.0, ffi_error_code!(e), ptr::null_mut(), 0, 0)
                    })
                    .into_box()
                    .into()
            })?;

        Ok(())
    });

    0
}

/// Free memory allocated for a `RegisteredApp` structure
#[no_mangle]
pub unsafe extern "C" fn registered_app_free(app: *mut RegisteredApp) {
    let app = Box::from_raw(app);
    ffi_string_free(app.app_id);
    container_permissions_array_free(app.containers);
}

/// Free memory allocated to a vector of registered applications
#[no_mangle]
pub unsafe extern "C" fn authenticator_registered_apps_free(apps: *mut RegisteredApp,
                                                            len: usize,
                                                            cap: usize) {
    let _ = Vec::from_raw_parts(apps, len, cap);
}
