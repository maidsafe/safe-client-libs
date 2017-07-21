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

use super::{AccessContainerEntry, AuthError, AuthFuture, Authenticator};
use super::access_container::{access_container, access_container_entry, put_access_container_entry};
use config::{self, Apps};
use ffi_utils::{FFI_RESULT_OK, FfiResult, OpaqueCtx, ReprC, StringError, base64_encode,
                catch_unwind_cb, from_c_str};
use futures::{Future, future};
use maidsafe_utilities::serialisation::{deserialise, serialise};
use revocation::revoke_app;
use routing::{Action, ClientError, EntryActions, PermissionSet, User};
use rust_sodium::crypto::sign;
use safe_core::{Client, CoreError, FutureExt, MDataInfo, nfs};
use safe_core::ipc::{self, IpcError, IpcMsg, decode_msg};
use safe_core::ipc::req::{AppExchangeInfo, AuthReq, ContainersReq, IpcReq};
use safe_core::ipc::req::ffi::{Permission, convert_permission_set};
use safe_core::ipc::req::ffi::AuthReq as FfiAuthReq;
use safe_core::ipc::req::ffi::ContainersReq as FfiContainersReq;
use safe_core::ipc::resp::{AccessContInfo, AppKeys, AuthGranted, IpcResp};
use std::collections::{BTreeSet, HashMap};
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_void};
use std::ptr;
use tiny_keccak::sha3_256;

/// App data stored in the authenticator configuration.
///
/// We need to store it even for revoked apps because we need to
/// preserve the app keys. An app can encrypt data and create mutable data
/// instances on its own, so we need to make sure that the app can
/// access the encrypted data in future, even if the app was revoked
/// at some point.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppInfo {
    /// Application info (id, name, vendor, etc.)
    pub info: AppExchangeInfo,
    /// Application keys
    pub keys: AppKeys,
}

/// Decodes a given encoded IPC message and returns either an `IpcMsg` struct or
/// an error code + description & an encoded `IpcMsg::Resp` in case of an error
#[cfg_attr(feature="cargo-clippy", allow(type_complexity))]
pub fn decode_ipc_msg(client: &Client<()>,
                      msg: IpcMsg)
                      -> Box<AuthFuture<Result<IpcMsg, (i32, CString, CString)>>> {
    match msg {
        IpcMsg::Req {
            req: IpcReq::Auth(auth_req),
            req_id,
        } => {
            // Ok status should be returned for all app states (including
            // Revoked and Authenticated).
            ok!(Ok(IpcMsg::Req {
                       req_id: req_id,
                       req: IpcReq::Auth(auth_req),
                   }))
        }
        IpcMsg::Req {
            req: IpcReq::Unregistered,
            req_id,
        } => {
            ok!(Ok(IpcMsg::Req {
                       req_id: req_id,
                       req: IpcReq::Unregistered,
                   }))
        }
        IpcMsg::Req {
            req: IpcReq::Containers(cont_req),
            req_id,
        } => {
            let app_id = cont_req.app.id.clone();
            let app_id2 = app_id.clone();

            let c2 = client.clone();

            config::list_apps(client)
                .and_then(move |(_config_version, config)| app_state(&c2, &config, app_id))
                .and_then(move |app_state| {
                    match app_state {
                        AppState::Authenticated => {
                            Ok(Ok(IpcMsg::Req {
                                      req_id: req_id,
                                      req: IpcReq::Containers(cont_req),
                                  }))
                        }
                        AppState::Revoked |
                        AppState::NotAuthenticated => {
                            // App is not authenticated
                            let (error_code, description) =
                                ffi_error!(AuthError::from(IpcError::UnknownApp));

                            let resp = IpcMsg::Resp {
                                resp: IpcResp::Auth(Err(IpcError::UnknownApp)),
                                req_id: req_id,
                            };
                            let resp = encode_response(&resp, &app_id2)?;

                            Ok(Err((error_code, description, resp)))
                        }
                    }
                })
                .into_box()
        }
        IpcMsg::Resp { .. } |
        IpcMsg::Revoked { .. } |
        IpcMsg::Err(..) => {
            return err!(AuthError::IpcError(IpcError::InvalidMsg.into()));
        }
    }
}

/// Decodes a given encoded IPC message without requiring an authorised account
#[no_mangle]
pub unsafe extern "C" fn auth_unregistered_decode_ipc_msg(msg: *const c_char,
                                                          user_data: *mut c_void,
                                                          o_unregistered: extern "C" fn(*mut c_void,
                                                                                        u32),
                                                          o_err: extern "C" fn(*mut c_void,
                                                                  FfiResult,
                                                                  *const c_char))
{
    let user_data = OpaqueCtx(user_data);

    catch_unwind_cb(user_data.0, o_err, || -> Result<_, AuthError> {
        let msg_raw = CStr::from_ptr(msg).to_str()?;
        let msg = decode_msg(msg_raw)?;

        match msg {
            IpcMsg::Req {
                req: IpcReq::Unregistered,
                req_id,
            } => {
                o_unregistered(user_data.0, req_id);
            }
            _ => {
                let (error_code, description) =
                    ffi_error!(AuthError::CoreError(CoreError::OperationForbidden));
                o_err(user_data.0,
                      FfiResult {
                          error_code,
                          description: description.as_ptr(),
                      },
                      ptr::null_mut());
            }
        }

        Ok(())
    })
}

/// Decodes a given encoded IPC message and calls a corresponding callback
#[no_mangle]
pub unsafe extern "C" fn auth_decode_ipc_msg(auth: *const Authenticator,
                                             msg: *const c_char,
                                             user_data: *mut c_void,
                                             o_auth: extern "C" fn(*mut c_void,
                                                                   u32,
                                                                   *const FfiAuthReq),
                                             o_containers: extern "C" fn(*mut c_void,
                                                                         u32,
                                                                         *const FfiContainersReq),
                                             o_unregistered: extern "C" fn(*mut c_void, u32),
                                             o_err: extern "C" fn(*mut c_void,
                                                                  FfiResult,
                                                                  *const c_char)) {
    let user_data = OpaqueCtx(user_data);

    catch_unwind_cb(user_data.0, o_err, || -> Result<_, AuthError> {
        let msg_raw = CStr::from_ptr(msg).to_str()?;
        let msg = decode_msg(msg_raw)?;

        (*auth)
            .send(move |client| {
                decode_ipc_msg(client, msg)
                    .and_then(move |msg| {
                        match msg {
                            Ok(IpcMsg::Req {
                                   req: IpcReq::Auth(auth_req),
                                   req_id,
                               }) => {
                                o_auth(user_data.0, req_id, &auth_req.into_repr_c()?);
                            }
                            Ok(IpcMsg::Req {
                                   req: IpcReq::Containers(cont_req),
                                   req_id,
                               }) => {
                                o_containers(user_data.0, req_id, &cont_req.into_repr_c()?);
                            }
                            Ok(IpcMsg::Req {
                                   req: IpcReq::Unregistered,
                                   req_id,
                               }) => {
                                o_unregistered(user_data.0, req_id);
                            }
                            Err((error_code, description, err)) => {
                                o_err(user_data.0,
                                      FfiResult {
                                          error_code,
                                          description: description.as_ptr(),
                                      },
                                      err.as_ptr());
                            }
                            Ok(IpcMsg::Resp { .. }) |
                            Ok(IpcMsg::Revoked { .. }) |
                            Ok(IpcMsg::Err(..)) => {
                                let (error_code, description) = ffi_error!(
                                        AuthError::Unexpected("Unexpected msg \
                                                               type"
                                          .to_owned()));
                                o_err(user_data.0,
                                      FfiResult {
                                          error_code,
                                          description: description.as_ptr(),
                                      },
                                      ptr::null_mut());
                            }
                        }
                        Ok(())
                    })
                    .map_err(move |err| {
                        let (error_code, description) = ffi_error!(err);
                        o_err(user_data.0,
                              FfiResult {
                                  error_code,
                                  description: description.as_ptr(),
                              },
                              ptr::null_mut());
                    })
                    .into_box()
                    .into()
            })?;
        Ok(())
    })
}

/// Revoke app access
#[no_mangle]
pub unsafe extern "C" fn authenticator_revoke_app(auth: *const Authenticator,
                                                  app_id: *const c_char,
                                                  user_data: *mut c_void,
                                                  o_cb: extern "C" fn(*mut c_void,
                                                                      FfiResult,
                                                                      *const c_char)) {
    let user_data = OpaqueCtx(user_data);

    catch_unwind_cb(user_data.0, o_cb, || -> Result<_, AuthError> {
        let app_id = from_c_str(app_id)?;

        (*auth)
            .send(move |client| {
                revoke_app(client, &app_id)
                    .and_then(move |app_id| {
                                  let resp =
                                      encode_response(&IpcMsg::Revoked { app_id: app_id.clone() },
                                                      &app_id)?;
                                  o_cb(user_data.0, FFI_RESULT_OK, resp.as_ptr());
                                  Ok(())
                              })
                    .map_err(move |e| {
                        let (error_code, description) = ffi_error!(e);
                        o_cb(user_data.0,
                             FfiResult {
                                 error_code,
                                 description: description.as_ptr(),
                             },
                             ptr::null())
                    })
                    .into_box()
                    .into()
            })?;

        Ok(())
    });
}

/// Encodes a response to unregistered client authentication request
#[no_mangle]
pub unsafe extern "C" fn encode_unregistered_resp(req_id: u32,
                                                  is_granted: bool,
                                                  user_data: *mut c_void,
                                                  o_cb: extern "C" fn(*mut c_void,
                                                                      FfiResult,
                                                                      *const c_char)) {
    let user_data = OpaqueCtx(user_data);

    catch_unwind_cb(user_data.0, o_cb, || -> Result<(), AuthError> {
        if !is_granted {
            let resp = encode_response(&IpcMsg::Resp {
                                            req_id: req_id,
                                            resp: IpcResp::Unregistered(Err(IpcError::AuthDenied)),
                                        },
                                       "unregistered")?;

            let (error_code, description) = ffi_error!(AuthError::from(IpcError::AuthDenied));
            o_cb(user_data.0,
                 FfiResult {
                     error_code,
                     description: description.as_ptr(),
                 },
                 resp.as_ptr());
        } else {
            let bootstrap_cfg = Client::<()>::bootstrap_config()?;

            let resp = encode_response(&IpcMsg::Resp {
                                            req_id: req_id,
                                            resp: IpcResp::Unregistered(Ok(bootstrap_cfg)),
                                        },
                                       "unregistered")?;

            o_cb(user_data.0, FFI_RESULT_OK, resp.as_ptr());
        }
        Ok(())
    })
}

/// Provides and encodes an Authenticator response
#[no_mangle]
pub unsafe extern "C" fn encode_auth_resp(auth: *const Authenticator,
                                          req: *const FfiAuthReq,
                                          req_id: u32,
                                          is_granted: bool,
                                          user_data: *mut c_void,
                                          o_cb: extern "C" fn(*mut c_void,
                                                              FfiResult,
                                                              *const c_char)) {
    let user_data = OpaqueCtx(user_data);

    catch_unwind_cb(user_data.0, o_cb, || -> Result<(), AuthError> {
        let auth_req = AuthReq::clone_from_repr_c(req)?;

        if !is_granted {
            let resp = encode_response(&IpcMsg::Resp {
                                            req_id: req_id,
                                            resp: IpcResp::Auth(Err(IpcError::AuthDenied)),
                                        },
                                       &auth_req.app.id)?;

            let (error_code, description) = ffi_error!(AuthError::from(IpcError::AuthDenied));
            o_cb(user_data.0,
                 FfiResult {
                     error_code,
                     description: description.as_ptr(),
                 },
                 resp.as_ptr());
        } else {
            let permissions = auth_req.containers.clone();

            (*auth)
                .send(move |client| {
                    let app_id = auth_req.app.id.clone();
                    let app_id2 = app_id.clone();
                    let app_id3 = app_id.clone();
                    let app_container = auth_req.app_container;

                    let c2 = client.clone();
                    let c3 = client.clone();
                    let c4 = client.clone();

                    config::list_apps(client)
                        .and_then(move |(_cfg_version, config)| {
                                      app_state(&c2, &config, app_id.clone())
                                          .map(move |app_state| (config, app_state, app_id))
                                  })
                        .and_then(move |(mut config, app_state, app_id)| {
                            // Determine an app state. If it's revoked we can reuse existing
                            // keys stored in the config. And if it is authorised, we just
                            // return the app info from the config.
                            match app_state {
                                AppState::NotAuthenticated => {
                                    let owner_key = fry!(c3.owner_key().map_err(AuthError::from));
                                    let keys = AppKeys::random(owner_key);
                                    let app = AppInfo {
                                        info: auth_req.app,
                                        keys: keys,
                                    };
                                    config::insert_app(&c3, app.clone())
                                        .map(move |_| (app, app_state))
                                        .into_box()
                                }
                                AppState::Authenticated | AppState::Revoked => {
                                    let app_entry_name = sha3_256(app_id.as_bytes());
                                    if let Some(app) = config.remove(&app_entry_name) {
                                        ok!((app, app_state))
                                    } else {
                                        err!(AuthError::Unexpected("Logical error - couldn't \
                                                                    find a revoked app in config"
                                                                           .to_owned()))
                                    }
                                }
                            }
                        })
                        .and_then(move |(app, app_state)| {
                            let granted_future = match app_state {
                                AppState::Authenticated => {
                                    // Return info of the already registered app
                                    let app_keys = app.keys.clone();
                                    let bootstrap_config = fry!(Client::<()>::bootstrap_config());

                                    access_container(&c4)
                                        .and_then(move |dir| {
                                            let access_container =
                                                AccessContInfo::from_mdata_info(dir)?;
                                            Ok(AuthGranted {
                                                   app_keys: app_keys,
                                                   bootstrap_config: bootstrap_config,
                                                   access_container: access_container,
                                               })
                                        })
                                        .into_box()
                                }
                                AppState::NotAuthenticated |
                                AppState::Revoked => {
                                    // Register a new app or restore a previously registered app
                                    encode_auth_resp_impl(&c4, app, app_container, permissions)
                                }
                            };

                            granted_future
                                .and_then(move |auth_granted| {
                                    let resp =
                                        encode_response(&IpcMsg::Resp {
                                                             req_id: req_id,
                                                             resp: IpcResp::Auth(Ok(auth_granted)),
                                                         },
                                                        &app_id2)?;

                                    Ok(o_cb(user_data.0, FFI_RESULT_OK, resp.as_ptr()))
                                })
                                .or_else(move |e| -> Result<(), AuthError> {
                                    let (error_code, description) = ffi_error!(e);
                                    let resp = encode_response(&IpcMsg::Resp {
                                        req_id: req_id,
                                        resp:
                                        IpcResp::Auth(Err(e.into())),
                                    },
                                                               &app_id3)?;
                                    Ok(o_cb(user_data.0, FfiResult {
                                        error_code,
                                        description: description.as_ptr()
                                    }, resp.as_ptr()))
                                })
                                .into_box()
                        })
                        .map_err(move |e| {
                            let (error_code, description) = ffi_error!(e);
                            o_cb(user_data.0,
                                 FfiResult {
                                     error_code,
                                     description: description.as_ptr(),
                                 },
                                 ptr::null())
                        })
                        .into_box()
                        .into()
                })?;
        }

        Ok(())
    })
}

/// Update containers permissions for an App
#[no_mangle]
pub unsafe extern "C" fn encode_containers_resp(auth: *const Authenticator,
                                                req: *const FfiContainersReq,
                                                req_id: u32,
                                                is_granted: bool,
                                                user_data: *mut c_void,
                                                o_cb: extern "C" fn(*mut c_void,
                                                                    FfiResult,
                                                                    *const c_char)) {
    let user_data = OpaqueCtx(user_data);

    catch_unwind_cb(user_data.0, o_cb, || -> Result<(), AuthError> {
        let cont_req = ContainersReq::clone_from_repr_c(req)?;

        if !is_granted {
            let resp = encode_response(&IpcMsg::Resp {
                                            req_id: req_id,
                                            resp: IpcResp::Containers(Err(IpcError::AuthDenied)),
                                        },
                                       &cont_req.app.id)?;
            let (error_code, description) = ffi_error!(AuthError::from(IpcError::AuthDenied));
            o_cb(user_data.0,
                 FfiResult {
                     error_code,
                     description: description.as_ptr(),
                 },
                 resp.as_ptr());
        } else {
            let permissions = cont_req.containers.clone();
            let app_id = cont_req.app.id.clone();
            let app_id2 = app_id.clone();

            (*auth)
                .send(move |client| {
                    let c2 = client.clone();
                    let c3 = client.clone();
                    let c4 = client.clone();
                    let c5 = client.clone();

                    config::get_app(client, &app_id)
                        .and_then(move |app| {
                                      let sign_pk = app.keys.sign_pk;
                                      update_container_perms(&c2, permissions, sign_pk)
                                          .map(move |perms| (app, perms))
                                  })
                        .and_then(move |(app, perms)| {
                                      access_container(&c3).map(move |dir| (dir, app, perms))
                                  })
                        .and_then(move |(dir, app, mut perms)| {
                            let app_keys = app.keys;

                            access_container_entry(&c4, &dir, &app_id, app_keys.clone())
                                .then(move |res| {
                                    let version = match res {
                                        // Updating an existing entry
                                        Ok((version, Some(mut existing_perms))) => {
                                            for (key, val) in perms {
                                                let _ = existing_perms.insert(key, val);
                                            }
                                            perms = existing_perms;

                                            version + 1
                                        }

                                        // Adding a new access container entry
                                        Ok((_, None)) |
                                        Err(AuthError::CoreError(
                                        CoreError::RoutingClientError(
                                            ClientError::NoSuchEntry))) => 0,

                                        // Error has occurred while trying to get an
                                        // existing entry
                                        Err(e) => return Err(e),
                                    };
                                    Ok((version, app_id, app_keys, dir, perms))
                                })
                        })
                        .and_then(move |(version, app_id, app_keys, dir, perms)| {
                                      put_access_container_entry(&c5,
                                                                 &dir,
                                                                 &app_id,
                                                                 &app_keys,
                                                                 &perms,
                                                                 version)
                                  })
                        .and_then(move |_| {
                            let resp = encode_response(&IpcMsg::Resp {
                                                            req_id: req_id,
                                                            resp: IpcResp::Containers(Ok(())),
                                                        },
                                                       &cont_req.app.id)?;
                            o_cb(user_data.0, FFI_RESULT_OK, resp.as_ptr());
                            Ok(())
                        })
                        .or_else(move |e| -> Result<(), AuthError> {
                            let (error_code, description) = ffi_error!(e);
                            let resp = encode_response(&IpcMsg::Resp {
                                                            req_id: req_id,
                                                            resp:
                                                                IpcResp::Containers(Err(e.into())),
                                                        },
                                                       &app_id2)?;
                            Ok(o_cb(user_data.0,
                                    FfiResult {
                                        error_code,
                                        description: description.as_ptr(),
                                    },
                                    resp.as_ptr()))
                        })
                        .map_err(move |e| debug!("Unexpected error: {:?}", e))
                        .into_box()
                        .into()
                })?;
        }

        Ok(())
    });
}

/// Updates containers permissions
fn update_container_perms(client: &Client<()>,
                          permissions: HashMap<String, BTreeSet<Permission>>,
                          sign_pk: sign::PublicKey)
                          -> Box<AuthFuture<AccessContainerEntry>> {
    let root = fry!(client.user_root_dir());
    let mut reqs = Vec::new();

    for (container_key, access) in permissions {
        let key = fry!(root.enc_entry_key(container_key.as_bytes()));
        let perm_set = convert_permission_set(&access);

        let c2 = client.clone();
        let c3 = client.clone();
        let dir2 = root.clone();

        reqs.push(client
                      .get_mdata_value(root.name, root.type_tag, key)
                      .and_then(move |val| {
                                    let plaintext = fry!(dir2.decrypt(&val.content));
                                    let mdata_info = fry!(deserialise::<MDataInfo>(&plaintext));

                                    c2.get_mdata_version(mdata_info.name, mdata_info.type_tag)
                                        .map(move |version| (mdata_info, version))
                                        .into_box()
                                })
                      .and_then(move |(mdata_info, version)| {
                                    c3.set_mdata_user_permissions(mdata_info.name,
                                                                  mdata_info.type_tag,
                                                                  User::Key(sign_pk),
                                                                  perm_set,
                                                                  version + 1)
                                        .map(move |_| (container_key, mdata_info, access))
                                })
                      .map_err(AuthError::from));
    }

    future::join_all(reqs)
        .map(|perms| {
                 perms
                     .into_iter()
                     .fold(HashMap::new(), |mut map, (container_key, dir, access)| {
                let _ = map.insert(container_key, (dir, access));
                map
            })
             })
        .map_err(AuthError::from)
        .into_box()
}

fn encode_auth_resp_impl(client: &Client<()>,
                         app: AppInfo,
                         app_container: bool,
                         permissions: HashMap<String, BTreeSet<Permission>>)
                         -> Box<AuthFuture<AuthGranted>> {
    let c2 = client.clone();
    let c3 = client.clone();
    let c4 = client.clone();
    let c5 = client.clone();
    let c6 = client.clone();
    let c7 = client.clone();

    let sign_pk = app.keys.sign_pk;
    let app_keys = app.keys.clone();
    let app_info = app.info.clone();
    let app_id = app_info.id.clone();

    client
        .list_auth_keys_and_version()
        .and_then(move |(_, version)| c2.ins_auth_key(app.keys.sign_pk, version + 1))
        .map_err(AuthError::from)
        .and_then(move |_| update_container_perms(&c3, permissions, sign_pk))
        .and_then(move |perms| if app_container {
                      fetch_app_container(c4, app_id, sign_pk)
                          .map(move |mdata_info| (Some(mdata_info), perms))
                          .into_box()
                  } else {
                      ok!((None, perms))
                  })
        .and_then(move |(app_container, perms)| {
                      // Update access_container
                      access_container(&c5).map(move |dir| (dir, app_container, perms))
                  })
        .and_then(move |(dir, app_container, mut perms)| {
            if let Some(mdata_info) = app_container {
                // Store info about the app's dedicated container in the access container
                let mut access = BTreeSet::new();
                let _ = access.insert(Permission::Read);
                let _ = access.insert(Permission::Insert);
                let _ = access.insert(Permission::Update);
                let _ = access.insert(Permission::Delete);
                let _ = access.insert(Permission::ManagePermissions);

                let _ = perms.insert(format!("apps/{}", app_info.id), (mdata_info, access));
            };
            access_container_entry(&c6, &dir, &app_info.id, app_keys.clone()).then(move |res| {
                let version = match res {
                    // Updating an existing entry
                    Ok((version, _)) => version + 1,
                    // Adding a new access container entry
                    Err(AuthError::CoreError(
                            CoreError::RoutingClientError(
                                ClientError::NoSuchEntry))) => 0,
                    // Error has occurred while trying to get an existing entry
                    Err(e) => return Err(e),
                };
                Ok((version, app_info, app_keys, dir, perms))
            })
        })
        .and_then(move |(version, app_info, app_keys, dir, perms)| {
            put_access_container_entry(&c7, &dir, &app_info.id, &app_keys, &perms, version)
                .map(move |_| (dir, app_keys))
        })
        .and_then(move |(dir, app_keys)| {
                      Ok(AuthGranted {
                             app_keys: app_keys,
                             bootstrap_config: Client::<()>::bootstrap_config()?,
                             access_container: AccessContInfo::from_mdata_info(dir)?,
                         })
                  })
        .into_box()
}

/// Creates a new app dedicated container
fn create_app_container(client: Client<()>,
                        app_id: &str,
                        app_sign_pk: sign::PublicKey)
                        -> Box<AuthFuture<MDataInfo>> {
    let root = fry!(client.user_root_dir());
    let app_cont_name = format!("apps/{}", app_id);

    let c2 = client.clone();

    nfs::create_dir(&client, false)
        .map_err(From::from)
        .and_then(move |dir| {
            let serialised = fry!(serialise(&dir));
            let key = fry!(root.enc_entry_key(app_cont_name.as_bytes()));
            let ciphertext = fry!(root.enc_entry_value(&serialised));

            let actions = EntryActions::new().ins(key, ciphertext, 0);
            client
                .mutate_mdata_entries(root.name, root.type_tag, actions.into())
                .map_err(From::from)
                .map(move |_| dir)
                .into_box()
        })
        .and_then(move |dir| {
            let ps = PermissionSet::new()
                .allow(Action::Insert)
                .allow(Action::Update)
                .allow(Action::Delete)
                .allow(Action::ManagePermissions);

            c2.set_mdata_user_permissions(dir.name, dir.type_tag, User::Key(app_sign_pk), ps, 1)
                .map_err(From::from)
                .map(move |_| dir)
                .into_box()
        })
        .into_box()
}

/// Removes an app's dedicated container if it's available and stored in the user's root dir.
/// Returns `true` if it was removed successfully and `false` if it wasn't found in the parent dir.
pub fn remove_app_container(client: Client<()>, app_id: &str) -> Box<AuthFuture<bool>> {
    let root = fry!(client.user_root_dir());
    let app_cont_name = format!("apps/{}", app_id);
    let key = fry!(root.enc_entry_key(app_cont_name.as_bytes()));

    let c2 = client.clone();

    client
        .get_mdata_value(root.name, root.type_tag, key.clone())
        .then(move |res| {
            match res {
                Err(CoreError::RoutingClientError(ClientError::NoSuchEntry)) => {
                    // App container doesn't exist
                    ok!(false)
                }
                Err(e) => err!(e),
                Ok(val) => {
                    let decrypted = fry!(root.decrypt(&val.content));
                    let mdata_info = fry!(deserialise::<MDataInfo>(&decrypted));

                    let c3 = c2.clone();

                    c2.list_mdata_entries(mdata_info.name, mdata_info.type_tag)
                        .and_then(move |entries| {
                            // Remove all entries in MData
                            let actions = entries
                                .iter()
                                .fold(EntryActions::new(), |actions, (entry_name, val)| {
                                    actions.del(entry_name.clone(), val.entry_version + 1)
                                });
                            c3.mutate_mdata_entries(mdata_info.name,
                                                    mdata_info.type_tag,
                                                    actions.into())
                        })
                        .and_then(move |_| {
                            // Remove MData itself
                            let actions = EntryActions::new().del(key, val.entry_version + 1);
                            client.mutate_mdata_entries(root.name, root.type_tag, actions.into())

                            // TODO(nbaksalyar): when MData deletion is implemented properly,
                            // also delete the actual MutableData related to app
                        })
                        .map_err(From::from)
                        .map(move |_| true)
                        .into_box()
                }
            }
        })
        .into_box()
}

/// Checks if an app's dedicated container is available and stored in the user's root dir.
/// If no previously created container has been found, then it will be created.
fn fetch_app_container(client: Client<()>,
                       app_id: String,
                       app_sign_pk: sign::PublicKey)
                       -> Box<AuthFuture<MDataInfo>> {
    let root = fry!(client.user_root_dir());
    let app_cont_name = format!("apps/{}", app_id);
    let key = fry!(root.enc_entry_key(app_cont_name.as_bytes()));

    let c2 = client.clone();

    client
        .get_mdata_value(root.name, root.type_tag, key)
        .then(move |res| {
            match res {
                // If the container is not found, create it
                Ok(ref v) if v.content.is_empty() => {
                    create_app_container(client, &app_id, app_sign_pk)
                }
                Err(CoreError::RoutingClientError(ClientError::NoSuchEntry)) => {
                    create_app_container(client, &app_id, app_sign_pk)
                }
                // Reuse the already existing app container
                Ok(val) => {
                    let plaintext = fry!(root.decrypt(&val.content));
                    let mdata_info = fry!(deserialise::<MDataInfo>(&plaintext));

                    // Update permissions for the app container
                    let ps = PermissionSet::new()
                        .allow(Action::Insert)
                        .allow(Action::Update)
                        .allow(Action::Delete)
                        .allow(Action::ManagePermissions);

                    c2.get_mdata_version(mdata_info.name, mdata_info.type_tag)
                        .and_then(move |version| {
                                      c2.set_mdata_user_permissions(mdata_info.name,
                                                                    mdata_info.type_tag,
                                                                    User::Key(app_sign_pk),
                                                                    ps,
                                                                    version + 1)
                                          .map(move |_| mdata_info)
                                  })
                        .map_err(From::from)
                        .into_box()
                }
                Err(e) => err!(e),
            }
        })
        .into_box()
}

fn encode_response(msg: &IpcMsg, app_id: &str) -> Result<CString, IpcError> {
    let app_id = base64_encode(app_id.as_bytes());
    let resp = ipc::encode_msg(msg, &format!("safe-{}", app_id))?;
    Ok(CString::new(resp).map_err(StringError::from)?)
}

/// Represents current app state
#[derive(Debug)]
pub enum AppState {
    /// Exists in the authenticator config, access container, and registered in MaidManagers
    Authenticated,
    /// Exists in the authenticator config but not in access container and MaidManagers
    Revoked,
    /// Doesn't exist in the authenticator config
    NotAuthenticated,
}

/// Returns a current app state (`Authenticated` if it has an entry
/// in the config file AND the access container, `Revoked` if it has
/// an entry in the config but not in the access container, and `NotAuthenticated`
/// if it's not registered anywhere).
pub fn app_state(client: &Client<()>, apps: &Apps, app_id: String) -> Box<AuthFuture<AppState>> {
    let c2 = client.clone();
    let app_id_hash = sha3_256(app_id.clone().as_bytes());

    if let Some(app) = apps.get(&app_id_hash) {
        let app_keys = app.keys.clone();
        access_container(client)
            .and_then(move |dir| access_container_entry(&c2, &dir, &app_id, app_keys))
            .then(move |res| {
                match res {
                    Ok((_version, Some(_))) => Ok(AppState::Authenticated),
                    Ok((_, None)) |
                        Err(AuthError::CoreError(
                            CoreError::RoutingClientError(
                                ClientError::NoSuchEntry))) => {
                            // App is not in access container, so it is revoked
                            Ok(AppState::Revoked)
                        }
                    Err(e) => Err(e),
                }
            })
            .into_box()
    } else {
        ok!(AppState::NotAuthenticated)
    }
}
