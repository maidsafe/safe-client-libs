// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::access_container;
use crate::app_auth;
use crate::config;
use ffi_utils::{catch_unwind_cb, from_c_str, FfiResult, OpaqueCtx, ReprC, SafePtr, FFI_RESULT_OK};
use futures::{stream, Future, Stream};
use crate::ipc::{decode_ipc_msg, decode_share_mdata_req, encode_response, update_container_perms};
use crate::revocation::{flush_app_revocation_queue, revoke_app};
use routing::{ClientError, User};
use safe_core::ffi::ipc::req::{AuthReq, ContainersReq, ShareMDataReq};
use safe_core::ffi::ipc::resp::MetadataResponse;
use safe_core::ipc::req::{
    AuthReq as NativeAuthReq, ContainersReq as NativeContainersReq, IpcReq,
    ShareMDataReq as NativeShareMDataReq,
};
use safe_core::ipc::resp::IpcResp;
use safe_core::ipc::{decode_msg, IpcError, IpcMsg};
use safe_core::{client, Client, CoreError, FutureExt};
use std::ffi::CStr;
use std::os::raw::{c_char, c_void};
use crate::{AuthError, Authenticator};

/// Decodes a given encoded IPC message without requiring an authorised account.
#[no_mangle]
pub unsafe extern "C" fn auth_unregistered_decode_ipc_msg(
    msg: *const c_char,
    user_data: *mut c_void,
    o_unregistered: extern "C" fn(
        user_data: *mut c_void,
        req_id: u32,
        extra_data: *const u8,
        extra_data_len: usize,
    ),
    o_err: extern "C" fn(user_data: *mut c_void, result: *const FfiResult, response: *const c_char),
) {
    let user_data = OpaqueCtx(user_data);

    catch_unwind_cb(user_data.0, o_err, || -> Result<_, AuthError> {
        let msg_raw = CStr::from_ptr(msg).to_str()?;
        let msg = decode_msg(msg_raw)?;

        match msg {
            IpcMsg::Req {
                req: IpcReq::Unregistered(extra_data),
                req_id,
            } => {
                o_unregistered(
                    user_data.0,
                    req_id,
                    extra_data.as_safe_ptr(),
                    extra_data.len(),
                );
            }
            _ => {
                call_result_cb!(
                    Err::<(), _>(AuthError::CoreError(CoreError::OperationForbidden)),
                    user_data,
                    o_err
                );
            }
        }

        Ok(())
    })
}

/// Decodes a given encoded IPC message and calls a corresponding callback.
#[no_mangle]
pub unsafe extern "C" fn auth_decode_ipc_msg(
    auth: *const Authenticator,
    msg: *const c_char,
    user_data: *mut c_void,
    o_auth: extern "C" fn(user_data: *mut c_void, req_id: u32, req: *const AuthReq),
    o_containers: extern "C" fn(user_data: *mut c_void, req_id: u32, req: *const ContainersReq),
    o_unregistered: extern "C" fn(
        user_data: *mut c_void,
        req_id: u32,
        extra_data: *const u8,
        extra_data_len: usize,
    ),
    o_share_mdata: extern "C" fn(
        user_data: *mut c_void,
        req_id: u32,
        req: *const ShareMDataReq,
        metadata: *const MetadataResponse,
        metadata_len: usize,
    ),
    o_err: extern "C" fn(user_data: *mut c_void, result: *const FfiResult, response: *const c_char),
) {
    let user_data = OpaqueCtx(user_data);

    catch_unwind_cb(user_data.0, o_err, || -> Result<_, AuthError> {
        let msg_raw = CStr::from_ptr(msg).to_str()?;
        let msg = decode_msg(msg_raw)?;

        (*auth).send(move |client| {
            let c1 = client.clone();
            decode_ipc_msg(client, msg)
                .and_then(move |msg| match msg {
                    Ok(IpcMsg::Req {
                        req: IpcReq::Auth(auth_req),
                        req_id,
                    }) => {
                        let repr_c = fry!(auth_req.into_repr_c().map_err(AuthError::IpcError));
                        o_auth(user_data.0, req_id, &repr_c);
                        ok!(())
                    }
                    Ok(IpcMsg::Req {
                        req: IpcReq::Containers(cont_req),
                        req_id,
                    }) => {
                        let repr_c = fry!(cont_req.into_repr_c().map_err(AuthError::IpcError));
                        o_containers(user_data.0, req_id, &repr_c);
                        ok!(())
                    }
                    Ok(IpcMsg::Req {
                        req: IpcReq::Unregistered(extra_data),
                        req_id,
                    }) => {
                        o_unregistered(
                            user_data.0,
                            req_id,
                            extra_data.as_safe_ptr(),
                            extra_data.len(),
                        );
                        ok!(())
                    }
                    Ok(IpcMsg::Req {
                        req: IpcReq::ShareMData(share_mdata_req),
                        req_id,
                    }) => decode_share_mdata_req(&c1, &share_mdata_req)
                        .and_then(move |metadata_cont| {
                            let share_mdata_req_repr_c = share_mdata_req.into_repr_c()?;

                            let mut ffi_metadata_cont = Vec::with_capacity(metadata_cont.len());
                            for metadata in metadata_cont {
                                if let Some(metadata) = metadata {
                                    ffi_metadata_cont.push(metadata);
                                } else {
                                    ffi_metadata_cont.push(MetadataResponse::invalid());
                                }
                            }

                            o_share_mdata(
                                user_data.0,
                                req_id,
                                &share_mdata_req_repr_c,
                                ffi_metadata_cont.as_ptr(),
                                ffi_metadata_cont.len(),
                            );

                            Ok(())
                        }).into_box(),
                    Err((error_code, description, err)) => {
                        let res = FfiResult {
                            error_code,
                            description: description.as_ptr(),
                        };
                        o_err(user_data.0, &res, err.as_ptr());
                        ok!(())
                    }
                    Ok(IpcMsg::Resp { .. }) | Ok(IpcMsg::Revoked { .. }) | Ok(IpcMsg::Err(..)) => {
                        let err = AuthError::Unexpected(
                            "Unexpected msg \
                             type"
                                .to_owned(),
                        );
                        call_result_cb!(Err::<(), _>(err), user_data, o_err);
                        ok!(())
                    }
                }).map_err(move |err| {
                    call_result_cb!(Err::<(), _>(err), user_data, o_err);
                }).into_box()
                .into()
        })?;
        Ok(())
    })
}

/// Encode share mutable data response.
#[no_mangle]
pub unsafe extern "C" fn encode_share_mdata_resp(
    auth: *const Authenticator,
    req: *const ShareMDataReq,
    req_id: u32,
    is_granted: bool,
    user_data: *mut c_void,
    o_cb: extern "C" fn(user_data: *mut c_void, result: *const FfiResult, response: *const c_char),
) {
    let user_data = OpaqueCtx(user_data);

    catch_unwind_cb(user_data.0, o_cb, || -> Result<(), AuthError> {
        let share_mdata_req = NativeShareMDataReq::clone_from_repr_c(req)?;
        if is_granted {
            (*auth).send(move |client| {
                let client_cloned0 = client.clone();
                let client_cloned1 = client.clone();
                let user_data = user_data.0;
                config::get_app(client, &share_mdata_req.app.id)
                    .and_then(move |app_info| {
                        let user = User::Key(app_info.keys.sign_pk);
                        let num_mdata = share_mdata_req.mdata.len();
                        stream::iter_ok(share_mdata_req.mdata.into_iter())
                            .map(move |mdata| {
                                client_cloned0
                                    .get_mdata_shell(mdata.name, mdata.type_tag)
                                    .map(|md| (md.version(), mdata))
                            }).buffer_unordered(num_mdata)
                            .map(move |(version, mdata)| {
                                client_cloned1.set_mdata_user_permissions(
                                    mdata.name,
                                    mdata.type_tag,
                                    user,
                                    mdata.perms,
                                    version + 1,
                                )
                            }).buffer_unordered(num_mdata)
                            .map_err(AuthError::CoreError)
                            .for_each(|()| Ok(()))
                            .and_then(move |()| {
                                let resp = encode_response(&IpcMsg::Resp {
                                    req_id,
                                    resp: IpcResp::ShareMData(Ok(())),
                                }).map_err(AuthError::IpcError)?;
                                o_cb(user_data, FFI_RESULT_OK, resp.as_ptr());
                                Ok(())
                            }).into_box()
                    }).map_err(move |e| {
                        call_result_cb!(Err::<(), _>(e), user_data, o_cb);
                    }).into_box()
                    .into()
            })?;
        } else {
            let resp = encode_response(&IpcMsg::Resp {
                req_id,
                resp: IpcResp::ShareMData(Err(IpcError::ShareMDataDenied)),
            })?;
            let (error_code, description) = ffi_error!(AuthError::from(IpcError::ShareMDataDenied));
            let res = FfiResult {
                error_code,
                description: description.as_ptr(),
            };
            o_cb(user_data.0, &res, resp.as_ptr());
        }
        Ok(())
    })
}

/// Revoke app access.
#[no_mangle]
pub unsafe extern "C" fn auth_revoke_app(
    auth: *const Authenticator,
    app_id: *const c_char,
    user_data: *mut c_void,
    o_cb: extern "C" fn(user_data: *mut c_void, result: *const FfiResult, response: *const c_char),
) {
    let user_data = OpaqueCtx(user_data);

    catch_unwind_cb(user_data.0, o_cb, || -> Result<_, AuthError> {
        let app_id = from_c_str(app_id)?;

        (*auth).send(move |client| {
            revoke_app(client, &app_id)
                .and_then(move |_| {
                    let resp = encode_response(&IpcMsg::Revoked { app_id })?;
                    o_cb(user_data.0, FFI_RESULT_OK, resp.as_ptr());
                    Ok(())
                }).map_err(move |e| {
                    call_result_cb!(Err::<(), _>(e), user_data, o_cb);
                }).into_box()
                .into()
        })?;

        Ok(())
    });
}

/// Flush the revocation queue.
#[no_mangle]
pub unsafe extern "C" fn auth_flush_app_revocation_queue(
    auth: *const Authenticator,
    user_data: *mut c_void,
    o_cb: extern "C" fn(user_data: *mut c_void, result: *const FfiResult),
) {
    let user_data = OpaqueCtx(user_data);

    catch_unwind_cb(user_data.0, o_cb, || -> Result<_, AuthError> {
        (*auth).send(move |client| {
            flush_app_revocation_queue(client)
                .then(move |res| {
                    call_result_cb!(res, user_data, o_cb);
                    Ok(())
                }).into_box()
                .into()
        })
    })
}

/// Encodes a response to unregistered client authentication request.
#[no_mangle]
pub unsafe extern "C" fn encode_unregistered_resp(
    req_id: u32,
    is_granted: bool,
    user_data: *mut c_void,
    o_cb: extern "C" fn(user_data: *mut c_void, result: *const FfiResult, response: *const c_char),
) {
    let user_data = OpaqueCtx(user_data);

    catch_unwind_cb(user_data.0, o_cb, || -> Result<(), AuthError> {
        if !is_granted {
            let resp = encode_response(&IpcMsg::Resp {
                req_id,
                resp: IpcResp::Unregistered(Err(IpcError::AuthDenied)),
            })?;

            o_cb(user_data.0, FFI_RESULT_OK, resp.as_ptr());
        } else {
            let bootstrap_cfg = client::bootstrap_config()?;

            let resp = encode_response(&IpcMsg::Resp {
                req_id,
                resp: IpcResp::Unregistered(Ok(bootstrap_cfg)),
            })?;

            o_cb(user_data.0, FFI_RESULT_OK, resp.as_ptr());
        }
        Ok(())
    })
}

/// Provides and encodes an Authenticator response.
#[no_mangle]
pub unsafe extern "C" fn encode_auth_resp(
    auth: *const Authenticator,
    req: *const AuthReq,
    req_id: u32,
    is_granted: bool,
    user_data: *mut c_void,
    o_cb: extern "C" fn(user_data: *mut c_void, result: *const FfiResult, response: *const c_char),
) {
    let user_data = OpaqueCtx(user_data);

    catch_unwind_cb(user_data.0, o_cb, || -> Result<(), AuthError> {
        let auth_req = NativeAuthReq::clone_from_repr_c(req)?;

        if !is_granted {
            let resp = encode_response(&IpcMsg::Resp {
                req_id,
                resp: IpcResp::Auth(Err(IpcError::AuthDenied)),
            })?;

            o_cb(user_data.0, FFI_RESULT_OK, resp.as_ptr());
        } else {
            (*auth).send(move |client| {
                app_auth::authenticate(client, auth_req)
                    .and_then(move |auth_granted| {
                        let resp = encode_response(&IpcMsg::Resp {
                            req_id,
                            resp: IpcResp::Auth(Ok(auth_granted)),
                        })?;

                        o_cb(user_data.0, FFI_RESULT_OK, resp.as_ptr());
                        Ok(())
                    }).or_else(move |e| -> Result<(), AuthError> {
                        let (error_code, description) = ffi_error!(e);
                        let resp = encode_response(&IpcMsg::Resp {
                            req_id,
                            resp: IpcResp::Auth(Err(e.into())),
                        })?;
                        let res = FfiResult {
                            error_code,
                            description: description.as_ptr(),
                        };
                        o_cb(user_data.0, &res, resp.as_ptr());
                        Ok(())
                    }).map_err(move |e| {
                        call_result_cb!(Err::<(), _>(e), user_data, o_cb);
                    }).into_box()
                    .into()
            })?;
        }

        Ok(())
    })
}

/// Update containers permissions for an App.
#[no_mangle]
pub unsafe extern "C" fn encode_containers_resp(
    auth: *const Authenticator,
    req: *const ContainersReq,
    req_id: u32,
    is_granted: bool,
    user_data: *mut c_void,
    o_cb: extern "C" fn(user_data: *mut c_void, result: *const FfiResult, response: *const c_char),
) {
    let user_data = OpaqueCtx(user_data);

    catch_unwind_cb(user_data.0, o_cb, || -> Result<(), AuthError> {
        let cont_req = NativeContainersReq::clone_from_repr_c(req)?;

        if !is_granted {
            let resp = encode_response(&IpcMsg::Resp {
                req_id,
                resp: IpcResp::Containers(Err(IpcError::AuthDenied)),
            })?;

            o_cb(user_data.0, FFI_RESULT_OK, resp.as_ptr());
        } else {
            let permissions = cont_req.containers.clone();
            let app_id = cont_req.app.id.clone();

            (*auth).send(move |client| {
                let c2 = client.clone();
                let c3 = client.clone();
                let c4 = client.clone();

                config::get_app(client, &app_id)
                    .and_then(move |app| {
                        let sign_pk = app.keys.sign_pk;
                        update_container_perms(&c2, permissions, sign_pk)
                            .map(move |perms| (app, perms))
                    }).and_then(move |(app, mut perms)| {
                        let app_keys = app.keys;

                        access_container::fetch_entry(&c3, &app_id, app_keys.clone()).then(
                            move |res| {
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
                                    Ok((_, None))
                                    | Err(AuthError::CoreError(CoreError::RoutingClientError(
                                        ClientError::NoSuchEntry,
                                    ))) => 0,

                                    // Error has occurred while trying to get an
                                    // existing entry
                                    Err(e) => return Err(e),
                                };
                                Ok((version, app_id, app_keys, perms))
                            },
                        )
                    }).and_then(move |(version, app_id, app_keys, perms)| {
                        access_container::put_entry(&c4, &app_id, &app_keys, &perms, version)
                    }).and_then(move |_| {
                        let resp = encode_response(&IpcMsg::Resp {
                            req_id,
                            resp: IpcResp::Containers(Ok(())),
                        })?;
                        o_cb(user_data.0, FFI_RESULT_OK, resp.as_ptr());
                        Ok(())
                    }).or_else(move |e| -> Result<(), AuthError> {
                        let (error_code, description) = ffi_error!(e);
                        let resp = encode_response(&IpcMsg::Resp {
                            req_id,
                            resp: IpcResp::Containers(Err(e.into())),
                        })?;
                        let res = FfiResult {
                            error_code,
                            description: description.as_ptr(),
                        };
                        o_cb(user_data.0, &res, resp.as_ptr());
                        Ok(())
                    }).map_err(move |e| debug!("Unexpected error: {:?}", e))
                    .into_box()
                    .into()
            })?;
        }

        Ok(())
    });
}
