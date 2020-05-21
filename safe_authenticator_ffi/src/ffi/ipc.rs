// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::ffi::errors::FfiError;
use ffi_utils::{
    async_catch_unwind_cb, catch_unwind_cb, FfiResult, NativeResult, OpaqueCtx, ReprC, SafePtr,
    FFI_RESULT_OK,
};
use ffi_utils::{call_result_cb, ffi_error};
use futures::future::FutureExt;
use futures::{stream, Future, Stream};
use log::debug;
use safe_authenticator::access_container;
use safe_authenticator::app_auth;
use safe_authenticator::config;
use safe_authenticator::ipc::{decode_ipc_msg, decode_share_mdata_req, encode_response};
use safe_authenticator::revocation::{flush_app_revocation_queue, revoke_app};
use safe_authenticator::{AuthError, Authenticator};
use safe_core::client::Client;
use safe_core::ffi::ipc::req::{AuthReq, ContainersReq, ShareMDataRequest};
use safe_core::ffi::ipc::resp::MetadataResponse;
use safe_core::ipc::req::{
    AuthReq as NativeAuthReq, ContainersReq as NativeContainersReq, IpcReq,
    ShareMDataReq as NativeShareMDataReq,
};
use safe_core::ipc::resp::IpcResp;
use safe_core::ipc::{decode_msg, IpcError, IpcMsg};
use safe_core::{client, CoreError};
use safe_nd::MDataAddress;
use std::ffi::CStr;
use std::iter::Iterator;
use std::os::raw::{c_char, c_void};

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

    catch_unwind_cb(user_data.0, o_err, || -> Result<_, FfiError> {
        let msg_raw = CStr::from_ptr(msg).to_str()?;
        let msg = decode_msg(msg_raw)?;

        match msg {
            IpcMsg::Req {
                request: IpcReq::Unregistered(extra_data),
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
                    Err::<(), _>(FfiFfiError::from(CoreError::OperationForbidden)),
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
        req: *const ShareMDataRequest,
        metadata: *const MetadataResponse,
        metadata_len: usize,
    ),
    o_err: extern "C" fn(user_data: *mut c_void, result: *const FfiResult, response: *const c_char),
) {
    let user_data = OpaqueCtx(user_data);

    catch_unwind_cb(user_data.0, o_err, || -> Result<_, FfiError> {
        let msg_raw = CStr::from_ptr(msg).to_str()?;
        let msg = decode_msg(msg_raw)?;

        let client = (*auth).client;
        let c1 = client.clone();
        let msg = futures::executor::block_on(decode_ipc_msg(&client, msg))?;
        let res = match msg {
            Ok(IpcMsg::Req {
                request: IpcReq::Auth(auth_req),
                req_id,
            }) => {
                let repr_c = r#try!(auth_req.into_repr_c().map_err(AuthError::IpcError));
                o_auth(user_data.0, req_id, &repr_c);
                Ok(())
            }
            Ok(IpcMsg::Req {
                request: IpcReq::Containers(cont_req),
                req_id,
            }) => {
                let repr_c = r#try!(cont_req.into_repr_c().map_err(AuthError::IpcError));
                o_containers(user_data.0, req_id, &repr_c);
                Ok(())
            }
            Ok(IpcMsg::Req {
                request: IpcReq::Unregistered(extra_data),
                req_id,
            }) => {
                o_unregistered(
                    user_data.0,
                    req_id,
                    extra_data.as_safe_ptr(),
                    extra_data.len(),
                );
                Ok(())
            }
            Ok(IpcMsg::Req {
                request: IpcReq::ShareMData(share_mdata_req),
                req_id,
            }) => {
                let metadata_cont =
                    futures::executor::block_on(decode_share_mdata_req(&c1, &share_mdata_req))?;
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
            }
            Err((error_code, description, err)) => {
                let res = NativeResult {
                    error_code,
                    description: Some(description),
                }
                .into_repr_c()?;
                o_err(user_data.0, &res, err.as_ptr());
                Ok(())
            }
            Ok(IpcMsg::Resp { .. }) | Ok(IpcMsg::Revoked { .. }) | Ok(IpcMsg::Err(..)) => {
                let err = FfiError::from(AuthError::Unexpected("Unexpected msg type".to_owned()));
                call_result_cb!(Err::<(), _>(err), user_data, o_err);
                Ok(())
            }
        }
        .map_err(move |err: AuthError| {
            call_result_cb!(Err::<(), _>(FfiError::from(err)), user_data, o_err);
        });
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

    catch_unwind_cb(user_data.0, o_cb, || -> Result<_, FfiError> {
        let app_id = String::clone_from_repr_c(app_id)?;

        let client = (*auth).client;
        futures::executor::block_on(revoke_app(&client, &app_id)).map_err(move |e| {
            call_result_cb!(Err::<(), _>(FfiError::from(e)), user_data, o_cb);
        });

        let resp = encode_response(&IpcMsg::Revoked { app_id })?;
        o_cb(user_data.0, FFI_RESULT_OK, resp.as_ptr());

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
        let client = (*auth).client;
        let res = futures::executor::block_on(flush_app_revocation_queue(&client));
        call_result_cb!(res.map_err(FfiError::from), user_data, o_cb);
        Ok(())
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

    catch_unwind_cb(user_data.0, o_cb, || -> Result<(), FfiError> {
        if is_granted {
            let bootstrap_cfg = client::bootstrap_config()?;

            let resp = encode_response(&IpcMsg::Resp {
                req_id,
                response: IpcResp::Unregistered(Ok(bootstrap_cfg)),
            })?;

            o_cb(user_data.0, FFI_RESULT_OK, resp.as_ptr());
        } else {
            let resp = encode_response(&IpcMsg::Resp {
                req_id,
                response: IpcResp::Unregistered(Err(IpcError::AuthDenied)),
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

    catch_unwind_cb(user_data.0, o_cb, || -> Result<(), FfiError> {
        let auth_req = NativeAuthReq::clone_from_repr_c(req)?;

        if is_granted {
            let client = (*auth).client;
            let auth_granted =
                futures::executor::block_on(app_auth::authenticate(&client, auth_req))
                    .map_err(FfiError::from)?;

            let res = {
                let resp = encode_response(&IpcMsg::Resp {
                    req_id,
                    response: IpcResp::Auth(Ok(auth_granted)),
                })?;

                o_cb(user_data.0, FFI_RESULT_OK, resp.as_ptr());
                Ok(())
            };
            res.or_else(move |e: FfiError| -> Result<(), FfiError> {
                let (error_code, description) = ffi_error!(e);
                let resp = encode_response(&IpcMsg::Resp {
                    req_id,
                    response: IpcResp::Auth(Err(e.into())),
                })?;
                let result = NativeResult {
                    error_code,
                    description: Some(description),
                }
                .into_repr_c()?;
                o_cb(user_data.0, &result, resp.as_ptr());
                Ok(())
            })
            .map_err(move |e| {
                call_result_cb!(Err::<(), _>(e), user_data, o_cb);
            });
        } else {
            let response = encode_response(&IpcMsg::Resp {
                req_id,
                response: IpcResp::Auth(Err(IpcError::AuthDenied)),
            })?;

            o_cb(user_data.0, FFI_RESULT_OK, response.as_ptr());
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

    catch_unwind_cb(user_data.0, o_cb, || -> Result<(), FfiError> {
        let cont_req = NativeContainersReq::clone_from_repr_c(req)?;

        if is_granted {
            let permissions = cont_req.containers.clone();
            let app_id = cont_req.app.id;

            let client = (*auth).client;
            let c2 = client.clone();
            let c3 = client.clone();
            let c4 = client.clone();

            let app = futures::executor::block_on(config::get_app(&client, &app_id))?;
            let app_pk = app.keys.public_key();
            let mut perms = futures::executor::block_on(access_container::update_container_perms(
                &c2,
                permissions,
                app_pk,
            ))?;
            let app_keys = app.keys;

            let res = futures::executor::block_on(access_container::fetch_entry(
                c3,
                app_id,
                app_keys.clone(),
            ));
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
                Ok((_, None)) => 0,

                // Error has occurred while trying to get an
                // existing entry
                Err(e) => return Err(FfiError::from(e)),
            };
            futures::executor::block_on(access_container::put_entry(
                &c4, &app_id, &app_keys, &perms, version,
            ))?;

            let res: Result<(), Error> = {
                let resp = encode_response(&IpcMsg::Resp {
                    req_id,
                    response: IpcResp::Containers(Ok(())),
                })
                .map_err(FfiError::from)?;
                o_cb(user_data.0, FFI_RESULT_OK, resp.as_ptr());
                Ok(())
            }
            .or_else(move |e| -> Result<(), FfiError> {
                let (error_code, description) = ffi_error!(e);
                let resp = encode_response(&IpcMsg::Resp {
                    req_id,
                    response: IpcResp::Containers(Err(e.into())),
                })?;
                let result = NativeResult {
                    error_code,
                    description: Some(description),
                }
                .into_repr_c()?;
                o_cb(user_data.0, &result, resp.as_ptr());
                Ok(())
            })
            .map_err(move |e| debug!("Unexpected error: {:?}", e));
        } else {
            let response = encode_response(&IpcMsg::Resp {
                req_id,
                response: IpcResp::Containers(Err(IpcError::AuthDenied)),
            })?;

            o_cb(user_data.0, FFI_RESULT_OK, response.as_ptr());
        }

        Ok(())
    });
}

/// Encode share mutable data response.
#[no_mangle]
pub unsafe extern "C" fn encode_share_mdata_resp(
    auth: *const Authenticator,
    req: *const ShareMDataRequest,
    req_id: u32,
    is_granted: bool,
    user_data: *mut c_void,
    o_cb: extern "C" fn(user_data: *mut c_void, result: *const FfiResult, response: *const c_char),
) {
    let user_data = OpaqueCtx(user_data);

    catch_unwind_cb(user_data.0, o_cb, || -> Result<(), FfiError> {
        let share_mdata_req = NativeShareMDataReq::clone_from_repr_c(req)?;

        if is_granted {
            let client = (*auth).client;

            let client_cloned0 = client.clone();
            let client_cloned1 = client.clone();
            let user_data = user_data.0;

            let app_info =
                futures::executor::block_on(config::get_app(&client, &share_mdata_req.app.id))?;
            let user = app_info.keys.public_key();
            let num_mdata = share_mdata_req.mdata.len();

            let _ = {
                // let (version, mdata) =
                // stream::iter(
                // let _ =
                for mdata in share_mdata_req.mdata.iter() {
                    // share_mdata_req.mdata.into_iter()
                    // )
                    // .map(move |mdata| {
                    let md = futures::executor::block_on(
                        client_cloned0.get_seq_mdata_shell(mdata.name, mdata.type_tag),
                    )?;
                    // .catch_unwind()
                    // .map(|md| (md.version(), mdata))
                    // (md.version(), mdata)
                    // })
                    // .map( |res| {
                    //     match res {
                    //         Ok(tuple) => tuple,

                    //     }
                    // })
                    // .buffer_unordered(num_mdata)

                    // .map(move |(version, mdata)| {
                    futures::executor::block_on(client_cloned1.set_mdata_user_permissions(
                        MDataAddress::Seq {
                            name: mdata.name,
                            tag: mdata.type_tag,
                        },
                        user,
                        mdata.perms,
                        version + 1,
                    ))?;

                    // });
                    // .buffer_unordered(num_mdata)
                    // .map_err(AuthError::CoreError)
                    // .for_each(|()| Ok(()))
                    // .and_then(move |()| {
                    let resp = encode_response(&IpcMsg::Resp {
                        req_id,
                        response: IpcResp::ShareMData(Ok(())),
                    })
                    .map_err(AuthError::IpcError)?;
                    o_cb(user_data, FFI_RESULT_OK, resp.as_ptr());
                    // Ok(())
                }

                Ok(())
                // })
            }
            .map_err(move |e| {
                call_result_cb!(Err::<(), _>(FfiError::from(e)), user_data, o_cb);
                AuthError::from(e)
            })?;
        // .into_box()
        } else {
            let resp = encode_response(&IpcMsg::Resp {
                req_id,
                response: IpcResp::ShareMData(Err(IpcError::ShareMDataDenied)),
            })?;

            o_cb(user_data.0, FFI_RESULT_OK, resp.as_ptr());
        }

        Ok(())
    })
}
