// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

//! App-related IPC utilities.

use crate::errors::AppError;
use ffi_utils::{
    catch_unwind_cb, from_c_str, vec_clone_from_raw_parts, FfiResult, ReprC, FFI_RESULT_OK,
};
use maidsafe_utilities::serialisation::serialise;
use safe_core::ffi::ipc::req::{AuthReq, ContainersReq, ShareMDataReq};
use safe_core::ffi::ipc::resp::AuthGranted;
use safe_core::ipc::{
    self, AuthReq as NativeAuthReq, ContainersReq as NativeContainersReq, IpcError, IpcMsg, IpcReq,
    IpcResp, ShareMDataReq as NativeShareMDataReq,
};
use std::ffi::CString;
use std::os::raw::{c_char, c_void};

/// Encode `AuthReq`.
#[no_mangle]
pub unsafe extern "C" fn encode_auth_req(
    req: *const AuthReq,
    user_data: *mut c_void,
    o_cb: extern "C" fn(
        user_data: *mut c_void,
        result: *const FfiResult,
        req_id: u32,
        encoded: *const c_char,
    ),
) {
    catch_unwind_cb(user_data, o_cb, || -> Result<_, AppError> {
        let req_id = ipc::gen_req_id();
        let req = NativeAuthReq::clone_from_repr_c(req)?;

        let encoded = encode_ipc(req_id, IpcReq::Auth(req))?;
        o_cb(user_data, FFI_RESULT_OK, req_id, encoded.as_ptr());
        Ok(())
    })
}

/// Encode `AuthReq` using base64 encoding.
#[allow(dead_code)]
#[cfg(any(test, feature = "testing"))]
unsafe extern "C" fn encode_auth_req_64(
    req: *const AuthReq,
    user_data: *mut c_void,
    o_cb: extern "C" fn(
        user_data: *mut c_void,
        result: *const FfiResult,
        req_id: u32,
        encoded: *const c_char,
    ),
) {
    catch_unwind_cb(user_data, o_cb, || -> Result<_, AppError> {
        let req_id = ipc::gen_req_id();
        let req = NativeAuthReq::clone_from_repr_c(req)?;

        let encoded = encode_ipc_64(req_id, IpcReq::Auth(req))?;
        o_cb(user_data, FFI_RESULT_OK, req_id, encoded.as_ptr());
        Ok(())
    })
}

/// Encode `ContainersReq`.
#[no_mangle]
pub unsafe extern "C" fn encode_containers_req(
    req: *const ContainersReq,
    user_data: *mut c_void,
    o_cb: extern "C" fn(
        user_data: *mut c_void,
        result: *const FfiResult,
        req_id: u32,
        encoded: *const c_char,
    ),
) {
    catch_unwind_cb(user_data, o_cb, || -> Result<_, AppError> {
        let req_id = ipc::gen_req_id();
        let req = NativeContainersReq::clone_from_repr_c(req)?;

        let encoded = encode_ipc(req_id, IpcReq::Containers(req))?;
        o_cb(user_data, FFI_RESULT_OK, req_id, encoded.as_ptr());
        Ok(())
    })
}

/// Encode `AuthReq` for an unregistered client.
#[no_mangle]
pub unsafe extern "C" fn encode_unregistered_req(
    extra_data: *const u8,
    extra_data_len: usize,
    user_data: *mut c_void,
    o_cb: extern "C" fn(
        user_data: *mut c_void,
        result: *const FfiResult,
        req_id: u32,
        encoded: *const c_char,
    ),
) {
    catch_unwind_cb(user_data, o_cb, || -> Result<_, AppError> {
        let data = vec_clone_from_raw_parts(extra_data, extra_data_len);

        let req_id = ipc::gen_req_id();
        let encoded = encode_ipc(req_id, IpcReq::Unregistered(data))?;
        o_cb(user_data, FFI_RESULT_OK, req_id, encoded.as_ptr());
        Ok(())
    })
}

/// Encode `ShareMDataReq`.
#[no_mangle]
pub unsafe extern "C" fn encode_share_mdata_req(
    req: *const ShareMDataReq,
    user_data: *mut c_void,
    o_cb: extern "C" fn(
        user_data: *mut c_void,
        result: *const FfiResult,
        req_id: u32,
        encoded: *const c_char,
    ),
) {
    catch_unwind_cb(user_data, o_cb, || -> Result<_, AppError> {
        let req_id = ipc::gen_req_id();
        let req = NativeShareMDataReq::clone_from_repr_c(req)?;

        let encoded = encode_ipc(req_id, IpcReq::ShareMData(req))?;
        o_cb(user_data, FFI_RESULT_OK, req_id, encoded.as_ptr());
        Ok(())
    })
}

fn encode_ipc(req_id: u32, req: IpcReq) -> Result<CString, AppError> {
    let encoded = ipc::encode_msg(&IpcMsg::Req { req_id, req })?;
    Ok(CString::new(encoded)?)
}

#[cfg(any(test, feature = "testing"))]
fn encode_ipc_64(req_id: u32, req: IpcReq) -> Result<CString, AppError> {
    let encoded = ipc::encode_msg_64(&IpcMsg::Req { req_id, req })?;
    Ok(CString::new(encoded)?)
}

/// Decode IPC message.
#[no_mangle]
pub unsafe extern "C" fn decode_ipc_msg(
    msg: *const c_char,
    user_data: *mut c_void,
    o_auth: extern "C" fn(user_data: *mut c_void, req_id: u32, auth_granted: *const AuthGranted),
    o_unregistered: extern "C" fn(
        user_data: *mut c_void,
        req_id: u32,
        serialised_cfg: *const u8,
        serialised_cfg_len: usize,
    ),
    o_containers: extern "C" fn(user_data: *mut c_void, req_id: u32),
    o_share_mdata: extern "C" fn(user_data: *mut c_void, req_id: u32),
    o_revoked: extern "C" fn(user_data: *mut c_void),
    o_err: extern "C" fn(user_data: *mut c_void, result: *const FfiResult, req_id: u32),
) {
    catch_unwind_cb(user_data, o_err, || -> Result<_, AppError> {
        let msg = from_c_str(msg)?;
        let msg = ipc::decode_msg(&msg)?;

        decode_ipc_msg_impl(
            msg,
            user_data,
            o_auth,
            o_unregistered,
            o_containers,
            o_share_mdata,
            o_revoked,
            o_err,
        )?;

        Ok(())
    })
}

/// Decode IPC message.
#[allow(dead_code)]
#[cfg(any(test, feature = "testing"))]
unsafe extern "C" fn decode_ipc_msg_64(
    msg: *const c_char,
    user_data: *mut c_void,
    o_auth: extern "C" fn(user_data: *mut c_void, req_id: u32, auth_granted: *const AuthGranted),
    o_unregistered: extern "C" fn(
        user_data: *mut c_void,
        req_id: u32,
        serialised_cfg: *const u8,
        serialised_cfg_len: usize,
    ),
    o_containers: extern "C" fn(user_data: *mut c_void, req_id: u32),
    o_share_mdata: extern "C" fn(user_data: *mut c_void, req_id: u32),
    o_revoked: extern "C" fn(user_data: *mut c_void),
    o_err: extern "C" fn(user_data: *mut c_void, result: *const FfiResult, req_id: u32),
) {
    catch_unwind_cb(user_data, o_err, || -> Result<_, AppError> {
        let msg = from_c_str(msg)?;
        let msg = ipc::decode_msg_64(&msg)?;

        decode_ipc_msg_impl(
            msg,
            user_data,
            o_auth,
            o_unregistered,
            o_containers,
            o_share_mdata,
            o_revoked,
            o_err,
        )?;

        Ok(())
    })
}

fn decode_ipc_msg_impl(
    msg: IpcMsg,
    user_data: *mut c_void,
    o_auth: extern "C" fn(user_data: *mut c_void, req_id: u32, auth_granted: *const AuthGranted),
    o_unregistered: extern "C" fn(
        user_data: *mut c_void,
        req_id: u32,
        serialised_cfg: *const u8,
        serialised_cfg_len: usize,
    ),
    o_containers: extern "C" fn(user_data: *mut c_void, req_id: u32),
    o_share_mdata: extern "C" fn(user_data: *mut c_void, req_id: u32),
    o_revoked: extern "C" fn(user_data: *mut c_void),
    o_err: extern "C" fn(user_data: *mut c_void, result: *const FfiResult, req_id: u32),
) -> Result<(), AppError> {
    match msg {
        IpcMsg::Resp {
            resp: IpcResp::Auth(res),
            req_id,
        } => match res {
            Ok(auth_granted) => match auth_granted.into_repr_c() {
                Ok(auth_granted) => {
                    o_auth(user_data, req_id, &auth_granted);
                }
                Err(err) => {
                    let e = AppError::from(err);
                    let (error_code, description) = ffi_error!(e);
                    let res = FfiResult {
                        error_code,
                        description: description.as_ptr(),
                    };
                    o_err(user_data, &res, req_id);
                }
            },
            Err(err) => {
                let e = AppError::from(err);
                let (error_code, description) = ffi_error!(e);
                let res = FfiResult {
                    error_code,
                    description: description.as_ptr(),
                };
                o_err(user_data, &res, req_id);
            }
        },
        IpcMsg::Resp {
            resp: IpcResp::Containers(res),
            req_id,
        } => match res {
            Ok(()) => o_containers(user_data, req_id),
            Err(err) => {
                let e = AppError::from(err);
                let (error_code, description) = ffi_error!(e);
                let res = FfiResult {
                    error_code,
                    description: description.as_ptr(),
                };
                o_err(user_data, &res, req_id);
            }
        },
        IpcMsg::Resp {
            resp: IpcResp::Unregistered(res),
            req_id,
        } => match res {
            Ok(bootstrap_cfg) => {
                let serialised_cfg = serialise(&bootstrap_cfg)?;
                o_unregistered(
                    user_data,
                    req_id,
                    serialised_cfg.as_ptr(),
                    serialised_cfg.len(),
                );
            }
            Err(err) => {
                let e = AppError::from(err);
                let (error_code, description) = ffi_error!(e);
                let res = FfiResult {
                    error_code,
                    description: description.as_ptr(),
                };
                o_err(user_data, &res, req_id);
            }
        },
        IpcMsg::Resp {
            resp: IpcResp::ShareMData(res),
            req_id,
        } => match res {
            Ok(()) => o_share_mdata(user_data, req_id),
            Err(err) => {
                let e = AppError::from(err);
                let (error_code, description) = ffi_error!(e);
                let res = FfiResult {
                    error_code,
                    description: description.as_ptr(),
                };
                o_err(user_data, &res, req_id);
            }
        },
        IpcMsg::Revoked { .. } => o_revoked(user_data),
        _ => {
            return Err(IpcError::InvalidMsg.into());
        }
    };

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ffi_utils::test_utils::{call_1, call_2};
    use ffi_utils::ReprC;
    use rand;
    use routing::{Action, PermissionSet};
    use rust_sodium::crypto::secretbox;
    use safe_authenticator::ffi::ipc::encode_auth_resp;
    use safe_authenticator::test_utils as auth_utils;
    use safe_core::crypto::{shared_box, shared_secretbox, shared_sign};
    use safe_core::ffi::ipc::resp::AuthGranted as FfiAuthGranted;
    use safe_core::ipc::{
        self, AccessContInfo, AccessContainerEntry, AppKeys, AuthGranted, BootstrapConfig,
        ContainersReq, IpcMsg, IpcReq, IpcResp, Permission, ShareMData, ShareMDataReq,
    };
    use safe_core::utils;
    use std::collections::HashMap;
    use std::ffi::CString;
    use std::os::raw::c_void;
    use crate::test_utils;

    // Test that encoding and decoding base64 is no longer backwards compatible, as expected.
    #[test]
    fn base_64_encoding() {
        println!("Logging in...");
        let auth = auth_utils::create_account_and_login();

        println!("Authorising app...");
        let auth_req = test_utils::create_random_auth_req();
        let ffi_auth_req = unwrap!(auth_req.clone().into_repr_c());

        // Encode auth req using base64.
        let (_req_id, encoded): (u32, String) =
            unsafe { unwrap!(call_2(|ud, cb| encode_auth_req_64(&ffi_auth_req, ud, cb))) };

        // Try to decode ipc message, should fail.
        match auth_utils::auth_decode_ipc_msg_helper(&auth, &encoded) {
            Err((-1, None)) => (),
            _ => panic!("Unexpected result"),
        }

        // Encode auth req using base32.
        let (req_id, encoded): (u32, String) =
            unsafe { unwrap!(call_2(|ud, cb| encode_auth_req(&ffi_auth_req, ud, cb))) };

        // Decode ipc message in the authenticator.
        let decoded = unwrap!(auth_utils::auth_decode_ipc_msg_helper(&auth, &encoded));
        let auth_req = match decoded {
            (
                IpcMsg::Req {
                    req: IpcReq::Auth(auth_req),
                    ..
                },
                None,
            ) => auth_req,
            _ => panic!("Unexpected: {:?}", decoded),
        };

        let encoded_auth_resp: String = unsafe {
            unwrap!(call_1(|ud, cb| {
                let auth_req = unwrap!(auth_req.into_repr_c());
                encode_auth_resp(
                    &auth, &auth_req, req_id, true, // is_granted
                    ud, cb,
                )
            }))
        };
        let encoded_auth_resp = unwrap!(CString::new(encoded_auth_resp));

        let mut context = Context {
            unexpected_cb: false,
            req_id: 0,
            error_code: 0,
        };

        let context_ptr: *mut Context = &mut context;
        unsafe {
            decode_ipc_msg_64(
                encoded_auth_resp.as_ptr(),
                context_ptr as *mut c_void,
                auth_cb,
                unregistered_cb,
                containers_cb,
                share_mdata_cb,
                revoked_cb,
                err_cb,
            );
        }

        // err_cb should be called.
        assert!(!context.unexpected_cb);
        assert_eq!(context.req_id, 0);
        assert_eq!(context.error_code, -1);

        // Test succeeded!

        struct Context {
            unexpected_cb: bool,
            req_id: u32,
            error_code: i32,
        }

        extern "C" fn auth_cb(
            ctx: *mut c_void,
            _req_id: u32,
            _auth_granted: *const FfiAuthGranted,
        ) {
            unsafe {
                let ctx = ctx as *mut Context;
                (*ctx).unexpected_cb = true;
            }
        }

        extern "C" fn containers_cb(ctx: *mut c_void, _req_id: u32) {
            unsafe {
                let ctx = ctx as *mut Context;
                (*ctx).unexpected_cb = true;
            }
        }

        extern "C" fn share_mdata_cb(ctx: *mut c_void, _req_id: u32) {
            unsafe {
                let ctx = ctx as *mut Context;
                (*ctx).unexpected_cb = true;
            }
        }

        extern "C" fn revoked_cb(ctx: *mut c_void) {
            unsafe {
                let ctx = ctx as *mut Context;
                (*ctx).unexpected_cb = true;
            }
        }

        extern "C" fn unregistered_cb(
            ctx: *mut c_void,
            _req_id: u32,
            _bootstrap_cfg: *const u8,
            _bootstrap_cfg_len: usize,
        ) {
            unsafe {
                let ctx = ctx as *mut Context;
                (*ctx).unexpected_cb = true;
            }
        }

        extern "C" fn err_cb(ctx: *mut c_void, res: *const FfiResult, req_id: u32) {
            unsafe {
                let ctx = ctx as *mut Context;
                (*ctx).unexpected_cb = false;
                (*ctx).req_id = req_id;
                (*ctx).error_code = (*res).error_code;
            }
        }
    }

    // Test encoding and decoding authorisation requests.
    #[test]
    fn encode_auth_req_basics() {
        let req = test_utils::create_random_auth_req();

        let req_c = unwrap!(req.clone().into_repr_c());

        let (req_id, encoded): (u32, String) =
            unsafe { unwrap!(call_2(|ud, cb| encode_auth_req(&req_c, ud, cb))) };

        // Decode it and verify it's the same we encoded.
        let msg = unwrap!(ipc::decode_msg(&encoded));

        let (decoded_req_id, decoded_req) = match msg {
            IpcMsg::Req {
                req_id,
                req: IpcReq::Auth(req),
            } => (req_id, req),
            x => panic!("Unexpected {:?}", x),
        };

        assert_eq!(decoded_req_id, req_id);
        assert_eq!(decoded_req, req);
    }

    // Test encoding and decoding containers requests.
    #[test]
    fn encode_containers_req_basics() {
        let mut container_permissions = HashMap::new();
        let _ = container_permissions.insert(
            unwrap!(utils::generate_random_string(10)),
            btree_set![Permission::Read],
        );

        let req = ContainersReq {
            app: test_utils::gen_app_exchange_info(),
            containers: container_permissions,
        };

        let req_c = unwrap!(req.clone().into_repr_c());

        let (req_id, encoded): (u32, String) =
            unsafe { unwrap!(call_2(|ud, cb| encode_containers_req(&req_c, ud, cb))) };

        // Decode it and verify it's the same we encoded.
        let msg = unwrap!(ipc::decode_msg(&encoded));

        let (decoded_req_id, decoded_req) = match msg {
            IpcMsg::Req {
                req_id,
                req: IpcReq::Containers(req),
            } => (req_id, req),
            x => panic!("Unexpected {:?}", x),
        };

        assert_eq!(decoded_req_id, req_id);
        assert_eq!(decoded_req, req);
    }

    // Test encoding and decoding unregistered requests.
    #[test]
    fn encode_unregistered_req_basics() {
        let test_data = vec![1u8, 10];
        let (req_id, encoded): (u32, String) = unsafe {
            unwrap!(call_2(|ud, cb| encode_unregistered_req(
                test_data.as_ptr(),
                test_data.len(),
                ud,
                cb
            )))
        };

        // Decode it and verify it's the same we encoded.
        let msg = unwrap!(ipc::decode_msg(&encoded));

        let (decoded_req_id, decoded_data) = match msg {
            IpcMsg::Req {
                req_id,
                req: IpcReq::Unregistered(extra_data),
            } => (req_id, extra_data),
            x => panic!("Unexpected {:?}", x),
        };

        assert_eq!(decoded_req_id, req_id);
        assert_eq!(decoded_data, vec![1u8, 10]);
    }

    // Test encoding and decoding requests to share mutable data
    #[test]
    fn encode_share_mdata_basics() {
        let req = ShareMDataReq {
            app: test_utils::gen_app_exchange_info(),
            mdata: vec![ShareMData {
                type_tag: rand::random(),
                name: rand::random(),
                perms: PermissionSet::new()
                    .allow(Action::Insert)
                    .allow(Action::Update),
            }],
        };

        let req_c = unwrap!(req.clone().into_repr_c());

        let (req_id, encoded): (u32, String) =
            unsafe { unwrap!(call_2(|ud, cb| encode_share_mdata_req(&req_c, ud, cb))) };

        // Decode it and verify it's the same we encoded.
        let msg = unwrap!(ipc::decode_msg(&encoded));

        let (decoded_req_id, decoded_req) = match msg {
            IpcMsg::Req {
                req_id,
                req: IpcReq::ShareMData(req),
            } => (req_id, req),
            x => panic!("Unexpected {:?}", x),
        };

        assert_eq!(decoded_req_id, req_id);
        assert_eq!(decoded_req, req);
    }

    // Test that `decode_ipc_msg` calls the `o_auth` callback.
    #[test]
    fn decode_ipc_msg_with_auth_granted() {
        let req_id = ipc::gen_req_id();

        let access_container_info = AccessContInfo {
            id: rand::random(),
            tag: rand::random(),
            nonce: secretbox::gen_nonce(),
        };

        let auth_granted = AuthGranted {
            app_keys: gen_app_keys(),
            bootstrap_config: BootstrapConfig::default(),
            access_container_info,
            access_container_entry: AccessContainerEntry::default(),
        };

        let msg = IpcMsg::Resp {
            req_id,
            resp: IpcResp::Auth(Ok(auth_granted.clone())),
        };

        let encoded = unwrap!(ipc::encode_msg(&msg));
        let encoded = unwrap!(CString::new(encoded));

        let context = unsafe {
            let mut context = Context {
                unexpected_cb: false,
                req_id: 0,
                auth_granted: None,
            };

            extern "C" fn auth_cb(
                ctx: *mut c_void,
                req_id: u32,
                auth_granted: *const FfiAuthGranted,
            ) {
                unsafe {
                    let auth_granted = unwrap!(AuthGranted::clone_from_repr_c(auth_granted));

                    let ctx = ctx as *mut Context;
                    (*ctx).req_id = req_id;
                    (*ctx).auth_granted = Some(auth_granted);
                }
            }

            extern "C" fn containers_cb(ctx: *mut c_void, _req_id: u32) {
                unsafe {
                    let ctx = ctx as *mut Context;
                    (*ctx).unexpected_cb = true;
                }
            }

            extern "C" fn share_mdata_cb(ctx: *mut c_void, _req_id: u32) {
                unsafe {
                    let ctx = ctx as *mut Context;
                    (*ctx).unexpected_cb = true;
                }
            }

            extern "C" fn revoked_cb(ctx: *mut c_void) {
                unsafe {
                    let ctx = ctx as *mut Context;
                    (*ctx).unexpected_cb = true;
                }
            }

            extern "C" fn unregistered_cb(
                ctx: *mut c_void,
                _req_id: u32,
                _bootstrap_cfg: *const u8,
                _bootstrap_cfg_len: usize,
            ) {
                unsafe {
                    let ctx = ctx as *mut Context;
                    (*ctx).unexpected_cb = true;
                }
            }

            let context_ptr: *mut Context = &mut context;
            decode_ipc_msg(
                encoded.as_ptr(),
                context_ptr as *mut c_void,
                auth_cb,
                unregistered_cb,
                containers_cb,
                share_mdata_cb,
                revoked_cb,
                err_cb,
            );

            context
        };

        assert!(!context.unexpected_cb);
        assert_eq!(context.req_id, req_id);
        assert_eq!(unwrap!(context.auth_granted), auth_granted);
    }

    // Test that `decode_ipc_msg` calls the `o_containers` callback.
    #[test]
    fn decode_ipc_msg_with_containers_granted() {
        let req_id = ipc::gen_req_id();

        let msg = IpcMsg::Resp {
            req_id,
            resp: IpcResp::Containers(Ok(())),
        };

        let encoded = unwrap!(ipc::encode_msg(&msg));
        let encoded = unwrap!(CString::new(encoded));

        let mut context = Context {
            unexpected_cb: false,
            req_id: 0,
            auth_granted: None,
        };

        unsafe {
            extern "C" fn auth_cb(
                ctx: *mut c_void,
                _req_id: u32,
                _auth_granted: *const FfiAuthGranted,
            ) {
                unsafe {
                    let ctx = ctx as *mut Context;
                    (*ctx).unexpected_cb = true;
                }
            }

            extern "C" fn containers_cb(ctx: *mut c_void, req_id: u32) {
                unsafe {
                    let ctx = ctx as *mut Context;
                    (*ctx).req_id = req_id;
                }
            }

            extern "C" fn share_mdata_cb(ctx: *mut c_void, _req_id: u32) {
                unsafe {
                    let ctx = ctx as *mut Context;
                    (*ctx).unexpected_cb = true;
                }
            }

            extern "C" fn revoked_cb(ctx: *mut c_void) {
                unsafe {
                    let ctx = ctx as *mut Context;
                    (*ctx).unexpected_cb = true;
                }
            }

            extern "C" fn unregistered_cb(
                ctx: *mut c_void,
                _req_id: u32,
                _bootstrap_cfg: *const u8,
                _bootstrap_cfg_len: usize,
            ) {
                unsafe {
                    let ctx = ctx as *mut Context;
                    (*ctx).unexpected_cb = true;
                }
            }

            let context_ptr: *mut Context = &mut context;
            decode_ipc_msg(
                encoded.as_ptr(),
                context_ptr as *mut c_void,
                auth_cb,
                unregistered_cb,
                containers_cb,
                share_mdata_cb,
                revoked_cb,
                err_cb,
            );
        }

        assert!(!context.unexpected_cb);
        assert_eq!(context.req_id, req_id);
    }

    // Test that `decode_ipc_msg` calls the `o_unregistered` callback.
    #[test]
    fn decode_ipc_msg_with_unregistered_granted() {
        let req_id = ipc::gen_req_id();

        let msg = IpcMsg::Resp {
            req_id,
            resp: IpcResp::Unregistered(Ok(BootstrapConfig::default())),
        };

        let encoded = unwrap!(ipc::encode_msg(&msg));
        let encoded = unwrap!(CString::new(encoded));

        let mut context = Context {
            unexpected_cb: false,
            req_id: 0,
            auth_granted: None,
        };

        unsafe {
            extern "C" fn auth_cb(
                ctx: *mut c_void,
                _req_id: u32,
                _auth_granted: *const FfiAuthGranted,
            ) {
                unsafe {
                    let ctx = ctx as *mut Context;
                    (*ctx).unexpected_cb = true;
                }
            }

            extern "C" fn containers_cb(ctx: *mut c_void, _req_id: u32) {
                unsafe {
                    let ctx = ctx as *mut Context;
                    (*ctx).unexpected_cb = true;
                }
            }

            extern "C" fn share_mdata_cb(ctx: *mut c_void, _req_id: u32) {
                unsafe {
                    let ctx = ctx as *mut Context;
                    (*ctx).unexpected_cb = true;;
                }
            }

            extern "C" fn revoked_cb(ctx: *mut c_void) {
                unsafe {
                    let ctx = ctx as *mut Context;
                    (*ctx).unexpected_cb = true;
                }
            }

            extern "C" fn unregistered_cb(
                ctx: *mut c_void,
                req_id: u32,
                _bootstrap_cfg: *const u8,
                _bootstrap_cfg_len: usize,
            ) {
                unsafe {
                    let ctx = ctx as *mut Context;
                    (*ctx).req_id = req_id;
                }
            }

            let context_ptr: *mut Context = &mut context;
            decode_ipc_msg(
                encoded.as_ptr(),
                context_ptr as *mut c_void,
                auth_cb,
                unregistered_cb,
                containers_cb,
                share_mdata_cb,
                revoked_cb,
                err_cb,
            );
        }

        assert!(!context.unexpected_cb);
        assert_eq!(context.req_id, req_id);
    }

    // Test that `decode_ipc_msg` calls the `o_share_mdata` callback.
    #[test]
    fn decode_ipc_msg_with_share_mdata_granted() {
        let req_id = ipc::gen_req_id();

        let msg = IpcMsg::Resp {
            req_id,
            resp: IpcResp::ShareMData(Ok(())),
        };

        let encoded = unwrap!(ipc::encode_msg(&msg));
        let encoded = unwrap!(CString::new(encoded));

        let mut context = Context {
            unexpected_cb: false,
            req_id: 0,
            auth_granted: None,
        };

        unsafe {
            extern "C" fn auth_cb(
                ctx: *mut c_void,
                _req_id: u32,
                _auth_granted: *const FfiAuthGranted,
            ) {
                unsafe {
                    let ctx = ctx as *mut Context;
                    (*ctx).unexpected_cb = true;
                }
            }

            extern "C" fn containers_cb(ctx: *mut c_void, _req_id: u32) {
                unsafe {
                    let ctx = ctx as *mut Context;
                    (*ctx).unexpected_cb = true;
                }
            }

            extern "C" fn share_mdata_cb(ctx: *mut c_void, req_id: u32) {
                unsafe {
                    let ctx = ctx as *mut Context;
                    (*ctx).req_id = req_id;
                }
            }

            extern "C" fn revoked_cb(ctx: *mut c_void) {
                unsafe {
                    let ctx = ctx as *mut Context;
                    (*ctx).unexpected_cb = true;
                }
            }

            extern "C" fn unregistered_cb(
                ctx: *mut c_void,
                _req_id: u32,
                _bootstrap_cfg: *const u8,
                _bootstrap_cfg_len: usize,
            ) {
                unsafe {
                    let ctx = ctx as *mut Context;
                    (*ctx).unexpected_cb = true;
                }
            }

            let context_ptr: *mut Context = &mut context;
            decode_ipc_msg(
                encoded.as_ptr(),
                context_ptr as *mut c_void,
                auth_cb,
                unregistered_cb,
                containers_cb,
                share_mdata_cb,
                revoked_cb,
                err_cb,
            );
        }

        assert!(!context.unexpected_cb);
        assert_eq!(context.req_id, req_id);
    }

    fn gen_app_keys() -> AppKeys {
        let (owner_key, _) = shared_sign::gen_keypair();
        let enc_key = shared_secretbox::gen_key();
        let (sign_pk, sign_sk) = shared_sign::gen_keypair();
        let (enc_pk, enc_sk) = shared_box::gen_keypair();

        AppKeys {
            owner_key,
            enc_key,
            sign_pk,
            sign_sk,
            enc_pk,
            enc_sk,
        }
    }

    struct Context {
        unexpected_cb: bool,
        req_id: u32,
        auth_granted: Option<AuthGranted>,
    }

    extern "C" fn err_cb(ctx: *mut c_void, _res: *const FfiResult, _req_id: u32) {
        unsafe {
            let ctx = ctx as *mut Context;
            (*ctx).unexpected_cb = true;
        }
    }
}
