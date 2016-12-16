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

//! App-related IPC utilities.

use errors::AppError;
use ffi_utils::{FfiString, catch_unwind_cb, catch_unwind_error_code};
use rand::{self, Rng};
use safe_core::ipc::{self, AuthReq, ContainersReq, IpcError, IpcMsg, IpcReq, IpcResp};
use safe_core::ipc::req::ffi::AuthReq as FfiAuthReq;
use safe_core::ipc::req::ffi::ContainersReq as FfiContainersReq;
use safe_core::ipc::resp::ffi::AuthGranted as FfiAuthGranted;
use std::os::raw::c_void;
use std::u32;

/// Generate unique request ID.
pub fn gen_req_id() -> u32 {
    // Generate the number in range 1..MAX inclusive.
    rand::thread_rng().gen_range(0, u32::MAX) + 1
}

/// Encode `AuthReq`.
#[no_mangle]
pub unsafe extern "C" fn encode_auth_req(req: FfiAuthReq,
                                         o_req_id: *mut u32,
                                         o_encoded: *mut FfiString)
                                         -> i32 {
    catch_unwind_error_code(|| -> Result<_, AppError> {
        let req = AuthReq::from_repr_c(req)?;
        let req_id = gen_req_id();

        let msg = IpcMsg::Req {
            req_id: req_id,
            req: IpcReq::Auth(req),
        };

        let encoded = ipc::encode_msg(&msg, "safe-auth")?;

        *o_req_id = req_id;
        *o_encoded = FfiString::from_string(encoded);

        Ok(())
    })
}

/// Encode `ContainersReq`.
#[no_mangle]
pub unsafe extern "C" fn encode_containers_req(req: FfiContainersReq,
                                               o_req_id: *mut u32,
                                               o_encoded: *mut FfiString)
                                               -> i32 {
    catch_unwind_error_code(|| -> Result<_, AppError> {
        let req = ContainersReq::from_repr_c(req)?;
        let req_id = gen_req_id();

        let msg = IpcMsg::Req {
            req_id: req_id,
            req: IpcReq::Containers(req),
        };

        let encoded = ipc::encode_msg(&msg, "safe-auth")?;

        *o_req_id = req_id;
        *o_encoded = FfiString::from_string(encoded);

        Ok(())
    })
}

/// Decode IPC message.
#[no_mangle]
pub unsafe extern "C" fn decode_ipc_msg(msg: FfiString,
                                        user_data: *mut c_void,
                                        o_auth: extern "C" fn(*mut c_void, u32, FfiAuthGranted),
                                        o_containers: extern "C" fn(*mut c_void, u32),
                                        o_revoked: extern "C" fn(*mut c_void),
                                        o_err: extern "C" fn(*mut c_void, i32, u32)) {
    catch_unwind_cb(user_data, o_err, || -> Result<_, AppError> {
        let msg = msg.as_str()?;
        let msg = ipc::decode_msg(msg)?;

        match msg {
            IpcMsg::Resp { resp: IpcResp::Auth(res), req_id } => {
                match res {
                    Ok(auth_granted) => {
                        let auth_granted = auth_granted.into_repr_c();
                        o_auth(user_data, req_id, auth_granted);
                    }
                    Err(err) => o_err(user_data, ffi_error_code!(AppError::from(err)), req_id),
                }
            }
            IpcMsg::Resp { resp: IpcResp::Containers(res), req_id } => {
                match res {
                    Ok(()) => o_containers(user_data, req_id),
                    Err(err) => o_err(user_data, ffi_error_code!(AppError::from(err)), req_id),
                }
            }
            IpcMsg::Revoked { .. } => o_revoked(user_data),
            _ => {
                return Err(IpcError::InvalidMsg.into());
            }
        }

        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use ffi_utils::{FfiString, ffi_string_free};
    use rand;
    use rust_sodium::crypto::{box_, secretbox, sign};
    use safe_core::ipc::{self, AccessContInfo, AppExchangeInfo, AppKeys, AuthGranted, AuthReq,
                         Config, ContainersReq, IpcMsg, IpcReq, IpcResp};
    use safe_core::ipc::req::ffi::Permission;
    use safe_core::ipc::resp::ffi::AuthGranted as FfiAuthGranted;
    use safe_core::utils;
    use std::collections::HashMap;
    use std::mem;
    use std::os::raw::c_void;
    use super::*;

    #[test]
    fn encode_auth_req_basics() {
        let req = AuthReq {
            app: gen_app_exchange_info(),
            app_container: false,
            containers: HashMap::new(),
        };

        let req_c = req.clone().into_repr_c();

        let mut req_id = 0u32;
        let mut output = FfiString::default();

        let error_code = unsafe { encode_auth_req(req_c, &mut req_id, &mut output) };
        assert_eq!(error_code, 0);

        // Decode it and verify it's the same we encoded.
        let encoded = unsafe {
            let s = unwrap!(output.to_string());
            ffi_string_free(output);
            s
        };

        assert!(encoded.starts_with("safe-auth:"));
        let msg = unwrap!(ipc::decode_msg(&encoded));

        let (decoded_req_id, decoded_req) = match msg {
            IpcMsg::Req { req_id, req: IpcReq::Auth(req) } => (req_id, req),
            x => panic!("Unexpected {:?}", x),
        };

        assert_eq!(decoded_req_id, req_id);
        assert_eq!(decoded_req, req);
    }

    #[test]
    fn encode_containers_req_basics() {
        let mut container_permissions = HashMap::new();
        let _ = container_permissions.insert(unwrap!(utils::generate_random_string(10)),
                                             btree_set![Permission::Read]);

        let req = ContainersReq {
            app: gen_app_exchange_info(),
            containers: container_permissions,
        };

        let req_c = req.clone().into_repr_c();

        let mut req_id = 0u32;
        let mut output = FfiString::default();

        let error_code = unsafe { encode_containers_req(req_c, &mut req_id, &mut output) };
        assert_eq!(error_code, 0);

        // Decode it and verify it's the same we encoded.
        let encoded = unsafe {
            let s = unwrap!(output.to_string());
            ffi_string_free(output);
            s
        };

        assert!(encoded.starts_with("safe-auth:"));
        let msg = unwrap!(ipc::decode_msg(&encoded));

        let (decoded_req_id, decoded_req) = match msg {
            IpcMsg::Req { req_id, req: IpcReq::Containers(req) } => (req_id, req),
            x => panic!("Unexpected {:?}", x),
        };

        assert_eq!(decoded_req_id, req_id);
        assert_eq!(decoded_req, req);
    }

    #[test]
    fn decode_ipc_msg_with_auth_granted() {
        let req_id = gen_req_id();

        let access_container = AccessContInfo {
            id: rand::random(),
            tag: rand::random(),
            nonce: secretbox::gen_nonce(),
        };

        let auth_granted = AuthGranted {
            app_keys: gen_app_keys(),
            bootstrap_config: Config,
            access_container: access_container,
        };

        let msg = IpcMsg::Resp {
            req_id: req_id,
            resp: IpcResp::Auth(Ok(auth_granted.clone())),
        };

        let encoded = unwrap!(ipc::encode_msg(&msg, "app-id"));
        let encoded = FfiString::from_str(&encoded);

        struct Context {
            unexpected_cb: bool,
            req_id: u32,
            auth_granted: FfiAuthGranted,
        };

        let context = unsafe {
            let mut context = Context {
                unexpected_cb: false,
                req_id: 0,
                auth_granted: mem::uninitialized(),
            };

            extern "C" fn auth_cb(ctx: *mut c_void, req_id: u32, auth_granted: FfiAuthGranted) {
                unsafe {
                    let ctx = ctx as *mut Context;
                    (*ctx).req_id = req_id;
                    (*ctx).auth_granted = auth_granted;
                }
            }

            extern "C" fn containers_cb(ctx: *mut c_void, _req_id: u32) {
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

            extern "C" fn err_cb(ctx: *mut c_void, _error_code: i32, _req_id: u32) {
                unsafe {
                    let ctx = ctx as *mut Context;
                    (*ctx).unexpected_cb = true;
                }
            }

            let context_ptr: *mut Context = &mut context;
            decode_ipc_msg(encoded,
                           context_ptr as *mut c_void,
                           auth_cb,
                           containers_cb,
                           revoked_cb,
                           err_cb);

            context
        };

        assert!(!context.unexpected_cb);
        assert_eq!(context.req_id, req_id);
        let decoded_auth_granted = unsafe { AuthGranted::from_repr_c(context.auth_granted) };
        assert_eq!(decoded_auth_granted, auth_granted);
    }

    #[test]
    fn decode_ipc_msg_with_containers_granted() {
        let req_id = gen_req_id();

        let msg = IpcMsg::Resp {
            req_id: req_id,
            resp: IpcResp::Containers(Ok(())),
        };

        let encoded = unwrap!(ipc::encode_msg(&msg, "app-id"));
        let encoded = FfiString::from_str(&encoded);

        struct Context {
            unexpected_cb: bool,
            req_id: u32,
        };

        let mut context = Context {
            unexpected_cb: false,
            req_id: 0,
        };

        unsafe {
            extern "C" fn auth_cb(ctx: *mut c_void, _req_id: u32, _auth_granted: FfiAuthGranted) {
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

            extern "C" fn revoked_cb(ctx: *mut c_void) {
                unsafe {
                    let ctx = ctx as *mut Context;
                    (*ctx).unexpected_cb = true;
                }
            }

            extern "C" fn err_cb(ctx: *mut c_void, _error_code: i32, _req_id: u32) {
                unsafe {
                    let ctx = ctx as *mut Context;
                    (*ctx).unexpected_cb = true;
                }
            }

            let context_ptr: *mut Context = &mut context;
            decode_ipc_msg(encoded,
                           context_ptr as *mut c_void,
                           auth_cb,
                           containers_cb,
                           revoked_cb,
                           err_cb);
        }

        assert!(!context.unexpected_cb);
        assert_eq!(context.req_id, req_id);
    }

    fn gen_app_keys() -> AppKeys {
        let (owner_key, _) = sign::gen_keypair();
        let enc_key = secretbox::gen_key();
        let (sign_pk, sign_sk) = sign::gen_keypair();
        let (enc_pk, enc_sk) = box_::gen_keypair();

        AppKeys {
            owner_key: owner_key,
            enc_key: enc_key,
            sign_pk: sign_pk,
            sign_sk: sign_sk,
            enc_pk: enc_pk,
            enc_sk: enc_sk,
        }
    }

    fn gen_app_exchange_info() -> AppExchangeInfo {
        AppExchangeInfo {
            id: unwrap!(utils::generate_random_string(10)),
            scope: None,
            name: unwrap!(utils::generate_random_string(10)),
            vendor: unwrap!(utils::generate_random_string(10)),
        }
    }
}
