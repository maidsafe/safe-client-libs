use ffi_utils::test_utils::{send_via_user_data, sender_as_user_data};
use ffi_utils::{vec_clone_from_raw_parts, FfiResult, ReprC};
use log::error;
use safe_authenticator::Authenticator;
use safe_core::core_structs::UserMetadata;
use safe_core::ffi::ipc::req::{
    AuthReq as FfiAuthReq, ContainersReq as FfiContainersReq, ShareMDataRequest as FfiShareMDataReq,
};
use safe_core::ffi::ipc::resp::MetadataResponse as FfiUserMetadata;
use safe_core::ipc::{self, AuthReq, ContainersReq, IpcMsg, IpcReq, ShareMDataReq};
use safe_nd::XorName;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_void};
use std::slice;
use std::sync::mpsc;
use std::time::Duration;
use unwrap::unwrap;

/// Payload.
#[derive(Debug)]
pub enum Payload {
    /// Metadata.
    Metadata(Vec<(Option<UserMetadata>, XorName, u64)>),
}

/// Channel type.
pub type ChannelType = Result<(IpcMsg, Option<Payload>), (i32, Option<IpcMsg>)>;

// TODO: There should be a public function with a signature like this, and the
//       FFI function `ipc::decode_ipc_msg` should be only wrapper over it.
/// Helper to decode IpcMsg.
pub fn auth_decode_ipc_msg_helper(authenticator: &Authenticator, msg: &str) -> ChannelType {
    let (tx, rx) = mpsc::channel::<ChannelType>();

    extern "C" fn auth_cb(user_data: *mut c_void, req_id: u32, req: *const FfiAuthReq) {
        unsafe {
            let req = match AuthReq::clone_from_repr_c(req) {
                Ok(req) => req,
                Err(_) => return send_via_user_data::<ChannelType>(user_data, Err((-2, None))),
            };

            let msg = IpcMsg::Req {
                req_id,
                request: IpcReq::Auth(req),
            };

            send_via_user_data::<ChannelType>(user_data, Ok((msg, None)))
        }
    }

    extern "C" fn containers_cb(user_data: *mut c_void, req_id: u32, req: *const FfiContainersReq) {
        unsafe {
            let req = match ContainersReq::clone_from_repr_c(req) {
                Ok(req) => req,
                Err(_) => return send_via_user_data::<ChannelType>(user_data, Err((-2, None))),
            };

            let msg = IpcMsg::Req {
                req_id,
                request: IpcReq::Containers(req),
            };

            send_via_user_data::<ChannelType>(user_data, Ok((msg, None)))
        }
    }

    extern "C" fn share_mdata_cb(
        user_data: *mut c_void,
        req_id: u32,
        req: *const FfiShareMDataReq,
        ffi_metadata: *const FfiUserMetadata,
        ffi_metadata_len: usize,
    ) {
        unsafe {
            let req = match ShareMDataReq::clone_from_repr_c(req) {
                Ok(req) => req,
                Err(_) => return send_via_user_data::<ChannelType>(user_data, Err((-2, None))),
            };

            let metadatas: Vec<_> = slice::from_raw_parts(ffi_metadata, ffi_metadata_len)
                .iter()
                .map(|ffi_metadata| {
                    (
                        if ffi_metadata.name.is_null() {
                            None
                        } else {
                            Some(unwrap!(UserMetadata::clone_from_repr_c(ffi_metadata)))
                        },
                        XorName(ffi_metadata.xor_name),
                        ffi_metadata.type_tag,
                    )
                })
                .collect();

            let msg = IpcMsg::Req {
                req_id,
                request: IpcReq::ShareMData(req),
            };

            send_via_user_data::<ChannelType>(
                user_data,
                Ok((msg, Some(Payload::Metadata(metadatas)))),
            )
        }
    }

    let ffi_msg = unwrap!(CString::new(msg));
    let mut ud = Default::default();

    unsafe {
        crate::ffi::ipc::auth_decode_ipc_msg(
            authenticator,
            ffi_msg.as_ptr(),
            sender_as_user_data(&tx, &mut ud),
            auth_cb,
            containers_cb,
            unregistered_cb,
            share_mdata_cb,
            err_cb,
        );
    };

    let ret = match rx.recv_timeout(Duration::from_secs(30)) {
        Ok(r) => r,
        Err(e) => {
            error!("auth_decode_ipc_msg_helper: {:?}", e);
            Err((-1, None))
        }
    };
    drop(tx);
    ret
}

/// Unregistered callback.
pub extern "C" fn unregistered_cb(
    user_data: *mut c_void,
    req_id: u32,
    extra_data: *const u8,
    extra_data_len: usize,
) {
    unsafe {
        let msg = IpcMsg::Req {
            req_id,
            request: IpcReq::Unregistered(vec_clone_from_raw_parts(extra_data, extra_data_len)),
        };

        send_via_user_data::<ChannelType>(user_data, Ok((msg, None)))
    }
}

/// Error callback.
pub extern "C" fn err_cb(user_data: *mut c_void, res: *const FfiResult, response: *const c_char) {
    unsafe {
        let ipc_resp = if response.is_null() {
            None
        } else {
            let response = CStr::from_ptr(response);
            match ipc::decode_msg(unwrap!(response.to_str())) {
                Ok(ipc_resp) => Some(ipc_resp),
                Err(_) => None,
            }
        };

        send_via_user_data::<ChannelType>(user_data, Err(((*res).error_code, ipc_resp)))
    }
}
