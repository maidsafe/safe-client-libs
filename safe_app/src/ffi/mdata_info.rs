// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::errors::AppError;
use ffi_utils::{catch_unwind_cb, FfiResult, ReprC, SafePtr, FFI_RESULT_OK};
use maidsafe_utilities::serialisation::{deserialise, serialise};
use routing::XorName;
use rust_sodium::crypto::secretbox;
use safe_core::crypto::shared_secretbox;
use safe_core::ffi::arrays::{SymNonce, SymSecretKey, XorNameArray};
use safe_core::ffi::MDataInfo;
use safe_core::MDataInfo as NativeMDataInfo;
use std::os::raw::c_void;
use std::slice;

/// Create encrypted mdata info with explicit data name and a
/// provided private key.
#[no_mangle]
pub unsafe extern "C" fn mdata_info_new_private(
    name: *const XorNameArray,
    type_tag: u64,
    secret_key: *const SymSecretKey,
    nonce: *const SymNonce,
    user_data: *mut c_void,
    o_cb: extern "C" fn(
        user_data: *mut c_void,
        result: *const FfiResult,
        mdata_info: *const MDataInfo,
    ),
) {
    catch_unwind_cb(user_data, o_cb, || -> Result<_, AppError> {
        let name = XorName(*name);
        let sk = shared_secretbox::Key::from_raw(&*secret_key);
        let nonce = secretbox::Nonce(*nonce);

        let info = NativeMDataInfo::new_private(name, type_tag, (sk, nonce));
        let info = info.into_repr_c();

        o_cb(user_data, FFI_RESULT_OK, &info);
        Ok(())
    })
}

/// Create random, non-encrypted mdata info.
#[no_mangle]
pub unsafe extern "C" fn mdata_info_random_public(
    type_tag: u64,
    user_data: *mut c_void,
    o_cb: extern "C" fn(
        user_data: *mut c_void,
        result: *const FfiResult,
        mdata_info: *const MDataInfo,
    ),
) {
    catch_unwind_cb(user_data, o_cb, || -> Result<_, AppError> {
        let info = NativeMDataInfo::random_public(type_tag)?;
        let info = info.into_repr_c();

        o_cb(user_data, FFI_RESULT_OK, &info);
        Ok(())
    })
}

/// Create random, encrypted mdata info.
#[no_mangle]
pub unsafe extern "C" fn mdata_info_random_private(
    type_tag: u64,
    user_data: *mut c_void,
    o_cb: extern "C" fn(
        user_data: *mut c_void,
        result: *const FfiResult,
        mdata_info: *const MDataInfo,
    ),
) {
    catch_unwind_cb(user_data, o_cb, || -> Result<_, AppError> {
        let info = NativeMDataInfo::random_private(type_tag)?;
        let info = info.into_repr_c();

        o_cb(user_data, FFI_RESULT_OK, &info);
        Ok(())
    })
}

/// Encrypt mdata entry key using the corresponding mdata info.
#[no_mangle]
pub unsafe extern "C" fn mdata_info_encrypt_entry_key(
    info: *const MDataInfo,
    input: *const u8,
    input_len: usize,
    user_data: *mut c_void,
    o_cb: extern "C" fn(
        user_data: *mut c_void,
        result: *const FfiResult,
        enc_entry_key: *const u8,
        enc_entry_key_len: usize,
    ),
) {
    catch_unwind_cb(user_data, o_cb, || -> Result<_, AppError> {
        let info = NativeMDataInfo::clone_from_repr_c(info)?;
        let input = slice::from_raw_parts(input, input_len);
        let encoded = info.enc_entry_key(input).map_err(AppError::from)?;

        o_cb(
            user_data,
            FFI_RESULT_OK,
            encoded.as_safe_ptr(),
            encoded.len(),
        );
        Ok(())
    })
}

/// Encrypt mdata entry value using the corresponding mdata info.
#[no_mangle]
pub unsafe extern "C" fn mdata_info_encrypt_entry_value(
    info: *const MDataInfo,
    input: *const u8,
    input_len: usize,
    user_data: *mut c_void,
    o_cb: extern "C" fn(
        user_data: *mut c_void,
        result: *const FfiResult,
        enc_entry_value: *const u8,
        enc_entry_value_len: usize,
    ),
) {
    catch_unwind_cb(user_data, o_cb, || -> Result<_, AppError> {
        let info = NativeMDataInfo::clone_from_repr_c(info)?;
        let input = slice::from_raw_parts(input, input_len);
        let encoded = info.enc_entry_value(input).map_err(AppError::from)?;

        o_cb(
            user_data,
            FFI_RESULT_OK,
            encoded.as_safe_ptr(),
            encoded.len(),
        );
        Ok(())
    })
}

/// Decrypt mdata entry value or a key using the corresponding mdata info.
#[no_mangle]
pub unsafe extern "C" fn mdata_info_decrypt(
    info: *const MDataInfo,
    input: *const u8,
    input_len: usize,
    user_data: *mut c_void,
    o_cb: extern "C" fn(
        user_data: *mut c_void,
        result: *const FfiResult,
        mdata_info_decrypt: *const u8,
        mdata_info_decrypt_len: usize,
    ),
) {
    catch_unwind_cb(user_data, o_cb, || -> Result<_, AppError> {
        let info = NativeMDataInfo::clone_from_repr_c(info)?;
        let encoded = slice::from_raw_parts(input, input_len);
        let decoded = info.decrypt(encoded).map_err(AppError::from)?;

        o_cb(
            user_data,
            FFI_RESULT_OK,
            decoded.as_safe_ptr(),
            decoded.len(),
        );
        Ok(())
    })
}

/// Serialise `MDataInfo`.
#[no_mangle]
pub unsafe extern "C" fn mdata_info_serialise(
    info: *const MDataInfo,
    user_data: *mut c_void,
    o_cb: extern "C" fn(
        user_data: *mut c_void,
        result: *const FfiResult,
        encoded: *const u8,
        encoded_len: usize,
    ),
) {
    catch_unwind_cb(user_data, o_cb, || -> Result<_, AppError> {
        let info = NativeMDataInfo::clone_from_repr_c(info)?;
        let encoded = serialise(&info).map_err(AppError::from)?;

        o_cb(
            user_data,
            FFI_RESULT_OK,
            encoded.as_safe_ptr(),
            encoded.len(),
        );
        Ok(())
    })
}

/// Deserialise `MDataInfo`.
#[no_mangle]
pub unsafe extern "C" fn mdata_info_deserialise(
    encoded_ptr: *const u8,
    encoded_len: usize,
    user_data: *mut c_void,
    o_cb: extern "C" fn(
        user_data: *mut c_void,
        result: *const FfiResult,
        mdata_info: *const MDataInfo,
    ),
) {
    catch_unwind_cb(user_data, o_cb, || -> Result<_, AppError> {
        let encoded = slice::from_raw_parts(encoded_ptr, encoded_len);
        let info: NativeMDataInfo = deserialise(encoded)?;
        let info = info.into_repr_c();

        o_cb(user_data, FFI_RESULT_OK, &info);
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ffi_utils::test_utils::{call_1, call_vec_u8};
    use rand;
    use routing::XOR_NAME_LEN;
    use rust_sodium::crypto::secretbox;
    use safe_core::crypto::shared_secretbox;
    use safe_core::MDataInfo;

    // Test creating non-encrypted mdata info.
    #[test]
    fn create_public() {
        let type_tag: u64 = rand::random();

        let info: MDataInfo =
            unsafe { unwrap!(call_1(|ud, cb| mdata_info_random_public(type_tag, ud, cb))) };

        assert_eq!(info.type_tag, type_tag);
        assert!(info.enc_info.is_none());
    }

    // Test creating encrypted mdata info.
    #[test]
    fn create_private() {
        let type_tag: u64 = rand::random();

        let rand_info: MDataInfo =
            unsafe { unwrap!(call_1(|ud, cb| mdata_info_random_private(type_tag, ud, cb))) };

        let key = shared_secretbox::gen_key();
        let nonce = secretbox::gen_nonce();
        let new_info: MDataInfo = unsafe {
            unwrap!(call_1(|ud, cb| mdata_info_new_private(
                &[2; XOR_NAME_LEN],
                type_tag,
                &key.0,
                &nonce.0,
                ud,
                cb
            )))
        };

        assert_eq!(rand_info.type_tag, type_tag);
        assert!(rand_info.enc_info.is_some());

        assert_eq!(new_info.type_tag, type_tag);
        match new_info.enc_info {
            Some((ref got_key, ref got_nonce)) => {
                assert_eq!(*got_key, key);
                assert_eq!(*got_nonce, nonce);
            }
            None => panic!("Unexpected result: no enc_info in private MDataInfo"),
        }
    }

    // Test serialising and deserialising mdata_info.
    #[test]
    fn serialise_deserialise() {
        let info1 = unwrap!(MDataInfo::random_private(1000));
        let info1_ffi = info1.clone().into_repr_c();

        let encoded = unsafe {
            unwrap!(call_vec_u8(|ud, cb| mdata_info_serialise(
                &info1_ffi, ud, cb
            ),))
        };

        let info2 = unsafe {
            let res =
                call_1(|ud, cb| mdata_info_deserialise(encoded.as_ptr(), encoded.len(), ud, cb));

            unwrap!(res)
        };

        assert_eq!(info1, info2);
    }
}
