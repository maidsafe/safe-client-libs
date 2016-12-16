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

use App;
use ffi::helper::send_sync;
use ffi_utils::{catch_unwind_cb, u8_vec_to_ptr};
use object_cache::MDataInfoHandle;
use routing::XOR_NAME_LEN;
use safe_core::MDataInfo;
use std::os::raw::c_void;
use std::slice;

/// Create random, non-encrypted mdata info.
#[no_mangle]
pub unsafe extern "C" fn mdata_info_random_public(app: *const App,
                                                  type_tag: u64,
                                                  user_data: *mut c_void,
                                                  o_cb: extern "C" fn(*mut c_void,
                                                                      i32,
                                                                      MDataInfoHandle)) {
    catch_unwind_cb(user_data, o_cb, || {
        send_sync(app, user_data, o_cb, move |context| {
            let info = MDataInfo::random_public(type_tag)?;
            Ok(context.object_cache().insert_mdata_info(info))
        })
    })
}

/// Create random, encrypted mdata info.
#[no_mangle]
pub unsafe extern "C" fn mdata_info_random_private(app: *const App,
                                                   type_tag: u64,
                                                   user_data: *mut c_void,
                                                   o_cb: extern "C" fn(*mut c_void,
                                                                       i32,
                                                                       MDataInfoHandle)) {
    catch_unwind_cb(user_data, o_cb, || {
        send_sync(app, user_data, o_cb, move |context| {
            let info = MDataInfo::random_private(type_tag)?;
            Ok(context.object_cache().insert_mdata_info(info))
        })
    })
}

/// Encrypt mdata entry key using the corresponding mdata info.
#[no_mangle]
pub unsafe extern "C" fn mdata_info_encrypt_entry_key(app: *const App,
                                                      info_h: MDataInfoHandle,
                                                      input_ptr: *const u8,
                                                      input_len: usize,
                                                      user_data: *mut c_void,
                                                      o_cb: extern "C" fn(*mut c_void,
                                                                          i32,
                                                                          *mut u8,
                                                                          usize,
                                                                          usize)) {
    catch_unwind_cb(user_data, o_cb, || {
        let input = slice::from_raw_parts(input_ptr, input_len).to_vec();

        send_sync(app, user_data, o_cb, move |context| {
            let info = context.object_cache().get_mdata_info(info_h)?;
            let output = info.enc_entry_key(&input)?;
            Ok(u8_vec_to_ptr(output))
        })
    })
}

/// Encrypt mdata entry value using the corresponding mdata info.
#[no_mangle]
pub unsafe extern "C" fn mdata_info_encrypt_entry_value(app: *const App,
                                                        info_h: MDataInfoHandle,
                                                        input_ptr: *const u8,
                                                        input_len: usize,
                                                        user_data: *mut c_void,
                                                        o_cb: extern "C" fn(*mut c_void,
                                                                            i32,
                                                                            *mut u8,
                                                                            usize,
                                                                            usize)) {
    catch_unwind_cb(user_data, o_cb, || {
        let input = slice::from_raw_parts(input_ptr, input_len).to_vec();

        send_sync(app, user_data, o_cb, move |context| {
            let info = context.object_cache().get_mdata_info(info_h)?;
            let output = info.enc_entry_value(&input)?;
            Ok(u8_vec_to_ptr(output))
        })
    })
}

/// Extract name and type tag from the mdata info.
#[no_mangle]
pub unsafe extern "C"
fn mdata_info_extract_name_and_type_tag(app: *const App,
                                        info_h: MDataInfoHandle,
                                        user_data: *mut c_void,
                                        o_cb: extern "C" fn(*mut c_void,
                                                            i32,
                                                            [u8; XOR_NAME_LEN],
                                                            u64)) {
    catch_unwind_cb(user_data, o_cb, || {
        send_sync(app, user_data, o_cb, move |context| {
            let info = context.object_cache().get_mdata_info(info_h)?;
            Ok((info.name.0, info.type_tag))
        })
    })
}

#[cfg(test)]
mod tests {
    use ffi_utils::test_utils::call_1;
    use rand;
    use super::*;
    use test_utils::{create_app, run_now};

    #[test]
    fn create_public() {
        let app = create_app();
        let type_tag: u64 = rand::random();

        let info_h =
            unsafe { unwrap!(call_1(|ud, cb| mdata_info_random_public(&app, type_tag, ud, cb))) };

        run_now(&app, move |_, context| {
            let info = unwrap!(context.object_cache().get_mdata_info(info_h));
            assert_eq!(info.type_tag, type_tag);
            assert!(info.enc_info.is_none());
        })
    }
}
