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
use errors::AppError;
use ffi::helper::send_sync;
//use ffi_utils::{OpaqueCtx, catch_unwind_cb};

use maidsafe_utilities::serialisation::{deserialise, serialise};
//use object_cache::MDataInfoHandle;
use routing::{XOR_NAME_LEN, XorName};
//use safe_core::{CoreError, MDataInfo};
use routing::MutableData;
use std::os::raw::c_void;
use std::slice;

use ffi::helper::send_with_mdata_info;
use ffi_utils::{OpaqueCtx, catch_unwind_cb, vec_clone_from_raw_parts};
use futures::Future;
use object_cache::{MDataEntriesHandle, MDataEntryActionsHandle, MDataInfoHandle, MDataKeysHandle,
                   MDataPermissionSetHandle, MDataPermissionsHandle, MDataValuesHandle,
                   SignKeyHandle};
use safe_core::{CoreError, FutureExt, mdata_info, MDataInfo};
use std::ptr;


/// Create non-encrypted mdata info with explicit data name.
#[no_mangle]
pub unsafe extern "C" fn mdata_create_pub_mutable_data(app: *const App,
                                                       name: *const [u8; XOR_NAME_LEN],
                                                       type_tag: u64,
                                                       //entries: TODO define the structure to share the entries list
                                                       user_data: *mut c_void,
                                                       o_cb: extern "C" fn(*mut c_void,
                                                                           i32,
                                                                           MDataInfoHandle)) {
    catch_unwind_cb(user_data, o_cb, || {
        let name = XorName(*name);
        send_sync(app, user_data, o_cb, move |client, context| {
            let info_h = MDataInfo::new_public(name, type_tag);
            let md = context.object_cache().insert_mdata_info(info_h);

            let key = client.public_signing_key()?;
            let sign_key = context.object_cache().insert_sign_key(key);
            println!("ASA {}", sign_key);

            //let owner_key = try_cb!(client.owner_key().map_err(AppError::from), user_data, o_cb);

            let permissions = Default::default();

            let entries = Default::default();

            let data = try_cb!(MutableData::new(name,
                                                type_tag,
                                                permissions,
                                                entries,
                                                btree_set![key])
                                   .map_err(CoreError::from)
                                   .map_err(AppError::from),
                               user_data,
                               o_cb);

            client.put_mdata(data)
                .map_err(AppError::from)
                .then(move |result| {
                    o_cb(user_data.0, ffi_result_code!(result), md);
                    Ok(())
                })
                .into_box()
                .into()
        })

    })
}

/// Create non-encrypted mdata info with explicit data name.
#[no_mangle]
pub unsafe extern "C" fn mdata_info_new_public(app: *const App,
                                               name: *const [u8; XOR_NAME_LEN],
                                               type_tag: u64,
                                               user_data: *mut c_void,
                                               o_cb: extern "C" fn(*mut c_void,
                                                                   i32,
                                                                   MDataInfoHandle)) {
    catch_unwind_cb(user_data, o_cb, || {
        let name = XorName(*name);

        send_sync(app, user_data, o_cb, move |_, context| {
            let info = MDataInfo::new_public(name, type_tag);
            Ok(context.object_cache().insert_mdata_info(info))
        })
    })
}

/// Create encrypted mdata info with explicit data name.
#[no_mangle]
pub unsafe extern "C" fn mdata_info_new_private(app: *const App,
                                                name: *const [u8; XOR_NAME_LEN],
                                                type_tag: u64,
                                                user_data: *mut c_void,
                                                o_cb: extern "C" fn(*mut c_void,
                                                                    i32,
                                                                    MDataInfoHandle)) {
    catch_unwind_cb(user_data, o_cb, || {
        let name = XorName(*name);

        send_sync(app, user_data, o_cb, move |_, context| {
            let info = MDataInfo::new_private(name, type_tag);
            Ok(context.object_cache().insert_mdata_info(info))
        })
    })
}

/// Create random, non-encrypted mdata info.
#[no_mangle]
pub unsafe extern "C" fn mdata_info_random_public(app: *const App,
                                                  type_tag: u64,
                                                  user_data: *mut c_void,
                                                  o_cb: extern "C" fn(*mut c_void,
                                                                      i32,
                                                                      MDataInfoHandle)) {
    catch_unwind_cb(user_data, o_cb, || {
        send_sync(app, user_data, o_cb, move |_, context| {
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
        send_sync(app, user_data, o_cb, move |_, context| {
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
                                                                          *const u8,
                                                                          usize)) {
    catch_unwind_cb(user_data, o_cb, || {
        let user_data = OpaqueCtx(user_data);
        let input = slice::from_raw_parts(input_ptr, input_len).to_vec();

        (*app).send(move |_, context| {
            let info = try_cb!(context.object_cache().get_mdata_info(info_h),
                               user_data,
                               o_cb);
            let vec = try_cb!(info.enc_entry_key(&input).map_err(AppError::from),
                              user_data,
                              o_cb);

            o_cb(user_data.0, 0, vec.as_ptr(), vec.len());

            None
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
                                                                            *const u8,
                                                                            usize)) {
    catch_unwind_cb(user_data, o_cb, || {
        let user_data = OpaqueCtx(user_data);
        let input = slice::from_raw_parts(input_ptr, input_len).to_vec();

        (*app).send(move |_, context| {
            let info = try_cb!(context.object_cache().get_mdata_info(info_h),
                               user_data,
                               o_cb);
            let vec = try_cb!(info.enc_entry_value(&input).map_err(AppError::from),
                              user_data,
                              o_cb);

            o_cb(user_data.0, 0, vec.as_ptr(), vec.len());

            None
        })
    })
}

/// Extract name and type tag from the mdata info.
#[no_mangle]
pub unsafe extern "C" fn mdata_info_extract_name_and_type_tag(app: *const App,
                                                              info_h: MDataInfoHandle,
                                                              user_data: *mut c_void,
                                                              o_cb: extern "C" fn(*mut c_void,
                                                                                  i32,
                                                                                  *const [u8;
                                                                                   XOR_NAME_LEN],
                                                                                  u64)) {
    catch_unwind_cb(user_data, o_cb, || {
        send_sync(app, user_data, o_cb, move |_, context| {
            let info = context.object_cache().get_mdata_info(info_h)?;
            Ok((&info.name.0, info.type_tag))
        })
    })
}

/// Serialise `MDataInfo`.
#[no_mangle]
pub unsafe extern "C" fn mdata_info_serialise(app: *const App,
                                              info_h: MDataInfoHandle,
                                              user_data: *mut c_void,
                                              o_cb: extern "C" fn(*mut c_void,
                                                                  i32,
                                                                  *const u8,
                                                                  usize)) {
    catch_unwind_cb(user_data, o_cb, || {
        let user_data = OpaqueCtx(user_data);

        (*app).send(move |_, context| {
            let info = try_cb!(context.object_cache().get_mdata_info(info_h),
                               user_data,
                               o_cb);
            let encoded = try_cb!(serialise(&*info).map_err(AppError::from), user_data, o_cb);

            o_cb(user_data.0, 0, encoded.as_ptr(), encoded.len());
            None
        })
    })
}

/// Deserialise `MDataInfo`.
#[no_mangle]
pub unsafe extern "C" fn mdata_info_deserialise(app: *const App,
                                                ptr: *const u8,
                                                len: usize,
                                                user_data: *mut c_void,
                                                o_cb: extern "C" fn(*mut c_void,
                                                                    i32,
                                                                    MDataInfoHandle)) {
    catch_unwind_cb(user_data, o_cb, || {
        let encoded = slice::from_raw_parts(ptr, len).to_vec();

        send_sync(app, user_data, o_cb, move |_, context| {
            let info = deserialise(&encoded)?;
            Ok(context.object_cache().insert_mdata_info(info))
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ffi_utils::test_utils::{call_1, call_vec_u8};
    use rand;
    use safe_core::MDataInfo;
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

    #[test]
    fn serialise_deserialise() {
        let app = create_app();
        let info1 = unwrap!(MDataInfo::random_private(1000));

        let info1_h = {
            let info = info1.clone();
            run_now(&app,
                    move |_, context| context.object_cache().insert_mdata_info(info))
        };

        let encoded =
            unsafe { unwrap!(call_vec_u8(|ud, cb| mdata_info_serialise(&app, info1_h, ud, cb))) };

        let info2_h = unsafe {
            let res = call_1(|ud, cb| {
                mdata_info_deserialise(&app, encoded.as_ptr(), encoded.len(), ud, cb)
            });

            unwrap!(res)
        };

        let info2 = run_now(&app, move |_, context| {
            unwrap!(context.object_cache().remove_mdata_info(info2_h))
        });

        assert_eq!(info1, info2);
    }
}
