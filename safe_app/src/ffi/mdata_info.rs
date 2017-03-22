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
#![allow(unused_variables)]
use App;
use errors::AppError;
use ffi::helper::send_sync;
//use ffi_utils::{OpaqueCtx, catch_unwind_cb};

use maidsafe_utilities::serialisation::{deserialise, serialise};
//use object_cache::MDataInfoHandle;
use routing::{XOR_NAME_LEN, XorName};
//use safe_core::{CoreError, MDataInfo};
use std::os::raw::c_void;
use std::slice;

use ffi_utils::{OpaqueCtx, catch_unwind_cb, vec_clone_from_raw_parts};
use futures::Future;
use routing::{Action, EntryAction, Value, MutableData, PermissionSet, User};
use object_cache::MDataInfoHandle;
use safe_core::{mdata_info, MDataInfo, FutureExt, CoreError};
use std::collections::BTreeMap;

/// Create non-encrypted mdata with explicit data name and default permissions.
#[no_mangle]
pub unsafe extern "C" fn mdata_create_pub_mutable_data(app: *const App,
                                                       name: *const [u8; XOR_NAME_LEN],
                                                       type_tag: u64,
                                                       user_data: *mut c_void,
                                                       o_cb: extern "C" fn(*mut c_void,
                                                                           i32,
                                                                           MDataInfoHandle)) {
    catch_unwind_cb(user_data, o_cb, || {
        let name = XorName(*name);
        let user_data = OpaqueCtx(user_data);

        (*app).send(move |client, context| {
            let info = MDataInfo::new_public(name, type_tag);
            let info_h = context.object_cache().insert_mdata_info(info.clone());

            let owner_key = try_cb!(client.owner_key().map_err(AppError::from), user_data, o_cb);

            let entries = Default::default();

            let mut perm_set = PermissionSet::new();
            perm_set = perm_set.allow(Action::Insert);
            perm_set = perm_set.allow(Action::Update);
            perm_set = perm_set.allow(Action::Delete);
            perm_set = perm_set.allow(Action::ManagePermissions);

            let user_key = client.public_signing_key().unwrap();

            let mut output = BTreeMap::new();
            let _ = output.insert(User::Key(user_key), perm_set);

            let data = try_cb!(MutableData::new(info.name,
                                                info.type_tag,
                                                output,
                                                entries,
                                                btree_set![owner_key])
                       .map_err(CoreError::from)
                       .map_err(AppError::from),
                                   user_data,
                                   o_cb);

            client.put_mdata(data)
                .map_err(AppError::from)
                .then(move |result| {
                    o_cb(user_data.0, ffi_result_code!(result), info_h);
                    Ok(())
                })
                .into_box()
                .into()
        })
    })
}

/// Insert an entry to the MutableData and send the tx to the network.
#[no_mangle]
pub unsafe extern "C" fn mdata_insert_entry(app: *const App,
                                              info_h: MDataInfoHandle,
                                              key_ptr: *const u8,
                                              key_len: usize,
                                              value_ptr: *const u8,
                                              value_len: usize,
                                              user_data: *mut c_void,
                                              o_cb: extern "C" fn(*mut c_void, i32)) {

    catch_unwind_cb(user_data, o_cb, || {
        let mut actions: BTreeMap<Vec<u8>, EntryAction> = Default::default();
        let key = vec_clone_from_raw_parts(key_ptr, key_len);
        let value = vec_clone_from_raw_parts(value_ptr, value_len);
        let action = EntryAction::Ins(Value {
              content: value,
              entry_version: 0,
        });
        let _ = actions.insert(key, action);


        let user_data = OpaqueCtx(user_data);

        (*app).send(move |client, context| {
            let info = try_cb!(context.object_cache().get_mdata_info(info_h),
                               user_data,
                               o_cb);
            let actions = try_cb!(mdata_info::encrypt_entry_actions(&info, &actions).map_err(AppError::from),
                        user_data,
                        o_cb);

            client.mutate_mdata_entries(info.name, info.type_tag, actions)
                .map_err(AppError::from)
                .then(move |result| {
                    o_cb(user_data.0, ffi_result_code!(result));
                    Ok(())
                })
                .into_box()
                .into()
        })
    })
}

/// Update an entry of the MutableData and send the tx to the network.
#[no_mangle]
pub unsafe extern "C" fn mdata_update_entry(app: *const App,
                                              info_h: MDataInfoHandle,
                                              key_ptr: *const u8,
                                              key_len: usize,
                                              value_ptr: *const u8,
                                              value_len: usize,
                                              user_data: *mut c_void,
                                              o_cb: extern "C" fn(*mut c_void, i32)) {

    catch_unwind_cb(user_data, o_cb, || {
        let mut actions: BTreeMap<Vec<u8>, EntryAction> = Default::default();
        let key = vec_clone_from_raw_parts(key_ptr, key_len);
        let value = vec_clone_from_raw_parts(value_ptr, value_len);
        let action = EntryAction::Update(Value {
              content: value,
              entry_version: 1, // FIXME: we need to fetch current version and add 1 to it
        });
        let _ = actions.insert(key, action);

        let user_data = OpaqueCtx(user_data);

        (*app).send(move |client, context| {
            let info = try_cb!(context.object_cache().get_mdata_info(info_h),
                               user_data,
                               o_cb);
            let actions = try_cb!(mdata_info::encrypt_entry_actions(&info, &actions).map_err(AppError::from),
                        user_data,
                        o_cb);

            client.mutate_mdata_entries(info.name, info.type_tag, actions)
                .map_err(AppError::from)
                .then(move |result| {
                    o_cb(user_data.0, ffi_result_code!(result));
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
u64)){
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
