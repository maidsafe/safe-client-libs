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

#[cfg(test)]
mod tests;

use core::{CLIENT_STRUCTURED_DATA_TAG, CoreError};
use core::futures::FutureExt;
use core::structured_data::{self, unversioned, versioned};
use ffi::{AppHandle, CipherOptHandle, DataIdHandle, StructDataHandle};
use ffi::{FfiError, OpaqueCtx, Session, helper};
use futures::{self, Future};
use routing::{Data, StructuredData, XOR_NAME_LEN, XorName};
use std::{ptr, slice};
use std::os::raw::c_void;
use super::cipher_opt::CipherOpt;

/// Create new StructuredData
#[no_mangle]
pub unsafe extern "C" fn struct_data_new(session: *const Session,
                                         app_h: AppHandle,
                                         type_tag: u64,
                                         id: *const [u8; XOR_NAME_LEN],
                                         version: u64,
                                         cipher_opt_h: CipherOptHandle,
                                         data: *const u8,
                                         data_len: usize,
                                         user_data: *mut c_void,
                                         o_cb: unsafe extern "C" fn(*mut c_void,
                                                                    i32,
                                                                    StructDataHandle)) {
    helper::catch_unwind_cb(user_data, o_cb, || {
        let id = XorName(*id);
        let data = slice::from_raw_parts(data, data_len);
        let user_data = OpaqueCtx(user_data);

        (*session).send(move |client, object_cache| {
            let (sign_pk, sign_sk) = try_cb!(client.signing_keypair(), user_data, o_cb);

            let encrypted_data = {
                let app = try_cb!(object_cache.get_app(app_h), user_data, o_cb);
                let cipher_opt =
                    try_cb!(object_cache.get_cipher_opt(cipher_opt_h), user_data, o_cb);

                try_cb!(cipher_opt.encrypt(&*app, data), user_data.0, o_cb)
            };

            let object_cache = object_cache.clone();

            let fut = match type_tag {
                ::UNVERSIONED_STRUCT_DATA_TYPE_TAG => {
                    unversioned::create(client,
                                        type_tag,
                                        id,
                                        version,
                                        encrypted_data,
                                        vec![sign_pk],
                                        vec![],
                                        sign_sk,
                                        None)
                }
                ::VERSIONED_STRUCT_DATA_TYPE_TAG => {
                    versioned::create(client,
                                      type_tag,
                                      id,
                                      encrypted_data,
                                      vec![sign_pk],
                                      sign_sk,
                                      None)
                }
                x if x >= CLIENT_STRUCTURED_DATA_TAG => {
                    futures::done(StructuredData::new(type_tag,
                                                      id,
                                                      version,
                                                      encrypted_data,
                                                      vec![sign_pk],
                                                      vec![],
                                                      Some(&sign_sk)))
                        .map_err(CoreError::from)
                        .into_box()
                }
                _ => err!(CoreError::InvalidStructuredDataTypeTag),
            };

            fut.map(move |data| {
                    let handle = object_cache.insert_sd(data);
                    o_cb(user_data.0, 0, handle);
                })
                .map_err(move |err| {
                    let err = FfiError::from(err);
                    o_cb(user_data.0, ffi_error_code!(err), 0);
                })
                .into_box()
                .into()
        })
    })
}

/// Fetch an existing StructuredData from Network.
#[no_mangle]
pub unsafe extern "C" fn struct_data_fetch(session: *const Session,
                                           data_id_h: DataIdHandle,
                                           user_data: *mut c_void,
                                           o_cb: unsafe extern "C" fn(*mut c_void,
                                                                      i32,
                                                                      StructDataHandle)) {
    helper::catch_unwind_cb(user_data, o_cb, || {
        let user_data = OpaqueCtx(user_data);

        (*session).send(move |client, object_cache| {
            let object_cache = object_cache.clone();
            let data_id = *try_cb!(object_cache.get_data_id(data_id_h), user_data.0, o_cb);

            client.get(data_id, None)
                .and_then(|data| match data {
                    Data::Structured(data) => Ok(data),
                    _ => Err(CoreError::ReceivedUnexpectedData),
                })
                .map(move |data| {
                    let handle = object_cache.insert_sd(data);
                    o_cb(user_data.0, 0, handle);
                })
                .map_err(move |err| {
                    let err = FfiError::from(err);
                    o_cb(user_data.0, ffi_error_code!(err), 0);
                })
                .into_box()
                .into()
        })
    })
}

/// Extract DataIdentifier from StructuredData.
#[no_mangle]
pub unsafe extern "C" fn struct_data_extract_data_id(session: *const Session,
                                                     sd_h: StructDataHandle,
                                                     user_data: *mut c_void,
                                                     o_cb: unsafe extern "C" fn(*mut c_void,
                                                                                i32,
                                                                                DataIdHandle)) {
    helper::catch_unwind_cb(user_data, o_cb, || {
        let user_data = OpaqueCtx(user_data);

        (*session).send(move |_, object_cache| {
            let data_id = {
                let data = try_cb!(object_cache.get_sd(sd_h), user_data.0, o_cb);
                data.identifier()
            };

            let handle = object_cache.insert_data_id(data_id);
            o_cb(user_data.0, 0, handle);
            None
        })
    })
}


/// Put new data into StructuredData.
#[no_mangle]
pub unsafe extern "C" fn struct_data_update(session: *const Session,
                                            app_h: AppHandle,
                                            sd_h: StructDataHandle,
                                            cipher_opt_h: CipherOptHandle,
                                            data: *const u8,
                                            data_len: usize,
                                            user_data: *mut c_void,
                                            o_cb: unsafe extern "C" fn(*mut c_void, i32)) {
    helper::catch_unwind_cb(user_data, o_cb, || {
        let data = slice::from_raw_parts(data, data_len);
        let user_data = OpaqueCtx(user_data);

        (*session).send(move |client, object_cache| {
            let sign_sk = try_cb!(client.secret_signing_key(), user_data.0, o_cb);

            let encrypted_data = {
                let app = try_cb!(object_cache.get_app(app_h), user_data.0, o_cb);
                let cipher_opt =
                    try_cb!(object_cache.get_cipher_opt(cipher_opt_h), user_data.0, o_cb);
                try_cb!(cipher_opt.encrypt(&*app, data), user_data.0, o_cb)
            };

            let old_sd = try_cb!(object_cache.remove_sd(sd_h), user_data.0, o_cb);

            let object_cache = object_cache.clone();

            let fut = match old_sd.get_type_tag() {
                ::UNVERSIONED_STRUCT_DATA_TYPE_TAG => {
                    unversioned::create(client,
                                        old_sd.get_type_tag(),
                                        *old_sd.name(),
                                        old_sd.get_version() + 1,
                                        encrypted_data,
                                        old_sd.get_owner_keys().clone(),
                                        old_sd.get_previous_owner_keys().clone(),
                                        sign_sk,
                                        None)
                }
                ::VERSIONED_STRUCT_DATA_TYPE_TAG => {
                    let owner_keys = old_sd.get_owner_keys().clone();
                    versioned::update(client, old_sd, encrypted_data, owner_keys, sign_sk, None)
                }
                x if x >= CLIENT_STRUCTURED_DATA_TAG => {
                    futures::done(StructuredData::new(old_sd.get_type_tag(),
                                                      *old_sd.name(),
                                                      old_sd.get_version() + 1,
                                                      encrypted_data,
                                                      old_sd.get_owner_keys().clone(),
                                                      old_sd.get_previous_owner_keys().clone(),
                                                      Some(&sign_sk)))
                        .map_err(CoreError::from)
                        .into_box()
                }
                _ => err!(CoreError::InvalidStructuredDataTypeTag),
            };

            fut.map(move |new_sd| {
                    // Replace the SD in the object cache with the updated one.
                    object_cache.insert_sd_at(sd_h, new_sd);
                    o_cb(user_data.0, 0);
                })
                .map_err(move |err| {
                    // TODO: should we put the old SD back to the object cache here?
                    // (it would require cloning the SD though)
                    o_cb(user_data.0, ffi_error_code!(err));
                })
                .into_box()
                .into()
        })
    })
}

/// Extract data from StructuredData
#[no_mangle]
pub unsafe extern "C" fn struct_data_extract_data(session: *const Session,
                                                  app_h: AppHandle,
                                                  sd_h: StructDataHandle,
                                                  user_data: *mut c_void,
                                                  o_cb: unsafe extern "C" fn(*mut c_void,
                                                                             i32,
                                                                             *mut u8,
                                                                             usize,
                                                                             usize)) {
    helper::catch_unwind_cb(user_data, o_cb, || {
        let user_data = OpaqueCtx(user_data);

        (*session).send(move |client, object_cache| {
            let object_cache = object_cache.clone();

            let fut = {
                let sd = try_cb!(object_cache.get_sd(sd_h), user_data.0, o_cb);

                match sd.get_type_tag() {
                    ::UNVERSIONED_STRUCT_DATA_TYPE_TAG => {
                        unversioned::extract_value(client, &*sd, None)
                    }
                    ::VERSIONED_STRUCT_DATA_TYPE_TAG => {
                        versioned::extract_current_value(client, &*sd, None)
                    }
                    x if x >= CLIENT_STRUCTURED_DATA_TAG => ok!(sd.get_data().clone()),
                    _ => err!(CoreError::InvalidStructuredDataTypeTag),
                }
            };

            fut.map_err(FfiError::from)
                .and_then(move |encrypted_data| {
                    let app = object_cache.get_app(app_h)?;
                    CipherOpt::decrypt(&*app, &encrypted_data)
                })
                .map(move |data| {
                    let (ptr, size, capacity) = helper::u8_vec_to_ptr(data);
                    o_cb(user_data.0, 0, ptr, size, capacity);
                })
                .map_err(move |err| {
                    o_cb(user_data.0, ffi_error_code!(err), ptr::null_mut(), 0, 0);
                })
                .into_box()
                .into()
        })
    })
}

/// Get number of versions from a versioned StructuredData
#[no_mangle]
pub unsafe extern "C" fn struct_data_num_of_versions(session: *const Session,
                                                     sd_h: StructDataHandle,
                                                     user_data: *mut c_void,
                                                     o_cb: unsafe extern "C" fn(*mut c_void,
                                                                                i32,
                                                                                u64)) {
    helper::catch_unwind_cb(user_data, o_cb, || {
        let user_data = OpaqueCtx(user_data);

        (*session).send(move |_, object_cache| {
            let sd = try_cb!(object_cache.get_sd(sd_h), user_data, o_cb);
            let num = try_cb!(versioned::version_count(&sd), user_data, o_cb);

            o_cb(user_data.0, 0, num);

            None
        })
    })
}

/// Get nth (starts from 0) version from a versioned StructuredData
#[no_mangle]
pub unsafe extern "C" fn struct_data_nth_version(session: *const Session,
                                                 app_h: AppHandle,
                                                 sd_h: StructDataHandle,
                                                 n: u64,
                                                 user_data: *mut c_void,
                                                 o_cb: unsafe extern "C" fn(*mut c_void,
                                                                            i32,
                                                                            *mut u8,
                                                                            usize,
                                                                            usize)) {
    helper::catch_unwind_cb(user_data, o_cb, || {
        let user_data = OpaqueCtx(user_data);

        (*session).send(move |client, object_cache| {
            let object_cache = object_cache.clone();

            let fut = {
                let sd = try_cb!(object_cache.get_sd(sd_h), user_data, o_cb);

                if sd.get_type_tag() == ::VERSIONED_STRUCT_DATA_TYPE_TAG {
                    versioned::extract_value(client, &*sd, n, None)
                } else {
                    err!(CoreError::InvalidStructuredDataTypeTag)
                }
            };

            fut.map_err(FfiError::from)
                .and_then(move |encrypted_data| {
                    let app = object_cache.get_app(app_h)?;
                    CipherOpt::decrypt(&*app, &encrypted_data)
                })
                .map(move |data| {
                    let (ptr, size, capacity) = helper::u8_vec_to_ptr(data);
                    o_cb(user_data.0, 0, ptr, size, capacity);
                })
                .map_err(move |err| {
                    o_cb(user_data.0, ffi_error_code!(err), ptr::null_mut(), 0, 0);
                })
                .into_box()
                .into()

        })
    })
}

/// Get the current version of StructuredData by its handle
#[no_mangle]
pub unsafe extern "C" fn struct_data_version(session: *const Session,
                                             handle: StructDataHandle,
                                             user_data: *mut c_void,
                                             o_cb: unsafe extern "C" fn(*mut c_void, i32, u64)) {
    helper::catch_unwind_cb(user_data, o_cb, || {
        let user_data = OpaqueCtx(user_data);

        (*session).send(move |_, object_cache| {
            let sd = try_cb!(object_cache.get_sd(handle), user_data, o_cb);
            o_cb(user_data.0, 0, sd.get_version());
            None
        })
    })
}

/// PUT StructuredData
#[no_mangle]
pub unsafe extern "C" fn struct_data_put(session: *const Session,
                                         sd_h: StructDataHandle,
                                         user_data: *mut c_void,
                                         o_cb: unsafe extern "C" fn(*mut c_void, i32)) {
    helper::catch_unwind_cb(user_data, o_cb, || {
        let user_data = OpaqueCtx(user_data);

        (*session).send(move |client, object_cache| {
            let sign_sk = try_cb!(client.secret_signing_key(), user_data, o_cb);
            let sd = try_cb!(object_cache.get_sd(sd_h), user_data, o_cb).clone();

            let object_cache = object_cache.clone();

            client.put_recover(Data::Structured(sd), None, sign_sk.clone())
                .map_err(FfiError::from)
                .and_then(move |version| {
                    // Update the SD version in the object cache.
                    let old_sd = object_cache.remove_sd(sd_h)?;
                    let new_sd = StructuredData::new(old_sd.get_type_tag(),
                                                     *old_sd.name(),
                                                     version,
                                                     old_sd.get_data().clone(),
                                                     old_sd.get_owner_keys().clone(),
                                                     old_sd.get_previous_owner_keys()
                                                         .clone(),
                                                     Some(&sign_sk))?;

                    let _ = object_cache.insert_sd_at(sd_h, new_sd);
                    Ok(())
                })
                .map(move |_| o_cb(user_data.0, 0))
                .map_err(move |err| o_cb(user_data.0, ffi_error_code!(err)))
                .into_box()
                .into()
        })
    })
}

/// POST StructuredData
#[no_mangle]
pub unsafe extern "C" fn struct_data_post(session: *const Session,
                                          sd_h: StructDataHandle,
                                          user_data: *mut c_void,
                                          o_cb: unsafe extern "C" fn(*mut c_void, i32)) {
    helper::catch_unwind_cb(user_data, o_cb, || {
        let user_data = OpaqueCtx(user_data);

        (*session).send(move |client, object_cache| {
            let sd = try_cb!(object_cache.get_sd(sd_h), user_data, o_cb).clone();

            client.post(Data::Structured(sd), None)
                .map(move |_| o_cb(user_data.0, 0))
                .map_err(move |err| {
                    let err = FfiError::from(err);
                    o_cb(user_data.0, ffi_error_code!(err));
                })
                .into_box()
                .into()
        })
    })
}

/// DELETE StructuredData. Version will be bumped.
#[no_mangle]
pub unsafe extern "C" fn struct_data_delete(session: *const Session,
                                            sd_h: StructDataHandle,
                                            user_data: *mut c_void,
                                            o_cb: unsafe extern "C" fn(*mut c_void, i32)) {
    helper::catch_unwind_cb(user_data, o_cb, || {
        let user_data = OpaqueCtx(user_data);

        (*session).send(move |client, object_cache| {
            let sd = try_cb!(object_cache.remove_sd(sd_h), user_data, o_cb);
            let sign_sk = try_cb!(client.secret_signing_key(), user_data, o_cb);

            structured_data::delete(client, sd, &sign_sk)
                .map(move |_| o_cb(user_data.0, 0))
                .map_err(move |err| {
                    let err = FfiError::from(err);
                    o_cb(user_data.0, ffi_error_code!(err));
                })
                .into_box()
                .into()
        })
    })
}

/// See if StructuredData size is valid.
#[no_mangle]
pub unsafe extern "C" fn struct_data_validate_size(session: *const Session,
                                                   handle: StructDataHandle,
                                                   user_data: *mut c_void,
                                                   o_cb: extern "C" fn(*mut c_void, i32, bool)) {
    helper::catch_unwind_cb(user_data, o_cb, || {
        let user_data = OpaqueCtx(user_data);

        (*session).send(move |_, object_cache| {
            let sd = try_cb!(object_cache.get_sd(handle), user_data, o_cb);
            o_cb(user_data.0, 0, sd.validate_size());
            None
        })
    })
}

/// Returns true if we are one of the owners of the provided StructuredData.
#[no_mangle]
pub unsafe extern "C" fn struct_data_is_owned(session: *const Session,
                                              sd_h: StructDataHandle,
                                              user_data: *mut c_void,
                                              o_cb: unsafe extern "C" fn(*mut c_void, i32, bool)) {
    helper::catch_unwind_cb(user_data, o_cb, || {
        let user_data = OpaqueCtx(user_data);

        (*session).send(move |client, object_cache| {
            let sd = try_cb!(object_cache.get_sd(sd_h), user_data, o_cb);
            let my_key = try_cb!(client.public_signing_key(), user_data, o_cb);

            o_cb(user_data.0, 0, sd.get_owner_keys().contains(&my_key));
            None
        })
    })
}

/// Free StructuredData handle
#[no_mangle]
pub unsafe extern "C" fn struct_data_free(session: *const Session,
                                          handle: StructDataHandle,
                                          user_data: *mut c_void,
                                          o_cb: unsafe extern "C" fn(*mut c_void, i32)) {
    helper::catch_unwind_cb(user_data, o_cb, || {
        let user_data = OpaqueCtx(user_data);

        (*session).send(move |_, object_cache| {
            let _ = try_cb!(object_cache.remove_sd(handle), user_data, o_cb);
            o_cb(user_data.0, 0);
            None
        })
    })
}
