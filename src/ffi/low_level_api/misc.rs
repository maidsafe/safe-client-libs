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

use ffi::{AppendableDataHandle, DataIdHandle, EncryptKeyHandle, SignKeyHandle, StructDataHandle};
use ffi::{FfiError, FfiResult, OpaqueCtx, Session, helper};
use ffi::low_level_api::appendable_data::AppendableData;
use ffi::object_cache::ObjectCache;
use maidsafe_utilities::serialisation::{deserialise, serialise};
use std::{mem, ptr, slice};
use std::os::raw::c_void;

type ADHandle = AppendableDataHandle;

/// Free Encrypt Key handle
#[no_mangle]
pub unsafe extern "C" fn misc_encrypt_key_free(session: *const Session,
                                               handle: EncryptKeyHandle,
                                               user_data: *mut c_void,
                                               o_cb: unsafe extern "C" fn(*mut c_void, i32)) {
    let user_data = OpaqueCtx(user_data);

    helper::catch_unwind_cb(user_data, o_cb, || {
        (*session).send(move |_, obj_cache| {
            let res = obj_cache.remove_encrypt_key(handle);
            o_cb(user_data.0, ffi_result_code!(res));
            None
        })
    })
}

/// Free Sign Key handle
#[no_mangle]
pub unsafe extern "C" fn misc_sign_key_free(session: *const Session,
                                            handle: SignKeyHandle,
                                            user_data: *mut c_void,
                                            o_cb: unsafe extern "C" fn(*mut c_void, i32)) {
    let user_data = OpaqueCtx(user_data);

    helper::catch_unwind_cb(user_data, o_cb, || {
        (*session).send(move |_, obj_cache| {
            let res = obj_cache.remove_sign_key(handle);
            o_cb(user_data.0, ffi_result_code!(res));
            None
        })
    });
}

/// Serialise sign::PubKey
#[no_mangle]
pub unsafe extern "C" fn misc_serialise_sign_key(session: *const Session,
                                                 sign_key_h: SignKeyHandle,
                                                 user_data: *mut c_void,
                                                 o_cb: unsafe extern "C" fn(*mut c_void,
                                                                            i32,
                                                                            *mut u8,
                                                                            usize,
                                                                            usize)) {
    let user_data = OpaqueCtx(user_data);

    helper::catch_unwind_cb(user_data, o_cb, || {
        (*session).send(move |_, obj_cache| {
            match misc_serialise_sign_key_impl(obj_cache, sign_key_h) {
                Ok(mut ser_sign_key) => {
                    let data = ser_sign_key.as_mut_ptr();
                    let size = ser_sign_key.len();
                    let capacity = ser_sign_key.capacity();
                    o_cb(user_data.0, 0, data, size, capacity);
                    mem::forget(ser_sign_key);
                }
                Err(e) => o_cb(user_data.0, ffi_error_code!(e), ptr::null_mut(), 0, 0),
            }
            None
        })
    });
}

fn misc_serialise_sign_key_impl(obj_cache: &ObjectCache,
                                sign_key_h: SignKeyHandle)
                                -> FfiResult<Vec<u8>> {
    Ok(serialise(&*obj_cache.get_sign_key(sign_key_h)?).map_err(FfiError::from)?)
}

/// Deserialise sign::PubKey
#[no_mangle]
pub unsafe extern "C" fn misc_deserialise_sign_key(session: *const Session,
                                                   data: *mut u8,
                                                   size: usize,
                                                   user_data: *mut c_void,
                                                   o_cb: unsafe extern "C" fn(*mut c_void,
                                                                              i32,
                                                                              SignKeyHandle)) {
    let user_data = OpaqueCtx(user_data);

    helper::catch_unwind_cb(user_data, o_cb, || {
        let data = OpaqueCtx(data as *mut _);

        (*session).send(move |_, obj_cache| {
            let ser_sign_key = slice::from_raw_parts(data.0 as *mut u8, size);
            let sign_key = match deserialise(ser_sign_key).map_err(FfiError::from) {
                Ok(sign_key) => sign_key,
                Err(e) => {
                    o_cb(user_data.0, ffi_error_code!(e), 0);
                    return None;
                }
            };
            let handle = obj_cache.insert_sign_key(sign_key);
            o_cb(user_data.0, 0, handle);
            None
        })
    });
}

/// Get MAID-sign::PubKey
#[no_mangle]
pub unsafe extern "C" fn misc_maid_sign_key(session: *const Session,
                                            user_data: *mut c_void,
                                            o_cb: unsafe extern "C" fn(*mut c_void,
                                                                       i32,
                                                                       SignKeyHandle)) {
    let user_data = OpaqueCtx(user_data);

    helper::catch_unwind_cb(user_data, o_cb, || {
        (*session).send(move |client, obj_cache| {
            let sign_key = match client.public_signing_key() {
                Ok(sign_key) => sign_key,
                Err(e) => {
                    o_cb(user_data.0, ffi_error_code!(e), 0);
                    return None;
                }
            };
            let handle = obj_cache.insert_sign_key(sign_key);
            o_cb(user_data.0, 0, handle);
            None
        })
    });
}

/// Serialise DataIdentifier
/// Callback arguments are (error_code, user_data, data, size, capacity)
#[no_mangle]
pub unsafe extern "C" fn misc_serialise_data_id(session: *const Session,
                                                data_id_h: DataIdHandle,
                                                user_data: *mut c_void,
                                                o_cb: unsafe extern "C" fn(*mut c_void,
                                                                           i32,
                                                                           *mut u8,
                                                                           usize,
                                                                           usize)) {
    let user_data = OpaqueCtx(user_data);

    helper::catch_unwind_cb(user_data, o_cb, || {
        (*session).send(move |_, obj_cache| {
            match misc_serialise_data_id_impl(obj_cache, data_id_h) {
                Ok(mut ser_data_id) => {
                    let data = ser_data_id.as_mut_ptr();
                    let size = ser_data_id.len();
                    let capacity = ser_data_id.capacity();
                    o_cb(user_data.0, 0, data, size, capacity);

                    mem::forget(ser_data_id);
                }
                Err(e) => {
                    o_cb(user_data.0, ffi_error_code!(e), ptr::null_mut(), 0, 0);
                }
            }
            None
        })
    });
}

fn misc_serialise_data_id_impl(obj_cache: &ObjectCache,
                               data_id_h: DataIdHandle)
                               -> FfiResult<Vec<u8>> {
    Ok(serialise(&*obj_cache.get_data_id(data_id_h)?).map_err(FfiError::from)?)
}

/// Deserialise DataIdentifier
#[no_mangle]
pub unsafe extern "C" fn misc_deserialise_data_id(session: *const Session,
                                                  data: *const u8,
                                                  size: usize,
                                                  user_data: *mut c_void,
                                                  o_cb: unsafe extern "C" fn(*mut c_void,
                                                                             i32,
                                                                             DataIdHandle)) {
    let user_data = OpaqueCtx(user_data);

    helper::catch_unwind_cb(user_data, o_cb, || {
        let data = OpaqueCtx(data as *mut _);

        (*session).send(move |_, obj_cache| {
            let data: *const u8 = data.0 as *const _;
            let ser_data_id = slice::from_raw_parts(data, size);
            let data_id = match deserialise(ser_data_id).map_err(FfiError::from) {
                Ok(data_id) => data_id,
                Err(e) => {
                    o_cb(user_data.0, ffi_error_code!(e), 0);
                    return None;
                }
            };

            let handle = obj_cache.insert_data_id(data_id);
            o_cb(user_data.0, 0, handle);
            None
        })
    });
}

/// Serialise AppendableData
#[no_mangle]
pub unsafe extern "C" fn misc_serialise_appendable_data(session: *const Session,
                                                        ad_h: ADHandle,
                                                        user_data: *mut c_void,
                                                        o_cb: unsafe extern "C" fn(*mut c_void,
                                                                                   i32,
                                                                                   *mut u8,
                                                                                   usize,
                                                                                   usize)) {
    let user_data = OpaqueCtx(user_data);

    helper::catch_unwind_cb(user_data, o_cb, || {
        (*session).send(move |_, obj_cache| {
            match serialise_appendable_data_impl(obj_cache, ad_h) {
                Ok(mut ser_ad) => {
                    let data = ser_ad.as_mut_ptr();
                    let size = ser_ad.len();
                    let capacity = ser_ad.capacity();
                    o_cb(user_data.0, 0, data, size, capacity);
                    mem::forget(ser_ad);
                }
                Err(e) => o_cb(user_data.0, ffi_error_code!(e), ptr::null_mut(), 0, 0),
            }
            None
        })
    });
}

fn serialise_appendable_data_impl(object_cache: &ObjectCache,
                                  ad_h: ADHandle)
                                  -> FfiResult<Vec<u8>> {
    Ok(match *object_cache.get_ad(ad_h)? {
        AppendableData::Pub(ref ad) => serialise(ad).map_err(FfiError::from)?,
        AppendableData::Priv(ref ad) => serialise(ad).map_err(FfiError::from)?,
    })
}

/// Deserialise AppendableData
#[no_mangle]
pub unsafe extern "C" fn misc_deserialise_appendable_data(session: *const Session,
                                                          data: *const u8,
                                                          size: usize,
                                                          user_data: *mut c_void,
                                                          o_cb: unsafe extern "C" fn(*mut c_void,
                                                                                     i32,
                                                                                     ADHandle)) {
    let user_data = OpaqueCtx(user_data);

    helper::catch_unwind_cb(user_data, o_cb, || {
        let data = OpaqueCtx(data as *mut _);

        (*session).send(move |_, obj_cache| {
            let ser_ad = slice::from_raw_parts(data.0 as *mut u8, size);
            match deserialise_appendable_data_impl(obj_cache, ser_ad) {
                Ok(handle) => o_cb(user_data.0, 0, handle),
                Err(e) => o_cb(user_data.0, ffi_error_code!(e), 0),
            }
            None
        })
    });
}

fn deserialise_appendable_data_impl(obj_cache: &ObjectCache, ser_ad: &[u8]) -> FfiResult<ADHandle> {
    let ad = {
        if let Ok(elt) = deserialise(ser_ad) {
            AppendableData::Priv(elt)
        } else {
            AppendableData::Pub(deserialise(ser_ad).map_err(FfiError::from)?)
        }
    };
    Ok(obj_cache.insert_ad(ad))
}

/// Serialise StructuredData
#[no_mangle]
pub unsafe extern "C" fn misc_serialise_struct_data(session: *const Session,
                                                    sd_h: StructDataHandle,
                                                    user_data: *mut c_void,
                                                    o_cb: unsafe extern "C" fn(*mut c_void,
                                                                               i32,
                                                                               *mut u8,
                                                                               usize,
                                                                               usize)) {
    let user_data = OpaqueCtx(user_data);

    helper::catch_unwind_cb(user_data, o_cb, || {
        (*session).send(move |_, obj_cache| {
            match misc_serialise_struct_data_impl(obj_cache, sd_h) {
                Ok(mut ser_sd) => {
                    let data = ser_sd.as_mut_ptr();
                    let size = ser_sd.len();
                    let capacity = ser_sd.capacity();

                    o_cb(user_data.0, 0, data, size, capacity);
                    mem::forget(ser_sd);
                }
                Err(e) => o_cb(user_data.0, ffi_error_code!(e), ptr::null_mut(), 0, 0),
            }
            None
        })
    });
}

fn misc_serialise_struct_data_impl(obj_cache: &ObjectCache,
                                   sd_h: StructDataHandle)
                                   -> FfiResult<Vec<u8>> {
    Ok(serialise(&*obj_cache.get_sd(sd_h)?).map_err(FfiError::from)?)
}

/// Deserialise StructuredData
#[no_mangle]
pub unsafe extern "C" fn misc_deserialise_struct_data(session: *const Session,
                                                      data: *const u8,
                                                      size: usize,
                                                      user_data: *mut c_void,
                                                      o_cb: unsafe extern "C"
                                                      fn(*mut c_void,
                                                         i32,
                                                         StructDataHandle)) {
    let user_data = OpaqueCtx(user_data);

    helper::catch_unwind_cb(user_data, o_cb, || {
        let data = OpaqueCtx(data as *mut _);

        (*session).send(move |_, obj_cache| {
            let ser_sd = slice::from_raw_parts(data.0 as *mut u8, size);
            let sd = match deserialise(ser_sd).map_err(FfiError::from) {
                Ok(sd) => sd,
                Err(e) => {
                    o_cb(user_data.0, ffi_error_code!(e), 0);
                    return None;
                }
            };
            let handle = obj_cache.insert_sd(sd);
            o_cb(user_data.0, 0, handle);
            None
        })
    });
}



/// Deallocate pointer obtained via FFI and allocated by safe_core
#[no_mangle]
pub unsafe extern "C" fn misc_u8_ptr_free(ptr: *mut u8, size: usize, capacity: usize) {
    // TODO: refactor implementation to remove the need for `cap`. Related issue:
    // <https://github.com/rust-lang/rust/issues/36284>.
    let _ = Vec::from_raw_parts(ptr, size, capacity);
}

/// Reset the object cache (drop all objects stored in it). This will invalidate
/// all currently held object handles.
#[no_mangle]
pub unsafe extern "C" fn misc_object_cache_reset(session: *const Session,
                                                 user_data: *mut c_void,
                                                 o_cb: unsafe extern "C" fn(*mut c_void, i32)) {
    let user_data = OpaqueCtx(user_data);

    helper::catch_unwind_cb(user_data, o_cb, || {
        (*session).send(move |_, obj_cache| {
            obj_cache.reset();
            o_cb(user_data.0, 0);
            None
        })
    })
}

#[cfg(test)]
mod tests {
    use core::utility;
    use ffi::low_level_api::appendable_data::*;
    use ffi::low_level_api::cipher_opt::*;
    use ffi::low_level_api::data_id::*;
    use ffi::low_level_api::struct_data::*;
    use ffi::test_utils;
    use rand;
    use routing::DataIdentifier;
    use std::hash::Hash;
    use super::*;

    #[test]
    fn sign_key_serialisation() {
        let sess = test_utils::create_session();

        let sign_key_h = test_utils::run_now(&sess, |client, obj_cache| {
            let sign_key = unwrap!(client.public_signing_key());
            obj_cache.insert_sign_key(sign_key)
        });

        unsafe {
            let mut data = unwrap!(test_utils::call_vec_u8(|user_data, cb| {
                misc_serialise_sign_key(&sess, sign_key_h, user_data, cb);
            }));

            let got_sign_key_h = unwrap!(test_utils::call_1(|user_data, cb| {
                misc_deserialise_sign_key(&sess, data.as_mut_ptr(), data.len(), user_data, cb)
            }));

            test_utils::run_now(&sess, move |_, obj_cache| {
                let before = hash(&*unwrap!(obj_cache.get_sign_key(sign_key_h)));
                let after = hash(&*unwrap!(obj_cache.get_sign_key(got_sign_key_h)));

                assert_eq!(before, after);
            });

            unwrap!(test_utils::call_0(|user_data, cb| {
                misc_sign_key_free(&sess, got_sign_key_h, user_data, cb)
            }));

            unwrap!(test_utils::call_0(|user_data, cb| {
                misc_sign_key_free(&sess, sign_key_h, user_data, cb)
            }));
        }
    }

    #[test]
    fn appendable_data_serialisation() {
        let sess = test_utils::create_session();
        let app = test_utils::create_app(&sess, false);
        let app_h = test_utils::run_now(&sess, move |_, obj_cache| obj_cache.insert_app(app));

        let ad_pub_h;
        let ad_priv_h;

        // Initialise mock appendable data
        unsafe {
            let ad_name = rand::random();
            ad_pub_h = unwrap!(test_utils::call_1(|user_data, cb| {
                appendable_data_new_pub(&sess, &ad_name, user_data, cb)
            }));

            let ad_name = rand::random();
            ad_priv_h = unwrap!(test_utils::call_1(|user_data, cb| {
                appendable_data_new_priv(&sess, app_h, &ad_name, user_data, cb)
            }));
        }

        // Test pub appendable data
        unsafe {
            let mut data = unwrap!(test_utils::call_vec_u8(|user_data, cb| {
                misc_serialise_appendable_data(&sess, ad_pub_h, user_data, cb)
            }));
            let appendable_data_h = unwrap!(test_utils::call_1(|user_data, cb| {
                misc_deserialise_appendable_data(&sess,
                                                 data.as_mut_ptr(),
                                                 data.len(),
                                                 user_data,
                                                 cb)
            }));
            assert!(appendable_data_h != ad_pub_h);

            test_utils::run_now(&sess, move |_, obj_cache| {
                let before = hash(&*unwrap!(obj_cache.get_ad(ad_pub_h)));
                let after = hash(&*unwrap!(obj_cache.get_ad(appendable_data_h)));

                assert_eq!(before, after);
            });
        }

        // Test priv appendable data
        unsafe {
            let mut data = unwrap!(test_utils::call_vec_u8(|user_data, cb| {
                misc_serialise_appendable_data(&sess, ad_priv_h, user_data, cb)
            }));

            let appendable_data_h = unwrap!(test_utils::call_1(|user_data, cb| {
                misc_deserialise_appendable_data(&sess,
                                                 data.as_mut_ptr(),
                                                 data.len(),
                                                 user_data,
                                                 cb)
            }));
            assert!(appendable_data_h != ad_priv_h);

            test_utils::run_now(&sess, move |_, obj_cache| {
                let before = hash(&*unwrap!(obj_cache.get_ad(ad_priv_h)));
                let after = hash(&*unwrap!(obj_cache.get_ad(appendable_data_h)));

                assert_eq!(before, after);
            })
        }
    }

    #[test]
    fn structured_data_serialisation() {
        let sess = test_utils::create_session();
        let app = test_utils::create_app(&sess, false);
        let app_h = test_utils::run_now(&sess, move |_, obj_cache| obj_cache.insert_app(app));

        let cipher_opt_h;
        let sd_h;

        // Initialise mock structured data
        unsafe {
            cipher_opt_h = unwrap!(test_utils::call_1(|user_data, cb| {
                cipher_opt_new_symmetric(&sess, user_data, cb)
            }));

            sd_h = unwrap!(test_utils::call_1(|user_data, cb| {
                let sd_id = rand::random();
                let plain_text = unwrap!(utility::generate_random_vector::<u8>(10));

                struct_data_new(&sess,
                                app_h,
                                ::UNVERSIONED_STRUCT_DATA_TYPE_TAG,
                                &sd_id,
                                0,
                                cipher_opt_h,
                                plain_text.as_ptr(),
                                plain_text.len(),
                                user_data,
                                cb)
            }));
        }

        unsafe {
            let mut data = unwrap!(test_utils::call_vec_u8(|user_data, cb| {
                misc_serialise_struct_data(&sess, sd_h, user_data, cb)
            }));

            let struct_data_h = unwrap!(test_utils::call_1(|user_data, cb| {
                misc_deserialise_struct_data(&sess, data.as_mut_ptr(), data.len(), user_data, cb)
            }));
            assert!(struct_data_h != sd_h);

            test_utils::run_now(&sess, move |_, obj_cache| {
                let before = hash(&*unwrap!(obj_cache.get_sd(sd_h)));
                let after = hash(&*unwrap!(obj_cache.get_sd(struct_data_h)));

                assert_eq!(before, after);
            })
        }
    }

    #[test]
    fn data_id_serialisation() {
        let sess = test_utils::create_session();

        let data_id_sd = DataIdentifier::Structured(rand::random(), rand::random());
        let data_id_id = DataIdentifier::Immutable(rand::random());
        let data_id_ad = DataIdentifier::PrivAppendable(rand::random());
        assert!(data_id_sd != data_id_id);
        assert!(data_id_sd != data_id_ad);
        assert!(data_id_ad != data_id_id);

        let (sd_data_id_h, id_data_id_h, ad_data_id_h) = test_utils::run_now(&sess, move |_,
                                                                                   obj_cache| {
            (obj_cache.insert_data_id(data_id_sd),
             obj_cache.insert_data_id(data_id_id),
             obj_cache.insert_data_id(data_id_ad))
        });

        unsafe {
            let mut data = unwrap!(test_utils::call_vec_u8(|user_data, cb| {
                misc_serialise_data_id(&sess, sd_data_id_h, user_data, cb)
            }));

            let data_id_h = unwrap!(test_utils::call_1(|user_data, cb| {
                misc_deserialise_data_id(&sess, data.as_mut_ptr(), data.len(), user_data, cb)
            }));
            assert!(data_id_h != sd_data_id_h);

            test_utils::run_now(&sess, move |_, obj_cache| {
                let before_id = *unwrap!(obj_cache.get_data_id(sd_data_id_h));
                let after_id = unwrap!(obj_cache.get_data_id(data_id_h));

                assert_eq!(before_id, *after_id);
                assert_eq!(data_id_sd, *after_id);
            });
        }

        unsafe {
            let mut data = unwrap!(test_utils::call_vec_u8(|user_data, cb| {
                misc_serialise_data_id(&sess, id_data_id_h, user_data, cb)
            }));

            let data_id_h = unwrap!(test_utils::call_1(|user_data, cb| {
                misc_deserialise_data_id(&sess, data.as_mut_ptr(), data.len(), user_data, cb)
            }));
            assert!(data_id_h != id_data_id_h);

            test_utils::run_now(&sess, move |_, obj_cache| {
                let before_id = *unwrap!(obj_cache.get_data_id(id_data_id_h));
                let after_id = unwrap!(obj_cache.get_data_id(data_id_h));

                assert_eq!(before_id, *after_id);
                assert_eq!(data_id_id, *after_id);
            })
        }

        unsafe {
            let mut data = unwrap!(test_utils::call_vec_u8(|user_data, cb| {
                misc_serialise_data_id(&sess, ad_data_id_h, user_data, cb)
            }));

            let data_id_h = unwrap!(test_utils::call_1(|user_data, cb| {
                misc_deserialise_data_id(&sess, data.as_mut_ptr(), data.len(), user_data, cb)
            }));
            assert!(data_id_h != id_data_id_h);

            test_utils::run_now(&sess, move |_, obj_cache| {
                let before_id = *unwrap!(obj_cache.get_data_id(ad_data_id_h));
                let after_id = unwrap!(obj_cache.get_data_id(data_id_h));

                assert_eq!(before_id, *after_id);
                assert_eq!(data_id_ad, *after_id);
            })
        }

        unsafe {
            unwrap!(test_utils::call_0(|user_data, cb| {
                data_id_free(&sess, sd_data_id_h, user_data, cb)
            }));
            unwrap!(test_utils::call_0(|user_data, cb| {
                data_id_free(&sess, id_data_id_h, user_data, cb)
            }));
            unwrap!(test_utils::call_0(|user_data, cb| {
                data_id_free(&sess, ad_data_id_h, user_data, cb)
            }));
        }
    }

    // SipHasher is deprecated on nigthly.
    #[allow(deprecated)]
    fn hash<T: Hash>(t: &T) -> u64 {
        use std::hash::{Hasher, SipHasher};

        let mut s = SipHasher::new();
        t.hash(&mut s);
        s.finish()
    }
}
