// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use ffi::errors::FfiError;
use ffi::helper;
use ffi::low_level_api::{AppendableDataHandle, DataIdHandle, EncryptKeyHandle, SignKeyHandle,
                         StructDataHandle};
use ffi::low_level_api::appendable_data::AppendableData;
use ffi::low_level_api::object_cache::object_cache;
use maidsafe_utilities::serialisation::{deserialise, serialise};
use std::{mem, ptr, slice};

/// Free Encrypt Key handle
#[no_mangle]
pub extern "C" fn misc_encrypt_key_free(handle: EncryptKeyHandle) -> i32 {
    helper::catch_unwind_i32(|| {
        let _ = ffi_try!(unwrap!(object_cache()).remove_encrypt_key(handle));
        0
    })
}

/// Free Sign Key handle
#[no_mangle]
pub extern "C" fn misc_sign_key_free(handle: SignKeyHandle) -> i32 {
    helper::catch_unwind_i32(|| {
        let _ = ffi_try!(unwrap!(object_cache()).remove_sign_key(handle));
        0
    })
}

/// Serialise sign::PubKey
#[no_mangle]
pub unsafe extern "C" fn misc_serialise_sign_key(sign_key_h: SignKeyHandle,
                                                 o_data: *mut *mut u8,
                                                 o_size: *mut usize,
                                                 o_capacity: *mut usize)
                                                 -> i32 {
    helper::catch_unwind_i32(|| {
        let mut ser_sign_key = ffi_try!(serialise(ffi_try!(unwrap!(object_cache())
                .get_sign_key(sign_key_h)))
            .map_err(FfiError::from));

        *o_data = ser_sign_key.as_mut_ptr();
        ptr::write(o_size, ser_sign_key.len());
        ptr::write(o_capacity, ser_sign_key.capacity());
        mem::forget(ser_sign_key);

        0
    })
}

/// Deserialise sign::PubKey
#[no_mangle]
pub unsafe extern "C" fn misc_deserialise_sign_key(data: *mut u8,
                                                   size: usize,
                                                   o_handle: *mut SignKeyHandle)
                                                   -> i32 {
    helper::catch_unwind_i32(|| {
        let ser_sign_key = slice::from_raw_parts(data, size);
        let sign_key = ffi_try!(deserialise(ser_sign_key).map_err(FfiError::from));

        let handle = unwrap!(object_cache()).insert_sign_key(sign_key);
        ptr::write(o_handle, handle);

        0
    })
}

/// Serialise DataIdentifier
#[no_mangle]
pub unsafe extern "C" fn misc_serialise_data_id(data_id_h: DataIdHandle,
                                                o_data: *mut *mut u8,
                                                o_size: *mut usize,
                                                o_capacity: *mut usize)
                                                -> i32 {
    helper::catch_unwind_i32(|| {
        let mut ser_data_id = ffi_try!(serialise(ffi_try!(unwrap!(object_cache())
                .get_data_id(data_id_h)))
            .map_err(FfiError::from));

        *o_data = ser_data_id.as_mut_ptr();
        ptr::write(o_size, ser_data_id.len());
        ptr::write(o_capacity, ser_data_id.capacity());
        mem::forget(ser_data_id);

        0
    })
}

/// Deserialise DataIdentifier
#[no_mangle]
pub unsafe extern "C" fn misc_deserialise_data_id(data: *const u8,
                                                  size: usize,
                                                  o_handle: *mut DataIdHandle)
                                                  -> i32 {
    helper::catch_unwind_i32(|| {
        let ser_data_id = slice::from_raw_parts(data, size);
        let data_id = ffi_try!(deserialise(ser_data_id).map_err(FfiError::from));

        let handle = unwrap!(object_cache()).insert_data_id(data_id);
        ptr::write(o_handle, handle);

        0
    })
}

/// Serialise AppendableData
#[no_mangle]
pub unsafe extern "C" fn misc_serialise_appendable_data(ad_h: AppendableDataHandle,
                                                        o_data: *mut *mut u8,
                                                        o_size: *mut usize,
                                                        o_capacity: *mut usize)
                                                        -> i32 {
    helper::catch_unwind_i32(|| {
        let mut object_cache = unwrap!(object_cache());
        let mut ser_ad = match *ffi_try!(object_cache.get_ad(ad_h)) {
            AppendableData::Pub(ref ad) => ffi_try!(serialise(ad).map_err(FfiError::from)),
            AppendableData::Priv(ref ad) => ffi_try!(serialise(ad).map_err(FfiError::from)),
        };

        *o_data = ser_ad.as_mut_ptr();
        ptr::write(o_size, ser_ad.len());
        ptr::write(o_capacity, ser_ad.capacity());
        mem::forget(ser_ad);

        0
    })
}

/// Deserialise AppendableData
#[no_mangle]
pub unsafe extern "C" fn misc_deserialise_appendable_data(data: *const u8,
                                                          size: usize,
                                                          o_handle: *mut AppendableDataHandle)
                                                          -> i32 {
    helper::catch_unwind_i32(|| {
        let ser_ad = slice::from_raw_parts(data, size);
        let ad = {
            if let Ok(elt) = deserialise(ser_ad) {
                AppendableData::Priv(elt)
            } else {
                AppendableData::Pub(ffi_try!(deserialise(ser_ad).map_err(FfiError::from)))
            }
        };

        let handle = unwrap!(object_cache()).insert_ad(ad);
        ptr::write(o_handle, handle);

        0
    })
}

/// Serialise StructuredData
#[no_mangle]
pub unsafe extern "C" fn misc_serialise_struct_data(sd_h: StructDataHandle,
                                                    o_data: *mut *mut u8,
                                                    o_size: *mut usize,
                                                    o_capacity: *mut usize)
                                                    -> i32 {
    helper::catch_unwind_i32(|| {
        let mut ser_ad = ffi_try!(serialise(ffi_try!(unwrap!(object_cache()).get_sd(sd_h)))
            .map_err(FfiError::from));

        *o_data = ser_ad.as_mut_ptr();
        ptr::write(o_size, ser_ad.len());
        ptr::write(o_capacity, ser_ad.capacity());
        mem::forget(ser_ad);

        0
    })
}

/// Deserialise StructuredData
#[no_mangle]
pub unsafe extern "C" fn misc_deserialise_struct_data(data: *const u8,
                                                      size: usize,
                                                      o_handle: *mut StructDataHandle)
                                                      -> i32 {
    helper::catch_unwind_i32(|| {
        let ser_sd = slice::from_raw_parts(data, size);
        let sd = ffi_try!(deserialise(ser_sd).map_err(FfiError::from));

        let handle = unwrap!(object_cache()).insert_sd(sd);
        ptr::write(o_handle, handle);

        0
    })
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
pub extern "C" fn misc_object_cache_reset() {
    unwrap!(object_cache()).reset()
}

#[cfg(test)]
mod tests {
    use core::utility;
    use ffi::low_level_api::appendable_data::*;
    use ffi::low_level_api::cipher_opt::*;
    use ffi::low_level_api::data_id::*;
    use ffi::low_level_api::struct_data::*;
    use ffi::low_level_api::object_cache::object_cache;
    use ffi::test_utils;
    use rand;
    use routing::DataIdentifier;
    use std::hash::{Hash, Hasher, SipHasher};
    use std::ptr;
    use super::*;

    #[test]
    fn sign_key_serialisation() {
        let app = test_utils::create_app(false);
        let client = app.get_client();

        let sign_key = unwrap!(unwrap!(client.lock()).get_public_signing_key()).clone();
        let sign_key_h = unwrap!(object_cache()).insert_sign_key(sign_key);

        unsafe {
            let mut data_ptr: *mut u8 = ptr::null_mut();
            let mut data_size = 0;
            let mut capacity = 0;

            assert_eq!(misc_serialise_sign_key(sign_key_h,
                                               &mut data_ptr,
                                               &mut data_size,
                                               &mut capacity),
                       0);

            let mut got_sign_key_h = 0;
            assert_eq!(misc_deserialise_sign_key(data_ptr,
                                                 data_size,
                                                 &mut got_sign_key_h),
                       0);

            {
                let mut object_cache = unwrap!(object_cache());

                let before = hash(unwrap!(object_cache.get_sign_key(sign_key_h)));
                let after = hash(unwrap!(object_cache.get_sign_key(got_sign_key_h)));

                assert_eq!(before, after);
            }

            assert_eq!(misc_sign_key_free(got_sign_key_h), 0);
            assert_eq!(misc_sign_key_free(sign_key_h), 0);
        }
    }

    #[test]
    fn appendable_data_serialisation() {
        let app = test_utils::create_app(true);

        let mut ad_pub_h = 0;
        let mut ad_priv_h = 0;

        // Initialise mock appendable data
        unsafe {
            let ad_name = rand::random();
            assert_eq!(appendable_data_new_pub(&app, &ad_name, &mut ad_pub_h), 0);

            let ad_name = rand::random();
            assert_eq!(appendable_data_new_priv(&app, &ad_name, &mut ad_priv_h), 0);
        }

        // Test pub appendable data
        unsafe {
            let mut data_ptr: *mut u8 = ptr::null_mut();
            let mut data_size = 0;
            let mut capacity = 0;
            assert_eq!(misc_serialise_appendable_data(ad_pub_h,
                                                      &mut data_ptr,
                                                      &mut data_size,
                                                      &mut capacity),
                       0);

            let mut appendable_data_h = 0;
            assert_eq!(misc_deserialise_appendable_data(data_ptr, data_size, &mut appendable_data_h),
                       0);
            assert!(appendable_data_h != ad_pub_h);

            {
                let mut object_cache = unwrap!(object_cache());
                let before = hash(unwrap!(object_cache.get_ad(ad_pub_h)));
                let after = hash(unwrap!(object_cache.get_ad(appendable_data_h)));

                assert_eq!(before, after);
            }

            assert_eq!(appendable_data_free(appendable_data_h), 0);
            misc_u8_ptr_free(data_ptr, data_size, capacity);
        }

        // Test priv appendable data
        unsafe {
            let mut data_ptr: *mut u8 = ptr::null_mut();
            let mut data_size = 0;
            let mut capacity = 0;
            assert_eq!(misc_serialise_appendable_data(ad_priv_h,
                                                      &mut data_ptr,
                                                      &mut data_size,
                                                      &mut capacity),
                       0);

            let mut appendable_data_h = 0;
            assert_eq!(misc_deserialise_appendable_data(data_ptr, data_size, &mut appendable_data_h),
                       0);
            assert!(appendable_data_h != ad_priv_h);

            {
                let mut object_cache = unwrap!(object_cache());
                let before = hash(unwrap!(object_cache.get_ad(ad_priv_h)));
                let after = hash(unwrap!(object_cache.get_ad(appendable_data_h)));

                assert_eq!(before, after);
            }

            assert_eq!(appendable_data_free(appendable_data_h), 0);
            misc_u8_ptr_free(data_ptr, data_size, capacity);
        }

        assert_eq!(appendable_data_free(ad_priv_h), 0);
        assert_eq!(appendable_data_free(ad_pub_h), 0);
    }

    #[test]
    fn structured_data_serialisation() {
        let app = test_utils::create_app(true);

        let mut cipher_opt_h = 0;
        let mut sd_h = 0;

        // Initialise mock structured data
        unsafe {
            let sd_id = rand::random();
            let plain_text = unwrap!(utility::generate_random_vector::<u8>(10));

            assert_eq!(cipher_opt_new_symmetric(&mut cipher_opt_h), 0);

            assert_eq!(struct_data_new(&app,
                                       ::UNVERSIONED_STRUCT_DATA_TYPE_TAG,
                                       &sd_id,
                                       cipher_opt_h,
                                       plain_text.as_ptr(),
                                       plain_text.len(),
                                       &mut sd_h), 0);
        }

        unsafe {
            let mut data_ptr: *mut u8 = ptr::null_mut();
            let mut data_size = 0;
            let mut capacity = 0;
            assert_eq!(misc_serialise_struct_data(sd_h,
                                                  &mut data_ptr,
                                                  &mut data_size,
                                                  &mut capacity),
                       0);

            let mut struct_data_h = 0;
            assert_eq!(misc_deserialise_struct_data(data_ptr, data_size, &mut struct_data_h),
                       0);
            assert!(struct_data_h != sd_h);

            {
                let mut object_cache = unwrap!(object_cache());
                let before = hash(unwrap!(object_cache.get_sd(sd_h)));
                let after = hash(unwrap!(object_cache.get_sd(struct_data_h)));

                assert_eq!(before, after);
            }

            assert_eq!(struct_data_free(struct_data_h), 0);
            misc_u8_ptr_free(data_ptr, data_size, capacity);
        }

        assert_eq!(struct_data_free(sd_h), 0);
    }

    #[test]
    fn data_id_serialisation() {
        let data_id_sd = DataIdentifier::Structured(rand::random(), rand::random());
        let data_id_id = DataIdentifier::Immutable(rand::random());
        let data_id_ad = DataIdentifier::PrivAppendable(rand::random());
        assert!(data_id_sd != data_id_id);
        assert!(data_id_sd != data_id_ad);
        assert!(data_id_ad != data_id_id);

        let (sd_data_id_h, id_data_id_h, ad_data_id_h) = {
            let mut object_cache = unwrap!(object_cache());

            (object_cache.insert_data_id(data_id_sd),
             object_cache.insert_data_id(data_id_id),
             object_cache.insert_data_id(data_id_ad))
        };

        unsafe {
            let mut data_ptr: *mut u8 = ptr::null_mut();
            let mut data_size = 0;
            let mut capacity = 0;
            assert_eq!(misc_serialise_data_id(sd_data_id_h,
                                              &mut data_ptr,
                                              &mut data_size,
                                              &mut capacity),
                       0);

            let mut data_id_h = 0;
            assert_eq!(misc_deserialise_data_id(data_ptr, data_size, &mut data_id_h),
                       0);
            assert!(data_id_h != sd_data_id_h);

            {
                let mut object_cache = unwrap!(object_cache());
                let before_id = *unwrap!(object_cache.get_data_id(sd_data_id_h));
                let after_id = unwrap!(object_cache.get_data_id(data_id_h));

                assert_eq!(before_id, *after_id);
                assert_eq!(data_id_sd, *after_id);
            }

            assert_eq!(data_id_free(data_id_h), 0);
            misc_u8_ptr_free(data_ptr, data_size, capacity);
        }

        unsafe {
            let mut data_ptr: *mut u8 = ptr::null_mut();
            let mut data_size = 0;
            let mut capacity = 0;
            assert_eq!(misc_serialise_data_id(id_data_id_h,
                                              &mut data_ptr,
                                              &mut data_size,
                                              &mut capacity),
                       0);

            let mut data_id_h = 0;
            assert_eq!(misc_deserialise_data_id(data_ptr, data_size, &mut data_id_h),
                       0);
            assert!(data_id_h != id_data_id_h);

            {
                let mut object_cache = unwrap!(object_cache());
                let before_id = *unwrap!(object_cache.get_data_id(id_data_id_h));
                let after_id = unwrap!(object_cache.get_data_id(data_id_h));

                assert_eq!(before_id, *after_id);
                assert_eq!(data_id_id, *after_id);
            }

            assert_eq!(data_id_free(data_id_h), 0);
            misc_u8_ptr_free(data_ptr, data_size, capacity);
        }

        unsafe {
            let mut data_ptr: *mut u8 = ptr::null_mut();
            let mut data_size = 0;
            let mut capacity = 0;
            assert_eq!(misc_serialise_data_id(ad_data_id_h,
                                              &mut data_ptr,
                                              &mut data_size,
                                              &mut capacity),
                       0);

            let mut data_id_h = 0;
            assert_eq!(misc_deserialise_data_id(data_ptr, data_size, &mut data_id_h),
                       0);
            assert!(data_id_h != ad_data_id_h);

            {
                let mut object_cache = unwrap!(object_cache());
                let before_id = *unwrap!(object_cache.get_data_id(ad_data_id_h));
                let after_id = unwrap!(object_cache.get_data_id(data_id_h));

                assert_eq!(before_id, *after_id);
                assert_eq!(data_id_ad, *after_id);
            }

            assert_eq!(data_id_free(data_id_h), 0);
            misc_u8_ptr_free(data_ptr, data_size, capacity);
        }

        assert_eq!(data_id_free(sd_data_id_h), 0);
        assert_eq!(data_id_free(id_data_id_h), 0);
        assert_eq!(data_id_free(ad_data_id_h), 0);
    }

    fn hash<T: Hash>(t: &T) -> u64 {
        let mut s = SipHasher::new();
        t.hash(&mut s);
        s.finish()
    }
}
