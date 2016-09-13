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

use core::{SelfEncryptionStorage, SelfEncryptionStorageError};
use core::errors::CoreError;
use core::immut_data_operations;
use ffi::app::App;
use ffi::errors::FfiError;
use ffi::helper;
use ffi::low_level_api::{CipherOptHandle, DataIdHandle, SelfEncryptorReaderHandle,
                         SelfEncryptorWriterHandle};
use ffi::low_level_api::cipher_opt::CipherOpt;
use ffi::low_level_api::object_cache::object_cache;
use maidsafe_utilities::serialisation::{deserialise, serialise};
use routing::{Data, DataIdentifier, ImmutableData};
use self_encryption::{DataMap, SelfEncryptor, SequentialEncryptor};
use std::{mem, ptr, slice};

/// SelfEncryptorWriterWrapper ties in the objects with dependent lifetimes and manages correct
/// destruction sequence.
pub struct SelfEncryptorWriterWrapper {
    se: SequentialEncryptor<'static, SelfEncryptionStorageError, SelfEncryptionStorage>,
    _storage: Box<SelfEncryptionStorage>,
}

/// SelfEncryptorWriterWrapper ties in the objects with dependent lifetimes and manages correct
/// destruction sequence.
pub struct SelfEncryptorReaderWrapper {
    se: SelfEncryptor<'static, SelfEncryptionStorageError, SelfEncryptionStorage>,
    _storage: Box<SelfEncryptionStorage>,
}

/// Get a Self Encryptor
#[no_mangle]
pub unsafe extern "C" fn immut_data_new_self_encryptor(app: *const App,
                                                       o_handle: *mut SelfEncryptorWriterHandle)
                                                       -> i32 {
    helper::catch_unwind_i32(|| {
        let mut se_storage = Box::new(SelfEncryptionStorage::new((*app).get_client()));
        let se = ffi_try!(SequentialEncryptor::new(mem::transmute(&mut *se_storage), None)
            .map_err(CoreError::from));

        let se_wrapper = SelfEncryptorWriterWrapper {
            se: se,
            _storage: se_storage,
        };

        let mut obj_cache = unwrap!(object_cache());
        let handle = obj_cache.new_handle();
        if obj_cache.se_writer.insert(handle, se_wrapper).is_some() {
            debug!("Displaced SelfEncryptor from ObjectCache.");
        }

        ptr::write(o_handle, handle);
        0
    })
}

/// Write to Self Encryptor
#[no_mangle]
pub unsafe extern "C" fn immut_data_write_to_self_encryptor(se_h: SelfEncryptorWriterHandle,
                                                            data: *const u8,
                                                            size: usize)
                                                            -> i32 {
    helper::catch_unwind_i32(|| {
        let data_slice = slice::from_raw_parts(data, size);
        ffi_try!(ffi_try!(unwrap!(object_cache())
                .se_writer
                .get_mut(&se_h)
                .ok_or(FfiError::InvalidSelfEncryptorHandle))
            .se
            .write(data_slice)
            .map_err(CoreError::from));

        0
    })
}

/// Close Self Encryptor
#[no_mangle]
pub unsafe extern "C" fn immut_data_close_self_encryptor(app: *const App,
                                                         se_h: SelfEncryptorWriterHandle,
                                                         cipher_opt_h: CipherOptHandle,
                                                         o_handle: *mut DataIdHandle)
                                                         -> i32 {
    helper::catch_unwind_i32(|| {
        let app = &*app;
        let client = (*app).get_client();

        let data_map = ffi_try!(ffi_try!(unwrap!(object_cache())
                .se_writer
                .get_mut(&se_h)
                .ok_or(FfiError::InvalidSelfEncryptorHandle))
            .se
            .close()
            .map_err(CoreError::from));

        let ser_data_map = ffi_try!(serialise(&data_map).map_err(FfiError::from));
        let final_immut_data =
            ffi_try!(immut_data_operations::create(client.clone(), ser_data_map, None));
        let ser_final_immut_data = ffi_try!(serialise(&final_immut_data).map_err(FfiError::from));

        let raw_data = ffi_try!(ffi_try!(unwrap!(object_cache())
                .cipher_opt
                .get_mut(&cipher_opt_h)
                .ok_or(FfiError::InvalidCipherOptHandle))
            .encrypt(app, &ser_final_immut_data));

        let raw_immut_data = ImmutableData::new(raw_data);
        let raw_immut_data_name = *raw_immut_data.name();
        let resp_getter = ffi_try!(unwrap!(client.lock())
            .put(Data::Immutable(raw_immut_data), None));
        ffi_try!(resp_getter.get());

        let data_id = DataIdentifier::Immutable(raw_immut_data_name);

        let mut obj_cache = unwrap!(object_cache());
        let handle = obj_cache.insert_data_id(data_id);
        ptr::write(o_handle, handle);

        0
    })
}

/// Fetch Self Encryptor
#[no_mangle]
pub unsafe extern "C" fn immut_data_fetch_self_encryptor(app: *const App,
                                                         data_id_h: DataIdHandle,
                                                         o_handle: *mut SelfEncryptorReaderHandle)
                                                         -> i32 {
    helper::catch_unwind_i32(|| {
        let app = &*app;
        let client = app.get_client();

        let data_id = ffi_try!(unwrap!(object_cache())
                .data_id
                .get_mut(&data_id_h)
                .ok_or(FfiError::InvalidDataIdHandle))
            .clone();

        let resp_getter = ffi_try!(unwrap!(client.lock()).get(data_id, None));
        let raw_immut_data = match ffi_try!(resp_getter.get()) {
            Data::Immutable(immut_data) => immut_data,
            _ => ffi_try!(Err(CoreError::ReceivedUnexpectedData)),
        };

        let ser_final_immut_data = ffi_try!(CipherOpt::decrypt(&app, raw_immut_data.value()));
        let final_immut_data = ffi_try!(deserialise::<ImmutableData>(&ser_final_immut_data)
            .map_err(FfiError::from));
        let ser_data_map = ffi_try!(immut_data_operations::get_data_from_immut_data(client.clone(),
                                                                    final_immut_data,
                                                                    None));

        let data_map = ffi_try!(deserialise::<DataMap>(&ser_data_map).map_err(FfiError::from));

        let mut se_storage = Box::new(SelfEncryptionStorage::new(client));
        let se = ffi_try!(SelfEncryptor::new(mem::transmute(&mut *se_storage), data_map)
            .map_err(CoreError::from));

        let se_wrapper = SelfEncryptorReaderWrapper {
            se: se,
            _storage: se_storage,
        };

        let mut obj_cache = unwrap!(object_cache());
        let handle = obj_cache.new_handle();
        if obj_cache.se_reader.insert(handle, se_wrapper).is_some() {
            debug!("Displaced SelfEncryptor from ObjectCache.");
        }

        ptr::write(o_handle, handle);
        0
    })
}

/// Get data size from Self Encryptor
#[no_mangle]
pub unsafe extern "C" fn immut_data_size(se_h: SelfEncryptorReaderHandle, o_size: *mut u64) -> i32 {
    helper::catch_unwind_i32(|| {
        let size = ffi_try!(unwrap!(object_cache())
                .se_reader
                .get_mut(&se_h)
                .ok_or(FfiError::InvalidSelfEncryptorHandle))
            .se
            .len();

        ptr::write(o_size, size);
        0
    })
}

/// Read from Self Encryptor
#[no_mangle]
pub unsafe extern "C" fn immut_data_read_from_self_encryptor(se_h: SelfEncryptorReaderHandle,
                                                             from_pos: u64,
                                                             len: u64,
                                                             o_data: *mut *mut u8,
                                                             o_size: *mut usize,
                                                             o_capacity: *mut usize)
                                                             -> i32 {
    helper::catch_unwind_i32(|| {
        let mut obj_cache = unwrap!(object_cache());
        let se_wrapper = ffi_try!(obj_cache.se_reader
            .get_mut(&se_h)
            .ok_or(FfiError::InvalidSelfEncryptorHandle));
        let se = &mut se_wrapper.se;

        if from_pos + len > se.len() {
            ffi_try!(Err(FfiError::InvalidSelfEncryptorReadOffsets));
        }

        let mut data = ffi_try!(se.read(from_pos, len).map_err(CoreError::from));

        *o_data = data.as_mut_ptr();
        ptr::write(o_size, data.len());
        ptr::write(o_capacity, data.capacity());
        mem::forget(data);

        0
    })
}

/// Free Self Encryptor Writer handle
#[no_mangle]
pub extern "C" fn immut_data_self_encryptor_writer_free(handle: SelfEncryptorWriterHandle) -> i32 {
    helper::catch_unwind_i32(|| {
        let _ = ffi_try!(unwrap!(object_cache())
            .se_writer
            .remove(&handle)
            .ok_or(FfiError::InvalidSelfEncryptorHandle));

        0
    })
}

/// Free Self Encryptor Reader handle
#[no_mangle]
pub extern "C" fn immut_data_self_encryptor_reader_free(handle: SelfEncryptorReaderHandle) -> i32 {
    helper::catch_unwind_i32(|| {
        let _ = ffi_try!(unwrap!(object_cache())
            .se_reader
            .remove(&handle)
            .ok_or(FfiError::InvalidSelfEncryptorHandle));

        0
    })
}

#[cfg(test)]
mod tests {
    use core::utility;
    use ffi::errors::FfiError;
    use ffi::low_level_api::cipher_opt::*;
    use ffi::low_level_api::data_id::data_id_free;
    use ffi::low_level_api::object_cache::object_cache;
    use ffi::test_utils;
    use std::ptr;
    use super::*;

    #[test]
    fn immut_data_operations() {
        let app_0 = test_utils::create_app(false);
        let app_1 = test_utils::create_app(false);

        let mut cipher_opt_h = 0;
        let mut se_writer_h = 0;
        let mut se_reader_h = 0;
        let mut data_id_h = 0;

        let plain_text = unwrap!(utility::generate_random_vector::<u8>(10));

        let app_1_encrypt_key_handle = {
            let mut obj_cache = unwrap!(object_cache());
            let app_1_encrypt_key_handle = obj_cache.new_handle();
            let app_1_pub_encrypt_key = unwrap!(app_1.asym_keys()).0;
            let _ = obj_cache.encrypt_key
                .insert(app_1_encrypt_key_handle, app_1_pub_encrypt_key);
            app_1_encrypt_key_handle
        };

        unsafe {
            // App-0
            assert_eq!(cipher_opt_new_asymmetric(app_1_encrypt_key_handle, &mut cipher_opt_h),
                       0);

            assert_eq!(immut_data_write_to_self_encryptor(se_writer_h,
                                                          plain_text.as_ptr(),
                                                          plain_text.len()),
                       FfiError::InvalidSelfEncryptorHandle.into());

            assert_eq!(immut_data_new_self_encryptor(&app_0, &mut se_writer_h), 0);
            assert_eq!(immut_data_write_to_self_encryptor(se_writer_h,
                                                          plain_text.as_ptr(),
                                                          plain_text.len()),
                       0);
            assert_eq!(immut_data_close_self_encryptor(&app_0,
                                                       se_writer_h,
                                                       cipher_opt_h,
                                                       &mut data_id_h),
                       0);

            assert_eq!(immut_data_self_encryptor_reader_free(se_writer_h),
                       FfiError::InvalidSelfEncryptorHandle.into());
            assert_eq!(immut_data_self_encryptor_writer_free(se_writer_h), 0);
            assert_eq!(immut_data_self_encryptor_writer_free(se_writer_h),
                       FfiError::InvalidSelfEncryptorHandle.into());

            // App-1
            let mut size = 0;
            assert_eq!(immut_data_size(se_reader_h, &mut size),
                       FfiError::InvalidSelfEncryptorHandle.into());
            assert_eq!(immut_data_size(se_writer_h, &mut size),
                       FfiError::InvalidSelfEncryptorHandle.into());

            assert!(immut_data_fetch_self_encryptor(&app_0, data_id_h, &mut se_reader_h) != 0);
            assert_eq!(immut_data_self_encryptor_reader_free(se_reader_h),
                       FfiError::InvalidSelfEncryptorHandle.into());

            assert_eq!(immut_data_fetch_self_encryptor(&app_1, data_id_h, &mut se_reader_h),
                       0);
            assert_eq!(immut_data_size(se_reader_h, &mut size), 0);
            assert_eq!(size, plain_text.len() as u64);

            let mut data_ptr: *mut u8 = ptr::null_mut();
            let mut data_size = 0;
            let mut capacity = 0;
            assert_eq!(immut_data_read_from_self_encryptor(se_reader_h,
                                                           1,
                                                           size,
                                                           &mut data_ptr,
                                                           &mut data_size,
                                                           &mut capacity),
                       FfiError::InvalidSelfEncryptorReadOffsets.into());
            assert_eq!(immut_data_read_from_self_encryptor(se_reader_h,
                                                           0,
                                                           size,
                                                           &mut data_ptr,
                                                           &mut data_size,
                                                           &mut capacity),
                       0);
            let plain_text_rx =
                Vec::from_raw_parts(data_ptr, data_size, capacity);
            assert_eq!(plain_text, plain_text_rx);

            assert_eq!(immut_data_self_encryptor_reader_free(se_reader_h), 0);
            assert_eq!(immut_data_self_encryptor_reader_free(se_reader_h),
                       FfiError::InvalidSelfEncryptorHandle.into());

            assert_eq!(cipher_opt_free(cipher_opt_h), 0);
            assert_eq!(data_id_free(data_id_h), 0);
        }
    }
}
