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

use core::{CoreError, FutureExt, SelfEncryptionStorage, immutable_data};
use ffi::{AppHandle, CipherOptHandle, DataIdHandle, SelfEncryptorReaderHandle,
          SelfEncryptorWriterHandle};
use ffi::{FfiError, OpaqueCtx, Session};
use ffi::helper::catch_unwind_cb;
use ffi::low_level_api::cipher_opt::CipherOpt;
use futures::Future;
use maidsafe_utilities::serialisation::{deserialise, serialise};
use routing::{Data, DataIdentifier, ImmutableData};
use self_encryption::{DataMap, SelfEncryptor, SequentialEncryptor};
use std::{mem, ptr, slice};
use std::os::raw::c_void;

type SEWriterHandle = SelfEncryptorWriterHandle;
type SEReaderHandle = SelfEncryptorReaderHandle;

/// Get a Self Encryptor
#[no_mangle]
pub unsafe extern "C" fn immut_data_new_self_encryptor(session: *const Session,
                                                       user_data: *mut c_void,
                                                       o_cb: unsafe extern "C" fn(*mut c_void,
                                                                                  i32,
                                                                                  SEWriterHandle)) {
    let user_data = OpaqueCtx(user_data);

    catch_unwind_cb(user_data, o_cb, || {
        (*session).send(move |client, obj_cache| {
            let se_storage = SelfEncryptionStorage::new(client.clone());
            let obj_cache = obj_cache.clone();

            let fut = SequentialEncryptor::new(se_storage, None)
                .map_err(CoreError::from)
                .map(move |se| {
                    let handle = obj_cache.insert_se_writer(se);
                    o_cb(user_data.0, 0, handle);
                })
                .map_err(move |e| {
                    o_cb(user_data.0, ffi_error_code!(e), 0);
                })
                .into_box();

            Some(fut)
        })
    });
}

/// Write to Self Encryptor
#[no_mangle]
pub unsafe extern "C" fn immut_data_write_to_self_encryptor(session: *const Session,
                                                            se_h: SEWriterHandle,
                                                            data: *const u8,
                                                            size: usize,
                                                            user_data: *mut c_void,
                                                            o_cb: unsafe extern "C" fn(*mut c_void,
                                                                                       i32)) {
    let user_data = OpaqueCtx(user_data);

    catch_unwind_cb(user_data, o_cb, || {
        let data_slice = slice::from_raw_parts(data, size);

        (*session).send(move |_, obj_cache| {
            let fut = {
                match obj_cache.get_se_writer(se_h) {
                    Ok(writer) => writer.write(data_slice),
                    Err(e) => {
                        o_cb(user_data.0, ffi_error_code!(e));
                        return None;
                    }
                }
            };
            let fut = fut.map_err(CoreError::from)
                .then(move |res| {
                    o_cb(user_data.0, ffi_result_code!(res));
                    Ok(())
                })
                .into_box();
            Some(fut)
        })
    });
}

/// Close Self Encryptor
#[no_mangle]
pub unsafe extern "C" fn immut_data_close_self_encryptor(session: *const Session,
                                                         app: AppHandle,
                                                         se_h: SEWriterHandle,
                                                         cipher_opt_h: CipherOptHandle,
                                                         user_data: *mut c_void,
                                                         o_cb: unsafe extern "C" fn(*mut c_void,
                                                                                    i32,
                                                                                    DataIdHandle)) {
    let user_data = OpaqueCtx(user_data);

    catch_unwind_cb(user_data, o_cb, || {
        (*session).send(move |client, obj_cache| {
            let fut = {
                match obj_cache.remove_se_writer(se_h) {
                    Ok(se_wrapper) => se_wrapper.close(),
                    Err(e) => {
                        o_cb(user_data.0, ffi_error_code!(e), 0);
                        return None;
                    }
                }
            };

            let c2 = client.clone();
            let c3 = client.clone();

            let obj_cache = obj_cache.clone();

            let fut = fut.map_err(CoreError::from)
                .map_err(FfiError::from)
                .and_then(move |(data_map, _)| {
                    let ser_data_map = fry!(serialise(&data_map));
                    immutable_data::create(&c2, ser_data_map, None)
                        .map_err(FfiError::from)
                        .into_box()
                })
                .and_then(move |final_immut_data| {
                    let ser_final_immut_data = fry!(serialise(&final_immut_data));

                    let raw_data = {
                        let app = fry!(obj_cache.get_app(app)).clone();
                        let cipher_opt = fry!(obj_cache.get_cipher_opt(cipher_opt_h));
                        fry!(cipher_opt.encrypt(&app, &ser_final_immut_data))
                    };

                    let raw_immut_data = ImmutableData::new(raw_data);
                    let raw_immut_data_name = *raw_immut_data.name();

                    c3.put(Data::Immutable(raw_immut_data), None)
                        .map_err(FfiError::from)
                        .map(move |_| {
                            let data_id = DataIdentifier::Immutable(raw_immut_data_name);
                            obj_cache.insert_data_id(data_id)
                        })
                        .into_box()
                })
                .then(move |result| {
                    match result {
                        Ok(handle) => o_cb(user_data.0, 0, handle),
                        Err(e) => o_cb(user_data.0, ffi_error_code!(e), 0),
                    }
                    Ok(())
                })
                .into_box();

            Some(fut)
        })
    });
}

/// Fetch Self Encryptor
#[no_mangle]
pub unsafe extern "C" fn immut_data_fetch_self_encryptor(session: *const Session,
                                                         app: AppHandle,
                                                         data_id_h: DataIdHandle,
                                                         user_data: *mut c_void,
                                                         o_cb: unsafe extern "C" fn(
                                                             *mut c_void,
                                                             i32,
                                                             SEReaderHandle)) {
    let user_data = OpaqueCtx(user_data);

    catch_unwind_cb(user_data, o_cb, || {
        (*session).send(move |client, obj_cache| {
            let c2 = client.clone();
            let c3 = client.clone();

            let obj_cache2 = obj_cache.clone();
            let obj_cache3 = obj_cache.clone();

            let fut = {
                match obj_cache.get_data_id(data_id_h) {
                    Ok(data_id) => client.get(*data_id, None),
                    Err(e) => {
                        o_cb(user_data.0, ffi_error_code!(e), 0);
                        return None;
                    }
                }
            };

            let fut = fut.map_err(FfiError::from)
                .and_then(move |data| {
                    let raw_immut_data = match data {
                        Data::Immutable(immut_data) => immut_data,
                        _ => fry!(Err(CoreError::ReceivedUnexpectedData)),
                    };

                    let ser_final_immut_data = {
                        let app = fry!(obj_cache2.get_app(app));
                        fry!(CipherOpt::decrypt(&app, raw_immut_data.value()))
                    };

                    let final_immut_data =
                        fry!(deserialise::<ImmutableData>(&ser_final_immut_data));

                    immutable_data::extract_value(&c2, final_immut_data, None)
                        .map_err(FfiError::from)
                        .into_box()
                })
                .and_then(move |ser_data_map| {
                    let data_map = deserialise::<DataMap>(&ser_data_map)?;

                    let se_storage = SelfEncryptionStorage::new(c3);

                    SelfEncryptor::new(se_storage, data_map)
                        .map_err(CoreError::from)
                        .map_err(FfiError::from)
                })
                .map(move |se_wrapper| {
                    let handle = obj_cache3.insert_se_reader(se_wrapper);
                    o_cb(user_data.0, 0, handle);
                })
                .map_err(move |e| {
                    o_cb(user_data.0, ffi_error_code!(e), 0);
                })
                .into_box();
            Some(fut)
        })
    });
}

/// Get data size from Self Encryptor
#[no_mangle]
pub unsafe extern "C" fn immut_data_size(session: *const Session,
                                         se_h: SEReaderHandle,
                                         user_data: *mut c_void,
                                         o_cb: unsafe extern "C" fn(*mut c_void, i32, u64)) {
    let user_data = OpaqueCtx(user_data);

    catch_unwind_cb(user_data, o_cb, || {
        (*session).send(move |_, obj_cache| {
            match obj_cache.get_se_reader(se_h) {
                Ok(se) => {
                    o_cb(user_data.0, 0, se.len());
                }
                Err(e) => {
                    o_cb(user_data.0, ffi_error_code!(e), 0);
                }
            };
            None
        })
    });
}

/// Read from Self Encryptor
/// Callback parameters are: user_data, error_code, data, size, capacity
#[no_mangle]
pub unsafe extern "C" fn immut_data_read_from_self_encryptor(session: *const Session,
                                                             se_h: SEReaderHandle,
                                                             from_pos: u64,
                                                             len: u64,
                                                             user_data: *mut c_void,
                                                             o_cb: unsafe extern "C" fn(*mut c_void,
                                                                                        i32,
                                                                                        *mut u8,
                                                                                        usize,
                                                                                        usize)) {
    let user_data = OpaqueCtx(user_data);

    catch_unwind_cb(user_data, o_cb, || {
        (*session).send(move |_, obj_cache| {
            let se = match obj_cache.get_se_reader(se_h) {
                Ok(r) => r,
                Err(e) => {
                    o_cb(user_data.0, ffi_error_code!(e), ptr::null_mut(), 0, 0);
                    return None;
                }
            };

            if from_pos + len > se.len() {
                o_cb(user_data.0,
                     ffi_error_code!(FfiError::InvalidSelfEncryptorReadOffsets),
                     ptr::null_mut(),
                     0,
                     0);
                return None;
            }

            let fut = se.read(from_pos, len)
                .map(move |mut data| {
                    let size = data.len();
                    let capacity = data.capacity();
                    o_cb(user_data.0, 0, data.as_mut_ptr(), size, capacity);
                    mem::forget(data);
                })
                .map_err(CoreError::from)
                .map_err(move |e| {
                    o_cb(user_data.0, ffi_error_code!(e), ptr::null_mut(), 0, 0);
                })
                .into_box();

            Some(fut)
        })
    });
}

/// Free Self Encryptor Writer handle
#[no_mangle]
pub unsafe extern "C" fn immut_data_self_encryptor_writer_free(session: *const Session,
                                                               handle: SEWriterHandle,
                                                               user_data: *mut c_void,
                                                               o_cb: unsafe
                                                               extern "C" fn(*mut c_void,
                                                                             i32)) {
    let user_data = OpaqueCtx(user_data);

    catch_unwind_cb(user_data, o_cb, || {
        (*session).send(move |_, obj_cache| {
            let res = obj_cache.remove_se_writer(handle);
            o_cb(user_data.0, ffi_result_code!(res));
            None
        })
    });
}

/// Free Self Encryptor Reader handle
#[no_mangle]
pub unsafe extern "C" fn immut_data_self_encryptor_reader_free(session: *const Session,
                                                               handle: SEReaderHandle,
                                                               user_data: *mut c_void,
                                                               o_cb: unsafe
                                                               extern "C" fn(*mut c_void,
                                                                             i32)) {
    let user_data = OpaqueCtx(user_data);

    catch_unwind_cb(user_data, o_cb, || {
        (*session).send(move |_, obj_cache| {
            let res = obj_cache.remove_se_reader(handle);
            o_cb(user_data.0, ffi_result_code!(res));
            None
        })
    })
}

#[cfg(test)]
mod tests {
    use core::utility;
    use ffi::{ObjectHandle, test_utils};
    use ffi::errors::FfiError;
    use ffi::low_level_api::cipher_opt::*;
    use ffi::low_level_api::data_id::data_id_free;
    use std::{panic, process};
    use std::os::raw::c_void;
    use std::sync::mpsc;
    use super::*;

    #[test]
    fn immut_data_operations() {
        let sess = test_utils::create_session();
        let app_0 = test_utils::create_app(&sess, false);
        let app_1 = test_utils::create_app(&sess, false);

        let plain_text = unwrap!(utility::generate_random_vector::<u8>(10));

        let (app_1_encrypt_key_handle, app_0, app_1) = test_utils::run_now(&sess, |_, obj_cache| {
            let app_1_pub_encrypt_key = unwrap!(app_1.asym_enc_keys()).0;
            let encrypt_key_h = obj_cache.insert_encrypt_key(app_1_pub_encrypt_key);
            let app_0_h = obj_cache.insert_app(app_0);
            let app_1_h = obj_cache.insert_app(app_1);

            (encrypt_key_h, app_0_h, app_1_h)
        });

        unsafe {
            // App-0
            let (mut err_code_tx, err_code_rx) = mpsc::channel::<i32>();
            let (mut handle_tx, handle_rx) = mpsc::channel::<(i32, ObjectHandle)>();
            let (mut data_size_tx, data_size_rx) = mpsc::channel::<(i32, u64)>();
            let (mut read_tx, read_rx) = mpsc::channel::<(i32, *mut u8, usize, usize)>();

            let err_code_tx: *mut _ = &mut err_code_tx;
            let err_code_tx = err_code_tx as *mut c_void;

            let handle_tx: *mut _ = &mut handle_tx;
            let handle_tx = handle_tx as *mut c_void;

            let data_size_tx: *mut _ = &mut data_size_tx;
            let data_size_tx = data_size_tx as *mut c_void;

            let read_tx: *mut _ = &mut read_tx;
            let read_tx = read_tx as *mut c_void;

            cipher_opt_new_asymmetric(&sess, app_1_encrypt_key_handle, handle_tx, handle_cb);
            let (err_code, cipher_opt_h) = unwrap!(handle_rx.recv());
            assert_eq!(err_code, 0);

            immut_data_new_self_encryptor(&sess, handle_tx, handle_cb);
            let (err_code, se_writer_h) = unwrap!(handle_rx.recv());
            assert_eq!(err_code, 0);

            immut_data_write_to_self_encryptor(&sess,
                                               0,
                                               plain_text.as_ptr(),
                                               plain_text.len(),
                                               err_code_tx,
                                               err_code_cb);
            assert_eq!(unwrap!(err_code_rx.recv()),
                       FfiError::InvalidSelfEncryptorHandle.into());

            immut_data_write_to_self_encryptor(&sess,
                                               se_writer_h,
                                               plain_text.as_ptr(),
                                               plain_text.len(),
                                               err_code_tx,
                                               err_code_cb);
            assert_eq!(unwrap!(err_code_rx.recv()), 0);

            immut_data_close_self_encryptor(&sess,
                                            app_0,
                                            se_writer_h,
                                            cipher_opt_h,
                                            handle_tx,
                                            handle_cb);
            let (err_code, data_id_h) = unwrap!(handle_rx.recv());
            assert_eq!(err_code, 0);

            immut_data_self_encryptor_reader_free(&sess, se_writer_h, err_code_tx, err_code_cb);
            assert_eq!(unwrap!(err_code_rx.recv()),
                       FfiError::InvalidSelfEncryptorHandle.into());

            immut_data_self_encryptor_writer_free(&sess, se_writer_h, err_code_tx, err_code_cb);
            assert_eq!(unwrap!(err_code_rx.recv()),
                       // It should've been closed by immut_data_close_self_encryptor
                       FfiError::InvalidSelfEncryptorHandle.into());

            // App-1
            let se_reader_h = 0;
            let se_writer_h = 0;
            immut_data_size(&sess, se_reader_h, data_size_tx, data_size_cb);
            let (err_code, _) = unwrap!(data_size_rx.recv());
            assert_eq!(err_code, FfiError::InvalidSelfEncryptorHandle.into());

            immut_data_size(&sess, se_writer_h, data_size_tx, data_size_cb);
            let (err_code, _) = unwrap!(data_size_rx.recv());
            assert_eq!(err_code, FfiError::InvalidSelfEncryptorHandle.into());

            immut_data_fetch_self_encryptor(&sess, app_0, data_id_h, handle_tx, handle_cb);
            let (err_code, _) = unwrap!(handle_rx.recv());
            assert!(err_code != 0);

            immut_data_self_encryptor_reader_free(&sess, se_reader_h, err_code_tx, err_code_cb);
            assert_eq!(unwrap!(err_code_rx.recv()),
                       FfiError::InvalidSelfEncryptorHandle.into());

            immut_data_fetch_self_encryptor(&sess, app_1, data_id_h, handle_tx, handle_cb);
            let (err_code, se_reader_h) = unwrap!(handle_rx.recv());
            assert_eq!(err_code, 0);

            immut_data_size(&sess, se_reader_h, data_size_tx, data_size_cb);
            let (err_code, size) = unwrap!(data_size_rx.recv());
            assert_eq!(err_code, 0);
            assert_eq!(size, plain_text.len() as u64);

            immut_data_read_from_self_encryptor(&sess, se_reader_h, 1, size, read_tx, read_cb);
            let (err_code, _, _, _) = unwrap!(read_rx.recv());
            assert_eq!(err_code, FfiError::InvalidSelfEncryptorReadOffsets.into());

            immut_data_read_from_self_encryptor(&sess, se_reader_h, 0, size, read_tx, read_cb);
            let (err_code, data_ptr, data_size, capacity) = unwrap!(read_rx.recv());
            assert_eq!(err_code, 0);
            let plain_text_rx = Vec::from_raw_parts(data_ptr, data_size, capacity);
            assert_eq!(plain_text, plain_text_rx);

            immut_data_self_encryptor_reader_free(&sess, se_reader_h, err_code_tx, err_code_cb);
            assert_eq!(unwrap!(err_code_rx.recv()), 0);

            immut_data_self_encryptor_reader_free(&sess, se_reader_h, err_code_tx, err_code_cb);
            assert_eq!(unwrap!(err_code_rx.recv()),
                       FfiError::InvalidSelfEncryptorHandle.into());

            cipher_opt_free(&sess, cipher_opt_h, err_code_tx, err_code_cb);
            assert_eq!(unwrap!(err_code_rx.recv()), 0);

            data_id_free(&sess, data_id_h, err_code_tx, err_code_cb);
            assert_eq!(unwrap!(err_code_rx.recv()), 0);
        }
    }

    unsafe extern "C" fn err_code_cb(tx: *mut c_void, error_code: i32) {
        let res = panic::catch_unwind(|| {
            let tx = tx as *mut mpsc::Sender<i32>;
            unwrap!((*tx).send(error_code));
        });
        if res.is_err() {
            process::exit(-1);
        }
    }

    unsafe extern "C" fn handle_cb(tx: *mut c_void, error_code: i32, handle: ObjectHandle) {
        let res = panic::catch_unwind(|| {
            let tx = tx as *mut mpsc::Sender<(i32, ObjectHandle)>;
            unwrap!((*tx).send((error_code, handle)));
        });
        if res.is_err() {
            process::exit(-1);
        }
    }

    unsafe extern "C" fn data_size_cb(tx: *mut c_void, error_code: i32, size: u64) {
        let res = panic::catch_unwind(|| {
            let tx = tx as *mut mpsc::Sender<(i32, u64)>;
            unwrap!((*tx).send((error_code, size)));
        });
        if res.is_err() {
            process::exit(-1);
        }
    }

    unsafe extern "C" fn read_cb(tx: *mut c_void,
                                 error_code: i32,
                                 data: *mut u8,
                                 size: usize,
                                 cap: usize) {
        let res = panic::catch_unwind(|| {
            let tx = tx as *mut mpsc::Sender<(i32, *mut u8, usize, usize)>;
            unwrap!((*tx).send((error_code, data, size, cap)));
        });
        if res.is_err() {
            process::exit(-1);
        }
    }
}
