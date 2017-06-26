// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement.  This, along with the Licenses can be
// found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use super::cipher_opt::CipherOpt;
use App;
use errors::AppError;
use ffi_utils::{FFI_RESULT_OK, FfiResult, OpaqueCtx, catch_unwind_cb, vec_clone_from_raw_parts};
use futures::Future;
use maidsafe_utilities::serialisation::{deserialise, serialise};
use object_cache::{CipherOptHandle, SelfEncryptorReaderHandle, SelfEncryptorWriterHandle};
use routing::{XOR_NAME_LEN, XorName};
use safe_core::{FutureExt, SelfEncryptionStorage, immutable_data};
use self_encryption::{SelfEncryptor, SequentialEncryptor};
use std::os::raw::c_void;
use std::ptr;

type SEWriterHandle = SelfEncryptorWriterHandle;
type SEReaderHandle = SelfEncryptorReaderHandle;
type XorNamePtr = *const [u8; XOR_NAME_LEN];

/// Get a Self Encryptor
#[no_mangle]
pub unsafe extern "C" fn idata_new_self_encryptor(app: *const App,
                                                  user_data: *mut c_void,
                                                  o_cb: extern "C" fn(*mut c_void,
                                                                      FfiResult,
                                                                      SEWriterHandle)) {
    let user_data = OpaqueCtx(user_data);

    catch_unwind_cb(user_data, o_cb, || {
        (*app).send(move |client, context| {
            let se_storage = SelfEncryptionStorage::new(client.clone());
            let context = context.clone();

            let fut = SequentialEncryptor::new(se_storage, None)
                .map_err(AppError::from)
                .map(move |se| {
                         let handle = context.object_cache().insert_se_writer(se);
                         o_cb(user_data.0, FFI_RESULT_OK, handle);
                     })
                .map_err(move |e| {
                    let (error_code, description) = ffi_error!(e);
                    o_cb(user_data.0,
                         FfiResult {
                             error_code,
                             description: description.as_ptr(),
                         },
                         0);
                })
                .into_box();

            Some(fut)
        })
    });
}

/// Write to Self Encryptor
#[no_mangle]
pub unsafe extern "C" fn idata_write_to_self_encryptor(app: *const App,
                                                       se_h: SEWriterHandle,
                                                       data: *const u8,
                                                       size: usize,
                                                       user_data: *mut c_void,
                                                       o_cb: extern "C" fn(*mut c_void,
                                                                           FfiResult)) {
    let user_data = OpaqueCtx(user_data);

    catch_unwind_cb(user_data, o_cb, || {
        let data_slice = vec_clone_from_raw_parts(data, size);

        (*app).send(move |_, context| {
            let fut = {
                match context.object_cache().get_se_writer(se_h) {
                    Ok(writer) => writer.write(&data_slice),
                    Err(e) => {
                        let (error_code, description) = ffi_error!(e);
                        o_cb(user_data.0,
                             FfiResult {
                                 error_code,
                                 description: description.as_ptr(),
                             });
                        return None;
                    }
                }
            };
            let fut = fut.map_err(AppError::from)
                .then(move |res| {
                    let (error_code, description) = ffi_result!(res);
                    o_cb(user_data.0,
                         FfiResult {
                             error_code,
                             description: description.as_ptr(),
                         });
                    Ok(())
                })
                .into_box();
            Some(fut)
        })
    });
}

/// Close Self Encryptor
#[no_mangle]
pub unsafe extern "C" fn idata_close_self_encryptor(app: *const App,
                                                    se_h: SEWriterHandle,
                                                    cipher_opt_h: CipherOptHandle,
                                                    user_data: *mut c_void,
                                                    o_cb: extern "C" fn(*mut c_void,
                                                                        FfiResult,
                                                                        XorNamePtr)) {
    let user_data = OpaqueCtx(user_data);

    catch_unwind_cb(user_data, o_cb, || {
        (*app).send(move |client, context| {
            let client2 = client.clone();
            let client3 = client.clone();
            let context2 = context.clone();

            let se_writer = try_cb!(context.object_cache().remove_se_writer(se_h),
                                    user_data,
                                    o_cb);

            se_writer
                .close()
                .map_err(AppError::from)
                .and_then(move |(data_map, _)| {
                    let ser_data_map = serialise(&data_map)?;
                    let enc_data_map = {
                        let cipher_opt = context2.object_cache().get_cipher_opt(cipher_opt_h)?;
                        cipher_opt.encrypt(&ser_data_map, &context2)?
                    };

                    Ok(enc_data_map)
                })
                .and_then(move |enc_data_map| {
                              immutable_data::create(&client2, &enc_data_map, None)
                                  .map_err(AppError::from)
                          })
                .and_then(move |data| {
                              let name = *data.name();

                              client3
                                  .put_idata(data)
                                  .map_err(AppError::from)
                                  .map(move |_| name)
                          })
                .then(move |result| {
                    match result {
                        Ok(name) => o_cb(user_data.0, FFI_RESULT_OK, &name.0),
                        Err(e) => {
                            let (error_code, description) = ffi_error!(e);
                            o_cb(user_data.0,
                                 FfiResult {
                                     error_code,
                                     description: description.as_ptr(),
                                 },
                                 ptr::null())
                        }
                    }
                    Ok(())
                })
                .into_box()
                .into()
        })
    });
}

/// Fetch Self Encryptor
#[no_mangle]
pub unsafe extern "C" fn idata_fetch_self_encryptor(app: *const App,
                                                    name: XorNamePtr,
                                                    user_data: *mut c_void,
                                                    o_cb: extern "C" fn(*mut c_void,
                                                                        FfiResult,
                                                                        SEReaderHandle)) {
    catch_unwind_cb(user_data, o_cb, || {
        let user_data = OpaqueCtx(user_data);
        let name = XorName(*name);

        (*app).send(move |client, context| {
            let client2 = client.clone();
            let client3 = client.clone();
            let context2 = context.clone();
            let context3 = context.clone();

            immutable_data::get_value(client, &name, None)
                .map_err(AppError::from)
                .and_then(move |enc_data_map| {
                              let ser_data_map =
                                  CipherOpt::decrypt(&enc_data_map, &context2, &client2)?;
                              let data_map = deserialise(&ser_data_map)?;

                              Ok(data_map)
                          })
                .and_then(move |data_map| {
                              let se_storage = SelfEncryptionStorage::new(client3);
                              SelfEncryptor::new(se_storage, data_map).map_err(AppError::from)
                          })
                .map(move |se_reader| {
                         let handle = context3.object_cache().insert_se_reader(se_reader);
                         o_cb(user_data.0, FFI_RESULT_OK, handle);
                     })
                .map_err(move |e| {
                    let (error_code, description) = ffi_error!(e);
                    o_cb(user_data.0,
                         FfiResult {
                             error_code,
                             description: description.as_ptr(),
                         },
                         0);
                })
                .into_box()
                .into()
        })
    });
}

/// Get serialised size of `ImmutableData`
#[no_mangle]
pub unsafe extern "C" fn idata_serialised_size(app: *const App,
                                               name: XorNamePtr,
                                               user_data: *mut c_void,
                                               o_cb: extern "C" fn(*mut c_void, FfiResult, u64)) {
    let user_data = OpaqueCtx(user_data);

    catch_unwind_cb(user_data, o_cb, || {
        let name = XorName(*name);

        (*app).send(move |client, _| {
            client
                .get_idata(name)
                .map(move |idata| o_cb(user_data.0, FFI_RESULT_OK, idata.serialised_size()))
                .map_err(move |e| {
                    let e = AppError::from(e);
                    let (error_code, description) = ffi_error!(e);
                    o_cb(user_data.0,
                         FfiResult {
                             error_code,
                             description: description.as_ptr(),
                         },
                         0);
                })
                .into_box()
                .into()
        })
    });
}

/// Get data size from Self Encryptor
#[no_mangle]
pub unsafe extern "C" fn idata_size(app: *const App,
                                    se_h: SEReaderHandle,
                                    user_data: *mut c_void,
                                    o_cb: extern "C" fn(*mut c_void, FfiResult, u64)) {
    let user_data = OpaqueCtx(user_data);

    catch_unwind_cb(user_data, o_cb, || {
        (*app).send(move |_, context| {
            match context.object_cache().get_se_reader(se_h) {
                Ok(se) => {
                    o_cb(user_data.0, FFI_RESULT_OK, se.len());
                }
                Err(e) => {
                    let (error_code, description) = ffi_error!(e);
                    o_cb(user_data.0,
                         FfiResult {
                             error_code,
                             description: description.as_ptr(),
                         },
                         0);
                }
            };
            None
        })
    });
}

/// Read from Self Encryptor
/// Callback parameters are: user data, error code, data, size, capacity
#[no_mangle]
pub unsafe extern "C" fn idata_read_from_self_encryptor(app: *const App,
                                                        se_h: SEReaderHandle,
                                                        from_pos: u64,
                                                        len: u64,
                                                        user_data: *mut c_void,
                                                        o_cb: extern "C" fn(*mut c_void,
                                                                            FfiResult,
                                                                            *const u8,
                                                                            usize)) {
    let user_data = OpaqueCtx(user_data);

    catch_unwind_cb(user_data, o_cb, || {
        (*app).send(move |_, context| {
            let se = match context.object_cache().get_se_reader(se_h) {
                Ok(r) => r,
                Err(e) => {
                    let (error_code, description) = ffi_error!(e);
                    o_cb(user_data.0,
                         FfiResult {
                             error_code,
                             description: description.as_ptr(),
                         },
                         ptr::null(),
                         0);
                    return None;
                }
            };

            if from_pos + len > se.len() {
                let (error_code, description) =
                    ffi_error!(AppError::InvalidSelfEncryptorReadOffsets);
                o_cb(user_data.0,
                     FfiResult {
                         error_code,
                         description: description.as_ptr(),
                     },
                     ptr::null_mut(),
                     0);
                return None;
            }

            let fut = se.read(from_pos, len)
                .map(move |data| { o_cb(user_data.0, FFI_RESULT_OK, data.as_ptr(), data.len()); })
                .map_err(AppError::from)
                .map_err(move |e| {
                    let (error_code, description) = ffi_error!(e);
                    o_cb(user_data.0,
                         FfiResult {
                             error_code,
                             description: description.as_ptr(),
                         },
                         ptr::null(),
                         0);
                })
                .into_box();

            Some(fut)
        })
    });
}

/// Free Self Encryptor Writer handle
#[no_mangle]
pub unsafe extern "C" fn idata_self_encryptor_writer_free(app: *const App,
                                                          handle: SEWriterHandle,
                                                          user_data: *mut c_void,
                                                          o_cb: extern "C" fn(*mut c_void,
                                                                              FfiResult)) {
    let user_data = OpaqueCtx(user_data);

    catch_unwind_cb(user_data, o_cb, || {
        (*app).send(move |_, context| {
            let res = context.object_cache().remove_se_writer(handle);
            let (error_code, description) = ffi_result!(res);
            o_cb(user_data.0,
                 FfiResult {
                     error_code,
                     description: description.as_ptr(),
                 });
            None
        })
    });
}

/// Free Self Encryptor Reader handle
#[no_mangle]
pub unsafe extern "C" fn idata_self_encryptor_reader_free(app: *const App,
                                                          handle: SEReaderHandle,
                                                          user_data: *mut c_void,
                                                          o_cb: extern "C" fn(*mut c_void,
                                                                              FfiResult)) {
    let user_data = OpaqueCtx(user_data);

    catch_unwind_cb(user_data, o_cb, || {
        (*app).send(move |_, context| {
            let res = context.object_cache().remove_se_reader(handle);
            let (error_code, description) = ffi_result!(res);
            o_cb(user_data.0,
                 FfiResult {
                     error_code,
                     description: description.as_ptr(),
                 });
            None
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use errors::AppError;
    use ffi::cipher_opt::*;
    use ffi_utils::ErrorCode;
    use ffi_utils::test_utils::{call_0, call_1, call_vec_u8};
    use routing::XOR_NAME_LEN;
    use safe_core::utils;
    use test_utils::create_app;

    #[test]
    fn immut_data_operations() {
        let app = create_app();

        let plain_text = unwrap!(utils::generate_random_vector::<u8>(10));

        unsafe {
            let cipher_opt_h = unwrap!(call_1(|ud, cb| cipher_opt_new_symmetric(&app, ud, cb)));
            let se_writer_h = unwrap!(call_1(|ud, cb| idata_new_self_encryptor(&app, ud, cb)));

            let res = call_0(|ud, cb| {
                                 idata_write_to_self_encryptor(&app,
                                                               0,
                                                               plain_text.as_ptr(),
                                                               plain_text.len(),
                                                               ud,
                                                               cb)
                             });
            assert_eq!(res, Err(AppError::InvalidSelfEncryptorHandle.error_code()));

            unwrap!(call_0(|ud, cb| {
                               idata_write_to_self_encryptor(&app,
                                                             se_writer_h,
                                                             plain_text.as_ptr(),
                                                             plain_text.len(),
                                                             ud,
                                                             cb)
                           }));

            let name: [u8; XOR_NAME_LEN];
            name = unwrap!(call_1(|ud, cb| {
                                      idata_close_self_encryptor(&app,
                                                                 se_writer_h,
                                                                 cipher_opt_h,
                                                                 ud,
                                                                 cb)
                                  }));

            // It should've been closed by immut_data_close_self_encryptor
            let res = call_0(|ud, cb| idata_self_encryptor_writer_free(&app, se_writer_h, ud, cb));
            assert_eq!(res, Err(AppError::InvalidSelfEncryptorHandle.error_code()));

            // Invalid Self encryptor reader.
            let res: Result<u64, _> = call_1(|ud, cb| idata_size(&app, 0, ud, cb));
            assert_eq!(res, Err(AppError::InvalidSelfEncryptorHandle.error_code()));

            // Invalid Self encryptor reader.
            let res: Result<u64, _> = call_1(|ud, cb| idata_size(&app, se_writer_h, ud, cb));
            assert_eq!(res, Err(AppError::InvalidSelfEncryptorHandle.error_code()));

            // Invalid Self encryptor reader.
            let res: u64 = unwrap!(call_1(|ud, cb| idata_serialised_size(&app, &name, ud, cb)));
            assert!(res > 0);

            let se_reader_h = {
                unwrap!(call_1(|ud, cb| idata_fetch_self_encryptor(&app, &name, ud, cb)))
            };

            let size = unwrap!(call_1(|ud, cb| idata_size(&app, se_reader_h, ud, cb)));
            assert_eq!(size, plain_text.len() as u64);

            let res =
                call_vec_u8(|ud, cb| {
                                idata_read_from_self_encryptor(&app, se_reader_h, 1, size, ud, cb)
                            });
            assert_eq!(res,
                       Err(AppError::InvalidSelfEncryptorReadOffsets.error_code()));

            let received_plain_text;
            received_plain_text =
                call_vec_u8(|ud, cb| {
                                idata_read_from_self_encryptor(&app, se_reader_h, 0, size, ud, cb)
                            });
            assert_eq!(plain_text, unwrap!(received_plain_text));

            unwrap!(call_0(|ud, cb| idata_self_encryptor_reader_free(&app, se_reader_h, ud, cb)));

            let res = call_0(|ud, cb| idata_self_encryptor_reader_free(&app, se_reader_h, ud, cb));
            assert_eq!(res, Err(AppError::InvalidSelfEncryptorHandle.error_code()));

            unwrap!(call_0(|ud, cb| cipher_opt_free(&app, cipher_opt_h, ud, cb)));
        }
    }
}
