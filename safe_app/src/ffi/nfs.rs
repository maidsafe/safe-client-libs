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

use {App, AppContext};
use errors::AppError;
use ffi::helper::send;
use ffi_utils::{FFI_RESULT_OK, FfiResult, OpaqueCtx, ReprC, SafePtr, catch_unwind_cb, from_c_str,
                vec_clone_from_raw_parts};
use futures::Future;
use futures::future::{self, Either};
use object_cache::FileContextHandle;
use safe_core::{FutureExt, MDataInfo};
use safe_core::ffi::MDataInfo as FfiMDataInfo;
use safe_core::ffi::nfs::File;
use safe_core::nfs::{Mode, Reader, Writer, file_helper};
use safe_core::nfs::File as NativeFile;
use std::os::raw::{c_char, c_void};

/// Holds context for file operations, depending on the mode.
pub struct FileContext {
    reader: Option<Reader<AppContext>>,
    writer: Option<Writer<AppContext>>,
    original_file: NativeFile,
}

/// Replaces the entire content of the file when writing data.
pub static OPEN_MODE_OVERWRITE: u64 = 1;
/// Appends to existing data in the file.
pub static OPEN_MODE_APPEND: u64 = 2;
/// Open file to read.
pub static OPEN_MODE_READ: u64 = 4;
/// Read entire contents of a file.
pub static FILE_READ_TO_END: u64 = 0;

/// Retrieve file with the given name, and its version, from the directory.
///
/// Callback parameters: user data, error code, file, version
#[no_mangle]
pub unsafe extern "C" fn dir_fetch_file(
    app: *const App,
    parent_info: *const FfiMDataInfo,
    file_name: *const c_char,
    user_data: *mut c_void,
    o_cb: extern "C" fn(user_data: *mut c_void,
                        result: *const FfiResult,
                        file: *const File,
                        version: u64),
) {
    catch_unwind_cb(user_data, o_cb, || {
        let parent_info = MDataInfo::clone_from_repr_c(parent_info)?;
        let file_name = from_c_str(file_name)?;
        let user_data = OpaqueCtx(user_data);

        (*app).send(move |client, _| {
            file_helper::fetch(client.clone(), parent_info, file_name)
                .map(move |(version, file)| {
                    let ffi_file = file.into_repr_c();
                    o_cb(user_data.0, FFI_RESULT_OK, &ffi_file, version)
                })
                .map_err(AppError::from)
                .map_err(move |err| {
                    call_result_cb!(Err::<(), _>(err), user_data, o_cb);
                })
                .into_box()
                .into()
        })
    })
}

/// Insert the file into the parent directory.
///
/// Callback parameters: user data, error code
#[no_mangle]
pub unsafe extern "C" fn dir_insert_file(
    app: *const App,
    parent_info: *const FfiMDataInfo,
    file_name: *const c_char,
    file: *const File,
    user_data: *mut c_void,
    o_cb: extern "C" fn(user_data: *mut c_void, result: *const FfiResult),
) {
    catch_unwind_cb(user_data, o_cb, || {
        let parent_info = MDataInfo::clone_from_repr_c(parent_info)?;
        let file = NativeFile::clone_from_repr_c(file)?;
        let file_name = from_c_str(file_name)?;

        send(app, user_data, o_cb, move |client, _| {
            file_helper::insert(client.clone(), parent_info, file_name, &file)
        })
    })
}

/// Replace the file in the parent directory.
/// If `version` is 0, the correct version is obtained automatically.
///
/// Callback parameters: user data, error code
#[no_mangle]
pub unsafe extern "C" fn dir_update_file(
    app: *const App,
    parent_info: *const FfiMDataInfo,
    file_name: *const c_char,
    file: *const File,
    version: u64,
    user_data: *mut c_void,
    o_cb: extern "C" fn(user_data: *mut c_void, result: *const FfiResult),
) {
    catch_unwind_cb(user_data, o_cb, || {
        let parent_info = MDataInfo::clone_from_repr_c(parent_info)?;
        let file = NativeFile::clone_from_repr_c(file)?;
        let file_name = from_c_str(file_name)?;

        send(app, user_data, o_cb, move |client, _| {
            file_helper::update(client.clone(), parent_info, file_name, &file, version)
        })
    })
}

/// Delete the file in the parent directory.
///
/// Callback parameters: user data, error code
#[no_mangle]
pub unsafe extern "C" fn dir_delete_file(
    app: *const App,
    parent_info: *const FfiMDataInfo,
    file_name: *const c_char,
    version: u64,
    user_data: *mut c_void,
    o_cb: extern "C" fn(user_data: *mut c_void, result: *const FfiResult),
) {
    catch_unwind_cb(user_data, o_cb, || {
        let parent_info = MDataInfo::clone_from_repr_c(parent_info)?;
        let file_name = from_c_str(file_name)?;

        send(app, user_data, o_cb, move |client, _| {
            file_helper::delete(client, &parent_info, file_name, version)
        })
    })
}

/// Open the file to read of write its contents.
///
/// Callback parameters: user data, error code, file context handle
#[no_mangle]
pub unsafe extern "C" fn file_open(
    app: *const App,
    parent_info: *const FfiMDataInfo,
    file: *const File,
    open_mode: u64,
    user_data: *mut c_void,
    o_cb: extern "C" fn(user_data: *mut c_void,
                        result: *const FfiResult,
                        file_h: FileContextHandle),
) {
    catch_unwind_cb(user_data, o_cb, || {
        let parent_info = MDataInfo::clone_from_repr_c(parent_info)?;
        let file = NativeFile::clone_from_repr_c(file)?;

        send(app, user_data, o_cb, move |client, context| {
            let context = context.clone();
            let original_file = file.clone();

            // Initialise the reader if OPEN_MODE_READ is requested
            let reader = if open_mode & OPEN_MODE_READ != 0 {
                let fut = file_helper::read(client.clone(), &file, parent_info.enc_key().cloned())
                    .map(Some);
                Either::A(fut)
            } else {
                Either::B(future::ok(None))
            };

            // Initialise the writer if one of write modes is requested
            let writer = if open_mode & (OPEN_MODE_OVERWRITE | OPEN_MODE_APPEND) != 0 {
                let writer_mode = if open_mode & OPEN_MODE_APPEND != 0 {
                    Mode::Append
                } else {
                    Mode::Overwrite
                };
                let fut = file_helper::write(
                    client.clone(),
                    file,
                    writer_mode,
                    parent_info.enc_key().cloned(),
                ).map(Some);
                Either::A(fut)
            } else {
                Either::B(future::ok(None))
            };

            reader.join(writer).map(move |(reader, writer)| {
                let file_ctx = FileContext {
                    reader,
                    writer,
                    original_file,
                };
                context.object_cache().insert_file(file_ctx)
            })
        })
    })
}

/// Get a size of file opened for read.
///
/// Callback parameters: user data, error code, file size
#[no_mangle]
pub unsafe extern "C" fn file_size(
    app: *const App,
    file_h: FileContextHandle,
    user_data: *mut c_void,
    o_cb: extern "C" fn(user_data: *mut c_void, result: *const FfiResult, size: u64),
) {
    catch_unwind_cb(user_data, o_cb, || {
        let user_data = OpaqueCtx(user_data);

        (*app).send(move |_client, context| {
            let file_ctx = try_cb!(context.object_cache().get_file(file_h), user_data, o_cb);

            if let Some(ref reader) = file_ctx.reader {
                o_cb(user_data.0, FFI_RESULT_OK, reader.size());
            } else {
                call_result_cb!(Err::<(), _>(AppError::InvalidFileMode), user_data, o_cb);
            }
            None
        })
    })
}

/// Read data from file.
///
/// Callback parameters: user data, error code, file data vector, vector size
#[no_mangle]
pub unsafe extern "C" fn file_read(
    app: *const App,
    file_h: FileContextHandle,
    position: u64,
    len: u64,
    user_data: *mut c_void,
    o_cb: extern "C" fn(user_data: *mut c_void,
                        result: *const FfiResult,
                        data_ptr: *const u8,
                        data_len: usize),
) {
    catch_unwind_cb(user_data, o_cb, || {
        let user_data = OpaqueCtx(user_data);

        (*app).send(move |_client, context| {
            let file_ctx = try_cb!(context.object_cache().get_file(file_h), user_data, o_cb);

            if let Some(ref reader) = file_ctx.reader {
                reader
                    .read(
                        position,
                        if len == FILE_READ_TO_END {
                            reader.size() - position
                        } else {
                            len
                        },
                    )
                    .map(move |data| {
                        o_cb(user_data.0, FFI_RESULT_OK, data.as_safe_ptr(), data.len());
                    })
                    .map_err(move |err| {
                        call_result_cb!(Err::<(), _>(AppError::from(err)), user_data, o_cb);
                    })
                    .into_box()
                    .into()
            } else {
                call_result_cb!(Err::<(), _>(AppError::InvalidFileMode), user_data, o_cb);
                None
            }
        })
    })
}

/// Write data to file in smaller chunks.
///
/// Callback parameters: user data, error code
#[no_mangle]
pub unsafe extern "C" fn file_write(
    app: *const App,
    file_h: FileContextHandle,
    data: *const u8,
    data_len: usize,
    user_data: *mut c_void,
    o_cb: extern "C" fn(user_data: *mut c_void, result: *const FfiResult),
) {
    catch_unwind_cb(user_data, o_cb, || {
        let user_data = OpaqueCtx(user_data);
        let data = vec_clone_from_raw_parts(data, data_len);

        (*app).send(move |_client, context| {
            let file_ctx = try_cb!(context.object_cache().get_file(file_h), user_data, o_cb);

            if let Some(ref writer) = file_ctx.writer {
                writer
                    .write(&data)
                    .then(move |res| {
                        call_result_cb!(res.map_err(AppError::from), user_data, o_cb);
                        Ok(())
                    })
                    .into_box()
                    .into()
            } else {
                call_result_cb!(Err::<(), _>(AppError::InvalidFileMode), user_data, o_cb);
                None
            }
        })
    })
}

/// Close is invoked only after all the data is completely written. The
/// file is saved only when `close` is invoked.
///
/// If the file was opened in any of the read modes, returns the modified
/// file structure as a result. If the file was opened in the read mode,
/// returns the original file structure that was passed as an argument to
/// `file_open`.
///
/// Frees the file context handle.
///
/// Callback parameters: user data, error code, file
#[no_mangle]
pub unsafe extern "C" fn file_close(
    app: *const App,
    file_h: FileContextHandle,
    user_data: *mut c_void,
    o_cb: extern "C" fn(user_data: *mut c_void,
                        result: *const FfiResult,
                        file: *const File),
) {
    catch_unwind_cb(user_data, o_cb, || {
        let user_data = OpaqueCtx(user_data);

        (*app).send(move |_client, context| {
            let file_ctx = try_cb!(context.object_cache().remove_file(file_h), user_data, o_cb);

            if let Some(writer) = file_ctx.writer {
                writer
                    .close()
                    .map(move |file| {
                        o_cb(user_data.0, FFI_RESULT_OK, &file.into_repr_c());
                    })
                    .map_err(move |err| {
                        call_result_cb!(Err::<(), _>(AppError::from(err)), user_data, o_cb);
                    })
                    .into_box()
                    .into()
            } else {
                // The reader will be dropped automatically
                o_cb(
                    user_data.0,
                    FFI_RESULT_OK,
                    &file_ctx.original_file.into_repr_c(),
                );
                None
            }
        })
    })
}
