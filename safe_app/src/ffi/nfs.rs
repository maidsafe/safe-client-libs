// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use client::AppClient;
use errors::AppError;
use ffi::helper::send;
use ffi::object_cache::FileContextHandle;
use ffi_utils::{
    catch_unwind_cb, from_c_str, vec_clone_from_raw_parts, FfiResult, OpaqueCtx, ReprC, SafePtr,
    FFI_RESULT_OK,
};
use futures::future::{self, Either};
use futures::Future;
use safe_core::ffi::nfs::File;
use safe_core::ffi::MDataInfo;
use safe_core::nfs::file_helper::{self, Version};
use safe_core::nfs::File as NativeFile;
use safe_core::nfs::{Mode, Reader, Writer};
use safe_core::{FutureExt, MDataInfo as NativeMDataInfo};
use std::os::raw::{c_char, c_void};
use App;

/// Holds context for file operations, depending on the mode.
pub struct FileContext {
    reader: Option<Reader<AppClient>>,
    writer: Option<Writer<AppClient>>,
    original_file: NativeFile,
}

/// Constant to pass to `dir_update_file()` or `dir_delete_file()` when the next version should be
/// retrieved and used automatically.
pub const GET_NEXT_VERSION: u64 = 0;

/// Replaces the entire content of the file when writing data.
pub static OPEN_MODE_OVERWRITE: u64 = 1;
/// Appends to existing data in the file.
pub static OPEN_MODE_APPEND: u64 = 2;
/// Open file to read.
pub static OPEN_MODE_READ: u64 = 4;
/// Read entire contents of a file.
pub static FILE_READ_TO_END: u64 = 0;

/// Retrieve file with the given name, and its version, from the directory.
#[no_mangle]
pub unsafe extern "C" fn dir_fetch_file(
    app: *const App,
    parent_info: *const MDataInfo,
    file_name: *const c_char,
    user_data: *mut c_void,
    o_cb: extern "C" fn(
        user_data: *mut c_void,
        result: *const FfiResult,
        file: *const File,
        version: u64,
    ),
) {
    catch_unwind_cb(user_data, o_cb, || {
        let parent_info = NativeMDataInfo::clone_from_repr_c(parent_info)?;
        let file_name = from_c_str(file_name)?;
        let user_data = OpaqueCtx(user_data);

        (*app).send(move |client, _| {
            file_helper::fetch(client.clone(), parent_info, file_name)
                .map(move |(version, file)| {
                    let ffi_file = file.into_repr_c();
                    o_cb(user_data.0, FFI_RESULT_OK, &ffi_file, version)
                }).map_err(AppError::from)
                .map_err(move |err| {
                    call_result_cb!(Err::<(), _>(err), user_data, o_cb);
                }).into_box()
                .into()
        })
    })
}

/// Insert the file into the parent directory.
#[no_mangle]
pub unsafe extern "C" fn dir_insert_file(
    app: *const App,
    parent_info: *const MDataInfo,
    file_name: *const c_char,
    file: *const File,
    user_data: *mut c_void,
    o_cb: extern "C" fn(user_data: *mut c_void, result: *const FfiResult),
) {
    catch_unwind_cb(user_data, o_cb, || {
        let parent_info = NativeMDataInfo::clone_from_repr_c(parent_info)?;
        let file = NativeFile::clone_from_repr_c(file)?;
        let file_name = from_c_str(file_name)?;

        send(app, user_data, o_cb, move |client, _| {
            file_helper::insert(client.clone(), parent_info, file_name, &file)
        })
    })
}

/// Replace the file in the parent directory.
///
/// If `version` is `GET_NEXT_VERSION`, the correct version is obtained automatically.
#[no_mangle]
pub unsafe extern "C" fn dir_update_file(
    app: *const App,
    parent_info: *const MDataInfo,
    file_name: *const c_char,
    file: *const File,
    version: u64,
    user_data: *mut c_void,
    o_cb: extern "C" fn(user_data: *mut c_void, result: *const FfiResult, new_version: u64),
) {
    catch_unwind_cb(user_data, o_cb, || {
        let parent_info = NativeMDataInfo::clone_from_repr_c(parent_info)?;
        let file = NativeFile::clone_from_repr_c(file)?;
        let file_name = from_c_str(file_name)?;

        send(app, user_data, o_cb, move |client, _| {
            let version = if version == GET_NEXT_VERSION {
                Version::GetNext
            } else {
                Version::Custom(version)
            };
            file_helper::update(client.clone(), parent_info, file_name, &file, version)
        })
    })
}

/// Delete the file in the parent directory.
///
/// If `version` is `GET_NEXT_VERSION`, the correct version is obtained automatically.
#[no_mangle]
pub unsafe extern "C" fn dir_delete_file(
    app: *const App,
    parent_info: *const MDataInfo,
    file_name: *const c_char,
    version: u64,
    user_data: *mut c_void,
    o_cb: extern "C" fn(user_data: *mut c_void, result: *const FfiResult, new_version: u64),
) {
    catch_unwind_cb(user_data, o_cb, || {
        let parent_info = NativeMDataInfo::clone_from_repr_c(parent_info)?;
        let file_name = from_c_str(file_name)?;

        send(app, user_data, o_cb, move |client, _| {
            let version = if version == GET_NEXT_VERSION {
                Version::GetNext
            } else {
                Version::Custom(version)
            };
            file_helper::delete(client.clone(), parent_info, file_name, version)
        })
    })
}

/// Open the file to read or write its contents.
#[no_mangle]
pub unsafe extern "C" fn file_open(
    app: *const App,
    parent_info: *const MDataInfo,
    file: *const File,
    open_mode: u64,
    user_data: *mut c_void,
    o_cb: extern "C" fn(
        user_data: *mut c_void,
        result: *const FfiResult,
        file_h: FileContextHandle,
    ),
) {
    catch_unwind_cb(user_data, o_cb, || {
        let parent_info = NativeMDataInfo::clone_from_repr_c(parent_info)?;
        let file = NativeFile::clone_from_repr_c(file)?;

        send(app, user_data, o_cb, move |client, context| {
            let context = context.clone();
            let original_file = file.clone();

            // Initialise the reader if OPEN_MODE_READ is requested.
            let reader = if open_mode & OPEN_MODE_READ != 0 {
                let fut = file_helper::read(client.clone(), &file, parent_info.enc_key().cloned())
                    .map(Some);
                Either::A(fut)
            } else {
                Either::B(future::ok(None))
            };

            // Initialise the writer if one of write modes is requested.
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
#[no_mangle]
pub unsafe extern "C" fn file_read(
    app: *const App,
    file_h: FileContextHandle,
    position: u64,
    len: u64,
    user_data: *mut c_void,
    o_cb: extern "C" fn(
        user_data: *mut c_void,
        result: *const FfiResult,
        data: *const u8,
        data_len: usize,
    ),
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
                    ).map(move |data| {
                        o_cb(user_data.0, FFI_RESULT_OK, data.as_safe_ptr(), data.len());
                    }).map_err(move |err| {
                        call_result_cb!(Err::<(), _>(AppError::from(err)), user_data, o_cb);
                    }).into_box()
                    .into()
            } else {
                call_result_cb!(Err::<(), _>(AppError::InvalidFileMode), user_data, o_cb);
                None
            }
        })
    })
}

/// Write data to file in smaller chunks.
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
                    }).into_box()
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
#[no_mangle]
pub unsafe extern "C" fn file_close(
    app: *const App,
    file_h: FileContextHandle,
    user_data: *mut c_void,
    o_cb: extern "C" fn(user_data: *mut c_void, result: *const FfiResult, file: *const File),
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
                    }).map_err(move |err| {
                        call_result_cb!(Err::<(), _>(AppError::from(err)), user_data, o_cb);
                    }).into_box()
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
