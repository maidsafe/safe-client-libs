// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net
// Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3,
// depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project
// generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0.
// This, along with the
// Licenses can be found in the root directory of this project at LICENSE,
// COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network
// Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
// OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions
// and limitations
// relating to use of the SAFE Network Software.

//! Operations on file writer

use core::{Client, FutureExt, SelfEncryptionStorage};
use ffi::{App, AppHandle, FfiError, FfiFuture, OpaqueCtx, Session, helper};
use futures::Future;
use nfs::helper::file_helper;
use nfs::helper::writer::Mode;
use nfs::helper::writer::Writer as InnerWriter;
use std::{ptr, slice};
use std::os::raw::c_void;

/// File writer.
pub struct Writer {
    inner: InnerWriter,
}

unsafe impl Send for Writer {}

impl Writer {
    fn close(self) -> Box<FfiFuture<()>> {
        Box::new(self.inner.close().map_err(FfiError::from).map(|_dir| ()))
    }
}

/// Create new file and return a NFS Writer handle to it.
#[no_mangle]
pub unsafe extern "C" fn nfs_create_file(session: *const Session,
                                         app_handle: AppHandle,
                                         file_path: *const u8,
                                         file_path_len: usize,
                                         user_metadata: *const u8,
                                         user_metadata_len: usize,
                                         is_path_shared: bool,
                                         is_versioned: bool,
                                         user_data: *mut c_void,
                                         o_cb: extern "C" fn(*mut c_void, i32, *mut Writer)) {
    helper::catch_unwind_cb(user_data, o_cb, || {
        trace!("FFI get nfs writer for creating a new file.");

        let file_path = helper::c_utf8_to_str(file_path, file_path_len)?;
        let user_metadata = helper::u8_ptr_to_vec(user_metadata, user_metadata_len);

        let user_data = OpaqueCtx(user_data);

        (*session).send(move |client, obj_cache| {
            match obj_cache.get_app(app_handle) {
                Ok(app) => {
                    let fut = create_file(&client,
                                          &app,
                                          file_path,
                                          user_metadata,
                                          is_path_shared,
                                          is_versioned)
                        .map(move |writer| {
                            let writer_handle = Box::into_raw(Box::new(writer));
                            o_cb(user_data.0, 0, writer_handle);
                        })
                        .map_err(move |e| {
                            o_cb(user_data.0, ffi_error_code!(e), ptr::null_mut());
                        })
                        .into_box();
                    Some(fut)
                }
                Err(e) => {
                    o_cb(user_data.0, ffi_error_code!(e), ptr::null_mut());
                    None
                }
            }
        })
    })
}

/// Obtain NFS writer handle for writing data to a file in streaming mode
#[no_mangle]
pub unsafe extern "C" fn nfs_writer_open(session: *const Session,
                                         app_handle: AppHandle,
                                         file_path: *const u8,
                                         file_path_len: usize,
                                         is_path_shared: bool,
                                         user_data: *mut c_void,
                                         o_cb: extern "C" fn(*mut c_void, i32, *mut Writer)) {
    helper::catch_unwind_cb(user_data, o_cb, || {
        trace!("FFI get nfs writer for modification of existing file.");
        let file_path = helper::c_utf8_to_str(file_path, file_path_len)?;

        let user_data = OpaqueCtx(user_data);

        (*session).send(move |client, obj_cache| {
            match obj_cache.get_app(app_handle) {
                Ok(app) => {
                    let fut = writer_open(&client, &app, file_path, is_path_shared)
                        .map(move |writer| {
                            let writer_handle = Box::into_raw(Box::new(writer));
                            o_cb(user_data.0, 0, writer_handle);
                        })
                        .map_err(move |e| {
                            o_cb(user_data.0, ffi_error_code!(e), ptr::null_mut());
                        })
                        .into_box();
                    Some(fut)
                }
                Err(e) => {
                    o_cb(user_data.0, ffi_error_code!(e), ptr::null_mut());
                    None
                }
            }
        })
    })
}

/// Write data to the Network using the NFS Writer handle
#[no_mangle]
pub unsafe extern "C" fn nfs_writer_write(session: *const Session,
                                          writer_handle: *mut Writer,
                                          data: *const u8,
                                          len: usize,
                                          user_data: *mut c_void,
                                          o_cb: extern "C" fn(*mut c_void, i32)) {
    helper::catch_unwind_cb(user_data, o_cb, || {
        trace!("FFI Write data using nfs writer.");

        let data = slice::from_raw_parts(data, len);

        let user_data = OpaqueCtx(user_data);
        let writer_handle = OpaqueCtx(writer_handle as *mut _);

        (*session).send(move |_, _| {
            let writer_handle: *mut Writer = writer_handle.0 as *mut _;
            Some((*writer_handle)
                .inner
                .write(&data[..])
                .then(move |res| {
                    o_cb(user_data.0, ffi_result_code!(res));
                    Ok(())
                })
                .into_box())
        })
    })
}

/// Closes the NFS Writer handle
#[no_mangle]
pub unsafe extern "C" fn nfs_writer_close(session: *const Session,
                                          writer_handle: *mut Writer,
                                          user_data: *mut c_void,
                                          o_cb: extern "C" fn(*mut c_void, i32)) {
    helper::catch_unwind_cb(user_data, o_cb, || {
        trace!("FFI Close and consume nfs writer.");

        let writer = *Box::from_raw(writer_handle);

        let user_data = OpaqueCtx(user_data);

        (*session).send(move |_, _| {
            Some(writer.close()
                .then(move |res| {
                    o_cb(user_data.0, ffi_result_code!(res));
                    Ok(())
                })
                .into_box())
        })
    })
}

fn create_file(client: &Client,
               app: &App,
               file_path: &str,
               user_metadata: Vec<u8>,
               is_path_shared: bool,
               is_versioned: bool)
               -> Box<FfiFuture<Writer>> {
    let c2 = client.clone();

    helper::dir_and_file(&client, app, file_path, is_path_shared)
        .and_then(move |(dir, dir_meta, filename)| {
            file_helper::create(c2,
                                filename,
                                user_metadata,
                                dir_meta.id(),
                                dir,
                                is_versioned)
                .map_err(FfiError::from)
        })
        .map(move |inner| Writer { inner: inner })
        .into_box()
}

fn writer_open(client: &Client,
               app: &App,
               file_path: &str,
               is_path_shared: bool)
               -> Box<FfiFuture<Writer>> {
    let c2 = client.clone();

    helper::dir_and_file(&client.clone(), app, file_path, is_path_shared)
        .and_then(move |(dir, dir_meta, filename)| {
            let file = fry!(dir.find_file(&filename).cloned().ok_or(FfiError::InvalidPath));
            let storage = SelfEncryptionStorage::new(c2.clone());
            InnerWriter::new(c2, storage, Mode::Modify, dir_meta.id(), dir, file)
                .map_err(FfiError::from)
                .into_box()
        })
        .map(move |inner| Writer { inner: inner })
        .into_box()
}

#[cfg(test)]
mod tests {
    use core::FutureExt;
    use ffi::test_utils;
    use futures::Future;
    use nfs::helper::{dir_helper, file_helper};
    use std::str;
    use std::sync::mpsc;
    use std::time::Duration;

    #[test]
    fn create_file() {
        const METADATA: &'static str = "user metadata";

        let sess = test_utils::create_session();
        let app = test_utils::create_app(&sess, false);
        let app_dir_id = unwrap!(app.app_dir());

        let (tx, rx) = mpsc::channel::<()>();
        let tx2 = tx.clone();

        unwrap!(sess.send(move |client, _| {
            let c2 = client.clone();
            let c3 = client.clone();

            let fut = super::create_file(&client.clone(),
                                         &app,
                                         "/test_file.txt",
                                         METADATA.as_bytes().to_vec(),
                                         false,
                                         false)
                .then(move |res| {
                    let writer = unwrap!(res, "can't create /test_file.txt");
                    writer.inner
                        .write("hello world".as_bytes())
                        .then(move |res| {
                            let _ = unwrap!(res, "can't write data to /test_file.txt");
                            writer.close()
                        })
                })
                .then(move |res| {
                    let _ = unwrap!(res, "can't close writer");
                    dir_helper::get(c2, &app_dir_id)
                })
                .then(move |res| {
                    let app_dir = unwrap!(res, "can't get app dir");
                    let file = unwrap!(app_dir.find_file("test_file.txt"));
                    let reader = unwrap!(file_helper::read(c3, file.metadata()));
                    let size = reader.size();
                    reader.read(0, size)
                })
                .then(move |res| {
                    let content = unwrap!(res);
                    let content = unwrap!(str::from_utf8(&content));
                    assert_eq!(content, "hello world");

                    unwrap!(tx2.send(()));
                    Ok(())
                })
                .into_box();
            Some(fut)
        }));

        let _ = unwrap!(rx.recv_timeout(Duration::from_secs(15)));
    }
}
