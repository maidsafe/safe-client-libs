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

//! File operations

use core::futures::FutureExt;
use dns::operations;
use ffi::{FfiError, OpaqueCtx, Session};
use ffi::file_details::{FileDetails, FileMetadata};
use ffi::helper;
use futures::Future;
use nfs::helper::dir_helper;
use std::os::raw::c_void;
use std::ptr;

/// Get file.
#[no_mangle]
pub unsafe extern "C" fn dns_get_file(session: *const Session,
                                      long_name: *const u8,
                                      long_name_len: usize,
                                      service_name: *const u8,
                                      service_name_len: usize,
                                      file_path: *const u8,
                                      file_path_len: usize,
                                      offset: i64,
                                      length: i64,
                                      include_metadata: bool,
                                      user_data: *mut c_void,
                                      o_cb: extern "C" fn(*mut c_void, i32, *mut FileDetails)) {
    helper::catch_unwind_cb(user_data, o_cb, || {
        let long_name = helper::c_utf8_to_string(long_name, long_name_len)?;
        let service_name = helper::c_utf8_to_string(service_name, service_name_len)?;
        let file_path = helper::c_utf8_to_string(file_path, file_path_len)?;

        trace!("FFI get file located at given path starting from home directory of \"//{}.{}\".",
               service_name,
               long_name);

        let user_data = OpaqueCtx(user_data);

        (*session).send(move |client, _| {
            let client2 = client.clone();
            let client3 = client.clone();

            let fut = operations::get_service_home_dir_id(client, &long_name, service_name, None)
                .map_err(FfiError::from)
                .and_then(move |dir_id| {
                    dir_helper::get_file_by_path(&client2, Some(&dir_id), &file_path)
                        .map_err(FfiError::from)
                })
                .and_then(move |file| {
                    FileDetails::new(file, client3, offset, length, include_metadata)
                })
                .map(move |details| {
                    let details = Box::into_raw(Box::new(details));
                    o_cb(user_data.0, 0, details);
                })
                .map_err(move |err| {
                    o_cb(user_data.0, ffi_error_code!(err), ptr::null_mut());
                })
                .into_box();

            Some(fut)
        })
    })
}

/// Get file metadata.
#[no_mangle]
pub unsafe extern "C" fn dns_get_file_metadata(session: *const Session,
                                               long_name: *const u8,
                                               long_name_len: usize,
                                               service_name: *const u8,
                                               service_name_len: usize,
                                               file_path: *const u8,
                                               file_path_len: usize,
                                               user_data: *mut c_void,
                                               o_cb: extern "C" fn(*mut c_void,
                                                                   i32,
                                                                   *mut FileMetadata)) {
    helper::catch_unwind_cb(user_data, o_cb, || {
        let long_name = helper::c_utf8_to_string(long_name, long_name_len)?;
        let service_name = helper::c_utf8_to_string(service_name, service_name_len)?;
        let file_path = helper::c_utf8_to_string(file_path, file_path_len)?;

        trace!("FFI get file metadata for file located at given path starting from home \
                directory of \"//{}.{}\".",
               service_name,
               long_name);

        let user_data = OpaqueCtx(user_data);

        (*session).send(move |client, _| {
            let client2 = client.clone();

            let fut = operations::get_service_home_dir_id(client, &long_name, service_name, None)
                .map_err(FfiError::from)
                .and_then(move |dir_id| {
                    dir_helper::get_file_by_path(&client2, Some(&dir_id), &file_path)
                        .map_err(FfiError::from)
                })
                .and_then(move |file| {
                    let metadata = FileMetadata::new(file.metadata())?;
                    let metadata = Box::into_raw(Box::new(metadata));
                    o_cb(user_data.0, 0, metadata);
                    Ok(())
                })
                .map_err(move |err| {
                    o_cb(user_data.0, ffi_error_code!(err), ptr::null_mut());
                })
                .into_box();

            Some(fut)
        })
    })
}

#[cfg(test)]
mod tests {
    use core::utility;
    use dns::operations;
    use ffi::Session;
    use ffi::file_details::FileDetails;
    use ffi::test_utils;
    use futures::Future;
    use nfs::DirId;
    use nfs::helper::{dir_helper, file_helper};
    use rust_sodium::crypto::box_;
    use std::os::raw::c_void;
    use std::sync::mpsc;
    use super::*;

    fn create_public_file(session: &Session, file_name: String, file_content: Vec<u8>) -> DirId {
        test_utils::run(session, |client, _| {
            let c2 = client.clone();
            let c3 = client.clone();

            dir_helper::user_root_dir(client.clone())
                .then(move |res| {
                    let (parent, parent_id) = unwrap!(res);
                    dir_helper::create_sub_dir(c2, "dir", None, Vec::new(), &parent, &parent_id)
                })
                .then(move |result| {
                    let (_parent, dir, dir_meta) = unwrap!(result);
                    file_helper::create(c3, file_name, Vec::new(), dir_meta.id(), dir, false)
                        .map(move |writer| (writer, dir_meta.id()))
                })
                .then(move |result| {
                    let (writer, dir_id) = unwrap!(result);
                    writer.write(&file_content).map(move |_| (writer, dir_id))
                })
                .then(move |result| {
                    let (writer, dir_id) = unwrap!(result);
                    writer.close().map(move |_| dir_id)
                })
        })
    }

    fn register_service(session: &Session,
                        long_name: String,
                        service_name: String,
                        service_dir_id: DirId) {
        test_utils::run(session, move |client, _| {
            let (msg_pk, msg_sk) = box_::gen_keypair();
            let (sign_pk, sign_sk) = unwrap!(client.signing_keypair());
            let services = vec![(service_name, service_dir_id)];

            operations::register_dns(client,
                                     long_name,
                                     msg_pk,
                                     msg_sk,
                                     &services,
                                     vec![sign_pk],
                                     sign_sk,
                                     None)
        })
    }

    #[test]
    fn get_public_file() {
        let session = test_utils::create_session();

        let file_name = "index.html".to_string();
        let file_content = "<html><title>Home</title></html>";

        let public_dir_id = create_public_file(&session,
                                               file_name.clone(),
                                               file_content.as_bytes().to_vec());

        let long_name = unwrap!(utility::generate_random_string(10));
        let service_name = "www".to_string();

        register_service(&session,
                         long_name.clone(),
                         service_name.clone(),
                         public_dir_id);

        let (tx, rx) = mpsc::channel::<()>();

        let long_name = test_utils::as_raw_parts(&long_name);
        let service_name = test_utils::as_raw_parts(&service_name);
        let file_name = test_utils::as_raw_parts(&file_name);

        extern "C" fn callback(user_data: *mut c_void,
                               error: i32,
                               _file_details_ptr: *mut FileDetails) {
            assert_eq!(error, 0);
            unsafe { test_utils::send_via_user_data(user_data, ()) }
        }

        unsafe {
            dns_get_file(&session,
                         long_name.ptr,
                         long_name.len,
                         service_name.ptr,
                         service_name.len,
                         file_name.ptr,
                         file_name.len,
                         0,
                         0,
                         false,
                         test_utils::sender_as_user_data(&tx),
                         callback);
        };
        let _ = unwrap!(rx.recv());

        // Fetch the file using a new client
        let session2 = test_utils::create_session();

        unsafe {
            dns_get_file(&session2,
                         long_name.ptr,
                         long_name.len,
                         service_name.ptr,
                         service_name.len,
                         file_name.ptr,
                         file_name.len,
                         0,
                         0,
                         false,
                         test_utils::sender_as_user_data(&tx),
                         callback);
        };
        let _ = unwrap!(rx.recv());

        // Fetch the file using an unregisterd client
        let session3 = test_utils::create_unregistered_session();

        unsafe {
            dns_get_file(&session3,
                         long_name.ptr,
                         long_name.len,
                         service_name.ptr,
                         service_name.len,
                         file_name.ptr,
                         file_name.len,
                         0,
                         0,
                         false,
                         test_utils::sender_as_user_data(&tx),
                         callback);
        };
        let _ = unwrap!(rx.recv());
    }
}
