// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use errors::AppError;
use ffi::nfs::*;
use ffi::object_cache::FileContextHandle;
use ffi_utils::test_utils::{call_0, call_1, call_2, call_vec_u8};
use ffi_utils::ErrorCode;
use futures::Future;
use safe_core::ffi::nfs::File;
use safe_core::ffi::MDataInfo;
use safe_core::ipc::Permission;
use safe_core::nfs::{File as NativeFile, NfsError};
use std;
use std::collections::HashMap;
use std::ffi::CString;
use test_utils::{create_app_by_req, create_auth_req_with_access, run};
use App;

fn setup() -> (App, MDataInfo) {
    let mut container_permissions = HashMap::new();
    let _ = container_permissions.insert(
        "_videos".to_string(),
        btree_set![
            Permission::Read,
            Permission::Insert,
            Permission::Update,
            Permission::Delete,
        ],
    );

    let app = unwrap!(create_app_by_req(&create_auth_req_with_access(
        container_permissions
    ),));

    let container_info = run(&app, move |client, context| {
        context.get_access_info(client).then(move |res| {
            let mut access_info = unwrap!(res);
            Ok(unwrap!(access_info.remove("_videos")).0)
        })
    });
    let container_info = container_info.into_repr_c();

    (app, container_info)
}

// Test the basics of NFS.
// 1. Fetching a non-existing file should fail.
// 2. Create an empty file.
// 3. Fetch it back, assert that all file info is correct.
// 4. Delete the file.
#[test]
fn basics() {
    let (app, container_info) = setup();

    let file_name0 = "file0.txt";
    let ffi_file_name0 = unwrap!(CString::new(file_name0));

    // Fetching non-existing file fails.
    let res: Result<(NativeFile, u64), i32> = unsafe {
        call_2(|ud, cb| dir_fetch_file(&app, &container_info, ffi_file_name0.as_ptr(), ud, cb))
    };

    match res {
        Err(code) if code == AppError::from(NfsError::FileNotFound).error_code() => (),
        Err(x) => panic!("Unexpected: {:?}", x),
        Ok(_) => panic!("Unexpected success"),
    }

    // Create empty file.
    let user_metadata = b"metadata".to_vec();
    let file = NativeFile::new(user_metadata.clone());
    let ffi_file = file.into_repr_c();

    unsafe {
        unwrap!(call_0(|ud, cb| dir_insert_file(
            &app,
            &container_info,
            ffi_file_name0.as_ptr(),
            &ffi_file,
            ud,
            cb,
        )))
    }

    // Fetch it back.
    let (retrieved_file, retrieved_version): (NativeFile, u64) = unsafe {
        unwrap!(call_2(|ud, cb| dir_fetch_file(
            &app,
            &container_info,
            ffi_file_name0.as_ptr(),
            ud,
            cb
        )))
    };
    assert_eq!(retrieved_file.user_metadata(), &user_metadata[..]);
    assert_eq!(retrieved_file.size(), 0);
    assert_eq!(retrieved_version, 0);

    // Delete file.
    let version: u64 = unsafe {
        unwrap!(call_1(|ud, cb| dir_delete_file(
            &app,
            &container_info,
            ffi_file_name0.as_ptr(),
            1,
            ud,
            cb
        )))
    };
    assert_eq!(version, 1);
}

// Test NFS functions for writing and updating file contents.
// 1. Create an empty file, open it for writing, write contents.
// 2. Insert file into a container.
// 3. Fetch the file from a container, check that it has a correct version.
// 4. Open the file again, now in a combined append + read mode.
// 5. Read the file contents; it should be the same as we have written it.
// Check that the file's created and modified timestamps are correct.
// 6. Append a string to a file contents (by using `OPEN_MODE_APPEND`, _not_
// by rewriting the existing data with an appended string).
// 7. Update the file in the directory.
// 8. Fetch the updated file version again and ensure that it contains
// the expected string.
// 9. Check that the file's created and modified timestamps are correct.
#[test]
fn open_file() {
    let (app, container_info) = setup();

    // Create non-empty file.
    let file = NativeFile::new(Vec::new());
    let ffi_file = file.into_repr_c();

    let file_name1 = "file1.txt";
    let ffi_file_name1 = unwrap!(CString::new(file_name1));

    let content = b"hello world";

    let write_h = unsafe {
        unwrap!(call_1(|ud, cb| file_open(
            &app,
            &container_info,
            &ffi_file,
            OPEN_MODE_OVERWRITE,
            ud,
            cb,
        )))
    };

    let size: Result<u64, i32> = unsafe { call_1(|ud, cb| file_size(&app, write_h, ud, cb)) };
    match size {
        Err(code) if code == AppError::InvalidFileMode.error_code() => (),
        Err(x) => panic!("Unexpected: {:?}", x),
        Ok(_) => panic!("Unexpected success"),
    }

    let written_file: NativeFile = unsafe {
        unwrap!(call_0(|ud, cb| file_write(
            &app,
            write_h,
            content.as_ptr(),
            content.len(),
            ud,
            cb
        )));
        unwrap!(call_1(|ud, cb| file_close(&app, write_h, ud, cb)))
    };

    let created_time = *written_file.created_time();

    // Insert file into container.
    unsafe {
        unwrap!(call_0(|ud, cb| dir_insert_file(
            &app,
            &container_info,
            ffi_file_name1.as_ptr(),
            &written_file.into_repr_c(),
            ud,
            cb,
        )))
    }

    // Fetch it back.
    let (file, version): (NativeFile, u64) = {
        unsafe {
            unwrap!(call_2(|ud, cb| dir_fetch_file(
                &app,
                &container_info,
                ffi_file_name1.as_ptr(),
                ud,
                cb
            )))
        }
    };
    assert_eq!(version, 0);

    let size0 = file.size();

    // Read the content.
    let read_write_h = unsafe {
        unwrap!(call_1(|ud, cb| file_open(
            &app,
            &container_info,
            &file.into_repr_c(),
            OPEN_MODE_READ | OPEN_MODE_APPEND,
            ud,
            cb,
        )))
    };

    let size1: u64 = unsafe { unwrap!(call_1(|ud, cb| file_size(&app, read_write_h, ud, cb))) };
    assert_eq!(size0, size1);

    let retrieved_content = unsafe {
        unwrap!(call_vec_u8(|ud, cb| file_read(
            &app,
            read_write_h,
            0,
            FILE_READ_TO_END,
            ud,
            cb
        )))
    };
    assert_eq!(retrieved_content, content);

    // Fetch the file back and compare timestamps
    let (file, _version): (NativeFile, u64) = {
        unsafe {
            unwrap!(call_2(|ud, cb| dir_fetch_file(
                &app,
                &container_info,
                ffi_file_name1.as_ptr(),
                ud,
                cb
            )))
        }
    };
    let read_created_time = *file.created_time();
    let read_modified_time = *file.modified_time();
    assert_eq!(created_time, read_created_time);
    assert!(created_time <= read_modified_time);

    // Append content
    let append_content = b" appended";

    let written_file: NativeFile = unsafe {
        unwrap!(call_0(|ud, cb| file_write(
            &app,
            read_write_h,
            append_content.as_ptr(),
            append_content.len(),
            ud,
            cb,
        )));
        unwrap!(call_1(|ud, cb| file_close(&app, read_write_h, ud, cb)))
    };

    // Update it in the dir
    let version: u64 = unsafe {
        unwrap!(call_1(|ud, cb| dir_update_file(
            &app,
            &container_info,
            ffi_file_name1.as_ptr(),
            &written_file.into_repr_c(),
            GET_NEXT_VERSION,
            ud,
            cb,
        )))
    };
    assert_eq!(version, 1);

    // Read the updated content
    let (file, version): (NativeFile, u64) = {
        unsafe {
            unwrap!(call_2(|ud, cb| dir_fetch_file(
                &app,
                &container_info,
                ffi_file_name1.as_ptr(),
                ud,
                cb
            )))
        }
    };
    assert_eq!(version, 1);

    // Check timestamps again after append and update
    assert_eq!(created_time, *file.created_time());
    assert!(read_modified_time <= *file.modified_time());

    let orig_file = file.clone();

    let read_h = unsafe {
        unwrap!(call_1(|ud, cb| file_open(
            &app,
            &container_info,
            &file.into_repr_c(),
            OPEN_MODE_READ,
            ud,
            cb,
        )))
    };

    let size: u64 = unsafe { unwrap!(call_1(|ud, cb| file_size(&app, read_h, ud, cb))) };
    assert_eq!(size, orig_file.size());

    let retrieved_content = unsafe {
        unwrap!(call_vec_u8(|ud, cb| file_read(
            &app,
            read_h,
            0,
            FILE_READ_TO_END,
            ud,
            cb
        )))
    };
    assert_eq!(retrieved_content, b"hello world appended");

    let returned_file: NativeFile =
        unsafe { unwrap!(call_1(|ud, cb| file_close(&app, read_h, ud, cb))) };

    assert_eq!(returned_file, orig_file);
}

// Test fetching files from a container.
// 1. Create a file with contents but an empty filename.
// 2. Insert file into container.
// 3. Immediately fetch it back and check the contents.
// 4. Sleep several seconds and repeat step 3.
#[test]
fn fetch_file() {
    let (app, container_info) = setup();

    // Create non-empty file.
    let file = NativeFile::new(Vec::new());
    let ffi_file = file.into_repr_c();

    let file_name1 = "";
    let ffi_file_name1 = unwrap!(CString::new(file_name1));

    let content = b"hello world";

    let write_h = unsafe {
        unwrap!(call_1(|ud, cb| file_open(
            &app,
            &container_info,
            &ffi_file,
            OPEN_MODE_OVERWRITE,
            ud,
            cb,
        )))
    };

    let written_file: NativeFile = unsafe {
        unwrap!(call_0(|ud, cb| file_write(
            &app,
            write_h,
            content.as_ptr(),
            content.len(),
            ud,
            cb
        )));
        unwrap!(call_1(|ud, cb| file_close(&app, write_h, ud, cb)))
    };

    // Insert file into container.
    unsafe {
        unwrap!(call_0(|ud, cb| dir_insert_file(
            &app,
            &container_info,
            ffi_file_name1.as_ptr(),
            &written_file.into_repr_c(),
            ud,
            cb,
        )))
    }

    // Fetch it back.
    let (file, version): (NativeFile, u64) = {
        unsafe {
            unwrap!(call_2(|ud, cb| dir_fetch_file(
                &app,
                &container_info,
                ffi_file_name1.as_ptr(),
                ud,
                cb
            )))
        }
    };
    assert_eq!(version, 0);

    let size0 = file.size();

    // Read the content
    let read_write_h = unsafe {
        unwrap!(call_1(|ud, cb| file_open(
            &app,
            &container_info,
            &file.into_repr_c(),
            OPEN_MODE_READ | OPEN_MODE_APPEND,
            ud,
            cb,
        )))
    };

    let size1: u64 = unsafe { unwrap!(call_1(|ud, cb| file_size(&app, read_write_h, ud, cb))) };
    assert_eq!(size0, size1);

    let retrieved_content = unsafe {
        unwrap!(call_vec_u8(|ud, cb| file_read(
            &app,
            read_write_h,
            0,
            FILE_READ_TO_END,
            ud,
            cb
        )))
    };
    assert_eq!(retrieved_content, content);

    std::thread::sleep(std::time::Duration::new(2, 0));

    // Fetch it back.
    let (file, version): (NativeFile, u64) = {
        unsafe {
            unwrap!(call_2(|ud, cb| dir_fetch_file(
                &app,
                &container_info,
                ffi_file_name1.as_ptr(),
                ud,
                cb
            )))
        }
    };
    assert_eq!(version, 0);

    let size0 = file.size();

    // Read the content.
    let read_write_h = unsafe {
        unwrap!(call_1(|ud, cb| file_open(
            &app,
            &container_info,
            &file.into_repr_c(),
            OPEN_MODE_READ | OPEN_MODE_APPEND,
            ud,
            cb,
        )))
    };

    let size1: u64 = unsafe { unwrap!(call_1(|ud, cb| file_size(&app, read_write_h, ud, cb))) };
    assert_eq!(size0, size1);

    let retrieved_content = unsafe {
        unwrap!(call_vec_u8(|ud, cb| file_read(
            &app,
            read_write_h,
            0,
            FILE_READ_TO_END,
            ud,
            cb
        )))
    };
    assert_eq!(retrieved_content, content);
}

// Test that NFS functions still work after deleting and updating file contents.
// 1. Create an empty file, open it for writing, write original contents.
// 2. Insert file into the container.
// 3. Delete file in the container.
// 4. Create non-empty file with new contents.
// 5. Update the file in the container with new contents and version.
// 6. Fetch the file from the container, check that it has the updated version.
// 7. Read the file contents and ensure that they correspond to the data from step 4.
#[test]
fn delete_then_open_file() {
    let (app, container_info) = setup();

    // Create non-empty file.
    let file = NativeFile::new(Vec::new());
    let ffi_file = file.into_repr_c();

    let file_name2 = "file2.txt";
    let ffi_file_name2 = unwrap!(CString::new(file_name2));

    let content_original = b"hello world";

    let write_h = unsafe {
        unwrap!(call_1(|ud, cb| file_open(
            &app,
            &container_info,
            &ffi_file,
            OPEN_MODE_OVERWRITE,
            ud,
            cb,
        )))
    };

    let written_file: NativeFile = unsafe {
        unwrap!(call_0(|ud, cb| file_write(
            &app,
            write_h,
            content_original.as_ptr(),
            content_original.len(),
            ud,
            cb,
        )));
        unwrap!(call_1(|ud, cb| file_close(&app, write_h, ud, cb)))
    };

    // Insert file into container.
    unsafe {
        unwrap!(call_0(|ud, cb| dir_insert_file(
            &app,
            &container_info,
            ffi_file_name2.as_ptr(),
            &written_file.into_repr_c(),
            ud,
            cb,
        )))
    }

    // Delete file.
    let version: u64 = unsafe {
        unwrap!(call_1(|ud, cb| dir_delete_file(
            &app,
            &container_info,
            ffi_file_name2.as_ptr(),
            GET_NEXT_VERSION,
            ud,
            cb
        )))
    };
    assert_eq!(version, 1);

    // Create new non-empty file.
    let file = NativeFile::new(Vec::new());
    let ffi_file = file.into_repr_c();

    let content_new = b"hello goodbye";

    let write_h = unsafe {
        unwrap!(call_1(|ud, cb| file_open(
            &app,
            &container_info,
            &ffi_file,
            OPEN_MODE_OVERWRITE,
            ud,
            cb,
        )))
    };

    let new_file: NativeFile = unsafe {
        unwrap!(call_0(|ud, cb| file_write(
            &app,
            write_h,
            content_new.as_ptr(),
            content_new.len(),
            ud,
            cb,
        )));
        unwrap!(call_1(|ud, cb| file_close(&app, write_h, ud, cb)))
    };

    // Update file in container.
    let version: u64 = unsafe {
        unwrap!(call_1(|ud, cb| dir_update_file(
            &app,
            &container_info,
            ffi_file_name2.as_ptr(),
            &new_file.into_repr_c(),
            2,
            ud,
            cb,
        )))
    };
    assert_eq!(version, 2);

    // Fetch the file.
    let (file, version): (NativeFile, u64) = {
        unsafe {
            unwrap!(call_2(|ud, cb| dir_fetch_file(
                &app,
                &container_info,
                ffi_file_name2.as_ptr(),
                ud,
                cb
            )))
        }
    };
    assert_eq!(version, 2);

    // Read the content.
    let read_write_h = unsafe {
        unwrap!(call_1(|ud, cb| file_open(
            &app,
            &container_info,
            &file.into_repr_c(),
            OPEN_MODE_READ | OPEN_MODE_APPEND,
            ud,
            cb,
        )))
    };

    let retrieved_content = unsafe {
        unwrap!(call_vec_u8(|ud, cb| file_read(
            &app,
            read_write_h,
            0,
            FILE_READ_TO_END,
            ud,
            cb
        )))
    };
    assert_eq!(retrieved_content, content_new);
}

// Test closing files immediately after opening them in the different modes.
// 1. Create a new file, close it, and insert it into a container.
// 2. Fetch it, open it in READ mode, and close it.
// 3. Open the file in OVERWRITE mode and close it.
// 4. Open the file in APPEND mode and close it.
#[test]
fn open_close_file() {
    let (app, container_info) = setup();

    let file_name = "file0.txt";
    let ffi_file_name = unwrap!(CString::new(file_name));

    // Create a file.
    let user_metadata = b"metadata".to_vec();
    let file = NativeFile::new(user_metadata.clone());
    let ffi_file = file.into_repr_c();

    let content = b"hello world";

    let write_h = unsafe {
        unwrap!(call_1(|ud, cb| file_open(
            &app,
            &container_info,
            &ffi_file,
            OPEN_MODE_OVERWRITE,
            ud,
            cb,
        )))
    };

    // Write to the file, close it and insert it.
    let written_file: NativeFile = unsafe {
        unwrap!(call_0(|ud, cb| file_write(
            &app,
            write_h,
            content.as_ptr(),
            content.len(),
            ud,
            cb
        )));
        unwrap!(call_1(|ud, cb| file_close(&app, write_h, ud, cb)))
    };

    unsafe {
        unwrap!(call_0(|ud, cb| dir_insert_file(
            &app,
            &container_info,
            ffi_file_name.as_ptr(),
            &written_file.into_repr_c(),
            ud,
            cb,
        )))
    }

    // Fetch the file
    let (file, _version): (NativeFile, u64) = {
        unsafe {
            unwrap!(call_2(|ud, cb| dir_fetch_file(
                &app,
                &container_info,
                ffi_file_name.as_ptr(),
                ud,
                cb
            )))
        }
    };

    // Open in READ mode.
    let read_h = unsafe {
        unwrap!(call_1(|ud, cb| file_open(
            &app,
            &container_info,
            &file.into_repr_c(),
            OPEN_MODE_READ,
            ud,
            cb,
        )))
    };
    // Close the file.
    let _: *const File = unsafe { unwrap!(call_1(|ud, cb| file_close(&app, read_h, ud, cb))) };

    // Fetch the file
    let (file, _version): (NativeFile, u64) = {
        unsafe {
            unwrap!(call_2(|ud, cb| dir_fetch_file(
                &app,
                &container_info,
                ffi_file_name.as_ptr(),
                ud,
                cb
            )))
        }
    };

    // Open in OVERWRITE mode and close the file.
    let write_h = unsafe {
        unwrap!(call_1(|ud, cb| file_open(
            &app,
            &container_info,
            &file.into_repr_c(),
            OPEN_MODE_OVERWRITE,
            ud,
            cb,
        )))
    };

    let _: NativeFile = unsafe { unwrap!(call_1(|ud, cb| file_close(&app, write_h, ud, cb))) };

    // Fetch the file
    let (file, _version): (NativeFile, u64) = {
        unsafe {
            unwrap!(call_2(|ud, cb| dir_fetch_file(
                &app,
                &container_info,
                ffi_file_name.as_ptr(),
                ud,
                cb
            )))
        }
    };

    // Open in APPEND mode and close the file.
    let append_h = unsafe {
        unwrap!(call_1(|ud, cb| file_open(
            &app,
            &container_info,
            &file.into_repr_c(),
            OPEN_MODE_APPEND,
            ud,
            cb,
        )))
    };

    let _: NativeFile = unsafe { unwrap!(call_1(|ud, cb| file_close(&app, append_h, ud, cb))) };
}

// Open a file in all modes simultaneously.
#[test]
fn file_open_read_write() {
    let (app, container_info) = setup();

    // Create empty file.
    let file = NativeFile::new(Vec::new());
    let ffi_file = file.into_repr_c();

    let initial_content = b"";
    let content = b"hello world";

    // Write to the file first because we can't open a non-existent file for reading.
    let write_h = unsafe {
        unwrap!(call_1(|ud, cb| file_open(
            &app,
            &container_info,
            &ffi_file,
            OPEN_MODE_OVERWRITE,
            ud,
            cb,
        )))
    };

    let written_file: NativeFile = unsafe {
        unwrap!(call_0(|ud, cb| file_write(
            &app,
            write_h,
            initial_content.as_ptr(),
            initial_content.len(),
            ud,
            cb
        )));
        unwrap!(call_1(|ud, cb| file_close(&app, write_h, ud, cb)))
    };

    // Open with ALL the modes.
    let read_write_h = unsafe {
        unwrap!(call_1(|ud, cb| file_open(
            &app,
            &container_info,
            &written_file.into_repr_c(),
            OPEN_MODE_OVERWRITE | OPEN_MODE_APPEND | OPEN_MODE_READ,
            ud,
            cb,
        )))
    };

    // Can query the size since the file is opened in read mode.
    let size: u64 = unsafe { unwrap!(call_1(|ud, cb| file_size(&app, read_write_h, ud, cb))) };
    assert_eq!(size, initial_content.len() as u64);

    // Do a write followed by read. The read should not see the new changes.
    let retrieved_content = unsafe {
        // Write.
        unwrap!(call_0(|ud, cb| file_write(
            &app,
            read_write_h,
            content.as_ptr(),
            content.len(),
            ud,
            cb
        )));

        // Read.
        unwrap!(call_vec_u8(|ud, cb| file_read(
            &app,
            read_write_h,
            0,
            FILE_READ_TO_END,
            ud,
            cb
        )))
    };
    assert_eq!(retrieved_content, vec![0u8; 0]);

    // Size did not change.
    let size: u64 = unsafe { unwrap!(call_1(|ud, cb| file_size(&app, read_write_h, ud, cb))) };
    assert_eq!(size, 0);

    // Close the file.
    let written_file: NativeFile =
        unsafe { unwrap!(call_1(|ud, cb| file_close(&app, read_write_h, ud, cb))) };

    // Open it again to read changes.
    let read_h = unsafe {
        unwrap!(call_1(|ud, cb| file_open(
            &app,
            &container_info,
            &written_file.into_repr_c(),
            OPEN_MODE_OVERWRITE | OPEN_MODE_APPEND | OPEN_MODE_READ,
            ud,
            cb,
        )))
    };

    // Size should have been updated.
    let size: u64 = unsafe { unwrap!(call_1(|ud, cb| file_size(&app, read_h, ud, cb))) };
    assert_eq!(size, content.len() as u64);

    // We should be able to read the changes now.
    let retrieved_content = unsafe {
        unwrap!(call_vec_u8(|ud, cb| file_read(
            &app,
            read_h,
            0,
            FILE_READ_TO_END,
            ud,
            cb
        )))
    };
    assert_eq!(retrieved_content, content);
}

// Test reading files in chunks.
#[test]
fn file_read_chunks() {
    const ORIG_SIZE: usize = 5555;

    let (app, container_info) = setup();

    // Create non-empty file.
    let file = NativeFile::new(Vec::new());
    let ffi_file = file.into_repr_c();

    let file_name = "file.txt";
    let ffi_file_name = unwrap!(CString::new(file_name));

    let content = [0u8; ORIG_SIZE];

    let write_h = unsafe {
        unwrap!(call_1(|ud, cb| file_open(
            &app,
            &container_info,
            &ffi_file,
            OPEN_MODE_OVERWRITE,
            ud,
            cb,
        )))
    };

    let written_file: NativeFile = unsafe {
        unwrap!(call_0(|ud, cb| file_write(
            &app,
            write_h,
            content.as_ptr(),
            content.len(),
            ud,
            cb
        )));
        unwrap!(call_1(|ud, cb| file_close(&app, write_h, ud, cb)))
    };
    unsafe {
        unwrap!(call_0(|ud, cb| dir_insert_file(
            &app,
            &container_info,
            ffi_file_name.as_ptr(),
            &written_file.into_repr_c(),
            ud,
            cb,
        )))
    }

    // Fetch it back.
    let (file, version): (NativeFile, u64) = {
        unsafe {
            unwrap!(call_2(|ud, cb| dir_fetch_file(
                &app,
                &container_info,
                ffi_file_name.as_ptr(),
                ud,
                cb
            )))
        }
    };
    assert_eq!(version, 0);

    // Read the content in chunks
    let read_h = unsafe {
        unwrap!(call_1(|ud, cb| file_open(
            &app,
            &container_info,
            &file.into_repr_c(),
            OPEN_MODE_READ,
            ud,
            cb,
        )))
    };

    let size = unsafe { unwrap!(call_1(|ud, cb| file_size(&app, read_h, ud, cb))) };
    const CHUNK_SIZE: u64 = 1000;
    let mut size_read = 0;
    let mut result = Vec::new();

    while size_read < size {
        let to_read = if size_read + CHUNK_SIZE >= size {
            size - size_read
        } else {
            CHUNK_SIZE
        };

        let mut retrieved_content = unsafe {
            unwrap!(call_vec_u8(|ud, cb| file_read(
                &app, read_h, size_read, to_read, ud, cb
            ),))
        };

        size_read += retrieved_content.len() as u64;
        result.append(&mut retrieved_content);
    }

    assert_eq!(size, size_read);
    assert_eq!(result, vec![0u8; ORIG_SIZE]);

    // Read 0 bytes, should succeed

    let retrieved_content = unsafe {
        unwrap!(call_vec_u8(|ud, cb| file_read(
            &app, read_h, size, 0, ud, cb
        ),))
    };
    assert_eq!(retrieved_content, Vec::<u8>::new());

    // Read 1 byte past end of file, should fail
    let retrieved_content =
        unsafe { call_vec_u8(|ud, cb| file_read(&app, read_h, size, 1, ud, cb)) };

    match retrieved_content {
        Err(code) if code == AppError::from(NfsError::InvalidRange).error_code() => (),
        Err(x) => panic!("Unexpected: {:?}", x),
        Ok(_) => panic!("Unexpected success"),
    }
}

// Test writing to files in chunks.
#[test]
fn file_write_chunks() {
    const GOAL_SIZE: usize = 5555;
    const CHUNK_SIZE: usize = 1000;

    let (app, container_info) = setup();

    let content = [0u8; GOAL_SIZE];

    // Test overwrite mode

    let file = NativeFile::new(Vec::new());
    let ffi_file = file.into_repr_c();

    let file_name = "file.txt";
    let ffi_file_name = unwrap!(CString::new(file_name));

    let write_h = unsafe {
        unwrap!(call_1(|ud, cb| file_open(
            &app,
            &container_info,
            &ffi_file,
            OPEN_MODE_OVERWRITE,
            ud,
            cb,
        )))
    };

    // Write in chunks.
    let written_file = write_chunks(&app, write_h, &content, GOAL_SIZE, CHUNK_SIZE);

    unsafe {
        unwrap!(call_0(|ud, cb| dir_insert_file(
            &app,
            &container_info,
            ffi_file_name.as_ptr(),
            &written_file.into_repr_c(),
            ud,
            cb,
        )))
    }

    // Fetch it back.
    let (file, version): (NativeFile, u64) = {
        unsafe {
            unwrap!(call_2(|ud, cb| dir_fetch_file(
                &app,
                &container_info,
                ffi_file_name.as_ptr(),
                ud,
                cb
            )))
        }
    };
    assert_eq!(version, 0);

    // Read the content
    let read_h = unsafe {
        unwrap!(call_1(|ud, cb| file_open(
            &app,
            &container_info,
            &file.into_repr_c(),
            OPEN_MODE_READ,
            ud,
            cb,
        )))
    };

    let retrieved_content = unsafe {
        unwrap!(call_vec_u8(|ud, cb| file_read(
            &app,
            read_h,
            0,
            FILE_READ_TO_END,
            ud,
            cb
        )))
    };

    assert_eq!(retrieved_content, vec![0u8; GOAL_SIZE]);

    // Test append mode

    let (file, version): (NativeFile, u64) = unsafe {
        unwrap!(call_2(|ud, cb| dir_fetch_file(
            &app,
            &container_info,
            ffi_file_name.as_ptr(),
            ud,
            cb
        )))
    };
    assert_eq!(version, 0);
    let ffi_file = file.into_repr_c();

    let write_h = unsafe {
        unwrap!(call_1(|ud, cb| file_open(
            &app,
            &container_info,
            &ffi_file,
            OPEN_MODE_APPEND,
            ud,
            cb
        )))
    };

    let written_file = write_chunks(&app, write_h, &content, GOAL_SIZE, CHUNK_SIZE);

    // Read the content
    let read_h = unsafe {
        unwrap!(call_1(|ud, cb| file_open(
            &app,
            &container_info,
            &written_file.into_repr_c(),
            OPEN_MODE_READ,
            ud,
            cb,
        )))
    };

    let retrieved_content = unsafe {
        unwrap!(call_vec_u8(|ud, cb| file_read(
            &app,
            read_h,
            0,
            FILE_READ_TO_END,
            ud,
            cb
        )))
    };

    assert_eq!(retrieved_content, vec![0u8; 2 * GOAL_SIZE]);
}

// Helper function for writing to a file in chunks.
fn write_chunks(
    app: &App,
    write_h: FileContextHandle,
    content: &[u8],
    goal_size: usize,
    chunk_size: usize,
) -> NativeFile {
    let mut size_written = 0;

    while size_written < goal_size {
        let to_write = if size_written + chunk_size > goal_size {
            goal_size - size_written
        } else {
            chunk_size
        };

        println!("Writing {} bytes to file", to_write);
        unsafe {
            unwrap!(call_0(|ud, cb| file_write(
                app,
                write_h,
                content.get_unchecked(size_written),
                to_write,
                ud,
                cb,
            )))
        }

        size_written += to_write;
    }

    // Write 0 bytes, should succeed.
    unsafe {
        println!("Writing 0 bytes to file");
        unwrap!(call_0(|ud, cb| file_write(
            app,
            write_h,
            content.get_unchecked(goal_size),
            0,
            ud,
            cb
        )));
        unwrap!(call_1(|ud, cb| file_close(app, write_h, ud, cb)))
    }
}
