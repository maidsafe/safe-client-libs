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

//! File operations


use ffi::app::App;
use ffi::errors::FfiError;
use ffi::file_details::{FileDetails, FileMetadata};
use ffi::helper;
use libc::int32_t;
use nfs::errors::NfsError;
use nfs::file::File;
use nfs::helper::directory_helper::DirectoryHelper;
use nfs::helper::file_helper::FileHelper;
use nfs::helper::writer::Mode;
use time;


/// Delete a file.
#[no_mangle]
pub unsafe extern "C" fn nfs_delete_file(app_handle: *const App,
                                         file_path: *const u8,
                                         file_path_len: usize,
                                         is_shared: bool)
                                         -> int32_t {
    helper::catch_unwind_i32(|| {
                                 trace!("FFI delete file, given the path.");
        #[cfg_attr(rustfmt, rustfmt_skip)]
                                 let file_path = ffi_try!(helper::c_utf8_to_str(file_path,
                                                                                file_path_len));
                                 ffi_try!(delete_file(&*app_handle, file_path, is_shared));
                                 0
                             })
}

/// Get file. The returned `FileDetails` pointer must be disposed of by calling
/// `file_details_drop` when no longer needed.
#[no_mangle]
pub unsafe extern "C" fn nfs_get_file(app_handle: *const App,
                                      offset: i64,
                                      length: i64,
                                      file_path: *const u8,
                                      file_path_len: usize,
                                      is_path_shared: bool,
                                      include_metadata: bool,
                                      details_handle: *mut *mut FileDetails)
                                      -> int32_t {
    helper::catch_unwind_i32(|| {
        trace!("FFI get file, given the path.");

        let file_path = ffi_try!(helper::c_utf8_to_str(file_path, file_path_len));

        let response = ffi_try!(get_file(&*app_handle,
                                         file_path,
                                         is_path_shared,
                                         offset,
                                         length,
                                         include_metadata));

        *details_handle = Box::into_raw(Box::new(response));
        0
    })
}

/// Modify name, metadata or content of the file.
#[no_mangle]
pub unsafe extern "C" fn nfs_modify_file(app_handle: *const App,
                                         file_path: *const u8,
                                         file_path_len: usize,
                                         is_shared: bool,
                                         new_name: *const u8,
                                         new_name_len: usize,
                                         new_metadata: *const u8,
                                         new_metadata_len: usize,
                                         new_content: *const u8,
                                         new_content_len: usize)
                                         -> int32_t {
    helper::catch_unwind_i32(|| {
        trace!("FFI modify file, given the path.");

        let file_path = ffi_try!(helper::c_utf8_to_str(file_path, file_path_len));
        let new_name = ffi_try!(helper::c_utf8_to_opt_string(new_name, new_name_len));
        let new_metadata = helper::u8_ptr_to_opt_vec(new_metadata, new_metadata_len);
        let new_content = helper::u8_ptr_to_opt_vec(new_content, new_content_len);

        ffi_try!(modify_file(&*app_handle,
                             file_path,
                             is_shared,
                             new_name,
                             new_metadata,
                             new_content));
        0
    })
}

/// Move or copy a file.
#[no_mangle]
pub unsafe extern "C" fn nfs_move_file(app_handle: *const App,
                                       src_path: *const u8,
                                       src_path_len: usize,
                                       is_src_path_shared: bool,
                                       dst_path: *const u8,
                                       dst_path_len: usize,
                                       is_dst_path_shared: bool,
                                       retain_src: bool)
                                       -> int32_t {
    helper::catch_unwind_i32(|| {
        trace!("FFI move file, from {:?} to {:?}.", src_path, dst_path);

        let src_path = ffi_try!(helper::c_utf8_to_str(src_path, src_path_len));
        let dst_path = ffi_try!(helper::c_utf8_to_str(dst_path, dst_path_len));

        ffi_try!(move_file(&*app_handle,
                           src_path,
                           is_src_path_shared,
                           dst_path,
                           is_dst_path_shared,
                           retain_src));
        0
    })
}

/// Get file metadata. The returned pointer must be disposed of by calling
/// `file_metadata_drop` when no longer needed.
#[no_mangle]
pub unsafe extern "C" fn nfs_get_file_metadata(app_handle: *const App,
                                               file_path: *const u8,
                                               file_path_len: usize,
                                               is_path_shared: bool,
                                               metadata_handle: *mut *mut FileMetadata)
                                               -> int32_t {
    helper::catch_unwind_i32(|| {
        trace!("FFI get file metadata, given the path.");
        let file_path = ffi_try!(helper::c_utf8_to_str(file_path, file_path_len));
        let metadata = ffi_try!(get_file_metadata(&*app_handle, file_path, is_path_shared));
        *metadata_handle = Box::into_raw(Box::new(metadata));
        0
    })
}

fn delete_file(app: &App, file_path: &str, is_shared: bool) -> Result<(), FfiError> {
    let (mut directory, file_name) = helper::get_directory_and_file(app, file_path, is_shared)?;

    let file_helper = FileHelper::new(app.get_client());
    let _ = file_helper.delete(file_name, &mut directory)?;

    Ok(())
}

fn get_file(app: &App,
            file_path: &str,
            is_path_shared: bool,
            offset: i64,
            length: i64,
            include_metadata: bool)
            -> Result<FileDetails, FfiError> {
    let (directory, file_name) = helper::get_directory_and_file(app, file_path, is_path_shared)?;
    let file = directory.find_file(&file_name)
        .ok_or(FfiError::InvalidPath)?;

    FileDetails::new(file, app.get_client(), offset, length, include_metadata)
}

fn modify_file(app: &App,
               file_path: &str,
               is_shared: bool,
               new_name: Option<String>,
               new_metadata: Option<Vec<u8>>,
               new_content: Option<Vec<u8>>)
               -> Result<(), FfiError> {
    if new_name.is_none() && new_metadata.is_none() && new_content.is_none() {
        return Err(FfiError::from("Optional parameters could not be parsed"));
    }

    let (mut directory, file_name) = helper::get_directory_and_file(app, file_path, is_shared)?;
    let mut file = directory.find_file(&file_name)
        .cloned()
        .ok_or(FfiError::InvalidPath)?;

    let mut file_helper = FileHelper::new(app.get_client());

    let mut metadata_updated = false;
    if let Some(name) = new_name {
        file.get_mut_metadata().set_name(name);
        metadata_updated = true;
    }

    if let Some(metadata) = new_metadata {
        file.get_mut_metadata().set_user_metadata(metadata);
        metadata_updated = true;
    }

    if metadata_updated {
        file.get_mut_metadata()
            .set_modified_time(time::now_utc());
        let _ = file_helper.update_metadata(file.clone(), &mut directory)?;
    }

    if let Some(content) = new_content {
        let mut writer = file_helper.update_content(file.clone(), Mode::Overwrite, directory)?;
        writer.write(&content[..])?;
        let _ = writer.close()?;
    }

    Ok(())
}

fn move_file(app: &App,
             src_path: &str,
             is_src_path_shared: bool,
             dst_path: &str,
             is_dst_path_shared: bool,
             retain_src: bool)
             -> Result<(), FfiError> {
    let directory_helper = DirectoryHelper::new(app.get_client());
    let (mut src_dir, src_file_name) =
        helper::get_directory_and_file(app, src_path, is_src_path_shared)?;
    let mut dst_dir = helper::get_directory(app, dst_path, is_dst_path_shared)?;

    if dst_dir.find_file(&src_file_name).is_some() {
        return Err(FfiError::from(NfsError::FileAlreadyExistsWithSameName));
    }

    let mut file = match src_dir.find_file(&src_file_name).cloned() {
        Some(file) => file,
        None => return Err(FfiError::PathNotFound),
    };

    if retain_src {
        file = File::new(file.get_metadata().clone(), file.get_datamap().clone())?;
    }

    dst_dir.upsert_file(file);

    let _ = directory_helper.update(&dst_dir)?;

    if !retain_src {
        let _ = src_dir.remove_file(&src_file_name)?;
        let _ = directory_helper.update(&src_dir)?;
    }

    Ok(())
}

fn get_file_metadata(app: &App,
                     file_path: &str,
                     is_path_shared: bool)
                     -> Result<FileMetadata, FfiError> {
    let (directory, file_name) = helper::get_directory_and_file(app, file_path, is_path_shared)?;
    let file = directory.find_file(&file_name)
        .ok_or(FfiError::InvalidPath)?;

    FileMetadata::new(file.get_metadata())
}

#[cfg(test)]
mod test {
    use ffi::app::App;
    use ffi::test_utils;
    use nfs::helper::directory_helper::DirectoryHelper;
    use nfs::helper::file_helper::FileHelper;
    use std::slice;
    use std::str;

    fn create_test_file(app: &App, name: &str) {
        let mut file_helper = FileHelper::new(app.get_client());
        let dir_helper = DirectoryHelper::new(app.get_client());

        let app_root_dir_key = unwrap!(app.get_app_dir_key());
        let app_root_dir = unwrap!(dir_helper.get(&app_root_dir_key));

        let mut writer = unwrap!(file_helper.create(name.to_string(), Vec::new(), app_root_dir));
        let data = vec![10u8; 20];
        unwrap!(writer.write(&data[..]));
        let _ = unwrap!(writer.close());
    }

    #[test]
    fn delete_file() {
        let app = test_utils::create_app(false);
        let dir_helper = DirectoryHelper::new(app.get_client());
        let app_root_dir_key = unwrap!(app.get_app_dir_key());

        create_test_file(&app, "test_file.txt");

        let app_root_dir = unwrap!(dir_helper.get(&app_root_dir_key));
        assert_eq!(app_root_dir.get_files().len(), 1);
        assert!(app_root_dir.find_file("test_file.txt").is_some());

        assert!(super::delete_file(&app, "/test_file.txt", false).is_ok());

        let app_root_dir = unwrap!(dir_helper.get(&app_root_dir_key));
        assert_eq!(app_root_dir.get_files().len(), 0);

        assert!(super::delete_file(&app, "/test_file.txt", false).is_err());
    }

    #[test]
    fn get_file() {
        let app = test_utils::create_app(false);

        create_test_file(&app, "test_file.txt");

        let details = unwrap!(super::get_file(&app, "/test_file.txt", false, 0, 0, true));
        unsafe {
            let metadata = unwrap!(details.metadata.as_ref());
            let name = slice::from_raw_parts(metadata.name, metadata.name_len);
            let name = String::from_utf8(name.to_owned()).unwrap();
            assert_eq!(name, "test_file.txt");
        }

        assert!(super::get_file(&app, "/does_not_exist", false, 0, 0, true).is_err());
    }

    #[test]
    fn file_rename() {
        let app = test_utils::create_app(false);
        let dir_helper = DirectoryHelper::new(app.get_client());
        let app_root_dir_key = unwrap!(app.get_app_dir_key());

        create_test_file(&app, "test_file.txt");

        let app_root_dir = unwrap!(dir_helper.get(&app_root_dir_key));
        assert_eq!(app_root_dir.get_files().len(), 1);
        assert!(app_root_dir.find_file("test_file.txt").is_some());

        assert!(super::modify_file(&app,
                                   "/test_file.txt",
                                   false,
                                   Some("new_test_file.txt".to_string()),
                                   None,
                                   None)
                        .is_ok());

        let app_root_dir = unwrap!(dir_helper.get(&app_root_dir_key));
        assert_eq!(app_root_dir.get_files().len(), 1);
        assert!(app_root_dir.find_file("test_file.txt").is_none());
        assert!(app_root_dir.find_file("new_test_file.txt").is_some());
    }

    #[test]
    fn file_update_user_metadata() {
        const METADATA: &'static str = "user metadata";

        let app = test_utils::create_app(false);
        let dir_helper = DirectoryHelper::new(app.get_client());
        let app_root_dir_key = unwrap!(app.get_app_dir_key());

        create_test_file(&app, "test_file.txt");

        let app_root_dir = unwrap!(dir_helper.get(&app_root_dir_key));
        let file = unwrap!(app_root_dir.find_file("test_file.txt"));
        assert_eq!(file.get_metadata().get_user_metadata().len(), 0);

        assert!(super::modify_file(&app,
                                   "/test_file.txt",
                                   false,
                                   None,
                                   Some(METADATA.as_bytes().to_vec()),
                                   None)
                        .is_ok());

        let app_root_dir = unwrap!(dir_helper.get(&app_root_dir_key));
        let file = unwrap!(app_root_dir.find_file("test_file.txt"));
        assert!(file.get_metadata().get_user_metadata().len() > 0);
        assert_eq!(file.get_metadata().get_user_metadata(), METADATA.as_bytes());
    }

    #[test]
    fn file_update_content() {
        let app = test_utils::create_app(false);
        let mut file_helper = FileHelper::new(app.get_client());
        let dir_helper = DirectoryHelper::new(app.get_client());
        let app_root_dir_key = unwrap!(app.get_app_dir_key());

        create_test_file(&app, "test_file.txt");

        let content = b"first".to_vec();
        unwrap!(super::modify_file(&app, "/test_file.txt", false, None, None, Some(content)));


        {
            let app_root_dir = unwrap!(dir_helper.get(&app_root_dir_key));
            let file = unwrap!(app_root_dir.find_file("test_file.txt"));
            let mut reader = unwrap!(file_helper.read(file));
            let size = reader.size();

            let content = unwrap!(reader.read(0, size));
            let content = unwrap!(str::from_utf8(&content));
            assert_eq!(content, "first");
        }

        let content = b"second".to_vec();
        unwrap!(super::modify_file(&app, "/test_file.txt", false, None, None, Some(content)));

        {
            let app_root_dir = unwrap!(dir_helper.get(&app_root_dir_key));
            let file = unwrap!(app_root_dir.find_file("test_file.txt"));
            let mut reader = unwrap!(file_helper.read(file));
            let size = reader.size();

            let content = unwrap!(reader.read(0, size));
            let content = unwrap!(str::from_utf8(&content));
            assert_eq!(content, "second");
        }
    }
}
