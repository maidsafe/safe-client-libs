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

//! Directory operations.

use ffi::app::App;
use ffi::directory_details::DirectoryDetails;
use ffi::errors::FfiError;
use ffi::helper;
use libc::int32_t;
use nfs::{AccessLevel, UNVERSIONED_DIRECTORY_LISTING_TAG, VERSIONED_DIRECTORY_LISTING_TAG};
use nfs::errors::NfsError;
use nfs::helper::directory_helper::DirectoryHelper;
use rustc_serialize::base64::FromBase64;
use time;

/// Create a new directory.
#[no_mangle]
pub unsafe extern "C" fn nfs_create_dir(app_handle: *const App,
                                        dir_path: *const u8,
                                        dir_path_len: usize,
                                        user_metadata: *const u8,
                                        user_metadata_len: usize,
                                        is_private: bool,
                                        is_versioned: bool,
                                        is_shared: bool)
                                        -> int32_t {
    helper::catch_unwind_i32(|| {
        trace!("FFI create directory, given the path.");

        let dir_path = ffi_try!(helper::c_utf8_to_str(dir_path, dir_path_len));
        let user_metadata = ffi_try!(helper::c_utf8_to_str(user_metadata, user_metadata_len));

        ffi_try!(create_dir(&*app_handle,
                            dir_path,
                            user_metadata,
                            is_private,
                            is_versioned,
                            is_shared));
        0
    })
}

/// Delete a directory.
#[no_mangle]
pub unsafe extern "C" fn nfs_delete_dir(app_handle: *const App,
                                        dir_path: *const u8,
                                        dir_path_len: usize,
                                        is_shared: bool)
                                        -> int32_t {
    helper::catch_unwind_i32(|| {
        trace!("FFI delete dir, given the path.");
        let dir_path = ffi_try!(helper::c_utf8_to_str(dir_path, dir_path_len));
        ffi_try!(delete_dir(&*app_handle, dir_path, is_shared));
        0
    })
}

/// Get directory
#[no_mangle]
pub unsafe extern "C" fn nfs_get_dir(app_handle: *const App,
                                     dir_path: *const u8,
                                     dir_path_len: usize,
                                     is_shared: bool,
                                     details_handle: *mut *mut DirectoryDetails)
                                     -> int32_t {
    helper::catch_unwind_i32(|| {
        trace!("FFI get dir, given the path.");
        let dir_path = ffi_try!(helper::c_utf8_to_str(dir_path, dir_path_len));
        let details = ffi_try!(get_dir(&*app_handle, dir_path, is_shared));
        *details_handle = Box::into_raw(Box::new(details));
        0
    })
}

/// Modify name and/or metadata of a directory.
#[no_mangle]
pub unsafe extern "C" fn nfs_modify_dir(app_handle: *const App,
                                        dir_path: *const u8,
                                        dir_path_len: usize,
                                        is_shared: bool,
                                        new_name: *const u8,
                                        new_name_len: usize,
                                        new_user_metadata: *const u8,
                                        new_user_metadata_len: usize)
                                        -> int32_t {
    helper::catch_unwind_i32(|| {
        trace!("JSON modify directory, given the path.");
        let dir_path = ffi_try!(helper::c_utf8_to_str(dir_path, dir_path_len));
        let new_name = ffi_try!(helper::c_utf8_to_opt_string(new_name, new_name_len));
        let new_user_metadata = ffi_try!(helper::c_utf8_to_opt_string(new_user_metadata,
                                                                      new_user_metadata_len));

        ffi_try!(modify_dir(&*app_handle,
                            dir_path,
                            is_shared,
                            new_name,
                            new_user_metadata));
        0
    })
}

/// Move or copy a directory.
#[no_mangle]
pub unsafe extern "C" fn nfs_move_dir(app_handle: *const App,
                                      src_path: *const u8,
                                      src_path_len: usize,
                                      is_src_path_shared: bool,
                                      dst_path: *const u8,
                                      dst_path_len: usize,
                                      is_dst_path_shared: bool,
                                      retain_src: bool)
                                      -> int32_t {
    helper::catch_unwind_i32(|| {
        trace!("FFI move directory, from {:?} to {:?}.", src_path, dst_path);

        let src_path = ffi_try!(helper::c_utf8_to_str(src_path, src_path_len));
        let dst_path = ffi_try!(helper::c_utf8_to_str(dst_path, dst_path_len));

        ffi_try!(move_dir(&*app_handle,
                          src_path,
                          is_src_path_shared,
                          dst_path,
                          is_dst_path_shared,
                          retain_src));
        0
    })
}



fn create_dir(app: &App,
              dir_path: &str,
              user_metadata: &str,
              is_private: bool,
              is_versioned: bool,
              is_shared: bool)
              -> Result<(), FfiError> {
    let dir_helper = DirectoryHelper::new(app.get_client());
    let root_dir_key = try!(app.get_root_dir_key(is_shared));
    let (dir_name, mut parent_dir) = try!(dir_helper.get_name_and_parent(&root_dir_key, dir_path));

    let tag = if is_versioned {
        VERSIONED_DIRECTORY_LISTING_TAG
    } else {
        UNVERSIONED_DIRECTORY_LISTING_TAG
    };

    let user_metadata = try!(parse_result!(user_metadata.from_base64(),
                                           "Faild Converting from Base64."));
    let access_level = if is_private {
        AccessLevel::Private
    } else {
        AccessLevel::Public
    };

    let _ = try!(dir_helper.create(dir_name,
                                   tag,
                                   user_metadata,
                                   is_versioned,
                                   access_level,
                                   Some(&mut parent_dir)));

    Ok(())
}

fn delete_dir(app: &App, dir_path: &str, is_shared: bool) -> Result<(), FfiError> {
    let dir_helper = DirectoryHelper::new(app.get_client());
    let root_dir_key = try!(app.get_root_dir_key(is_shared));
    let (dir_name, mut parent_dir) = try!(dir_helper.get_name_and_parent(&root_dir_key, dir_path));
    let _ = try!(dir_helper.delete(&mut parent_dir, &dir_name));
    Ok(())
}

fn get_dir(app: &App, dir_path: &str, is_shared: bool) -> Result<DirectoryDetails, FfiError> {
    let directory = try!(helper::get_directory(app, dir_path, is_shared));
    DirectoryDetails::from_directory(directory)
}

fn modify_dir(app: &App,
              dir_path: &str,
              is_shared: bool,
              new_name: Option<String>,
              new_metadata: Option<String>)
              -> Result<(), FfiError> {
    if new_name.is_none() && new_metadata.is_none() {
        return Err(FfiError::from("Optional parameters could not be parsed"));
    }

    let mut dir_to_modify = try!(helper::get_directory(app, dir_path, is_shared));
    let directory_helper = DirectoryHelper::new(app.get_client());
    if let Some(name) = new_name {
        dir_to_modify.metadata_mut().set_name(name);
    }

    if let Some(metadata) = new_metadata {
        let metadata = try!(parse_result!(metadata.from_base64(), "Failed to convert from base64"));
        dir_to_modify.metadata_mut().set_user_metadata(metadata);
    }

    dir_to_modify.metadata_mut().set_modified_time(time::now_utc());
    let _ = try!(directory_helper.update(&dir_to_modify));

    Ok(())
}

fn move_dir(app: &App,
            src_path: &str,
            is_src_path_shared: bool,
            dst_path: &str,
            is_dst_path_shared: bool,
            retain_src: bool)
            -> Result<(), FfiError> {
    let dir_helper = DirectoryHelper::new(app.get_client());
    let src_root_key = try!(app.get_root_dir_key(is_src_path_shared));
    let dst_root_key = try!(app.get_root_dir_key(is_dst_path_shared));

    let (src_dir, mut src_parent) = try!(dir_helper.get_directory_and_parent(&src_root_key, src_path));
    let (mut dst_dir, _) = try!(dir_helper.get_directory_and_parent(&dst_root_key, dst_path));

    if dst_dir.find_sub_directory(src_dir.name()).is_some() {
        return Err(FfiError::from(NfsError::DirectoryAlreadyExistsWithSameName));
    }

    if retain_src {
        let name = src_dir.metadata().name().to_owned();
        let user_metadata = src_dir.metadata().user_metadata().to_owned();
        let access_level = src_dir.key().access_level();
        let created_time = *src_dir.metadata().created_time();
        let modified_time = *src_dir.metadata().modified_time();
        let (mut dir, _) = try!(dir_helper.create(name,
                                                  src_dir.key().type_tag(),
                                                  user_metadata,
                                                  src_dir.key().versioned(),
                                                  access_level,
                                                  Some(&mut dst_dir)));
        src_dir.files().iter().all(|file| {
            dir.files_mut().push(file.clone());
            true
        });
        src_dir.sub_directories()
            .iter()
            .all(|sub_dir| {
                dir.sub_directories_mut().push(sub_dir.clone());
                true
            });
        dir.metadata_mut().set_created_time(created_time);
        dir.metadata_mut().set_modified_time(modified_time);
        let _ = try!(dir_helper.update(&dir));
    } else {
        dst_dir.upsert_sub_directory(src_dir.key().clone(),
                                     src_dir.metadata().clone());
        let _ = try!(dir_helper.update(&dst_dir));
        let _ = try!(dir_helper.update(&src_dir));

        // TODO (Spandan) - Fetch and issue a DELETE on the removed directory.
        let _ = try!(src_parent.remove_sub_directory(src_dir.name()));
        let _ = try!(dir_helper.update(&src_parent));
    }

    Ok(())
}

#[cfg(test)]
mod test {

    use ffi::{config, test_utils};

    use ffi::app::App;
    use nfs::{AccessLevel, UNVERSIONED_DIRECTORY_LISTING_TAG};
    use nfs::helper::directory_helper::DirectoryHelper;
    use rustc_serialize::base64::ToBase64;
    use std::slice;

    fn create_test_dir(app: &App, name: &str) {
        let app_dir_key = unwrap!(app.get_app_dir_key());
        let dir_helper = DirectoryHelper::new(app.get_client());
        let mut app_root_dir = unwrap!(dir_helper.get(&app_dir_key));
        let _ = unwrap!(dir_helper.create(name.to_string(),
                                          UNVERSIONED_DIRECTORY_LISTING_TAG,
                                          Vec::new(),
                                          false,
                                          AccessLevel::Private,
                                          Some(&mut app_root_dir)));
    }

    #[test]
    fn create_dir() {
        let app = test_utils::create_app(false);
        let user_metadata = "InNhbXBsZSBtZXRhZGF0YSI=".to_string();

        assert!(super::create_dir(&app, "/", &user_metadata, true, false, false).is_err());

        assert!(super::create_dir(&app,
                                  "/test_dir/secondlevel",
                                  &user_metadata,
                                  true,
                                  false,
                                  false)
            .is_err());

        assert!(super::create_dir(&app, "/test_dir", &user_metadata, true, false, false).is_ok());

        assert!(super::create_dir(&app, "/test_dir2", &user_metadata, true, false, false).is_ok());

        assert!(super::create_dir(&app,
                                  "/test_dir/secondlevel",
                                  &user_metadata,
                                  true,
                                  false,
                                  false)
            .is_ok());

        let dir_helper = DirectoryHelper::new(app.get_client());
        let app_dir = unwrap!(dir_helper.get(&unwrap!(app.get_app_dir_key())));

        assert!(app_dir.find_sub_directory("test_dir").is_some());
        assert!(app_dir.find_sub_directory("test_dir2").is_some());
        assert_eq!(app_dir.sub_directories().len(), 2);

        let test_dir_key = unwrap!(app_dir.find_sub_directory("test_dir")).key();
        let test_dir = unwrap!(dir_helper.get(test_dir_key));
        assert!(test_dir.find_sub_directory("secondlevel").is_some());
    }

    #[test]
    fn delete_dir() {
        let app = test_utils::create_app(false);
        let app_dir_key = unwrap!(app.get_app_dir_key());
        let dir_helper = DirectoryHelper::new(app.get_client());

        create_test_dir(&app, "test_dir");

        assert!(super::delete_dir(&app, "/test_dir2", false).is_err());

        let app_root_dir = unwrap!(dir_helper.get(&app_dir_key));
        assert_eq!(app_root_dir.sub_directories().len(), 1);
        assert!(app_root_dir.find_sub_directory("test_dir").is_some());

        assert!(super::delete_dir(&app, "/test_dir", false).is_ok());

        let app_root_dir = unwrap!(dir_helper.get(&app_dir_key));
        assert_eq!(app_root_dir.sub_directories().len(), 0);

        assert!(super::delete_dir(&app, "/test_dir", false).is_err());
    }

    #[test]
    fn get_dir() {
        let app = test_utils::create_app(false);

        create_test_dir(&app, "test_dir");

        let details = unwrap!(super::get_dir(&app, "/test_dir", false));

        unsafe {
            let name = slice::from_raw_parts(details.metadata.name, details.metadata.name_len);
            let name = String::from_utf8(name.to_owned()).unwrap();
            assert_eq!(name, "test_dir");
        }

        assert_eq!(details.files.len(), 0);
        assert_eq!(details.sub_directories.len(), 0);

        assert!(super::get_dir(&app, "/does_not_exist", false).is_err());
    }

    #[test]
    fn rename_dir() {
        let app = test_utils::create_app(false);
        let dir_helper = DirectoryHelper::new(app.get_client());
        let app_root_dir_key = unwrap!(app.get_app_dir_key());

        create_test_dir(&app, "test_dir");

        let app_root_dir = unwrap!(dir_helper.get(&app_root_dir_key));
        assert_eq!(app_root_dir.sub_directories().len(), 1);
        assert!(app_root_dir.find_sub_directory("test_dir").is_some());

        assert!(super::modify_dir(&app,
                                  "/test_dir",
                                  false,
                                  Some("new_test_dir".to_string()),
                                  None)
            .is_ok());

        let app_root_dir = unwrap!(dir_helper.get(&app_root_dir_key));
        assert_eq!(app_root_dir.sub_directories().len(), 1);
        assert!(app_root_dir.find_sub_directory("test_dir").is_none());
        assert!(app_root_dir.find_sub_directory("new_test_dir").is_some());
    }

    #[test]
    fn dir_update_user_metadata() {
        const METADATA_BASE64: &'static str = "c2FtcGxlIHRleHQ=";

        let app = test_utils::create_app(false);
        let dir_helper = DirectoryHelper::new(app.get_client());
        let app_root_dir_key = unwrap!(app.get_app_dir_key());

        create_test_dir(&app, "test_dir");

        let app_root_dir = unwrap!(dir_helper.get(&app_root_dir_key));
        let dir_key = unwrap!(app_root_dir.find_sub_directory("test_dir")).key();
        let dir_to_modify = unwrap!(dir_helper.get(dir_key));
        assert_eq!(dir_to_modify.metadata().user_metadata().len(), 0);

        assert!(super::modify_dir(&app,
                                  "/test_dir",
                                  false,
                                  None,
                                  Some(METADATA_BASE64.to_string()))
            .is_ok());

        let dir_to_modify = unwrap!(dir_helper.get(dir_key));
        assert!(dir_to_modify.metadata().user_metadata().len() > 0);
        assert_eq!(dir_to_modify.metadata()
                       .user_metadata()
                       .to_base64(config::get_base64_config()),
                   METADATA_BASE64.to_string());
    }

    #[test]
    fn move_dir() {
        let app = test_utils::create_app(false);
        let dir_helper = DirectoryHelper::new(app.get_client());
        let app_root_dir_key = unwrap!(app.get_app_dir_key());

        create_test_dir(&app, "test_dir_a");
        create_test_dir(&app, "test_dir_b");

        let app_root_dir = unwrap!(dir_helper.get(&app_root_dir_key));
        assert_eq!(app_root_dir.sub_directories().len(), 2);

        let dst_dir_key = unwrap!(app_root_dir.find_sub_directory("test_dir_b")).key();
        let dst_dir = unwrap!(dir_helper.get(&dst_dir_key));
        assert_eq!(dst_dir.sub_directories().len(), 0);

        assert!(super::move_dir(&app, "/test_dir_a", false, "/test_dir_b", false, false).is_ok());

        let app_root_dir = unwrap!(dir_helper.get(&app_root_dir_key));
        assert_eq!(app_root_dir.sub_directories().len(), 1);

        let dst_dir = unwrap!(dir_helper.get(&dst_dir_key));
        assert_eq!(dst_dir.sub_directories().len(), 1);
    }

    #[test]
    fn copy_dir() {
        let app = test_utils::create_app(false);
        let dir_helper = DirectoryHelper::new(app.get_client());
        let app_root_dir_key = unwrap!(app.get_app_dir_key());

        create_test_dir(&app, "test_dir_a");
        create_test_dir(&app, "test_dir_b");

        let app_root_dir = unwrap!(dir_helper.get(&app_root_dir_key));
        assert_eq!(app_root_dir.sub_directories().len(), 2);

        let dst_dir_key = unwrap!(app_root_dir.find_sub_directory("test_dir_b")).key();
        let dst_dir = unwrap!(dir_helper.get(&dst_dir_key));
        assert_eq!(dst_dir.sub_directories().len(), 0);

        assert!(super::move_dir(&app, "/test_dir_a", false, "/test_dir_b", false, true).is_ok());

        let app_root_dir = unwrap!(dir_helper.get(&app_root_dir_key));
        assert_eq!(app_root_dir.sub_directories().len(), 2);

        let dst_dir = unwrap!(dir_helper.get(&dst_dir_key));
        assert_eq!(dst_dir.sub_directories().len(), 1);
    }
}
