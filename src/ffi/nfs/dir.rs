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

//! Directory operations.

use chrono::prelude::UTC;
use ffi::app::App;
use ffi::directory_details::DirectoryDetails;
use ffi::errors::FfiError;
use ffi::helper;
use libc::int32_t;
use nfs::{AccessLevel, UNVERSIONED_DIRECTORY_LISTING_TAG, VERSIONED_DIRECTORY_LISTING_TAG};
use nfs::errors::NfsError;
use nfs::helper::directory_helper::DirectoryHelper;
use std::slice;

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
        let user_metadata = slice::from_raw_parts(user_metadata, user_metadata_len);

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
#[cfg_attr(rustfmt, rustfmt_skip)]
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
                                 let dir_path = ffi_try!(helper::c_utf8_to_str(dir_path,
                                                                               dir_path_len));
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
        trace!("FFI modify directory, given the path.");
        let dir_path = ffi_try!(helper::c_utf8_to_str(dir_path, dir_path_len));
        let new_name = ffi_try!(helper::c_utf8_to_opt_string(new_name, new_name_len));
        let new_user_metadata = helper::u8_ptr_to_opt_vec(new_user_metadata, new_user_metadata_len);

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
              user_metadata: &[u8],
              is_private: bool,
              is_versioned: bool,
              is_shared: bool)
              -> Result<(), FfiError> {
    let mut tokens = helper::tokenise_path(dir_path, false);
    let dir_to_create = tokens.pop().ok_or(FfiError::InvalidPath)?;

    let start_dir_key = app.get_root_dir_key(is_shared)?;
    let mut parent_sub_dir =
        helper::get_final_subdirectory(app.get_client(), &tokens, Some(&start_dir_key))?;

    let dir_helper = DirectoryHelper::new(app.get_client());

    let access_level = if is_private {
        AccessLevel::Private
    } else {
        AccessLevel::Public
    };

    let tag = if is_versioned {
        VERSIONED_DIRECTORY_LISTING_TAG
    } else {
        UNVERSIONED_DIRECTORY_LISTING_TAG
    };

    let _ = dir_helper
        .create(dir_to_create,
                tag,
                user_metadata.to_owned(),
                is_versioned,
                access_level,
                Some(&mut parent_sub_dir))?;

    Ok(())
}

fn delete_dir(app: &App, dir_path: &str, is_shared: bool) -> Result<(), FfiError> {
    let mut tokens = helper::tokenise_path(dir_path, false);
    let dir_helper = DirectoryHelper::new(app.get_client());
    let dir_to_delete = tokens.pop().ok_or(FfiError::InvalidPath)?;

    let root_dir_key = app.get_root_dir_key(is_shared)?;
    let root_dir = dir_helper.get(&root_dir_key)?;
    let mut parent_dir = if tokens.is_empty() {
        root_dir
    } else {
        helper::get_final_subdirectory(app.get_client(),
                                       &tokens,
                                       Some(root_dir.get_metadata().get_key()))?
    };

    let _ = dir_helper.delete(&mut parent_dir, &dir_to_delete)?;
    Ok(())
}

fn get_dir(app: &App, dir_path: &str, is_shared: bool) -> Result<DirectoryDetails, FfiError> {
    let directory = helper::get_directory(app, dir_path, is_shared)?;
    DirectoryDetails::from_directory_listing(directory)
}

fn modify_dir(app: &App,
              dir_path: &str,
              is_shared: bool,
              new_name: Option<String>,
              new_metadata: Option<Vec<u8>>)
              -> Result<(), FfiError> {
    if new_name.is_none() && new_metadata.is_none() {
        return Err(FfiError::from("Optional parameters could not be parsed"));
    }

    let mut dir_to_modify = helper::get_directory(app, dir_path, is_shared)?;
    let directory_helper = DirectoryHelper::new(app.get_client());
    if let Some(name) = new_name {
        dir_to_modify.get_mut_metadata().set_name(name);
    }

    if let Some(metadata) = new_metadata {
        dir_to_modify
            .get_mut_metadata()
            .set_user_metadata(metadata);
    }

    dir_to_modify
        .get_mut_metadata()
        .set_modified_time(UTC::now());
    let _ = directory_helper.update(&dir_to_modify)?;

    Ok(())
}

fn move_dir(app: &App,
            src_path: &str,
            is_src_path_shared: bool,
            dst_path: &str,
            is_dst_path_shared: bool,
            retain_src: bool)
            -> Result<(), FfiError> {
    let directory_helper = DirectoryHelper::new(app.get_client());
    let mut src_dir = helper::get_directory(app, src_path, is_src_path_shared)?;
    let mut dst_dir = helper::get_directory(app, dst_path, is_dst_path_shared)?;

    if dst_dir
           .find_sub_directory(src_dir.get_metadata().get_name())
           .is_some() {
        return Err(FfiError::from(NfsError::DirectoryAlreadyExistsWithSameName));
    }

    let org_parent_of_src_dir = src_dir
        .get_metadata()
        .get_parent_dir_key()
        .cloned()
        .ok_or_else(|| FfiError::from("Parent directory not found"))?;

    if retain_src {
        let name = src_dir.get_metadata().get_name().to_owned();
        let user_metadata = src_dir.get_metadata().get_user_metadata().to_owned();
        let access_level = *src_dir.get_metadata().get_access_level();
        let created_time = *src_dir.get_metadata().get_created_time();
        let modified_time = *src_dir.get_metadata().get_modified_time();
        let (mut dir, _) = directory_helper
            .create(name,
                    src_dir.get_metadata().get_key().get_type_tag(),
                    user_metadata,
                    src_dir.get_metadata().get_key().is_versioned(),
                    access_level,
                    Some(&mut dst_dir))?;
        src_dir
            .get_files()
            .iter()
            .all(|file| {
                     dir.get_mut_files().push(file.clone());
                     true
                 });
        src_dir
            .get_sub_directories()
            .iter()
            .all(|sub_dir| {
                     dir.get_mut_sub_directories().push(sub_dir.clone());
                     true
                 });
        dir.get_mut_metadata().set_created_time(created_time);
        dir.get_mut_metadata().set_modified_time(modified_time);
        let _ = directory_helper.update(&dir)?;
    } else {
        src_dir
            .get_mut_metadata()
            .set_parent_dir_key(Some(*dst_dir.get_metadata().get_key()));
        dst_dir.upsert_sub_directory(src_dir.get_metadata().clone());
        let _ = directory_helper.update(&dst_dir)?;
        let _ = directory_helper.update(&src_dir)?;
        let mut parent_of_src_dir = directory_helper.get(&org_parent_of_src_dir)?;
        // TODO (Spandan) - Fetch and issue a DELETE on the removed directory.
        let _dir_meta = parent_of_src_dir
            .remove_sub_directory(src_dir.get_metadata().get_name())?;
        let _ = directory_helper.update(&parent_of_src_dir)?;
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use ffi::app::App;
    use ffi::test_utils;
    use nfs::{AccessLevel, UNVERSIONED_DIRECTORY_LISTING_TAG};
    use nfs::helper::directory_helper::DirectoryHelper;
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
        let user_metadata = b"user metadata".to_vec();

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
        assert_eq!(app_dir.get_sub_directories().len(), 2);

        let test_dir_key = unwrap!(app_dir.find_sub_directory("test_dir")).get_key();
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
        assert_eq!(app_root_dir.get_sub_directories().len(), 1);
        assert!(app_root_dir.find_sub_directory("test_dir").is_some());

        assert!(super::delete_dir(&app, "/test_dir", false).is_ok());

        let app_root_dir = unwrap!(dir_helper.get(&app_dir_key));
        assert_eq!(app_root_dir.get_sub_directories().len(), 0);

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
        assert_eq!(app_root_dir.get_sub_directories().len(), 1);
        assert!(app_root_dir.find_sub_directory("test_dir").is_some());

        assert!(super::modify_dir(&app,
                                  "/test_dir",
                                  false,
                                  Some("new_test_dir".to_string()),
                                  None)
                        .is_ok());

        let app_root_dir = unwrap!(dir_helper.get(&app_root_dir_key));
        assert_eq!(app_root_dir.get_sub_directories().len(), 1);
        assert!(app_root_dir.find_sub_directory("test_dir").is_none());
        assert!(app_root_dir.find_sub_directory("new_test_dir").is_some());
    }

    #[test]
    fn dir_update_user_metadata() {
        const METADATA: &'static str = "user metadata";

        let app = test_utils::create_app(false);
        let dir_helper = DirectoryHelper::new(app.get_client());
        let app_root_dir_key = unwrap!(app.get_app_dir_key());

        create_test_dir(&app, "test_dir");

        let app_root_dir = unwrap!(dir_helper.get(&app_root_dir_key));
        let dir_key = unwrap!(app_root_dir.find_sub_directory("test_dir")).get_key();
        let dir_to_modify = unwrap!(dir_helper.get(dir_key));
        assert_eq!(dir_to_modify.get_metadata().get_user_metadata().len(), 0);

        assert!(super::modify_dir(&app,
                                  "/test_dir",
                                  false,
                                  None,
                                  Some(METADATA.as_bytes().to_vec()))
                        .is_ok());

        let dir_to_modify = unwrap!(dir_helper.get(dir_key));
        assert!(dir_to_modify.get_metadata().get_user_metadata().len() > 0);
        assert_eq!(dir_to_modify.get_metadata().get_user_metadata(),
                   METADATA.as_bytes());
    }

    #[test]
    fn move_dir() {
        let app = test_utils::create_app(false);
        let dir_helper = DirectoryHelper::new(app.get_client());
        let app_root_dir_key = unwrap!(app.get_app_dir_key());

        create_test_dir(&app, "test_dir_a");
        create_test_dir(&app, "test_dir_b");

        let app_root_dir = unwrap!(dir_helper.get(&app_root_dir_key));
        assert_eq!(app_root_dir.get_sub_directories().len(), 2);

        let dst_dir_key = unwrap!(app_root_dir.find_sub_directory("test_dir_b")).get_key();
        let dst_dir = unwrap!(dir_helper.get(&dst_dir_key));
        assert_eq!(dst_dir.get_sub_directories().len(), 0);

        assert!(super::move_dir(&app, "/test_dir_a", false, "/test_dir_b", false, false).is_ok());

        let app_root_dir = unwrap!(dir_helper.get(&app_root_dir_key));
        assert_eq!(app_root_dir.get_sub_directories().len(), 1);

        let dst_dir = unwrap!(dir_helper.get(&dst_dir_key));
        assert_eq!(dst_dir.get_sub_directories().len(), 1);
    }

    #[test]
    fn copy_dir() {
        let app = test_utils::create_app(false);
        let dir_helper = DirectoryHelper::new(app.get_client());
        let app_root_dir_key = unwrap!(app.get_app_dir_key());

        create_test_dir(&app, "test_dir_a");
        create_test_dir(&app, "test_dir_b");

        let app_root_dir = unwrap!(dir_helper.get(&app_root_dir_key));
        assert_eq!(app_root_dir.get_sub_directories().len(), 2);

        let dst_dir_key = unwrap!(app_root_dir.find_sub_directory("test_dir_b")).get_key();
        let dst_dir = unwrap!(dir_helper.get(&dst_dir_key));
        assert_eq!(dst_dir.get_sub_directories().len(), 0);

        assert!(super::move_dir(&app, "/test_dir_a", false, "/test_dir_b", false, true).is_ok());

        let app_root_dir = unwrap!(dir_helper.get(&app_root_dir_key));
        assert_eq!(app_root_dir.get_sub_directories().len(), 2);

        let dst_dir = unwrap!(dir_helper.get(&dst_dir_key));
        assert_eq!(dst_dir.get_sub_directories().len(), 1);
    }
}
