// Copyright 2015 MaidSafe.net limited.
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


use core::client::Client;
use ffi::app::App;
use ffi::config::SAFE_DRIVE_DIR_NAME;
use ffi::errors::FfiError;
use libc::{int32_t, int64_t};
use nfs::AccessLevel;
use nfs::UNVERSIONED_DIRECTORY_LISTING_TAG;
use nfs::directory_listing::DirectoryListing;
use nfs::helper::directory_helper::DirectoryHelper;
use nfs::metadata::directory_key::DirectoryKey;
use std;
use std::error::Error;
use std::mem;
use std::panic;
use std::ptr;
use std::slice;
use std::sync::{Arc, Mutex};

pub unsafe fn c_utf8_to_string(ptr: *const u8, len: usize) -> Result<String, FfiError> {
    c_utf8_to_str(ptr, len).map(|v| v.to_owned())
}

pub unsafe fn c_utf8_to_str(ptr: *const u8, len: usize) -> Result<&'static str, FfiError> {
    std::str::from_utf8(slice::from_raw_parts(ptr, len))
        .map_err(|error| FfiError::from(error.description()))
}

pub unsafe fn c_utf8_to_opt_string(ptr: *const u8, len: usize) -> Result<Option<String>, FfiError> {
    if ptr.is_null() {
        Ok(None)
    } else {
        String::from_utf8(slice::from_raw_parts(ptr, len).to_owned())
            .map(|v| Some(v))
            .map_err(|error| FfiError::from(error.description()))
    }
}

/// Returns a heap-allocated raw string, usable by C/FFI-boundary.
/// The tuple means (pointer, length_in_bytes, capacity).
/// Use `dealloc_c_utf8_alloced_from_rust` to free the memory.
pub fn string_to_c_utf8(s: String) -> (*mut u8, usize, usize) {
    let mut v = s.into_bytes();
    v.shrink_to_fit();
    let p = v.as_mut_ptr();
    let len = v.len();
    let cap = v.capacity();
    mem::forget(v);
    (p, len, cap)
}

/// Dealloc a string allocated with `string_to_c_utf8`.
pub unsafe fn dealloc_c_utf8_alloced_from_rust(p: *mut u8, len: usize,
                                               cap: usize) {
    // TODO: refactor implementation to remove the need for `cap`. Related issue:
    // <https://github.com/rust-lang/rust/issues/36284>.
    let _ = Vec::from_raw_parts(p, len, cap);
}

// TODO: add c_char_ptr_to_str and c_char_ptr_to_opt_str (return &str instead of String)

pub fn catch_unwind_i32<F: FnOnce() -> int32_t>(f: F) -> int32_t {
    let errno: i32 = FfiError::Unexpected(String::new()).into();
    panic::catch_unwind(panic::AssertUnwindSafe(f)).unwrap_or(errno)
}

pub fn catch_unwind_i64<F: FnOnce() -> int64_t>(f: F) -> int64_t {
    let errno: i32 = FfiError::Unexpected(String::new()).into();
    panic::catch_unwind(panic::AssertUnwindSafe(f)).unwrap_or(errno as i64)
}

pub fn catch_unwind_ptr<T, F: FnOnce() -> *const T>(f: F) -> *const T {
    panic::catch_unwind(panic::AssertUnwindSafe(f)).unwrap_or(ptr::null())
}

pub fn tokenise_path(path: &str, keep_empty_splits: bool) -> Vec<String> {
    path.split(|element| element == '/')
        .filter(|token| keep_empty_splits || !token.is_empty())
        .map(|token| token.to_string())
        .collect()
}

pub fn get_safe_drive_key(client: Arc<Mutex<Client>>) -> Result<DirectoryKey, FfiError> {
    trace!("Obtain directory key for SAFEDrive - This can be cached for efficiency. So if this \
            is seen many times, check for missed optimisation opportunity.");

    let safe_drive_dir_name = SAFE_DRIVE_DIR_NAME.to_string();
    let dir_helper = DirectoryHelper::new(client);
    let mut root_dir = try!(dir_helper.get_user_root_directory_listing());
    let dir_metadata = match root_dir.find_sub_directory(&safe_drive_dir_name).cloned() {
        Some(metadata) => metadata,
        None => {
            trace!("SAFEDrive does not exist - creating one.");
            let (created_dir, _) = try!(dir_helper.create(safe_drive_dir_name,
                                                          UNVERSIONED_DIRECTORY_LISTING_TAG,
                                                          Vec::new(),
                                                          false,
                                                          AccessLevel::Private,
                                                          Some(&mut root_dir)));
            created_dir.get_metadata().clone()
        }
    };

    let key = dir_metadata.get_key().clone();
    Ok(key)
}

pub fn get_final_subdirectory(client: Arc<Mutex<Client>>,
                              tokens: &[String],
                              starting_directory: Option<&DirectoryKey>)
                              -> Result<DirectoryListing, FfiError> {
    trace!("Traverse directory tree to get the final subdirectory.");

    let dir_helper = DirectoryHelper::new(client);

    let mut current_dir_listing = match starting_directory {
        Some(directory_key) => {
            trace!("Traversal begins at given starting directory.");
            try!(dir_helper.get(directory_key))
        }
        None => {
            trace!("Traversal begins at user-root-directory.");
            try!(dir_helper.get_user_root_directory_listing())
        }
    };

    for it in tokens.iter() {
        trace!("Traversing to dir with name: {}", *it);

        current_dir_listing = {
            let current_dir_metadata = try!(current_dir_listing.get_sub_directories()
                .iter()
                .find(|a| *a.get_name() == *it)
                .ok_or(FfiError::PathNotFound));
            try!(dir_helper.get(current_dir_metadata.get_key()))
        };
    }

    Ok(current_dir_listing)
}

// Return a DirectoryListing corresponding to the path.
pub fn get_directory(app: &App, path: &str, is_shared: bool) -> Result<DirectoryListing, FfiError> {
    let start_dir_key = try!(app.get_root_dir_key(is_shared));
    let tokens = tokenise_path(path, false);
    get_final_subdirectory(app.get_client(), &tokens, Some(&start_dir_key))
}

pub fn get_directory_and_file(app: &App,
                              path: &str,
                              is_shared: bool)
                              -> Result<(DirectoryListing, String), FfiError> {
    let start_dir_key = try!(app.get_root_dir_key(is_shared));
    let mut tokens = tokenise_path(path, false);
    let file_name = try!(tokens.pop().ok_or(FfiError::PathNotFound));
    let directory_listing =
        try!(get_final_subdirectory(app.get_client(), &tokens, Some(&start_dir_key)));
    Ok((directory_listing, file_name))
}
