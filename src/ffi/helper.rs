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
use nfs::directory::Directory;
use nfs::helper::directory_helper::DirectoryHelper;
use nfs::metadata::DirectoryKey;
use std::error::Error;
use std::mem;
use std::panic;
use std::ptr;
use std::slice;
use std::str;
use std::sync::{Arc, Mutex};

pub unsafe fn c_utf8_to_string(ptr: *const u8, len: usize) -> Result<String, FfiError> {
    c_utf8_to_str(ptr, len).map(|v| v.to_owned())
}

pub unsafe fn c_utf8_to_str(ptr: *const u8, len: usize) -> Result<&'static str, FfiError> {
    str::from_utf8(slice::from_raw_parts(ptr, len))
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

// TODO: add c_utf8_to_opt_str (return Option<&str> instead of Option<String>)

/// Returns a heap-allocated raw string, usable by C/FFI-boundary.
/// The tuple means (pointer, length_in_bytes, capacity).
/// Use `misc_u8_ptr_free` to free the memory.
pub fn string_to_c_utf8(s: String) -> (*mut u8, usize, usize) {
    let mut v = s.into_bytes();
    v.shrink_to_fit();
    let p = v.as_mut_ptr();
    let len = v.len();
    let cap = v.capacity();
    mem::forget(v);
    (p, len, cap)
}

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

pub fn get_safe_drive_key(client: Arc<Mutex<Client>>) -> Result<DirectoryKey, FfiError> {
    trace!("Obtain directory key for SAFEDrive - This can be cached for efficiency. So if this \
            is seen many times, check for missed optimisation opportunity.");

    let safe_drive_dir_name = SAFE_DRIVE_DIR_NAME.to_string();
    let dir_helper = DirectoryHelper::new(client);
    let mut root_dir = try!(dir_helper.get_user_root_directory());
    let key = match root_dir.find_sub_directory(&safe_drive_dir_name).map(|dir| dir.key().clone()) {
        Some(sub_dir_key) => sub_dir_key,
        None => {
            trace!("SAFEDrive does not exist - creating one.");
            let (created_dir, _) = try!(dir_helper.create(safe_drive_dir_name,
                                                          UNVERSIONED_DIRECTORY_LISTING_TAG,
                                                          Vec::new(),
                                                          false,
                                                          AccessLevel::Private,
                                                          Some(&mut root_dir)));
            created_dir.key().clone()
        }
    };

    Ok(key)
}

// Return a DirectoryListing corresponding to the path.
pub fn get_directory(app: &App, path: &str, is_shared: bool) -> Result<Directory, FfiError> {
    let dir_helper = DirectoryHelper::new(app.get_client());
    let root_dir_key = try!(app.get_root_dir_key(is_shared));
    let (dir, _) = try!(dir_helper.get_directory_and_parent(&root_dir_key, path));
    Ok(dir)
}

pub fn get_directory_and_file(app: &App,
                              path: &str,
                              is_shared: bool)
                              -> Result<(Directory, String), FfiError> {
    let dir_helper = DirectoryHelper::new(app.get_client());
    let root_dir_key = try!(app.get_root_dir_key(is_shared));
    let (file_name, parent_dir) = try!(dir_helper.get_name_and_parent(&root_dir_key, path));
    Ok((parent_dir, file_name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn string_conversion() {
        let (ptr, size, cap) = string_to_c_utf8(String::new());
        assert_eq!(size, 0);
        unsafe { let _ = Vec::from_raw_parts(ptr, size, cap); }

        let (ptr, size, cap) = string_to_c_utf8("hello world".to_owned());
        assert!(ptr != 0 as *mut u8);
        assert_eq!(size, 11);
        assert!(cap >= 11);
        unsafe { let _ = Vec::from_raw_parts(ptr, size, cap); }
    }
}
