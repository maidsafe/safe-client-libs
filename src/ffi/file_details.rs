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

//! FFI-enabled types containing details (content and metadata) about a file.


use core::client::Client;
use ffi::config;
use ffi::errors::FfiError;
use nfs::file::File;
use nfs::helper::file_helper::FileHelper;
use nfs::metadata::file_metadata::FileMetadata as NfsFileMetadata;
use rustc_serialize::base64::ToBase64;
use std::ptr;
use std::sync::{Arc, Mutex};
use super::helper;

/// Details of a file and its content.
#[derive(Debug)]
#[repr(C)]
pub struct FileDetails {
    /// Content of the file, base64 encoded string.
    pub content: *mut u8,
    /// Size of `content`
    pub content_len: usize,
    /// Capacity of `content`. Only used by the allocator's `dealloc` algorithm.
    pub content_cap: usize,
    /// Metadata of the file.
    pub metadata: *mut FileMetadata,
}

impl FileDetails {
    /// Obtain `FileDetails` for the given file.
    pub fn new(file: &File,
               client: Arc<Mutex<Client>>,
               offset: i64,
               length: i64,
               include_metadata: bool)
               -> Result<Self, FfiError> {
        let start_position = offset as u64;
        let mut file_helper = FileHelper::new(client);
        let mut reader = try!(file_helper.read(&file));
        let mut size = length as u64;
        if size == 0 {
            size = reader.size() - start_position;
        };

        let content = try!(reader.read(start_position, size));
        let content = content.to_base64(config::get_base64_config());
        let (content, content_len, content_cap) = helper::string_to_c_utf8(content);

        let file_metadata_ptr = if include_metadata {
            Box::into_raw(Box::new(try!(FileMetadata::new(file.get_metadata()))))
        } else {
            ptr::null_mut()
        };

        Ok(FileDetails {
            content: content,
            content_len: content_len,
            content_cap: content_cap,
            metadata: file_metadata_ptr,
        })
    }

    // TODO: when drop-flag removal lands in stable, we should turn this into
    // a proper impl Drop.
    fn deallocate(self) {
        unsafe {
            helper::dealloc_c_utf8_alloced_from_rust(self.content,
                                                     self.content_len,
                                                     self.content_cap);
        }

        if !self.metadata.is_null() {
            let _ = unsafe { Box::from_raw(self.metadata) };
        }
    }
}

/// FFI-enabled wrapper for file metadata.
#[allow(missing_docs)]
#[derive(Debug)]
#[repr(C)]
pub struct FileMetadata {
    pub name: *mut u8,
    pub name_len: usize,
    pub name_cap: usize,
    pub user_metadata: *mut u8,
    pub user_metadata_len: usize,
    pub user_metadata_cap: usize,
    pub size: i64,
    pub creation_time_sec: i64,
    pub creation_time_nsec: i64,
    pub modification_time_sec: i64,
    pub modification_time_nsec: i64,
}

impl FileMetadata {
    /// Create new FFI file metadata wrapper.
    pub fn new(file_metadata: &NfsFileMetadata) -> Result<Self, FfiError> {
        use rustc_serialize::base64::ToBase64;

        let created_time = file_metadata.get_created_time().to_timespec();
        let modified_time = file_metadata.get_modified_time().to_timespec();

        let (name, name_len, name_cap) = helper::string_to_c_utf8(file_metadata.get_name()
            .to_string());

        let user_metadata = file_metadata.get_user_metadata()
            .to_base64(config::get_base64_config());
        let (user_metadata, user_metadata_len, user_metadata_cap) =
            helper::string_to_c_utf8(user_metadata);

        Ok(FileMetadata {
            name: name,
            name_len: name_len,
            name_cap: name_cap,
            size: file_metadata.get_size() as i64,
            user_metadata: user_metadata,
            user_metadata_len: user_metadata_len,
            user_metadata_cap: user_metadata_cap,
            creation_time_sec: created_time.sec,
            creation_time_nsec: created_time.nsec as i64,
            modification_time_sec: modified_time.sec,
            modification_time_nsec: modified_time.nsec as i64,
        })
    }

    /// Deallocate memory allocated by this struct (drop-flags workaround).
    // TODO: when drop-flag removal lands in stable, we should turn this into
    // a proper impl Drop.
    pub fn deallocate(&mut self) {
        unsafe {
            helper::dealloc_c_utf8_alloced_from_rust(self.name, self.name_len, self.name_cap);
            helper::dealloc_c_utf8_alloced_from_rust(self.user_metadata,
                                                     self.user_metadata_len,
                                                     self.user_metadata_cap);
        }
    }
}

/// Dispose of the FileDetails instance.
#[no_mangle]
pub unsafe extern "C" fn file_details_drop(details: *mut FileDetails) {
    Box::from_raw(details).deallocate()
}

/// Dispose of the FileMetadata instance.
#[no_mangle]
pub unsafe extern "C" fn file_metadata_drop(metadata: *mut FileMetadata) {
    Box::from_raw(metadata).deallocate()
}
