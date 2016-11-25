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

//! FFI-enabled types containing details (content and metadata) about a file.

use core::Client;
use core::futures::FutureExt;
use ffi::{FfiError, FfiFuture};
use futures::Future;
use nfs::File;
use nfs::FileMetadata as NfsFileMetadata;
use nfs::helper::file_helper;
use std::ptr;
use super::helper;

/// Details of a single file version or an unversioned file and its contents.
#[derive(Debug)]
#[repr(C)]
pub struct FileDetails {
    /// Content of the file
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
    /// If file is versioned, then the latest version is returned.
    pub fn new(file: File,
               client: Client,
               offset: i64,
               length: i64,
               include_metadata: bool)
               -> Box<FfiFuture<Self>> {
        let start_position = offset as u64;

        let reader = fry!(file_helper::read(client, &file.metadata()).map_err(FfiError::from));
        let mut size = length as u64;
        if size == 0 {
            size = reader.size() - start_position;
        };

        reader.read(start_position, size)
            .map_err(FfiError::from)
            .and_then(move |content| {
                let (content, content_len, content_cap) = helper::u8_vec_to_ptr(content);

                let file_metadata_ptr = if include_metadata {
                    Box::into_raw(Box::new(FileMetadata::new(file.metadata())?))
                } else {
                    ptr::null_mut()
                };

                Ok(FileDetails {
                    content: content,
                    content_len: content_len,
                    content_cap: content_cap,
                    metadata: file_metadata_ptr,
                })
            })
            .into_box()
    }
}

impl Drop for FileDetails {
    fn drop(&mut self) {
        unsafe {
            let _ = Vec::from_raw_parts(self.content, self.content_len, self.content_cap);
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
    pub size: u64,
    pub creation_time_sec: i64,
    pub creation_time_nsec: i64,
    pub modification_time_sec: i64,
    pub modification_time_nsec: i64,
}

impl FileMetadata {
    /// Create new FFI file metadata wrapper.
    pub fn new(file_metadata: &NfsFileMetadata) -> Result<Self, FfiError> {
        let created_time = file_metadata.created_time().to_timespec();
        let modified_time = file_metadata.modified_time().to_timespec();

        let (name, name_len, name_cap) = helper::string_to_c_utf8(file_metadata.name()
            .to_string());

        let user_metadata = file_metadata.user_metadata().to_owned();
        let (user_metadata, user_metadata_len, user_metadata_cap) =
            helper::u8_vec_to_ptr(user_metadata);

        Ok(FileMetadata {
            name: name,
            name_len: name_len,
            name_cap: name_cap,
            size: file_metadata.size(),
            user_metadata: user_metadata,
            user_metadata_len: user_metadata_len,
            user_metadata_cap: user_metadata_cap,
            creation_time_sec: created_time.sec,
            creation_time_nsec: created_time.nsec as i64,
            modification_time_sec: modified_time.sec,
            modification_time_nsec: modified_time.nsec as i64,
        })
    }
}

impl Drop for FileMetadata {
    fn drop(&mut self) {
        unsafe {
            let _ = Vec::from_raw_parts(self.name, self.name_len, self.name_cap);
            let _ = Vec::from_raw_parts(self.user_metadata,
                                        self.user_metadata_len,
                                        self.user_metadata_cap);
        }
    }
}

/// Dispose of the FileDetails instance.
#[no_mangle]
pub unsafe extern "C" fn file_details_drop(details: *mut FileDetails) {
    let _ = Box::from_raw(details);
}

/// Dispose of the FileMetadata instance.
#[no_mangle]
pub unsafe extern "C" fn file_metadata_drop(metadata: *mut FileMetadata) {
    let _ = Box::from_raw(metadata);
}
