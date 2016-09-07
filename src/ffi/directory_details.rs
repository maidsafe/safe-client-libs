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

//! Details about directory and its content.


use core::client::Client;
use ffi::config;
use ffi::errors::FfiError;
use ffi::file_details::FileMetadata;
use nfs::directory_listing::DirectoryListing;
use nfs::helper::directory_helper::DirectoryHelper;
use nfs::metadata::directory_key::DirectoryKey;
use nfs::metadata::directory_metadata::DirectoryMetadata as NfsDirectoryMetadata;
use std::ptr;
use std::sync::{Arc, Mutex};
use super::helper;

/// Details about a directory and its content.
#[derive(Debug)]
pub struct DirectoryDetails {
    /// Metadata of this directory.
    pub metadata: DirectoryMetadata,
    /// Metadata of every file of this directory.
    pub files: Vec<FileMetadata>,
    /// Metadata of every sub-directory of this directory.
    pub sub_directories: Vec<DirectoryMetadata>,
}

impl DirectoryDetails {
    /// Obtain `DirectoryDetails` from the given directory key.
    pub fn from_directory_key(client: Arc<Mutex<Client>>,
                              directory_key: DirectoryKey)
                              -> Result<Self, FfiError> {
        let dir_helper = DirectoryHelper::new(client);
        let dir_listing = try!(dir_helper.get(&directory_key));

        Self::from_directory_listing(dir_listing)
    }

    /// Obtain `DirectoryDetails` from the given directory listing.
    pub fn from_directory_listing(listing: DirectoryListing) -> Result<Self, FfiError> {
        let mut details = DirectoryDetails {
            metadata: try!(DirectoryMetadata::new(listing.get_metadata())),
            files: Vec::with_capacity(listing.get_files().len()),
            sub_directories: Vec::with_capacity(listing.get_sub_directories().len()),
        };

        for file in listing.get_files() {
            details.files.push(try!(FileMetadata::new(file.get_metadata())));
        }

        for metadata in listing.get_sub_directories() {
            details.sub_directories.push(try!(DirectoryMetadata::new(metadata)));
        }

        Ok(details)
    }
}

// TODO: when drop-flags removal lands in stable, we should implement Drop for
// DirectoryMetadata and FileMetadata and remove this whole impl.
impl Drop for DirectoryDetails {
    fn drop(&mut self) {
        self.metadata.deallocate();

        for mut metadata in self.files.drain(..) {
            metadata.deallocate();
        }

        for mut metadata in self.sub_directories.drain(..) {
            metadata.deallocate();
        }
    }
}

#[allow(missing_docs)]
#[derive(Debug)]
#[repr(C)]
pub struct DirectoryMetadata {
    pub name: *mut u8,
    pub name_len: usize,
    pub name_cap: usize,
    pub user_metadata: *mut u8,
    pub user_metadata_len: usize,
    pub user_metadata_cap: usize,
    pub is_private: bool,
    pub is_versioned: bool,
    pub creation_time_sec: i64,
    pub creation_time_nsec: i64,
    pub modification_time_sec: i64,
    pub modification_time_nsec: i64,
}

impl DirectoryMetadata {
    fn new(dir_metadata: &NfsDirectoryMetadata) -> Result<Self, FfiError> {
        use rustc_serialize::base64::ToBase64;

        let dir_key = dir_metadata.get_key();
        let created_time = dir_metadata.get_created_time().to_timespec();
        let modified_time = dir_metadata.get_modified_time().to_timespec();

        let (name, name_len, name_cap) = helper::string_to_c_utf8(dir_metadata.get_name()
            .to_string());
        let user_metadata = dir_metadata.get_user_metadata().to_base64(config::get_base64_config());
        let (user_metadata, user_metadata_len, user_metadata_cap) =
            helper::string_to_c_utf8(user_metadata);

        Ok(DirectoryMetadata {
            name: name,
            name_len: name_len,
            name_cap: name_cap,
            user_metadata: user_metadata,
            user_metadata_len: user_metadata_len,
            user_metadata_cap: user_metadata_cap,
            is_private: *dir_key.get_access_level() == ::nfs::AccessLevel::Private,
            is_versioned: dir_key.is_versioned(),
            creation_time_sec: created_time.sec,
            creation_time_nsec: created_time.nsec as i64,
            modification_time_sec: modified_time.sec,
            modification_time_nsec: modified_time.nsec as i64,
        })
    }

    // TODO: when drop-flag removal lands in stable, we should turn this into
    // a proper impl Drop.
    fn deallocate(&mut self) {
        unsafe {
            let _ =
                helper::dealloc_c_utf8_alloced_from_rust(self.name, self.name_len, self.name_cap);
            let _ = helper::dealloc_c_utf8_alloced_from_rust(self.user_metadata,
                                                             self.user_metadata_len,
                                                             self.user_metadata_cap);
        }
    }
}

/// Get non-owning pointer to the directory metadata.
#[no_mangle]
pub unsafe extern "C" fn directory_details_get_metadata(details: *const DirectoryDetails)
                                                        -> *const DirectoryMetadata {
    &(*details).metadata
}

/// Get the number of files in the directory.
#[no_mangle]
pub unsafe extern "C" fn directory_details_get_files_len(details: *const DirectoryDetails) -> u64 {
    (*details).files.len() as u64
}

/// Get a non-owning pointer to the metadata of the i-th file in the directory.
#[no_mangle]
pub unsafe extern "C" fn directory_details_get_file_at(details: *const DirectoryDetails,
                                                       index: u64)
                                                       -> *const FileMetadata {
    let details = &*details;
    let index = index as usize;

    if index < details.files.len() {
        &details.files[index]
    } else {
        ptr::null()
    }
}

/// Get the number of sub-directories in the directory.
#[no_mangle]
pub unsafe extern "C" fn directory_details_get_sub_directories_len(
    details: *const DirectoryDetails) -> u64 {
    (*details).sub_directories.len() as u64
}

/// Get a non-owning pointer to the metadata of the i-th sub-directory of the
/// directory.
#[no_mangle]
pub unsafe extern "C" fn directory_details_get_sub_directory_at(details: *const DirectoryDetails,
                                                                index: u64)
                                                                -> *const DirectoryMetadata {
    let details = &*details;
    let index = index as usize;

    if index < details.sub_directories.len() {
        &details.sub_directories[index]
    } else {
        ptr::null()
    }
}

/// Dispose of the DirectoryDetails instance.
#[no_mangle]
pub unsafe extern "C" fn directory_details_drop(details: *mut DirectoryDetails) {
    let _ = Box::from_raw(details);
}
