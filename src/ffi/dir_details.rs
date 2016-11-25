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

//! Details about directory and its content.

use ffi::FfiError;
use ffi::file_details::FileMetadata;
use nfs::Dir;
use nfs::DirMetadata as NfsDirMetadata;
use std::ptr;
use super::helper;

/// Details about a directory and its content.
#[derive(Debug)]
pub struct DirDetails {
    /// Metadata of this directory.
    pub metadata: Option<DirMetadata>,
    /// Metadata of every file of this directory.
    pub files: Vec<FileMetadata>,
    /// Metadata of every sub-directory of this directory.
    pub sub_dirs: Vec<DirMetadata>,
}

impl DirDetails {
    /// Obtain `DirDetails` without metadata from the given directory.
    pub fn from_dir(dir: Dir) -> Result<Self, FfiError> {
        let mut details = DirDetails {
            metadata: None,
            files: Vec::with_capacity(dir.files().len()),
            sub_dirs: Vec::with_capacity(dir.sub_dirs().len()),
        };

        for file in dir.files() {
            details.files.push(FileMetadata::new(file.metadata())?);
        }

        for metadata in dir.sub_dirs() {
            details.sub_dirs.push(DirMetadata::new(metadata)?);
        }

        Ok(details)
    }

    /// Obtain `DirDetails` from the given directory and metadata.
    pub fn from_dir_and_metadata(dir: Dir, metadata: NfsDirMetadata) -> Result<Self, FfiError> {
        let mut details = Self::from_dir(dir)?;
        details.metadata = Some(DirMetadata::new(&metadata)?);
        Ok(details)
    }
}

#[allow(missing_docs)]
#[derive(Debug)]
#[repr(C)]
pub struct DirMetadata {
    pub name: *mut u8,
    pub name_len: usize,
    pub name_cap: usize,
    pub user_metadata: *mut u8,
    pub user_metadata_len: usize,
    pub user_metadata_cap: usize,
    pub is_private: bool,
    pub creation_time_sec: i64,
    pub creation_time_nsec: i64,
    pub modification_time_sec: i64,
    pub modification_time_nsec: i64,
}

impl DirMetadata {
    fn new(dir_metadata: &NfsDirMetadata) -> Result<Self, FfiError> {
        let created_time = dir_metadata.created_time().to_timespec();
        let modified_time = dir_metadata.modified_time().to_timespec();

        let (name, name_len, name_cap) = helper::string_to_c_utf8(dir_metadata.name()
            .to_string());
        let user_metadata = dir_metadata.user_metadata().to_owned();
        let (user_metadata, user_metadata_len, user_metadata_cap) =
            helper::u8_vec_to_ptr(user_metadata);

        Ok(DirMetadata {
            name: name,
            name_len: name_len,
            name_cap: name_cap,
            user_metadata: user_metadata,
            user_metadata_len: user_metadata_len,
            user_metadata_cap: user_metadata_cap,
            is_private: dir_metadata.encrypt_key().is_some(),
            creation_time_sec: created_time.sec,
            creation_time_nsec: created_time.nsec as i64,
            modification_time_sec: modified_time.sec,
            modification_time_nsec: modified_time.nsec as i64,
        })
    }
}

impl Drop for DirMetadata {
    fn drop(&mut self) {
        unsafe {
            let _ = Vec::from_raw_parts(self.name, self.name_len, self.name_cap);
            let _ = Vec::from_raw_parts(self.user_metadata,
                                        self.user_metadata_len,
                                        self.user_metadata_cap);
        }
    }
}

/// Get non-owning pointer to the directory metadata.
#[no_mangle]
pub unsafe extern "C" fn directory_details_get_metadata(details: *const DirDetails)
                                                        -> *const DirMetadata {
    helper::catch_unwind_ok(|| {
        match (*details).metadata {
            Some(ref metadata) => metadata,
            None => ptr::null(),
        }
    })
}

/// Get the number of files in the directory.
#[no_mangle]
pub unsafe extern "C" fn directory_details_get_files_len(details: *const DirDetails) -> usize {
    helper::catch_unwind_ok(|| (*details).files.len())
}

/// Get a non-owning pointer to the metadata of the i-th file in the directory.
#[no_mangle]
pub unsafe extern "C" fn directory_details_get_file_at(details: *const DirDetails,
                                                       index: usize)
                                                       -> *const FileMetadata {
    helper::catch_unwind_ok(|| {
        let details = &*details;

        if index < details.files.len() {
            &details.files[index]
        } else {
            ptr::null()
        }
    })
}

/// Get the number of sub-directories in the directory.
#[no_mangle]
pub unsafe extern "C" fn directory_details_get_sub_directories_len(details: *const DirDetails)
                                                                   -> usize {
    helper::catch_unwind_ok(|| (*details).sub_dirs.len())
}

/// Get a non-owning pointer to the metadata of the i-th sub-directory of the
/// directory.
#[no_mangle]
pub unsafe extern "C" fn directory_details_get_sub_directory_at(details: *const DirDetails,
                                                                index: usize)
                                                                -> *const DirMetadata {
    helper::catch_unwind_ok(|| {
        let details = &*details;

        if index < details.sub_dirs.len() {
            &details.sub_dirs[index]
        } else {
            ptr::null()
        }
    })
}

/// Dispose of the DirDetails instance.
#[no_mangle]
pub unsafe extern "C" fn directory_details_free(details: *mut DirDetails) {
    helper::catch_unwind_ok(|| {
        let _ = Box::from_raw(details);
    })
}
