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

use std::sync::{Arc, Mutex};

use core::client::Client;
use ffi::config;
use ffi::errors::FfiError;
use nfs::directory_listing::DirectoryListing;
use nfs::helper::directory_helper::DirectoryHelper;
use nfs::metadata::directory_key::DirectoryKey;
use nfs::metadata::directory_metadata::DirectoryMetadata;
use nfs::metadata::file_metadata::FileMetadata;

#[derive(RustcEncodable, Debug)]
pub struct GetDirResponse {
    info: DirectoryInfo,
    files: Vec<FileInfo>,
    sub_directories: Vec<DirectoryInfo>,
}

#[derive(RustcEncodable, Debug)]
struct DirectoryInfo {
    name: String,
    is_private: bool,
    is_versioned: bool,
    user_metadata: String,
    creation_time_sec: i64,
    creation_time_nsec: i64,
    modification_time_sec: i64,
    modification_time_nsec: i64,
}

#[derive(RustcEncodable, Debug)]
struct FileInfo {
    name: String,
    size: i64,
    user_metadata: String,
    creation_time_sec: i64,
    creation_time_nsec: i64,
    modification_time_sec: i64,
    modification_time_nsec: i64,
}

pub fn get_response(client: Arc<Mutex<Client>>,
                    directory_key: DirectoryKey)
                    -> Result<GetDirResponse, FfiError> {
    let dir_helper = DirectoryHelper::new(client);
    let dir_listing = try!(dir_helper.get(&directory_key));
    Ok(convert_to_response(dir_listing))
}

pub fn convert_to_response(directory_listing: DirectoryListing) -> GetDirResponse {
    let dir_info = get_directory_info(directory_listing.get_metadata());
    let mut sub_dirs: Vec<DirectoryInfo> =
        Vec::with_capacity(directory_listing.get_sub_directories().len());
    for metadata in directory_listing.get_sub_directories() {
        sub_dirs.push(get_directory_info(metadata));
    }

    let mut files: Vec<FileInfo> = Vec::with_capacity(directory_listing.get_files().len());
    for file in directory_listing.get_files() {
        files.push(get_file_info(file.get_metadata()));
    }

    GetDirResponse {
        info: dir_info,
        files: files,
        sub_directories: sub_dirs,
    }
}

fn get_directory_info(dir_metadata: &DirectoryMetadata) -> DirectoryInfo {
    use rustc_serialize::base64::ToBase64;

    let dir_key = dir_metadata.get_key();
    let created_time = dir_metadata.get_created_time().to_timespec();
    let modified_time = dir_metadata.get_modified_time().to_timespec();

    DirectoryInfo {
        name: dir_metadata.get_name().to_owned(),
        is_private: *dir_key.get_access_level() == ::nfs::AccessLevel::Private,
        is_versioned: dir_key.is_versioned(),
        user_metadata: (*dir_metadata.get_user_metadata()).to_base64(config::get_base64_config()),
        creation_time_sec: created_time.sec,
        creation_time_nsec: created_time.nsec as i64,
        modification_time_sec: modified_time.sec,
        modification_time_nsec: modified_time.nsec as i64,
    }
}

fn get_file_info(file_metadata: &FileMetadata) -> FileInfo {
    use rustc_serialize::base64::ToBase64;

    let created_time = file_metadata.get_created_time().to_timespec();
    let modified_time = file_metadata.get_modified_time().to_timespec();
    FileInfo {
        name: file_metadata.get_name().to_owned(),
        size: file_metadata.get_size() as i64,
        user_metadata: (*file_metadata.get_user_metadata()).to_base64(config::get_base64_config()),
        creation_time_sec: created_time.sec,
        creation_time_nsec: created_time.nsec as i64,
        modification_time_sec: modified_time.sec,
        modification_time_nsec: modified_time.nsec as i64,
    }
}
