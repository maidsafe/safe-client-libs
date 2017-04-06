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


use dns::dns_operations::DnsOperations;
use ffi::app::App;
use ffi::errors::FfiError;
use ffi::file_details::{FileDetails, FileMetadata};
use ffi::helper;
use libc::int32_t;

/// Get file.
#[no_mangle]
pub unsafe extern "C" fn dns_get_file(app_handle: *const App,
                                      long_name: *const u8,
                                      long_name_len: usize,
                                      service_name: *const u8,
                                      service_name_len: usize,
                                      file_path: *const u8,
                                      file_path_len: usize,
                                      offset: i64,
                                      length: i64,
                                      include_metadata: bool,
                                      details_handle: *mut *mut FileDetails)
                                      -> int32_t {
    helper::catch_unwind_i32(|| {
        let long_name = ffi_try!(helper::c_utf8_to_string(long_name, long_name_len));
        let service_name = ffi_try!(helper::c_utf8_to_string(service_name, service_name_len));
        let file_path = ffi_try!(helper::c_utf8_to_string(file_path, file_path_len));

        trace!("FFI get file located at given path starting from home directory of \"//{}.{}\".",
               service_name,
               long_name);

        let response = ffi_try!(get_file(&*app_handle,
                                         &long_name,
                                         &service_name,
                                         &file_path,
                                         offset,
                                         length,
                                         include_metadata));

        *details_handle = Box::into_raw(Box::new(response));
        0
    })
}

/// Get file metadata.
#[no_mangle]
pub unsafe extern "C" fn dns_get_file_metadata(app_handle: *const App,
                                               long_name: *const u8,
                                               long_name_len: usize,
                                               service_name: *const u8,
                                               service_name_len: usize,
                                               file_path: *const u8,
                                               file_path_len: usize,
                                               metadata_handle: *mut *mut FileMetadata)
                                               -> int32_t {
    helper::catch_unwind_i32(|| {
        let long_name = ffi_try!(helper::c_utf8_to_string(long_name, long_name_len));
        let service_name = ffi_try!(helper::c_utf8_to_string(service_name, service_name_len));
        let file_path = ffi_try!(helper::c_utf8_to_string(file_path, file_path_len));

        trace!("FFI get file metadata for file located at given path starting from home \
                directory of \"//{}.{}\".",
               service_name,
               long_name);

        let metadata =
            ffi_try!(get_file_metadata(&*app_handle, &long_name, &service_name, &file_path));

        *metadata_handle = Box::into_raw(Box::new(metadata));
        0
    })
}



fn get_file(app: &App,
            long_name: &str,
            service_name: &str,
            file_path: &str,
            offset: i64,
            length: i64,
            include_metadata: bool)
            -> Result<FileDetails, FfiError> {
    let dns_operations = match app.get_app_dir_key() {
        Some(_) => DnsOperations::new(app.get_client())?,
        None => DnsOperations::new_unregistered(app.get_client()),
    };
    let directory_key = dns_operations
        .get_service_home_directory_key(long_name, service_name, None)?;
    let mut tokens = helper::tokenise_path(file_path, false);
    let file_name = tokens.pop().ok_or(FfiError::InvalidPath)?;
    let file_dir = helper::get_final_subdirectory(app.get_client(), &tokens, Some(&directory_key))?;
    let file = file_dir
        .find_file(&file_name)
        .ok_or(FfiError::InvalidPath)?;

    FileDetails::new(file, app.get_client(), offset, length, include_metadata)
}

fn get_file_metadata(app: &App,
                     long_name: &str,
                     service_name: &str,
                     file_path: &str)
                     -> Result<FileMetadata, FfiError> {
    let dns_operations = match app.get_app_dir_key() {
        Some(_) => DnsOperations::new(app.get_client())?,
        None => DnsOperations::new_unregistered(app.get_client()),
    };

    let directory_key = dns_operations
        .get_service_home_directory_key(long_name, service_name, None)?;
    let mut tokens = helper::tokenise_path(file_path, false);
    let file_name = tokens.pop().ok_or(FfiError::InvalidPath)?;
    let file_dir = helper::get_final_subdirectory(app.get_client(), &tokens, Some(&directory_key))?;
    let file = file_dir
        .find_file(&file_name)
        .ok_or(FfiError::InvalidPath)?;

    FileMetadata::new(&file.get_metadata().clone())
}

#[cfg(test)]
mod test {

    use core::utility;
    use dns::dns_operations::DnsOperations;
    use ffi::app::App;
    use ffi::test_utils;
    use nfs::{AccessLevel, UNVERSIONED_DIRECTORY_LISTING_TAG};
    use nfs::helper::directory_helper::DirectoryHelper;
    use nfs::helper::file_helper::FileHelper;
    use nfs::metadata::directory_key::DirectoryKey;
    use rust_sodium::crypto::box_;
    use std::collections::BTreeSet;

    fn create_public_file(app: &App, file_name: String, file_content: Vec<u8>) -> DirectoryKey {
        let dir_helper = DirectoryHelper::new(app.get_client());
        let mut file_helper = FileHelper::new(app.get_client());

        let app_dir_key = unwrap!(app.get_app_dir_key());
        let mut app_dir = unwrap!(dir_helper.get(&app_dir_key));

        let (file_dir, _) = unwrap!(dir_helper.create("public-dir".to_string(),
                                                      UNVERSIONED_DIRECTORY_LISTING_TAG,
                                                      vec![0u8; 0],
                                                      false,
                                                      AccessLevel::Public,
                                                      Some(&mut app_dir)));
        let dir_key = *file_dir.get_key();

        let bin_metadata = vec![0u8; 0];
        let mut writer = unwrap!(file_helper.create(file_name, bin_metadata, file_dir));
        unwrap!(writer.write(&file_content));
        let _ = unwrap!(writer.close());

        dir_key
    }

    fn register_service(app: &App,
                        service_name: String,
                        public_name: String,
                        dir_key: DirectoryKey) {
        let (msg_public_key, msg_secret_key) = box_::gen_keypair();
        let services = vec![(service_name, dir_key)];
        let client = app.get_client();

        let public_signing_key = *unwrap!(unwrap!(client.lock()).get_public_signing_key());
        let secret_signing_key = unwrap!(unwrap!(client.lock()).get_secret_signing_key()).clone();
        let dns_operation = unwrap!(DnsOperations::new(client));

        let mut owners = BTreeSet::new();
        owners.insert(public_signing_key);

        unwrap!(dns_operation.register_dns(public_name,
                                           &msg_public_key,
                                           &msg_secret_key,
                                           &services,
                                           owners,
                                           &secret_signing_key,
                                           None));
    }

    #[test]
    fn get_public_file() {
        let app = test_utils::create_app(false);

        let file_name = "index.html";
        let file_content = "<html><title>Home</title></html>";

        let public_directory_key = create_public_file(&app,
                                                      file_name.to_string(),
                                                      file_content.as_bytes().to_vec());
        let service_name = "www";
        let public_name = unwrap!(utility::generate_random_string(10));

        register_service(&app,
                         service_name.to_string(),
                         public_name.clone(),
                         public_directory_key);

        let _ = unwrap!(super::get_file(&app, &public_name, service_name, file_name, 0, 0, false));

        // Fetch the file using a new client
        let app2 = test_utils::create_app(false);

        let _ = unwrap!(super::get_file(&app2, &public_name, service_name, file_name, 0, 0, false));

        // Fetch the file using an unregisterd client
        let app3 = test_utils::create_unregistered_app();

        let _ = unwrap!(super::get_file(&app3, &public_name, service_name, file_name, 0, 0, false));
    }
}
