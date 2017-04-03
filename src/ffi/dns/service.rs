// Copyright 2015 MaidSafe.net limited.
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

//! DNS service operations


use dns::dns_operations::DnsOperations;
use ffi::app::App;
use ffi::directory_details::DirectoryDetails;
use ffi::errors::FfiError;
use ffi::helper;
use ffi::string_list::{self, StringList};
use libc::int32_t;

/// Add service.
#[no_mangle]
pub unsafe extern "C" fn dns_add_service(app_handle: *const App,
                                         long_name: *const u8,
                                         long_name_len: usize,
                                         service_name: *const u8,
                                         service_name_len: usize,
                                         service_home_dir_path: *const u8,
                                         service_home_dir_path_len: usize,
                                         is_path_shared: bool)
                                         -> int32_t {
    helper::catch_unwind_i32(|| {
        trace!("FFI add service.");

        let long_name = ffi_try!(helper::c_utf8_to_string(long_name, long_name_len));
        let service_name = ffi_try!(helper::c_utf8_to_string(service_name, service_name_len));
        let service_home_dir_path = ffi_try!(helper::c_utf8_to_string(service_home_dir_path,
                                                                      service_home_dir_path_len));

        ffi_try!(add_service(&*app_handle,
                             long_name,
                             service_name,
                             &service_home_dir_path,
                             is_path_shared));
        0
    })
}

/// Delete DNS service.
#[no_mangle]
pub unsafe extern "C" fn dns_delete_service(app_handle: *const App,
                                            long_name: *const u8,
                                            long_name_len: usize,
                                            service_name: *const u8,
                                            service_name_len: usize)
                                            -> int32_t {
    helper::catch_unwind_i32(|| {
        trace!("FFI delete service.");

        let long_name = ffi_try!(helper::c_utf8_to_string(long_name, long_name_len));
        let service_name = ffi_try!(helper::c_utf8_to_string(service_name, service_name_len));

        ffi_try!(delete_service(&*app_handle, long_name, service_name));
        0
    })
}

/// Get home directory of the given service.
#[no_mangle]
pub unsafe extern "C" fn dns_get_service_dir(app_handle: *const App,
                                             long_name: *const u8,
                                             long_name_len: usize,
                                             service_name: *const u8,
                                             service_name_len: usize,
                                             details_handle: *mut *mut DirectoryDetails)
                                             -> int32_t {
    helper::catch_unwind_i32(|| {
        let long_name = ffi_try!(helper::c_utf8_to_string(long_name, long_name_len));
        let service_name = ffi_try!(helper::c_utf8_to_string(service_name, service_name_len));

        trace!("FFI Get service home directory for \"//{}.{}\".",
               service_name,
               long_name);

        let response = ffi_try!(get_service_dir(&*app_handle, &long_name, &service_name));
        *details_handle = Box::into_raw(Box::new(response));
        0
    })
}

/// Get all registered long names.
#[no_mangle]
pub unsafe extern "C" fn dns_get_services(app_handle: *const App,
                                          long_name: *const u8,
                                          long_name_len: usize,
                                          list_handle: *mut *mut StringList)
                                          -> int32_t {
    helper::catch_unwind_i32(|| {
        let long_name = ffi_try!(helper::c_utf8_to_string(long_name, long_name_len));

        trace!("FFI Get all services for dns with name: {}", long_name);

        let list = ffi_try!(get_services(&*app_handle, &long_name));
        *list_handle = ffi_try!(string_list::into_ptr(list));
        0
    })
}



fn add_service(app: &App,
               long_name: String,
               service_name: String,
               service_home_dir_path: &str,
               is_path_shared: bool)
               -> Result<(), FfiError> {
    let dir_to_map = helper::get_directory(app, service_home_dir_path, is_path_shared)?;
    let client = app.get_client();
    let signing_key = unwrap!(client.lock()).get_secret_signing_key()?.clone();
    let dns_operation = DnsOperations::new(client)?;

    dns_operation.add_service(&long_name,
                     (service_name, *dir_to_map.get_key()),
                     &signing_key,
                     None)?;
    Ok(())
}


fn delete_service(app: &App, long_name: String, service_name: String) -> Result<(), FfiError> {
    let client = app.get_client();
    let signing_key = unwrap!(client.lock()).get_secret_signing_key()?.clone();
    let dns_ops = DnsOperations::new(client)?;

    dns_ops.remove_service(&long_name, service_name, &signing_key, None)?;

    Ok(())
}

fn get_service_dir(app: &App,
                   long_name: &str,
                   service_name: &str)
                   -> Result<DirectoryDetails, FfiError> {
    let dns_operations = match app.get_app_dir_key() {
        Some(_) => DnsOperations::new(app.get_client())?,
        None => DnsOperations::new_unregistered(app.get_client()),
    };

    let directory_key =
        dns_operations.get_service_home_directory_key(long_name, service_name, None)?;
    DirectoryDetails::from_directory_key(app.get_client(), directory_key)
}

fn get_services(app: &App, long_name: &str) -> Result<Vec<String>, FfiError> {
    let dns_ops = DnsOperations::new(app.get_client())?;
    let list = dns_ops.get_all_services(long_name, None)?;

    Ok(list)
}

#[cfg(test)]
mod test {
    use core::utility;
    use ffi::dns::long_name;
    use ffi::test_utils;
    use nfs::{AccessLevel, UNVERSIONED_DIRECTORY_LISTING_TAG};
    use nfs::helper::directory_helper::DirectoryHelper;

    #[test]
    fn add_service() {
        let app = test_utils::create_app(false);
        let dir_helper = DirectoryHelper::new(app.get_client());
        let app_root_dir_key = &unwrap!(app.get_app_dir_key());
        let mut app_root_dir = unwrap!(dir_helper.get(&app_root_dir_key));

        let public_name = unwrap!(utility::generate_random_string(10));

        let _ = unwrap!(dir_helper.create("test_dir".to_string(),
                                          UNVERSIONED_DIRECTORY_LISTING_TAG,
                                          Vec::new(),
                                          false,
                                          AccessLevel::Public,
                                          Some(&mut app_root_dir)));

        unwrap!(long_name::register_long_name(&app, public_name.clone()));
        assert!(super::add_service(&app, public_name, "www".to_string(), "/test_dir", false)
                    .is_ok());
    }

    #[test]
    fn get_service_dir() {
        let app = test_utils::create_app(false);
        let dir_helper = DirectoryHelper::new(app.get_client());
        let app_root_dir_key = unwrap!(app.get_app_dir_key());
        let mut app_root_dir = unwrap!(dir_helper.get(&app_root_dir_key));

        let _ = unwrap!(dir_helper.create("test_dir".to_string(),
                                          UNVERSIONED_DIRECTORY_LISTING_TAG,
                                          Vec::new(),
                                          false,
                                          AccessLevel::Public,
                                          Some(&mut app_root_dir)));

        let public_name = unwrap!(utility::generate_random_string(10));

        unwrap!(long_name::register_long_name(&app, public_name.clone()));
        unwrap!(super::add_service(&app,
                                   public_name.clone(),
                                   "www".to_string(),
                                   "/test_dir",
                                   false));
        unwrap!(super::add_service(&app,
                                   public_name.clone(),
                                   "bloq".to_string(),
                                   "/test_dir",
                                   false));

        let app2 = test_utils::create_unregistered_app();
        assert!(super::get_service_dir(&app2, &public_name, "www").is_ok());
    }
}
