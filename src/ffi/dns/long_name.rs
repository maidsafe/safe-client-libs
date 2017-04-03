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

//! DNS Long name operations


use dns::dns_operations::DnsOperations;
use ffi::app::App;
use ffi::errors::FfiError;
use ffi::helper;
use ffi::string_list::{self, StringList};
use libc::int32_t;
use rust_sodium::crypto::box_;
use std::collections::BTreeSet;

/// Register DNS long name (for calling via FFI).
#[no_mangle]
pub unsafe extern "C" fn dns_register_long_name(app_handle: *const App,
                                                long_name: *const u8,
                                                long_name_len: usize)
                                                -> int32_t {
    helper::catch_unwind_i32(|| {
        let long_name = ffi_try!(helper::c_utf8_to_string(long_name, long_name_len));

        trace!("FFI register public-id with name: {}. This means to register dns without a \
                given service.",
               long_name);

        ffi_try!(register_long_name(&*app_handle, long_name));
        0
    })
}

/// Register DNS long name (for calling from rust).
#[no_mangle]
pub fn register_long_name(app: &App, long_name: String) -> Result<(), FfiError> {
    let (msg_public_key, msg_secret_key) = box_::gen_keypair();
    let services = vec![];
    let client = app.get_client();

    let (owners, private_signing_key) = {
        let client_guard = unwrap!(client.lock());

        let mut owners = BTreeSet::new();
        owners.insert(*client_guard.get_public_signing_key()?);

        let private_signing_key = client_guard.get_secret_signing_key()?.clone();
        (owners, private_signing_key)
    };

    let dns_operation = DnsOperations::new(client.clone())?;
    dns_operation.register_dns(long_name,
                      &msg_public_key,
                      &msg_secret_key,
                      &services,
                      owners,
                      &private_signing_key,
                      None)?;

    Ok(())
}

/// Delete DNS.
#[no_mangle]
#[cfg_attr(rustfmt, rustfmt_skip)]
pub unsafe extern "C" fn dns_delete_long_name(app_handle: *const App,
                                              long_name: *const u8,
                                              long_name_len: usize)
                                              -> int32_t {
    helper::catch_unwind_i32(|| {
        trace!("FFI delete DNS.");
        let long_name = ffi_try!(helper::c_utf8_to_string(long_name, long_name_len));
        ffi_try!(delete_long_name(&*app_handle, &long_name));
        0
    })
}

/// Get all registered long names.
#[no_mangle]
pub unsafe extern "C" fn dns_get_long_names(app_handle: *const App,
                                            list_handle: *mut *mut StringList)
                                            -> int32_t {
    helper::catch_unwind_i32(|| {
                                 trace!("FFI Get all dns long names.");

                                 let list = ffi_try!(get_long_names(&*app_handle));
                                 *list_handle = ffi_try!(string_list::into_ptr(list));
                                 0
                             })
}

fn delete_long_name(app: &App, long_name: &str) -> Result<(), FfiError> {
    let client = app.get_client();
    let signing_key = unwrap!(client.lock()).get_secret_signing_key()?.clone();
    let dns_ops = DnsOperations::new(client)?;
    dns_ops.delete_dns(long_name, &signing_key)?;

    Ok(())
}

fn get_long_names(app: &App) -> Result<Vec<String>, FfiError> {
    let dns_ops = DnsOperations::new(app.get_client())?;
    let list = dns_ops.get_all_registered_names()?;
    Ok(list)
}

#[cfg(test)]
mod test {
    use core::utility;
    use ffi::test_utils;

    #[test]
    fn register_long_name() {
        let app = test_utils::create_app(false);
        let public_name = unwrap!(utility::generate_random_string(10));

        assert!(super::register_long_name(&app, public_name.clone()).is_ok());

        let app2 = test_utils::create_app(false);
        assert!(super::register_long_name(&app2, public_name).is_err());
    }
}
