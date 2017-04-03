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

use core::utility;
use ffi::app::App;
use ffi::session::Session;
use std::ffi::CString;
use std::sync::{Arc, Mutex};

pub fn generate_random_cstring(len: usize) -> CString {
    let mut cstring_vec = unwrap!(utility::generate_random_vector::<u8>(len));

    // Avoid internal nulls and ensure valid ASCII (thus valid utf8)
    for it in &mut cstring_vec {
        *it %= 128;
        if *it == 0 {
            *it += 1;
        }
    }

    // Ok to unwrap, as we took care of removing all NULs above.
    unwrap!(CString::new(cstring_vec))
}

pub fn create_app(has_safe_drive_access: bool) -> App {
    let acc_locator = unwrap!(utility::generate_random_string(10));
    let acc_password = unwrap!(utility::generate_random_string(10));
    let invitation = unwrap!(utility::generate_random_string(10));

    let session = unwrap!(Session::create_account(&acc_locator, &acc_password, &invitation));
    let app_name = "Test App".to_string();
    let app_id = unwrap!(utility::generate_random_string(10));
    let vendor = "Test Vendor".to_string();

    unwrap!(App::registered(Arc::new(Mutex::new(session)),
                            app_name,
                            app_id,
                            vendor,
                            has_safe_drive_access))
}

pub fn create_unregistered_app() -> App {
    let session = unwrap!(Session::create_unregistered_client());
    App::unregistered(Arc::new(Mutex::new(session)))
}
