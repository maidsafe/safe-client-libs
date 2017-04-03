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

#[cfg_attr(test, macro_use)]
extern crate maidsafe_utilities;
#[macro_use]
extern crate unwrap;

extern crate rust_sodium;
extern crate safe_core;

use rust_sodium::crypto::hash::sha256::{self, Digest};
use safe_core::ffi::app::*;
use safe_core::ffi::low_level_api::appendable_data::*;
use safe_core::ffi::low_level_api::cipher_opt::*;
use safe_core::ffi::low_level_api::data_id::*;
use safe_core::ffi::low_level_api::immut_data::*;
use safe_core::ffi::low_level_api::misc::*;
use safe_core::ffi::session::*;
use std::{ptr, slice};

unsafe fn self_auth(session_h: *mut *mut SessionHandle) {
    unwrap!(maidsafe_utilities::log::init(true));

    println!("\nDo you already have an account created (enter Y for yes) ?");

    let mut user_option = String::new();
    let _ = std::io::stdin().read_line(&mut user_option);
    user_option = user_option.trim().to_string();

    if user_option != "Y" && user_option != "y" {
        println!("\n\tAccount Creation");
        println!("\t================");
    } else {
        println!("\n\n\tAccount Login");
        println!("\t====================");
    }

    let mut secret_0 = String::new();
    let mut secret_1 = String::new();
    let mut invitation = String::new();

    println!("\n------------ Enter account-locator ---------------");
    let _ = std::io::stdin().read_line(&mut secret_0);
    secret_0 = secret_0.trim().to_string();

    println!("\n------------ Enter password ---------------");
    let _ = std::io::stdin().read_line(&mut secret_1);
    secret_1 = secret_1.trim().to_string();

    println!("\n------------ Enter invitation ---------------");
    let _ = std::io::stdin().read_line(&mut invitation);
    invitation = invitation.trim().to_string();

    if user_option != "Y" && user_option != "y" {
        println!("\nTrying to create an account ...");
        assert_eq!(create_account(secret_0.as_bytes().as_ptr(),
                                  secret_0.as_bytes().len(),
                                  secret_1.as_bytes().as_ptr(),
                                  secret_1.as_bytes().len(),
                                  invitation.as_bytes().as_ptr(),
                                  invitation.as_bytes().len(),
                                  session_h),
                   0);
    } else {
        println!("\nTrying to log in ...");
        assert_eq!(log_in(secret_0.as_bytes().as_ptr(),
                          secret_0.as_bytes().len(),
                          secret_1.as_bytes().as_ptr(),
                          secret_1.as_bytes().len(),
                          session_h),
                   0);
    }
}

unsafe fn create_email(app_h: *mut App) {
    let mut email = String::new();
    println!("\nEnter email name of choice:");
    let _ = std::io::stdin().read_line(&mut email);
    email = email.trim().to_string();

    let Digest(digest) = sha256::hash(email.as_bytes());

    let mut ad_h = 0;
    assert_eq!(appendable_data_new_priv(app_h, &digest, &mut ad_h), 0);
    assert_eq!(appendable_data_put(app_h, ad_h), 0);
    assert_eq!(appendable_data_free(ad_h), 0);

    println!("Email created successfully !");
}

unsafe fn send_email(app_h: *mut App) {
    let mut email = String::new();
    println!("\nEnter peer email address:");
    let _ = std::io::stdin().read_line(&mut email);
    email = email.trim().to_string();

    let mut msg = String::new();
    println!("\nEnter message:");
    let _ = std::io::stdin().read_line(&mut msg);
    msg = msg.trim().to_string();

    let Digest(digest) = sha256::hash(email.as_bytes());

    let mut data_id_h = 0;
    assert_eq!(data_id_new_appendable_data(&digest, true, &mut data_id_h),
               0);

    let mut ad_h = 0;
    assert_eq!(appendable_data_get(app_h, data_id_h, &mut ad_h), 0);
    assert_eq!(data_id_free(data_id_h), 0);

    let mut cipher_opt_h = 0;
    {
        let mut encrypt_key_h = 0;
        assert_eq!(appendable_data_encrypt_key(ad_h, &mut encrypt_key_h), 0);
        assert_eq!(cipher_opt_new_asymmetric(encrypt_key_h, &mut cipher_opt_h),
                   0);
        assert_eq!(misc_encrypt_key_free(encrypt_key_h), 0);
    }

    let mut se_h = 0;
    assert_eq!(immut_data_new_self_encryptor(app_h, &mut se_h), 0);
    assert_eq!(immut_data_write_to_self_encryptor(se_h,
                                                  msg.as_bytes().as_ptr(),
                                                  msg.as_bytes().len()),
               0);
    assert_eq!(immut_data_close_self_encryptor(app_h, se_h, cipher_opt_h, &mut data_id_h),
               0);
    assert_eq!(appendable_data_append(app_h, ad_h, data_id_h), 0);

    assert_eq!(appendable_data_free(ad_h), 0);
    assert_eq!(cipher_opt_free(cipher_opt_h), 0);
    assert_eq!(data_id_free(data_id_h), 0);
    assert_eq!(immut_data_self_encryptor_writer_free(se_h), 0);

    println!("Email sent successfully !");
}

unsafe fn read_email(app_h: *mut App) {
    let mut email = String::new();
    println!("\nEnter your email address:");
    let _ = std::io::stdin().read_line(&mut email);
    email = email.trim().to_string();

    let Digest(digest) = sha256::hash(email.as_bytes());

    let mut data_id_h = 0;
    assert_eq!(data_id_new_appendable_data(&digest, true, &mut data_id_h),
               0);

    let mut ad_h = 0;
    assert_eq!(appendable_data_get(app_h, data_id_h, &mut ad_h), 0);
    assert_eq!(data_id_free(data_id_h), 0);

    let mut num_of_emails = 0;
    assert_eq!(appendable_data_num_of_data(ad_h, &mut num_of_emails), 0);

    println!("\n================ You have a total of {} email(s). ================",
             num_of_emails);

    for n in 0..num_of_emails {
        assert_eq!(appendable_data_nth_data_id(app_h, ad_h, n, &mut data_id_h),
                   0);

        let mut se_h = 0;
        assert_eq!(immut_data_fetch_self_encryptor(app_h, data_id_h, &mut se_h),
                   0);

        let mut total_size = 0;
        assert_eq!(immut_data_size(se_h, &mut total_size), 0);

        let mut data_ptr: *mut u8 = ptr::null_mut();
        let mut read_size = 0;
        let mut capacity = 0;
        assert_eq!(immut_data_read_from_self_encryptor(se_h,
                                                       0,
                                                       total_size,
                                                       &mut data_ptr,
                                                       &mut read_size,
                                                       &mut capacity),
                   0);

        // TODO Confirm that cloning is done - else this is UB as we are freeing the vector
        // separately.
        let data = unwrap!(std::str::from_utf8(slice::from_raw_parts(data_ptr, read_size)))
            .to_owned();

        println!("\nEmail {}:\n{}", n, data);

        assert_eq!(data_id_free(data_id_h), 0);
        assert_eq!(immut_data_self_encryptor_reader_free(se_h), 0);
        misc_u8_ptr_free(data_ptr, read_size, capacity as usize);
    }

    assert_eq!(appendable_data_free(ad_h), 0);

    println!("\n================ All Emails read successfully ! ================");
}

fn main() {
    let mut session_h: *mut SessionHandle = ptr::null_mut();
    unsafe {
        self_auth(&mut session_h);
    }

    let app_name = "EmailApp".to_string();
    let unique_token = "EmailApp".to_string();
    let vendor = "MaidSafe".to_string();
    let mut app_h: *mut App = ptr::null_mut();

    unsafe {
        assert_eq!(register_app(session_h,
                                app_name.as_bytes().as_ptr(),
                                app_name.as_bytes().len(),
                                unique_token.as_bytes().as_ptr(),
                                unique_token.as_bytes().len(),
                                vendor.as_bytes().as_ptr(),
                                vendor.as_bytes().len(),
                                false,
                                &mut app_h),
                   0);
    }

    loop {
        let mut opt = String::new();
        println!("\n0) Create Email\n1) Send Email\n2) Read Email\nx) Anything else to \
                  exit\nEnter Option:");
        let _ = std::io::stdin().read_line(&mut opt);
        opt = opt.trim().to_string();

        match &opt[..] {
            "0" => unsafe { create_email(app_h) },
            "1" => unsafe { send_email(app_h) },
            "2" => unsafe { read_email(app_h) },
            _ => break,
        }
    }

    unsafe {
        drop_app(app_h);
        drop_session(session_h);
    }

    println!("============================================================\n");
}
