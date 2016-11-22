// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net
// Commercial License, version 1.0 or later, or (2) The General Public License
// (GPL), version 3, depending on which licence you accepted on initial access
// to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project
// generally, you agree to be bound by the terms of the MaidSafe Contributor
// Agreement, version 1.0. This, along with the Licenses can be found in the
// root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network
// Software distributed under the GPL Licence is distributed on an "AS IS"
// BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
//
// Please review the Licences for the specific language governing permissions
// and limitations relating to use of the SAFE Network Software.

//! Email Example

// For explanation of lint checks, run `rustc -W help` or see
// https://github.
// com/maidsafe/QA/blob/master/Documentation/Rust%20Lint%20Checks.md
#![forbid(exceeding_bitshifts, mutable_transmutes, no_mangle_const_items,
          unknown_crate_types, warnings)]
#![deny(bad_style, deprecated, improper_ctypes, missing_docs,
        non_shorthand_field_patterns, overflowing_literals, plugin_as_library,
        private_no_mangle_fns, private_no_mangle_statics, stable_features, unconditional_recursion,
        unknown_lints, unused, unused_allocation, unused_attributes,
        unused_comparisons, unused_features, unused_parens, while_true)]
#![warn(trivial_casts, trivial_numeric_casts, unused_extern_crates, unused_import_braces,
        unused_qualifications, unused_results)]
#![allow(box_pointers, fat_ptr_transmutes, missing_copy_implementations,
         missing_debug_implementations, variant_size_differences)]

#![cfg_attr(feature="clippy", feature(plugin))]
#![cfg_attr(feature="clippy", plugin(clippy))]
#![cfg_attr(feature="clippy", deny(clippy, unicode_not_nfc, wrong_pub_self_convention,
                                   option_unwrap_used))]
#![cfg_attr(feature="clippy", allow(use_debug, doc_markdown))]

/*

#[macro_use]
extern crate maidsafe_utilities;
#[macro_use]
extern crate unwrap;

extern crate rust_sodium;
extern crate safe_core;

use rust_sodium::crypto::hash::sha256::{self, Digest};
use safe_core::ffi::AppHandle;
use safe_core::ffi::app::*;
use safe_core::ffi::low_level_api::appendable_data::*;
use safe_core::ffi::low_level_api::cipher_opt::*;
use safe_core::ffi::low_level_api::data_id::*;
use safe_core::ffi::low_level_api::immut_data::*;
use safe_core::ffi::low_level_api::misc::*;
use safe_core::ffi::session::*;
use std::os::raw::c_void;
use std::ptr;
use std::sync::mpsc::{self, Sender};

unsafe fn self_auth(session_h: *mut *mut Session) {
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

    println!("\n------------ Enter account-locator ---------------");
    let _ = std::io::stdin().read_line(&mut secret_0);
    secret_0 = secret_0.trim().to_string();

    println!("\n------------ Enter password ---------------");
    let _ = std::io::stdin().read_line(&mut secret_1);
    secret_1 = secret_1.trim().to_string();


    if user_option != "Y" && user_option != "y" {
        println!("\nTrying to create an account ...");
        assert_eq!(create_account(secret_0.as_bytes().as_ptr(),
                                  secret_0.as_bytes().len(),
                                  secret_1.as_bytes().as_ptr(),
                                  secret_1.as_bytes().len(),
                                  session_h,
                                  ptr::null_mut(),
                                  network_event_callback),
                   0);
    } else {
        println!("\nTrying to log in ...");
        assert_eq!(log_in(secret_0.as_bytes().as_ptr(),
                          secret_0.as_bytes().len(),
                          secret_1.as_bytes().as_ptr(),
                          secret_1.as_bytes().len(),
                          session_h,
                          ptr::null_mut(),
                          network_event_callback),
                   0);
    }
}

unsafe fn create_email(session: *const Session, app_h: AppHandle) -> Result<(), i32> {
    let mut email = String::new();
    println!("\nEnter email name of choice:");
    let _ = std::io::stdin().read_line(&mut email);
    email = email.trim().to_string();

    let Digest(digest) = sha256::hash(email.as_bytes());

    let ad_h = try!(c1(|u, cb| appendable_data_new_priv(session, app_h, &digest, u, cb)));

    try!(c0(|u, cb| appendable_data_put(session, ad_h, u, cb)));
    try!(c0(|u, cb| appendable_data_free(session, ad_h, u, cb)));

    println!("Email created successfully !");
    Ok(())
}

unsafe fn send_email(sess: *const Session, app_h: AppHandle) -> Result<(), i32> {
    let mut email = String::new();
    println!("\nEnter peer email address:");
    let _ = std::io::stdin().read_line(&mut email);
    email = email.trim().to_string();

    let mut msg = String::new();
    println!("\nEnter message:");
    let _ = std::io::stdin().read_line(&mut msg);
    msg = msg.trim().to_string();

    let Digest(digest) = sha256::hash(email.as_bytes());

    let data_id_h = try!(c1(|u, cb| data_id_new_appendable_data(sess, &digest, true, u, cb)));

    let ad_h = try!(c1(|u, cb| appendable_data_get(sess, data_id_h, u, cb)));

    assert!(c0(|u, cb| data_id_free(sess, data_id_h, u, cb)).is_ok());

    let enc_key_h = try!(c1(|u, cb| appendable_data_encrypt_key(sess, ad_h, u, cb)));
    let cipher_opt_h = try!(c1(|u, cb| cipher_opt_new_asymmetric(sess, enc_key_h, u, cb)));
    try!(c0(|u, cb| misc_encrypt_key_free(sess, enc_key_h, u, cb)));

    let se_h = try!(c1(|u, cb| immut_data_new_self_encryptor(sess, u, cb)));

    let size = msg.len();
    let msg = msg.as_bytes().as_ptr();
    try!(c0(|u, cb| immut_data_write_to_self_encryptor(sess, se_h, msg, size, u, cb)));

    let data_id_h =
        try!(c1(|u, cb| immut_data_close_self_encryptor(sess, app_h, se_h, cipher_opt_h, u, cb)));
    try!(c0(|u, cb| appendable_data_append(sess, ad_h, data_id_h, u, cb)));

    try!(c0(|u, cb| appendable_data_free(sess, ad_h, u, cb)));
    try!(c0(|u, cb| cipher_opt_free(sess, cipher_opt_h, u, cb)));
    try!(c0(|u, cb| data_id_free(sess, data_id_h, u, cb)));

    println!("Email sent successfully !");
    Ok(())
}

unsafe fn read_email(sess: *const Session, app_h: AppHandle) -> Result<(), i32> {
    let mut email = String::new();
    println!("\nEnter your email address:");
    let _ = std::io::stdin().read_line(&mut email);
    email = email.trim().to_string();

    let Digest(digest) = sha256::hash(email.as_bytes());

    let data_id_h = try!(c1(|u, cb| data_id_new_appendable_data(sess, &digest, true, u, cb)));

    let ad_h = try!(c1(|u, cb| appendable_data_get(sess, data_id_h, u, cb)));

    assert!(c0(|u, cb| data_id_free(sess, data_id_h, u, cb)).is_ok());

    let num_of_emails = try!(c1(|u, cb| appendable_data_num_of_data(sess, ad_h, u, cb)));

    println!("\n================ You have a total of {} email(s). ================",
             num_of_emails);

    for n in 0..num_of_emails {
        let data_id_h = try!(c1(|u, cb| appendable_data_nth_data_id(sess, app_h, ad_h, n, u, cb)));

        let se_h = try!(c1(|u, cb| immut_data_fetch_self_encryptor(sess, app_h, data_id_h, u, cb)));

        let total_size = try!(c1(|u, cb| immut_data_size(sess, se_h, u, cb)));

        let data = try!(call_vec_u8(|u, cb| {
            immut_data_read_from_self_encryptor(sess, se_h, 0, total_size, u, cb)
        }));

        let data = try!(String::from_utf8(data).map_err(|e| {
            println!("Can't decode string: {:?}", e);
            -1
        }));

        println!("\nEmail {}:\n{}", n, data);

        try!(c0(|u, cb| data_id_free(sess, data_id_h, u, cb)));
        try!(c0(|u, cb| immut_data_self_encryptor_reader_free(sess, se_h, u, cb)));
    }

    assert!(c0(|u, cb| appendable_data_free(sess, ad_h, u, cb)).is_ok());

    println!("\n================ All Emails read successfully ! ================");
    Ok(())
}

fn main() {
    let mut session: *mut Session = ptr::null_mut();
    unsafe {
        self_auth(&mut session);
    }

    let app_name = "EmailApp".to_string();
    let unique_token = "EmailApp".to_string();
    let vendor = "MaidSafe".to_string();
    let app_h;

    unsafe {
        app_h = unwrap!(c1(|u, cb| {
            register_app(session,
                         app_name.as_bytes().as_ptr(),
                         app_name.as_bytes().len(),
                         unique_token.as_bytes().as_ptr(),
                         unique_token.as_bytes().len(),
                         vendor.as_bytes().as_ptr(),
                         vendor.as_bytes().len(),
                         false,
                         u,
                         cb)
        }),
                        "Can't register app");
    }

    loop {
        let mut opt = String::new();
        println!("\n0) Create Email\n1) Send Email\n2) Read Email\nx) Anything else to \
                  exit\nEnter Option:");
        let _ = std::io::stdin().read_line(&mut opt);
        opt = opt.trim().to_string();

        match &opt[..] {
            "0" => unsafe { assert!(create_email(session, app_h).is_ok()) },
            "1" => unsafe { assert!(send_email(session, app_h).is_ok()) },
            "2" => unsafe { assert!(read_email(session, app_h).is_ok()) },
            _ => break,
        }
    }

    unsafe {
        session_free(session);
    }

    println!("============================================================\n");
}

// Convert a `mpsc::Sender<T>` to a void ptr which can be passed as user data to
// ffi functions
fn sender_as_user_data<T>(tx: &Sender<T>) -> *mut c_void {
    let ptr: *const _ = tx;
    ptr as *mut c_void
}

// Send through a `mpsc::Sender` pointed to by the user data pointer.
unsafe fn send_via_user_data<T>(u: *mut c_void, value: T)
    where T: Send
{
    let tx = u as *mut Sender<T>;
    unwrap!((*tx).send(value));
}

// Call a FFI function and block until its callback gets called.
// Use this if the callback accepts no arguments in addition to u
// and error_code.
fn c0<F>(f: F) -> Result<(), i32>
    where F: FnOnce(*mut c_void, unsafe extern "C" fn(*mut c_void, i32))
{
    let (tx, rx) = mpsc::channel::<i32>();
    f(sender_as_user_data(&tx), callback_0);

    let error = unwrap!(rx.recv());
    if error == 0 { Ok(()) } else { Err(error) }
}

// Call a FFI function and block until its callback gets called, then return
// the argument which were passed to that callback.
// Use this if the callback accepts one argument in addition to u
// and error_code.
unsafe fn c1<F, T>(f: F) -> Result<T, i32>
    where F: FnOnce(*mut c_void, unsafe extern "C" fn(*mut c_void, i32, T))
{
    let (tx, rx) = mpsc::channel::<(i32, SendWrapper<T>)>();
    f(sender_as_user_data(&tx), callback_1::<T>);

    let (error, args) = unwrap!(rx.recv());
    if error == 0 { Ok(args.0) } else { Err(error) }
}

// Call a FFI function and block until its callback gets called, then return
// the arguments which were passed to that callback in a tuple.
// Use this if the callback accepts three arguments in addition to u and
// error_code.
unsafe fn c3<F, T0, T1, T2>(f: F) -> Result<(T0, T1, T2), i32>
    where F: FnOnce(*mut c_void,
                    unsafe extern "C" fn(*mut c_void, i32, T0, T1, T2))
{
    let (tx, rx) = mpsc::channel::<(i32, SendWrapper<(T0, T1, T2)>)>();
    f(sender_as_user_data(&tx), callback_3::<T0, T1, T2>);

    let (error, args) = unwrap!(rx.recv());
    if error == 0 { Ok(args.0) } else { Err(error) }
}

// Call a FFI function and block until its callback gets called, then return
// the arguments which were passed to that callback converted to Vec<u8>.
// The callbacks must accept three arguments (in addition to u and
// error_code): pointer to the begining of the data (`*mut u8`), lengths
// (`usize`)
// and capacity (`usize`).
unsafe fn call_vec_u8<F>(f: F) -> Result<Vec<u8>, i32>
    where F: FnOnce(*mut c_void,
                    unsafe extern "C" fn(*mut c_void, i32, *mut u8, usize, usize))
{
    c3(f).map(|(ptr, len, cap)| Vec::from_raw_parts(ptr, len, cap))
}

unsafe extern "C" fn callback_0(user_data: *mut c_void, error: i32) {
    send_via_user_data(user_data, error)
}

unsafe extern "C" fn callback_1<T>(user_data: *mut c_void, error: i32, arg: T) {
    send_via_user_data(user_data, (error, SendWrapper(arg)))
}

unsafe extern "C" fn callback_3<T0, T1, T2>(user_data: *mut c_void,
                                            error: i32,
                                            arg0: T0,
                                            arg1: T1,
                                            arg2: T2) {
    send_via_user_data(user_data, (error, SendWrapper((arg0, arg1, arg2))))
}

// Unsafe wrapper for passing non-Send types through mpsc channels.
// Use with caution!
struct SendWrapper<T>(T);
unsafe impl<T> Send for SendWrapper<T> {}

unsafe extern "C" fn network_event_callback(_user_data: *mut c_void, err_code: i32, event: i32) {
    println!("Network event with code {}, err_code: {}", event, err_code);
}

*/

fn main() {}
