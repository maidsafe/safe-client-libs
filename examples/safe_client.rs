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

//! Safe client example.

// For explanation of lint checks, run `rustc -W help` or see
// https://github.com/maidsafe/QA/blob/master/Documentation/Rust%20Lint%20Checks.md
#![forbid(bad_style, exceeding_bitshifts, mutable_transmutes, no_mangle_const_items,
          unknown_crate_types, warnings)]
#![deny(deprecated, drop_with_repr_extern, improper_ctypes, missing_docs,
        non_shorthand_field_patterns, overflowing_literals, plugin_as_library,
        private_no_mangle_fns, private_no_mangle_statics, stable_features, unconditional_recursion,
        unknown_lints, unsafe_code, unused, unused_allocation, unused_attributes,
        unused_comparisons, unused_features, unused_parens, while_true)]
#![warn(trivial_casts, trivial_numeric_casts, unused_extern_crates, unused_import_braces,
        unused_qualifications, unused_results)]
#![allow(box_pointers, fat_ptr_transmutes, missing_copy_implementations,
         missing_debug_implementations, variant_size_differences)]

#![cfg_attr(feature="clippy", feature(plugin))]
#![cfg_attr(feature="clippy", plugin(clippy))]
#![cfg_attr(feature="clippy", deny(clippy, clippy_pedantic))]

extern crate mpid_messaging;
extern crate routing;
extern crate safe_core;
extern crate sodiumoxide;
extern crate xor_name;
#[macro_use] extern crate maidsafe_utilities;

use maidsafe_utilities::serialisation::deserialise;
use mpid_messaging::{MpidMessage, MpidMessageWrapper};
use routing::Data;
use safe_core::client::Client;
use safe_core::client::response_getter::ResponseGetter;
use safe_core::errors::CoreError;
use sodiumoxide::crypto::hash::sha512;
use xor_name::XorName;

#[cfg(feature = "use-mock-routing")]
const MOCK_NETWORK: bool = true;
#[cfg(not(feature = "use-mock-routing"))]
const MOCK_NETWORK: bool = false;

fn main() {
    maidsafe_utilities::log::init(true);

    let mut keyword = String::new();
    let mut password = String::new();
    let mut pin = String::new();

    println!("\nDo you already have an account created (enter Y for yes) ?");

    let mut user_option = String::new();
    let _ = std::io::stdin().read_line(&mut user_option);
    user_option = user_option.trim().to_string();

    if user_option != "Y" && user_option != "y" {
        println!("\n\tAccount Creation");
        println!("\t================");

        println!("\n------------ Enter Keyword ---------------");
        let _ = std::io::stdin().read_line(&mut keyword);

        println!("\n\n------------ Enter Password --------------");
        let _ = std::io::stdin().read_line(&mut password);

        loop {
            println!("\n\n--------- Enter PIN (4 Digits) -----------");
            let _ = std::io::stdin().read_line(&mut pin);
            pin = pin.trim().to_string();
            if pin.parse::<u16>().is_ok() && pin.len() == 4 {
                break;
            }
            println!("ERROR: PIN is not 4 Digits !!");
            pin.clear();
        }

        // Account Creation
        {
            println!("\nTrying to create an account ...");

            let _ = unwrap_result!(Client::create_account(keyword.clone(), pin.clone(), password.clone()));
            println!("Account Created Successfully !!");
        }

        println!("\n\n\tAuto Account Login");
        println!("\t==================");

        // Log into the created account
        {
            println!("\nTrying to log into the created account using supplied credentials ...");

            let _ = unwrap_result!(Client::log_in(keyword, pin, password));
            println!("Account Login Successful !!");
        }
    }

    println!("\n\n\tManual Account Login");
    println!("\t====================");

    loop {
        keyword = String::new();
        password = String::new();

        println!("\n------------ Enter Keyword ---------------");
        let _ = std::io::stdin().read_line(&mut keyword);

        println!("\n\n------------ Enter Password --------------");
        let _ = std::io::stdin().read_line(&mut password);

        loop {
            pin = String::new();
            println!("\n\n--------- Enter PIN (4 Digits) -----------");
            let _ = std::io::stdin().read_line(&mut pin);
            pin = pin.trim().to_string();
            if pin.parse::<u16>().is_ok() && pin.len() == 4 {
                break;
            }
            println!("ERROR: PIN is not 4 Digits !!");
        }

        // Log into the created account
        {
            println!("\nTrying to log in ...");
            match Client::log_in(keyword, pin, password) {
                Ok(client) => {
                    println!("Account Login Successful !!");
                    if MOCK_NETWORK {
                        println!("Messaging feature has been skipped as mock routing is being used !!");
                    } else {
                        messaging(&client);
                    }
                    break;
                }
                Err(error)  => println!("Account Login Failed !! Reason: {:?}\n\n", error),
            }
        }
    }
}

fn messaging(client: &Client) {
    println!("\nDo you want to continue with the mpid messaging feature (enter Y for yes) ?");
    let mut messaging_option = String::new();
    let _ = std::io::stdin().read_line(&mut messaging_option);
    messaging_option = messaging_option.trim().to_string();
    if messaging_option != "Y" && messaging_option != "y" {
        return;
    }

    println!("\n------------ enter a memorable name as mpid_account ---------------");
    let mut account_name = String::new();
    let _ = std::io::stdin().read_line(&mut account_name);
    let mpid_account = XorName(sha512::hash(&account_name.into_bytes()).0);

    loop {
        println!("\n------- messaging options: r for receive, s for send, t for terminate ------- \
                  \n-------                    d for delete,  q for query outbox          -------");
        let mut operation = String::new();
        let _ = std::io::stdin().read_line(&mut operation);
        operation = operation.trim().to_string();
        if operation == "r" {
            let _ = receive_mpid_message(&client, &mpid_account);
        } else if operation == "s" {
            send_mpid_message(&client, &mpid_account);
        } else if operation == "d" {
            let _ = delete(&client, &mpid_account);
        } else if operation == "q" {
            let _ = query_outbox(&client, &mpid_account);
        } else if operation == "t" {
            break;
        }
    }
}

fn receive_mpid_message(client: &Client, mpid_account: &XorName) -> Result<MpidMessage, CoreError> {
    let response_getter = unwrap_result!(client.register_online(&mpid_account));
    let mpid_message_wrapper = unwrap_result!(receiving_response(&response_getter));
    match mpid_message_wrapper {
        MpidMessageWrapper::PutMessage(mpid_message) => {
            println!("received mpid message {:?}", mpid_message);
            Ok(mpid_message)
        }
        _ => {
            println!("unknown received mpid_message_wrapper {:?}", mpid_message_wrapper);
            Err(CoreError::ReceivedUnexpectedData)
        }
    }
}

fn send_mpid_message(client: &Client, mpid_account: &XorName) {
    let _ = client.register_online(&mpid_account);
    let mut receiver_name = String::new();
    let mut msg_metadata = String::new();
    let mut msg_content = String::new();
    println!("\n------------ enter receiver's memorable name ---------------");
    let _ = std::io::stdin().read_line(&mut receiver_name);
    let receiver_account = XorName(sha512::hash(&receiver_name.into_bytes()).0);
    println!("\n------------ enter metadata of the message ---------------");
    let _ = std::io::stdin().read_line(&mut msg_metadata);
    println!("\n------------ enter content of the message ---------------");
    let _ = std::io::stdin().read_line(&mut msg_content);
    let secret_key = unwrap_result!(client.get_secret_signing_key());
    let _ = client.send_message(mpid_account, msg_metadata.into_bytes(),
                                msg_content.into_bytes(), receiver_account, &secret_key);
}

fn delete(client: &Client, mpid_account: &XorName) -> Result<(), CoreError> {
    println!("\n------- delete options: 1 for sender delete a message from own outbox        -------\
              \n-------                 2 for receiver delete a message from sender's outbox -------\
              \n-------                 3 for delete a header from inbox                     -------\
              \n-------                 other for return                                     -------");
    let mut operation = String::new();
    let _ = std::io::stdin().read_line(&mut operation);
    operation = operation.trim().to_string();
    if operation == "1" {
        let headers = get_headers_in_outbox(client, mpid_account);
        if headers.len() == 0 {
            println!("outbox is empty");
        } else {
            let _ = client.delete_message(mpid_account, &headers[0]);
        }
    } else if operation == "2" || operation == "3" {
        let mpid_message = unwrap_result!(receive_mpid_message(client, mpid_account));
        let msg_name = unwrap_result!(mpid_message.name());
        if operation == "2" {
            println!("not supported when using memoryable name. \
                      This feature requires XorName(sha512::hash(&client_public_key).0) \
                      to be used as mpid_account directly");
            // let _ = client.delete_message(mpid_message.header().sender(), &msg_name);
        } else {
            let _ = client.delete_header(mpid_account, &msg_name);
        }
    }
    Ok(())
}

fn get_headers_in_outbox(client: &Client, mpid_account: &XorName) -> Vec<XorName> {
    let response_getter = match client.get_outbox_headers(mpid_account) {
        Ok(response_getter) => response_getter,
        Err(_) => return Vec::<XorName>::new(),
    };
    let mpid_message_wrapper = match receiving_response(&response_getter) {
        Ok(mpid_message_wrapper) => mpid_message_wrapper,
        Err(_) => return Vec::<XorName>::new(),
    };
    match mpid_message_wrapper {
        MpidMessageWrapper::GetOutboxHeadersResponse(mpid_headers) => {
            println!("received mpid headers {:?}", mpid_headers);
            mpid_headers.iter().map(|mpid_header| mpid_header.name().ok().unwrap()).collect()
        }
        _ => {
            println!("unknown received mpid_message_wrapper {:?}", mpid_message_wrapper);
            Vec::<XorName>::new()
        }
    }
}

fn query_outbox(client: &Client, mpid_account: &XorName) -> Result<(), CoreError> {
    let headers = get_headers_in_outbox(client, mpid_account);
    let response_getter = unwrap_result!(client.query_outbox_headers(mpid_account, headers));
    let mpid_message_wrapper = unwrap_result!(receiving_response(&response_getter));
    match mpid_message_wrapper {
        MpidMessageWrapper::OutboxHasResponse(has_response) => println!("received query response {:?}", has_response),
        _ => println!("unknown received mpid_message_wrapper {:?}", mpid_message_wrapper),
    }
    Ok(())
}

fn receiving_response(response_getter: &ResponseGetter) -> Result<MpidMessageWrapper, CoreError> {
    loop {
        match response_getter.get() {
            Ok(data) => {
                match data {
                    Data::Plain(plain_data) => {
                        let mpid_message_wrapper : MpidMessageWrapper = unwrap_result!(deserialise(plain_data.value()));
                        return Ok(mpid_message_wrapper);
                    }
                    _ => return Err(CoreError::ReceivedUnexpectedData),
                }
            }
            Err(_) => {}
        }
        std::thread::sleep(std::time::Duration::from_millis(1000));
    }
}
