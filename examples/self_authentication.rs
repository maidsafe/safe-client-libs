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

//! Self-authentication example.

// For explanation of lint checks, run `rustc -W help` or see
// https://github.com/maidsafe/QA/blob/master/Documentation/Rust%20Lint%20Checks.md
#![forbid(bad_style, exceeding_bitshifts, mutable_transmutes, no_mangle_const_items,
          unknown_crate_types, warnings)]
#![deny(deprecated, improper_ctypes, missing_docs,
        non_shorthand_field_patterns, overflowing_literals, plugin_as_library,
        private_no_mangle_fns, private_no_mangle_statics, stable_features, unconditional_recursion,
        unknown_lints, unsafe_code, unused, unused_allocation, unused_attributes,
        unused_comparisons, unused_features, unused_parens, while_true)]
#![warn(trivial_casts, trivial_numeric_casts, unused_extern_crates, unused_import_braces,
        unused_qualifications, unused_results)]
#![allow(box_pointers, fat_ptr_transmutes, missing_copy_implementations,
         missing_debug_implementations, variant_size_differences)]

extern crate safe_core;
#[cfg_attr(test, macro_use)]
extern crate maidsafe_utilities;
extern crate routing;
#[macro_use]
extern crate unwrap;

use routing::client_errors::MutationError;
use safe_core::core::client::Client;
use safe_core::core::errors::CoreError;

fn main() {
    unwrap!(maidsafe_utilities::log::init(true));

    let mut secret_0 = String::new();
    let mut secret_1 = String::new();
    let mut invitation = String::new();

    println!("\nDo you already have an account created (enter Y for yes) ?");

    let mut user_option = String::new();
    let _ = std::io::stdin().read_line(&mut user_option);
    user_option = user_option.trim().to_string();

    if user_option != "Y" && user_option != "y" {
        println!("\n\tAccount Creation");
        println!("\t================");

        println!("\n------------ Enter account-locator ---------------");
        let _ = std::io::stdin().read_line(&mut secret_0);
        secret_0 = secret_0.trim().to_string();
        println!("\n------------ Enter password ---------------");
        let _ = std::io::stdin().read_line(&mut secret_1);
        secret_1 = secret_1.trim().to_string();
        println!("\n------------ Enter invitation ---------------");
        let _ = std::io::stdin().read_line(&mut invitation);
        invitation = invitation.trim().to_string();

        // Account Creation
        {
            println!("\nTrying to create an account ...");

            match Client::create_account(&secret_0, &secret_1, &invitation) {
                Ok(_) => (),
                Err(CoreError::MutationFailure {
                        reason: MutationError::AccountExists, ..
                    }) => {
                    println!("ERROR: This domain is already taken. Please retry with different \
                              Keyword and/or PIN");
                    return;
                }
                Err(err) => panic!("{:?}", err),
            }
            println!("Account Created Successfully !!");
        }

        println!("\n\n\tAuto Account Login");
        println!("\t==================");

        // Log into the created account
        {
            println!("\nTrying to log into the created account using supplied credentials ...");

            let _ = unwrap!(Client::log_in(&secret_0, &secret_1));
            println!("Account Login Successful !!");
        }
    }

    println!("\n\n\tManual Account Login");
    println!("\t====================");

    loop {
        secret_0 = String::new();
        secret_1 = String::new();

        println!("\n------------ Enter account-locator ---------------");
        let _ = std::io::stdin().read_line(&mut secret_0);
        secret_0 = secret_0.trim().to_string();
        println!("\n------------ Enter password ---------------");
        let _ = std::io::stdin().read_line(&mut secret_1);
        secret_1 = secret_1.trim().to_string();

        // Log into the created account
        {
            println!("\nTrying to log in ...");
            match Client::log_in(&secret_0, &secret_1) {
                Ok(_) => {
                    println!("Account Login Successful !!");
                    break;
                }
                Err(error) => println!("ERROR: Account Login Failed !!\nReason: {:?}\n\n", error),
            }
        }
    }
}
