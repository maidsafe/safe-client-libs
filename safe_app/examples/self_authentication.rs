// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! Self-authentication example.

// For explanation of lint checks, run `rustc -W help` or see
// https://github.com/maidsafe/QA/blob/master/Documentation/Rust%20Lint%20Checks.md
#![forbid(
    exceeding_bitshifts,
    mutable_transmutes,
    no_mangle_const_items,
    unknown_crate_types,
    warnings
)]
#![deny(
    bad_style,
    deprecated,
    improper_ctypes,
    missing_docs,
    non_shorthand_field_patterns,
    overflowing_literals,
    plugin_as_library,
    stable_features,
    unconditional_recursion,
    unknown_lints,
    unsafe_code,
    unused,
    unused_allocation,
    unused_attributes,
    unused_comparisons,
    unused_features,
    unused_parens,
    while_true,
    clippy::all,
    clippy::option_unwrap_used,
    clippy::unicode_not_nfc,
    clippy::wrong_pub_self_convention
)]
#![warn(
    trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    unused_results
)]
#![allow(
    box_pointers,
    missing_copy_implementations,
    missing_debug_implementations,
    variant_size_differences,
    clippy::implicit_hasher,
    clippy::too_many_arguments,
    clippy::use_debug
)]

#[macro_use]
extern crate unwrap;

use clap::{App, Arg};
use safe_app::{utils, ClientError, CoreError};
use safe_authenticator::{AuthError, Authenticator};

fn main() {
    unwrap!(maidsafe_utilities::log::init(true));

    let matches = App::new("self_authentication")
        .arg(
            Arg::with_name("invite")
                .long("invite")
                .takes_value(true)
                .help("Use the given invite."),
        )
        .get_matches();

    let mut secret_0 = String::new();
    let mut secret_1 = String::new();

    println!("\nDo you already have an account created (enter Y for yes)?");

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

        let invitation: String = if let Some(i) = matches.value_of("invite") {
            i.to_string()
        } else {
            unwrap!(utils::generate_random_string(10))
        };

        // Account Creation
        println!("\nTrying to create an account...");

        match Authenticator::create_acc(
            secret_0.as_str(),
            secret_1.as_str(),
            invitation.as_str(),
            || (),
        ) {
            Ok(_) => (),
            Err(AuthError::CoreError(CoreError::RoutingClientError(
                ClientError::AccountExists,
            ))) => {
                println!(
                    "ERROR: This domain is already taken. Please retry with different \
                     locator and/or password"
                );
                return;
            }
            Err(err) => panic!("{:?}", err),
        }
        println!("Account created successfully!");

        println!("\n\n\tAuto Account Login");
        println!("\t==================");

        // Log into the created account.
        {
            println!("\nTrying to log into the created account using supplied credentials...");

            let _ = unwrap!(Authenticator::login(secret_0, secret_1, || ()));
            println!("Account login successful!");
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

        // Log into the created account.
        {
            println!("\nTrying to log in...");
            match Authenticator::login(secret_0, secret_1, || ()) {
                Ok(_) => {
                    println!("Account login successful!");
                    break;
                }
                Err(error) => println!("ERROR: Account login failed!\nReason: {:?}\n\n", error),
            }
        }
    }
}
