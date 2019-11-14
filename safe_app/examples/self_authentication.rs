// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

//! Self-authentication example.

// For explanation of lint checks, run `rustc -W help`.
#![deny(unsafe_code)]
#![warn(
    missing_docs,
    trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    unused_results
)]

#[macro_use]
extern crate unwrap;

use safe_app::CoreError;
use safe_authenticator::{AuthError, Authenticator};
use safe_nd::Error as SndError;

fn main() {
    unwrap!(safe_core::utils::logging::init(true));

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

        // FIXME - pass secret key of the wallet as an argument
        let bls_sk = threshold_crypto::SecretKey::random();

        // Account Creation
        println!("\nTrying to create an account...");

        match Authenticator::create_acc(secret_0.as_str(), secret_1.as_str(), bls_sk, || ()) {
            Ok(_) => (),
            Err(AuthError::CoreError(CoreError::DataError(SndError::LoginPacketExists))) => {
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
