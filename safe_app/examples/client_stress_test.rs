// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

//! Safe client example.

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
    variant_size_differences
)]

#[macro_use]
extern crate clap;
#[macro_use]
extern crate safe_core;
#[macro_use]
extern crate unwrap;

use clap::{App, Arg};
use futures::Future;
use rand::{Rng, SeedableRng};
use safe_app::{Client, CoreError, CoreFuture, FutureExt, PubImmutableData};
use safe_authenticator::{AuthClient, Authenticator};
use safe_nd::{IData, PublicKey, SeqMutableData, XorName};
use std::sync::mpsc;

fn random_mutable_data<R: Rng>(
    type_tag: u64,
    public_key: &PublicKey,
    rng: &mut R,
) -> SeqMutableData {
    SeqMutableData::new_with_data(
        XorName(rng.gen()),
        type_tag,
        btree_map![],
        btree_map![],
        *public_key,
    )
}

enum Data {
    Mutable(SeqMutableData),
    Immutable(IData),
}

fn main() {
    unwrap!(maidsafe_utilities::log::init(true));

    let matches = App::new("client_stress_test")
        .about(
            "A stress test involving putting and getting immutable and mutable data chunks to the \
             network",
        )
        .arg(
            Arg::with_name("immutable")
                .short("i")
                .long("immutable")
                .takes_value(true)
                .default_value("100")
                .help("Number of PubImmutableData chunks to Put and Get."),
        )
        .arg(
            Arg::with_name("mutable")
                .short("m")
                .long("mutable")
                .takes_value(true)
                .default_value("100")
                .help("Number of MutableData chunks to Put and Get."),
        )
        .arg(
            Arg::with_name("seed")
                .long("seed")
                .takes_value(true)
                .help("Seed for a pseudo-random number generator."),
        )
        .arg(
            Arg::with_name("get-only")
                .long("get-only")
                .requires("seed")
                .help("Only Get the data, don't Put it. Logs in to an existing account."),
        )
        .arg(
            Arg::with_name("locator")
                .short("l")
                .long("locator")
                .takes_value(true)
                .requires("password")
                .help("Use the given Locator for login."),
        )
        .arg(
            Arg::with_name("password")
                .short("p")
                .long("password")
                .takes_value(true)
                .requires("locator")
                .help("Use the given Password for login."),
        )
        .get_matches();

    let immutable_data_count = unwrap!(value_t!(matches, "immutable", usize));
    let mutable_data_count = unwrap!(value_t!(matches, "mutable", usize));

    let seed = if matches.is_present("seed") {
        unwrap!(value_t!(matches, "seed", u32))
    } else {
        rand::random()
    };
    let mut rng = rand::XorShiftRng::from_seed([0, 0, 0, seed]);

    let get_only = matches.is_present("get-only");

    // Create account
    let (locator, password) = if let (Some(locator), Some(password)) =
        (matches.value_of("locator"), matches.value_of("password"))
    {
        (locator.to_string(), password.to_string())
    } else {
        let new_locator = rng.gen_ascii_chars().take(20).collect();
        let new_password = rng.gen_ascii_chars().take(20).collect();
        println!(
            "A new account will be created.\nLocator: {}\nPassword: {}",
            new_locator, new_password
        );
        (new_locator, new_password)
    };

    let try_login = matches.is_present("locator") && matches.is_present("password");
    let auth = if get_only || try_login {
        println!("\n\tAccount Login");
        println!("\t================");
        println!("\nTrying to login to an account ...");

        unwrap!(Authenticator::login(locator, password, || ()))
    } else {
        println!("\n\tAccount Creation");
        println!("\t================");
        println!("\nTrying to create an account ...");

        // FIXME - pass the secret key of the wallet as a parameter
        let bls_sk = threshold_crypto::SecretKey::random();

        let auth = unwrap!(Authenticator::create_acc(
            locator.as_str(),
            password.as_str(),
            bls_sk,
            || ()
        ));

        println!("Account created!");

        auth
    };

    println!("\nLogged in successfully!");
    println!("Seed: {}", seed);

    let mut stored_data = Vec::with_capacity(mutable_data_count + immutable_data_count);

    for _ in 0..immutable_data_count {
        // Construct data
        let data = PubImmutableData::new(rng.gen_iter().take(1024).collect());
        println!("{:?}", data.name());
        stored_data.push(Data::Immutable(data.into()));
    }

    let (tx, rx) = mpsc::channel();

    unwrap!(auth.send(move |client| {
        let public_key = client.public_key();

        unwrap!(tx.send(public_key));

        ok!(()).into()
    }));

    let public_key = unwrap!(rx.recv());

    for _ in immutable_data_count..(immutable_data_count + mutable_data_count) {
        // Construct data
        let mutable_data = random_mutable_data(100_000, &public_key, &mut rng);
        stored_data.push(Data::Mutable(mutable_data));
    }

    let message = format!(
        "Generated {} items ({} immutable, {} mutable)",
        stored_data.len(),
        immutable_data_count,
        mutable_data_count
    );
    let underline = (0..message.len()).map(|_| "=").collect::<String>();

    println!("\n\t{}\n\t{}", message, underline);

    for (i, data) in stored_data.into_iter().enumerate() {
        let (tx, rx) = mpsc::channel();

        unwrap!(auth.send(move |client| {
            let c2 = client.clone();
            let c3 = client.clone();

            match data {
                Data::Immutable(data) => {
                    let fut = if get_only {
                        futures::finished(data).into_box()
                    } else {
                        // Put the data to the network.
                        put_idata(&c2, data, i)
                    };

                    fut.and_then(move |data| {
                        // Get all the chunks again.
                        c3.get_idata(*data.address()).map(move |retrieved_data| {
                            println!("Retrieved chunk #{}: {:?}", i, data.name());
                            assert_eq!(data, retrieved_data);
                            Ok(())
                        })
                    })
                    .into_box()
                }
                Data::Mutable(data) => {
                    let fut = if get_only {
                        futures::finished(data).into_box()
                    } else {
                        // Put the data to the network.
                        put_mdata(&c2, data, i)
                    };

                    // TODO(nbaksalyar): stress test mutate_mdata and get_mdata_value here
                    fut.and_then(move |data| {
                        // Get all the chunks again.
                        c3.get_seq_mdata_shell(*data.name(), data.tag()).map(
                            move |retrieved_data| {
                                assert_eq!(data, retrieved_data);
                                println!("Retrieved chunk #{}: {:?}", i, data.name());
                                Ok(())
                            },
                        )
                    })
                    .into_box()
                }
            }
            .map(move |_: Result<(), CoreError>| unwrap!(tx.send(())))
            .map_err(|e| println!("Error: {:?}", e))
            .into_box()
            .into()
        }));

        unwrap!(rx.recv());
    }

    println!("Done");
}

fn put_idata(client: &AuthClient, data: IData, i: usize) -> Box<CoreFuture<IData>> {
    let c2 = client.clone();

    client
        .put_idata(data.clone())
        .and_then(move |_| {
            println!("Put PubImmutableData chunk #{}: {:?}", i, data.name());

            // Get the data
            c2.get_idata(*data.address()).map(move |retrieved_data| {
                assert_eq!(data, retrieved_data);
                retrieved_data
            })
        })
        .and_then(move |retrieved_data| {
            println!(
                "Retrieved PubImmutableData chunk #{}: {:?}",
                i,
                retrieved_data.name()
            );
            Ok(retrieved_data)
        })
        .into_box()
}

fn put_mdata(
    client: &AuthClient,
    data: SeqMutableData,
    i: usize,
) -> Box<CoreFuture<SeqMutableData>> {
    let c2 = client.clone();

    client
        .put_seq_mutable_data(data.clone())
        .and_then(move |_| {
            println!("Put MutableData chunk #{}: {:?}", i, data.name());

            // Get the data.
            c2.get_seq_mdata_shell(*data.name(), data.tag())
                .map(move |retrieved_data| {
                    assert_eq!(data, retrieved_data);
                    retrieved_data
                })
        })
        .and_then(move |retrieved_data| {
            println!(
                "Retrieved MutableData chunk #{}: {:?}",
                i,
                retrieved_data.name()
            );
            Ok(retrieved_data)
        })
        .into_box()
}
