// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! Generate invitations example.

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
extern crate clap;
#[macro_use]
extern crate safe_core;
#[macro_use]
extern crate unwrap;

use clap::{App as ClapApp, Arg};
use futures::Future;
use rand::{thread_rng, Rng};
use safe_app::utils::seed;
use safe_app::{Action, App, Client, FutureExt, MutableData, PermissionSet, User, XorName};
use safe_authenticator::Authenticator;
use std::fs::File;
use std::io::{Read, Write};
use std::sync::mpsc;
use std::time::UNIX_EPOCH;
use tiny_keccak::sha3_256;

const INVITE_TOKEN_SIZE: usize = 90;
const INVITE_TOKEN_TYPE_TAG: u64 = 8;

fn main() {
    unwrap!(maidsafe_utilities::log::init(true));

    let matches = ClapApp::new("gen_invites")
        .about("Generate invites to the network")
        .arg(
            Arg::with_name("gen-seed")
                .long("gen-seed")
                .takes_value(true)
                .help("Only generate a random seed of given size, writing into input file."),
        )
        .arg(
            Arg::with_name("get-pk")
                .long("get-pk")
                .help("Only get the public sign key given the seed, don't do anything extra."),
        )
        .arg(
            Arg::with_name("check-invite")
                .long("check-invite")
                .takes_value(true)
                .help("Only check the status of the given invite (exists, consumed etc.)."),
        )
        .arg(
            Arg::with_name("create")
                .short("c")
                .long("create")
                .help("Create account using seed from input file. By default it will login."),
        )
        .arg(
            Arg::with_name("num-invites")
                .short("n")
                .long("num-invites")
                .takes_value(true)
                .help("Number of invites to generate (will populate the Network too)."),
        )
        .get_matches();

    if let Ok(size) = value_t!(matches, "gen-seed", usize) {
        let mut input = unwrap!(File::create("./input"), "Unable to create input file");
        let seed = generate_random_printable(size);
        unwrap!(write!(input, "{}", seed));
        return println!("----------- Done -----------");
    }

    let mut seed = String::with_capacity(100);
    {
        let mut input = unwrap!(File::open("./input"), "Unable to open input file");
        let _ = unwrap!(input.read_to_string(&mut seed));
    }

    if matches.is_present("get-pk") {
        let sign_pk = unwrap!(seed::sign_pk_from_seed(&seed));
        return println!("Public Signing Key: {:?}", sign_pk.0);
    }

    // Check a single invite.

    if let Some(invite) = matches.value_of("check-invite") {
        let invite = invite.to_string();
        let app = unwrap!(App::unregistered(|| (), None,));
        let (tx, rx) = mpsc::channel();

        unwrap!(app.send(move |client, _| {
            let id = XorName(sha3_256(invite.as_str().as_bytes()));

            client
                .get_mdata_version(id, INVITE_TOKEN_TYPE_TAG)
                .then(move |res| -> Result<(), ()> {
                    match res {
                        Ok(version) => println!("Invite version: {}", version),
                        Err(e) => println!("Can't find invite: {:?}", e),
                    }
                    unwrap!(tx.send(()));
                    Ok(())
                })
                .map_err(|e| panic!("{:?}", e))
                .into_box()
                .into()
        }));

        unwrap!(rx.recv());
        println!("----------- Done -----------");
        return;
    }

    // Generate invites.

    let output = {
        let name = format!("./output-{}", unwrap!(UNIX_EPOCH.elapsed()).as_secs());
        unwrap!(File::create(&name))
    };

    let create = matches.is_present("create");

    let auth = unwrap!(if create {
        println!("\nTrying to create an account using given seed from file...");
        Authenticator::create_acc_with_seed(seed.as_str(), || ())
    } else {
        println!("\nTrying to log into the created account using given seed from file...");
        Authenticator::login_with_seed(seed.as_str(), || ())
    });

    println!("Success !");

    let num_invites = value_t!(matches, "num-invites", usize).unwrap_or_else(|_| {
        // Get number of invites to generate, if not passed in.

        println!("\n----------- Enter number of invitations to generate ---------------");

        let mut num = String::new();
        let _ = std::io::stdin().read_line(&mut num);
        num = num.trim().to_string();
        unwrap!(num.parse::<usize>())
    });

    println!("\nGenerating {} invites...", num_invites);

    for i in 0..num_invites {
        let inv = generate_random_printable(INVITE_TOKEN_SIZE);
        let id = XorName(sha3_256(inv.as_bytes()));

        let perms = btree_map![User::Anyone => PermissionSet::new()
                                       .allow(Action::Insert)
                                       .allow(Action::Update)
                                       .allow(Action::Delete)
                                       .allow(Action::ManagePermissions)];
        let data = btree_map![];
        let (tx, rx) = mpsc::channel();

        unwrap!(auth.send(move |client| {
            let owner_key = unwrap!(client.owner_key());
            let md = unwrap!(MutableData::new(
                id,
                INVITE_TOKEN_TYPE_TAG,
                perms,
                data,
                btree_set![owner_key]
            ));

            client
                .put_mdata(md)
                .then(move |_| {
                    unwrap!(tx.send(()));
                    Ok(())
                })
                .into_box()
                .into()
        }));

        unwrap!(rx.recv());
        let mut output2 = unwrap!(output.try_clone());
        unwrap!(writeln!(output2, "{}", inv));
        println!("Generated invite {} / {}", i + 1, num_invites);
    }

    println!("----------- Done -----------");
}

fn generate_random_printable(len: usize) -> String {
    thread_rng().gen_ascii_chars().take(len).collect()
}
