// Copyright 2017 MaidSafe.net limited.
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

//! Generate Invitations

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

#[macro_use]
extern crate unwrap;

extern crate docopt;
extern crate maidsafe_utilities;
extern crate safe_core;
extern crate rand;
extern crate routing;
extern crate rustc_serialize;
extern crate tiny_keccak;

use docopt::Docopt;
use rand::{Rng, thread_rng};
use routing::{Data, DataIdentifier, StructuredData, XorName};
use safe_core::core::client::Client;
use std::fs::File;
use std::io::{Read, Write};
use std::time::UNIX_EPOCH;
use tiny_keccak::sha3_256;

const INVITE_TOKEN_SIZE: usize = 90;
const INVITE_TOKEN_TYPE_TAG: u64 = 8;

static USAGE: &'static str = "
Usage:
  gen_invites [--gen-seed SIZE | --get-pk | --check-invite INVITE | -c [-n INVITES] | \
               -n INVITES | -h]

Options:
  --gen-seed SIZE            Only generate a random seed of given size, writing into input file.
  --get-pk                   Only get the public sign key given the seed, don't do anything extra.
  --check-invite INVITE      Only check the status of the given invite (exists, consumed etc.).
  -c, --create               Create account using seed from input file. By default it will login.
  -n, --num-invites INVITES  Number of invites to generate (will populate the Network too).
  -h, --help                 Display this help message and exit.
";

#[derive(Debug, RustcDecodable)]
struct Args {
    flag_gen_seed: Option<usize>,
    flag_get_pk: bool,
    flag_check_invite: Option<String>,
    flag_create: bool,
    flag_num_invites: Option<usize>,
    flag_help: bool,
}

fn main() {
    unwrap!(maidsafe_utilities::log::init(true));

    let args: Args = Docopt::new(USAGE)
        .and_then(|docopt| docopt.decode())
        .unwrap_or_else(|error| error.exit());

    if let Some(size) = args.flag_gen_seed {
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

    if args.flag_get_pk {
        let sign_pk = unwrap!(Client::sign_pk_from_seed(&seed));
        return println!("Public Signing Key: {:?}", sign_pk.0);
    }

    if let Some(invite) = args.flag_check_invite {
        let mut cl = unwrap!(Client::create_unregistered_client());
        let id = XorName(sha3_256(invite.as_bytes()));

        let data = unwrap!(unwrap!(cl.get(DataIdentifier::Structured(id, INVITE_TOKEN_TYPE_TAG),
                                          None))
                                   .get()
                                   .map_err(|e| format!("Invite does not exist: {:?}", e)));
        match data {
            Data::Structured(sd) => println!("Invite already consumed: {}", sd.is_deleted()),
            x => {
                println!("Address space taken by an unexpected data-type. Expected \
                                StructuredData, found: {:?}",
                         x);
            }
        }
        return;
    }

    let mut output = {
        let name = format!("./output-{}", unwrap!(UNIX_EPOCH.elapsed()).as_secs());
        unwrap!(File::create(&name))
    };

    let mut cl = if args.flag_create {
        println!("\nTrying to create an account using given seed from file...");
        unwrap!(Client::create_account_with_seed(&seed))
    } else {
        println!("\nTrying to log into the created account using given seed from file...");
        unwrap!(Client::login_with_seed(&seed))
    };
    println!("Success !");

    let num_invites = args.flag_num_invites.unwrap_or_else(|| {
        println!("\n------------ Enter number of invitations to generate ---------------");
        let mut num = String::new();
        let _ = std::io::stdin().read_line(&mut num);
        num = num.trim().to_string();
        unwrap!(num.parse::<usize>())
    });

    for i in 0..num_invites {
        let invitation = generate_random_printable(INVITE_TOKEN_SIZE);
        let id = XorName(sha3_256(invitation.as_bytes()));

        let sd =
            unwrap!(StructuredData::new(INVITE_TOKEN_TYPE_TAG, id, 0, vec![1], Default::default()));

        unwrap!(unwrap!(cl.put(Data::Structured(sd), None)).get());
        unwrap!(write!(output, "{}\n", invitation));

        println!("Generated {} / {}", i + 1, num_invites);
    }

    println!("----------- Done -----------");
}

fn generate_random_printable(len: usize) -> String {
    thread_rng().gen_ascii_chars().take(len).collect()
}
