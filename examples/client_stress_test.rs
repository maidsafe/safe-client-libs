// Copyright 2016 MaidSafe.net limited.
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
#![cfg_attr(feature="clippy", allow(use_debug, print_stdout))]

extern crate docopt;
extern crate rand;
extern crate routing;
extern crate rustc_serialize;
extern crate safe_core;
extern crate sodiumoxide;
#[macro_use]
extern crate maidsafe_utilities;
#[macro_use]
extern crate unwrap;

use safe_core::core::client::Client;

use docopt::Docopt;
use routing::{Data, ImmutableData, StructuredData};
use rand::{Rng, SeedableRng};
use rand::distributions::{IndependentSample, Range};
use sodiumoxide::crypto::sign::{PublicKey, SecretKey};


#[cfg_attr(rustfmt, rustfmt_skip)]
static USAGE: &'static str = "
Usage:
  client_stress_test [options]

Options:
  -i <count>, --immutable=<count>   Number of ImmutableData chunks to Put and
                                    Get [default: 100].
  -s <count>, --structured=<count>  Number of StructuredData chunks to Put and
                                    Get [default: 100].
  --seed <seed>                     Seed for a pseudo-random number generator.
  --get-only                        Only Get the data, don't Put it.
  -h, --help                        Display this help message and exit.
";

#[derive(Debug, RustcDecodable)]
struct Args {
    flag_immutable: Option<usize>,
    flag_structured: Option<usize>,
    flag_seed: Option<u32>,
    flag_get_only: bool,
    flag_help: bool,
}

fn random_structured_data<R: Rng>(type_tag: u64,
                                  public_key: &PublicKey,
                                  secret_key: &SecretKey,
                                  rng: &mut R)
                                  -> StructuredData {
    unwrap!(StructuredData::new(type_tag,
                                rng.gen(),
                                0,
                                rng.gen_iter().take(10).collect(),
                                vec![public_key.clone()],
                                vec![],
                                Some(secret_key)))
}


fn main() {
    unwrap!(maidsafe_utilities::log::init(true));

    let args: Args = Docopt::new(USAGE)
        .and_then(|docopt| docopt.decode())
        .unwrap_or_else(|error| error.exit());

    let immutable_data_count = unwrap!(args.flag_immutable);
    let structured_data_count = unwrap!(args.flag_structured);
    let mut rng = rand::XorShiftRng::from_seed(match args.flag_seed {
        Some(seed) => [0, 0, 0, seed],
        None => [rand::random(), rand::random(), rand::random(), rand::random()],
    });

    // Create account
    let keyword: String = rng.gen_ascii_chars().take(20).collect();
    let password: String = rng.gen_ascii_chars().take(20).collect();
    let pin_range = Range::new(0u16, 9999);
    let pin = pin_range.ind_sample(&mut rng).to_string();

    let mut client = if args.flag_get_only {
        unwrap!(Client::log_in(keyword.clone(), pin.clone(), password.clone()))
    } else {
        println!("\n\tAccount Creation");
        println!("\t================");
        println!("\nTrying to create an account ...");
        unwrap!(Client::create_account(keyword.clone(), pin.clone(), password.clone()))
    };
    println!("Logged in successfully !!");
    let public_key = *unwrap!(client.get_public_signing_key());
    let secret_key = unwrap!(client.get_secret_signing_key()).clone();

    if !args.flag_get_only {
        // Put and Get ImmutableData chunks
        let message = format!("Put and Get {} ImmutableData chunks", immutable_data_count);
        let underline = (0..message.len()).map(|_| "=").collect::<String>();
        println!("\n\t{}\n\t{}", message, underline);
    }
    let mut stored_data = Vec::with_capacity(immutable_data_count + structured_data_count);
    for i in 0..immutable_data_count {
        // Construct data
        let data = Data::Immutable(ImmutableData::new(rng.gen_iter().take(1024).collect()));
        if !args.flag_get_only {
            // Put the data to the network and block until we get a response
            let put_response_getter = unwrap!(client.put(data.clone(), None));
            unwrap!(put_response_getter.get());
            println!("Put chunk #{}: {:?}", i, data.name());
            // Get the data
            let get_response_getter = unwrap!(client.get(data.identifier(), None));
            let retrieved_data = unwrap!(get_response_getter.get());
            assert_eq!(data, retrieved_data);
            println!("Retrieved chunk #{}: {:?}", i, data.name());
        }
        // Keep the data for later checks
        stored_data.push(data);
    }

    if !args.flag_get_only {
        // Put and Get StructuredData chunks
        let message = format!("Put and Get {} StructuredData chunks",
                              structured_data_count);
        let underline = (0..message.len()).map(|_| "=").collect::<String>();
        println!("\n\t{}\n\t{}", message, underline);
    }
    for i in immutable_data_count..(immutable_data_count + structured_data_count) {
        // Construct data
        let structured_data = random_structured_data(100000, &public_key, &secret_key, &mut rng);
        let data = Data::Structured(structured_data.clone());
        if !args.flag_get_only {
            // Put the data to the network and block until we get a response
            let put_response_getter = unwrap!(client.put(data.clone(), None));
            unwrap!(put_response_getter.get());
            println!("Put chunk #{}, {:?}", i, data.name());
            // Get the data
            let data_id = data.identifier();
            let get_response_getter = unwrap!(client.get(data_id, None));
            let retrieved_data = unwrap!(get_response_getter.get());
            assert_eq!(data, retrieved_data);
            println!("Retrieved chunk #{}: {:?}", i, data.name());
        }
        // Keep the data for later checks
        stored_data.push(data);
    }

    if !args.flag_get_only {
        // Post new versions of StructuredData chunks
        let message = format!("Post {} StructuredData chunks", structured_data_count);
        let underline = (0..message.len()).map(|_| "=").collect::<String>();
        println!("\n\t{}\n\t{}", message, underline);
    }
    for (i, data) in stored_data.iter_mut().enumerate() {
        // Construct data
        let structured_data = if let Data::Structured(sd) = data.clone() {
            unwrap!(StructuredData::new(sd.get_type_tag(),
                                        *sd.get_identifier(),
                                        sd.get_version() + 1,
                                        rng.gen_iter().take(10).collect(),
                                        sd.get_owner_keys().clone(),
                                        vec![],
                                        Some(&secret_key)))
        } else {
            continue; // Skip non-structured data.
        };
        let new_data = Data::Structured(structured_data.clone());
        if !args.flag_get_only {
            // Put the data to the network and block until we get a response
            let put_response_getter = unwrap!(client.post(new_data.clone(), None));
            unwrap!(put_response_getter.get());
            println!("Post chunk #{}: {:?}", i, data.name());
            // Get the data
            let data_id = new_data.identifier();
            let get_response_getter = unwrap!(client.get(data_id, None));
            let retrieved_data = unwrap!(get_response_getter.get());
            assert_eq!(new_data, retrieved_data);
            println!("Retrieved chunk #{}: {:?}", i, new_data.name());
        }
        // Keep the data for later checks
        *data = new_data;
    }

    // Get all the chunks again
    let message = format!("Get {} chunks",
                          structured_data_count + immutable_data_count);
    let underline = (0..message.len()).map(|_| "=").collect::<String>();
    println!("\n\t{}\n\t{}", message, underline);
    for (i, data) in stored_data.into_iter().enumerate() {
        let get_response_getter = unwrap!(client.get(data.identifier(), None));
        let retrieved_data = unwrap!(get_response_getter.get());
        assert_eq!(data, retrieved_data);
        println!("Retrieved chunk #{}: {:?}", i, data.name());
    }
}
