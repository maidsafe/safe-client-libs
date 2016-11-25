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

//! Safe client example.

// For explanation of lint checks, run `rustc -W help` or see
// https://github.
// com/maidsafe/QA/blob/master/Documentation/Rust%20Lint%20Checks.md
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

#![cfg_attr(feature="clippy", feature(plugin))]
#![cfg_attr(feature="clippy", plugin(clippy))]
#![cfg_attr(feature="clippy", deny(clippy, clippy_pedantic))]
#![cfg_attr(feature="clippy", allow(use_debug, print_stdout))]

/*

extern crate docopt;
extern crate futures;
extern crate rand;
extern crate routing;
extern crate rustc_serialize;
extern crate safe_core;
extern crate rust_sodium;
extern crate tokio_core;
#[macro_use]
extern crate maidsafe_utilities;
#[macro_use]
extern crate unwrap;

use docopt::Docopt;
use futures::Future;
use futures::stream::{self, Stream};
use rand::{Rng, SeedableRng};
use routing::{Data, ImmutableData, StructuredData};
use rust_sodium::crypto::sign::{PublicKey, SecretKey};
use safe_core::core::{self, Client, CoreMsg, FutureExt};
use tokio_core::channel;
use tokio_core::reactor::Core;


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

    let el = unwrap!(Core::new());
    let el_h = el.handle();

    let (core_tx, core_rx) = unwrap!(channel::channel(&el_h));
    let (net_tx, _net_rx) = unwrap!(channel::channel(&el_h));

    // Create account
    let secret_0: String = rng.gen_ascii_chars().take(20).collect();
    let secret_1: String = rng.gen_ascii_chars().take(20).collect();

    let client = if args.flag_get_only {
        unwrap!(Client::login(&secret_0, &secret_1, el_h, core_tx.clone(), net_tx))
    } else {
        println!("\n\tAccount Creation");
        println!("\t================");
        println!("\nTrying to create an account ...");
        unwrap!(Client::registered(&secret_0, &secret_1, el_h, core_tx.clone(), net_tx))
    };
    println!("Logged in successfully!");
    let public_key = unwrap!(client.public_signing_key());
    let secret_key = unwrap!(client.secret_signing_key());
    let core_tx_clone = core_tx.clone();

    unwrap!(core_tx.send(CoreMsg::new(move |client, _| {
        let mut stored_data = Vec::with_capacity(immutable_data_count + structured_data_count);

        for _ in 0..immutable_data_count {
            // Construct data
            let data = Data::Immutable(ImmutableData::new(rng.gen_iter().take(1024).collect()));
            stored_data.push(data);
        }

        for _ in immutable_data_count..(immutable_data_count + structured_data_count) {
            // Construct data
            let structured_data =
                random_structured_data(100000, &public_key, &secret_key, &mut rng);
            let data = Data::Structured(structured_data.clone());
            stored_data.push(data);
        }

        let message = format!("Generated {} items ({} immutable, {} structured)",
                              stored_data.len(),
                              immutable_data_count,
                              structured_data_count);
        let underline = (0..message.len()).map(|_| "=").collect::<String>();
        println!("\n\t{}\n\t{}", message, underline);

        let stored_data = stored_data.into_iter().enumerate().map(Ok);

        stream::iter(stored_data)
            .fold((client.clone(), args, rng),
                  |(client, args, mut rng), (i, data)| {
                let c2 = client.clone();
                let c3 = client.clone();
                let c4 = client.clone();
                let c5 = client.clone();
                let c6 = client.clone();

                let fut = if !args.flag_get_only {
                    // Put the data to the network
                    c2.put(data.clone(), None)
                        .and_then(move |_| {
                            println!("Put chunk #{}: {:?}", i, data.name());

                            // Get the data
                            c3.get(data.identifier(), None)
                                .map(move |retrieved_data| {
                                    assert_eq!(data, retrieved_data);
                                    retrieved_data
                                })
                        })
                        .and_then(move |retrieved_data| {
                            println!("Retrieved chunk #{}: {:?}", i, retrieved_data.name());
                            Ok(retrieved_data)
                        })
                        .into_box()
                } else {
                    futures::finished(data).into_box()
                };

                fut.and_then(move |data| {
                        // Construct data
                        if let Data::Structured(sd) = data.clone() {
                            let structured_data = unwrap!(StructuredData::new(sd.get_type_tag(),
                                                        *sd.name(),
                                                        sd.get_version() + 1,
                                                        rng.gen_iter().take(10).collect(),
                                                        sd.get_owner_keys().clone(),
                                                        vec![],
                                                        Some(&unwrap!(c4.secret_signing_key()))));
                            let new_data = Data::Structured(structured_data.clone());

                            if !args.flag_get_only {
                                // Put the data to the network and block until we get a response
                                c4.post(new_data.clone(), None)
                                    .and_then(move |_| {
                                        println!("Post chunk #{}: {:?}", i, data.name());

                                        // Get the data
                                        let data_id = new_data.identifier();
                                        c5.get(data_id, None)
                                            .map(move |retrieved_data| {
                                                assert_eq!(new_data, retrieved_data);
                                                println!("Retrieved chunk #{}: {:?}",
                                                         i,
                                                         new_data.name());
                                                (args, rng, new_data)
                                            })
                                    })
                                    .into_box()
                            } else {
                                futures::finished((args, rng, new_data)).into_box()
                            }
                        } else {
                            // Skip non-structured data.
                            futures::finished((args, rng, data)).into_box()
                        }
                    })
                    .and_then(move |(args, rng, data)| {
                        // Get all the chunks again
                        c6.get(data.identifier(), None)
                            .map(move |retrieved_data| {
                                assert_eq!(data, retrieved_data);
                                println!("Retrieved chunk #{}: {:?}", i, data.name());
                                (args, rng)
                            })
                    })
                    .map(move |(args, rng)| (client, args, rng))
                    .map_err(|e| println!("Error: {:?}", e))
                    .into_box()
            })
            .map(move |_| unwrap!(core_tx_clone.send(CoreMsg::build_terminator())))
            .into_box()
            .into()
    })));

    core::run(el, client, (), core_rx);
}

*/

fn main() {}
