// Copyright 2016 MaidSafe.net limited.
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

#![cfg_attr(feature="cargo-clippy", deny(clippy, clippy_pedantic))]
#![cfg_attr(feature="cargo-clippy", allow(use_debug, print_stdout, missing_docs_in_private_items))]

extern crate docopt;
extern crate rand;
extern crate rustc_serialize;
extern crate futures;
extern crate routing;
extern crate rust_sodium;
#[macro_use]
extern crate safe_core;
extern crate tokio_core;
extern crate maidsafe_utilities;
#[macro_use]
extern crate unwrap;

use docopt::Docopt;
use futures::Future;
use futures::stream::{self, Stream};
use futures::sync::mpsc;
use rand::{Rng, SeedableRng};
use routing::{ImmutableData, MutableData};
use rust_sodium::crypto::sign::PublicKey;
use safe_core::{Client, CoreMsg, FutureExt, event_loop};
use tokio_core::reactor::Core;

#[cfg_attr(rustfmt, rustfmt_skip)]
static USAGE: &'static str = "
Usage:
  client_stress_test [options]

Options:
  -i <count>, --immutable=<count>   Number of ImmutableData chunks to Put and
                                    Get [default: 100].
  -m <count>, --mutable=<count>     Number of MutableData chunks to Put and
                                    Get [default: 100].
  --seed <seed>                     Seed for a pseudo-random number generator.
  --get-only                        Only Get the data, don't Put it.
  --invite INVITATION               Use the given invite.
  -h, --help                        Display this help message and exit.
";

#[derive(Debug, RustcDecodable)]
struct Args {
    flag_immutable: Option<usize>,
    flag_mutable: Option<usize>,
    flag_seed: Option<u32>,
    flag_get_only: bool,
    flag_invite: Option<String>,
    flag_help: bool,
}

fn random_mutable_data<R: Rng>(type_tag: u64, public_key: &PublicKey, rng: &mut R) -> MutableData {
    let permissions = btree_map![];
    let data = btree_map![];

    unwrap!(MutableData::new(
        rng.gen(),
        type_tag,
        permissions,
        data,
        btree_set![*public_key],
    ))
}

enum Data {
    Mutable(MutableData),
    Immutable(ImmutableData),
}

fn main() {
    unwrap!(maidsafe_utilities::log::init(true));

    let args: Args = Docopt::new(USAGE)
        .and_then(|docopt| docopt.decode())
        .unwrap_or_else(|error| error.exit());

    let immutable_data_count = unwrap!(args.flag_immutable);
    let mutable_data_count = unwrap!(args.flag_mutable);
    let mut rng = rand::XorShiftRng::from_seed(match args.flag_seed {
        Some(seed) => [0, 0, 0, seed],
        None => {
            [
                rand::random(),
                rand::random(),
                rand::random(),
                rand::random(),
            ]
        }
    });

    let el = unwrap!(Core::new());
    let el_h = el.handle();

    let (core_tx, core_rx) = mpsc::unbounded();
    let (net_tx, _net_rx) = mpsc::unbounded();

    // Create account
    let secret_0: String = rng.gen_ascii_chars().take(20).collect();
    let secret_1: String = rng.gen_ascii_chars().take(20).collect();
    let mut invitation = rng.gen_ascii_chars().take(20).collect();
    if let Some(i) = args.flag_invite.clone() {
        invitation = i;
    }

    let client = if args.flag_get_only {
        unwrap!(Client::login(
            &secret_0,
            &secret_1,
            el_h,
            core_tx.clone(),
            net_tx,
        ))
    } else {
        println!("\n\tAccount Creation");
        println!("\t================");
        println!("\nTrying to create an account ...");
        unwrap!(Client::registered(
            &secret_0,
            &secret_1,
            &invitation,
            el_h,
            core_tx.clone(),
            net_tx,
        ))
    };
    println!("Logged in successfully!");
    let public_key = unwrap!(client.public_signing_key());
    let core_tx_clone = core_tx.clone();

    unwrap!(core_tx.unbounded_send(CoreMsg::new(move |client, _| {
        let mut stored_data = Vec::with_capacity(mutable_data_count + immutable_data_count);

        for _ in 0..immutable_data_count {
            // Construct data
            let data = ImmutableData::new(rng.gen_iter().take(1024).collect());
            stored_data.push(Data::Immutable(data));
        }

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

        stream::iter_ok(stored_data.into_iter().enumerate())
            .fold((client.clone(), args, rng), |(client, args, rng),
             (i, data)| {
                let c2 = client.clone();
                let c3 = client.clone();
                let c4 = client.clone();

                match data {
                    Data::Immutable(data) => {
                        let fut = if args.flag_get_only {
                            futures::finished(data).into_box()
                        } else {
                            // Put the data to the network
                            c2.put_idata(data.clone())
                                .and_then(move |_| {
                                    println!("Put ImmutableData chunk #{}: {:?}", i, data.name());

                                    // Get the data
                                    c3.get_idata(*data.name()).map(move |retrieved_data| {
                                        assert_eq!(data, retrieved_data);
                                        retrieved_data
                                    })
                                })
                                .and_then(move |retrieved_data| {
                                    println!(
                                        "Retrieved ImmutableData chunk #{}: {:?}",
                                        i,
                                        retrieved_data.name()
                                    );
                                    Ok(retrieved_data)
                                })
                                .into_box()
                        };

                        fut.and_then(move |data| {
                            // Get all the chunks again
                            c4.get_idata(*data.name()).map(move |retrieved_data| {
                                assert_eq!(data, retrieved_data);
                                println!("Retrieved chunk #{}: {:?}", i, data.name());
                                (args, rng)
                            })
                        }).map(move |(args, rng)| (client, args, rng))
                            .map_err(|e| println!("Error: {:?}", e))
                            .into_box()
                    }
                    Data::Mutable(data) => {
                        let fut = if args.flag_get_only {
                            futures::finished(data).into_box()
                        } else {
                            // Put the data to the network
                            c2.put_mdata(data.clone())
                                .and_then(move |_| {
                                    println!("Put MutableData chunk #{}: {:?}", i, data.name());

                                    // Get the data
                                    c3.get_mdata_shell(*data.name(), data.tag()).map(
                                        move |retrieved_data| {
                                            assert_eq!(data, retrieved_data);
                                            retrieved_data
                                        },
                                    )
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
                        };

                        // TODO(nbaksalyar): stress test mutate_mdata and get_mdata_value here
                        fut.and_then(move |data| {
                            // Get all the chunks again
                            c4.get_mdata_shell(*data.name(), data.tag()).map(
                                move |retrieved_data| {
                                    assert_eq!(data, retrieved_data);
                                    println!("Retrieved chunk #{}: {:?}", i, data.name());
                                    (args, rng)
                                },
                            )
                        }).map(move |(args, rng)| (client, args, rng))
                            .map_err(|e| println!("Error: {:?}", e))
                            .into_box()
                    }
                }
            })
            .map(move |_| {
                unwrap!(core_tx_clone.unbounded_send(CoreMsg::build_terminator()))
            })
            .into_box()
            .into()
    })));

    event_loop::run(el, &client, &(), core_rx);
}
