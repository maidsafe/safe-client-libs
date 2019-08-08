// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! Integration tests for Safe Client Libs.

#![cfg(test)]
// For explanation of lint checks, run `rustc -W help` or see
// https://github.
// com/maidsafe/QA/blob/master/Documentation/Rust%20Lint%20Checks.md
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

mod real_network;

use futures::future::Future;
use safe_app::{run, App, Client, PubImmutableData};
use safe_core::utils;
use safe_core::utils::test_utils::random_client;
use unwrap::unwrap;

// Test unregistered clients.
// 1. Have a registered client PUT something on the network.
// 2. Try to read it as unregistered.
#[test]
fn unregistered_client() {
    let orig_data = PubImmutableData::new(unwrap!(utils::generate_random_vector(30)));

    // Registered Client PUTs something onto the network.
    {
        let orig_data = orig_data.clone();
        random_client(|client| client.put_idata(orig_data));
    }

    // Unregistered Client should be able to retrieve the data.
    let app = unwrap!(App::unregistered(|| (), None));
    unwrap!(run(&app, move |client, _context| {
        let _ = client.get_idata(*orig_data.address()).map(move |data| {
            assert_eq!(data, orig_data.into());
        });
        Ok(())
    }));
}
