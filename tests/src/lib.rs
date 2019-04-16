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
    while_true
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
#![cfg_attr(
    feature = "cargo-clippy",
    deny(clippy, unicode_not_nfc, wrong_pub_self_convention, option_unwrap_used)
)]
#![cfg_attr(
    feature = "cargo-clippy",
    allow(implicit_hasher, too_many_arguments, use_debug)
)]

extern crate ffi_utils;
extern crate futures;
extern crate safe_app;
extern crate safe_authenticator;
#[macro_use]
extern crate safe_core;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
#[macro_use]
extern crate unwrap;

mod real_network;

use futures::future::Future;
use safe_app::test_utils::run_now;
use safe_app::{App, Client, ImmutableData};
use safe_core::utils;
use safe_core::utils::test_utils::random_client;

// Test unregistered clients.
// 1. Have a registered client PUT something on the network.
// 2. Try to read it as unregistered.
#[test]
fn unregistered_client() {
    let orig_data = ImmutableData::new(unwrap!(utils::generate_random_vector(30)));

    // Registered Client PUTs something onto the network.
    {
        let orig_data = orig_data.clone();
        random_client(|client| client.put_idata(orig_data));
    }

    // Unregistered Client should be able to retrieve the data.
    let app = unwrap!(App::unregistered(|| (), None));
    run_now(&app, move |client, _context| {
        let _ = client.get_idata(*orig_data.name()).map(move |data| {
            assert_eq!(data, orig_data);
        });
    });
}
