// Copyright 2015 MaidSafe.net limited.
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

#![crate_name = "safe_client"]
#![crate_type = "lib"]
#![doc(html_logo_url = "https://raw.githubusercontent.com/maidsafe/QA/master/Images/maidsafe_logo.png",
       html_favicon_url = "http://maidsafe.net/img/favicon.ico",
              html_root_url = "http://dirvine.github.io/dirvine/safe_client/")]

///////////////////////////////////////////////////
//               LINT
///////////////////////////////////////////////////

#![forbid(bad_style, warnings)]

#![deny(deprecated, improper_ctypes, missing_docs, non_shorthand_field_patterns,
overflowing_literals, plugin_as_library, private_no_mangle_fns, private_no_mangle_statics,
raw_pointer_derive, stable_features, unconditional_recursion, unknown_lints, unsafe_code,
unused, unused_allocation, unused_attributes, unused_comparisons,
unused_features, unused_parens, unused_mut, while_true)]

#![warn(trivial_casts, trivial_numeric_casts, unused_extern_crates, unused_import_braces,
unused_qualifications, variant_size_differences)]

///////////////////////////////////////////////////

//! #Safe-Client Library
//! [Project github page](https://github.com/maidsafe/safe_client)

extern crate cbor;
extern crate rand;
extern crate routing;
extern crate sodiumoxide;
extern crate lru_time_cache;
extern crate rustc_serialize;
extern crate self_encryption;
#[macro_use] extern crate log;

/// Macros defined for usage
#[macro_use]
mod macros;

/// Public and Private Id types
pub mod id;
/// Safe-Client Errors
pub mod errors;
/// Self-Auth and Gateway Module
pub mod client;
/// Utility functions
pub mod utility;
/// Events filtered from set of Routing provided events, on which the Client Modules must
/// specifically act
pub mod translated_events;
/// Implements the Self Encryption storage trait
pub mod self_encryption_storage;
/// Helper functions to handle StructuredData related operations
pub mod structured_data_operations;

pub use self_encryption_storage::SelfEncryptionStorage;

/// All Maidsafe tagging should positive-offset from this
pub const MAIDSAFE_TAG: u64 = 5483_000;
/// All StructuredData tagging should positive-offset from this if the operation needs to go
/// through this safe_client crate
pub const CLIENT_STRUCTURED_DATA_TAG: u64 = 15000; // TODO offset this itself from routing
