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

//! SAFE core

#![doc(html_logo_url =
           "https://raw.githubusercontent.com/maidsafe/QA/master/Images/maidsafe_logo.png",
       html_favicon_url = "http://maidsafe.net/img/favicon.ico",
       html_root_url = "http://maidsafe.github.io/safe_core")]

// For explanation of lint checks, run `rustc -W help` or see
// https://github.
// com/maidsafe/QA/blob/master/Documentation/Rust%20Lint%20Checks.md
#![forbid(exceeding_bitshifts, mutable_transmutes, no_mangle_const_items,
          unknown_crate_types, warnings)]
#![deny(bad_style, deprecated, improper_ctypes, missing_docs,
        non_shorthand_field_patterns, overflowing_literals, plugin_as_library,
        private_no_mangle_fns, private_no_mangle_statics, stable_features,
        unconditional_recursion, unknown_lints, unsafe_code, unused,
        unused_allocation, unused_attributes, unused_comparisons, unused_features,
        unused_parens, while_true)]
#![warn(trivial_casts, trivial_numeric_casts, unused_extern_crates, unused_import_braces,
        unused_qualifications, unused_results)]
#![allow(box_pointers, fat_ptr_transmutes, missing_copy_implementations,
         missing_debug_implementations, variant_size_differences)]

#![cfg_attr(feature="cargo-clippy", deny(clippy, unicode_not_nfc, wrong_pub_self_convention,
                                         option_unwrap_used))]
#![cfg_attr(feature="cargo-clippy", allow(use_debug, too_many_arguments))]

extern crate base64;
extern crate chrono;
extern crate ffi_utils;
extern crate futures;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;
extern crate lru_cache;
extern crate maidsafe_utilities;
extern crate rand;
extern crate routing;
#[macro_use]
extern crate serde_derive;
extern crate rust_sodium;
extern crate self_encryption;
extern crate tokio_core;
#[macro_use]
extern crate unwrap;

/// Utility functions
#[macro_use]
pub mod utils;
/// Event loop handling
pub mod event_loop;
/// Helper functions to handle `ImmutableData` related operations
pub mod immutable_data;
/// Inter-Process Communication utilities
pub mod ipc;
/// NFS utilities
pub mod nfs;
/// Implements the Self Encryption storage trait
pub mod self_encryption_storage;

mod client;
mod errors;
mod event;

pub use self::client::{Client, ClientKeys, MDataInfo, mdata_info};
pub use self::errors::CoreError;
pub use self::event::{CoreEvent, NetworkEvent, NetworkRx, NetworkTx};
pub use self::event_loop::{CoreFuture, CoreMsg, CoreMsgRx, CoreMsgTx};
pub use self::self_encryption_storage::{SelfEncryptionStorage, SelfEncryptionStorageError};
pub use self::utils::FutureExt;

/// All Maidsafe tagging should positive-offset from this
pub const MAIDSAFE_TAG: u64 = 5483_000;
/// `MutableData` type tag for a directory
pub const DIR_TAG: u64 = 15000;
/// type tag for public ids.
pub const PUBLIC_ID_TAG: u64 = 7;
