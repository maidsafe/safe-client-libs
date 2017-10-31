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

//! SAFE core.
//!
//! # Config
//!
//! You can create a config file with custom options following the example in sample_config/. The
//! file should be named <exe>.safe_core.config. The available options are as follows:
//!
//! ```ignore
//! mock_unlimited_mutations
//! ```
//!
//! If true, switch off mutations limit in mock-vault. If `safe_core` is built with
//! `--features=use-mock-routing`, then setting this option will allow an unlimited number of
//! mutations. `safe_core` does not need to be rebuilt for this to take effect. The default value is
//! false.
//!
//! ```ignore
//! mock_in_memory_storage
//! ```
//!
//! If true, use memory store instead of file store in mock-vault. If `safe_core` is built with
//! `--features=use-mock-routing`, then setting this option will use mock-vault's memory store,
//! which is faster than reading/writing to disk. `safe_core` does not need to be rebuilt for this
//! to take effect. The default value is false (true when running tests).
//!
//! ```ignore
//! mock_vault_path
//! ```
//!
//! If this variable is set and we are using file storage (`mock_in_memory_storage` is `false`),
//! use this as the path for mock-vault, overriding the default

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
extern crate config_file_handler;
extern crate ffi_utils;
#[cfg(feature = "use-mock-routing")]
extern crate fs2;
extern crate futures;
#[cfg(feature = "use-mock-routing")]
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;
extern crate lru_cache;
extern crate maidsafe_utilities;
extern crate rand;
extern crate routing;
extern crate serde;
#[macro_use]
extern crate serde_derive;
#[cfg(test)]
extern crate serde_json;
extern crate rust_sodium;
extern crate self_encryption;
extern crate tiny_keccak;
extern crate tokio_core;
#[macro_use]
extern crate unwrap;

pub mod ffi;

pub use ffi::*;
pub use ffi::arrays::*;
pub use ffi::ipc::req::*;
pub use ffi::ipc::resp::*;
pub use ffi::nfs::*;

/// Utility functions.
#[macro_use]
pub mod utils;

/// Config file handling.
pub mod config_handler;
/// Cryptographic utilities.
pub mod crypto;
/// Event loop handling.
pub mod event_loop;
/// Utilities for handling `ImmutableData`.
pub mod immutable_data;
/// Inter-Process Communication utilities.
pub mod ipc;
/// NFS utilities.
pub mod nfs;
/// Implements the Self Encryption storage trait.
pub mod self_encryption_storage;

mod client;
mod errors;
mod event;

pub use self::client::{Client, ClientKeys, MDataInfo, mdata_info, recovery};
#[cfg(feature = "use-mock-routing")]
pub use self::client::{MockRouting, mock_vault_path};
pub use self::errors::CoreError;
pub use self::event::{CoreEvent, NetworkEvent, NetworkRx, NetworkTx};
pub use self::event_loop::{CoreFuture, CoreMsg, CoreMsgRx, CoreMsgTx};
pub use self::self_encryption_storage::{SelfEncryptionStorage, SelfEncryptionStorageError};
pub use self::utils::FutureExt;
pub use ffi::*;

/// All Maidsafe tagging should positive-offset from this.
pub const MAIDSAFE_TAG: u64 = 5_483_000;
/// `MutableData` type tag for a directory.
pub const DIR_TAG: u64 = 15_000;
