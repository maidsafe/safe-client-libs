// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! SAFE core.
//!
//! # Environment Variables
//!
//! The following environment variables can be set to enable custom options. Each one has higher
//! precedence than its respective config file option (see the "Config" section below).
//!
//! ```ignore
//! SAFE_MOCK_UNLIMITED_MUTATIONS
//! ```
//!
//! If set, switch off mutations limit in mock-vault. If `safe_core` is built with
//! `--features=use-mock-routing`, then setting this option will allow an unlimited number of
//! mutations. `safe_core` does not need to be rebuilt for this to take effect.
//!
//! ```ignore
//! SAFE_MOCK_IN_MEMORY_STORAGE
//! ```
//!
//! If set, use memory store instead of file store in mock-vault. If `safe_core` is built with
//! `--features=use-mock-routing`, then setting this option will use mock-vault's memory store,
//! which is faster than reading/writing to disk. `safe_core` does not need to be rebuilt for this
//! to take effect.
//!
//! ```ignore
//! SAFE_MOCK_VAULT_PATH
//! ```
//!
//! If this is set and file storage is being used (`mock_in_memory_storage` is `false`), use this as
//! the path for mock-vault.
//!
//! # Config
//!
//! You can create a config file with custom options following the example in `sample_config/`. The
//! file should be named `<exe>.safe_core.config`. The available options are as follows:
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
//! to take effect. The default value is false.
//!
//! ```ignore
//! mock_vault_path
//! ```
//!
//! If this variable is set and file storage is being used (`mock_in_memory_storage` is `false`),
//! use this as the path for mock-vault.

#![doc(
    html_logo_url = "https://raw.githubusercontent.com/maidsafe/QA/master/Images/maidsafe_logo.png",
    html_favicon_url = "http://maidsafe.net/img/favicon.ico",
    test(attr(forbid(warnings))),
)]
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
    private_no_mangle_fns,
    private_no_mangle_statics,
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
    deny(
        clippy,
        unicode_not_nfc,
        wrong_pub_self_convention,
        option_unwrap_used
    )
)]
#![cfg_attr(
    feature = "cargo-clippy",
    allow(implicit_hasher, too_many_arguments, use_debug)
)]

extern crate chrono;
extern crate config_file_handler;
extern crate data_encoding;
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
extern crate rust_sodium;
extern crate self_encryption;
#[cfg(test)]
extern crate serde_json;
extern crate tiny_keccak;
extern crate tokio_core;
#[macro_use]
extern crate unwrap;

pub mod ffi;

pub use ffi::arrays::*;
pub use ffi::ipc::req::*;
pub use ffi::ipc::resp::*;
pub use ffi::nfs::*;
pub use ffi::*;

/// Utility functions.
#[macro_use]
pub mod utils;

/// Client trait and related constants.
pub mod client;
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

mod errors;
mod event;

pub use self::client::{mdata_info, recovery, Client, ClientKeys, MDataInfo};
#[cfg(feature = "use-mock-routing")]
pub use self::client::{mock_vault_path, MockRouting};
pub use self::errors::CoreError;
pub use self::event::{CoreEvent, NetworkEvent, NetworkRx, NetworkTx};
pub use self::event_loop::{CoreFuture, CoreMsg, CoreMsgRx, CoreMsgTx};
pub use self::self_encryption_storage::{SelfEncryptionStorage, SelfEncryptionStorageError};
pub use self::utils::FutureExt;

/// All Maidsafe tagging should positive-offset from this.
pub const MAIDSAFE_TAG: u64 = 5_483_000;
/// `MutableData` type tag for a directory.
pub const DIR_TAG: u64 = 15_000;

/// Gets name of the dedicated container of the given app.
pub fn app_container_name(app_id: &str) -> String {
    format!("apps/{}", app_id)
}
