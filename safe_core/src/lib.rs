// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! SAFE Core.
//!
//! ## Configuring SAFE Core
//!
//! Please see the [Configuring Client
//! Libs](https://github.com/maidsafe/safe_client_libs/wiki/Configuring-Client-Libs) section of the
//! wiki.

#![doc(
    html_logo_url = "https://raw.githubusercontent.com/maidsafe/QA/master/Images/maidsafe_logo.png",
    html_favicon_url = "http://maidsafe.net/img/favicon.ico",
    test(attr(forbid(warnings)))
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
    clippy::all,
    clippy::option_unwrap_used,
    clippy::unicode_not_nfc,
    clippy::wrong_pub_self_convention,
    deprecated,
    improper_ctypes,
    missing_docs,
    non_shorthand_field_patterns,
    overflowing_literals,
    plugin_as_library,
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
    clippy::implicit_hasher,
    clippy::too_many_arguments,
    clippy::use_debug,
    missing_copy_implementations,
    missing_debug_implementations,
    variant_size_differences
)]

#[cfg(feature = "mock-network")]
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;
#[macro_use]
extern crate serde_derive;
#[cfg(test)]
extern crate serde_json;
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
#[cfg(feature = "mock-network")]
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
