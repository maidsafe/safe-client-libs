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
// For explanation of lint checks, run `rustc -W help`.
#![deny(unsafe_code)]
#![warn(
    missing_docs,
    trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    unused_results
)]

// Public exports. See https://github.com/maidsafe/safe_client_libs/wiki/Export-strategy.

// Export FFI interface.

pub use ffi::arrays::*;
pub use ffi::ipc::req::*;
pub use ffi::ipc::resp::*;
pub use ffi::nfs::*;
pub use ffi::*;

// Export public core interface.

pub use self::client::{
    mdata_info, recoverable_apis, test_create_balance, AuthActions, Client, ClientKeys, MDataInfo,
};
#[cfg(feature = "mock-network")]
pub use self::client::{mock_vault_path, MockConnectionManager as ConnectionManager};
pub use self::config_handler::config_dir;
#[cfg(not(feature = "mock-network"))]
pub use self::connection_manager::ConnectionManager;
pub use self::errors::CoreError;
pub use self::event_loop::{CoreFuture, CoreMsg, CoreMsgRx, CoreMsgTx};
pub use self::network_event::{NetworkEvent, NetworkRx, NetworkTx};
pub use self::self_encryption_storage::{
    SEStorageError as SelfEncryptionStorageError, SelfEncryptionStorage,
};
pub use self::utils::logging;
pub use self::utils::FutureExt;
pub use quic_p2p::Config as QuicP2pConfig;

/// Client trait and related constants.
pub mod client;
/// Config file handling.
pub mod config_handler;
/// Core structs and associated functionality
pub mod core_structs;
/// Cryptographic utilities.
pub mod crypto;
/// Event loop handling.
pub mod event_loop;
/// FFI.
pub mod ffi;
/// Utilities for handling `ImmutableData`.
pub mod immutable_data;
/// Inter-Process Communication utilities.
pub mod ipc;
/// NFS utilities.
pub mod nfs;
/// Implements the Self Encryption storage trait.
pub mod self_encryption_storage;
/// Utility functions.
#[macro_use]
pub mod utils;

#[cfg(not(feature = "mock-network"))]
mod connection_manager;
mod errors;
mod network_event;

/// All Maidsafe tagging should positive-offset from this.
pub const MAIDSAFE_TAG: u64 = 5_483_000;
/// `MutableData` type tag for a directory.
pub const DIR_TAG: u64 = 15_000;

/// Gets name of the dedicated container of the given app.
pub fn app_container_name(app_id: &str) -> String {
    format!("apps/{}", app_id)
}
