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

// Export public core interface.

pub use self::client::{map_info, Client, MapInfo};
pub use self::config_handler::config_dir;
pub use self::connection_manager::ConnectionManager;
pub use self::errors::CoreError;
// pub use self::network_event::{NetworkEvent, NetworkRx, NetworkTx};
pub use self::utils::logging;
pub use quic_p2p::Config as QuicP2pConfig;

/// Client trait and related constants.
pub mod client;
/// Config file handling.
pub mod config_handler;
/// Cryptographic utilities.
pub mod crypto;
/// Utility functions.
pub mod utils;

mod connection_manager;
mod errors;
// mod network_event;

/// `Map` type tag for a directory.
pub const DIR_TAG: u64 = 15_000;
