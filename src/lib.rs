// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! The Safe Network Client.
//!
//! In order to connect to The Safe Network you'll need to send messages back and forth to network nodes.
//! The [Client] has everything needed to perform this communication, with APIs to enable
//! working with data.
//!
//! With these APIs you can easily:
//! - Connect to The Safe Network
//! - Read Public data from the network
//! - Write data to the network (assuming you have a SafeCoin balance)
//!
//! ## Basic Usage
//!
//! Setting up a random client for read only access:
//!
//! ```no_run
//! # // The Safe Client is an sync library so will need some kind of runtime. Here we use tokio.
//! # extern crate tokio; use sn_client::ClientError;
//! use sn_client::Client;
//! # #[tokio::main] async fn main() { let _: Result<(), ClientError> = futures::executor::block_on( async {
//! let mut client = Client::new(None).await?;
//! // Now for example you can perform read operations:
//! let _some_balance = client.get_balance().await?;
//! # Ok(()) } ); }
//! ```
//!
//! Or use a pre-existing SecretKey which has a SafeCoin balance to be able to write to the network:
//!
//! ```no_run
//! # // The Safe Client is an sync library so will need some kind of runtime. Here we use tokio.
//! # extern crate tokio; use sn_client::ClientError;
//! use sn_client::Client;
//! use rand::rngs::OsRng;
//! use sn_data_types::Keypair;
//! # #[tokio::main] async fn main() { let _: Result<(), ClientError> = futures::executor::block_on( async {
//! let id = Keypair::new_ed25519(&mut OsRng);
//! let mut client = Client::new(Some(id)).await?;
//! // Now for example you can perform read operations:
//! let _some_balance = client.get_balance().await?;
//! # Ok(()) } ); }
//! ```

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

// Export public client interface.

pub use self::client::{map_info, Client, MapInfo};
pub use self::config_handler::dirs;
pub use self::errors::ClientError;
// pub use self::network_event::{NetworkEvent, NetworkRx, NetworkTx};
pub use self::utils::logging;
pub use qp2p::Config as QuicP2pConfig;

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
