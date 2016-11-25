// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net
// Commercial License, version 1.0 or later, or (2) The General Public License
// (GPL), version 3, depending on which licence you accepted on initial access
// to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project
// generally, you agree to be bound by the terms of the MaidSafe Contributor
// Agreement, version 1.0.
// This, along with the Licenses can be found in the root directory of this
// project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network
// Software distributed under the GPL Licence is distributed on an "AS IS"
// BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
//
// Please review the Licences for the specific language governing permissions
// and limitations relating to use of the SAFE Network Software.

// use futures::Future;
// use tokio_core::channel;

/// Helpers to work with futures.
// #[macro_use]
// pub mod futures;
/// Utility functions
pub mod utility;
/// Implements the Self Encryption storage trait
pub mod self_encryption_storage;
/// Helper functions to handle `ImmutableData` related operations
// pub mod immutable_data;
/// Helper functions to handle `StructuredData` related operations
// pub mod structured_data;

// pub use self::client::Client;
pub use self::client::{ClientKeys, Dir};
// pub use self::core_el::{CoreMsg, CoreMsgRx, CoreMsgTx, TailFuture, run};
pub use self::errors::{CORE_ERROR_START_RANGE, CoreError};

// pub use self::event::NetworkEvent;
// pub use self::futures::FutureExt;
pub use self::self_encryption_storage::SelfEncryptionStorageError;

/// Future trait returned from core operations.
// pub type CoreFuture<T> = Future<Item = T, Error = CoreError>;
/// `NetworkEvent` receiver stream.
// pub type NetworkRx = channel::Receiver<NetworkEvent>;
/// `NetworkEvent` transmitter.
// pub type NetworkTx = channel::Sender<NetworkEvent>;
/// All Maidsafe tagging should positive-offset from this
pub const MAIDSAFE_TAG: u64 = 5483_000;
/// All `StructuredData` tagging should positive-offset from this if the
/// operation needs to go through this crate
// pub const CLIENT_STRUCTURED_DATA_TAG: u64 = 15000;

mod client;
// mod core_el;
mod errors;
// mod event;
