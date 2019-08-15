// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

/// `FileHelper` provides functions for CRUD on file.
pub mod file_helper;

mod data_map;
mod dir;
mod errors;
mod file;
mod reader;
#[cfg(test)]
mod tests;
mod writer;

pub use self::dir::create_dir;
pub use self::errors::NfsError;
pub use self::file::File;
pub use self::reader::Reader;
pub use self::writer::{Mode, Writer};
use futures::Future;

/// Helper type for futures that can result in `NfsError`.
pub type NfsFuture<T> = dyn Future<Item = T, Error = NfsError>;
