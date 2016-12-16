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

/// `FileHelper` provides functions for CRUD on file
pub mod file_helper;

mod errors;
mod data_map;
mod dir;
mod file;
mod std_dirs;
mod reader;
mod writer;

use futures::Future;
pub use self::dir::create_dir;
pub use self::errors::NfsError;
pub use self::file::File;
pub use self::reader::Reader;
pub use self::std_dirs::create_std_dirs;
pub use self::writer::{Mode, Writer};

/// Helper type for futures that can result in `NfsError`
pub type NfsFuture<T> = Future<Item = T, Error = NfsError>;

lazy_static!{
/// Default Directories to be created at registration
    pub static ref DEFAULT_PRIVATE_DIRS: Vec<&'static str> = vec!["_documents",
            "_downloads", "_music", "_videos", "_publicNames"];
    ///publicly accessible default directories to be created upon registration
    pub static ref DEFAULT_PUBLIC_DIRS: Vec<&'static str> = vec!["_public"];
}
