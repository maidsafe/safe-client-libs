// Copyright 2015 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

/// Module for File struct
pub mod file;
/// Errors
pub mod errors;
/// Helper for directory_listing and File for NFS Low level API
pub mod helper;
/// Directory and File Metadata
pub mod metadata;
/// Module for directory related structs
pub mod directory;

/// Root directory name
pub const ROOT_DIRECTORY_NAME: &'static str = "USER_ROOT";
/// Configuration directory Name stored in the session packet
pub const CONFIGURATION_DIRECTORY_NAME: &'static str = "CONFIGURATION_ROOT";
/// Tag representing the Versioned Directory Listing
pub const VERSIONED_DIRECTORY_LISTING_TAG: u64 = ::core::CLIENT_STRUCTURED_DATA_TAG + 100;
/// Tag representing the Versioned Directory Listing
pub const UNVERSIONED_DIRECTORY_LISTING_TAG: u64 = VERSIONED_DIRECTORY_LISTING_TAG + 1;

/// AccessLevel indicates whether the container is Private or Public shared
#[derive(RustcEncodable, RustcDecodable, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Debug)]
pub enum AccessLevel {
    /// Private Directory where the directory is encrypted with users private keys
    Private,
    /// Public Directory where the directory is not encrypted and anyone can read the contents of it
    Public,
}
