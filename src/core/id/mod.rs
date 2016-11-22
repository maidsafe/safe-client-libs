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

/// Maid
pub mod id_type;
/// `PublicMaid`
pub mod public_id_type;
/// `AnMaid`
pub mod revocation_id_type;

pub use self::id_type::*;
pub use self::public_id_type::*;
pub use self::revocation_id_type::*;

/// Interface to `IdTypes`
pub trait IdTypeTags {
    /// returns tag type for revocation id type
    fn revocation_id_type_tag(&self) -> u64;
    /// returns tag type for id type
    fn id_type_tag(&self) -> u64;
    /// returns tag type for public id type
    fn public_id_type_tag(&self) -> u64;
}

/// Type tags for Maid type variants
pub struct MaidTypeTags;

/// Type tags for Maid type variants
pub struct MpidTypeTags;

impl IdTypeTags for MaidTypeTags {
    /// returns tag type for AnMaid type
    fn revocation_id_type_tag(&self) -> u64 {
        data_tags::AN_MAID_TAG
    }
    /// returns tag type for Maid type
    fn id_type_tag(&self) -> u64 {
        data_tags::MAID_TAG
    }
    /// returns tag type for PublicMaid type
    fn public_id_type_tag(&self) -> u64 {
        data_tags::PUBLIC_MAID_TAG
    }
}

impl IdTypeTags for MpidTypeTags {
    /// returns tag type for AnMpid type
    fn revocation_id_type_tag(&self) -> u64 {
        data_tags::AN_MPID_TAG
    }
    /// returns tag type for Mpid type
    fn id_type_tag(&self) -> u64 {
        data_tags::MPID_TAG
    }
    /// returns tag type for PublicMpid type
    fn public_id_type_tag(&self) -> u64 {
        data_tags::PUBLIC_MPID_TAG
    }
}

/// Random trait is used to generate random instances.  Used in the test mod
pub trait Random {
    /// Generates a random instance and returns the created random instance
    fn generate_random() -> Self;
}

/// All Maidsafe ID tags
#[allow(missing_docs)]
pub mod data_tags {
    use core;

    pub const MAIDSAFE_DATA_TAG: u64 = core::MAIDSAFE_TAG + 100;
    pub const AN_MPID_TAG: u64 = MAIDSAFE_DATA_TAG + 5;
    pub const AN_MAID_TAG: u64 = MAIDSAFE_DATA_TAG + 6;
    pub const MAID_TAG: u64 = MAIDSAFE_DATA_TAG + 7;
    pub const MPID_TAG: u64 = MAIDSAFE_DATA_TAG + 8;
    pub const PUBLIC_MAID_TAG: u64 = MAIDSAFE_DATA_TAG + 9;
    pub const PUBLIC_MPID_TAG: u64 = MAIDSAFE_DATA_TAG + 10;
}
