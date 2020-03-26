// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

//! Permissions utilities

use safe_nd::MDataPermissionSet;
use serde_derive::{Deserialize, Serialize};

/// Object representing a (User, Permission Set) pair.
#[derive(Clone, Default, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct UserPermissionSet {
    /// User's permission set.
    pub perm_set: MDataPermissionSet,
}
