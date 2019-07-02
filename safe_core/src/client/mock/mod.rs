// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

pub mod vault;

mod account;
mod routing;
#[cfg(test)]
mod tests;

pub use self::account::{Account, CoinBalance, DEFAULT_MAX_MUTATIONS};
pub use self::routing::{NewFullId, RequestHookFn, Routing};

use ::routing::XorName;

/// Identifier for a data.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
pub enum DataId {
    /// Identifier of immutable data.
    Immutable(XorName),
    /// Identifier of mutable data.
    Mutable { name: XorName, tag: u64 },
    /// Identifier of appendonly data.
    AppendOnly { name: XorName, tag: u64 },
}

impl DataId {
    /// Get name of this identifier.
    pub fn name(&self) -> &XorName {
        match *self {
            DataId::Immutable(ref name) => name,
            DataId::Mutable { ref name, .. } => name,
            DataId::AppendOnly { ref name, .. } => name,
        }
    }
}
