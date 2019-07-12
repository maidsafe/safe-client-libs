// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

pub mod vault;

mod account;
#[macro_use]
mod routing;
#[cfg(test)]
mod tests;

pub use self::account::{Account, CoinBalance, DEFAULT_MAX_MUTATIONS};
pub use self::routing::{NewFullId, RequestHookFn, Routing};

use ::routing::XorName;
use safe_nd::{ADataAddress, IDataAddress, MDataAddress};

/// Identifier for a data.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
pub enum DataId {
    /// Identifier of old mutable data.
    OldMutable { name: XorName, tag: u64 },
    /// Identifier of immutable data.
    Immutable(IDataAddress),
    /// Identifier of mutable data.
    Mutable(MDataAddress),
    /// Identifier of appendonly data.
    AppendOnly(ADataAddress),
}

impl DataId {
    /// Get name of this identifier.
    pub fn name(&self) -> &XorName {
        match *self {
            DataId::OldMutable { ref name, .. } => name,
            DataId::Immutable(ref address) => address.name(),
            DataId::Mutable(ref address) => address.name(),
            DataId::AppendOnly(ref address) => address.name(),
        }
    }
}
