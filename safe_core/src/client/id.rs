// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use safe_nd::{AppFullId, ClientFullId, PublicId, Signature};
use std::sync::Arc;

/// An enum representing the Full Id variants for a Client or App
#[derive(Clone)]
pub enum SafeKey {
    /// Represents an application authorised by a client.
    App(Arc<AppFullId>),
    /// Represents a network client.
    Client(Arc<ClientFullId>),
}

impl SafeKey {
    /// Create a client full ID.
    pub fn client(full_id: ClientFullId) -> Self {
        SafeKey::Client(Arc::new(full_id))
    }

    /// Create an app full ID.
    pub fn app(full_id: AppFullId) -> Self {
        SafeKey::App(Arc::new(full_id))
    }

    /// Sign a given message using the App / Client full id as required.
    pub fn sign(&self, msg: &[u8]) -> Signature {
        match self {
            SafeKey::App(app_full_id) => app_full_id.sign(msg),
            SafeKey::Client(client_full_id) => client_full_id.sign(msg),
        }
    }

    /// Return a corresponding public ID.
    pub fn public_id(&self) -> PublicId {
        match self {
            SafeKey::App(app_full_id) => PublicId::App(app_full_id.public_id().clone()),
            SafeKey::Client(client_full_id) => PublicId::Client(client_full_id.public_id().clone()),
        }
    }
}
