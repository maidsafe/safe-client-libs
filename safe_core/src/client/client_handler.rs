// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::Client;
use crate::client::AuthActions;
use crate::errors::CoreError;
use crate::event_loop::CoreFuture;
use crate::utils::FutureExt;
use futures::future::{self, Loop};
use futures::Future;
use safe_nd::{AppPermissions, Error as SndError, PublicKey};

const MAX_ATTEMPTS: usize = 10;

///! Client Handler functionality

/// Insert key to Client Handler.
/// Covers the `InvalidSuccessor` error case (it should not fail if the key already exists).
pub fn ins_auth_key(
    client: &(impl Client + AuthActions),
    key: PublicKey,
    permissions: AppPermissions,
    version: u64,
) -> Box<CoreFuture<()>> {
    let state = (0, version);
    let client = client.clone();

    future::loop_fn(state, move |(attempts, version)| {
        client
            .ins_auth_key(key, permissions, version)
            .map(|_| Loop::Break(()))
            .or_else(move |error| match error {
                CoreError::DataError(SndError::InvalidSuccessor(current_version)) => {
                    if attempts < MAX_ATTEMPTS {
                        Ok(Loop::Continue((attempts + 1, current_version + 1)))
                    } else {
                        Err(error)
                    }
                }
                CoreError::RequestTimeout => {
                    if attempts < MAX_ATTEMPTS {
                        Ok(Loop::Continue((attempts + 1, version)))
                    } else {
                        Err(CoreError::RequestTimeout)
                    }
                }
                error => Err(error),
            })
    })
    .into_box()
}
