// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::client::{Client, MDataInfo};
use crate::errors::CoreError;
use futures::Future;
use crate::nfs::{NfsError, NfsFuture};
use routing::{ClientError, MutableData, PermissionSet, User, Value};
use std::collections::BTreeMap;
use crate::utils::FutureExt;

/// Create a new directory based on the provided `MDataInfo`.
pub fn create_dir(
    client: &impl Client,
    dir: &MDataInfo,
    contents: BTreeMap<Vec<u8>, Value>,
    perms: BTreeMap<User, PermissionSet>,
) -> Box<NfsFuture<()>> {
    let pub_key = fry!(
        client
            .owner_key()
            .ok_or_else(|| NfsError::Unexpected("Owner key not found".to_string()))
    );
    let owners = btree_set![pub_key];
    let dir_md = fry!(
        MutableData::new(dir.name, dir.type_tag, perms, contents, owners).map_err(CoreError::from)
    );
    client
        .put_mdata(dir_md)
        .or_else(move |err| {
            match err {
                // This dir has been already created
                CoreError::RoutingClientError(ClientError::DataExists) => Ok(()),
                e => Err(e),
            }
        }).map_err(NfsError::from)
        .into_box()
}
