// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::client::{Client, MDataInfo};
use crate::errors::CoreError;
use crate::nfs::NfsError;
use log::trace;
use safe_nd::{Error as SndError, MDataPermissionSet, MDataSeqEntries, PublicKey, SeqMutableData};
use std::collections::BTreeMap;

/// Create a new directory based on the provided `MDataInfo`.
pub async fn create_directory(
    client: &(impl Client + Sync),
    dir: &MDataInfo,
    contents: MDataSeqEntries,
    perms: BTreeMap<PublicKey, MDataPermissionSet>,
) -> Result<(), NfsError> {
    let pub_key = client.owner_key().await;

    let dir_md =
        SeqMutableData::new_with_data(dir.name(), dir.type_tag(), contents, perms, pub_key);

    trace!("Creating new directory: {:?}", dir);
    client
        .clone()
        .put_seq_mutable_data(dir_md)
        .await
        .or_else(move |err| {
            trace!("Error: {:?}", err);
            match err {
                // This dir has been already created
                CoreError::DataError(SndError::DataExists) => Ok(()),
                e => Err(NfsError::from(e)),
            }
        })
}
