// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::client::{Client, MDataInfo};
use crate::crypto::shared_secretbox;
use crate::errors::CoreError;
use crate::nfs::{File, Mode, NfsError, Reader, Writer};
use crate::self_encryption_storage::SelfEncryptionStorage;

use bincode::{deserialize, serialize};
use log::trace;
use safe_nd::{Error as SndError, MDataSeqEntryActions};
use serde::{Deserialize, Serialize};

/// Enum specifying which version should be used in places where a version is required.
#[derive(Copy, Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum Version {
    /// Query the network for the next version.
    GetNext,
    /// Use the specified version.
    Custom(u64),
}

/// Insert the file into the directory.
pub async fn insert<S>(
    client: impl Client,
    parent: MDataInfo,
    name: S,
    file: &File,
) -> Result<(), NfsError>
where
    S: AsRef<str>,
{
    let name = name.as_ref();
    trace!("Inserting file with name '{}'", name);

    let encoded = serialize(&file)?;

    let key = parent.enc_entry_key(name.as_bytes())?;
    let value = parent.enc_entry_value(&encoded)?;

    client
        .mutate_seq_mdata_entries(
            parent.name(),
            parent.type_tag(),
            MDataSeqEntryActions::new().ins(key, value, 0),
        )
        .await
        .map_err(From::from)
}

/// Get a file and its version from the directory.
pub async fn fetch<S>(
    client: impl Client,
    parent: MDataInfo,
    name: S,
) -> Result<(u64, File), NfsError>
where
    S: AsRef<str>,
{
    let key = parent.enc_entry_key(name.as_ref().as_bytes())?;

    let value = client
        .get_seq_mdata_value(parent.name(), parent.type_tag(), key)
        .await?;

    let plaintext = parent.decrypt(&value.data)?;
    let file = deserialize(&plaintext)?;
    Ok((value.version, file))
}

/// Return a Reader for reading the file contents.
pub async fn read<C: Client>(
    client: C,
    file: &File,
    encryption_key: Option<shared_secretbox::Key>,
) -> Result<Reader<C>, NfsError> {
    trace!("Reading file {:?}", file);
    Reader::new(
        client.clone(),
        SelfEncryptionStorage::new(client, file.published()),
        file,
        encryption_key,
    )
    .await
}

/// Delete a file from the directory.
///
/// If `version` is `Version::GetNext`, the current version is first retrieved from the network, and
/// that version incremented by one is then used as the actual version.
// Allow pass by value for consistency with other functions.
#[allow(clippy::needless_pass_by_value)]
pub async fn delete<S>(
    client: impl Client,
    parent: MDataInfo,
    name: S,
    published: bool,
    version: Version,
) -> Result<u64, NfsError>
where
    S: AsRef<str>,
{
    let name = name.as_ref();
    let name2 = name.to_owned();
    let client2 = client.clone();
    let client3 = client.clone();
    let parent2 = parent.clone();
    trace!("Deleting file with name {}.", name);

    let key = parent.enc_entry_key(name.as_bytes())?;

    let new_version = match version {
        Version::GetNext => {
            let value = client
                .get_seq_mdata_value(parent.name(), parent.type_tag(), key.clone())
                .await?;
            value.version + 1
        }
        Version::Custom(version) => version,
    };
    // version_fut
    if !published {
        let (_, file) = fetch(client, parent2, name2).await?;
        client2.del_unpub_idata(*file.data_map_name()).await?;
    }
    client3
        .mutate_seq_mdata_entries(
            parent.name(),
            parent.type_tag(),
            MDataSeqEntryActions::new().del(key, new_version),
        )
        .await?;

    Ok(new_version)
}

/// Update the file.
///
/// If `version` is `Version::GetNext`, the current version is first retrieved from the network, and
/// that version incremented by one is then used as the actual version.
pub async fn update<S>(
    client: impl Client,
    parent: MDataInfo,
    name: S,
    file: &File,
    version: Version,
) -> Result<u64, NfsError>
where
    S: AsRef<str>,
{
    let name = name.as_ref();
    trace!("Updating file with name '{}'", name);

    let client2 = client.clone();

    let encoded = serialize(&file)?;

    let key = parent.enc_entry_key(name.as_bytes())?;
    let content = parent.enc_entry_value(&encoded)?;

    let version = match version {
        Version::GetNext => {
            let value = client
                .get_seq_mdata_value(parent.name(), parent.type_tag(), key.clone())
                .await?;
            value.version + 1
        }
        Version::Custom(version) => version,
    };

    client2
        .mutate_seq_mdata_entries(
            parent.name(),
            parent.type_tag(),
            MDataSeqEntryActions::new().update(key, content, version),
        )
        .await?;

    Ok(version)
}

/// Helper function to update content of a file in a directory. A Writer
/// object is returned, through which the data for the file can be written to
/// the network. The file is actually saved in the directory listing only after
/// `writer.close()` is invoked.
pub async fn write<C: Client>(
    client: C,
    file: File,
    mode: Mode,
    encryption_key: Option<shared_secretbox::Key>,
) -> Result<Writer<C>, NfsError> {
    trace!("Creating a writer for a file");

    Writer::new(
        &client.clone(),
        SelfEncryptionStorage::new(client, file.published()),
        file,
        mode,
        encryption_key,
    )
    .await
}

// This is different from `impl From<CoreError> for NfsError`, because it maps
// `NoSuchEntry` to `FileNotFound`.
// TODO:  consider performing such conversion directly in the mentioned `impl From`.
fn convert_error(err: CoreError) -> NfsError {
    match err {
        CoreError::DataError(SndError::NoSuchEntry) => NfsError::FileNotFound,
        _ => NfsError::from(err),
    }
}
