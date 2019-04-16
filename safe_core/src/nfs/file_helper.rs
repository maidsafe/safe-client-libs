// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use client::{Client, MDataInfo};
use crypto::shared_secretbox;
use errors::CoreError;
use futures::{Future, IntoFuture};
use maidsafe_utilities::serialisation::{deserialise, serialise};
use nfs::{File, Mode, NfsError, NfsFuture, Reader, Writer};
use routing::{ClientError, EntryActions};
use self_encryption_storage::SelfEncryptionStorage;
use utils::FutureExt;

/// Enum specifying which version should be used in places where a version is required.
#[derive(Copy, Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum Version {
    /// Query the network for the next version.
    GetNext,
    /// Use the specified version.
    Custom(u64),
}

/// Insert the file into the directory.
pub fn insert<S>(client: impl Client, parent: MDataInfo, name: S, file: &File) -> Box<NfsFuture<()>>
where
    S: AsRef<str>,
{
    let name = name.as_ref();
    trace!("Inserting file with name '{}'", name);

    serialise(&file)
        .map_err(From::from)
        .and_then(|encoded| {
            let key = parent.enc_entry_key(name.as_bytes())?;
            let value = parent.enc_entry_value(&encoded)?;

            Ok((key, value))
        })
        .into_future()
        .and_then(move |(key, value)| {
            client.mutate_mdata_entries(
                parent.name,
                parent.type_tag,
                EntryActions::new().ins(key, value, 0).into(),
            )
        })
        .map_err(From::from)
        .into_box()
}

/// Get a file from the directory.
pub fn fetch<S>(client: impl Client, parent: MDataInfo, name: S) -> Box<NfsFuture<(u64, File)>>
where
    S: AsRef<str>,
{
    parent
        .enc_entry_key(name.as_ref().as_bytes())
        .into_future()
        .and_then(move |key| {
            client
                .get_mdata_value(parent.name, parent.type_tag, key)
                .map(move |value| (value, parent))
        })
        .and_then(move |(value, parent)| {
            let plaintext = parent.decrypt(&value.content)?;
            let file = deserialise(&plaintext)?;
            Ok((value.entry_version, file))
        })
        .map_err(convert_error)
        .into_box()
}

/// Return a Reader for reading the file contents.
pub fn read<C: Client>(
    client: C,
    file: &File,
    encryption_key: Option<shared_secretbox::Key>,
) -> Box<NfsFuture<Reader<C>>> {
    trace!("Reading file {:?}", file);
    Reader::new(
        client.clone(),
        SelfEncryptionStorage::new(client),
        file,
        encryption_key,
    )
}

/// Delete a file from the directory.
///
/// If `version` is `Version::GetNext`, the current version is first retrieved from the network, and
/// that version incremented by one is then used as the actual version.
// Allow pass by value for consistency with other functions.
#[allow(unknown_lints)]
#[allow(clippy::needless_pass_by_value)]
pub fn delete<S>(
    client: impl Client,
    parent: MDataInfo,
    name: S,
    version: Version,
) -> Box<NfsFuture<u64>>
where
    S: AsRef<str>,
{
    let name = name.as_ref();
    trace!("Deleting file with name {}.", name);

    let key = fry!(parent.enc_entry_key(name.as_bytes()));

    let version_fut = match version {
        Version::GetNext => client
            .get_mdata_value(parent.name, parent.type_tag, key.clone())
            .map(move |value| (value.entry_version + 1))
            .into_box(),
        Version::Custom(version) => ok!(version),
    }
    .map_err(NfsError::from);

    version_fut
        .and_then(move |version| {
            client
                .mutate_mdata_entries(
                    parent.name,
                    parent.type_tag,
                    EntryActions::new().del(key, version).into(),
                )
                .map(move |()| version)
                .map_err(convert_error)
        })
        .into_box()
}

/// Update the file.
///
/// If `version` is `Version::GetNext`, the current version is first retrieved from the network, and
/// that version incremented by one is then used as the actual version.
pub fn update<S>(
    client: impl Client,
    parent: MDataInfo,
    name: S,
    file: &File,
    version: Version,
) -> Box<NfsFuture<u64>>
where
    S: AsRef<str>,
{
    let name = name.as_ref();
    trace!("Updating file with name '{}'", name);

    let client2 = client.clone();

    serialise(&file)
        .map_err(From::from)
        .and_then(|encoded| {
            let key = parent.enc_entry_key(name.as_bytes())?;
            let content = parent.enc_entry_value(&encoded)?;

            Ok((key, content))
        })
        .into_future()
        .and_then(move |(key, content)| match version {
            Version::GetNext => client
                .get_mdata_value(parent.name, parent.type_tag, key.clone())
                .map(move |value| (key, content, value.entry_version + 1, parent))
                .into_box(),
            Version::Custom(version) => ok!((key, content, version, parent)),
        })
        .and_then(move |(key, content, version, parent)| {
            client2
                .mutate_mdata_entries(
                    parent.name,
                    parent.type_tag,
                    EntryActions::new().update(key, content, version).into(),
                )
                .map(move |()| version)
        })
        .map_err(convert_error)
        .into_box()
}

/// Helper function to update content of a file in a directory. A Writer
/// object is returned, through which the data for the file can be written to
/// the network. The file is actually saved in the directory listing only after
/// `writer.close()` is invoked.
pub fn write<C: Client>(
    client: C,
    file: File,
    mode: Mode,
    encryption_key: Option<shared_secretbox::Key>,
) -> Box<NfsFuture<Writer<C>>> {
    trace!("Creating a writer for a file");

    Writer::new(
        &client.clone(),
        SelfEncryptionStorage::new(client),
        file,
        mode,
        encryption_key,
    )
}

// This is different from `impl From<CoreError> for NfsError`, because it maps
// `NoSuchEntry` to `FileNotFound`.
// TODO:  consider performing such conversion directly in the mentioned `impl From`.
fn convert_error(err: CoreError) -> NfsError {
    match err {
        CoreError::RoutingClientError(ClientError::NoSuchEntry) => NfsError::FileNotFound,
        _ => NfsError::from(err),
    }
}
