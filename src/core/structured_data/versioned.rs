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

use core::{Client, CoreError, CoreFuture, immutable_data};
use core::futures::FutureExt;
use futures::Future;
use maidsafe_utilities::serialisation::{deserialise, serialise};
use routing::{Data, ImmutableData, StructuredData, XorName};
use rust_sodium::crypto::{secretbox, sign};
use super::DataFitResult;

// Information about versioned data.
#[derive(RustcEncodable, RustcDecodable, Debug)]
struct VersionsInfo {
    // Name of the immutable data containing list of names of all versions
    version_list_name: XorName,
    // Number of versions
    num_versions: u64,
    // Name of the current version
    current_version_name: XorName,
}

/// Create new versioned structured data (version 0)
pub fn create(client: &Client,
              type_tag: u64,
              id: XorName,
              value: Vec<u8>,
              owner_keys: Vec<sign::PublicKey>,
              sig_sk: sign::SecretKey,
              encryption_key: Option<secretbox::Key>)
              -> Box<CoreFuture<StructuredData>> {
    let client2 = client.clone();

    immutable_data::create(client, value, encryption_key)
        .and_then(move |curr_version_data| {
            append_version(client2,
                           type_tag,
                           id,
                           0,
                           curr_version_data,
                           vec![],
                           owner_keys,
                           vec![],
                           sig_sk)
        })
        .into_box()
}

/// Update the versioned structured data by creating a new version.
pub fn update(client: &Client,
              data: StructuredData,
              value: Vec<u8>,
              curr_owner_keys: Vec<sign::PublicKey>,
              sig_sk: sign::SecretKey,
              encryption_key: Option<secretbox::Key>)
              -> Box<CoreFuture<StructuredData>> {
    let client2 = client.clone();

    let future1 = immutable_data::create(client, value, encryption_key);
    let future2 = extract_all_version_names(client, &data);

    future1.join(future2)
        .and_then(move |(curr_version_data, version_list)| {
            let prev_owner_keys = if curr_owner_keys != *data.get_owner_keys() {
                data.get_owner_keys().clone()
            } else {
                data.get_previous_owner_keys().clone()
            };

            append_version(client2,
                           data.get_type_tag(),
                           *data.name(),
                           data.get_version() + 1,
                           curr_version_data,
                           version_list,
                           curr_owner_keys,
                           prev_owner_keys,
                           sig_sk)
        })
        .into_box()
}

/// Extract the value for the given version.
pub fn extract_value(client: &Client,
                     data: &StructuredData,
                     version: u64,
                     decryption_key: Option<secretbox::Key>)
                     -> Box<CoreFuture<Vec<u8>>> {
    if data.is_deleted() {
        return ok!(Vec::new());
    }

    let client2 = client.clone();

    extract_all_version_names(client, data)
        .and_then(move |names| {
            names.get(version as usize).cloned()
                 // TODO: add proper error variant for this
                 .ok_or(CoreError::Unexpected("invalid version".to_owned()))
        })
        .and_then(move |name| immutable_data::get_value(&client2, &name, decryption_key))
        .into_box()
}

/// Extract the value for the current (latest) version.
pub fn extract_current_value(client: &Client,
                             data: &StructuredData,
                             decryption_key: Option<secretbox::Key>)
                             -> Box<CoreFuture<Vec<u8>>> {
    if data.is_deleted() {
        return ok!(Vec::new());
    }

    let name = fry!(current_version_name(data));
    immutable_data::get_value(client, &name, decryption_key)
}

/// Extract the complete list of names of versions of versioned StructuredData.
pub fn extract_all_version_names(client: &Client,
                                 data: &StructuredData)
                                 -> Box<CoreFuture<Vec<XorName>>> {
    let info = fry!(deserialise::<VersionsInfo>(&data.get_data()));
    immutable_data::get_value(client, &info.version_list_name, None)
        .and_then(|encoded_list| Ok(deserialise(&encoded_list)?))
        .into_box()
}

/// Get the total number of versions in versioned StructuredData
pub fn version_count(data: &StructuredData) -> Result<u64, CoreError> {
    if data.get_type_tag() != ::VERSIONED_STRUCT_DATA_TYPE_TAG {
        return Err(CoreError::InvalidStructuredDataTypeTag);
    }

    let info = deserialise::<VersionsInfo>(&data.get_data())?;
    Ok(info.num_versions)
}

/// Get the name of the current version of versioned StructuredData
pub fn current_version_name(data: &StructuredData) -> Result<XorName, CoreError> {
    if data.get_type_tag() != ::VERSIONED_STRUCT_DATA_TYPE_TAG {
        return Err(CoreError::InvalidStructuredDataTypeTag);
    }

    let info = deserialise::<VersionsInfo>(&data.get_data())?;
    Ok(info.current_version_name)
}

// Append new version to versioned StructuredData
fn append_version(client: Client,
                  type_tag: u64,
                  id: XorName,
                  version: u64,
                  curr_version_data: ImmutableData,
                  mut version_list: Vec<XorName>,
                  curr_owner_keys: Vec<sign::PublicKey>,
                  prev_owner_keys: Vec<sign::PublicKey>,
                  sig_sk: sign::SecretKey)
                  -> Box<CoreFuture<StructuredData>> {
    let client2 = client.clone();

    version_list.push(*curr_version_data.name());
    let num_versions = version_list.len() as u64;
    let encoded_version_list = fry!(serialise(&version_list));

    immutable_data::create(&client, encoded_version_list, None)
        .map(move |version_list_data| (version_list_data, curr_version_data))
        .and_then(move |(version_list_data, curr_version_data)| {
            let info = VersionsInfo {
                version_list_name: *version_list_data.name(),
                num_versions: num_versions,
                current_version_name: *curr_version_data.name(),
            };

            let structured_data = build(type_tag,
                                        id,
                                        version,
                                        info,
                                        curr_owner_keys,
                                        prev_owner_keys,
                                        sig_sk)?;

            Ok((structured_data, version_list_data, curr_version_data))
        })
        .and_then(move |(structured_data, version_list_data, curr_version_data)| {
            let put1 = client2.put(Data::Immutable(version_list_data), None);
            let put2 = client2.put(Data::Immutable(curr_version_data), None);
            put1.join(put2).map(move |_| structured_data)
        })
        .into_box()
}

// Create StructuredData containing the given VersionsInfo.
fn build(type_tag: u64,
         id: XorName,
         version: u64,
         info: VersionsInfo,
         curr_owner_keys: Vec<sign::PublicKey>,
         prev_owner_keys: Vec<sign::PublicKey>,
         sig_sk: sign::SecretKey)
         -> Result<StructuredData, CoreError> {
    let encoded = serialise(&info)?;

    match super::can_data_fit(&encoded, curr_owner_keys.clone(), prev_owner_keys.clone())? {

        DataFitResult::DataFits => {
            Ok(StructuredData::new(type_tag,
                                   id,
                                   version,
                                   encoded,
                                   curr_owner_keys,
                                   prev_owner_keys,
                                   Some(&sig_sk))?)
        }
        _ => {
            trace!("VersionsInfo does not fit in StructuredData.");
            Err(CoreError::StructuredDataHeaderSizeProhibitive)
        }
    }
}

#[cfg(test)]
mod tests {
    use core::utility;
    use core::utility::test_utils::{self, finish, random_client};
    use futures::Future;
    use rand;
    use super::*;

    #[test]
    fn create_update_retrieve() {
        let data_name = rand::random();

        let value0 = unwrap!(utility::generate_random_vector(1024));
        let value1 = unwrap!(utility::generate_random_vector(1024));
        let value1_2 = value1.clone();

        let owner_keys = test_utils::get_max_sized_public_keys(1);
        let sign_key = test_utils::get_max_sized_secret_keys(1).remove(0);

        random_client(move |client| {
            let client2 = client.clone();
            let client3 = client.clone();
            let client4 = client.clone();

            create(client,
                   ::VERSIONED_STRUCT_DATA_TYPE_TAG,
                   data_name,
                   value0.clone(),
                   owner_keys.clone(),
                   sign_key.clone(),
                   None)
                .then(move |res| {
                    let data = unwrap!(res);
                    assert_eq!(unwrap!(version_count(&data)), 1);
                    extract_current_value(&client2, &data, None).map(move |value| (data, value))
                })
                .then(move |res| {
                    let (data, value_after) = unwrap!(res);
                    assert_eq!(value_after, value0);

                    update(&client3, data, value1, owner_keys, sign_key, None)
                })
                .then(move |res| {
                    let data = unwrap!(res);
                    assert_eq!(unwrap!(version_count(&data)), 2);
                    extract_current_value(&client4, &data, None)
                })
                .then(move |res| {
                    let value_after = unwrap!(res);
                    assert_eq!(value_after, value1_2);
                    finish()
                })
        })
    }
}
