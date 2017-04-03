// Copyright 2015 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement.  This, along with the Licenses can be
// found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use core::client::Client;
use core::errors::CoreError;
use core::structured_data_operations::{DataFitResult, check_if_data_can_fit_in_structured_data};
use maidsafe_utilities::serialisation::{deserialise, serialise};
use routing::{Data, DataIdentifier, ImmutableData, StructuredData, XorName};
use rust_sodium::crypto::sign;
use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

/// All fields updated whenever a version is appended/removed
#[derive(RustcEncodable, RustcDecodable, Debug)]
struct VersionsInfo {
    /// Contains an ID for Vec<XorName> of versions
    ptr_to_versions: XorName,
    /// Total number of available versions
    total_versions: u64,
    /// Contains an ID for the current version
    ptr_to_current_version: XorName,
}

/// Create the `StructuredData` to manage versioned data.
pub fn create(client: Arc<Mutex<Client>>,
              version_name_to_store: XorName,
              tag_type: u64,
              name: XorName,
              version: u64,
              owners: BTreeSet<sign::PublicKey>)
              -> Result<StructuredData, CoreError> {
    trace!("Creating versioned StructuredData.");

    create_impl(client,
                &[version_name_to_store],
                tag_type,
                name,
                version,
                owners)
}

/// Get the complete version list
pub fn get_all_versions(client: Arc<Mutex<Client>>,
                        struct_data: &StructuredData)
                        -> Result<Vec<XorName>, CoreError> {
    trace!("Getting all versions of versioned StructuredData.");

    let immut_data = get_immutable_data(client, struct_data)?;
    Ok(deserialise(immut_data.value())?)
}

/// Append a new version
pub fn append_version(client: Arc<Mutex<Client>>,
                      struct_data: StructuredData,
                      version_to_append: XorName,
                      _private_signing_key: &sign::SecretKey,
                      increment_version_number: bool)
                      -> Result<StructuredData, CoreError> {
    trace!("Appending version to versioned StructuredData.");

    // let immut_data = try!(get_immutable_data(mut client, struct_data));
    // client.delete(immut_data);
    let mut versions = get_all_versions(client.clone(), &struct_data)?;
    versions.push(version_to_append);

    let new_version_number = struct_data.get_version() +
                             if increment_version_number { 1 } else { 0 };

    create_impl(client,
                &versions,
                struct_data.get_type_tag(),
                *struct_data.name(),
                new_version_number,
                struct_data.get_owners().clone())
}

fn create_impl(client: Arc<Mutex<Client>>,
               version_names_to_store: &[XorName],
               tag_type: u64,
               name: XorName,
               version: u64,
               owners: BTreeSet<sign::PublicKey>)
               -> Result<StructuredData, CoreError> {
    let immutable_data = ImmutableData::new(serialise(&version_names_to_store)?);
    let name_of_immutable_data = *immutable_data.name();

    let total_versions = version_names_to_store.len();
    let versions_info = VersionsInfo {
        ptr_to_versions: name_of_immutable_data,
        total_versions: total_versions as u64,
        ptr_to_current_version: version_names_to_store[total_versions - 1],
    };

    let encoded = serialise(&versions_info)?;

    match check_if_data_can_fit_in_structured_data(&encoded, owners.clone())? {
        DataFitResult::DataFits => {
            trace!("Name of ImmutableData containing versions fits in StructuredData.");

            let data = Data::Immutable(immutable_data);
            Client::put_recover(client, data, None)?;

            Ok(StructuredData::new(tag_type, name, version, encoded, owners)?)
        }
        _ => {
            trace!("Name of ImmutableData containing versions does not fit in StructuredData.");
            Err(CoreError::StructuredDataHeaderSizeProhibitive)
        }
    }
}

/// Get a total number of versions in versioned `StructuredData`
pub fn version_count(sd: &StructuredData) -> Result<u64, CoreError> {
    if sd.get_type_tag() != ::VERSIONED_STRUCT_DATA_TYPE_TAG {
        return Err(CoreError::InvalidStructuredDataTypeTag);
    }
    Ok(deserialise::<VersionsInfo>(sd.get_data())
           ?
           .total_versions)
}

/// Get the current version of versioned `StructuredData`
pub fn current_version(sd: &StructuredData) -> Result<XorName, CoreError> {
    if sd.get_type_tag() != ::VERSIONED_STRUCT_DATA_TYPE_TAG {
        return Err(CoreError::InvalidStructuredDataTypeTag);
    }
    Ok(deserialise::<VersionsInfo>(sd.get_data())
           ?
           .ptr_to_current_version)
}

fn get_immutable_data(client: Arc<Mutex<Client>>,
                      struct_data: &StructuredData)
                      -> Result<ImmutableData, CoreError> {
    let name = deserialise::<VersionsInfo>(struct_data.get_data())
        ?
        .ptr_to_versions;
    let resp_getter = unwrap!(client.lock()).get(DataIdentifier::Immutable(name), None)?;
    let data = resp_getter.get()?;
    match data {
        Data::Immutable(immutable_data) => Ok(immutable_data),
        _ => Err(CoreError::ReceivedUnexpectedData),
    }
}

#[cfg(test)]
mod test {

    use super::*;
    use core::utility;
    use rand;
    use routing::XorName;

    use std::sync::{Arc, Mutex};

    #[test]
    fn save_and_retrieve_immutable_data() {
        let client = unwrap!(utility::test_utils::get_client());
        let client = Arc::new(Mutex::new(client));

        let id: XorName = rand::random();
        let owners = utility::test_utils::generate_public_keys(1);
        let secret_key = &utility::test_utils::generate_secret_keys(1)[0];

        let version_0: XorName = rand::random();

        let mut structured_data_result = create(client.clone(),
                                                version_0,
                                                ::VERSIONED_STRUCT_DATA_TYPE_TAG,
                                                id,
                                                0,
                                                owners);

        let mut structured_data = unwrap!(structured_data_result);
        let mut versions_res = get_all_versions(client.clone(), &structured_data);
        let mut versions = unwrap!(versions_res);
        assert_eq!(versions.len(), 1);
        assert_eq!(unwrap!(version_count(&structured_data)), 1);
        assert_eq!(unwrap!(current_version(&structured_data)), version_0);

        let version_1: XorName = rand::random();

        structured_data_result =
            append_version(client.clone(), structured_data, version_1, secret_key, true);
        structured_data = unwrap!(structured_data_result);
        versions_res = get_all_versions(client, &structured_data);
        versions = unwrap!(versions_res);
        assert_eq!(versions.len(), 2);
        assert_eq!(unwrap!(version_count(&structured_data)), 2);

        assert_eq!(versions[0], version_0);
        assert_eq!(versions[1], version_1);
        assert_eq!(unwrap!(current_version(&structured_data)), version_1);
    }
}
