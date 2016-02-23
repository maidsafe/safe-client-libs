// Copyright 2015 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use client::Client;
use xor_name::XorName;
use errors::CoreError;
use sodiumoxide::crypto::sign;
use maidsafe_utilities::serialisation::{serialise, deserialise};
use routing::{StructuredData, ImmutableData, ImmutableDataType, Data, DataRequest};
use structured_data_operations::{DataFitResult, check_if_data_can_fit_in_structured_data};

/// Create the StructuredData to manage versioned data.
pub fn create(client: &Client,
              version_name_to_store: XorName,
              tag_type: u64,
              identifier: XorName,
              version: u64,
              owner_keys: Vec<sign::PublicKey>,
              prev_owner_keys: Vec<sign::PublicKey>,
              private_signing_key: &sign::SecretKey)
              -> Result<StructuredData, CoreError> {
    create_impl(client,
                &vec![version_name_to_store],
                tag_type,
                identifier,
                version,
                owner_keys,
                prev_owner_keys,
                private_signing_key)
}

/// Get the complete version list
pub fn get_all_versions(client: &mut Client,
                        struct_data: &StructuredData)
                        -> Result<Vec<XorName>, CoreError> {
    let immut_data = try!(get_immutable_data(client, struct_data));
    Ok(try!(deserialise(&immut_data.value())))
}

/// Append a new version
pub fn append_version(client: &mut Client,
                      struct_data: StructuredData,
                      version_to_append: XorName,
                      private_signing_key: &sign::SecretKey)
                      -> Result<StructuredData, CoreError> {
    // let immut_data = try!(get_immutable_data(mut client, struct_data));
    // client.delete(immut_data);
    let mut versions = try!(get_all_versions(client, &struct_data));
    versions.push(version_to_append);
    create_impl(client,
                &versions,
                struct_data.get_type_tag(),
                struct_data.get_identifier().clone(),
                struct_data.get_version() + 1,
                struct_data.get_owner_keys().clone(),
                struct_data.get_previous_owner_keys().clone(),
                private_signing_key)
}

fn create_impl(client: &::client::Client,
               version_names_to_store: &Vec<XorName>,
               tag_type: u64,
               identifier: XorName,
               version: u64,
               owner_keys: Vec<sign::PublicKey>,
               prev_owner_keys: Vec<sign::PublicKey>,
               private_signing_key: &sign::SecretKey)
               -> Result<StructuredData, CoreError> {
    let immutable_data = ImmutableData::new(ImmutableDataType::Normal,
                                            try!(serialise(version_names_to_store)));
    let name_of_immutable_data = immutable_data.name();

    let encoded_name = try!(serialise(&name_of_immutable_data));

    match try!(check_if_data_can_fit_in_structured_data(&encoded_name,
                                                        owner_keys.clone(),
                                                        prev_owner_keys.clone())) {
        DataFitResult::DataFits => {
            let data = Data::Immutable(immutable_data);
            try!(client.put(data, None));

            Ok(try!(StructuredData::new(tag_type,
                                        identifier,
                                        version,
                                        encoded_name,
                                        owner_keys,
                                        prev_owner_keys,
                                        Some(private_signing_key))))
        }
        _ => Err(CoreError::StructuredDataHeaderSizeProhibitive),
    }
}

fn get_immutable_data(client: &mut Client,
                      struct_data: &StructuredData)
                      -> Result<ImmutableData, CoreError> {
    let name = try!(deserialise(&struct_data.get_data()));
    let response_getter = try!(client.get(DataRequest::Immutable(name,
                                                                     ImmutableDataType::Normal),
                                          None));
    let data = try!(response_getter.get());
    match data {
        Data::Immutable(immutable_data) => Ok(immutable_data),
        _ => Err(CoreError::ReceivedUnexpectedData),
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use xor_name::XorName;

    const TAG_ID: u64 = ::MAIDSAFE_TAG + 1001;

    #[test]
    fn save_and_retrieve_immutable_data() {
        let mut client = unwrap_result!(::utility::test_utils::get_client());

        let id = XorName::new(unwrap_result!(::utility::generate_random_array_u8_64()));
        let owners = ::utility::test_utils::generate_public_keys(1);
        let prev_owners = Vec::new();
        let ref secret_key = ::utility::test_utils::generate_secret_keys(1)[0];

        let version_0 = XorName::new(unwrap_result!(::utility::generate_random_array_u8_64()));

        let mut structured_data_result = create(&client,
                                                version_0.clone(),
                                                TAG_ID,
                                                id,
                                                0,
                                                owners,
                                                prev_owners,
                                                secret_key);

        let mut structured_data = unwrap_result!(structured_data_result);
        let mut versions_res = get_all_versions(&mut client, &structured_data);
        let mut versions = unwrap_result!(versions_res);
        assert_eq!(versions.len(), 1);

        let version_1 = XorName::new(unwrap_result!(::utility::generate_random_array_u8_64()));

        structured_data_result = append_version(&mut client,
                                                structured_data,
                                                version_1.clone(),
                                                secret_key);
        structured_data = unwrap_result!(structured_data_result);
        versions_res = get_all_versions(&mut client, &structured_data);
        versions = unwrap_result!(versions_res);
        assert_eq!(versions.len(), 2);

        assert_eq!(versions[0], version_0);
        assert_eq!(versions[1], version_1);
    }
}
