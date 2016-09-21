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


use core::SelfEncryptionStorage;
use core::client::Client;
use core::errors::CoreError;
use core::structured_data_operations::{DataFitResult, check_if_data_can_fit_in_structured_data};
use core::utility;
use maidsafe_utilities::serialisation::{deserialise, serialise};
use routing::{Data, DataIdentifier, ImmutableData, StructuredData, XorName};
use rust_sodium::crypto::{secretbox, sign};
use self_encryption::{DataMap, SelfEncryptor};
use std::sync::{Arc, Mutex};

/// Create the StructuredData to manage versioned data.
#[cfg_attr(feature="clippy", allow(too_many_arguments))]
pub fn create(client: Arc<Mutex<Client>>,
              type_tag: u64,
              name: XorName,
              data: Vec<u8>,
              owner_keys: Vec<sign::PublicKey>,
              signing_key: &sign::SecretKey,
              encryption_key: Option<&secretbox::Key>)
              -> Result<StructuredData, CoreError> {
    trace!("Creating versioned StructuredData.");

    let version_name = try!(put_data(client.clone(), data, encryption_key));
    let encoded_version_names_name = try!(put_version_names(client.clone(),
                                                            owner_keys.clone(),
                                                            vec![],
                                                            &[version_name]));

    Ok(try!(StructuredData::new(type_tag,
                                name,
                                0,
                                encoded_version_names_name,
                                owner_keys,
                                vec![],
                                Some(signing_key))))
}

/// Update the versioned structured data by creating new version.
pub fn update(client: Arc<Mutex<Client>>,
              struct_data: StructuredData,
              data: Vec<u8>,
              signing_key: &sign::SecretKey,
              encryption_key: Option<&secretbox::Key>,
              increment_version_number: bool)
              -> Result<StructuredData, CoreError> {
    trace!("Appending version to versioned StructuredData.");

    let mut version_names = try!(get_all_version_names(client.clone(), &struct_data));
    let new_version_name = try!(put_data(client.clone(), data, encryption_key));
    version_names.push(new_version_name);

    let encoded_version_names_name = try!(put_version_names(client.clone(),
                                                            struct_data.get_owner_keys().clone(),
                                                            struct_data.get_previous_owner_keys().clone(),
                                                            &version_names));


    let new_version_number = struct_data.get_version() +
                             if increment_version_number { 1 } else { 0 };

    Ok(try!(StructuredData::new(struct_data.get_type_tag(),
                                *struct_data.name(),
                                new_version_number,
                                encoded_version_names_name,
                                struct_data.get_owner_keys().clone(),
                                struct_data.get_previous_owner_keys().clone(),
                                Some(signing_key))))
}

/// Retrieve the data with the given version name.
pub fn get_data(client: Arc<Mutex<Client>>,
                name: &XorName,
                encryption_key: Option<&secretbox::Key>)
                -> Result<Vec<u8>, CoreError> {
    let request = DataIdentifier::Immutable(*name);
    let resp_getter = try!(unwrap!(client.lock()).get(request, None));
    let data = match try!(resp_getter.get()) {
        Data::Immutable(data) => data,
        _ => return Err(CoreError::ReceivedUnexpectedData),
    };
    let data = data.value();

    if let Some(secret_key) = encryption_key {
        let data_map = try!(utility::symmetric_decrypt(data, secret_key));
        let data_map = try!(deserialise(&data_map));
        let mut storage = SelfEncryptionStorage::new(client.clone());
        let mut self_encryptor = try!(SelfEncryptor::new(&mut storage, data_map));
        let length = self_encryptor.len();
        Ok(try!(self_encryptor.read(0, length)))
    } else {
        Ok(data.clone())
    }
}

// Save the data into the netowork as immutable data and return its name.
fn put_data(client: Arc<Mutex<Client>>,
            data: Vec<u8>,
            encryption_key: Option<&secretbox::Key>)
                -> Result<XorName, CoreError> {
    let data = match encryption_key {
        Some(secret_key) => {
            let mut storage = SelfEncryptionStorage::new(client.clone());
            let mut self_encryptor = try!(SelfEncryptor::new(&mut storage, DataMap::None));
            try!(self_encryptor.write(&data, 0));
            let data = try!(self_encryptor.close());
            let data = try!(serialise(&data));
            try!(utility::symmetric_encrypt(&data, secret_key))
        }
        None => data,
    };

    let immut_data = ImmutableData::new(data);
    let name = *immut_data.name();

    try!(Client::put_recover(client, Data::Immutable(immut_data), None));
    Ok(name)
}

// Save the version names into the network as immutable data and return its
// serialised name.
fn put_version_names(client: Arc<Mutex<Client>>,
                     curr_owner_keys: Vec<sign::PublicKey>,
                     prev_owner_keys: Vec<sign::PublicKey>,
                     version_names: &[XorName])
                     -> Result<Vec<u8>, CoreError> {
    let immut_data = ImmutableData::new(try!(serialise(&version_names)));
    let name = *immut_data.name();
    let encoded_name = try!(serialise(&name));

    match try!(check_if_data_can_fit_in_structured_data(&encoded_name,
                                                        curr_owner_keys,
                                                        prev_owner_keys)) {
        DataFitResult::DataFits => {
            try!(Client::put_recover(client, Data::Immutable(immut_data), None));
            Ok(encoded_name)
        }
        _ => Err(CoreError::StructuredDataHeaderSizeProhibitive),
    }
}

/// Get the complete version list
pub fn get_all_version_names(client: Arc<Mutex<Client>>,
                             struct_data: &StructuredData)
                             -> Result<Vec<XorName>, CoreError> {
    trace!("Getting all versions of versioned StructuredData.");

    let name = try!(deserialise(&struct_data.get_data()));
    let resp_getter = try!(unwrap!(client.lock()).get(DataIdentifier::Immutable(name), None));
    let data = match try!(resp_getter.get()) {
        Data::Immutable(data) => data,
        _ => return Err(CoreError::ReceivedUnexpectedData),
    };

    Ok(try!(deserialise(&data.value())))
}

#[cfg(test)]
mod test {
    use core;
    use core::utility;
    use core::utility::test_utils;
    use rand;
    use std::sync::{Arc, Mutex};
    use super::*;

    const TAG: u64 = core::MAIDSAFE_TAG + 1001;

    #[test]
    fn create_update_retrieve() {
        let client = unwrap!(test_utils::get_client());
        let client = Arc::new(Mutex::new(client));

        let name = rand::random();
        let owner_keys = test_utils::generate_public_keys(1);
        let secret_key = &test_utils::generate_secret_keys(1)[0];

        let content0 = unwrap!(utility::generate_random_vector(10));
        let struct_data = unwrap!(create(client.clone(),
                                         TAG,
                                         name,
                                         content0.clone(),
                                         owner_keys,
                                         secret_key,
                                         None));

        let version_names = unwrap!(get_all_version_names(client.clone(), &struct_data));
        assert_eq!(version_names.len(), 1);
        assert_eq!(unwrap!(get_data(client.clone(), &version_names[0], None)),
                   content0);

        let content1 = unwrap!(utility::generate_random_vector(10));
        let struct_data = unwrap!(update(client.clone(),
                                         struct_data,
                                         content1.clone(),
                                         secret_key,
                                         None,
                                         true));

        let version_names = unwrap!(get_all_version_names(client.clone(), &struct_data));
        assert_eq!(version_names.len(), 2);
        assert_eq!(unwrap!(get_data(client.clone(), &version_names[0], None)),
                   content0);
        assert_eq!(unwrap!(get_data(client.clone(), &version_names[1], None)),
                   content1);
    }
}
