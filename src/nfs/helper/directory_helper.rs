// Copyright 2015 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences".to_string()).
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

use std::sync::{Arc, Mutex};

use nfs::errors::NfsError;
use nfs::directory_listing::DirectoryListing;
use routing::XorName;
use maidsafe_utilities::serialisation::{serialise, deserialise};
use nfs::metadata::directory_key::DirectoryKey;
use routing::{ImmutableData, StructuredData, Data, DataIdentifier};
use core::client::Client;
use core::errors::CoreError;
use core::structured_data_operations::{unversioned, versioned};
use nfs::AccessLevel;

/// DirectoryHelper provides helper functions to perform Operations on Directory
pub struct DirectoryHelper {
    client: Arc<Mutex<Client>>,
}

impl DirectoryHelper {
    /// Create a new DirectoryHelper instance
    pub fn new(client: Arc<Mutex<Client>>) -> DirectoryHelper {
        DirectoryHelper { client: client }
    }

    /// Creates a Directory in the network.
    /// When a directory is created and parent_directory is passed as a parameter.
    /// Then the parent directory is updated.
    /// If the parent_directory passed has a parent, then the parent_directory's parent
    /// is also updated and the same is returned
    /// Returns (created_directory, Option<parent_directory's parent>)
    pub fn create(&self,
                  directory_name: String,
                  tag_type: u64,
                  user_metadata: Vec<u8>,
                  versioned: bool,
                  access_level: AccessLevel,
                  parent_directory: Option<&mut DirectoryListing>)
                  -> Result<(DirectoryListing, Option<DirectoryListing>), NfsError> {

        if parent_directory.iter()
            .next()
            .and_then(|dir| dir.find_sub_directory(&directory_name))
            .is_some() {
            return Err(NfsError::DirectoryAlreadyExistsWithSameName);
        }

        let directory =
            try!(DirectoryListing::new(directory_name,
                                       tag_type,
                                       user_metadata,
                                       versioned,
                                       access_level,
                                       parent_directory.iter()
                                           .next()
                                           .map(|directory| directory.get_key().clone())));

        let structured_data = try!(self.save_directory_listing(&directory));
        debug!("Posting PUT request to network to save structured data for directory ...");
        try!(unwrap_result!(self.client.lock()).put_recover(Data::Structured(structured_data), None));
        if let Some(mut parent_directory) = parent_directory {
            parent_directory.upsert_sub_directory(directory.get_metadata().clone());
            Ok((directory, try!(self.update(parent_directory))))
        } else {
            Ok((directory, None))
        }
    }

    /// Deletes a sub directory
    /// The parent_directory's parent is also updated if present
    /// Returns Option<parent_directory's parent>
    pub fn delete(&self,
                  parent_directory: &mut DirectoryListing,
                  directory_to_delete: &String)
                  -> Result<Option<DirectoryListing>, NfsError> {
        try!(parent_directory.remove_sub_directory(directory_to_delete));
        parent_directory.get_mut_metadata().set_modified_time(::time::now_utc());
        self.update(&parent_directory)
    }

    /// Updates an existing DirectoryListing in the network.
    /// The parent_directory's parent is also updated and the same is returned
    /// Returns Option<parent_directory's parent>
    pub fn update(&self,
                  directory: &DirectoryListing)
                  -> Result<Option<DirectoryListing>, NfsError> {
        try!(self.update_directory_listing(directory));
        if let Some(parent_dir_key) = directory.get_metadata().get_parent_dir_key() {
            let mut parent_directory = try!(self.get(&parent_dir_key));
            parent_directory.upsert_sub_directory(directory.get_metadata().clone());
            try!(self.update_directory_listing(&parent_directory));
            Ok(Some(parent_directory))
        } else {
            Ok(None)
        }
    }

    /// Return the versions of the directory
    pub fn get_versions(&self,
                        directory_id: &XorName,
                        type_tag: u64)
                        -> Result<Vec<XorName>, NfsError> {
        let structured_data = try!(self.get_structured_data(directory_id, type_tag));
        Ok(try!(versioned::get_all_versions(&mut *unwrap_result!(self.client.lock()),
                                            &structured_data)))
    }

    /// Return the DirectoryListing for the specified version
    pub fn get_by_version(&self,
                          directory_id: &XorName,
                          access_level: &AccessLevel,
                          version: XorName)
                          -> Result<DirectoryListing, NfsError> {
        let immutable_data = try!(self.get_immutable_data(version));
        match *access_level {
            AccessLevel::Private => {
                DirectoryListing::decrypt(self.client.clone(),
                                          directory_id,
                                          immutable_data.value().clone())
            }
            AccessLevel::Public => Ok(try!(deserialise(immutable_data.value()))),
        }
    }

    /// Return the DirectoryListing for the latest version
    pub fn get(&self, directory_key: &DirectoryKey) -> Result<DirectoryListing, NfsError> {
        let directory_id = directory_key.get_id();
        let type_tag = directory_key.get_type_tag();
        let versioned = directory_key.is_versioned();
        let access_level = directory_key.get_access_level();

        if versioned {
            let versions = try!(self.get_versions(directory_id, type_tag));
            let latest_version = try!(versions.last()
                .ok_or(NfsError::from("Programming Error - Please report this as a Bug.")));
            self.get_by_version(directory_id, access_level, *latest_version)
        } else {
            let private_key;
            let secret_key;
            let nonce;

            let encryption_keys = match *access_level {
                AccessLevel::Private => {
                    private_key = try!(unwrap_result!(self.client.lock())
                            .get_public_encryption_key())
                        .clone();
                    secret_key = try!(unwrap_result!(self.client.lock())
                            .get_secret_encryption_key())
                        .clone();
                    nonce = DirectoryListing::generate_nonce(directory_id);

                    Some((&private_key, &secret_key, &nonce))
                }
                AccessLevel::Public => None,
            };

            let structured_data = try!(self.get_structured_data(directory_id, type_tag));
            let serialised_directory_listing =
                try!(unversioned::get_data(self.client.clone(), &structured_data, encryption_keys));
            Ok(try!(deserialise(&serialised_directory_listing)))
        }
    }

    /// Returns the Root Directory
    pub fn get_user_root_directory_listing(&self) -> Result<DirectoryListing, NfsError> {
        let root_directory_id = unwrap_result!(self.client.lock())
            .get_user_root_directory_id()
            .map(|id| id.clone());
        match root_directory_id {
            Some(id) => {
                debug!("Retrieving directory at id {:?} ...", id);
                self.get(&DirectoryKey::new(id,
                                            ::nfs::UNVERSIONED_DIRECTORY_LISTING_TAG,
                                            false,
                                            AccessLevel::Private))
            }
            None => {
                debug!("Retrieving root directory ...");
                let (created_directory, _) =
                    try!(self.create(::nfs::ROOT_DIRECTORY_NAME.to_string(),
                                     ::nfs::UNVERSIONED_DIRECTORY_LISTING_TAG,
                                     Vec::new(),
                                     false,
                                     AccessLevel::Private,
                                     None));
                try!(unwrap_result!(self.client.lock())
                    .set_user_root_directory_id(created_directory.get_key().get_id().clone()));
                Ok(created_directory)
            }
        }
    }

    /// Returns the Configuration DirectoryListing from the configuration root folder
    /// Creates the directory or the root or both if it doesn't find one.
    pub fn get_configuration_directory_listing(&self,
                                               directory_name: String)
                                               -> Result<DirectoryListing, NfsError> {
        let config_dir_id = unwrap_result!(self.client.lock())
            .get_configuration_root_directory_id()
            .map(|id| id.clone());
        let mut config_directory_listing = match config_dir_id {
            Some(id) => {
                debug!("Retrieving root configuration directory at id {:?} ...", id);
                try!(self.get(&DirectoryKey::new(id,
                                                 ::nfs::UNVERSIONED_DIRECTORY_LISTING_TAG,
                                                 false,
                                                 AccessLevel::Private)))
            }
            None => {
                debug!("Creating root configuration directory ...");
                let (created_directory, _) =
                    try!(self.create(::nfs::CONFIGURATION_DIRECTORY_NAME.to_string(),
                                     ::nfs::UNVERSIONED_DIRECTORY_LISTING_TAG,
                                     Vec::new(),
                                     false,
                                     AccessLevel::Private,
                                     None));
                try!(unwrap_result!(self.client.lock())
                    .set_configuration_root_directory_id(created_directory.get_key()
                        .get_id()
                        .clone()));
                created_directory
            }
        };
        match config_directory_listing.get_sub_directories()
            .iter()
            .position(|metadata| *metadata.get_name() == directory_name) {
            Some(index) => {
                debug!("Retrieving {:?} specific configuration directory ...",
                       directory_name);
                let directory_key = config_directory_listing.get_sub_directories()[index].get_key();
                Ok(try!(self.get(&directory_key)))
            }
            None => {
                debug!("Creating new directory {:?} in root configuration directory ...",
                       directory_name);
                let (directory, _) = try!(self.create(directory_name,
                                                      ::nfs::UNVERSIONED_DIRECTORY_LISTING_TAG,
                                                      Vec::new(),
                                                      false,
                                                      AccessLevel::Private,
                                                      Some(&mut config_directory_listing)));
                Ok(directory)
            }
        }
    }

    /// Creates a StructuredData in the Network
    /// The StructuredData is created based on the version and AccessLevel of the DirectoryListing
    fn save_directory_listing(&self,
                              directory: &DirectoryListing)
                              -> Result<StructuredData, NfsError> {
        let signing_key = try!(unwrap_result!(self.client.lock()).get_secret_signing_key()).clone();
        let owner_key = try!(unwrap_result!(self.client.lock()).get_public_signing_key()).clone();
        let access_level = directory.get_key().get_access_level();
        let versioned = directory.get_key().is_versioned();

        if versioned {
            let serialised_data = match *access_level {
                AccessLevel::Private => try!(directory.encrypt(self.client.clone())),
                AccessLevel::Public => try!(serialise(&directory)),
            };
            let version = try!(self.save_as_immutable_data(serialised_data));
            Ok(try!(versioned::create(&mut *unwrap_result!(self.client.lock()),
                                      version,
                                      directory.get_key().get_type_tag(),
                                      directory.get_key().get_id().clone(),
                                      0,
                                      vec![owner_key],
                                      Vec::new(),
                                      &signing_key)))
        } else {
            let private_key = try!(unwrap_result!(self.client.lock()).get_public_encryption_key())
                .clone();
            let secret_key = try!(unwrap_result!(self.client.lock()).get_secret_encryption_key())
                .clone();
            let nonce = DirectoryListing::generate_nonce(directory.get_key().get_id());
            let serialised_data = try!(serialise(&directory));

            let encryption_keys = match *access_level {
                AccessLevel::Private => Some((&private_key, &secret_key, &nonce)),
                AccessLevel::Public => None,
            };
            Ok(try!(unversioned::create(self.client.clone(),
                                        directory.get_key().get_type_tag(),
                                        directory.get_key().get_id().clone(),
                                        0,
                                        serialised_data,
                                        vec![owner_key.clone()],
                                        Vec::new(),
                                        &signing_key,
                                        encryption_keys)))
        }
    }

    fn update_directory_listing(&self, directory: &DirectoryListing) -> Result<(), NfsError> {
        let structured_data = try!(self.get_structured_data(directory.get_key().get_id(),
                                                            directory.get_key().get_type_tag()));

        let signing_key = try!(unwrap_result!(self.client.lock()).get_secret_signing_key()).clone();
        let owner_key = try!(unwrap_result!(self.client.lock()).get_public_signing_key()).clone();
        let access_level = directory.get_key().get_access_level();
        let versioned = directory.get_key().is_versioned();

        let updated_structured_data = if versioned {
            let serialised_data = match *access_level {
                AccessLevel::Private => try!(directory.encrypt(self.client.clone())),
                AccessLevel::Public => try!(serialise(&directory)),
            };
            let version = try!(self.save_as_immutable_data(serialised_data));
            try!(versioned::append_version(&mut *unwrap_result!(self.client.lock()),
                                           structured_data,
                                           version,
                                           &signing_key))
        } else {
            let private_key = try!(unwrap_result!(self.client.lock()).get_public_encryption_key())
                .clone();
            let secret_key = try!(unwrap_result!(self.client.lock()).get_secret_encryption_key())
                .clone();
            let nonce = DirectoryListing::generate_nonce(directory.get_key().get_id());
            let serialised_data = try!(serialise(&directory));

            let encryption_keys = match *access_level {
                AccessLevel::Private => Some((&private_key, &secret_key, &nonce)),
                AccessLevel::Public => None,
            };
            try!(unversioned::create(self.client.clone(),
                                     directory.get_key().get_type_tag(),
                                     directory.get_key().get_id().clone(),
                                     structured_data.get_version() + 1,
                                     serialised_data,
                                     vec![owner_key.clone()],
                                     Vec::new(),
                                     &signing_key,
                                     encryption_keys))
        };
        debug!("Posting updated structured data to the network ...");
        try!(try!(unwrap_result!(self.client.lock())
                .post(Data::Structured(updated_structured_data), None))
            .get());
        Ok(())
    }

    /// Saves the data as ImmutableData in the network and returns the name
    fn save_as_immutable_data(&self, data: Vec<u8>) -> Result<XorName, NfsError> {
        let immutable_data = ImmutableData::new(data);
        let name = immutable_data.name();
        debug!("Posting PUT request to save immutable data to the network ...");
        try!(unwrap_result!(self.client.lock()).put_recover(Data::Immutable(immutable_data), None));
        Ok(name)
    }

    /// Get StructuredData from the Network
    fn get_structured_data(&self, id: &XorName, type_tag: u64) -> Result<StructuredData, NfsError> {
        let request = DataIdentifier::Structured(id.clone(), type_tag);
        debug!("Getting structured data from the network ...");
        let response_getter = try!(unwrap_result!(self.client.lock()).get(request, None));
        match try!(response_getter.get()) {
            Data::Structured(structured_data) => Ok(structured_data),
            _ => Err(NfsError::from(CoreError::ReceivedUnexpectedData)),
        }
    }

    /// Get ImmutableData from the Network
    fn get_immutable_data(&self, id: XorName) -> Result<ImmutableData, NfsError> {
        let request = DataIdentifier::Immutable(id);
        debug!("Getting immutable data from the network ...");
        let response_getter = try!(unwrap_result!(self.client.lock()).get(request, None));
        match try!(response_getter.get()) {
            Data::Immutable(immutable_data) => Ok(immutable_data),
            _ => Err(NfsError::from(CoreError::ReceivedUnexpectedData)),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::sync::{Arc, Mutex};
    use core::utility::test_utils;
    use nfs::AccessLevel;

    #[test]
    fn create_dir_listing() {
        let test_client = unwrap_result!(test_utils::get_client());
        let client = Arc::new(Mutex::new(test_client));
        let dir_helper = DirectoryHelper::new(client.clone());
        // Create a Directory
        let (mut directory, grand_parent) = unwrap_result!(dir_helper.create("DirName".to_string(),
                    ::nfs::VERSIONED_DIRECTORY_LISTING_TAG,
                    Vec::new(),
                    true,
                    AccessLevel::Private,
                    None));
        assert!(grand_parent.is_none());
        assert_eq!(directory,
                   unwrap_result!(dir_helper.get(directory.get_key())));
        // Create a Child directory and update the parent_directory
        let (mut child_directory, grand_parent) =
            unwrap_result!(dir_helper.create("Child".to_string(),
                                             ::nfs::VERSIONED_DIRECTORY_LISTING_TAG,
                                             Vec::new(),
                                             true,
                                             AccessLevel::Private,
                                             Some(&mut directory)));
        assert!(grand_parent.is_none());
        // Assert whether parent is updated
        let parent = unwrap_result!(dir_helper.get(directory.get_key()));
        assert!(parent.find_sub_directory(child_directory.get_metadata().get_name()).is_some());

        let (grand_child_directory, grand_parent) =
            unwrap_result!(dir_helper.create("Grand Child".to_string(),
                                             ::nfs::VERSIONED_DIRECTORY_LISTING_TAG,
                                             Vec::new(),
                                             true,
                                             AccessLevel::Private,
                                             Some(&mut child_directory)));
        assert!(dir_helper.create("Grand Child".to_string(),
                    ::nfs::VERSIONED_DIRECTORY_LISTING_TAG,
                    Vec::new(),
                    true,
                    AccessLevel::Private,
                    Some(&mut child_directory))
            .is_err());
        assert!(grand_parent.is_some());
        let grand_parent = unwrap_option!(grand_parent, "Grand Parent Should be updated");
        assert_eq!(*grand_parent.get_metadata().get_name(),
                   *directory.get_metadata().get_name());
        assert_eq!(*grand_parent.get_metadata().get_modified_time(),
                   *grand_child_directory.get_metadata().get_modified_time());
    }

    #[test]
    fn create_versioned_public_directory() {
        let public_directory;
        {
            let test_client = unwrap_result!(test_utils::get_client());
            let client = Arc::new(Mutex::new(test_client));
            let dir_helper = DirectoryHelper::new(client.clone());
            let (directory, _) = unwrap_result!(dir_helper.create("PublicDirectory".to_string(),
                        ::nfs::VERSIONED_DIRECTORY_LISTING_TAG,
                        vec![2u8, 10],
                        true,
                        AccessLevel::Public,
                        None));
            public_directory = directory;
        }
        {
            let test_client = unwrap_result!(test_utils::get_client());
            let client = Arc::new(Mutex::new(test_client));
            let dir_helper = DirectoryHelper::new(client.clone());
            let retrieved_public_directory =
                unwrap_result!(dir_helper.get(public_directory.get_key()));
            assert_eq!(retrieved_public_directory, public_directory);
        }
    }

    #[test]
    fn create_unversioned_public_directory() {
        let public_directory;
        {
            let test_client = unwrap_result!(test_utils::get_client());
            let client = Arc::new(Mutex::new(test_client));
            let dir_helper = DirectoryHelper::new(client.clone());
            let (directory, _) = unwrap_result!(dir_helper.create("PublicDirectory".to_string(),
                        ::nfs::UNVERSIONED_DIRECTORY_LISTING_TAG,
                        vec![2u8, 10],
                        false,
                        AccessLevel::Public,
                        None));
            public_directory = directory;
        }
        {
            let test_client = unwrap_result!(test_utils::get_client());
            let client = Arc::new(Mutex::new(test_client));
            let dir_helper = DirectoryHelper::new(client.clone());
            let retrieved_public_directory =
                unwrap_result!(dir_helper.get(public_directory.get_key()));
            assert_eq!(retrieved_public_directory, public_directory);
        }
    }

    #[test]
    fn user_root_configuration() {
        let test_client = unwrap_result!(test_utils::get_client());
        let client = Arc::new(Mutex::new(test_client));
        let dir_helper = DirectoryHelper::new(client.clone());

        let mut root_dir = unwrap_result!(dir_helper.get_user_root_directory_listing());
        let (created_dir, _) = unwrap_result!(dir_helper.create("DirName".to_string(),
                    ::nfs::VERSIONED_DIRECTORY_LISTING_TAG,
                    Vec::new(),
                    true,
                    AccessLevel::Private,
                    Some(&mut root_dir)));
        let root_dir = unwrap_result!(dir_helper.get_user_root_directory_listing());
        assert!(root_dir.find_sub_directory(created_dir.get_metadata().get_name()).is_some());
    }

    #[test]
    fn configuration_directory() {
        let test_client = unwrap_result!(test_utils::get_client());
        let client = Arc::new(Mutex::new(test_client));
        let dir_helper = DirectoryHelper::new(client.clone());
        let config_dir =
            unwrap_result!(dir_helper.get_configuration_directory_listing("DNS".to_string()));
        assert_eq!(config_dir.get_metadata().get_name().clone(),
                   "DNS".to_string());
        let id = config_dir.get_key().get_id().clone();
        let config_dir =
            unwrap_result!(dir_helper.get_configuration_directory_listing("DNS".to_string()));
        assert_eq!(config_dir.get_key().get_id().clone(), id);
    }

    #[test]
    fn update_and_versioning() {
        let test_client = unwrap_result!(test_utils::get_client());
        let client = Arc::new(Mutex::new(test_client));
        let dir_helper = DirectoryHelper::new(client.clone());

        let (mut dir_listing, _) = unwrap_result!(dir_helper.create("DirName2".to_string(),
                    ::nfs::VERSIONED_DIRECTORY_LISTING_TAG,
                    Vec::new(),
                    true,
                    AccessLevel::Private,
                    None));

        let mut versions = unwrap_result!(dir_helper.get_versions(dir_listing.get_key().get_id(),
                                                                  dir_listing.get_key()
                                                                      .get_type_tag()));
        assert_eq!(versions.len(), 1);

        dir_listing.get_mut_metadata().set_name("NewName".to_string());
        assert!(dir_helper.update(&dir_listing).is_ok());

        versions = unwrap_result!(dir_helper.get_versions(dir_listing.get_key().get_id(),
                                                          dir_listing.get_key().get_type_tag()));
        assert_eq!(versions.len(), 2);

        let rxd_dir_listing =
            unwrap_result!(dir_helper.get_by_version(dir_listing.get_key().get_id(),
                                                     dir_listing.get_key().get_access_level(),
                                                     versions[versions.len() - 1].clone()));
        assert_eq!(rxd_dir_listing, dir_listing);

        let rxd_dir_listing =
            unwrap_result!(dir_helper.get_by_version(dir_listing.get_key().get_id(),
                                                     dir_listing.get_key().get_access_level(),
                                                     versions[0].clone()));
        assert_eq!(*rxd_dir_listing.get_metadata().get_name(),
                   "DirName2".to_string());
    }

    #[test]
    fn delete_directory() {
        let test_client = unwrap_result!(test_utils::get_client());
        let client = Arc::new(Mutex::new(test_client));
        let dir_helper = DirectoryHelper::new(client.clone());
        // Create a Directory
        let (mut directory, grand_parent) = unwrap_result!(dir_helper.create("DirName".to_string(),
                    ::nfs::VERSIONED_DIRECTORY_LISTING_TAG,
                    Vec::new(),
                    true,
                    AccessLevel::Private,
                    None));
        assert!(grand_parent.is_none());
        assert_eq!(directory,
                   unwrap_result!(dir_helper.get(directory.get_key())));
        // Create a Child directory and update the parent_directory
        let (mut child_directory, grand_parent) =
            unwrap_result!(dir_helper.create("Child".to_string(),
                                             ::nfs::VERSIONED_DIRECTORY_LISTING_TAG,
                                             Vec::new(),
                                             true,
                                             AccessLevel::Private,
                                             Some(&mut directory)));
        assert!(grand_parent.is_none());
        // Assert whether parent is updated
        let parent = unwrap_result!(dir_helper.get(directory.get_key()));
        assert!(parent.find_sub_directory(child_directory.get_metadata().get_name()).is_some());

        let (grand_child_directory, grand_parent) =
            unwrap_result!(dir_helper.create("Grand Child".to_string(),
                                             ::nfs::VERSIONED_DIRECTORY_LISTING_TAG,
                                             Vec::new(),
                                             true,
                                             AccessLevel::Private,
                                             Some(&mut child_directory)));

        let _ = unwrap_option!(grand_parent, "Grand Parent Should be updated");

        let delete_result = unwrap_result!(dir_helper.delete(&mut child_directory,
                                                             grand_child_directory.get_metadata()
                                                                 .get_name()));
        let updated_grand_parent = unwrap_option!(delete_result,
                                                  "Parent directory should be returned");
        assert_eq!(*updated_grand_parent.get_metadata().get_id(),
                   *directory.get_metadata().get_id());

        let delete_result = unwrap_result!(dir_helper.delete(&mut directory,
                                                             child_directory.get_metadata()
                                                                 .get_name()));
        assert!(delete_result.is_none());
    }
}
