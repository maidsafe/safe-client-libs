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


use core::client::Client;
use core::errors::CoreError;
use core::structured_data_operations::{unversioned, versioned};
use maidsafe_utilities::serialisation::{deserialise, serialise};
use nfs::AccessLevel;
use nfs::directory::Directory;
use nfs::errors::NfsError;
use nfs::metadata::{DirectoryKey, DirectoryMetadata};
use rand::{OsRng, Rand};
use routing::{Data, DataIdentifier, StructuredData, XorName};
use rust_sodium::crypto::secretbox;
use std::sync::{Arc, Mutex};

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
                  type_tag: u64,
                  user_metadata: Vec<u8>,
                  versioned: bool,
                  access_level: AccessLevel,
                  parent_directory: Option<&mut Directory>)
                  -> Result<(Directory, Option<Directory>), NfsError> {
        trace!("Creating directory (versioned: {}) with name: {}",
               versioned,
               directory_name);

        if parent_directory.as_ref()
            .and_then(|dir| dir.find_sub_directory(&directory_name))
            .is_some() {
            return Err(NfsError::DirectoryAlreadyExistsWithSameName);
        }

        let mut rng = try!(OsRng::new().map_err(|e| NfsError::Unexpected(format!("{}", e))));
        let id = Rand::rand(&mut rng);

        let secret_key = match access_level {
            AccessLevel::Private => Some(secretbox::gen_key()),
            AccessLevel::Public => None,
        };

        let key = DirectoryKey::new(id, type_tag, versioned, secret_key);
        let metadata = DirectoryMetadata::new(directory_name, user_metadata);

        let directory = Directory::empty(key.clone(), metadata.clone());
        try!(self.create_directory(&directory));

        if let Some(mut parent_directory) = parent_directory {
            parent_directory.upsert_sub_directory(key, metadata);
            Ok((directory, try!(self.update(parent_directory))))
        } else {
            Ok((directory, None))
        }
    }

    /// Deletes a sub directory
    /// The parent_directory's parent is also updated if present
    /// Returns Option<parent_directory's parent>
    pub fn delete(&self,
                  parent_directory: &mut Directory,
                  directory_to_delete: &str)
                  -> Result<Option<Directory>, NfsError> {
        trace!("Deleting directory with name: {}", directory_to_delete);

        // TODO (Spandan) - Fetch and issue a DELETE on the removed directory.
        let _dir_meta = try!(parent_directory.remove_sub_directory(directory_to_delete));
        parent_directory.metadata_mut().set_modified_time(::time::now_utc());
        self.update(parent_directory)
    }

    /// Updates an existing DirectoryListing in the network.
    /// The parent_directory's parent is also updated and the same is returned
    /// Returns Option<parent_directory's parent>
    pub fn update(&self,
                  _directory: &Directory)
                  -> Result<Option<Directory>, NfsError> {
        trace!("Updating directory given the directory listing.");

        // TODO (adam): adapt this to symm. keys

        // try!(self.update_directory(directory));
        // if let Some(parent_dir_key) = directory.metadata().get_parent_dir_key() {
        //     let mut parent_directory = try!(self.get(&parent_dir_key));
        //     parent_directory.upsert_sub_directory(directory.metadata().clone());
        //     try!(self.update_directory(&parent_directory));
        //     Ok(Some(parent_directory))
        // } else {
        //     Ok(None)
        // }

        Ok(None)
    }

    /// Return the versions of the directory
    pub fn get_versions(&self,
                        directory_id: &XorName,
                        type_tag: u64)
                        -> Result<Vec<XorName>, NfsError> {
        trace!("Getting all versions of a versioned directory.");

        let structured_data = try!(self.get_structured_data(directory_id, type_tag));
        Ok(try!(versioned::get_all_version_names(self.client.clone(), &structured_data)))
    }

    /// Return the DirectoryListing for the specified version
    pub fn get_by_version(&self, directory_key: &DirectoryKey, version: &XorName)
                          -> Result<Directory, NfsError> {
        trace!("Getting a version of a versioned directory.");

        let encoded = try!(versioned::get_data(self.client.clone(),
                                               version,
                                               directory_key.secret_key()));
        let content = try!(deserialise(&encoded));

        Ok(Directory::with_content(directory_key.clone(), content))
    }

    /// Return the latest version of the Directory corresponding to the given key.
    pub fn get(&self, directory_key: &DirectoryKey) -> Result<Directory, NfsError> {
        if directory_key.versioned() {
            trace!("Getting the last version of a versioned directory listing.");

            let versions = try!(self.get_versions(directory_key.id(),
                                                  directory_key.type_tag()));
            let latest_version = try!(versions.last()
                .ok_or(NfsError::from("Programming Error - Please report this as a Bug.")));
            self.get_by_version(directory_key, latest_version)
        } else {
            trace!("Getting an unversioned directory listing.");

            let structured_data = try!(self.get_structured_data(directory_key.id(), directory_key.type_tag()));
            let encoded_content = try!(unversioned::get_data(self.client.clone(),
                                                             &structured_data,
                                                             directory_key.secret_key()));
            let content = try!(deserialise(&encoded_content));

            Ok(Directory::with_content(directory_key.clone(), content))
        }
    }

    /// Returns the Root Directory
    pub fn get_user_root_directory(&self) -> Result<Directory, NfsError> {
        trace!("Getting the user root directory listing.");

        let root_directory_id = unwrap!(self.client.lock())
            .get_user_root_dir()
            .cloned();
        match root_directory_id {
            Some((id, secret_key)) => {
                self.get(&DirectoryKey::new(id,
                                            ::nfs::UNVERSIONED_DIRECTORY_LISTING_TAG,
                                            false,
                                            Some(secret_key)))
            }
            None => {
                debug!("Root directory does not exist - creating one.");
                let (created_directory, _) =
                    try!(self.create(::nfs::ROOT_DIRECTORY_NAME.to_string(),
                                     ::nfs::UNVERSIONED_DIRECTORY_LISTING_TAG,
                                     Vec::new(),
                                     false,
                                     AccessLevel::Private,
                                     None));

                let id = *created_directory.key().id();
                let secret_key = unwrap!(created_directory.key().secret_key()).clone();

                try!(unwrap!(self.client.lock()).set_user_root_dir((id, secret_key)));
                Ok(created_directory)
            }
        }
    }

    /// Returns the Configuration Directory from the configuration root folder
    /// Creates the directory or the root or both if it doesn't find one.
    pub fn get_config_directory(&self, directory_name: String) -> Result<Directory, NfsError> {
        let mut config_root_dir = try!(self.get_config_root_directory());
        match self.get_sub_directory(&config_root_dir, &directory_name) {
            Ok(dir) => Ok(dir),
            Err(NfsError::DirectoryNotFound) => {
                debug!("Give configuration directory does not exist (inside the root \
                        configuration dir) - creating one.");

                let (directory, _) = try!(self.create(directory_name,
                                                      ::nfs::UNVERSIONED_DIRECTORY_LISTING_TAG,
                                                      Vec::new(),
                                                      false,
                                                      AccessLevel::Private,
                                                      Some(&mut config_root_dir)));
                Ok(directory)

            }
            Err(error) => Err(error),
        }
    }

    /// Returns the configuration root Directory.
    pub fn get_config_root_directory(&self) -> Result<Directory, NfsError> {
        trace!("Getting a configuration root directory");

        let root_dir = unwrap!(self.client.lock()).get_config_root_dir().cloned();
        match root_dir {
            Some((id, secret_key)) => {
                self.get(&DirectoryKey::new(id,
                                            ::nfs::UNVERSIONED_DIRECTORY_LISTING_TAG,
                                            false,
                                            Some(secret_key)))
            }
            None => {
                debug!("Configuartion Root directory does not exist - creating one.");
                let (created_directory, _) =
                    try!(self.create(::nfs::CONFIGURATION_DIRECTORY_NAME.to_string(),
                                     ::nfs::UNVERSIONED_DIRECTORY_LISTING_TAG,
                                     Vec::new(),
                                     false,
                                     AccessLevel::Private,
                                     None));

                let id = *created_directory.key().id();
                let secret_key = unwrap!(created_directory.key().secret_key()).clone();

                try!(unwrap!(self.client.lock()).set_config_root_dir((id, secret_key)));
                Ok(created_directory)
            }
        }
    }

    /// Return the name and parent Directory of the file or directory corresponding to
    /// the given path. The path is relative to the given root directory.
    pub fn get_name_and_parent(&self,
                               root_dir_key: &DirectoryKey,
                               path: &str)
                               -> Result<(String, Directory), NfsError> {
        let mut tokens = path.split(|ch| ch == '/')
                             .filter(|token| !token.is_empty())
                             .collect::<Vec<_>>();

        let name = tokens.pop()
                         .map(|s| s.to_owned())
                         .unwrap_or_else(String::new);

        let mut dir = try!(self.get(root_dir_key));

        for token in tokens {
            dir = try!(self.get_sub_directory(&dir, &token));
        }

        Ok((name, dir))
    }

    /// Return the Directory and its parent Directory corresponding to the given
    /// path. The path is relative to the given root directory.
    pub fn get_directory_and_parent(&self,
                                    root_dir_key: &DirectoryKey,
                                    path: &str)
                                    -> Result<(Directory, Directory), NfsError> {
        let (name, parent) = try!(self.get_name_and_parent(root_dir_key, path));
        let dir = try!(self.get_sub_directory(&parent, &name));

        Ok((dir, parent))
    }

    /// Get sub-directory with the given name of the given parent Directory.
    pub fn get_sub_directory(&self,
                             parent_directory: &Directory,
                             name: &str)
                             -> Result<Directory, NfsError> {
        self.get(try!(parent_directory.find_sub_directory(name)
                                      .map(|dir| dir.key())
                                      .ok_or(NfsError::DirectoryNotFound)))
    }

    // Creates a StructuredData in the Network
    // The StructuredData is created based on the version and AccessLevel of the Directory
    fn create_directory(&self, directory: &Directory) -> Result<(), NfsError> {
        let signing_key = try!(unwrap!(self.client.lock()).get_secret_signing_key()).clone();
        let owner_key = *try!(unwrap!(self.client.lock()).get_public_signing_key());
        let secret_key = directory.key().secret_key();
        let versioned = directory.key().versioned();

        let encoded_content = try!(serialise(directory.content()));

        let structured_data = if versioned {
            trace!("Converting directory listing to a versioned StructuredData.");
            try!(versioned::create(self.client.clone(),
                                   directory.key().type_tag(),
                                   directory.key().id().clone(),
                                   encoded_content,
                                   vec![owner_key],
                                   &signing_key,
                                   secret_key))
        } else {
            trace!("Converting directory listing to an unversioned StructuredData.");
            try!(unversioned::create(self.client.clone(),
                                     directory.key().type_tag(),
                                     directory.key().id().clone(),
                                     0,
                                     encoded_content,
                                     vec![owner_key],
                                     vec![],
                                     &signing_key,
                                     secret_key))
        };

        try!(Client::put_recover(self.client.clone(), Data::Structured(structured_data), None));
        Ok(())
    }

    // TODO (adam): un-unuse this
    #[allow(unused)]
    fn update_directory(&self, directory: &Directory) -> Result<(), NfsError> {
        let structured_data = try!(self.get_structured_data(directory.key().id(),
                                                            directory.key().type_tag()));

        let signing_key = try!(unwrap!(self.client.lock()).get_secret_signing_key()).clone();
        let owner_key = *try!(unwrap!(self.client.lock()).get_public_signing_key());
        let secret_key = directory.key().secret_key();
        let versioned = directory.key().versioned();

        let encoded_content = try!(serialise(directory.content()));

        let updated_structured_data = if versioned {
            trace!("Updating directory listing with a new one (will convert DL to a versioned \
                    StructuredData).");
            try!(versioned::update(self.client.clone(),
                                   structured_data,
                                   encoded_content,
                                   &signing_key,
                                   secret_key,
                                   true))
        } else {
            trace!("Updating directory listing with a new one (will convert DL to an unversioned \
                    StructuredData).");
            try!(unversioned::create(self.client.clone(),
                                     directory.key().type_tag(),
                                     directory.key().id().clone(),
                                     structured_data.get_version() + 1,
                                     encoded_content,
                                     vec![owner_key],
                                     vec![],
                                     &signing_key,
                                     secret_key))
        };
        debug!("Posting updated structured data to the network ...");
        try!(try!(unwrap!(self.client.lock())
                .post(Data::Structured(updated_structured_data), None))
            .get());
        Ok(())
    }

    /// Get StructuredData from the Network
    fn get_structured_data(&self, id: &XorName, type_tag: u64) -> Result<StructuredData, NfsError> {
        let request = DataIdentifier::Structured(*id, type_tag);
        debug!("Getting structured data from the network ...");
        let response_getter = try!(unwrap!(self.client.lock()).get(request, None));
        match try!(response_getter.get()) {
            Data::Structured(structured_data) => Ok(structured_data),
            _ => Err(NfsError::from(CoreError::ReceivedUnexpectedData)),
        }
    }
}

#[cfg(test)]
mod test {
    use core::utility::test_utils;
    use nfs::AccessLevel;
    use std::sync::{Arc, Mutex};
    use super::*;

    #[test]
    fn create_dir_listing() {
        let test_client = unwrap!(test_utils::get_client());
        let client = Arc::new(Mutex::new(test_client));
        let dir_helper = DirectoryHelper::new(client.clone());
        // Create a Directory
        let (mut directory, grand_parent) = unwrap!(dir_helper.create("DirName".to_string(),
                    ::nfs::VERSIONED_DIRECTORY_LISTING_TAG,
                    Vec::new(),
                    true,
                    AccessLevel::Private,
                    None));
        assert!(grand_parent.is_none());
        assert_eq!(directory, unwrap!(dir_helper.get(directory.key())));
        // Create a Child directory and update the parent_directory
        let (mut child_directory, grand_parent) = unwrap!(dir_helper.create("Child".to_string(),
                    ::nfs::VERSIONED_DIRECTORY_LISTING_TAG,
                    Vec::new(),
                    true,
                    AccessLevel::Private,
                    Some(&mut directory)));
        assert!(grand_parent.is_none());
        // Assert whether parent is updated
        let parent = unwrap!(dir_helper.get(directory.key()));
        assert!(parent.find_sub_directory(child_directory.metadata().name()).is_some());

        let (grand_child_directory, grand_parent) =
            unwrap!(dir_helper.create("Grand Child".to_string(),
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
        let grand_parent = unwrap!(grand_parent, "Grand Parent Should be updated");
        assert_eq!(*grand_parent.metadata().name(),
                   *directory.metadata().name());
        assert_eq!(*grand_parent.metadata().modified_time(),
                   *grand_child_directory.metadata().modified_time());
    }

    #[test]
    fn create_versioned_public_directory() {
        let public_directory;
        {
            let test_client = unwrap!(test_utils::get_client());
            let client = Arc::new(Mutex::new(test_client));
            let dir_helper = DirectoryHelper::new(client.clone());
            let (directory, _) = unwrap!(dir_helper.create("PublicDirectory".to_string(),
                        ::nfs::VERSIONED_DIRECTORY_LISTING_TAG,
                        vec![2u8, 10],
                        true,
                        AccessLevel::Public,
                        None));
            public_directory = directory;
        }
        {
            let test_client = unwrap!(test_utils::get_client());
            let client = Arc::new(Mutex::new(test_client));
            let dir_helper = DirectoryHelper::new(client.clone());
            let retrieved_public_directory = unwrap!(dir_helper.get(public_directory.key()));
            assert_eq!(retrieved_public_directory, public_directory);
        }
    }

    #[test]
    fn create_unversioned_public_directory() {
        let public_directory;
        {
            let test_client = unwrap!(test_utils::get_client());
            let client = Arc::new(Mutex::new(test_client));
            let dir_helper = DirectoryHelper::new(client.clone());
            let (directory, _) = unwrap!(dir_helper.create("PublicDirectory".to_string(),
                        ::nfs::UNVERSIONED_DIRECTORY_LISTING_TAG,
                        vec![2u8, 10],
                        false,
                        AccessLevel::Public,
                        None));
            public_directory = directory;
        }
        {
            let test_client = unwrap!(test_utils::get_client());
            let client = Arc::new(Mutex::new(test_client));
            let dir_helper = DirectoryHelper::new(client.clone());
            let retrieved_public_directory = unwrap!(dir_helper.get(public_directory.key()));
            assert_eq!(retrieved_public_directory, public_directory);
        }
    }

    #[test]
    fn user_root_configuration() {
        let test_client = unwrap!(test_utils::get_client());
        let client = Arc::new(Mutex::new(test_client));
        let dir_helper = DirectoryHelper::new(client.clone());

        let mut root_dir = unwrap!(dir_helper.get_user_root_directory());
        let (created_dir, _) = unwrap!(dir_helper.create("DirName".to_string(),
                                                         ::nfs::VERSIONED_DIRECTORY_LISTING_TAG,
                                                         Vec::new(),
                                                         true,
                                                         AccessLevel::Private,
                                                         Some(&mut root_dir)));
        let root_dir = unwrap!(dir_helper.get_user_root_directory());
        assert!(root_dir.find_sub_directory(created_dir.metadata().name()).is_some());
    }

    #[test]
    fn configuration_directory() {
        let test_client = unwrap!(test_utils::get_client());
        let client = Arc::new(Mutex::new(test_client));
        let dir_helper = DirectoryHelper::new(client.clone());
        let config_dir = unwrap!(dir_helper.get_config_directory("DNS".to_string()));
        assert_eq!(config_dir.metadata().name().clone(),
                   "DNS".to_string());
        let id = config_dir.key().id();
        let config_dir = unwrap!(dir_helper.get_config_directory("DNS".to_string()));
        assert_eq!(config_dir.key().id(), id);
    }

    #[test]
    fn update_and_versioning() {
        let test_client = unwrap!(test_utils::get_client());
        let client = Arc::new(Mutex::new(test_client));
        let dir_helper = DirectoryHelper::new(client.clone());

        let (mut dir_listing, _) = unwrap!(dir_helper.create("DirName2".to_string(),
                    ::nfs::VERSIONED_DIRECTORY_LISTING_TAG,
                    Vec::new(),
                    true,
                    AccessLevel::Private,
                    None));

        let mut versions = unwrap!(dir_helper.get_versions(dir_listing.key().id(),
                                                           dir_listing.key().type_tag()));
        assert_eq!(versions.len(), 1);

        dir_listing.metadata_mut().set_name("NewName".to_string());
        assert!(dir_helper.update(&dir_listing).is_ok());

        versions = unwrap!(dir_helper.get_versions(dir_listing.key().id(),
                                                   dir_listing.key().type_tag()));
        assert_eq!(versions.len(), 2);

        let rxd_dir_listing =
            unwrap!(dir_helper.get_by_version(dir_listing.key(),
                                              &versions[versions.len() - 1]));
        assert_eq!(rxd_dir_listing, dir_listing);

        let rxd_dir_listing = unwrap!(dir_helper.get_by_version(dir_listing.key(),
                                                                &versions[0]));
        assert_eq!(*rxd_dir_listing.metadata().name(),
                   "DirName2".to_string());
    }

    #[test]
    fn delete_directory() {
        let test_client = unwrap!(test_utils::get_client());
        let client = Arc::new(Mutex::new(test_client));
        let dir_helper = DirectoryHelper::new(client.clone());
        // Create a Directory
        let (mut directory, grand_parent) = unwrap!(dir_helper.create("DirName".to_string(),
                    ::nfs::VERSIONED_DIRECTORY_LISTING_TAG,
                    Vec::new(),
                    true,
                    AccessLevel::Private,
                    None));
        assert!(grand_parent.is_none());
        assert_eq!(directory, unwrap!(dir_helper.get(directory.key())));
        // Create a Child directory and update the parent_directory
        let (mut child_directory, grand_parent) = unwrap!(dir_helper.create("Child".to_string(),
                    ::nfs::VERSIONED_DIRECTORY_LISTING_TAG,
                    Vec::new(),
                    true,
                    AccessLevel::Private,
                    Some(&mut directory)));
        assert!(grand_parent.is_none());
        // Assert whether parent is updated
        let parent = unwrap!(dir_helper.get(directory.key()));
        assert!(parent.find_sub_directory(child_directory.metadata().name()).is_some());

        let (grand_child_directory, grand_parent) =
            unwrap!(dir_helper.create("Grand Child".to_string(),
                                      ::nfs::VERSIONED_DIRECTORY_LISTING_TAG,
                                      Vec::new(),
                                      true,
                                      AccessLevel::Private,
                                      Some(&mut child_directory)));

        let _ = unwrap!(grand_parent, "Grand Parent Should be updated");

        let delete_result = unwrap!(dir_helper.delete(&mut child_directory,
                                                      grand_child_directory.metadata()
                                                          .name()));
        let updated_grand_parent = unwrap!(delete_result, "Parent directory should be returned");
        assert_eq!(*updated_grand_parent.key().id(), *directory.key().id());

        let delete_result = unwrap!(dir_helper.delete(&mut directory,
                                                      child_directory.metadata()
                                                          .name()));
        assert!(delete_result.is_none());
    }
}
