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
use nfs;
use routing;
use time;
use client;

pub struct Container {
    client: ::std::sync::Arc<::std::sync::Mutex<client::Client>>,
    directory_listing: nfs::directory_listing::DirectoryListing
}

impl Container {
    /// Authorizes the root directory access and return the Container
    /// Entry point for the Rest API
    pub fn authorise(client: ::std::sync::Arc<::std::sync::Mutex<client::Client>>, dir_id: [u8;64]) -> Result<Container, String> {
        let mut directory_helper = nfs::helper::DirectoryHelper::new(client.clone());
        let result = directory_helper.get(&::routing::NameType(dir_id));
        match result {
            Ok(listing) => Ok(Container {
                client: client,
                directory_listing: listing
            }),
            Err(msg) => Err(msg)
        }
    }

    pub fn get_id(&self) -> [u8;64] {
        self.directory_listing.get_id().0
    }

    pub fn get_metadata(&self) -> Option<String> {
        let metadata = self.directory_listing.get_metadata().get_user_metadata();
        match metadata {
            Some(data) => Some(String::from_utf8(data.clone()).unwrap()),
            None => None
        }
    }

    pub fn get_name(&self) -> &String {
        self.directory_listing.get_metadata().get_name()
    }

    pub fn get_created_time(&self) -> time::Tm {
        self.directory_listing.get_metadata().get_created_time()
    }

    pub fn get_modified_time(&self) -> time::Tm {
        self.directory_listing.get_metadata().get_modified_time()
    }

    pub fn get_blobs(&self) -> Vec<nfs::rest::Blob> {
        self.directory_listing.get_files().iter().map(|x| nfs::rest::Blob::convert_from_file(self.client.clone(), x.clone())).collect()
    }

    pub fn get_blob(&self, name: String, version: Option<[u8;64]>) -> Result<nfs::rest::Blob, String> {
        match version {
            Some(version_id) => {
                let dir_id = self.directory_listing.get_id();
                let mut directory_helper = nfs::helper::DirectoryHelper::new(self.client.clone());
                match directory_helper.get_by_version(dir_id, &routing::NameType(version_id)) {
                    Ok(listing) => match self.find_file(&name, &listing){
                        Some(blob) => Ok(blob),
                        None => Err("Blob not found for the version specified".to_string())
                    },
                    Err(msg) => Err(msg)
                }
            },
            None => match self.find_file(&name, &self.directory_listing) {
                Some(blob) => Ok(blob),
                None => Err("Blob not found for the version specified".to_string())
            },
        }
    }

    pub fn create(&mut self, name: &String, metadata: Option<String>) -> Result<(), String> {
        match self.validate_metadata(metadata) {
            Ok(user_metadata) => {
                let mut directory_helper = nfs::helper::DirectoryHelper::new(self.client.clone());
                match directory_helper.create(name.clone(), user_metadata) {
                    Ok(dir_id) => {
                        let mut directory_helper = nfs::helper::DirectoryHelper::new(self.client.clone());
                        match directory_helper.get(&dir_id) {
                            Ok(created_directory) => {
                                self.directory_listing.get_mut_sub_directories().push(created_directory.get_info().clone());
                                let mut directory_helper = nfs::helper::DirectoryHelper::new(self.client.clone());
                                match directory_helper.update(&created_directory) {
                                    Ok(_) => Ok(()),
                                    Err(msg) => Err(msg)
                                }
                            },
                            Err(msg) => Err(msg)
                        }
                    },
                    Err(msg) => Err(msg)
                }
            },
            Err(err) => Err(err),
        }
    }

    pub fn get_containers(&self) -> Vec<nfs::rest::ContainerInfo> {
        self.directory_listing.get_sub_directories().iter().map(|info| {
                nfs::rest::ContainerInfo::convert_from_directory_info(info.clone())
            }).collect()
    }

    pub fn update_metadata(&mut self, metadata: Option<String>) -> Result<(), String>{
        match self.validate_metadata(metadata) {
            Ok(user_metadata) => {
                self.directory_listing.set_user_metadata(user_metadata);
                let mut directory_helper = nfs::helper::DirectoryHelper::new(self.client.clone());
                match directory_helper.update(&self.directory_listing) {
                    Ok(_) => Ok(()),
                    Err(msg) => Err(msg),
                }
            },
            Err(err) => Err(err),
        }
    }

    pub fn get_container(&mut self, name: &String, version: Option<[u8; 64]>) -> Result<Container, String> {
        let sub_dirs = self.directory_listing.get_sub_directories();
        match sub_dirs.iter().find(|&entry| *entry.get_name() == *name) {
            Some(dir_info) => {
                let mut directory_helper = nfs::helper::DirectoryHelper::new(self.client.clone());
                let get_dir_listing_result = match version {
                    Some(version_id) => directory_helper.get_by_version(dir_info.get_id(), &::routing::NameType(version_id)),
                    None =>  directory_helper.get(dir_info.get_id())
                };
                match get_dir_listing_result {
                    Ok(dir_listing) => Ok(Container::convert_from_directory_listing(self.client.clone(), dir_listing)),
                    Err(msg) => Err(msg)
                }
            },
            None => Err("Container not found".to_string())
        }
    }

    pub fn get_versions(&mut self) -> Result<Vec<[u8;64]>, String> {
        let mut directory_helper = nfs::helper::DirectoryHelper::new(self.client.clone());
        match directory_helper.get_versions(self.directory_listing.get_id()) {
            Ok(versions) => {
                Ok(versions.iter().map(|v| v.0).collect())
            },
            Err(msg) => Err(msg)
        }
    }

    pub fn delete_container(&mut self, name: &String) -> Result<(), String> {
        match self.directory_listing.get_sub_directories().iter().position(|entry| *entry.get_name() == *name) {
            Some(pos) => {
                self.directory_listing.get_mut_sub_directories().remove(pos);
                let mut directory_helper = nfs::helper::DirectoryHelper::new(self.client.clone());
                match directory_helper.update(&self.directory_listing) {
                    Ok(_) => Ok(()),
                    Err(msg) => Err(msg)
                }
            },
            None => {
                Err("Container not found".to_string())
            }
        }
    }

    pub fn create_blob(&mut self, name: String, metadata: Option<String>, size: u64) -> Result<nfs::io::Writer, String> {
        match self.validate_metadata(metadata) {
            Ok(user_metadata) => {
                let mut file_helper = nfs::helper::FileHelper::new(self.client.clone());
                file_helper.create(name, size, user_metadata, &self.directory_listing)
            },
            Err(err) => Err(err),
        }
    }    

    pub fn get_blob_content(&mut self, blob: nfs::rest::Blob) -> Result<Vec<u8>, String> {
        match self.get_reader_for_blob(blob) {
            Ok(mut reader) => {
                let size = reader.size();
                reader.read(0, size)
            },
            Err(msg) => Err(msg)
        }
    }

    pub fn get_blob_reader(&mut self, blob: nfs::rest::blob::Blob) -> Result<nfs::io::reader::Reader, String> {
        self.get_reader_for_blob(blob)
    }

    pub fn get_blob_versions(&mut self, name: &String) -> Result<Vec<[u8;64]>, String>{
        match self.find_file(name, &self.directory_listing) {
            Some(blob) => {
                let mut file_helper = nfs::helper::FileHelper::new(self.client.clone());
                let versions = file_helper.get_versions(self.directory_listing.get_id(), &blob.convert_to_file());
                Ok(Vec::new())
            },
            None=> Err("Blob not found".to_string())
        }
    }

    pub fn delete_blob(&mut self, name: &String) -> Result<(), String> {
        match self.directory_listing.get_sub_directories().iter().position(|file| *file.get_name() == *name) {
            Some(pos) => {
                self.directory_listing.get_mut_sub_directories().remove(pos);
                let mut directory_helper = nfs::helper::DirectoryHelper::new(self.client.clone());
                match directory_helper.update(&self.directory_listing) {
                    Ok(_) => Ok(()),
                    Err(msg) => Err(msg),
                }
            },
            None => Err("Blob not found".to_string())
        }
    }

    pub fn copy_blob(&mut self, blob_name: String, to_container: [u8;64]) -> Result<(), String> {
        let to_dir_id = ::routing::NameType(to_container);
        let mut directory_helper = nfs::helper::DirectoryHelper::new(self.client.clone());
        match self.directory_listing.get_files().iter().position(|file| *file.get_name() == blob_name) {
            Some(file_pos) => {
                match directory_helper.get(&to_dir_id) {
                    Ok(mut to_dir_listing) => {
                        match self.find_file(&blob_name, &to_dir_listing) {
                            Some(_) => Err("File already exists in the destination Conatiner".to_string()),
                            None => {
                                let file = self.directory_listing.get_files()[file_pos].clone();
                                to_dir_listing.get_mut_files().push(file);
                                match  directory_helper.update(&to_dir_listing) {
                                    Ok(_) => Ok(()),
                                    Err(msg) => Err(msg),
                                }
                            }
                        }
                    },
                    Err(msg) => Err(msg),
                }
            },
            None => Err("Blob not found".to_string()),
        }
    }

    fn get_writer_for_blob(&self, blob: &nfs::rest::blob::Blob) -> Result<nfs::io::Writer, String> {
        let mut helper = nfs::helper::FileHelper::new(self.client.clone());
        match helper.update(blob.convert_to_file(), &self.directory_listing) {
            Ok(writter) => Ok(writter),
            Err(_) => Err("Blob not found".to_string())
        }
    }

    pub fn update_blob_metadata(&mut self, blob: &mut nfs::rest::Blob, metadata: Option<String>) ->Result<(), String> {
        match self.validate_metadata(metadata) {
            Ok(user_metadata) => {
                let mut file_helper = nfs::helper::FileHelper::new(self.client.clone());
                file_helper.update_metadata(blob.convert_to_mut_file(), &mut self.directory_listing, &user_metadata)
            },
            Err(msg) => Err(msg),
        }
    }

    fn get_reader_for_blob(&self, blob: nfs::rest::blob::Blob) -> Result<nfs::io::Reader, String> {
        match self.find_file(blob.get_name(), &self.directory_listing) {
            Some(_) => {
                Ok(nfs::io::Reader::new(blob.convert_to_file().clone(), self.client.clone()))
            },
            None => Err("Blob not found".to_string())
        }
    }

    fn validate_metadata(&self, metadata: Option<String>) -> Result<Vec<u8>, String> {
        match metadata {
            Some(data) => {
                if data.len() == 0 {
                    Err("Metadata cannot be empty".to_string())
                } else {
                    Ok(data.into_bytes())
                }
            },
            None => Ok(Vec::new()),
        }
    }

    fn find_file(&self, name: &String, directory_listing: &nfs::directory_listing::DirectoryListing) -> Option<nfs::rest::Blob> {
        match directory_listing.get_files().iter().find(|file| file.get_name() == name) {
            Some(file) => Some(nfs::rest::Blob::convert_from_file(self.client.clone(), file.clone())),
            None => None
        }
    }

    pub fn convert_to_directory_listing(&self) -> nfs::directory_listing::DirectoryListing {
        self.directory_listing.clone()
    }

    pub fn convert_from_directory_listing(client: ::std::sync::Arc<::std::sync::Mutex<client::Client>>,
         directory_listing: nfs::directory_listing::DirectoryListing) -> Container {
        Container {
            client: client,
            directory_listing: directory_listing
        }
    }
}


#[cfg(test)]
mod test {
    use super::*;
    use ::std::sync::Arc;
    use ::std::sync::Mutex;
    use ::std::collections::BTreeMap;
    use std::thread::sleep_ms;
    use ::client;
    use ::client::Client;
    use nfs::directory_listing::DirectoryListing;
    use nfs::helper::DirectoryHelper;
    use routing::NameType;

    fn dummy_client() -> Client {
        let keyword = "keyword".to_string();
        let password = "password".as_bytes();
        let pin = 1234u32;
        let map = Arc::new(Mutex::new(BTreeMap::new()));

        Client::create_account(&keyword, pin, &password, map).ok().unwrap()
    }

    fn store_based_client() -> Client {
        let keyword = "keyword".to_string();
        let password = "password".as_bytes();
        let pin = 1234u32;
        let data_store = client::non_networking_test_framework::get_new_data_store();

        Client::create_account(&keyword, pin, &password, data_store.clone()).ok().unwrap()
    }


    #[test]
    fn create() {
        let client = Arc::new(Mutex::new(dummy_client()));
        let name = "directory".to_string();
        let directory_listing = DirectoryListing::new(name.clone(), Vec::new());

        let container = Container{ client: client.clone(), directory_listing: directory_listing.clone() };

        assert_eq!(container.get_name(), &name.clone());
    }

    #[test]
    fn create_from_directory_listing() {
        let client = Arc::new(Mutex::new(dummy_client()));
        let name = "directory".to_string();
        let directory_listing = DirectoryListing::new(name.clone(), Vec::new());
        let container = Container::convert_from_directory_listing(client, directory_listing.clone());

        assert_eq!(container.get_name(), directory_listing.get_name());
        assert_eq!(container.get_created_time(), directory_listing.get_metadata().get_created_time());
        assert_eq!(container.get_modified_time(), directory_listing.get_metadata().get_modified_time());
        assert_eq!(NameType(container.get_id()), directory_listing.get_id().clone());
        assert_eq!(container.get_blobs().len(), 0usize);
    }

    #[test]
    fn convert_to_directory_listing() {
        let client = Arc::new(Mutex::new(dummy_client()));
        let name = "directory".to_string();
        let directory_listing = DirectoryListing::new(name.clone(), Vec::new());

        let container = Container::convert_from_directory_listing(client, directory_listing.clone());

        assert_eq!(container.get_name(), directory_listing.get_name());
        assert_eq!(container.get_created_time(), directory_listing.get_metadata().get_created_time());
        assert_eq!(container.get_modified_time(), directory_listing.get_metadata().get_modified_time());
        assert_eq!(container.get_blobs().len(), 0usize);

        let directory_listing = container.convert_to_directory_listing();

        assert_eq!(container.get_name(), directory_listing.get_name());
        assert_eq!(container.get_created_time(), directory_listing.get_metadata().get_created_time());
        assert_eq!(container.get_modified_time(), directory_listing.get_metadata().get_modified_time());
        assert_eq!(NameType(container.get_id()), directory_listing.get_id().clone());
    }

    #[test]
    fn compare() {
        let client = Arc::new(Mutex::new(dummy_client()));
        let first_name = "first_directory".to_string();
        let first_directory_listing = DirectoryListing::new(first_name.clone(), Vec::new());

        let first_container = Container::convert_from_directory_listing(
                client.clone(), first_directory_listing.clone());
        let second_container = Container{ client: client.clone(),
                                          directory_listing: first_directory_listing.clone()
                                        };

        // allow 'times' to be sufficiently distinct
        sleep_ms(1000u32);

        let second_name = "second_directory".to_string();
        let second_directory_listing = DirectoryListing::new(second_name.clone(), Vec::new());

        let third_container = Container::convert_from_directory_listing(
                client.clone(), second_directory_listing.clone());

        assert_eq!(first_container.get_name(), second_container.get_name());
        assert_eq!(first_container.get_created_time(), second_container.get_created_time());
        assert_eq!(first_container.get_modified_time(), second_container.get_modified_time());
        assert_eq!(NameType(first_container.get_id()), NameType(second_container.get_id()));

        assert!(first_container.get_name() != third_container.get_name());
        assert!(first_container.get_created_time() != third_container.get_created_time());
        assert!(first_container.get_modified_time() != third_container.get_modified_time());
        assert!(NameType(first_container.get_id()) != NameType(third_container.get_id()));
    }

    #[test]
    fn create_blob() {
        let client = Arc::new(Mutex::new(store_based_client()));
        let mut directory_helper = DirectoryHelper::new(client.clone());
        let directory_result = directory_helper.create("root".to_string(), Vec::new());
        assert!(directory_result.is_ok());
        let directory_id = directory_result.unwrap();

        let container_result = Container::authorise(client.clone(), directory_id.0);
        assert!(container_result.is_ok());
        let mut container = container_result.unwrap();
        assert_eq!(container.get_blobs().len(), 0usize);

        let blob_name = "blob".to_string();
        let blob_writer_result = container.create_blob(blob_name.clone(), None, 0u64);
        assert!(blob_writer_result.is_ok());
        let mut blob_writer = blob_writer_result.unwrap();
        let content = "content".to_string();
        blob_writer.write(content.as_bytes(), 0u64);
        let blob_writer_close_result = blob_writer.close();
        assert!(blob_writer_close_result.is_ok());

        assert_eq!(container.get_blobs().len(), 1usize);
        let blob_versions = container.get_blob_versions(&blob_name.clone());
        assert!(blob_versions.is_ok());
        let blob_result = container.get_blob(blob_name.clone(), Some(blob_versions.unwrap()[0]));
        assert!(blob_result.is_ok());
        let blob = blob_result.unwrap();
        assert_eq!(blob_name.clone(), blob.get_name().clone());

        let blob_reader_result = container.get_reader_for_blob(blob);
        assert!(blob_reader_result.is_ok());
        let mut blob_reader = blob_reader_result.unwrap();
        let recovered_content = blob_reader.read(0u64, content.len() as u64);
        assert!(recovered_content.is_ok());
        assert_eq!(recovered_content.unwrap(), content.as_bytes().to_vec());
    }

    #[test]
    fn delete_blob() {
        let client = Arc::new(Mutex::new(store_based_client()));
        let mut directory_helper = DirectoryHelper::new(client.clone());
        let directory_result = directory_helper.create("root".to_string(), Vec::new());
        assert!(directory_result.is_ok());
        let directory_id = directory_result.unwrap();

        let container_result = Container::authorise(client.clone(), directory_id.0);
        assert!(container_result.is_ok());
        let mut container = container_result.unwrap();
        assert_eq!(container.get_blobs().len(), 0usize);

        let blob_name = "blob".to_string();
        let blob_writer_result = container.create_blob(blob_name.clone(), None, 0u64);
        assert!(blob_writer_result.is_ok());
        let mut blob_writer = blob_writer_result.unwrap();
        let content = "content".to_string();
        blob_writer.write(content.as_bytes(), 0u64);
        let blob_writer_close_result = blob_writer.close();
        assert!(blob_writer_close_result.is_ok());

        assert_eq!(container.get_blobs().len(), 1usize);
        let blob_result = container.get_blob(blob_name.clone(), None);
        assert!(blob_result.is_ok());
        let blob = blob_result.unwrap();
        assert_eq!(blob_name.clone(), blob.get_name().clone());

        let blob_delete_result = container.delete_blob(&blob_name.clone());
        assert!(blob_delete_result.is_ok());
        assert_eq!(container.get_blobs().len(), 0usize);
    }
}
