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
use time;
use nfs;
use nfs::helper::directory_helper::DirectoryHelper;
use routing;
use client;
use self_encryption;

/// File provides helper functions to perform Operations on Files
pub struct FileHelper {
    client: ::std::sync::Arc<::std::sync::Mutex<client::Client>>
}

impl FileHelper {
    /// Create a new FileHelper instance
    pub fn new(client: ::std::sync::Arc<::std::sync::Mutex<client::Client>>) -> FileHelper {
        FileHelper {
            client: client
        }
    }

    pub fn create(&mut self,
        name: String, size: u64,
        user_metatdata: Vec<u8>,
        directory: &nfs::directory_listing::DirectoryListing) -> Result<nfs::io::Writer, String> {
        match self.file_exists(directory, &name) {
            Some(_) => Err("File already exists".to_string()),
            None => {
                let mut metadata = nfs::metadata::Metadata::new(name, user_metatdata);
                metadata.set_size(size);
                let file = nfs::file::File::new(metadata, self_encryption::datamap::DataMap::None);
                Ok(nfs::io::Writer::new(directory.clone(), file, self.client.clone()))
            }
        }
    }

    pub fn update(&mut self,
        file: &nfs::file::File,
        directory: &nfs::directory_listing::DirectoryListing) -> Result<nfs::io::Writer, String> {
        match self.file_exists(directory, file.get_name()) {
            Some(_) => Ok(nfs::io::Writer::new(directory.clone(), file.clone(), self.client.clone())),
            None => Err("File not present in the directory".to_string())
        }
    }

    /// Updates the file metadata. Returns the updated DirectoryListing
    pub fn update_metadata(&mut self,
        file: &mut nfs::file::File,
        directory: &mut nfs::directory_listing::DirectoryListing,
        user_metadata: &Vec<u8>) -> Result<(), String> {
        match self.file_exists(directory, file.get_name()) {
            Some(_) => {
                file.get_mut_metadata().set_user_metadata(user_metadata.clone());
                directory.upsert_file(file.clone());
                let mut directory_helper = nfs::helper::DirectoryHelper::new(self.client.clone());
                match directory_helper.update(&directory) {
                    Ok(_) => Ok(()),
                    Err(_) => Err("Failed to update".to_string())
                }
            },
            None => Err("File not present in the directory".to_string())
        }
    }

    /// Return the versions of a directory containing modified versions of a file
    pub fn get_versions(&mut self,
        directory_id: &routing::NameType,
        file: &nfs::file::File) -> Result<Vec<routing::NameType>, String> {
        let mut versions = Vec::<routing::NameType>::new();
        let mut directory_helper = DirectoryHelper::new(self.client.clone());

        match directory_helper.get_versions(directory_id) {
            Ok(sdv_versions) => {
                let mut modified_time = time::empty_tm();
                for version_id in sdv_versions {
                    match directory_helper.get_by_version(directory_id, &version_id) {
                        Ok(directory_listing) => {
                            match directory_listing.get_files().iter().find(|&entry| entry.get_name() == file.get_name()) {
                                Some(file) => {
                                   if file.get_metadata().get_modified_time() != modified_time {
                                        modified_time = file.get_metadata().get_modified_time();
                                        versions.push(version_id);
                                    }
                                },
                                None => ()
                            }
                        }
                        Err(_) => { () }
                    }
                }
            },
            Err(_) => { () }
        }

        Ok(versions)
    }

    pub fn read(&mut self, file: nfs::file::File) -> nfs::io::Reader {
        nfs::io::Reader::new(file, self.client.clone())
    }

    fn file_exists(&self, directory: &nfs::directory_listing::DirectoryListing, file_name: &String) -> Option<String> {
        let result = directory.get_files().iter().find(|file| {
                *file.get_name() == *file_name
            });
        match result {
            Some(_) => Some(file_name.clone()),
            None => None
        }
    }

}

#[cfg(test)]
mod test {
    use super::*;
    use ::std::ops::Index;

    fn get_dummy_client() -> ::client::Client {
        let keyword = "Spandan".to_string();
        let password = "Sharma".as_bytes();
        let pin = 1234u32;

        ::client::Client::create_account(&keyword,
                                         pin,
                                         &password,
                                         ::std::sync::Arc::new(::std::sync::Mutex::new(::std::collections::BTreeMap::new()))).ok().unwrap()
    }


    #[test]
    fn create_read_update() {
        let client = ::std::sync::Arc::new(::std::sync::Mutex::new(get_dummy_client()));
        let mut dir_helper = ::nfs::helper::directory_helper::DirectoryHelper::new(client.clone());

        let created_dir_id: _;
        {
            let put_result = dir_helper.create("DirName".to_string(),
                                               vec![7u8; 100]);

            assert!(put_result.is_ok());
            created_dir_id = put_result.ok().unwrap();
        }

        let mut dir_listing: _;
        {
            let get_result = dir_helper.get(&created_dir_id);
            assert!(get_result.is_ok());
            dir_listing = get_result.ok().unwrap();
        }

        let mut file_helper = FileHelper::new(client);
        let mut writer: _;
        {
            let result = file_helper.create("Name".to_string(), 0, vec![98u8; 100], &dir_listing);
            assert!(result.is_ok());

            writer = result.ok().unwrap();
        }

        let data = vec![12u8; 20];
        writer.write(&data[..], 0);
        writer.close();

        {
            let get_result = dir_helper.get(&created_dir_id);
            assert!(get_result.is_ok());
            dir_listing = get_result.ok().unwrap();
        }

        {
            let result = dir_listing.get_files();
            assert_eq!(result.len(), 1);

            let file = result[0].clone();

            let mut reader = file_helper.read(file);
            let rxd_data = reader.read(0, data.len() as u64).ok().unwrap();

            assert_eq!(rxd_data, data);

            {
                let mut writer: _;
                {
                    let result = file_helper.update(result.index(0), &dir_listing);
                    assert!(result.is_ok());

                    writer = result.ok().unwrap();
                }

                let data = vec![11u8; 90];
                writer.write(&[11u8; 90], 0);
                writer.close();

                let get_result = dir_helper.get(&created_dir_id);
                assert!(get_result.is_ok());
                let dir_listing = get_result.ok().unwrap();

                let result = dir_listing.get_files();
                assert_eq!(result.len(), 1);

                let file = result[0].clone();

                let mut reader = file_helper.read(file.clone());
                let rxd_data = reader.read(0, data.len() as u64).ok().unwrap();

                assert_eq!(rxd_data, data);

                {
                    let versions = file_helper.get_versions(&created_dir_id, &file);
                    assert_eq!(versions.unwrap().len(), 2);
                }
            }
        }
    }
}
