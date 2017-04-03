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

use core::SelfEncryptionStorage;

use core::client::Client;
use nfs::directory_listing::DirectoryListing;
use nfs::errors::NfsError;
use nfs::file::File;
use nfs::helper::directory_helper::DirectoryHelper;
use nfs::helper::reader::Reader;
use nfs::helper::writer::{Mode, Writer};
use nfs::metadata::file_metadata::FileMetadata;
use self_encryption::DataMap;
use std::sync::{Arc, Mutex};

/// File provides helper functions to perform Operations on Files
pub struct FileHelper {
    client: Arc<Mutex<Client>>,
    storage: SelfEncryptionStorage,
}

impl FileHelper {
    /// Create a new FileHelper instance
    pub fn new(client: Arc<Mutex<Client>>) -> FileHelper {
        FileHelper {
            client: client.clone(),
            storage: SelfEncryptionStorage::new(client),
        }
    }

    /// Helper function to create a file in a directory listing
    /// A writer object is returned, through which the data for the file
    /// can be written to the network
    /// The file is actually saved in the directory listing only after
    /// `writer.close()` is invoked
    pub fn create(&mut self,
                  name: String,
                  user_metatdata: Vec<u8>,
                  parent_directory: DirectoryListing)
                  -> Result<Writer, NfsError> {
        trace!("Creating file with name: {}", name);

        match parent_directory.find_file(&name) {
            Some(_) => Err(NfsError::FileAlreadyExistsWithSameName),
            None => {
                let file = File::new(FileMetadata::new(name, user_metatdata), DataMap::None)?;
                Ok(Writer::new(self.client.clone(),
                               &mut self.storage,
                               Mode::Overwrite,
                               parent_directory,
                               file)?)
            }
        }
    }

    /// Delete a file from the DirectoryListing
    /// Returns Option<parent_directory's parent>
    pub fn delete(&self,
                  file_name: String,
                  parent_directory: &mut DirectoryListing)
                  -> Result<Option<DirectoryListing>, NfsError> {
        trace!("Deleting file with name {}.", file_name);

        let _ = parent_directory.remove_file(&file_name)?;
        let directory_helper = DirectoryHelper::new(self.client.clone());
        directory_helper.update(parent_directory)
    }

    /// Updates the file metadata.
    /// Returns Option<parent_directory's parent>
    pub fn update_metadata(&self,
                           file: File,
                           parent_directory: &mut DirectoryListing)
                           -> Result<Option<DirectoryListing>, NfsError> {
        trace!("Updating metadata for file.");

        {
            let existing_file = parent_directory.find_file_by_id(file.get_id())
                .ok_or(NfsError::FileNotFound)?;
            if existing_file.get_name() != file.get_name() &&
               parent_directory.find_file(file.get_name()).is_some() {
                return Err(NfsError::FileAlreadyExistsWithSameName);
            }
        }
        parent_directory.upsert_file(file);
        let directory_helper = DirectoryHelper::new(self.client.clone());
        directory_helper.update(parent_directory)
    }

    /// Helper function to Update content of a file in a directory listing
    /// A writer object is returned, through which the data for the file
    /// can be written to the network
    /// The file is actually saved in the directory listing only after
    /// `writer.close()` is invoked
    pub fn update_content(&mut self,
                          file: File,
                          mode: Mode,
                          parent_directory: DirectoryListing)
                          -> Result<Writer, NfsError> {
        trace!("Updating content in file with name {}", file.get_name());

        {
            let existing_file = parent_directory.find_file(file.get_name())
                .ok_or(NfsError::FileNotFound)?;
            if *existing_file != file {
                return Err(NfsError::FileDoesNotMatch);
            }
        }
        Ok(Writer::new(self.client.clone(),
                       &mut self.storage,
                       mode,
                       parent_directory,
                       file)?)
    }


    /// Return the versions of a directory containing modified versions of a file
    pub fn get_versions(&self,
                        file: &File,
                        parent_directory: &DirectoryListing)
                        -> Result<Vec<File>, NfsError> {
        trace!("Getting versions of a file with name {}", file.get_name());

        let mut versions = Vec::<File>::new();
        let directory_helper = DirectoryHelper::new(self.client.clone());

        let sdv_versions = directory_helper.get_versions(parent_directory.get_key().get_id(),
                          parent_directory.get_key().get_type_tag())?;

        // Because Version 0 is invalid, so can be made an initial comparison value
        let mut file_version = 0;
        for version_id in sdv_versions {
            let id = parent_directory.get_key().get_id();
            let directory_listing = directory_helper.get_by_version(id,
                                parent_directory.get_key().get_access_level(),
                                version_id)?;
            if let Some(file) = directory_listing
                   .get_files()
                   .iter()
                   .find(|&entry| entry.get_name() == file.get_name()) {
                if file.get_metadata().get_version() != file_version {
                    file_version = file.get_metadata().get_version();
                    versions.push(file.clone());
                }
            }
        }
        Ok(versions)
    }

    /// Returns a reader for reading the file contents
    pub fn read<'a>(&'a mut self, file: &'a File) -> Result<Reader<'a>, NfsError> {
        trace!("Reading file with name: {}", file.get_name());
        Reader::new(self.client.clone(), &mut self.storage, file)
    }
}

#[cfg(test)]
mod test {
    use core::client::Client;
    use core::utility::test_utils;
    use nfs::AccessLevel;
    use nfs::helper::directory_helper::DirectoryHelper;
    use nfs::helper::file_helper::FileHelper;
    use nfs::helper::writer::Mode;
    use std::sync::{Arc, Mutex};

    fn get_client() -> Arc<Mutex<Client>> {
        let test_client = unwrap!(test_utils::get_client());
        Arc::new(Mutex::new(test_client))
    }

    #[test]
    fn file_crud() {
        let client = get_client();
        let dir_helper = DirectoryHelper::new(client.clone());
        let (mut directory, _) = unwrap!(dir_helper.create("DirName".to_string(),
                                                           ::nfs::VERSIONED_DIRECTORY_LISTING_TAG,
                                                           Vec::new(),
                                                           true,
                                                           AccessLevel::Private,
                                                           None));
        let mut file_helper = FileHelper::new(client.clone());
        let file_name = "hello.txt".to_string();

        const ORIG_SIZE: usize = 100;
        {
            // create
            let mut writer = unwrap!(file_helper.create(file_name.clone(), Vec::new(), directory));
            unwrap!(writer.write(&[0u8; ORIG_SIZE]), "");
            let (updated_directory, _) = unwrap!(writer.close());
            directory = updated_directory;
            assert!(directory.find_file(&file_name).is_some());
        }
        {
            // read
            let file = unwrap!(directory.find_file(&file_name), "File not found");
            let mut reader = unwrap!(file_helper.read(file), "");
            let size = reader.size();
            assert_eq!(unwrap!(reader.read(0, size)), vec![0u8; 100]);
        }

        const NEW_SIZE: usize = 50;
        {
            // update - full rewrite
            let file = unwrap!(directory.find_file(&file_name).cloned(), "File not found");
            {
                let mut writer =
                    unwrap!(file_helper.update_content(file, Mode::Overwrite, directory));
                unwrap!(writer.write(&[1u8; NEW_SIZE]));
                let (updated_directory, _) = unwrap!(writer.close());
                directory = updated_directory;
            }
            let file = unwrap!(directory.find_file(&file_name), "File not found");
            let mut reader = unwrap!(file_helper.read(file), "");
            let size = reader.size();
            assert_eq!(unwrap!(reader.read(0, size)), vec![1u8; 50]);
        }

        const APPEND_SIZE: usize = 10;
        {
            // update - should append (after S.E behaviour changed)
            let file = unwrap!(directory.find_file(&file_name).cloned(), "File not found");
            {
                let mut writer = unwrap!(file_helper.update_content(file, Mode::Modify, directory));
                unwrap!(writer.write(&[2u8; APPEND_SIZE]));
                let (updated_directory, _) = unwrap!(writer.close());
                directory = updated_directory;
            }
            let file = unwrap!(directory.find_file(&file_name), "File not found");
            let mut reader = unwrap!(file_helper.read(file), "");
            let size = reader.size();
            let data = unwrap!(reader.read(0, size));

            assert_eq!(size, (NEW_SIZE + APPEND_SIZE) as u64);
            assert_eq!(data[0..NEW_SIZE].to_owned(), vec![1u8; NEW_SIZE]);
            assert_eq!(&data[NEW_SIZE..], [2u8; APPEND_SIZE]);
        }
        {
            // versions
            let file = unwrap!(directory.find_file(&file_name).cloned(), "File not found");
            let versions = unwrap!(file_helper.get_versions(&file, &directory));
            assert_eq!(versions.len(), 3);
        }
        {
            // Update Metadata
            let mut file = unwrap!(directory.find_file(&file_name).cloned(), "File not found");
            file.get_mut_metadata().set_user_metadata(vec![12u8; 10]);
            let _ = unwrap!(file_helper.update_metadata(file, &mut directory));
            let file = unwrap!(directory.find_file(&file_name).cloned(), "File not found");
            assert_eq!(*file.get_metadata().get_user_metadata(), [12u8; 10][..]);
        }
        {
            // Delete
            let _ = unwrap!(file_helper.delete(file_name.clone(), &mut directory));
            assert!(directory.find_file(&file_name).is_none());
        }
    }
}
