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

use nfs::errors::NfsError;
use nfs::file::File;
use nfs::metadata::{DirectoryKey, DirectoryMetadata};
use routing::XorName;
use rust_sodium::crypto::box_;
use std::cmp;

/// Struct that represent a directory in the network.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Directory {
    key: DirectoryKey,
    content: DirectoryContent,
}

impl Directory {
    /// Create a Directory given the content.
    pub fn with_content(key: DirectoryKey, content: DirectoryContent) -> Self {
        Directory {
            key: key,
            content: content,
        }
    }

    /// Create a new, empty Directory.
    pub fn empty(key: DirectoryKey, metadata: DirectoryMetadata) -> Self {
        Directory {
            key: key,
            content: DirectoryContent::empty(metadata),
        }
    }

    /// Returns name of this Directory.
    pub fn name(&self) -> &str {
        self.metadata().name()
    }

    /// Returns the DirectoryKey representing this Directory
    pub fn key(&self) -> &DirectoryKey {
        &self.key
    }

    /// Get Directory metadata
    pub fn metadata(&self) -> &DirectoryMetadata {
        &self.content.metadata
    }

    /// Get Directory metadata in mutable format so that it can also be updated
    pub fn metadata_mut(&mut self) -> &mut DirectoryMetadata {
        &mut self.content.metadata
    }

    /// Return the content of this Directory (the part to be serialized)
    pub fn content(&self) -> &DirectoryContent {
        &self.content
    }

    /// Get all files in this Directory
    pub fn files(&self) -> &[File] {
        &self.content.files
    }

    /// Get all files in this Directory with mutability to update the listing of files
    pub fn files_mut(&mut self) -> &mut Vec<File> {
        &mut self.content.files
    }

    /// Find file in this Directory by name.
    pub fn find_file(&self, file_name: &str) -> Option<&File> {
        self.files().iter().find(|file| *file.name() == *file_name)
    }

    /// Find file in this Directory by id.
    pub fn find_file_by_id(&self, id: &XorName) -> Option<&File> {
        self.files().iter().find(|file| *file.get_id() == *id)
    }

    /// Get all subdirectories in this Directory.
    pub fn sub_directories(&self) -> &[SubDirectory] {
        &self.content.sub_directories
    }

    /// Get all subdirectories in this Directory with mutability to update the
    /// listing of subdirectories.
    pub fn sub_directories_mut(&mut self) -> &mut Vec<SubDirectory> {
        &mut self.content.sub_directories
    }

    /// Find sub-directory of this Directory by name.
    pub fn find_sub_directory(&self, directory_name: &str) -> Option<&SubDirectory> {
        self.sub_directories().iter().find(|info| *info.name() == *directory_name)
    }

    /// Find sub-directory of this Directory by id.
    pub fn find_sub_directory_by_id(&self, id: &XorName) -> Option<&SubDirectory> {
        self.sub_directories().iter().find(|info| *info.id() == *id)
    }

    /// If file is present in this Directory then replace it else insert it
    pub fn upsert_file(&mut self, file: File) {
        let modified_time = *file.metadata().modified_time();
        // TODO try using the below approach for efficiency - also try the same
        // in upsert_sub_directory
        //     if let Some(mut existing_file) = self.files.iter_mut().find(
        //             |entry| *entry.name() == *file.name()) {
        //         *existing_file = file;
        if let Some(index) = self.files()
            .iter()
            .position(|entry| *entry.get_id() == *file.get_id()) {
            let mut existing = unwrap!(self.files_mut().get_mut(index));
            *existing = file;
        } else {
            self.files_mut().push(file);
        }
        self.metadata_mut().set_modified_time(modified_time)
    }

    /// Remove a file
    pub fn remove_file(&mut self, file_name: &str) -> Result<File, NfsError> {
        let index = try!(self.files()
            .iter()
            .position(|file| *file.name() == *file_name)
            .ok_or(NfsError::FileNotFound));
        Ok(self.files_mut().remove(index))
    }

    /// If DirectoryMetadata is present in the sub_directories of this Directory
    /// then replace it else insert it
    pub fn upsert_sub_directory(&mut self,
                                directory_key: DirectoryKey,
                                directory_metadata: DirectoryMetadata) {
        let modified_time = *directory_metadata.modified_time();
        let sub_directory = SubDirectory::new(directory_key, directory_metadata);
        if let Some(index) = self.sub_directories()
            .iter()
            .position(|entry| *entry.id() == *sub_directory.id()) {
            self.sub_directories_mut()[index] = sub_directory;
        } else {
            self.sub_directories_mut().push(sub_directory);
        }
        self.metadata_mut().set_modified_time(modified_time);
    }

    /// Remove a sub_directory
    pub fn remove_sub_directory(&mut self, directory_name: &str) -> Result<SubDirectory, NfsError> {
        let index = try!(self.sub_directories()
            .iter()
            .position(|dir_info| *dir_info.name() == *directory_name)
            .ok_or(NfsError::DirectoryNotFound));
        Ok(self.sub_directories_mut().remove(index))

    }

    // Generates a nonce based on the directory_id
    #[allow(missing_docs)]
    pub fn generate_nonce(directory_id: &XorName) -> box_::Nonce {
        let mut nonce = [0u8; box_::NONCEBYTES];
        let min_length = cmp::min(nonce.len(), directory_id.0.len());
        nonce.clone_from_slice(&directory_id.0[..min_length]);
        box_::Nonce(nonce)
    }
}

/// Struct containing all the directory data that are serialized in the network.
#[derive(Clone, Debug, Eq, PartialEq, RustcEncodable, RustcDecodable)]
pub struct DirectoryContent {
    metadata: DirectoryMetadata,
    sub_directories: Vec<SubDirectory>,
    files: Vec<File>,
}

impl DirectoryContent {
    fn empty(metadata: DirectoryMetadata) -> Self {
        DirectoryContent {
            metadata: metadata,
            sub_directories: vec![],
            files: vec![],
        }
    }
}

/// Sub-directory entry in a Directory.
#[derive(Clone, Debug, Eq, PartialEq, RustcDecodable, RustcEncodable)]
pub struct SubDirectory {
    key: DirectoryKey,
    metadata: DirectoryMetadata,
}

impl SubDirectory {
    /// Create new sub-directory entry.
    pub fn new(key: DirectoryKey, metadata: DirectoryMetadata) -> Self {
        SubDirectory {
            key: key,
            metadata: metadata,
        }
    }

    /// Get DirectoryKey of this subdirectory.
    pub fn key(&self) -> &DirectoryKey {
        &self.key
    }

    /// Get metadata of this subdirectory.
    pub fn metadata(&self) -> &DirectoryMetadata {
        &self.metadata
    }

    /// Get name of this subdirectory.
    pub fn name(&self) -> &str {
        self.metadata.name()
    }

    /// Get id (XorName) of this subdirectory.
    pub fn id(&self) -> &XorName {
        self.key.id()
    }
}

#[cfg(test)]
mod test {
    use maidsafe_utilities::serialisation::{deserialise, serialise};
    use nfs::file::File;
    use nfs::metadata::{DirectoryKey, DirectoryMetadata, FileMetadata};
    use rand;
    use self_encryption::DataMap;
    use super::Directory;

    const TAG: u64 = 100;

    fn create_directory(name: &str, user_metadata: Vec<u8>) -> Directory {
        let id = rand::random();
        let key = DirectoryKey::new(id, TAG, false, None);
        let metadata = DirectoryMetadata::new(name, user_metadata);

        Directory::empty(key, metadata)
    }

    #[test]
    fn serialise_and_deserialise_directory_content() {
        let dir = create_directory("Home",
                                   "some metadata about the directory"
                                       .to_string()
                                       .into_bytes());

        let serialised_content = unwrap!(serialise(dir.content()));
        let content_after = unwrap!(deserialise(&serialised_content));
        assert_eq!(*dir.content(), content_after);
    }

    #[test]
    fn find_upsert_remove_file() {
        let id = rand::random();
        let key = DirectoryKey::new(id, TAG, true, None);
        let metadata = DirectoryMetadata::new("Home", Vec::new());
        let mut dir = Directory::empty(key, metadata);
        let mut file = unwrap!(File::new(FileMetadata::new("index.html".to_string(), Vec::new()),
                                         DataMap::None));
        assert!(dir.find_file(file.name()).is_none());
        dir.upsert_file(file.clone());
        assert!(dir.find_file(file.name()).is_some());

        file.metadata_mut().set_name("home.html".to_string());
        dir.upsert_file(file.clone());
        assert_eq!(dir.files().len(), 1);
        let file2 = unwrap!(File::new(FileMetadata::new("demo.html".to_string(), Vec::new()),
                                      DataMap::None));
        dir.upsert_file(file2.clone());
        assert_eq!(dir.files().len(), 2);

        let _ = unwrap!(dir.find_file(file.name()), "File not found");
        let _ = unwrap!(dir.find_file(file2.name()), "File not found");

        let _ = unwrap!(dir.remove_file(file.metadata().name()));
        assert!(dir.find_file(file.name()).is_none());
        assert!(dir.find_file(file2.name()).is_some());
        assert_eq!(dir.files().len(), 1);

        let _ = unwrap!(dir.remove_file(file2.metadata().name()));
        assert_eq!(dir.files().len(), 0);
    }

    #[test]
    fn find_upsert_remove_directory() {
        let mut dir = create_directory("Home", Vec::new());
        let mut sub_dir = create_directory("Child one", Vec::new());
        assert!(dir.find_sub_directory(sub_dir.metadata().name())
            .is_none());
        dir.upsert_sub_directory(sub_dir.key().clone(), sub_dir.metadata().clone());
        assert!(dir.find_sub_directory(sub_dir.metadata().name())
            .is_some());

        sub_dir.metadata_mut().set_name("Child_1".to_string());
        dir.upsert_sub_directory(sub_dir.key().clone(), sub_dir.metadata().clone());
        assert_eq!(dir.sub_directories().len(), 1);
        let sub_dir_two = create_directory("Child Two", Vec::new());
        dir.upsert_sub_directory(sub_dir_two.key().clone(),
                                 sub_dir_two.metadata().clone());
        assert_eq!(dir.sub_directories().len(), 2);

        let _ = unwrap!(dir.find_sub_directory(sub_dir.metadata()
                            .name()),
                        "Directory not found");
        let _ = unwrap!(dir.find_sub_directory(sub_dir_two.metadata()
                            .name()),
                        "Directory not found");

        let _ = unwrap!(dir.remove_sub_directory(sub_dir.metadata()
            .name()));
        assert!(dir.find_sub_directory(sub_dir.metadata().name())
            .is_none());
        assert!(dir.find_sub_directory(sub_dir_two.metadata().name())
            .is_some());
        assert_eq!(dir.sub_directories().len(), 1);

        // TODO (Spandan) - Fetch and issue a DELETE on the removed directory, check elsewhere in
        // code/test. Also check what can be done for file removals.
        let _ = unwrap!(dir.remove_sub_directory(sub_dir_two.metadata().name()));
        assert_eq!(dir.sub_directories().len(), 0);
    }
}
