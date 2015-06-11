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
use time;

#[allow(dead_code)]
pub struct Blob {
    file: nfs::file::File,
}

impl Blob {

    pub fn get_name(&self) -> &String {
        self.file.get_metadata().get_name()
    }

    pub fn get_metadata(&self) -> Option<String> {
        match self.file.get_metadata().get_user_metadata() {
            Some(data) => {
                match String::from_utf8(data.clone()) {
                    Ok(metadata) => Some(metadata),
                    Err(_) => None
                }
            },
            None => None
        }
    }

    pub fn get_created_time(&self) -> time::Tm {
        self.file.get_metadata().get_created_time()
    }

    pub fn get_modified_time(&self) -> time::Tm {
        self.file.get_metadata().get_modified_time()
    }

    pub fn get_size(&self) -> u64 {
        self.file.get_metadata().get_size()
    }

    pub fn convert_to_file(&self) -> &nfs::file::File {
        &self.file
    }

    pub fn convert_to_mut_file(&mut self) -> &mut nfs::file::File {
        &mut self.file
    }

    pub fn convert_from_file(file: nfs::file::File) -> Blob {
        Blob {
            file: file
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
    use ::client::Client;
    use nfs::file::File;
    use nfs::metadata::Metadata;
    use self_encryption::datamap::DataMap;


    #[test]
    fn create() {
        let datamap = DataMap::None;
        let metadata = Metadata::new("blob".to_string(), Vec::new());
        let file = File::new(metadata.clone(), datamap.clone());

        let blob = Blob{file: file.clone() };

        assert_eq!(*blob.get_name(), *metadata.get_name());
        assert_eq!(blob.get_created_time(), metadata.get_created_time());
        assert_eq!(blob.get_modified_time(), metadata.get_modified_time());
        assert_eq!(blob.get_size(), metadata.get_size());
        assert!(blob.get_metadata().is_none());

        let file = blob.convert_to_file();

        assert_eq!(file.get_name(), metadata.get_name());
        assert_eq!(file.get_metadata().get_created_time(), metadata.get_created_time());
        assert_eq!(file.get_metadata().get_modified_time(), metadata.get_modified_time());
        assert_eq!(file.get_metadata().get_size(), metadata.get_size());
        assert_eq!(file.get_datamap().len(), datamap.len());
        assert!(!file.get_datamap().has_chunks());
    }

    #[test]
    fn create_from_file() {
        let datamap = DataMap::None;
        let metadata = Metadata::new("blob".to_string(), Vec::new());
        let file = File::new(metadata.clone(), datamap.clone());

        let blob = Blob::convert_from_file(file.clone());

        assert_eq!(*blob.get_name(), *file.get_name());
        assert_eq!(blob.get_created_time(), file.get_metadata().get_created_time());
        assert_eq!(blob.get_modified_time(), file.get_metadata().get_modified_time());
        assert_eq!(blob.get_size(), file.get_metadata().get_size());
        assert!(blob.get_metadata().is_none());
    }

    #[test]
    fn convert_to_file() {
        let datamap = DataMap::None;
        let metadata = Metadata::new("blob".to_string(), Vec::new());
        let file = File::new(metadata.clone(), datamap.clone());

        let blob = Blob{ file: file.clone() };

        assert_eq!(*blob.get_name(), *file.get_name());
        assert_eq!(blob.get_created_time(), file.get_metadata().get_created_time());
        assert_eq!(blob.get_modified_time(), file.get_metadata().get_modified_time());
        assert_eq!(blob.get_size(), file.get_metadata().get_size());
        assert!(blob.get_metadata().is_none());
        assert!(file.get_metadata().get_user_metadata().is_none());

        let file = blob.convert_to_file();

        assert_eq!(*blob.get_name(), *file.get_name());
        assert_eq!(blob.get_created_time(), file.get_metadata().get_created_time());
        assert_eq!(blob.get_modified_time(), file.get_metadata().get_modified_time());
        assert_eq!(blob.get_size(), file.get_metadata().get_size());
        assert!(file.get_metadata().get_user_metadata().is_none());
    }

    #[test]
    fn compare() {
        let first_datamap = DataMap::None;
        let first_metadata = Metadata::new("first_blob".to_string(), Vec::new());
        let first_file = File::new(first_metadata.clone(), first_datamap.clone());

        let first_blob = Blob::convert_from_file(first_file.clone());
        let second_blob = Blob{file: first_file.clone() };

        // allow 'times' to be sufficiently distinct
        sleep_ms(1000u32);

        let second_datamap = DataMap::None;
        let second_metadata = Metadata::new("second_blob".to_string(), Vec::new());
        let second_file = File::new(second_metadata, second_datamap.clone());

        let third_blob = Blob::convert_from_file(second_file.clone());

        assert_eq!(*first_blob.get_name(), *second_blob.get_name());
        assert_eq!(first_blob.get_created_time(), second_blob.get_created_time());
        assert_eq!(first_blob.get_modified_time(), second_blob.get_modified_time());

        assert!(*first_blob.get_name() != *third_blob.get_name());
        assert!(first_blob.get_created_time() != third_blob.get_created_time());
        assert!(first_blob.get_modified_time() != third_blob.get_modified_time());
    }
}
