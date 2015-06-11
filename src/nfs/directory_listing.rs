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

use nfs::file::File;
use nfs::directory_info::DirectoryInfo;
use nfs::metadata::Metadata;
use routing;
use std::fmt;

#[derive(RustcEncodable, RustcDecodable, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct DirectoryListing {
    info: DirectoryInfo,
    sub_directories: Vec<DirectoryInfo>,
    files: Vec<File>
}

impl DirectoryListing {
    pub fn new(name: String, user_metadata: Vec<u8>) -> DirectoryListing {
        DirectoryListing {
            info: DirectoryInfo::new(Metadata::new(name, user_metadata)),
            sub_directories: Vec::new(),
            files: Vec::new()
        }
    }

    pub fn get_info(&self) -> &DirectoryInfo {
        &self.info
    }

    pub fn get_mut_metadata(&mut self) -> &mut Metadata {
        self.info.get_mut_metadata()
    }

    pub fn get_metadata(&self) -> &Metadata {
        self.info.get_metadata()
    }

    // pub fn get_parent_dir_id(&self) -> &routing::NameType {
    //     self.info.get_parent_dir_id()
    // }

    pub fn upsert_file(&mut self, file: File) {
        match self.files.iter().position(|entry| entry.get_name() == file.get_name()) {
            Some(pos) => *self.files.get_mut(pos).unwrap() = file,
            None => self.files.push(file),
        }
    }

    pub fn get_files(&self) -> &Vec<File> {
        &self.files
    }

    pub fn get_mut_files(&mut self) -> &mut Vec<File> {
        &mut self.files
    }

    pub fn get_sub_directories(&self) -> &Vec<DirectoryInfo> {
        &self.sub_directories
    }

    pub fn get_mut_sub_directories(&mut self) -> &mut Vec<DirectoryInfo> {
        &mut self.sub_directories
    }

    pub fn get_id(&self) -> &routing::NameType {
        self.info.get_id()
    }

}

impl fmt::Debug for DirectoryListing {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "id: {}, metadata: {}", *self.info.get_id(), *self.info.get_metadata())
    }
}

impl fmt::Display for DirectoryListing {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "id: {}, metadata: {}", *self.info.get_id(), *self.info.get_metadata())
    }
}


#[cfg(test)]
mod test {
    use super::*;
    use cbor;

    #[test]
    fn serialise() {
        let obj_before = DirectoryListing::new("Home".to_string(), "{mime:\"application/json\"}".to_string().into_bytes());

        let mut e = cbor::Encoder::from_memory();
        e.encode(&[&obj_before]).unwrap();

        let mut d = cbor::Decoder::from_bytes(e.as_bytes());
        let obj_after: DirectoryListing = d.decode().next().unwrap().unwrap();

        assert_eq!(obj_before, obj_after);
    }
}
