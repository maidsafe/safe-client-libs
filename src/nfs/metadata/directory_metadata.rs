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

use nfs::AccessLevel;
use nfs::errors::NfsError;
use nfs::metadata::directory_key::DirectoryKey;
use rand::{OsRng, Rand};
use routing::XorName;
use rustc_serialize::{Decodable, Decoder};

/// Metadata about a File or a Directory
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct DirectoryMetadata {
    key: DirectoryKey,
    name: String,
    created_time: ::time::Tm,
    modified_time: ::time::Tm,
    user_metadata: Vec<u8>,
    parent_dir_key: Option<DirectoryKey>,
}

impl DirectoryMetadata {
    /// Create a new instance of Metadata
    pub fn new(name: String,
               type_tag: u64,
               versioned: bool,
               access_level: AccessLevel,
               user_metadata: Vec<u8>,
               parent_dir_key: Option<DirectoryKey>)
               -> Result<DirectoryMetadata, NfsError> {
        let id = Rand::rand(&mut unwrap!(OsRng::new(), "Failed to create OsRng."));
        Ok(DirectoryMetadata {
            key: DirectoryKey::new(id, type_tag, versioned, access_level),
            name: name,
            created_time: ::time::now_utc(),
            modified_time: ::time::now_utc(),
            user_metadata: user_metadata,
            parent_dir_key: parent_dir_key,
        })
    }

    /// Return the id
    pub fn get_id(&self) -> &XorName {
        self.key.get_id()
    }

    /// Return type_tag
    pub fn get_type_tag(&self) -> u64 {
        self.key.get_type_tag()
    }

    /// Returns true if the DirectoryListing is versioned, else returns false
    pub fn is_versioned(&self) -> bool {
        self.key.is_versioned()
    }

    /// Returns the AccessLevel of the DirectoryListing
    pub fn get_access_level(&self) -> &AccessLevel {
        self.key.get_access_level()
    }

    /// Get time of creation
    pub fn get_created_time(&self) -> &::time::Tm {
        &self.created_time
    }

    /// Get time of modification
    pub fn get_modified_time(&self) -> &::time::Tm {
        &self.modified_time
    }

    /// Get name associated with the structure (file or directory) that this metadata is a part
    /// of
    pub fn get_name(&self) -> &str {
        &self.name
    }

    /// Returns the DirectoryKey
    pub fn get_key(&self) -> &DirectoryKey {
        &self.key
    }

    /// Returns the Parent dir id
    pub fn get_parent_dir_key(&self) -> Option<&DirectoryKey> {
        self.parent_dir_key.iter().next()
    }

    /// Get user setteble custom metadata
    pub fn get_user_metadata(&self) -> &[u8] {
        &self.user_metadata
    }

    /// Set name associated with the structure (file or directory) that this metadata is a part
    /// of
    pub fn set_name(&mut self, name: String) {
        self.name = name;
    }

    /// Set time of creation
    pub fn set_created_time(&mut self, created_time: ::time::Tm) {
        self.created_time = created_time;
    }

    /// Set time of modification
    pub fn set_modified_time(&mut self, modified_time: ::time::Tm) {
        self.modified_time = modified_time
    }

    /// Setter for user_metadata
    pub fn set_user_metadata(&mut self, user_metadata: Vec<u8>) {
        self.user_metadata = user_metadata;
    }

    /// Setter for parent_dir_key
    pub fn set_parent_dir_key(&mut self, parent_dir_key: Option<DirectoryKey>) {
        self.parent_dir_key = parent_dir_key;
    }
}

impl ::rustc_serialize::Encodable for DirectoryMetadata {
    fn encode<E: ::rustc_serialize::Encoder>(&self, e: &mut E) -> Result<(), E::Error> {
        let created_time = self.created_time.to_timespec();
        let modified_time = self.modified_time.to_timespec();

        e.emit_struct("DirectoryMetadata", 8, |e| {
            try!(e.emit_struct_field("key", 0, |e| self.key.encode(e)));
            try!(e.emit_struct_field("name", 1, |e| self.name.encode(e)));
            try!(e.emit_struct_field("created_time_sec", 2, |e| created_time.sec.encode(e)));
            try!(e.emit_struct_field("created_time_nsec", 3, |e| created_time.nsec.encode(e)));
            try!(e.emit_struct_field("modified_time_sec", 4, |e| modified_time.sec.encode(e)));
            try!(e.emit_struct_field("modified_time_nsec", 5, |e| modified_time.nsec.encode(e)));
            try!(e.emit_struct_field("user_metadata", 6, |e| self.user_metadata.encode(e)));
            try!(e.emit_struct_field("parent_dir_key", 7, |e| self.parent_dir_key.encode(e)));

            Ok(())
        })
    }
}

impl Decodable for DirectoryMetadata {
    fn decode<D: Decoder>(d: &mut D) -> Result<DirectoryMetadata, D::Error> {
        d.read_struct("DirectoryMetadata", 8, |d| {
            Ok(DirectoryMetadata {
                key: try!(d.read_struct_field("key", 0, Decodable::decode)),
                name: try!(d.read_struct_field("name", 1, Decodable::decode)),
                created_time: ::time::at_utc(::time::Timespec {
                    sec: try!(d.read_struct_field("created_time_sec", 2, Decodable::decode)),
                    nsec: try!(d.read_struct_field("created_time_nsec", 3, Decodable::decode)),
                }),
                modified_time: ::time::at_utc(::time::Timespec {
                    sec: try!(d.read_struct_field("modified_time_sec", 4, Decodable::decode)),
                    nsec: try!(d.read_struct_field("modified_time_nsec", 5, Decodable::decode)),
                }),
                user_metadata: try!(d.read_struct_field("user_metadata", 6, Decodable::decode)),
                parent_dir_key: try!(d.read_struct_field("parent_dir_key", 7, Decodable::decode)),
            })
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rand;
    use routing::XorName;
    use nfs::metadata::directory_key::DirectoryKey;
    use maidsafe_utilities::serialisation::{deserialise, serialise};
    use nfs::AccessLevel;

    #[test]
    fn serialise_directory_metadata_without_parent_directory() {
        let obj_before = unwrap!(DirectoryMetadata::new("hello.txt".to_string(),
                                                        99u64,
                                                        true,
                                                        AccessLevel::Private,
                                                        Vec::new(),
                                                        None));
        let serialised_data = unwrap!(serialise(&obj_before));
        let obj_after = unwrap!(deserialise(&serialised_data));
        assert_eq!(obj_before, obj_after);
    }

    #[test]
    fn serialise_directory_metadata_with_parent_directory() {
        let id: XorName = rand::random();
        let parent_directory = DirectoryKey::new(id, 100u64, false, AccessLevel::Private);
        let obj_before = unwrap!(DirectoryMetadata::new("hello.txt".to_string(),
                                                        99u64,
                                                        true,
                                                        AccessLevel::Private,
                                                        "Some user metadata"
                                                            .to_string()
                                                            .into_bytes(),
                                                        Some(parent_directory.clone())));
        let serialised_data = unwrap!(serialise(&obj_before));
        let obj_after: DirectoryMetadata = unwrap!(deserialise(&serialised_data));
        assert_eq!(*unwrap!(obj_after.get_parent_dir_key(),
                            "Directory should not be None"),
                   parent_directory);
    }

    #[test]
    fn update_using_setters() {
        let id: XorName = rand::random();
        let modified_time = ::time::now_utc();
        let mut obj_before = unwrap!(DirectoryMetadata::new("hello.txt".to_string(),
                                                  99u64,
                                                  true,
                                                  AccessLevel::Private,
                                                  Vec::new(),
                                                  Some(DirectoryKey::new(id,
                                                                         100u64,
                                                                         false,
                                                                         AccessLevel::Private))));
        let user_metadata = "{mime: \"application/json\"}".to_string().into_bytes();
        obj_before.set_user_metadata(user_metadata.clone());
        obj_before.set_modified_time(modified_time);
        obj_before.set_name("index.txt".to_string());
        let serialised_data = unwrap!(serialise(&obj_before));
        let obj_after: DirectoryMetadata = unwrap!(deserialise(&serialised_data));
        assert_eq!(*user_metadata, *obj_after.get_user_metadata());
        assert_eq!(modified_time, *obj_after.get_modified_time());
        assert_eq!("index.txt".to_string(), *obj_after.get_name());
    }
}
