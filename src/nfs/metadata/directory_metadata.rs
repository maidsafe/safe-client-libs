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

use rustc_serialize::{Decodable, Decoder};

/// Metadata about a File or a Directory
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct DirectoryMetadata {
    name: String,
    created_time: ::time::Tm,
    modified_time: ::time::Tm,
    user_metadata: Vec<u8>,
}

impl DirectoryMetadata {
    /// Create a new instance of Metadata
    pub fn new<S>(name: S, user_metadata: Vec<u8>) -> Self
        where S: Into<String> {
        DirectoryMetadata {
            name: name.into(),
            created_time: ::time::now_utc(),
            modified_time: ::time::now_utc(),
            user_metadata: user_metadata,
        }
    }

    /// Get time of creation
    pub fn created_time(&self) -> &::time::Tm {
        &self.created_time
    }

    /// Get time of modification
    pub fn modified_time(&self) -> &::time::Tm {
        &self.modified_time
    }

    /// Get name associated with the structure (file or directory) that this metadata is a part
    /// of
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get user setteble custom metadata
    pub fn user_metadata(&self) -> &[u8] {
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
}

impl ::rustc_serialize::Encodable for DirectoryMetadata {
    fn encode<E: ::rustc_serialize::Encoder>(&self, e: &mut E) -> Result<(), E::Error> {
        let created_time = self.created_time.to_timespec();
        let modified_time = self.modified_time.to_timespec();

        e.emit_struct("DirectoryMetadata", 6, |e| {
            try!(e.emit_struct_field("name", 0, |e| self.name.encode(e)));
            try!(e.emit_struct_field("created_time_sec", 1, |e| created_time.sec.encode(e)));
            try!(e.emit_struct_field("created_time_nsec", 2, |e| created_time.nsec.encode(e)));
            try!(e.emit_struct_field("modified_time_sec", 3, |e| modified_time.sec.encode(e)));
            try!(e.emit_struct_field("modified_time_nsec", 4, |e| modified_time.nsec.encode(e)));
            try!(e.emit_struct_field("user_metadata", 5, |e| self.user_metadata.encode(e)));

            Ok(())
        })
    }
}

impl Decodable for DirectoryMetadata {
    fn decode<D: Decoder>(d: &mut D) -> Result<DirectoryMetadata, D::Error> {
        d.read_struct("DirectoryMetadata", 6, |d| {
            Ok(DirectoryMetadata {
                name: try!(d.read_struct_field("name", 0, Decodable::decode)),
                created_time: ::time::at_utc(::time::Timespec {
                    sec: try!(d.read_struct_field("created_time_sec", 1, Decodable::decode)),
                    nsec: try!(d.read_struct_field("created_time_nsec", 2, Decodable::decode)),
                }),
                modified_time: ::time::at_utc(::time::Timespec {
                    sec: try!(d.read_struct_field("modified_time_sec", 3, Decodable::decode)),
                    nsec: try!(d.read_struct_field("modified_time_nsec", 4, Decodable::decode)),
                }),
                user_metadata: try!(d.read_struct_field("user_metadata", 5, Decodable::decode)),
            })
        })
    }
}

#[cfg(test)]
mod test {
    use maidsafe_utilities::serialisation::{deserialise, serialise};
    use super::*;

    #[test]
    fn serialise_directory_metadata_without_parent_directory() {
        let obj_before = DirectoryMetadata::new("hello.txt".to_string(),
                                                Vec::new());
        let serialised_data = unwrap!(serialise(&obj_before));
        let obj_after = unwrap!(deserialise(&serialised_data));
        assert_eq!(obj_before, obj_after);
    }

    // TODO (adam): Re-enable this test once its decided how should the parent directory
    // info be stored in DirectoryMetadata (if at all).
    // #[test]
    // fn serialise_directory_metadata_with_parent_directory() {
    //     let id: XorName = rand::random();
    //     let parent_directory = DirectoryKey::new(id, 100u64, false, AccessLevel::Private);
    //     let obj_before = unwrap!(DirectoryMetadata::new("hello.txt".to_string(),
    //                                                     99u64,
    //                                                     true,
    //                                                     AccessLevel::Private,
    //                                                     "Some user metadata"
    //                                                         .to_string()
    //                                                         .into_bytes(),
    //                                                     Some(parent_directory.clone())));
    //     let serialised_data = unwrap!(serialise(&obj_before));
    //     let obj_after: DirectoryMetadata = unwrap!(deserialise(&serialised_data));
    //     assert_eq!(*unwrap!(obj_after.get_parent_dir_key(),
    //                         "Directory should not be None"),
    //                parent_directory);
    // }

    #[test]
    fn update_using_setters() {
        let modified_time = ::time::now_utc();
        let mut obj_before = DirectoryMetadata::new("hello.txt".to_string(),
                                                    Vec::new());
        let user_metadata = "{mime: \"application/json\"}".to_string().into_bytes();
        obj_before.set_user_metadata(user_metadata.clone());
        obj_before.set_modified_time(modified_time);
        obj_before.set_name("index.txt".to_string());
        let serialised_data = unwrap!(serialise(&obj_before));
        let obj_after: DirectoryMetadata = unwrap!(deserialise(&serialised_data));
        assert_eq!(*user_metadata, *obj_after.user_metadata());
        assert_eq!(modified_time, *obj_after.modified_time());
        assert_eq!("index.txt".to_string(), *obj_after.name());
    }
}
