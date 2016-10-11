// Copyright 2016 MaidSafe.net limited.
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

use rustc_serialize::{Decodable, Decoder, Encodable, Encoder};
use time::{self, Timespec, Tm};

/// FileMetadata about a File or a Directory
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct FileMetadata {
    name: String,
    size: u64,
    created_time: Tm,
    modified_time: Tm,
    user_metadata: Vec<u8>,
    version: u32,
}

impl FileMetadata {
    /// Create a new instance of FileMetadata
    pub fn new(name: String, user_metadata: Vec<u8>) -> FileMetadata {
        FileMetadata {
            name: name,
            size: 0,
            // Version 0 is considered as invalid - do not change to version 0. This is used as
            // default vaule in comparisons.
            version: 1,
            created_time: time::now_utc(),
            modified_time: time::now_utc(),
            user_metadata: user_metadata,
        }
    }

    /// Get version
    pub fn version(&self) -> u32 {
        self.version
    }

    /// Get time of creation
    pub fn created_time(&self) -> &Tm {
        &self.created_time
    }

    /// Get time of modification
    pub fn modified_time(&self) -> &Tm {
        &self.modified_time
    }

    /// Get name associated with the structure (file or directory) that this metadata is a part
    /// of
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get size information
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Get user setteble custom metadata
    pub fn user_metadata(&self) -> &[u8] {
        &self.user_metadata
    }


    /// Set name associated with the structure (file or directory)
    pub fn set_name(&mut self, name: String) {
        self.name = name;
    }

    /// Increment the file version
    pub fn increment_version(&mut self) {
        self.version = self.version.wrapping_add(1);
    }

    /// Set the size of file
    pub fn set_size(&mut self, size: u64) {
        self.size = size;
    }

    /// Set time of modification
    pub fn set_modified_time(&mut self, modified_time: Tm) {
        self.modified_time = modified_time
    }

    /// User setteble metadata for custom metadata
    pub fn set_user_metadata(&mut self, user_metadata: Vec<u8>) {
        self.user_metadata = user_metadata;
    }
}

impl Encodable for FileMetadata {
    fn encode<E: Encoder>(&self, e: &mut E) -> Result<(), E::Error> {
        let created_time = self.created_time.to_timespec();
        let modified_time = self.modified_time.to_timespec();

        e.emit_struct("FileMetadata", 8, |e| {
            try!(e.emit_struct_field("name", 0, |e| self.name.encode(e)));
            try!(e.emit_struct_field("size", 1, |e| self.size.encode(e)));
            try!(e.emit_struct_field("created_time_sec", 2, |e| created_time.sec.encode(e)));
            try!(e.emit_struct_field("created_time_nsec", 3, |e| created_time.nsec.encode(e)));
            try!(e.emit_struct_field("modified_time_sec", 4, |e| modified_time.sec.encode(e)));
            try!(e.emit_struct_field("modified_time_nsec", 5, |e| modified_time.nsec.encode(e)));
            try!(e.emit_struct_field("user_metadata", 6, |e| self.user_metadata.encode(e)));
            try!(e.emit_struct_field("version", 7, |e| self.version.encode(e)));

            Ok(())
        })
    }
}

impl Decodable for FileMetadata {
    fn decode<D: Decoder>(d: &mut D) -> Result<FileMetadata, D::Error> {
        d.read_struct("FileMetadata", 8, |d| {
            Ok(FileMetadata {
                name: try!(d.read_struct_field("name", 0, Decodable::decode)),
                size: try!(d.read_struct_field("size", 1, Decodable::decode)),
                created_time: ::time::at_utc(Timespec {
                    sec: try!(d.read_struct_field("created_time_sec", 2, Decodable::decode)),
                    nsec: try!(d.read_struct_field("created_time_nsec", 3, Decodable::decode)),
                }),
                modified_time: ::time::at_utc(Timespec {
                    sec: try!(d.read_struct_field("modified_time_sec", 4, Decodable::decode)),
                    nsec: try!(d.read_struct_field("modified_time_nsec", 5, Decodable::decode)),
                }),
                user_metadata: try!(d.read_struct_field("user_metadata", 6, Decodable::decode)),
                version: try!(d.read_struct_field("version", 7, Decodable::decode)),
            })
        })
    }
}

#[cfg(test)]
mod test {
    use maidsafe_utilities::serialisation::{deserialise, serialise};
    use super::*;

    #[test]
    fn serialise_and_deserialise_file_metadata() {
        let obj_before = FileMetadata::new("hello.txt".to_string(),
                                           "{mime: \"application/json\"}".to_string().into_bytes());
        let serialised_data = unwrap!(serialise(&obj_before));
        let obj_after = unwrap!(deserialise(&serialised_data));
        assert_eq!(obj_before, obj_after);
    }
}
