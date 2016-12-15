// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net
// Commercial License, version 1.0 or later, or (2) The General Public License
// (GPL), version 3, depending on which licence you accepted on initial access
// to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project
// generally, you agree to be bound by the terms of the MaidSafe Contributor
// Agreement, version 1.0.
// This, along with the Licenses can be found in the root directory of this
// project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network
// Software distributed under the GPL Licence is distributed on an "AS IS"
// BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
//
// Please review the Licences for the specific language governing permissions
// and limitations relating to use of the SAFE Network Software.

use rustc_serialize::{Decodable, Decoder, Encodable, Encoder};
use self_encryption::DataMap;
use time::{self, Timespec, Tm};

/// `FileMetadata` about a File or a Directory
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct FileMetadata {
    name: String,
    size: u64,
    created: Tm,
    modified: Tm,
    user_metadata: Vec<u8>,
    data_map: DataMap,
}

impl FileMetadata {
    /// Create a new instance of FileMetadata
    pub fn new(name: String, user_metadata: Vec<u8>, data_map: DataMap) -> FileMetadata {
        FileMetadata {
            name: name,
            size: data_map.len(),
            created: time::now_utc(),
            modified: time::now_utc(),
            user_metadata: user_metadata,
            data_map: data_map,
        }
    }

    /// Get time of creation
    pub fn created_time(&self) -> &Tm {
        &self.created
    }

    /// Get time of modification
    pub fn modified_time(&self) -> &Tm {
        &self.modified
    }

    /// Get the data-map of the File
    pub fn data_map(&self) -> &DataMap {
        &self.data_map
    }

    /// Get name associated with the structure (file or directory) that this
    /// metadata is a part of
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

    /// Set the data-map of the File
    pub fn set_data_map(&mut self, data_map: DataMap) {
        self.data_map = data_map;
    }

    /// Set name associated with the structure (file or directory)
    pub fn set_name<S>(&mut self, name: S)
        where S: Into<String>
    {
        self.name = name.into();
    }

    /// Set the size of file
    pub fn set_size(&mut self, size: u64) {
        self.size = size;
    }

    /// Set time of creation
    pub fn set_created_time(&mut self, created_time: Tm) {
        self.created = created_time
    }

    /// Set time of modification
    pub fn set_modified_time(&mut self, modified_time: Tm) {
        self.modified = modified_time
    }

    /// User setteble metadata for custom metadata
    pub fn set_user_metadata(&mut self, user_metadata: Vec<u8>) {
        self.user_metadata = user_metadata;
    }
}

impl Encodable for FileMetadata {
    fn encode<E: Encoder>(&self, e: &mut E) -> Result<(), E::Error> {
        let created_time = self.created.to_timespec();
        let modified_time = self.modified.to_timespec();

        e.emit_struct("FileMetadata", 8, |e| {
            e.emit_struct_field("name", 0, |e| self.name.encode(e))?;
            e.emit_struct_field("size", 1, |e| self.size.encode(e))?;
            e.emit_struct_field("created_time_sec", 2, |e| created_time.sec.encode(e))?;
            e.emit_struct_field("created_time_nsec", 3, |e| created_time.nsec.encode(e))?;
            e.emit_struct_field("modified_time_sec", 4, |e| modified_time.sec.encode(e))?;
            e.emit_struct_field("modified_time_nsec", 5, |e| modified_time.nsec.encode(e))?;
            e.emit_struct_field("user_metadata", 6, |e| self.user_metadata.encode(e))?;
            e.emit_struct_field("data_map", 7, |e| self.data_map.encode(e))?;

            Ok(())
        })
    }
}

impl Decodable for FileMetadata {
    fn decode<D: Decoder>(d: &mut D) -> Result<FileMetadata, D::Error> {
        d.read_struct("FileMetadata", 8, |d| {
            Ok(FileMetadata {
                name: d.read_struct_field("name", 0, Decodable::decode)?,
                size: d.read_struct_field("size", 1, Decodable::decode)?,
                created: ::time::at_utc(Timespec {
                    sec: d.read_struct_field("created_time_sec", 2, Decodable::decode)?,
                    nsec: d.read_struct_field("created_time_nsec", 3, Decodable::decode)?,
                }),
                modified: ::time::at_utc(Timespec {
                    sec: d.read_struct_field("modified_time_sec", 4, Decodable::decode)?,
                    nsec: d.read_struct_field("modified_time_nsec", 5, Decodable::decode)?,
                }),
                user_metadata: d.read_struct_field("user_metadata", 6, Decodable::decode)?,
                data_map: d.read_struct_field("data_map", 7, Decodable::decode)?,
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use maidsafe_utilities::serialisation::{deserialise, serialise};
    use self_encryption::DataMap;
    use super::*;

    #[test]
    fn serialise_and_deserialise_file_metadata() {
        let obj_before = FileMetadata::new("hello.txt".to_string(),
                                           "{mime: \"application/json\"}".to_string().into_bytes(),
                                           DataMap::None);
        let serialised_data = unwrap!(serialise(&obj_before));
        let obj_after = unwrap!(deserialise(&serialised_data));
        assert_eq!(obj_before, obj_after);
    }
}
