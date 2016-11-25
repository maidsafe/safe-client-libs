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

use routing::{DataIdentifier, XorName};
use rust_sodium::crypto::secretbox;
use rustc_serialize::{Decodable, Decoder};

/// Metadata about a File or a Directory
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct DirMetadata {
    locator: DataIdentifier,
    encrypt_key: Option<secretbox::Key>,
    name: String,
    created: ::time::Tm,
    modified: ::time::Tm,
    user_metadata: Vec<u8>,
}

impl DirMetadata {
    /// Create a new instance of Metadata
    pub fn new<S>(id: XorName,
                  name: S,
                  user_metadata: Vec<u8>,
                  encrypt_key: Option<secretbox::Key>)
                  -> Self
        where S: Into<String>
    {
        DirMetadata {
            locator: DataIdentifier::Structured(id, ::UNVERSIONED_STRUCT_DATA_TYPE_TAG),
            name: name.into(),
            encrypt_key: encrypt_key,
            created: ::time::now_utc(),
            modified: ::time::now_utc(),
            user_metadata: user_metadata,
        }
    }

    /// Get a directory identifier (locator + encryption key)
    pub fn id(&self) -> (DataIdentifier, Option<secretbox::Key>) {
        (self.locator.clone(), self.encrypt_key.clone())
    }

    /// Get directory locator (its XorName and type tag)
    pub fn locator(&self) -> &DataIdentifier {
        &self.locator
    }

    /// Get time of creation
    pub fn created_time(&self) -> &::time::Tm {
        &self.created
    }

    /// Get time of modification
    pub fn modified_time(&self) -> &::time::Tm {
        &self.modified
    }

    /// Get name associated with the structure (file or directory) that this
    /// metadata is a part of
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get user setteble custom metadata
    pub fn user_metadata(&self) -> &[u8] {
        &self.user_metadata
    }

    /// Get the directory encryption key
    pub fn encrypt_key(&self) -> Option<&secretbox::Key> {
        self.encrypt_key.as_ref()
    }

    /// Set name associated with the structure (file or directory) that this
    /// metadata is a part of
    pub fn set_name(&mut self, name: String) {
        self.name = name;
    }

    /// Set time of creation
    pub fn set_created_time(&mut self, created_time: ::time::Tm) {
        self.created = created_time;
    }

    /// Set time of modification
    pub fn set_modified_time(&mut self, modified_time: ::time::Tm) {
        self.modified = modified_time
    }

    /// Setter for user_metadata
    pub fn set_user_metadata(&mut self, user_metadata: Vec<u8>) {
        self.user_metadata = user_metadata;
    }
}

impl ::rustc_serialize::Encodable for DirMetadata {
    fn encode<E: ::rustc_serialize::Encoder>(&self, e: &mut E) -> Result<(), E::Error> {
        let created_time = self.created.to_timespec();
        let modified_time = self.modified.to_timespec();

        e.emit_struct("DirMetadata", 6, |e| {
            e.emit_struct_field("locator", 0, |e| self.locator.encode(e))?;
            e.emit_struct_field("encrypt_key", 1, |e| self.encrypt_key.encode(e))?;
            e.emit_struct_field("name", 2, |e| self.name.encode(e))?;
            e.emit_struct_field("created_time_sec", 3, |e| created_time.sec.encode(e))?;
            e.emit_struct_field("created_time_nsec", 4, |e| created_time.nsec.encode(e))?;
            e.emit_struct_field("modified_time_sec", 5, |e| modified_time.sec.encode(e))?;
            e.emit_struct_field("modified_time_nsec", 6, |e| modified_time.nsec.encode(e))?;
            e.emit_struct_field("user_metadata", 7, |e| self.user_metadata.encode(e))?;

            Ok(())
        })
    }
}

impl Decodable for DirMetadata {
    fn decode<D: Decoder>(d: &mut D) -> Result<DirMetadata, D::Error> {
        d.read_struct("DirMetadata", 8, |d| {
            Ok(DirMetadata {
                locator: d.read_struct_field("locator", 0, Decodable::decode)?,
                encrypt_key: d.read_struct_field("encrypt_key", 1, Decodable::decode)?,
                name: d.read_struct_field("name", 2, Decodable::decode)?,
                created: ::time::at_utc(::time::Timespec {
                    sec: d.read_struct_field("created_time_sec", 3, Decodable::decode)?,
                    nsec: d.read_struct_field("created_time_nsec", 4, Decodable::decode)?,
                }),
                modified: ::time::at_utc(::time::Timespec {
                    sec: d.read_struct_field("modified_time_sec", 5, Decodable::decode)?,
                    nsec: d.read_struct_field("modified_time_nsec", 6, Decodable::decode)?,
                }),
                user_metadata: d.read_struct_field("user_metadata", 7, Decodable::decode)?,
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use maidsafe_utilities::serialisation::{deserialise, serialise};
    use rand;
    use super::*;

    #[test]
    fn serialise_directory_metadata_without_parent_directory() {
        let id = rand::random();
        let obj_before = DirMetadata::new(id, "hello.txt", Vec::new(), None);
        let serialised_data = unwrap!(serialise(&obj_before));
        let obj_after = unwrap!(deserialise(&serialised_data));
        assert_eq!(obj_before, obj_after);
    }

    #[test]
    fn update_using_setters() {
        let modified_time = ::time::now_utc();
        let id = rand::random();
        let mut obj_before = DirMetadata::new(id, "hello.txt", Vec::new(), None);
        let user_metadata = "{mime: \"application/json\"}".to_string().into_bytes();
        obj_before.set_user_metadata(user_metadata.clone());
        obj_before.set_modified_time(modified_time);
        obj_before.set_name("index.txt".to_string());
        let serialised_data = unwrap!(serialise(&obj_before));
        let obj_after: DirMetadata = unwrap!(deserialise(&serialised_data));
        assert_eq!(obj_before, obj_after);
    }
}
