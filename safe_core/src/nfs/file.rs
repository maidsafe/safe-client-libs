// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::ffi::nfs::File as FfiFile;
use crate::nfs::errors::NfsError;
use chrono::{DateTime, NaiveDateTime, Utc};
use ffi_utils::{vec_into_raw_parts, ReprC};
use routing::XorName;
use std::slice;

/// Representation of a File to be put into the network. Could be any kind of
/// file: text, music, video, etc.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct File {
    size: u64,
    created: DateTime<Utc>,
    modified: DateTime<Utc>,
    user_metadata: Vec<u8>,
    data_map_name: XorName,
}

impl File {
    /// Create a new instance of FileMetadata
    pub fn new(user_metadata: Vec<u8>) -> File {
        File {
            size: 0,
            created: Utc::now(),
            modified: Utc::now(),
            user_metadata,
            data_map_name: XorName::default(),
        }
    }

    /// Construct FFI wrapper for the native Rust object, consuming self.
    pub fn into_repr_c(self) -> FfiFile {
        // TODO: move the metadata, not clone.
        let user_metadata = self.user_metadata().to_vec();
        let (user_metadata_ptr, user_metadata_len, user_metadata_cap) =
            vec_into_raw_parts(user_metadata);

        FfiFile {
            size: self.size(),
            created_sec: self.created_time().timestamp(),
            created_nsec: self.created_time().timestamp_subsec_nanos(),
            modified_sec: self.modified_time().timestamp(),
            modified_nsec: self.modified_time().timestamp_subsec_nanos(),
            user_metadata_ptr,
            user_metadata_len,
            user_metadata_cap,
            data_map_name: self.data_map_name().0,
        }
    }

    /// Get time of creation
    pub fn created_time(&self) -> &DateTime<Utc> {
        &self.created
    }

    /// Get time of modification
    pub fn modified_time(&self) -> &DateTime<Utc> {
        &self.modified
    }

    /// Get the network name of the data containing the data-map of the File
    pub fn data_map_name(&self) -> &XorName {
        &self.data_map_name
    }

    /// Get size information
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Get user setteble custom metadata
    pub fn user_metadata(&self) -> &[u8] {
        &self.user_metadata
    }

    /// Set the data-map name of the File
    pub fn set_data_map_name(&mut self, datamap_name: XorName) {
        self.data_map_name = datamap_name;
    }

    /// Set the size of file
    pub fn set_size(&mut self, size: u64) {
        self.size = size;
    }

    /// Set time of creation
    pub fn set_created_time(&mut self, created_time: DateTime<Utc>) {
        self.created = created_time
    }

    /// Set time of modification
    pub fn set_modified_time(&mut self, modified_time: DateTime<Utc>) {
        self.modified = modified_time
    }

    /// User setteble metadata for custom metadata
    pub fn set_user_metadata(&mut self, user_metadata: Vec<u8>) {
        self.user_metadata = user_metadata;
    }
}

impl ReprC for File {
    type C = *const FfiFile;
    type Error = NfsError;

    #[allow(unsafe_code)]
    unsafe fn clone_from_repr_c(repr_c: Self::C) -> Result<Self, Self::Error> {
        let user_metadata =
            slice::from_raw_parts((*repr_c).user_metadata_ptr, (*repr_c).user_metadata_len)
                .to_vec();

        let created = convert_date_time((*repr_c).created_sec, (*repr_c).created_nsec)?;
        let modified = convert_date_time((*repr_c).modified_sec, (*repr_c).modified_nsec)?;

        let mut file = File::new(user_metadata);
        file.set_size((*repr_c).size);
        file.set_created_time(created);
        file.set_modified_time(modified);
        file.set_data_map_name(XorName((*repr_c).data_map_name));

        Ok(file)
    }
}

#[inline]
fn convert_date_time(sec: i64, nsec: u32) -> Result<DateTime<Utc>, NfsError> {
    let naive = NaiveDateTime::from_timestamp_opt(sec, nsec)
        .ok_or_else(|| NfsError::Unexpected("Invalid date format".to_string()))?;
    Ok(DateTime::<Utc>::from_utc(naive, Utc))
}

#[cfg(test)]
mod tests {
    use super::*;
    use maidsafe_utilities::serialisation::{deserialise, serialise};

    // Test that serialising and deserialising a file restores the original file.
    #[test]
    fn serialise_deserialise() {
        let obj_before = File::new("{mime:\"application/json\"}".to_string().into_bytes());
        let serialised_data = unwrap!(serialise(&obj_before));
        let obj_after = unwrap!(deserialise(&serialised_data));
        assert_eq!(obj_before, obj_after);
    }
}
