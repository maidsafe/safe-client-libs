// Copyright 2017 MaidSafe.net limited.
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

use arrays::XorNameArray;

/// FFI-wrapper for `File`.
#[repr(C)]
pub struct File {
    /// File size in bytes.
    pub size: u64,
    /// Creation time (seconds part).
    pub created_sec: i64,
    /// Creation time (nanoseconds part).
    pub created_nsec: u32,
    /// Modification time (seconds part).
    pub modified_sec: i64,
    /// Modification time (nanoseconds part).
    pub modified_nsec: u32,
    /// Pointer to the user metadata.
    pub user_metadata_ptr: *mut u8,
    /// Size of the user metadata.
    pub user_metadata_len: usize,
    /// Capacity of the user metadata (internal field).
    pub user_metadata_cap: usize,
    /// Name of the `ImmutableData` containing the content of this file.
    pub data_map_name: XorNameArray,
}

impl Drop for File {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        let _ = unsafe {
            Vec::from_raw_parts(
                self.user_metadata_ptr,
                self.user_metadata_len,
                self.user_metadata_cap,
            )
        };
    }
}
