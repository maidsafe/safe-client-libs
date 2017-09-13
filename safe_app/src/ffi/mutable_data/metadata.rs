// Copyright 2016 MaidSafe.net limited.
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

//! FFI routines for handling mutable data metadata.

use AppError;
use ffi_utils::{FFI_RESULT_OK, FfiResult, ReprC, catch_unwind_cb};
use maidsafe_utilities::serialisation::serialise;
use safe_core::ffi::ipc::resp::MetadataResponse;
use safe_core::ipc::resp::UserMetadata;
use std::os::raw::c_void;

/// Serialize metadata.
#[no_mangle]
pub unsafe extern "C" fn mdata_encode_metadata(
    metadata: *const MetadataResponse,
    user_data: *mut c_void,
    o_cb: extern "C" fn(*mut c_void, FfiResult, *const u8, usize),
) {
    catch_unwind_cb(user_data, o_cb, || -> Result<_, AppError> {
        let metadata = UserMetadata::clone_from_repr_c(metadata)?;
        let encoded = serialise(&metadata)?;
        o_cb(user_data, FFI_RESULT_OK, encoded.as_ptr(), encoded.len());
        Ok(())
    })
}
