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

//! Utilities for passing strings across FFI boundaries.

use repr_c::ReprC;
use std::error::Error;
use std::ffi::{CStr, IntoStringError, NulError};
use std::os::raw::c_char;
use std::str::Utf8Error;

impl ReprC for String {
    type C = *const c_char;
    type Error = StringError;

    unsafe fn clone_from_repr_c(c_repr: Self::C) -> Result<String, StringError> {
        Ok(if c_repr.is_null() {
            String::default()
        } else {
            from_c_str(c_repr)?
        })
    }
}

/// Error type for strings
#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
pub enum StringError {
    /// UTF8 error
    Utf8(String),
    /// Null error
    Null(String),
    /// IntoString error
    IntoString(String),
}

impl From<Utf8Error> for StringError {
    fn from(e: Utf8Error) -> Self {
        StringError::Utf8(e.description().to_owned())
    }
}

impl From<NulError> for StringError {
    fn from(e: NulError) -> Self {
        StringError::Null(e.description().to_owned())
    }
}

impl From<IntoStringError> for StringError {
    fn from(e: IntoStringError) -> Self {
        StringError::IntoString(e.description().to_owned())
    }
}

/// Copies memory from a provided pointer and allocates a new `String`.
#[inline]
pub unsafe fn from_c_str(ptr: *const c_char) -> Result<String, StringError> {
    if ptr.is_null() {
        return Err(StringError::Null(
            "String could not be constructed from C null pointer"
                .to_owned(),
        ));
    }
    Ok(CStr::from_ptr(ptr).to_str()?.to_owned())
}
