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

use std::fmt;

use core::errors::CoreError;
use dns::errors::{DNS_ERROR_START_RANGE, DnsError};
use maidsafe_utilities::serialisation::SerialisationError;
use nfs::errors::NfsError;
use rustc_serialize::{json, base64};

/// Intended for converting Launcher Errors into numeric codes for propagating some error
/// information across FFI boundaries and specially to C.
pub const FFI_ERROR_START_RANGE: i32 = DNS_ERROR_START_RANGE - 500;

/// Launcher Errors
pub enum FfiError {
    /// Error from safe_core. Boxed to hold a pointer instead of value so that this enum variant is
    /// not insanely bigger than others.
    CoreError(Box<CoreError>),
    /// Errors from safe_nfs
    NfsError(Box<NfsError>),
    /// Errors from safe_nfs
    DnsError(Box<DnsError>),
    /// Unable to find/traverse directory or file path
    PathNotFound,
    /// Supplied path was invalid
    InvalidPath,
    /// Permission denied - e.g. permission to access SAFEDrive etc.
    PermissionDenied,
    /// Could not parse payload as a valid JSON
    JsonParseError(json::ParserError),
    /// Could not decode valid JSON into expected Structures probably because a mandatory field was
    /// missing or a field was wrongly named etc.
    JsonDecodeError(json::DecoderError),
    /// JSON non-conforming to the Launcher RFC and not covered by JsonDecodeError, e.g. things
    /// like invalid base64 formatting, unreasonable/unexpected indexing, ranges etc.
    SpecificParseError(String),
    /// Error encoding into Json String
    JsonEncodeError(json::EncoderError),
    /// Unable to Read from or Write to a Local Config file.
    LocalConfigAccessFailed(String),
    /// Unexpected - Probably a Logic error
    Unexpected(String),
    /// Could not serialise or deserialise data
    UnsuccessfulEncodeDecode(SerialisationError),
}

impl From<SerialisationError> for FfiError {
    fn from(error: SerialisationError) -> FfiError {
        FfiError::UnsuccessfulEncodeDecode(error)
    }
}
impl<'a> From<&'a str> for FfiError {
    fn from(error: &'a str) -> FfiError {
        FfiError::Unexpected(error.to_string())
    }
}

impl From<CoreError> for FfiError {
    fn from(error: CoreError) -> FfiError {
        FfiError::CoreError(Box::new(error))
    }
}

impl From<NfsError> for FfiError {
    fn from(error: NfsError) -> FfiError {
        FfiError::NfsError(Box::new(error))
    }
}

impl From<DnsError> for FfiError {
    fn from(error: DnsError) -> FfiError {
        FfiError::DnsError(Box::new(error))
    }
}

impl From<base64::FromBase64Error> for FfiError {
    fn from(_: base64::FromBase64Error) -> FfiError {
        FfiError::SpecificParseError("Base64 decode error".to_string())
    }
}

impl From<json::ParserError> for FfiError {
    fn from(error: json::ParserError) -> FfiError {
        FfiError::JsonParseError(error)
    }
}

impl From<json::EncoderError> for FfiError {
    fn from(error: json::EncoderError) -> FfiError {
        FfiError::JsonEncodeError(error)
    }
}

impl From<json::DecoderError> for FfiError {
    fn from(error: json::DecoderError) -> FfiError {
        FfiError::JsonDecodeError(error)
    }
}

impl Into<i32> for FfiError {
    fn into(self) -> i32 {
        match self {
            FfiError::CoreError(error) => (*error).into(),
            FfiError::NfsError(error) => (*error).into(),
            FfiError::DnsError(error) => (*error).into(),
            FfiError::PathNotFound => FFI_ERROR_START_RANGE - 1,
            FfiError::InvalidPath => FFI_ERROR_START_RANGE - 2,
            FfiError::PermissionDenied => FFI_ERROR_START_RANGE - 3,
            FfiError::JsonParseError(_) => FFI_ERROR_START_RANGE - 4,
            FfiError::JsonDecodeError(_) => FFI_ERROR_START_RANGE - 5,
            FfiError::SpecificParseError(_) => FFI_ERROR_START_RANGE - 6,
            FfiError::JsonEncodeError(_) => FFI_ERROR_START_RANGE - 7,
            FfiError::LocalConfigAccessFailed(_) => FFI_ERROR_START_RANGE - 8,
            FfiError::Unexpected(_) => FFI_ERROR_START_RANGE - 9,
            FfiError::UnsuccessfulEncodeDecode(_) => FFI_ERROR_START_RANGE - 10,
        }
    }
}

impl fmt::Debug for FfiError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            FfiError::CoreError(ref error) => write!(f, "FfiError::CoreError -> {:?}", error),
            FfiError::NfsError(ref error) => write!(f, "FfiError::NfsError -> {:?}", error),
            FfiError::DnsError(ref error) => write!(f, "FfiError::DnsError -> {:?}", error),
            FfiError::PathNotFound => write!(f, "FfiError::PathNotFound"),
            FfiError::InvalidPath => write!(f, "FfiError::InvalidPath"),
            FfiError::PermissionDenied => write!(f, "FfiError::PermissionDenied"),
            FfiError::JsonParseError(ref error) => {
                write!(f, "FfiError::JsonParseError -> {:?}", error)
            }
            FfiError::JsonDecodeError(ref error) => {
                write!(f, "FfiError::JsonDecodeError -> {:?}", error)
            }
            FfiError::SpecificParseError(ref error) => {
                write!(f, "FfiError::SpecificParseError -> {:?}", error)
            }
            FfiError::JsonEncodeError(ref error) => {
                write!(f, "FfiError::JsonEncodeError -> {:?}", error)
            }
            FfiError::LocalConfigAccessFailed(ref error) => {
                write!(f, "FfiError::LocalConfigAccessFailed -> {:?}", error)
            }
            FfiError::Unexpected(ref error) => write!(f, "FfiError::Unexpected{{{:?}}}", error),
            FfiError::UnsuccessfulEncodeDecode(ref err) => {
                write!(f, "FfiError::UnsuccessfulEncodeDecode -> {:?}", err)
            }
        }
    }
}
