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

use core::errors::CoreError;
use maidsafe_utilities::serialisation::SerialisationError;
use nfs::errors::{NfsError, NFS_ERROR_START_RANGE};

/// Intended for converting DNS Errors into numeric codes for propagating some error information
/// across FFI boundaries and specially to C.
pub const DNS_ERROR_START_RANGE: i32 = NFS_ERROR_START_RANGE - 500;

/// Safe-Dns specific errors
pub enum DnsError {
    /// Errors from Safe-Client
    CoreError(CoreError),
    /// Errors from Safe-Nfs
    NfsError(NfsError),
    /// Dns record already exists
    DnsNameAlreadyRegistered,
    /// Dns record not found
    DnsRecordNotFound,
    /// Service already exists
    ServiceAlreadyExists,
    /// Service not found
    ServiceNotFound,
    /// Dns Configuration file not found or corrupted
    DnsConfigFileNotFoundOrCorrupted,
    /// Unexpected, probably due to logical error
    Unexpected(String),
    /// Could not serialise or deserialise data
    UnsuccessfulEncodeDecode(SerialisationError),
}

impl From<SerialisationError> for DnsError {
    fn from(error: SerialisationError) -> DnsError {
        DnsError::UnsuccessfulEncodeDecode(error)
    }
}
impl From<CoreError> for DnsError {
    fn from(error: CoreError) -> DnsError {
        DnsError::CoreError(error)
    }
}

impl From<NfsError> for DnsError {
    fn from(error: NfsError) -> DnsError {
        DnsError::NfsError(error)
    }
}

impl<'a> From<&'a str> for DnsError {
    fn from(error: &'a str) -> DnsError {
        DnsError::Unexpected(error.to_string())
    }
}

impl Into<i32> for DnsError {
    fn into(self) -> i32 {
        match self {
            DnsError::CoreError(error) => error.into(),
            DnsError::NfsError(error) => error.into(),
            DnsError::DnsNameAlreadyRegistered => DNS_ERROR_START_RANGE,
            DnsError::DnsRecordNotFound => DNS_ERROR_START_RANGE - 1,
            DnsError::ServiceAlreadyExists => DNS_ERROR_START_RANGE - 2,
            DnsError::ServiceNotFound => DNS_ERROR_START_RANGE - 3,
            DnsError::DnsConfigFileNotFoundOrCorrupted => DNS_ERROR_START_RANGE - 4,
            DnsError::Unexpected(_) => DNS_ERROR_START_RANGE - 5,
            DnsError::UnsuccessfulEncodeDecode(_) => DNS_ERROR_START_RANGE - 6,
        }
    }
}

impl ::std::fmt::Debug for DnsError {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match *self {
            DnsError::CoreError(ref error) => write!(f, "DnsError::CoreError -> {:?}", error),
            DnsError::NfsError(ref error) => write!(f, "DnsError::NfsError -> {:?}", error),
            DnsError::DnsNameAlreadyRegistered => write!(f, "DnsError::DnsNameAlreadyRegistered"),
            DnsError::DnsRecordNotFound => write!(f, "DnsError::DnsRecordNotFound"),
            DnsError::ServiceAlreadyExists => write!(f, "DnsError::ServiceAlreadyExists"),
            DnsError::ServiceNotFound => write!(f, "DnsError::ServiceNotFound"),
            DnsError::DnsConfigFileNotFoundOrCorrupted => {
                write!(f, "DnsError::DnsConfigFileNotFoundOrCorrupted")
            }
            DnsError::Unexpected(ref error) => write!(f, "DnsError::Unexpected::{{{:?}}}", error),
            DnsError::UnsuccessfulEncodeDecode(ref err) => {
                write!(f, "DnsError::UnsuccessfulEncodeDecode -> {:?}", err)
            }
        }
    }
}
