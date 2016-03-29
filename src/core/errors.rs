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

use std::sync::mpsc;

use routing::{DataRequest, Data};
use safe_network_common::messaging;
use safe_network_common::client_errors::{GetError, MutationError};
use maidsafe_utilities::serialisation::SerialisationError;

/// Intended for converting Client Errors into numeric codes for propagating some error information
/// across FFI boundaries and specially to C.
pub const CLIENT_ERROR_START_RANGE: i32 = -1;

/// Client Errors
pub enum CoreError {
    /// StructuredData has no space available to fit in any user data inside it.
    StructuredDataHeaderSizeProhibitive,
    /// Could not Serialise or Deserialise
    UnsuccessfulEncodeDecode(SerialisationError),
    /// Asymmetric Key Decryption Failed
    AsymmetricDecipherFailure,
    /// Symmetric Key Decryption Failed
    SymmetricDecipherFailure,
    /// ReceivedUnexpectedData
    ReceivedUnexpectedData,
    /// No such data found in local version cache
    VersionCacheMiss,
    /// Cannot overwrite a root directory if it already exists
    RootDirectoryAlreadyExists,
    /// Unable to obtain generator for random data
    RandomDataGenerationFailure,
    /// Forbidden operation requested for this Client
    OperationForbiddenForClient,
    /// Unexpected - Probably a Logic error
    Unexpected(String),
    /// Routing Error
    RoutingError(::routing::RoutingError),
    /// Interface Error
    RoutingInterfaceError(::routing::InterfaceError),
    /// Unable to pack into or operate with size of Salt
    UnsupportedSaltSizeForPwHash,
    /// Unable to complete computation for password hashing - usually because OS refused to
    /// allocate amount of requested memory
    UnsuccessfulPwHash,
    /// Blocking operation was cancelled
    OperationAborted,
    /// MpidMessaging Error
    MpidMessagingError(messaging::Error),
    /// Performing a GET operation failed
    GetFailure {
        /// Orignal request that was made to the network
        request: DataRequest,
        /// Reason for failure
        reason: GetError,
    },
    /// Performing a network mutating operation such as PUT/POST/DELETE failed
    MutationFailure {
        /// Orignal data that was sent to the network
        data: Data,
        /// Reason for failure
        reason: MutationError,
    },
}

impl<'a> From<&'a str> for CoreError {
    fn from(error: &'a str) -> CoreError {
        CoreError::Unexpected(error.to_string())
    }
}

impl From<SerialisationError> for CoreError {
    fn from(error: SerialisationError) -> CoreError {
        CoreError::UnsuccessfulEncodeDecode(error)
    }
}

impl From<::routing::RoutingError> for CoreError {
    fn from(error: ::routing::RoutingError) -> CoreError {
        CoreError::RoutingError(error)
    }
}

impl From<::routing::InterfaceError> for CoreError {
    fn from(error: ::routing::InterfaceError) -> CoreError {
        CoreError::RoutingInterfaceError(error)
    }
}

impl From<mpsc::RecvError> for CoreError {
    fn from(_: mpsc::RecvError) -> CoreError {
        CoreError::OperationAborted
    }
}

impl From<messaging::Error> for CoreError {
    fn from(error: messaging::Error) -> CoreError {
        CoreError::MpidMessagingError(error)
    }
}

impl Into<i32> for CoreError {
    fn into(self) -> i32 {
        match self {
            CoreError::StructuredDataHeaderSizeProhibitive => CLIENT_ERROR_START_RANGE,
            CoreError::UnsuccessfulEncodeDecode(_) => CLIENT_ERROR_START_RANGE - 1,
            CoreError::AsymmetricDecipherFailure => CLIENT_ERROR_START_RANGE - 2,
            CoreError::SymmetricDecipherFailure => CLIENT_ERROR_START_RANGE - 3,
            CoreError::ReceivedUnexpectedData => CLIENT_ERROR_START_RANGE - 4,
            CoreError::VersionCacheMiss => CLIENT_ERROR_START_RANGE - 5,
            CoreError::RootDirectoryAlreadyExists => CLIENT_ERROR_START_RANGE - 6,
            CoreError::RandomDataGenerationFailure => CLIENT_ERROR_START_RANGE - 7,
            CoreError::OperationForbiddenForClient => CLIENT_ERROR_START_RANGE - 8,
            CoreError::Unexpected(_) => CLIENT_ERROR_START_RANGE - 9,
            CoreError::RoutingError(_) => CLIENT_ERROR_START_RANGE - 10,
            CoreError::RoutingInterfaceError(_) => CLIENT_ERROR_START_RANGE - 11,
            CoreError::UnsupportedSaltSizeForPwHash => CLIENT_ERROR_START_RANGE - 12,
            CoreError::UnsuccessfulPwHash => CLIENT_ERROR_START_RANGE - 13,
            CoreError::OperationAborted => CLIENT_ERROR_START_RANGE - 14,
            CoreError::MpidMessagingError(_) => CLIENT_ERROR_START_RANGE - 15,
            CoreError::GetFailure { reason: GetError::NoSuchAccount, .. } => CLIENT_ERROR_START_RANGE - 16,
            CoreError::GetFailure { reason: GetError::NoSuchData, .. } => CLIENT_ERROR_START_RANGE - 17,
            CoreError::GetFailure { reason: GetError::Unknown, .. } => CLIENT_ERROR_START_RANGE - 18,
            CoreError::MutationFailure { reason: MutationError::NoSuchAccount, .. } => CLIENT_ERROR_START_RANGE - 19,
            CoreError::MutationFailure { reason: MutationError::AccountExists, .. } => CLIENT_ERROR_START_RANGE - 20,
            CoreError::MutationFailure { reason: MutationError::NoSuchData, .. } => CLIENT_ERROR_START_RANGE - 21,
            CoreError::MutationFailure { reason: MutationError::DataExists, .. } => CLIENT_ERROR_START_RANGE - 22,
            CoreError::MutationFailure { reason: MutationError::LowBalance, .. } => CLIENT_ERROR_START_RANGE - 23,
            CoreError::MutationFailure { reason: MutationError::InvalidSuccessor, .. } => CLIENT_ERROR_START_RANGE - 24,
            CoreError::MutationFailure { reason: MutationError::InvalidOperation, .. } => CLIENT_ERROR_START_RANGE - 25,
            CoreError::MutationFailure { reason: MutationError::Unknown, .. } => CLIENT_ERROR_START_RANGE - 26,
            CoreError::MutationFailure { reason: MutationError::Timeout, .. } => CLIENT_ERROR_START_RANGE - 27,
        }
    }
}

impl ::std::fmt::Debug for CoreError {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match *self {
            CoreError::StructuredDataHeaderSizeProhibitive => {
                write!(f, "CoreError::StructuredDataHeaderSizeProhibitive")
            }
            CoreError::UnsuccessfulEncodeDecode(ref err) => {
                write!(f, "CoreError::UnsuccessfulEncodeDecode -> {:?}", err)
            }
            CoreError::AsymmetricDecipherFailure => write!(f, "CoreError::AsymmetricDecipherFailure"),
            CoreError::SymmetricDecipherFailure => write!(f, "CoreError::SymmetricDecipherFailure"),
            CoreError::ReceivedUnexpectedData => write!(f, "CoreError::ReceivedUnexpectedData"),
            CoreError::VersionCacheMiss => write!(f, "CoreError::VersionCacheMiss"),
            CoreError::RootDirectoryAlreadyExists => write!(f, "CoreError::RootDirectoryAlreadyExists"),
            CoreError::RandomDataGenerationFailure => write!(f, "CoreError::RandomDataGenerationFailure"),
            CoreError::OperationForbiddenForClient => write!(f, "CoreError::OperationForbiddenForClient"),
            CoreError::Unexpected(ref err) => write!(f, "CoreError::Unexpected::{{{:?}}}", err),
            CoreError::RoutingError(ref err) => write!(f, "CoreError::RoutingError -> {:?}", err),
            CoreError::RoutingInterfaceError(ref err) => write!(f, "CoreError::RoutingInterfaceError -> {:?}", err),
            CoreError::UnsupportedSaltSizeForPwHash => write!(f, "CoreError::UnsupportedSaltSizeForPwHash"),
            CoreError::UnsuccessfulPwHash => write!(f, "CoreError::UnsuccessfulPwHash"),
            CoreError::OperationAborted => write!(f, "CoreError::OperationAborted"),
            CoreError::MpidMessagingError(ref err) => write!(f, "CoreError::MpidMessagingError -> {:?}", err),
            CoreError::GetFailure { ref request, ref reason, } => {
                write!(f,
                       "CoreError::GetFailure::{{ reason: {:?}, request: {:?}}}",
                       reason,
                       request)
            }
            CoreError::MutationFailure { ref data, ref reason, } => {
                write!(f,
                       "CoreError::MutationFailure::{{ reason: {:?}, data: {:?}}}",
                       reason,
                       data)
            }
        }
    }
}
