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

use core::SelfEncryptionStorageError;
use maidsafe_utilities::serialisation::SerialisationError;
// use routing::{ClientError, DataIdentifier};
use routing::messaging;
use self_encryption::SelfEncryptionError;
use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};
use std::sync::mpsc;

/// Intended for converting Client Errors into numeric codes for propagating
/// some error information across FFI boundaries and specially to C.
pub const CORE_ERROR_START_RANGE: i32 = -1;

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
    /// Received unexpected data
    ReceivedUnexpectedData,
    /// Received unexpected event
    ReceivedUnexpectedEvent,
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
    /// Unable to complete computation for password hashing - usually because
    /// OS refused to
    /// allocate amount of requested memory
    UnsuccessfulPwHash,
    /// Blocking operation was cancelled
    OperationAborted,
    /// MpidMessaging Error
    MpidMessagingError(messaging::Error),
    /// Error while self-encrypting data
    SelfEncryption(SelfEncryptionError<SelfEncryptionStorageError>),
    /// The request has timed out
    RequestTimeout,
    /// Invalid type tag for StructuredData
    InvalidStructuredDataTypeTag,
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

impl From<SelfEncryptionError<SelfEncryptionStorageError>> for CoreError {
    fn from(error: SelfEncryptionError<SelfEncryptionStorageError>) -> CoreError {
        CoreError::SelfEncryption(error)
    }
}

impl Into<i32> for CoreError {
    fn into(self) -> i32 {
        match self {
            CoreError::StructuredDataHeaderSizeProhibitive => CORE_ERROR_START_RANGE,
            CoreError::UnsuccessfulEncodeDecode(_) => CORE_ERROR_START_RANGE - 1,
            CoreError::AsymmetricDecipherFailure => CORE_ERROR_START_RANGE - 2,
            CoreError::SymmetricDecipherFailure => CORE_ERROR_START_RANGE - 3,
            CoreError::ReceivedUnexpectedData => CORE_ERROR_START_RANGE - 4,
            CoreError::VersionCacheMiss => CORE_ERROR_START_RANGE - 5,
            CoreError::RootDirectoryAlreadyExists => CORE_ERROR_START_RANGE - 6,
            CoreError::RandomDataGenerationFailure => CORE_ERROR_START_RANGE - 7,
            CoreError::OperationForbiddenForClient => CORE_ERROR_START_RANGE - 8,
            CoreError::Unexpected(_) => CORE_ERROR_START_RANGE - 9,
            CoreError::RoutingError(_) => CORE_ERROR_START_RANGE - 10,
            CoreError::RoutingInterfaceError(_) => CORE_ERROR_START_RANGE - 11,
            CoreError::UnsupportedSaltSizeForPwHash => CORE_ERROR_START_RANGE - 12,
            CoreError::UnsuccessfulPwHash => CORE_ERROR_START_RANGE - 13,
            CoreError::OperationAborted => CORE_ERROR_START_RANGE - 14,
            CoreError::MpidMessagingError(_) => CORE_ERROR_START_RANGE - 15,
            // CoreError::GetFailure { reason: GetError::NoSuchAccount, .. } => {
            //     CORE_ERROR_START_RANGE - 16
            // }
            // CoreError::GetFailure { reason: GetError::NoSuchData, .. } => {
            //     CORE_ERROR_START_RANGE - 17
            // }
            // CoreError::GetFailure { reason: GetError::NetworkOther(_), .. } => {
            //     CORE_ERROR_START_RANGE - 18
            // }
            // CoreError::MutationFailure { reason: MutationError::NoSuchAccount, .. } => {
            //     CORE_ERROR_START_RANGE - 19
            // }
            // CoreError::MutationFailure { reason: MutationError::AccountExists, .. } => {
            //     CORE_ERROR_START_RANGE - 20
            // }
            // CoreError::MutationFailure { reason: MutationError::NoSuchData, .. } => {
            //     CORE_ERROR_START_RANGE - 21
            // }
            // CoreError::MutationFailure { reason: MutationError::DataExists, .. } => {
            //     CORE_ERROR_START_RANGE - 22
            // }
            // CoreError::MutationFailure { reason: MutationError::LowBalance, .. } => {
            //     CORE_ERROR_START_RANGE - 23
            // }
            // CoreError::MutationFailure { reason: MutationError::InvalidSuccessor, .. } => {
            //     CORE_ERROR_START_RANGE - 24
            // }
            // CoreError::MutationFailure { reason: MutationError::InvalidOperation, .. } => {
            //     CORE_ERROR_START_RANGE - 25
            // }
            // CoreError::MutationFailure { reason: MutationError::NetworkOther(_), .. } => {
            //     CORE_ERROR_START_RANGE - 26
            // }
            // CoreError::MutationFailure { reason: MutationError::NetworkFull, .. } => {
            //     CORE_ERROR_START_RANGE - 27
            // }
            // CoreError::MutationFailure { reason: MutationError::DataTooLarge, .. } => {
            //     CORE_ERROR_START_RANGE - 28
            // }
            CoreError::SelfEncryption(
                SelfEncryptionError::Compression::<SelfEncryptionStorageError>) => {
                CORE_ERROR_START_RANGE - 29
            }
            CoreError::SelfEncryption(
                SelfEncryptionError::Decryption::<SelfEncryptionStorageError>) => {
                CORE_ERROR_START_RANGE - 30
            }
            CoreError::SelfEncryption(SelfEncryptionError::Io::<SelfEncryptionStorageError>(_)) => {
                CORE_ERROR_START_RANGE - 31
            }
            // CoreError::GetAccountInfoFailure { reason: GetError::NoSuchAccount, .. } => {
            //     CORE_ERROR_START_RANGE - 32
            // }
            // CoreError::GetAccountInfoFailure { .. } => CORE_ERROR_START_RANGE - 33,
            CoreError::RequestTimeout => CORE_ERROR_START_RANGE - 34,
            CoreError::SelfEncryption(
                SelfEncryptionError::Storage::<SelfEncryptionStorageError>(
                    SelfEncryptionStorageError(err))) => (*err).into(),
            CoreError::InvalidStructuredDataTypeTag => CORE_ERROR_START_RANGE - 35,
            CoreError::ReceivedUnexpectedEvent => CORE_ERROR_START_RANGE - 36,
        }
    }
}

impl Debug for CoreError {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "{} - ", self.description())?;
        match *self {
            CoreError::StructuredDataHeaderSizeProhibitive => {
                write!(formatter, "CoreError::StructuredDataHeaderSizeProhibitive")
            }
            CoreError::UnsuccessfulEncodeDecode(ref error) => {
                write!(formatter,
                       "CoreError::UnsuccessfulEncodeDecode -> {:?}",
                       error)
            }
            CoreError::AsymmetricDecipherFailure => {
                write!(formatter, "CoreError::AsymmetricDecipherFailure")
            }
            CoreError::SymmetricDecipherFailure => {
                write!(formatter, "CoreError::SymmetricDecipherFailure")
            }
            CoreError::ReceivedUnexpectedData => {
                write!(formatter, "CoreError::ReceivedUnexpectedData")
            }
            CoreError::ReceivedUnexpectedEvent => {
                write!(formatter, "CoreError::ReceivedUnexpectedEvent")
            }
            CoreError::VersionCacheMiss => write!(formatter, "CoreError::VersionCacheMiss"),
            CoreError::RootDirectoryAlreadyExists => {
                write!(formatter, "CoreError::RootDirectoryAlreadyExists")
            }
            CoreError::RandomDataGenerationFailure => {
                write!(formatter, "CoreError::RandomDataGenerationFailure")
            }
            CoreError::OperationForbiddenForClient => {
                write!(formatter, "CoreError::OperationForbiddenForClient")
            }
            CoreError::Unexpected(ref error) => {
                write!(formatter, "CoreError::Unexpected::{{{:?}}}", error)
            }
            CoreError::RoutingError(ref error) => {
                write!(formatter, "CoreError::RoutingError -> {:?}", error)
            }
            CoreError::RoutingInterfaceError(ref error) => {
                write!(formatter, "CoreError::RoutingInterfaceError -> {:?}", error)
            }
            CoreError::UnsupportedSaltSizeForPwHash => {
                write!(formatter, "CoreError::UnsupportedSaltSizeForPwHash")
            }
            CoreError::UnsuccessfulPwHash => write!(formatter, "CoreError::UnsuccessfulPwHash"),
            CoreError::OperationAborted => write!(formatter, "CoreError::OperationAborted"),
            CoreError::MpidMessagingError(ref error) => {
                write!(formatter, "CoreError::MpidMessagingError -> {:?}", error)
            }
            // CoreError::GetFailure { ref data_id, ref reason } => {
            //     write!(formatter,
            //            "CoreError::GetFailure::{{ reason: {:?}, data_id: {:?}}}",
            //            reason,
            //            data_id)
            // }
            // CoreError::GetAccountInfoFailure { ref reason } => {
            //     write!(formatter,
            //            "CoreError::GetAccountInfoFailure::{{ reason: {:?}}}",
            //            reason)
            // }
            // CoreError::MutationFailure { ref data_id, ref reason } => {
            //     write!(formatter,
            //            "CoreError::MutationFailure::{{ reason: {:?}, data_id: {:?}}}",
            //            reason,
            //            data_id)
            // }
            CoreError::SelfEncryption(ref error) => {
                write!(formatter, "CoreError::SelfEncryption -> {:?}", error)
            }
            CoreError::RequestTimeout => write!(formatter, "CoreError::RequestTimeout"),
            CoreError::InvalidStructuredDataTypeTag => {
                write!(formatter, "CoreError::InvalidStructuredDataTypeTag")
            }
        }
    }
}

impl Display for CoreError {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        match *self {
            CoreError::StructuredDataHeaderSizeProhibitive => {
                write!(formatter,
                       "StructuredData doesn't have enough space available to accommodate user \
                        data")
            }
            CoreError::UnsuccessfulEncodeDecode(ref error) => {
                write!(formatter,
                       "Error while serialising/deserialising: {}",
                       error)
            }
            CoreError::AsymmetricDecipherFailure => {
                write!(formatter, "Asymmetric decryption failed")
            }
            CoreError::SymmetricDecipherFailure => write!(formatter, "Symmetric decryption failed"),
            CoreError::ReceivedUnexpectedData => write!(formatter, "Received unexpected data"),
            CoreError::ReceivedUnexpectedEvent => write!(formatter, "Received unexpected event"),
            CoreError::VersionCacheMiss => {
                write!(formatter, "No such data found in local version cache")
            }
            CoreError::RootDirectoryAlreadyExists => {
                write!(formatter,
                       "Cannot overwrite a root directory if it already exists")
            }
            CoreError::RandomDataGenerationFailure => {
                write!(formatter, "Unable to obtain generator for random data")
            }
            CoreError::OperationForbiddenForClient => {
                write!(formatter, "Forbidden operation requested for this Client")
            }
            CoreError::Unexpected(ref error) => {
                write!(formatter, "Unexpected (probably a logic error): {}", error)
            }
            CoreError::RoutingError(ref error) => {
                // TODO - use `{}` once `RoutingError` implements `std::error::Error`.
                write!(formatter, "Routing internal error: {:?}", error)
            }
            CoreError::RoutingInterfaceError(ref error) => {
                // TODO - use `{}` once `InterfaceError` implements `std::error::Error`.
                write!(formatter, "Routing interface error -> {:?}", error)
            }
            CoreError::UnsupportedSaltSizeForPwHash => {
                write!(formatter,
                       "Unable to pack into or operate with size of Salt")
            }
            CoreError::UnsuccessfulPwHash => {
                write!(formatter,
                       "Unable to complete computation for password hashing")
            }
            CoreError::OperationAborted => write!(formatter, "Blocking operation was cancelled"),
            CoreError::MpidMessagingError(ref error) => {
                write!(formatter, "Mpid messaging error: {}", error)
            }
            // CoreError::GetFailure { ref reason, .. } => {
            //     write!(formatter, "Failed to Get from network: {}", reason)
            // }
            // CoreError::GetAccountInfoFailure { ref reason } => {
            //     write!(formatter,
            //            "Failed to get account info from network: {}",
            //            reason)
            // }
            // CoreError::MutationFailure { ref reason, .. } => {
            //     write!(formatter,
            //            "Failed to Put/Post/Delete on network: {}",
            //            reason)
            // }
            CoreError::SelfEncryption(ref error) => {
                write!(formatter, "Self-encryption error: {}", error)
            }
            CoreError::RequestTimeout => write!(formatter, "CoreError::RequestTimeout"),
            CoreError::InvalidStructuredDataTypeTag => {
                write!(formatter, "CoreError::InvalidStructuredDataTypeTag")
            }
        }
    }
}

impl Error for CoreError {
    fn description(&self) -> &str {
        match *self {
            CoreError::StructuredDataHeaderSizeProhibitive => "SD Header too large",
            CoreError::UnsuccessfulEncodeDecode(_) => "Serialisation error",
            CoreError::AsymmetricDecipherFailure => "Asymmetric decryption failure",
            CoreError::SymmetricDecipherFailure => "Symmetric decryption failure",
            CoreError::ReceivedUnexpectedData => "Received unexpected data",
            CoreError::ReceivedUnexpectedEvent => "Received unexpected event",
            CoreError::VersionCacheMiss => "Version cache miss",
            CoreError::RootDirectoryAlreadyExists => "Root directory already exists",
            CoreError::RandomDataGenerationFailure => "Cannot obtain RNG",
            CoreError::OperationForbiddenForClient => "Operation forbidden",
            CoreError::Unexpected(_) => "Unexpected error",
            // TODO - use `error.description()` once `RoutingError` implements `std::error::Error`.
            CoreError::RoutingError(_) => "Routing internal error",
            // TODO - use `error.description()` once `InterfaceError` implements `std::error::Error`
            CoreError::RoutingInterfaceError(_) => "Routing interface error",
            CoreError::UnsupportedSaltSizeForPwHash => "Unsupported size of salt",
            CoreError::UnsuccessfulPwHash => "Failed while password hashing",
            CoreError::OperationAborted => "Operation aborted",
            CoreError::MpidMessagingError(_) => "Mpid messaging error",
            // CoreError::GetFailure { ref reason, .. } |
            // CoreError::GetAccountInfoFailure { ref reason } => reason.description(),
            // CoreError::MutationFailure { ref reason, .. } => reason.description(),
            CoreError::SelfEncryption(ref error) => error.description(),
            CoreError::RequestTimeout => "Request has timed out",
            CoreError::InvalidStructuredDataTypeTag => "Invalid Structured Data type tag",
        }
    }

    fn cause(&self) -> Option<&Error> {
        match *self {
            // TODO - add `RoutingError` and `InternalError` once they implement `std::error::Error`
            CoreError::UnsuccessfulEncodeDecode(ref error) => Some(error),
            CoreError::MpidMessagingError(ref error) => Some(error),
            // CoreError::GetFailure { ref reason, .. } |
            // CoreError::GetAccountInfoFailure { ref reason } => Some(reason),
            // CoreError::MutationFailure { ref reason, .. } => Some(reason),
            CoreError::SelfEncryption(ref error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    /*
    use core::SelfEncryptionStorageError;
    use rand;
    use routing::{ClientError, DataIdentifier};
    use self_encryption::SelfEncryptionError;
    use super::*;

    #[test]
    fn self_encryption_error() {
        let id = rand::random();
        let core_err_0 = CoreError::MutationFailure {
            data_id: DataIdentifier::Structured(id, 10000),
            reason: MutationError::LowBalance,
        };
        let core_err_1 = CoreError::MutationFailure {
            data_id: DataIdentifier::Structured(id, 10000),
            reason: MutationError::LowBalance,
        };

        let se_err = SelfEncryptionError::Storage(SelfEncryptionStorageError(Box::new(core_err_0)));
        let core_from_se_err = CoreError::from(se_err);

        assert_eq!(Into::<i32>::into(core_err_1),
                   Into::<i32>::into(core_from_se_err));
    }
    */
}
