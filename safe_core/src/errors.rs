// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use config_file_handler;
use futures::sync::mpsc::SendError;
use maidsafe_utilities::serialisation::SerialisationError;
use routing::messaging;
use routing::{ClientError, InterfaceError, RoutingError};
use safe_crypto;
use self_encryption::SelfEncryptionError;
use self_encryption_storage::SelfEncryptionStorageError;
use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};
use std::io;
use std::sync::mpsc;

/// Client Errors
#[cfg_attr(feature = "cargo-clippy", allow(large_enum_variant))]
pub enum CoreError {
    /// Could not Serialise or Deserialise.
    EncodeDecodeError(SerialisationError),
    /// Received unexpected data.
    ReceivedUnexpectedData,
    /// Received unexpected event.
    ReceivedUnexpectedEvent,
    /// No such data found in local version cache.
    VersionCacheMiss,
    /// Cannot overwrite a root directory if it already exists.
    RootDirectoryExists,
    /// Unable to obtain generator for random data.
    RandomDataGenerationFailure,
    /// Forbidden operation.
    OperationForbidden,
    /// Unexpected - Probably a Logic error.
    Unexpected(String),
    /// Routing Error.
    RoutingError(RoutingError),
    /// Interface Error.
    RoutingInterfaceError(InterfaceError),
    /// Routing Client Error.
    RoutingClientError(ClientError),
    /// Blocking operation was cancelled.
    OperationAborted,
    /// MpidMessaging Error.
    MpidMessagingError(messaging::Error),
    /// Error while self-encrypting data.
    SelfEncryption(SelfEncryptionError<SelfEncryptionStorageError>),
    /// The request has timed out.
    RequestTimeout,
    /// Configuration file error.
    ConfigError(config_file_handler::Error),
    /// Io error.
    IoError(io::Error),
    /// Crypto error.
    CryptoError(safe_crypto::Error),
}

impl<'a> From<&'a str> for CoreError {
    fn from(error: &'a str) -> CoreError {
        CoreError::Unexpected(error.to_string())
    }
}

impl From<String> for CoreError {
    fn from(error: String) -> CoreError {
        CoreError::Unexpected(error)
    }
}

impl<T> From<SendError<T>> for CoreError {
    fn from(error: SendError<T>) -> CoreError {
        CoreError::from(format!("Couldn't send message to the channel: {}", error))
    }
}

impl From<SerialisationError> for CoreError {
    fn from(error: SerialisationError) -> CoreError {
        CoreError::EncodeDecodeError(error)
    }
}

impl From<RoutingError> for CoreError {
    fn from(error: RoutingError) -> CoreError {
        CoreError::RoutingError(error)
    }
}

impl From<InterfaceError> for CoreError {
    fn from(error: InterfaceError) -> CoreError {
        CoreError::RoutingInterfaceError(error)
    }
}

impl From<ClientError> for CoreError {
    fn from(error: ClientError) -> CoreError {
        CoreError::RoutingClientError(error)
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

impl From<config_file_handler::Error> for CoreError {
    fn from(error: config_file_handler::Error) -> CoreError {
        CoreError::ConfigError(error)
    }
}

impl From<io::Error> for CoreError {
    fn from(error: io::Error) -> CoreError {
        CoreError::IoError(error)
    }
}

impl From<safe_crypto::Error> for CoreError {
    fn from(error: safe_crypto::Error) -> CoreError {
        CoreError::CryptoError(error)
    }
}

impl Debug for CoreError {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "{} - ", self.description())?;
        match *self {
            CoreError::EncodeDecodeError(ref error) => {
                write!(formatter, "CoreError::EncodeDecodeError -> {:?}", error)
            }
            CoreError::ReceivedUnexpectedData => {
                write!(formatter, "CoreError::ReceivedUnexpectedData")
            }
            CoreError::ReceivedUnexpectedEvent => {
                write!(formatter, "CoreError::ReceivedUnexpectedEvent")
            }
            CoreError::VersionCacheMiss => write!(formatter, "CoreError::VersionCacheMiss"),
            CoreError::RootDirectoryExists => write!(formatter, "CoreError::RootDirectoryExists"),
            CoreError::RandomDataGenerationFailure => {
                write!(formatter, "CoreError::RandomDataGenerationFailure")
            }
            CoreError::OperationForbidden => write!(formatter, "CoreError::OperationForbidden"),
            CoreError::Unexpected(ref error) => {
                write!(formatter, "CoreError::Unexpected::{{{:?}}}", error)
            }
            CoreError::RoutingError(ref error) => {
                write!(formatter, "CoreError::RoutingError -> {:?}", error)
            }
            CoreError::RoutingInterfaceError(ref error) => {
                write!(formatter, "CoreError::RoutingInterfaceError -> {:?}", error)
            }
            CoreError::RoutingClientError(ref error) => {
                write!(formatter, "CoreError::RoutingClientError -> {:?}", error)
            }
            CoreError::OperationAborted => write!(formatter, "CoreError::OperationAborted"),
            CoreError::MpidMessagingError(ref error) => {
                write!(formatter, "CoreError::MpidMessagingError -> {:?}", error)
            }
            CoreError::SelfEncryption(ref error) => {
                write!(formatter, "CoreError::SelfEncryption -> {:?}", error)
            }
            CoreError::RequestTimeout => write!(formatter, "CoreError::RequestTimeout"),
            CoreError::ConfigError(ref error) => {
                write!(formatter, "CoreError::ConfigError -> {:?}", error)
            }
            CoreError::IoError(ref error) => write!(formatter, "CoreError::IoError -> {:?}", error),
            CoreError::CryptoError(ref error) => {
                write!(formatter, "CoreError::CryptoError -> {:?}", error)
            }
        }
    }
}

impl Display for CoreError {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        match *self {
            CoreError::EncodeDecodeError(ref error) => write!(
                formatter,
                "Error while serialising/deserialising: {}",
                error
            ),
            CoreError::ReceivedUnexpectedData => write!(formatter, "Received unexpected data"),
            CoreError::ReceivedUnexpectedEvent => write!(formatter, "Received unexpected event"),
            CoreError::VersionCacheMiss => {
                write!(formatter, "No such data found in local version cache")
            }
            CoreError::RootDirectoryExists => write!(
                formatter,
                "Cannot overwrite a root directory if it already exists"
            ),
            CoreError::RandomDataGenerationFailure => {
                write!(formatter, "Unable to obtain generator for random data")
            }
            CoreError::OperationForbidden => write!(formatter, "Forbidden operation requested"),
            CoreError::Unexpected(ref error) => write!(formatter, "Unexpected: {}", error),
            CoreError::RoutingError(ref error) => {
                // TODO - use `{}` once `RoutingError` implements `std::error::Error`.
                write!(formatter, "Routing internal error: {:?}", error)
            }
            CoreError::RoutingInterfaceError(ref error) => {
                // TODO - use `{}` once `InterfaceError` implements `std::error::Error`.
                write!(formatter, "Routing interface error -> {:?}", error)
            }
            CoreError::RoutingClientError(ref error) => {
                write!(formatter, "Routing client error -> {}", error)
            }
            CoreError::OperationAborted => write!(formatter, "Blocking operation was cancelled"),
            CoreError::MpidMessagingError(ref error) => {
                write!(formatter, "Mpid messaging error: {}", error)
            }
            CoreError::SelfEncryption(ref error) => {
                write!(formatter, "Self-encryption error: {}", error)
            }
            CoreError::RequestTimeout => write!(formatter, "CoreError::RequestTimeout"),
            CoreError::ConfigError(ref error) => write!(formatter, "Config file error: {}", error),
            CoreError::IoError(ref error) => write!(formatter, "Io error: {}", error),
            CoreError::CryptoError(ref error) => write!(formatter, "Crypto error: {}", error),
        }
    }
}

impl Error for CoreError {
    fn description(&self) -> &str {
        match *self {
            CoreError::EncodeDecodeError(_) => "Serialisation error",
            CoreError::ReceivedUnexpectedData => "Received unexpected data",
            CoreError::ReceivedUnexpectedEvent => "Received unexpected event",
            CoreError::VersionCacheMiss => "Version cache miss",
            CoreError::RootDirectoryExists => "Root directory already exists",
            CoreError::RandomDataGenerationFailure => "Cannot obtain RNG",
            CoreError::OperationForbidden => "Operation forbidden",
            CoreError::Unexpected(_) => "Unexpected error",
            // TODO - use `error.description()` once `RoutingError` implements `std::error::Error`.
            CoreError::RoutingError(_) => "Routing internal error",
            // TODO - use `error.description()` once `InterfaceError` implements `std::error::Error`
            CoreError::RoutingClientError(ref error) => error.description(),
            CoreError::RoutingInterfaceError(_) => "Routing interface error",
            CoreError::OperationAborted => "Operation aborted",
            CoreError::MpidMessagingError(_) => "Mpid messaging error",
            CoreError::SelfEncryption(ref error) => error.description(),
            CoreError::RequestTimeout => "Request has timed out",
            CoreError::ConfigError(ref error) => error.description(),
            CoreError::IoError(ref error) => error.description(),
            CoreError::CryptoError(ref error) => error.description(),
        }
    }

    fn cause(&self) -> Option<&Error> {
        match *self {
            CoreError::EncodeDecodeError(ref err) => Some(err),
            CoreError::MpidMessagingError(ref err) => Some(err),
            // CoreError::RoutingError(ref err) => Some(err),
            // CoreError::RoutingInterfaceError(ref err) => Some(err),
            CoreError::RoutingClientError(ref err) => Some(err),
            CoreError::SelfEncryption(ref err) => Some(err),
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
