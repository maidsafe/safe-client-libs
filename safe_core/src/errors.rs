// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::self_encryption_storage::SelfEncryptionStorageError;
use config_file_handler;
use futures::sync::mpsc::SendError;
use maidsafe_utilities::serialisation::SerialisationError;
use routing::messaging;
use routing::{ClientError, InterfaceError, RoutingError};
use safe_nd::Error as SndError;
use self_encryption::SelfEncryptionError;
use std::error::Error as StdError;
use std::fmt::{self, Debug, Display, Formatter};
use std::io;
use std::sync::mpsc;

/// Client Errors
#[allow(clippy::large_enum_variant)]
pub enum CoreError {
    /// Could not Serialise or Deserialise.
    EncodeDecodeError(SerialisationError),
    /// Asymmetric Key Decryption Failed.
    AsymmetricDecipherFailure,
    /// Symmetric Key Decryption Failed.
    SymmetricDecipherFailure,
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
    /// Routing Client Error.
    NewRoutingClientError(SndError),
    /// Unable to pack into or operate with size of Salt.
    UnsupportedSaltSizeForPwHash,
    /// Unable to complete computation for password hashing - usually because OS
    /// refused to allocate amount of requested memory.
    UnsuccessfulPwHash,
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
    /// QuicP2p error.
    QuicP2p(quic_p2p::Error),
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

impl From<SndError> for CoreError {
    fn from(error: SndError) -> CoreError {
        CoreError::NewRoutingClientError(error)
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
    fn from(error: io::Error) -> Self {
        CoreError::IoError(error)
    }
}

impl From<quic_p2p::Error> for CoreError {
    fn from(error: quic_p2p::Error) -> Self {
        CoreError::QuicP2p(error)
    }
}

impl From<serde_json::error::Error> for CoreError {
    fn from(error: serde_json::error::Error) -> Self {
        CoreError::Unexpected(format!("{}", error))
    }
}

impl Debug for CoreError {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "{} - ", self.description())?;
        match *self {
            CoreError::EncodeDecodeError(ref error) => {
                write!(formatter, "CoreError::EncodeDecodeError -> {:?}", error)
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
            CoreError::NewRoutingClientError(ref error) => {
                write!(formatter, "CoreError::NewRoutingClientError -> {:?}", error)
            }
            CoreError::UnsupportedSaltSizeForPwHash => {
                write!(formatter, "CoreError::UnsupportedSaltSizeForPwHash")
            }
            CoreError::UnsuccessfulPwHash => write!(formatter, "CoreError::UnsuccessfulPwHash"),
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
            CoreError::QuicP2p(ref error) => write!(formatter, "CoreError::QuicP2p -> {:?}", error),
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
            CoreError::AsymmetricDecipherFailure => {
                write!(formatter, "Asymmetric decryption failed")
            }
            CoreError::SymmetricDecipherFailure => write!(formatter, "Symmetric decryption failed"),
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
            CoreError::NewRoutingClientError(ref error) => {
                write!(formatter, "New Routing client error -> {}", error)
            }
            CoreError::UnsupportedSaltSizeForPwHash => write!(
                formatter,
                "Unable to pack into or operate with size of Salt"
            ),
            CoreError::UnsuccessfulPwHash => write!(
                formatter,
                "Unable to complete computation for password hashing"
            ),
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
            CoreError::QuicP2p(ref error) => write!(formatter, "QuicP2P error: {}", error),
        }
    }
}

impl StdError for CoreError {
    fn description(&self) -> &str {
        match *self {
            CoreError::EncodeDecodeError(_) => "Serialisation error",
            CoreError::AsymmetricDecipherFailure => "Asymmetric decryption failure",
            CoreError::SymmetricDecipherFailure => "Symmetric decryption failure",
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
            CoreError::NewRoutingClientError(ref error) => error.description(),
            CoreError::RoutingInterfaceError(_) => "Routing interface error",
            CoreError::UnsupportedSaltSizeForPwHash => "Unsupported size of salt",
            CoreError::UnsuccessfulPwHash => "Failed while password hashing",
            CoreError::OperationAborted => "Operation aborted",
            CoreError::MpidMessagingError(_) => "Mpid messaging error",
            CoreError::SelfEncryption(ref error) => error.description(),
            CoreError::RequestTimeout => "Request has timed out",
            CoreError::ConfigError(ref error) => error.description(),
            CoreError::IoError(ref error) => error.description(),
            CoreError::QuicP2p(ref error) => error.description(),
        }
    }

    fn cause(&self) -> Option<&dyn StdError> {
        match *self {
            CoreError::EncodeDecodeError(ref err) => Some(err),
            CoreError::MpidMessagingError(ref err) => Some(err),
            // CoreError::RoutingError(ref err) => Some(err),
            // CoreError::RoutingInterfaceError(ref err) => Some(err),
            CoreError::RoutingClientError(ref err) => Some(err),
            CoreError::SelfEncryption(ref err) => Some(err),
            CoreError::QuicP2p(ref err) => Some(err),
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
