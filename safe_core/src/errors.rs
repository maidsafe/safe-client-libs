// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::self_encryption_storage::SEStorageError;
use bincode::Error as SerialisationError;
use futures::sync::mpsc::SendError;
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
    /// Error related to the data types.
    DataError(SndError),
    /// Unable to pack into or operate with size of Salt.
    UnsupportedSaltSizeForPwHash,
    /// Unable to complete computation for password hashing - usually because OS
    /// refused to allocate amount of requested memory.
    UnsuccessfulPwHash,
    /// Blocking operation was cancelled.
    OperationAborted,
    /// Error while self-encrypting data.
    SelfEncryption(SelfEncryptionError<SEStorageError>),
    /// The request has timed out.
    RequestTimeout,
    /// Configuration file error.
    ConfigError(serde_json::Error),
    /// Io error.
    IoError(io::Error),
    /// QuicP2p error.
    QuicP2p(quic_p2p::Error),
}

impl<'a> From<&'a str> for CoreError {
    fn from(error: &'a str) -> Self {
        Self::Unexpected(error.to_string())
    }
}

impl From<String> for CoreError {
    fn from(error: String) -> Self {
        Self::Unexpected(error)
    }
}

impl<T> From<SendError<T>> for CoreError {
    fn from(error: SendError<T>) -> Self {
        Self::from(format!("Couldn't send message to the channel: {}", error))
    }
}

impl From<SerialisationError> for CoreError {
    fn from(error: SerialisationError) -> Self {
        Self::EncodeDecodeError(error)
    }
}

impl From<SndError> for CoreError {
    fn from(error: SndError) -> Self {
        Self::DataError(error)
    }
}

impl From<mpsc::RecvError> for CoreError {
    fn from(_: mpsc::RecvError) -> Self {
        Self::OperationAborted
    }
}

impl From<SelfEncryptionError<SEStorageError>> for CoreError {
    fn from(error: SelfEncryptionError<SEStorageError>) -> Self {
        Self::SelfEncryption(error)
    }
}

impl From<io::Error> for CoreError {
    fn from(error: io::Error) -> Self {
        Self::IoError(error)
    }
}

impl From<quic_p2p::Error> for CoreError {
    fn from(error: quic_p2p::Error) -> Self {
        Self::QuicP2p(error)
    }
}

impl From<serde_json::error::Error> for CoreError {
    fn from(error: serde_json::error::Error) -> Self {
        use serde_json::error::Category;
        match error.classify() {
            Category::Io => Self::IoError(error.into()),
            Category::Syntax | Category::Data | Category::Eof => Self::ConfigError(error),
        }
    }
}

impl Debug for CoreError {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "{} - ", self.description())?;
        match *self {
            Self::EncodeDecodeError(ref error) => {
                write!(formatter, "CoreError::EncodeDecodeError -> {:?}", error)
            }
            Self::AsymmetricDecipherFailure => {
                write!(formatter, "CoreError::AsymmetricDecipherFailure")
            }
            Self::SymmetricDecipherFailure => {
                write!(formatter, "CoreError::SymmetricDecipherFailure")
            }
            Self::ReceivedUnexpectedData => write!(formatter, "CoreError::ReceivedUnexpectedData"),
            Self::ReceivedUnexpectedEvent => {
                write!(formatter, "CoreError::ReceivedUnexpectedEvent")
            }
            Self::VersionCacheMiss => write!(formatter, "CoreError::VersionCacheMiss"),
            Self::RootDirectoryExists => write!(formatter, "CoreError::RootDirectoryExists"),
            Self::RandomDataGenerationFailure => {
                write!(formatter, "CoreError::RandomDataGenerationFailure")
            }
            Self::OperationForbidden => write!(formatter, "CoreError::OperationForbidden"),
            Self::Unexpected(ref error) => {
                write!(formatter, "CoreError::Unexpected::{{{:?}}}", error)
            }
            Self::DataError(ref error) => write!(formatter, "CoreError::DataError -> {:?}", error),
            Self::UnsupportedSaltSizeForPwHash => {
                write!(formatter, "CoreError::UnsupportedSaltSizeForPwHash")
            }
            Self::UnsuccessfulPwHash => write!(formatter, "CoreError::UnsuccessfulPwHash"),
            Self::OperationAborted => write!(formatter, "CoreError::OperationAborted"),
            Self::SelfEncryption(ref error) => {
                write!(formatter, "CoreError::SelfEncryption -> {:?}", error)
            }
            Self::RequestTimeout => write!(formatter, "CoreError::RequestTimeout"),
            Self::ConfigError(ref error) => {
                write!(formatter, "CoreError::ConfigError -> {:?}", error)
            }
            Self::IoError(ref error) => write!(formatter, "CoreError::IoError -> {:?}", error),
            Self::QuicP2p(ref error) => write!(formatter, "CoreError::QuicP2p -> {:?}", error),
        }
    }
}

impl Display for CoreError {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        match *self {
            Self::EncodeDecodeError(ref error) => write!(
                formatter,
                "Error while serialising/deserialising: {}",
                error
            ),
            Self::AsymmetricDecipherFailure => write!(formatter, "Asymmetric decryption failed"),
            Self::SymmetricDecipherFailure => write!(formatter, "Symmetric decryption failed"),
            Self::ReceivedUnexpectedData => write!(formatter, "Received unexpected data"),
            Self::ReceivedUnexpectedEvent => write!(formatter, "Received unexpected event"),
            Self::VersionCacheMiss => {
                write!(formatter, "No such data found in local version cache")
            }
            Self::RootDirectoryExists => write!(
                formatter,
                "Cannot overwrite a root directory if it already exists"
            ),
            Self::RandomDataGenerationFailure => {
                write!(formatter, "Unable to obtain generator for random data")
            }
            Self::OperationForbidden => write!(formatter, "Forbidden operation requested"),
            Self::Unexpected(ref error) => write!(formatter, "Unexpected: {}", error),
            Self::DataError(ref error) => write!(formatter, "Data error -> {}", error),
            Self::UnsupportedSaltSizeForPwHash => write!(
                formatter,
                "Unable to pack into or operate with size of Salt"
            ),
            Self::UnsuccessfulPwHash => write!(
                formatter,
                "Unable to complete computation for password hashing"
            ),
            Self::OperationAborted => write!(formatter, "Blocking operation was cancelled"),
            Self::SelfEncryption(ref error) => {
                write!(formatter, "Self-encryption error: {}", error)
            }
            Self::RequestTimeout => write!(formatter, "RequestTimeout"),
            Self::ConfigError(ref error) => write!(formatter, "Config file error: {}", error),
            Self::IoError(ref error) => write!(formatter, "Io error: {}", error),
            Self::QuicP2p(ref error) => write!(formatter, "QuicP2P error: {}", error),
        }
    }
}

impl StdError for CoreError {
    fn description(&self) -> &str {
        match *self {
            Self::EncodeDecodeError(_) => "Serialisation error",
            Self::AsymmetricDecipherFailure => "Asymmetric decryption failure",
            Self::SymmetricDecipherFailure => "Symmetric decryption failure",
            Self::ReceivedUnexpectedData => "Received unexpected data",
            Self::ReceivedUnexpectedEvent => "Received unexpected event",
            Self::VersionCacheMiss => "Version cache miss",
            Self::RootDirectoryExists => "Root directory already exists",
            Self::RandomDataGenerationFailure => "Cannot obtain RNG",
            Self::OperationForbidden => "Operation forbidden",
            Self::Unexpected(_) => "Unexpected error",
            Self::DataError(ref error) => error.description(),
            Self::UnsupportedSaltSizeForPwHash => "Unsupported size of salt",
            Self::UnsuccessfulPwHash => "Failed while password hashing",
            Self::OperationAborted => "Operation aborted",
            Self::SelfEncryption(ref error) => error.description(),
            Self::RequestTimeout => "Request has timed out",
            Self::ConfigError(ref error) => error.description(),
            Self::IoError(ref error) => error.description(),
            Self::QuicP2p(ref error) => error.description(),
        }
    }

    fn cause(&self) -> Option<&dyn StdError> {
        match *self {
            Self::EncodeDecodeError(ref err) => Some(err),
            Self::SelfEncryption(ref err) => Some(err),
            Self::DataError(ref err) => Some(err),
            Self::QuicP2p(ref err) => Some(err),
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
