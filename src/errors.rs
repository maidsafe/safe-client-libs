// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

// use crate::self_encryption_storage::SEStorageError;
use bincode::Error as SerialisationError;
use futures::channel::mpsc::SendError;
use qp2p::Error as QuicP2pError;
use sn_data_types::{CmdError, Error as SndError, TransferError};

use std::error::Error as StdError;
use std::fmt::{self, Debug, Display, Formatter};
use std::io;
use std::sync::mpsc;

/// Client Errors
#[allow(clippy::large_enum_variant)]
pub enum ClientError {
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
    // TODO: unused?
    /// No such data found in local version cache.
    VersionCacheMiss,
    // TODO: unused?
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
    /// The request has timed out.
    RequestTimeout,
    /// Configuration file error.
    ConfigError(serde_json::Error),
    /// Io error.
    IoError(io::Error),
    /// QuicP2p error.
    QuicP2p(QuicP2pError),
}

impl<'a> From<&'a str> for ClientError {
    fn from(error: &'a str) -> Self {
        Self::Unexpected(error.to_string())
    }
}

impl From<String> for ClientError {
    fn from(error: String) -> Self {
        Self::Unexpected(error)
    }
}

// impl From<SelfEncryptionError<E>> for ClientError {
//     fn from(error: SelfEncryptionError<E> ) -> Self {
//         Self::from(format!("Self encryption error: {}",error))
//     }
// }

impl From<SendError> for ClientError {
    fn from(error: SendError) -> Self {
        Self::from(format!("Couldn't send message to the channel: {}", error))
    }
}

impl From<SerialisationError> for ClientError {
    fn from(error: SerialisationError) -> Self {
        Self::EncodeDecodeError(error)
    }
}

impl From<SndError> for ClientError {
    fn from(error: SndError) -> Self {
        Self::DataError(error)
    }
}

impl From<mpsc::RecvError> for ClientError {
    fn from(_: mpsc::RecvError) -> Self {
        Self::OperationAborted
    }
}

impl From<io::Error> for ClientError {
    fn from(error: io::Error) -> Self {
        Self::IoError(error)
    }
}

impl From<QuicP2pError> for ClientError {
    fn from(error: QuicP2pError) -> Self {
        Self::QuicP2p(error)
    }
}

impl From<CmdError> for ClientError {
    fn from(error: CmdError) -> Self {
        let err = match error {
            CmdError::Data(data_err) => data_err,
            CmdError::Transfer(err) => match err {
                TransferError::TransferValidation(err) => err,
                TransferError::TransferRegistration(err) => err,
            },
            CmdError::Auth(auth_error) => auth_error,
        };
        Self::DataError(err)
    }
}

impl From<serde_json::error::Error> for ClientError {
    fn from(error: serde_json::error::Error) -> Self {
        use serde_json::error::Category;
        match error.classify() {
            Category::Io => Self::IoError(error.into()),
            Category::Syntax | Category::Data | Category::Eof => Self::ConfigError(error),
        }
    }
}

impl Debug for ClientError {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "{} - ", self.to_string())?;
        match *self {
            Self::EncodeDecodeError(ref error) => {
                write!(formatter, "ClientError::EncodeDecodeError -> {:?}", error)
            }
            Self::AsymmetricDecipherFailure => {
                write!(formatter, "ClientError::AsymmetricDecipherFailure")
            }
            Self::SymmetricDecipherFailure => {
                write!(formatter, "ClientError::SymmetricDecipherFailure")
            }
            Self::ReceivedUnexpectedData => {
                write!(formatter, "ClientError::ReceivedUnexpectedData")
            }
            Self::ReceivedUnexpectedEvent => {
                write!(formatter, "ClientError::ReceivedUnexpectedEvent")
            }
            Self::VersionCacheMiss => write!(formatter, "ClientError::VersionCacheMiss"),
            Self::RootDirectoryExists => write!(formatter, "ClientError::RootDirectoryExists"),
            Self::RandomDataGenerationFailure => {
                write!(formatter, "ClientError::RandomDataGenerationFailure")
            }
            Self::OperationForbidden => write!(formatter, "ClientError::OperationForbidden"),
            Self::Unexpected(ref error) => {
                write!(formatter, "ClientError::Unexpected::{{{:?}}}", error)
            }
            Self::DataError(ref error) => {
                write!(formatter, "ClientError::DataError -> {:?}", error)
            }
            Self::UnsupportedSaltSizeForPwHash => {
                write!(formatter, "ClientError::UnsupportedSaltSizeForPwHash")
            }
            Self::UnsuccessfulPwHash => write!(formatter, "ClientError::UnsuccessfulPwHash"),
            Self::OperationAborted => write!(formatter, "ClientError::OperationAborted"),
            Self::RequestTimeout => write!(formatter, "ClientError::RequestTimeout"),
            Self::ConfigError(ref error) => {
                write!(formatter, "ClientError::ConfigError -> {:?}", error)
            }
            Self::IoError(ref error) => write!(formatter, "ClientError::IoError -> {:?}", error),
            Self::QuicP2p(ref error) => write!(formatter, "ClientError::QuicP2p -> {:?}", error),
        }
    }
}

impl Display for ClientError {
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
            Self::RequestTimeout => write!(formatter, "RequestTimeout"),
            Self::ConfigError(ref error) => write!(formatter, "Config file error: {}", error),
            Self::IoError(ref error) => write!(formatter, "Io error: {}", error),
            Self::QuicP2p(ref error) => write!(formatter, "QuicP2P error: {:?}", error),
        }
    }
}

impl StdError for ClientError {
    fn cause(&self) -> Option<&dyn StdError> {
        match *self {
            Self::EncodeDecodeError(ref err) => Some(err),
            Self::DataError(ref err) => Some(err),
            Self::QuicP2p(ref err) => Some(err),
            _ => None,
        }
    }
}
