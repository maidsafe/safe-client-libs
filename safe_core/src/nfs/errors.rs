// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::errors::CoreError;
use crate::self_encryption_storage::SEStorageError;
use bincode::Error as SerialisationError;
use self_encryption::SelfEncryptionError;
use std::fmt;

/// NFS Errors
#[allow(clippy::large_enum_variant)]
pub enum NfsError {
    /// Client Error
    CoreError(CoreError),
    /// File already exists with the same name in a directory
    FileExists,
    /// File not found
    FileNotFound,
    /// Invalid byte range specified
    InvalidRange,
    /// Unexpected error
    Unexpected(String),
    /// Unsuccessful Serialisation or Deserialisation
    EncodeDecodeError(SerialisationError),
    /// Error while self-encrypting/-decrypting data
    SelfEncryption(SelfEncryptionError<SEStorageError>),
}

impl From<CoreError> for NfsError {
    fn from(error: CoreError) -> Self {
        Self::CoreError(error)
    }
}

impl From<SerialisationError> for NfsError {
    fn from(error: SerialisationError) -> Self {
        Self::EncodeDecodeError(error)
    }
}

impl<'a> From<&'a str> for NfsError {
    fn from(error: &'a str) -> Self {
        Self::Unexpected(error.to_string())
    }
}

impl From<SelfEncryptionError<SEStorageError>> for NfsError {
    fn from(error: SelfEncryptionError<SEStorageError>) -> Self {
        Self::SelfEncryption(error)
    }
}

impl fmt::Display for NfsError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::CoreError(ref error) => write!(f, "Client Errror: {}", error),
            Self::FileExists => write!(f, "File already exists with the same name in a directory"),
            Self::FileNotFound => write!(f, "File not found"),

            Self::InvalidRange => write!(f, "Invalid byte range specified"),
            Self::Unexpected(ref error) => write!(f, "Unexpected error - {:?}", error),
            Self::EncodeDecodeError(ref error) => write!(
                f,
                "Unsuccessful Serialisation or Deserialisation: {:?}",
                error
            ),
            Self::SelfEncryption(ref error) => write!(
                f,
                "Error while self-encrypting/-decrypting data: {:?}",
                error
            ),
        }
    }
}

impl fmt::Debug for NfsError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::CoreError(ref error) => write!(f, "NfsError::CoreError -> {:?}", error),
            Self::FileExists => write!(f, "NfsError::FileExists"),
            Self::FileNotFound => write!(f, "NfsError::FileNotFound"),
            Self::InvalidRange => write!(f, "NfsError::InvalidRange"),
            Self::Unexpected(ref error) => write!(f, "NfsError::Unexpected -> {:?}", error),
            Self::EncodeDecodeError(ref error) => {
                write!(f, "NfsError::EncodeDecodeError -> {:?}", error)
            }
            Self::SelfEncryption(ref error) => write!(f, "NfsError::SelfEncrpytion -> {:?}", error),
        }
    }
}
