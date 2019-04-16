// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use errors::CoreError;
use maidsafe_utilities::serialisation::SerialisationError;
use self_encryption::SelfEncryptionError;
use self_encryption_storage::SelfEncryptionStorageError;
use std::fmt;

/// NFS Errors
#[cfg_attr(feature = "cargo-clippy", allow(clippy::large_enum_variant))]
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
    SelfEncryption(SelfEncryptionError<SelfEncryptionStorageError>),
}

impl From<CoreError> for NfsError {
    fn from(error: CoreError) -> NfsError {
        NfsError::CoreError(error)
    }
}

impl From<SerialisationError> for NfsError {
    fn from(error: SerialisationError) -> NfsError {
        NfsError::EncodeDecodeError(error)
    }
}

impl<'a> From<&'a str> for NfsError {
    fn from(error: &'a str) -> NfsError {
        NfsError::Unexpected(error.to_string())
    }
}

impl From<SelfEncryptionError<SelfEncryptionStorageError>> for NfsError {
    fn from(error: SelfEncryptionError<SelfEncryptionStorageError>) -> NfsError {
        NfsError::SelfEncryption(error)
    }
}

impl fmt::Display for NfsError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            NfsError::CoreError(ref error) => write!(f, "Client Errror: {}", error),
            NfsError::FileExists => {
                write!(f, "File already exists with the same name in a directory")
            }
            NfsError::FileNotFound => write!(f, "File not found"),

            NfsError::InvalidRange => write!(f, "Invalid byte range specified"),
            NfsError::Unexpected(ref error) => write!(f, "Unexpected error - {:?}", error),
            NfsError::EncodeDecodeError(ref error) => write!(
                f,
                "Unsuccessful Serialisation or Deserialisation: {:?}",
                error
            ),
            NfsError::SelfEncryption(ref error) => write!(
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
            NfsError::CoreError(ref error) => write!(f, "NfsError::CoreError -> {:?}", error),
            NfsError::FileExists => write!(f, "NfsError::FileExists"),
            NfsError::FileNotFound => write!(f, "NfsError::FileNotFound"),
            NfsError::InvalidRange => write!(f, "NfsError::InvalidRange"),
            NfsError::Unexpected(ref error) => write!(f, "NfsError::Unexpected -> {:?}", error),
            NfsError::EncodeDecodeError(ref error) => {
                write!(f, "NfsError::EncodeDecodeError -> {:?}", error)
            }
            NfsError::SelfEncryption(ref error) => {
                write!(f, "NfsError::SelfEncrpytion -> {:?}", error)
            }
        }
    }
}
