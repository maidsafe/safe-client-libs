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


use errors::CoreError;
use maidsafe_utilities::serialisation::SerialisationError;
use self_encryption::SelfEncryptionError;
use self_encryption_storage::SelfEncryptionStorageError;
use std::fmt;

/// NFS Errors
#[cfg_attr(feature="cargo-clippy", allow(large_enum_variant))]
pub enum NfsError {
    /// Client Error
    CoreError(CoreError),
    /// If Directory already exists with the same name in the same level
    DirectoryExists,
    /// Destination is Same as the Source
    DestinationAndSourceAreSame,
    /// Directory not found
    DirectoryNotFound,
    /// File Already exists with the same name in a directory
    FileExists,
    /// File does not match with the existing file in the directory listing
    FileDoesNotMatch,
    /// File not found
    FileNotFound,
    /// Invalid byte range specified
    InvalidRange,
    /// Validation error - if the field passed as parameter is not valid
    InvalidParameter,
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

impl fmt::Debug for NfsError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            NfsError::CoreError(ref error) => write!(f, "NfsError::CoreError -> {:?}", error),
            NfsError::DirectoryExists => write!(f, "NfsError::DirectoryExists"),
            NfsError::DestinationAndSourceAreSame => {
                write!(f, "NfsError::DestinationAndSourceAreSame")
            }
            NfsError::DirectoryNotFound => write!(f, "NfsError::DirectoryNotFound"),
            NfsError::FileExists => write!(f, "NfsError::FileExists"),
            NfsError::FileDoesNotMatch => write!(f, "NfsError::FileDoesNotMatch"),
            NfsError::FileNotFound => write!(f, "NfsError::FileNotFound"),
            NfsError::InvalidRange => write!(f, "NfsError::InvalidRange"),
            NfsError::InvalidParameter => write!(f, "NfsError::InvalidParameter"),
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
