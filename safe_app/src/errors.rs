// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

//! Errors thrown by App routines.

use bincode::Error as SerialisationError;
use ffi_utils::StringError;
use futures::channel::mpsc::SendError;
use safe_core::ipc::IpcError;
use safe_core::{CoreError, SelfEncryptionStorageError};
use safe_nd::Error as SndError;
use self_encryption::SelfEncryptionError;
use std::ffi::NulError;
use std::fmt::{self, Display, Formatter};
use std::io::Error as IoError;
use std::str::Utf8Error;
use std::sync::mpsc::{RecvError, RecvTimeoutError};
use threshold_crypto::error::FromBytesError;

/// App error.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum AppError {
    /// Error from safe_core.
    CoreError(CoreError),
    /// Error from safe-nd
    SndError(SndError),
    /// IPC error.
    IpcError(IpcError),
    /// Generic encoding / decoding failure.
    EncodeDecodeError,
    /// Forbidden operation.
    OperationForbidden,
    /// Container not found.
    NoSuchContainer(String),
    /// Invalid file mode (e.g. trying to write when file is opened for reading only).
    InvalidFileMode,
    /// Tried to access a client key from an unregistered client.
    UnregisteredClientAccess,

    /// Invalid CipherOpt handle.
    InvalidCipherOptHandle,
    /// Invalid encrypt (threshold_crypto) key handle.
    InvalidEncryptPubKeyHandle,
    /// Invalid secret key handle.
    InvalidEncryptSecKeyHandle,
    /// Invalid MutableData entries handle.
    InvalidMDataEntriesHandle,
    /// Invalid MutableData entry actions handle.
    InvalidMDataEntryActionsHandle,
    /// Invalid MutableData permissions handle.
    InvalidMDataPermissionsHandle,
    /// Invalid Self Encryptor handle.
    InvalidSelfEncryptorHandle,
    /// Invalid public sign key handle.
    InvalidSignPubKeyHandle,
    /// Invalid secret sign key handle.
    InvalidSignSecKeyHandle,
    /// Invalid public key handle.
    InvalidPubKeyHandle,
    /// Invalid file writer handle.
    InvalidFileContextHandle,

    /// Error while self-encrypting data.
    SelfEncryption(SelfEncryptionError<SelfEncryptionStorageError>),
    /// Invalid offsets (from-position and length combination) provided for
    /// reading form SelfEncryptor. Would have probably caused an overflow.
    InvalidSelfEncryptorReadOffsets,
    /// Input/output error.
    IoError(IoError),
    /// Unexpected error.
    Unexpected(String),
}

impl Display for AppError {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        match *self {
            Self::CoreError(ref error) => write!(formatter, "Core error: {}", error),
            Self::SndError(ref error) => write!(formatter, "Safe ND error: {}", error),
            Self::IpcError(ref error) => write!(formatter, "IPC error: {:?}", error),
            // Self::NfsError(ref error) => write!(formatter, "NFS error: {}", error),
            Self::EncodeDecodeError => write!(formatter, "Serialisation error"),
            Self::OperationForbidden => write!(formatter, "Forbidden operation"),
            Self::NoSuchContainer(ref name) => {
                write!(formatter, "'{}' not found in the access container", name)
            }
            Self::InvalidCipherOptHandle => write!(formatter, "Invalid CipherOpt handle"),
            Self::InvalidFileMode => write!(
                formatter,
                "Invalid file mode (e.g. trying to write when file is opened for reading only)"
            ),
            Self::UnregisteredClientAccess => write!(
                formatter,
                "Tried to access a client key from an unregistered client",
            ),
            Self::InvalidEncryptPubKeyHandle => {
                write!(formatter, "Invalid encrypt (threshold_crypto) key handle")
            }
            Self::InvalidMDataEntriesHandle => {
                write!(formatter, "Invalid MutableData entries handle")
            }
            Self::InvalidMDataEntryActionsHandle => {
                write!(formatter, "Invalid MutableData entry actions handle")
            }
            Self::InvalidMDataPermissionsHandle => {
                write!(formatter, "Invalid MutableData permissions handle")
            }
            Self::InvalidSelfEncryptorHandle => write!(formatter, "Invalid Self Encryptor handle"),
            Self::InvalidSignPubKeyHandle => write!(formatter, "Invalid sign public key handle"),
            Self::InvalidSignSecKeyHandle => write!(formatter, "Invalid sign secret key handle"),
            Self::InvalidPubKeyHandle => write!(formatter, "Invalid public key handle"),
            Self::InvalidEncryptSecKeyHandle => write!(formatter, "Invalid secret key handle"),
            Self::InvalidFileContextHandle => write!(formatter, "Invalid file context handle"),
            Self::SelfEncryption(ref error) => {
                write!(formatter, "Self-encryption error: {}", error)
            }
            Self::InvalidSelfEncryptorReadOffsets => write!(
                formatter,
                "Invalid offsets (from-position \
                 and length combination) provided for \
                 reading form SelfEncryptor. Would have \
                 probably caused an overflow."
            ),
            Self::IoError(ref error) => write!(formatter, "I/O error: {}", error),
            Self::Unexpected(ref error) => {
                write!(formatter, "Unexpected (probably a logic error): {}", error)
            }
        }
    }
}

impl From<CoreError> for AppError {
    fn from(err: CoreError) -> Self {
        match err {
            CoreError::Unexpected(reason) => Self::Unexpected(reason),
            _ => Self::CoreError(err),
        }
    }
}

impl From<IpcError> for AppError {
    fn from(err: IpcError) -> Self {
        match err {
            IpcError::EncodeDecodeError => Self::EncodeDecodeError,
            IpcError::Unexpected(reason) => Self::Unexpected(reason),
            _ => Self::IpcError(err),
        }
    }
}

impl From<SerialisationError> for AppError {
    fn from(_err: SerialisationError) -> Self {
        Self::EncodeDecodeError
    }
}

impl From<Utf8Error> for AppError {
    fn from(_err: Utf8Error) -> Self {
        Self::EncodeDecodeError
    }
}

impl From<StringError> for AppError {
    fn from(_err: StringError) -> Self {
        Self::EncodeDecodeError
    }
}

impl From<SelfEncryptionError<SelfEncryptionStorageError>> for AppError {
    fn from(err: SelfEncryptionError<SelfEncryptionStorageError>) -> Self {
        Self::SelfEncryption(err)
    }
}

impl From<IoError> for AppError {
    fn from(err: IoError) -> Self {
        Self::IoError(err)
    }
}

impl From<SndError> for AppError {
    fn from(error: SndError) -> Self {
        Self::SndError(error)
    }
}

impl<'a> From<&'a str> for AppError {
    fn from(s: &'a str) -> Self {
        Self::Unexpected(s.to_string())
    }
}

impl From<String> for AppError {
    fn from(s: String) -> Self {
        Self::Unexpected(s)
    }
}

impl<T: 'static> From<SendError<T>> for AppError {
    fn from(err: SendError<T>) -> Self {
        Self::from(err.to_string())
    }
}

impl From<NulError> for AppError {
    fn from(err: NulError) -> Self {
        Self::from(err.to_string())
    }
}

impl From<RecvError> for AppError {
    fn from(err: RecvError) -> Self {
        Self::from(err.to_string())
    }
}

impl From<RecvTimeoutError> for AppError {
    fn from(err: RecvTimeoutError) -> Self {
        Self::from(err.to_string())
    }
}

impl From<FromBytesError> for AppError {
    fn from(err: FromBytesError) -> Self {
        Self::from(err.to_string())
    }
}
