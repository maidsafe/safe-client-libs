// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

// use crate::error_codes::*;
use crate::ffi::error_codes::*;
use crate::self_encryption_storage::SEStorageError;
use bincode::Error as SerialisationError;
use futures::sync::mpsc::SendError;
use quic_p2p::QuicP2pError;
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
    /// Error while self-encrypting data.
    SelfEncryption(SelfEncryptionError<SEStorageError>),
    /// The request has timed out.
    RequestTimeout,
    /// Configuration file error.
    ConfigError(serde_json::Error),
    /// Io error.
    IoError(io::Error),
    /// QuicP2p error.
    QuicP2p(QuicP2pError),
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

impl From<QuicP2pError> for CoreError {
    fn from(error: QuicP2pError) -> Self {
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
        write!(formatter, "{} - ", self.to_string())?;
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

/// Get error code for a CoreError type.
pub fn core_error_code(err: &CoreError) -> i32 {
    match *err {
        CoreError::EncodeDecodeError(_) => ERR_ENCODE_DECODE_ERROR,
        CoreError::AsymmetricDecipherFailure => ERR_ASYMMETRIC_DECIPHER_FAILURE,
        CoreError::SymmetricDecipherFailure => ERR_SYMMETRIC_DECIPHER_FAILURE,
        CoreError::ReceivedUnexpectedData => ERR_RECEIVED_UNEXPECTED_DATA,
        CoreError::ReceivedUnexpectedEvent => ERR_RECEIVED_UNEXPECTED_EVENT,
        CoreError::VersionCacheMiss => ERR_VERSION_CACHE_MISS,
        CoreError::RootDirectoryExists => ERR_ROOT_DIRECTORY_EXISTS,
        CoreError::RandomDataGenerationFailure => ERR_RANDOM_DATA_GENERATION_FAILURE,
        CoreError::OperationForbidden => ERR_OPERATION_FORBIDDEN,
        CoreError::DataError(ref err) => match *err {
            SndError::AccessDenied => ERR_ACCESS_DENIED,
            SndError::NoSuchLoginPacket => ERR_NO_SUCH_LOGIN_PACKET,
            SndError::LoginPacketExists => ERR_LOGIN_PACKET_EXISTS,
            SndError::NoSuchData => ERR_NO_SUCH_DATA,
            SndError::DataExists => ERR_DATA_EXISTS,
            SndError::NoSuchEntry => ERR_NO_SUCH_ENTRY,
            SndError::TooManyEntries => ERR_TOO_MANY_ENTRIES,
            SndError::InvalidEntryActions(_) => ERR_INVALID_ENTRY_ACTIONS,
            SndError::NoSuchKey => ERR_NO_SUCH_KEY,
            SndError::KeysExist(_) => ERR_KEYS_EXIST,
            SndError::DuplicateEntryKeys => ERR_DUPLICATE_ENTRY_KEYS,
            SndError::DuplicateMessageId => ERR_DUPLICATE_MSG_ID,
            SndError::InvalidOwners => ERR_INVALID_OWNERS,
            SndError::InvalidSuccessor(_) => ERR_INVALID_SUCCESSOR,
            SndError::InvalidOperation => ERR_INVALID_OPERATION,
            SndError::NetworkOther(_) => ERR_NETWORK_OTHER,
            SndError::InvalidOwnersSuccessor(_) => ERR_INVALID_OWNERS_SUCCESSOR,
            SndError::InvalidPermissionsSuccessor(_) => ERR_INVALID_PERMISSIONS_SUCCESSOR,
            SndError::SigningKeyTypeMismatch => ERR_SIGN_KEYTYPE_MISMATCH,
            SndError::InvalidSignature => ERR_INVALID_SIGNATURE,
            SndError::LossOfPrecision => ERR_LOSS_OF_PRECISION,
            SndError::ExcessiveValue => ERR_EXCESSIVE_VALUE,
            SndError::NoSuchBalance => ERR_NO_SUCH_BALANCE,
            SndError::BalanceExists => ERR_BALANCE_EXISTS,
            SndError::FailedToParse(_) => ERR_FAILED_TO_PARSE,
            SndError::TransactionIdExists => ERR_TRANSACTION_ID_EXISTS,
            SndError::InsufficientBalance => ERR_INSUFFICIENT_BALANCE,
            SndError::ExceededSize => ERR_EXCEEDED_SIZE,
        },
        CoreError::QuicP2p(ref _err) => ERR_QUIC_P2P, // FIXME: use proper error codes
        CoreError::UnsupportedSaltSizeForPwHash => ERR_UNSUPPORTED_SALT_SIZE_FOR_PW_HASH,
        CoreError::UnsuccessfulPwHash => ERR_UNSUCCESSFUL_PW_HASH,
        CoreError::OperationAborted => ERR_OPERATION_ABORTED,
        CoreError::SelfEncryption(_) => ERR_SELF_ENCRYPTION,
        CoreError::RequestTimeout => ERR_REQUEST_TIMEOUT,
        CoreError::ConfigError(_) => ERR_CONFIG_FILE,
        CoreError::IoError(_) => ERR_IO,
        CoreError::Unexpected(_) => ERR_UNEXPECTED,
    }
}

/// Get error code for a safe_nd Error type.
pub fn safe_nd_error_core(err: &SndError) -> i32 {
    match *err {
        SndError::AccessDenied => ERR_ACCESS_DENIED,
        SndError::NoSuchLoginPacket => ERR_NO_SUCH_LOGIN_PACKET,
        SndError::LoginPacketExists => ERR_LOGIN_PACKET_EXISTS,
        SndError::NoSuchData => ERR_NO_SUCH_DATA,
        SndError::DataExists => ERR_DATA_EXISTS,
        SndError::NoSuchEntry => ERR_NO_SUCH_ENTRY,
        SndError::TooManyEntries => ERR_TOO_MANY_ENTRIES,
        SndError::InvalidEntryActions(_) => ERR_INVALID_ENTRY_ACTIONS,
        SndError::NoSuchKey => ERR_NO_SUCH_KEY,
        SndError::KeysExist(_) => ERR_KEYS_EXIST,
        SndError::DuplicateEntryKeys => ERR_DUPLICATE_ENTRY_KEYS,
        SndError::DuplicateMessageId => ERR_DUPLICATE_MSG_ID,
        SndError::InvalidOwners => ERR_INVALID_OWNERS,
        SndError::InvalidSuccessor(_) => ERR_INVALID_SUCCESSOR,
        SndError::InvalidOperation => ERR_INVALID_OPERATION,
        SndError::NetworkOther(_) => ERR_NETWORK_OTHER,
        SndError::InvalidOwnersSuccessor(_) => ERR_INVALID_OWNERS_SUCCESSOR,
        SndError::InvalidPermissionsSuccessor(_) => ERR_INVALID_PERMISSIONS_SUCCESSOR,
        SndError::SigningKeyTypeMismatch => ERR_SIGN_KEYTYPE_MISMATCH,
        SndError::InvalidSignature => ERR_INVALID_SIGNATURE,
        SndError::LossOfPrecision => ERR_LOSS_OF_PRECISION,
        SndError::ExcessiveValue => ERR_EXCESSIVE_VALUE,
        SndError::NoSuchBalance => ERR_NO_SUCH_BALANCE,
        SndError::BalanceExists => ERR_BALANCE_EXISTS,
        SndError::FailedToParse(_) => ERR_FAILED_TO_PARSE,
        SndError::TransactionIdExists => ERR_TRANSACTION_ID_EXISTS,
        SndError::InsufficientBalance => ERR_INSUFFICIENT_BALANCE,
        SndError::ExceededSize => ERR_EXCEEDED_SIZE,
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
