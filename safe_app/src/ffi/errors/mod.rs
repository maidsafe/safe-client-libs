// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

pub mod codes;

pub use crate::ffi::errors::codes::*;
pub use safe_core::ffi::error_codes::*;

use crate::errors::AppError;
use bincode::Error as SerialisationError;
use ffi_utils::{ErrorCode, StringError};
use futures::sync::mpsc::SendError;
use safe_core::ipc::IpcError;
use safe_core::nfs::NfsError;
use safe_core::{CoreError, SelfEncryptionStorageError};
use safe_nd::Error as SndError;
use self_encryption::SelfEncryptionError;
use std::ffi::NulError;
use std::fmt::{self, Display, Formatter};
use std::io::Error as IoError;
use std::str::Utf8Error;
use std::sync::mpsc::{RecvError, RecvTimeoutError};

/// FFI Result type
pub type Result<T> = std::result::Result<T, Error>;

/// FFI Error type
#[derive(Debug)]
pub struct Error(pub AppError);

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<AppError> for Error {
    fn from(error: AppError) -> Self {
        Self(error)
    }
}

impl From<CoreError> for Error {
    fn from(err: CoreError) -> Self {
        match err {
            CoreError::Unexpected(reason) => Self(AppError::Unexpected(reason)),
            _ => Self(AppError::CoreError(err)),
        }
    }
}

impl From<IpcError> for Error {
    fn from(err: IpcError) -> Self {
        match err {
            IpcError::EncodeDecodeError => Self(AppError::EncodeDecodeError),
            IpcError::Unexpected(reason) => Self(AppError::Unexpected(reason)),
            _ => Self(AppError::IpcError(err)),
        }
    }
}

impl From<NfsError> for Error {
    fn from(err: NfsError) -> Self {
        match err {
            NfsError::CoreError(err) => Self(AppError::CoreError(err)),
            NfsError::EncodeDecodeError(_) => Self(AppError::EncodeDecodeError),
            NfsError::SelfEncryption(err) => Self(AppError::SelfEncryption(err)),
            NfsError::Unexpected(reason) => Self(AppError::Unexpected(reason)),
            _ => Self(AppError::NfsError(err)),
        }
    }
}

impl From<SerialisationError> for Error {
    fn from(_err: SerialisationError) -> Self {
        Self(AppError::EncodeDecodeError)
    }
}

impl From<Utf8Error> for Error {
    fn from(_err: Utf8Error) -> Self {
        Self(AppError::EncodeDecodeError)
    }
}

impl From<StringError> for Error {
    fn from(_err: StringError) -> Self {
        Self(AppError::EncodeDecodeError)
    }
}

impl From<SelfEncryptionError<SelfEncryptionStorageError>> for Error {
    fn from(err: SelfEncryptionError<SelfEncryptionStorageError>) -> Self {
        Self(AppError::SelfEncryption(err))
    }
}

impl From<IoError> for Error {
    fn from(err: IoError) -> Self {
        Self(AppError::IoError(err))
    }
}

impl<'a> From<&'a str> for Error {
    fn from(s: &'a str) -> Self {
        Self(AppError::Unexpected(s.to_string()))
    }
}

impl From<String> for Error {
    fn from(s: String) -> Self {
        Self(AppError::Unexpected(s))
    }
}

impl<T: 'static> From<SendError<T>> for Error {
    fn from(err: SendError<T>) -> Self {
        Self(AppError::from(err))
    }
}

impl From<NulError> for Error {
    fn from(err: NulError) -> Self {
        Self(AppError::from(err))
    }
}

impl From<RecvError> for Error {
    fn from(err: RecvError) -> Self {
        Self(AppError::from(err))
    }
}

impl From<RecvTimeoutError> for Error {
    fn from(_err: RecvTimeoutError) -> Self {
        // TODO: change this to err.description() once that lands in stable.
        Self(AppError::from("mpsc receive error"))
    }
}

impl ErrorCode for Error {
    fn error_code(&self) -> i32 {
        match (*self).0 {
            AppError::CoreError(ref err) => core_error_code(err),
            AppError::SndError(ref err) => safe_nd_error_core(err),
            AppError::IpcError(ref err) => match *err {
                IpcError::AuthDenied => ERR_AUTH_DENIED,
                IpcError::ContainersDenied => ERR_CONTAINERS_DENIED,
                IpcError::InvalidMsg => ERR_INVALID_MSG,
                IpcError::EncodeDecodeError => ERR_ENCODE_DECODE_ERROR,
                IpcError::AlreadyAuthorised => ERR_ALREADY_AUTHORISED,
                IpcError::UnknownApp => ERR_UNKNOWN_APP,
                IpcError::Unexpected(_) => ERR_UNEXPECTED,
                IpcError::StringError(_) => ERR_STRING_ERROR,
                IpcError::ShareMDataDenied => ERR_SHARE_MDATA_DENIED,
                IpcError::InvalidOwner(..) => ERR_INVALID_OWNER,
                IpcError::IncompatibleMockStatus => ERR_INCOMPATIBLE_MOCK_STATUS,
            },
            AppError::NfsError(ref err) => match *err {
                NfsError::CoreError(ref err) => core_error_code(err),
                NfsError::FileExists => ERR_FILE_EXISTS,
                NfsError::FileNotFound => ERR_FILE_NOT_FOUND,
                NfsError::InvalidRange => ERR_INVALID_RANGE,
                NfsError::EncodeDecodeError(_) => ERR_ENCODE_DECODE_ERROR,
                NfsError::SelfEncryption(_) => ERR_SELF_ENCRYPTION,
                NfsError::Unexpected(_) => ERR_UNEXPECTED,
            },
            AppError::EncodeDecodeError => ERR_ENCODE_DECODE_ERROR,
            AppError::OperationForbidden => ERR_OPERATION_FORBIDDEN,
            AppError::NoSuchContainer(_) => ERR_NO_SUCH_CONTAINER,
            AppError::InvalidCipherOptHandle => ERR_INVALID_CIPHER_OPT_HANDLE,
            AppError::InvalidEncryptPubKeyHandle => ERR_INVALID_ENCRYPT_PUB_KEY_HANDLE,
            AppError::InvalidMDataEntriesHandle => ERR_INVALID_MDATA_ENTRIES_HANDLE,
            AppError::InvalidMDataEntryActionsHandle => ERR_INVALID_MDATA_ENTRY_ACTIONS_HANDLE,
            AppError::InvalidMDataPermissionsHandle => ERR_INVALID_MDATA_PERMISSIONS_HANDLE,
            AppError::InvalidSelfEncryptorHandle => ERR_INVALID_SELF_ENCRYPTOR_HANDLE,
            AppError::InvalidSignPubKeyHandle => ERR_INVALID_SIGN_PUB_KEY_HANDLE,
            AppError::InvalidSignSecKeyHandle => ERR_INVALID_SIGN_SEC_KEY_HANDLE,
            AppError::InvalidEncryptSecKeyHandle => ERR_INVALID_ENCRYPT_SEC_KEY_HANDLE,
            AppError::InvalidPubKeyHandle => ERR_INVALID_PUB_KEY_HANDLE,
            AppError::InvalidFileContextHandle => ERR_INVALID_FILE_CONTEXT_HANDLE,
            AppError::InvalidFileMode => ERR_INVALID_FILE_MODE,
            AppError::UnregisteredClientAccess => ERR_UNREGISTERED_CLIENT_ACCESS,
            AppError::SelfEncryption(_) => ERR_SELF_ENCRYPTION,
            AppError::InvalidSelfEncryptorReadOffsets => ERR_INVALID_SELF_ENCRYPTOR_READ_OFFSETS,
            AppError::IoError(_) => ERR_IO_ERROR,
            AppError::Unexpected(_) => ERR_UNEXPECTED,
        }
    }
}

fn safe_nd_error_core(err: &SndError) -> i32 {
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

fn core_error_code(err: &CoreError) -> i32 {
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
