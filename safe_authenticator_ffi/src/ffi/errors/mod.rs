// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

pub mod codes;

pub use crate::ffi::errors::codes::*;
pub use safe_core::ffi::error_codes::*;

use ffi_utils::{ErrorCode, StringError};
use futures::sync::mpsc::SendError;
use safe_authenticator::AuthError;
use safe_core::ipc::IpcError;
use safe_core::nfs::NfsError;
use safe_core::CoreError;
use safe_nd::Error as SndError;
use std::ffi::NulError;
use std::fmt::{self, Display, Formatter};
use std::io::Error as IoError;
use std::str::Utf8Error;
use std::string::FromUtf8Error;
use std::sync::mpsc::RecvError;

/// FFI Result type
pub type Result<T> = std::result::Result<T, Error>;

/// FFI Error type
#[derive(Debug)]
pub struct Error(AuthError);

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Into<IpcError> for Error {
    fn into(self) -> IpcError {
        match self.0 {
            AuthError::Unexpected(desc) => IpcError::Unexpected(desc),
            AuthError::IpcError(err) => err,
            err => IpcError::Unexpected(format!("{:?}", err)),
        }
    }
}

impl From<AuthError> for Error {
    fn from(error: AuthError) -> Self {
        Self(error)
    }
}

impl From<StringError> for Error {
    fn from(_err: StringError) -> Self {
        Self(AuthError::EncodeDecodeError)
    }
}

impl<'a> From<&'a str> for Error {
    fn from(s: &'a str) -> Self {
        Self(AuthError::Unexpected(s.to_string()))
    }
}

impl From<CoreError> for Error {
    fn from(error: CoreError) -> Self {
        Self(AuthError::CoreError(error))
    }
}

impl<T: 'static> From<SendError<T>> for Error {
    fn from(error: SendError<T>) -> Self {
        Self(AuthError::from(error))
    }
}

impl From<IpcError> for Error {
    fn from(error: IpcError) -> Self {
        Self(AuthError::IpcError(error))
    }
}

impl From<RecvError> for Error {
    fn from(error: RecvError) -> Self {
        Self(AuthError::from(error))
    }
}

impl From<NulError> for Error {
    fn from(error: NulError) -> Self {
        Self(AuthError::from(error))
    }
}

impl From<IoError> for Error {
    fn from(error: IoError) -> Self {
        Self(AuthError::IoError(error))
    }
}

impl From<SndError> for Error {
    fn from(error: SndError) -> Self {
        Self(AuthError::SndError(error))
    }
}

impl From<String> for Error {
    fn from(error: String) -> Self {
        Self(AuthError::Unexpected(error))
    }
}

impl From<NfsError> for Error {
    fn from(error: NfsError) -> Self {
        Self(AuthError::NfsError(error))
    }
}

impl From<Utf8Error> for Error {
    fn from(_err: Utf8Error) -> Self {
        Self(AuthError::EncodeDecodeError)
    }
}

impl From<FromUtf8Error> for Error {
    fn from(_err: FromUtf8Error) -> Self {
        Self(AuthError::EncodeDecodeError)
    }
}

impl ErrorCode for Error {
    fn error_code(&self) -> i32 {
        match (*self).0 {
            AuthError::CoreError(ref err) => core_error_code(err),
            AuthError::SndError(ref err) => safe_nd_error_core(err),
            AuthError::IpcError(ref err) => match *err {
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
            AuthError::NfsError(ref err) => match *err {
                NfsError::CoreError(ref err) => core_error_code(err),
                NfsError::FileExists => ERR_FILE_EXISTS,
                NfsError::FileNotFound => ERR_FILE_NOT_FOUND,
                NfsError::InvalidRange => ERR_INVALID_RANGE,
                NfsError::EncodeDecodeError(_) => ERR_ENCODE_DECODE_ERROR,
                NfsError::SelfEncryption(_) => ERR_SELF_ENCRYPTION,
                NfsError::Unexpected(_) => ERR_UNEXPECTED,
            },
            AuthError::EncodeDecodeError => ERR_ENCODE_DECODE_ERROR,
            AuthError::IoError(_) => ERR_IO_ERROR,

            AuthError::AccountContainersCreation(_) => ERR_ACCOUNT_CONTAINERS_CREATION,
            AuthError::NoSuchContainer(_) => ERR_NO_SUCH_CONTAINER,
            AuthError::PendingRevocation => ERR_PENDING_REVOCATION,
            AuthError::Unexpected(_) => ERR_UNEXPECTED,
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
        CoreError::DataError(ref err) => safe_nd_error_core(err),
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
