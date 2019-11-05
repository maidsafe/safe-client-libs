// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

pub use self::codes::*;
use config_file_handler::Error as ConfigFileHandlerError;
use ffi_utils::{ErrorCode, StringError};
use futures::sync::mpsc::SendError;
use maidsafe_utilities::serialisation::SerialisationError;
pub use safe_core::ffi::errors::shared_codes::*;
use safe_core::ipc::IpcError;
use safe_core::nfs::NfsError;
use safe_core::CoreError;
use safe_nd::Error as SndError;
use std::error::Error;
use std::ffi::NulError;
use std::fmt::{self, Display, Formatter};
use std::io::Error as IoError;
use std::str::Utf8Error;
use std::string::FromUtf8Error;
use std::sync::mpsc::RecvError;

#[allow(missing_docs)]
mod codes {
    // Data type errors
    pub const ERR_ACCESS_DENIED: i32 = -100;
    pub const ERR_NO_SUCH_DATA: i32 = -101;
    pub const ERR_DATA_EXISTS: i32 = -102;
    pub const ERR_NO_SUCH_ENTRY: i32 = -103;
    pub const ERR_TOO_MANY_ENTRIES: i32 = -104;
    pub const ERR_NO_SUCH_KEY: i32 = -105;
    pub const ERR_INVALID_OWNERS: i32 = -106;
    pub const ERR_INVALID_SUCCESSOR: i32 = -107;
    pub const ERR_INVALID_OPERATION: i32 = -108;
    pub const ERR_NETWORK_OTHER: i32 = -109;
    pub const ERR_INVALID_ENTRY_ACTIONS: i32 = -110;
    pub const ERR_DUPLICATE_MSG_ID: i32 = -111;
    pub const ERR_DUPLICATE_ENTRY_KEYS: i32 = -112;
    pub const ERR_KEYS_EXIST: i32 = -113;

    // Authenticator errors.
    pub const ERR_ACCOUNT_CONTAINERS_CREATION: i32 = -1014;
    pub const ERR_NO_SUCH_CONTAINER: i32 = -1015;
    pub const ERR_PENDING_REVOCATION: i32 = -1016;
}

/// Authenticator errors.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum AuthError {
    /// Unexpected - probably a logic error.
    Unexpected(String),
    /// Error from safe_core.
    CoreError(CoreError),
    /// Error from safe-nd
    SndError(SndError),
    /// Input/output error.
    IoError(IoError),
    /// NFS error
    NfsError(NfsError),
    /// Serialisation error.
    EncodeDecodeError,
    /// IPC error.
    IpcError(IpcError),

    /// Failure during the creation of standard account containers.
    AccountContainersCreation(String),
    /// Failure due to the attempted creation of an invalid container.
    NoSuchContainer(String),
    /// Couldn't authenticate app that is pending revocation.
    PendingRevocation,
}

impl Display for AuthError {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        match *self {
            Self::Unexpected(ref error) => {
                write!(formatter, "Unexpected (probably a logic error): {}", error)
            }
            Self::CoreError(ref error) => write!(formatter, "Core error: {}", error),
            Self::SndError(ref error) => write!(formatter, "Safe ND error: {}", error),
            Self::IoError(ref error) => write!(formatter, "I/O error: {}", error),
            Self::NfsError(ref error) => write!(formatter, "NFS error: {:?}", error),
            Self::EncodeDecodeError => write!(formatter, "Serialisation error"),
            Self::IpcError(ref error) => write!(formatter, "IPC error: {:?}", error),

            Self::AccountContainersCreation(ref reason) => write!(
                formatter,
                "Account containers creation error: {}. Login to attempt recovery.",
                reason
            ),
            Self::NoSuchContainer(ref name) => {
                write!(formatter, "'{}' not found in the access container", name)
            }
            Self::PendingRevocation => write!(
                formatter,
                "Couldn't authenticate app that is pending revocation"
            ),
        }
    }
}

impl Into<IpcError> for AuthError {
    fn into(self) -> IpcError {
        match self {
            Self::Unexpected(desc) => IpcError::Unexpected(desc),
            Self::IpcError(err) => err,
            err => IpcError::Unexpected(format!("{:?}", err)),
        }
    }
}

impl<T: 'static> From<SendError<T>> for AuthError {
    fn from(error: SendError<T>) -> Self {
        Self::Unexpected(error.description().to_owned())
    }
}

impl From<ConfigFileHandlerError> for AuthError {
    fn from(error: ConfigFileHandlerError) -> Self {
        Self::from(error.to_string())
    }
}

impl From<CoreError> for AuthError {
    fn from(error: CoreError) -> Self {
        Self::CoreError(error)
    }
}

impl From<IpcError> for AuthError {
    fn from(error: IpcError) -> Self {
        Self::IpcError(error)
    }
}

impl From<RecvError> for AuthError {
    fn from(error: RecvError) -> Self {
        Self::from(error.description())
    }
}

impl From<NulError> for AuthError {
    fn from(error: NulError) -> Self {
        Self::from(error.description())
    }
}

impl From<IoError> for AuthError {
    fn from(error: IoError) -> Self {
        Self::IoError(error)
    }
}

impl From<SndError> for AuthError {
    fn from(error: SndError) -> Self {
        Self::SndError(error)
    }
}

impl<'a> From<&'a str> for AuthError {
    fn from(error: &'a str) -> Self {
        Self::Unexpected(error.to_owned())
    }
}

impl From<String> for AuthError {
    fn from(error: String) -> Self {
        Self::Unexpected(error)
    }
}

impl From<NfsError> for AuthError {
    fn from(error: NfsError) -> Self {
        Self::NfsError(error)
    }
}

impl From<SerialisationError> for AuthError {
    fn from(_err: SerialisationError) -> Self {
        Self::EncodeDecodeError
    }
}

impl From<Utf8Error> for AuthError {
    fn from(_err: Utf8Error) -> Self {
        Self::EncodeDecodeError
    }
}

impl From<FromUtf8Error> for AuthError {
    fn from(_err: FromUtf8Error) -> Self {
        Self::EncodeDecodeError
    }
}

impl From<StringError> for AuthError {
    fn from(_err: StringError) -> Self {
        Self::EncodeDecodeError
    }
}

impl ErrorCode for AuthError {
    fn error_code(&self) -> i32 {
        use codes::*;
        match *self {
            Self::CoreError(ref err) => core_error_code(err),
            Self::SndError(ref err) => safe_nd_error_core(err),
            Self::IpcError(ref err) => match *err {
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
            Self::NfsError(ref err) => match *err {
                NfsError::CoreError(ref err) => core_error_code(err),
                NfsError::FileExists => ERR_FILE_EXISTS,
                NfsError::FileNotFound => ERR_FILE_NOT_FOUND,
                NfsError::InvalidRange => ERR_INVALID_RANGE,
                NfsError::EncodeDecodeError(_) => ERR_ENCODE_DECODE_ERROR,
                NfsError::SelfEncryption(_) => ERR_SELF_ENCRYPTION,
                NfsError::Unexpected(_) => ERR_UNEXPECTED,
            },
            Self::EncodeDecodeError => ERR_ENCODE_DECODE_ERROR,
            Self::IoError(_) => ERR_IO_ERROR,

            Self::AccountContainersCreation(_) => ERR_ACCOUNT_CONTAINERS_CREATION,
            Self::NoSuchContainer(_) => ERR_NO_SUCH_CONTAINER,
            Self::PendingRevocation => ERR_PENDING_REVOCATION,
            Self::Unexpected(_) => ERR_UNEXPECTED,
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
