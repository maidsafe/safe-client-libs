// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

pub use self::codes::*;
use config_file_handler::Error as ConfigFileHandlerError;
use ffi_utils::{ErrorCode, StringError};
use futures::sync::mpsc::SendError;
use maidsafe_utilities::serialisation::SerialisationError;
use routing::ClientError;
use safe_core::ipc::IpcError;
use safe_core::nfs::NfsError;
use safe_core::{CoreError, SelfEncryptionStorageError};
use safe_nd::Error as SndError;
use self_encryption::SelfEncryptionError;
use std::error::Error;
use std::ffi::NulError;
use std::fmt::{self, Display, Formatter};
use std::io::Error as IoError;
use std::str::Utf8Error;
use std::sync::mpsc::{RecvError, RecvTimeoutError};

#[allow(missing_docs)]
mod codes {
    // Core errors
    pub const ERR_ENCODE_DECODE_ERROR: i32 = -1;
    pub const ERR_ASYMMETRIC_DECIPHER_FAILURE: i32 = -2;
    pub const ERR_SYMMETRIC_DECIPHER_FAILURE: i32 = -3;
    pub const ERR_RECEIVED_UNEXPECTED_DATA: i32 = -4;
    pub const ERR_RECEIVED_UNEXPECTED_EVENT: i32 = -5;
    pub const ERR_VERSION_CACHE_MISS: i32 = -6;
    pub const ERR_ROOT_DIRECTORY_EXISTS: i32 = -7;
    pub const ERR_RANDOM_DATA_GENERATION_FAILURE: i32 = -8;
    pub const ERR_OPERATION_FORBIDDEN: i32 = -9;
    pub const ERR_ROUTING_ERROR: i32 = -10;
    pub const ERR_ROUTING_INTERFACE_ERROR: i32 = -11;
    pub const ERR_UNSUPPORTED_SALT_SIZE_FOR_PW_HASH: i32 = -12;
    pub const ERR_UNSUCCESSFUL_PW_HASH: i32 = -13;
    pub const ERR_OPERATION_ABORTED: i32 = -14;
    pub const ERR_MPID_MESSAGING_ERROR: i32 = -15;
    pub const ERR_SELF_ENCRYPTION: i32 = -16;
    pub const ERR_REQUEST_TIMEOUT: i32 = -17;
    pub const ERR_CONFIG_FILE: i32 = -18;
    pub const ERR_IO: i32 = -19;

    // routing Client errors
    pub const ERR_ACCESS_DENIED: i32 = -100;
    pub const ERR_NO_SUCH_ACCOUNT: i32 = -101;
    pub const ERR_ACCOUNT_EXISTS: i32 = -102;
    pub const ERR_NO_SUCH_DATA: i32 = -103;
    pub const ERR_DATA_EXISTS: i32 = -104;
    pub const ERR_DATA_TOO_LARGE: i32 = -105;
    pub const ERR_NO_SUCH_ENTRY: i32 = -106;
    pub const ERR_INVALID_ENTRY_ACTIONS: i32 = -107;
    pub const ERR_TOO_MANY_ENTRIES: i32 = -108;
    pub const ERR_NO_SUCH_KEY: i32 = -109;
    pub const ERR_INVALID_OWNERS: i32 = -110;
    pub const ERR_INVALID_SUCCESSOR: i32 = -111;
    pub const ERR_INVALID_OPERATION: i32 = -112;
    pub const ERR_LOW_BALANCE: i32 = -113;
    pub const ERR_NETWORK_FULL: i32 = -114;
    pub const ERR_NETWORK_OTHER: i32 = -115;
    pub const ERR_INVALID_INVITATION: i32 = -116;
    pub const ERR_INVITATION_ALREADY_CLAIMED: i32 = -117;
    pub const ERR_DUPLICATE_MSG_ID: i32 = -118;
    pub const ERR_DUPLICATE_ENTRY_KEYS: i32 = -119;
    pub const ERR_KEYS_EXIST: i32 = -120;

    // IPC errors.
    pub const ERR_AUTH_DENIED: i32 = -200;
    pub const ERR_CONTAINERS_DENIED: i32 = -201;
    pub const ERR_INVALID_MSG: i32 = -202;
    pub const ERR_ALREADY_AUTHORISED: i32 = -203;
    pub const ERR_UNKNOWN_APP: i32 = -204;
    pub const ERR_STRING_ERROR: i32 = -205;
    pub const ERR_SHARE_MDATA_DENIED: i32 = -206;
    pub const ERR_INVALID_OWNER: i32 = -207;
    pub const ERR_INCOMPATIBLE_MOCK_STATUS: i32 = -208;

    // NFS errors.
    pub const ERR_FILE_EXISTS: i32 = -300;
    pub const ERR_FILE_NOT_FOUND: i32 = -301;
    pub const ERR_INVALID_RANGE: i32 = -302;

    // App errors
    pub const ERR_NO_SUCH_CONTAINER: i32 = -1002;
    pub const ERR_INVALID_CIPHER_OPT_HANDLE: i32 = -1003;
    pub const ERR_INVALID_ENCRYPT_PUB_KEY_HANDLE: i32 = -1004;
    pub const ERR_INVALID_MDATA_INFO_HANDLE: i32 = -1005;
    pub const ERR_INVALID_MDATA_ENTRIES_HANDLE: i32 = -1006;
    pub const ERR_INVALID_MDATA_ENTRY_ACTIONS_HANDLE: i32 = -1007;
    pub const ERR_INVALID_MDATA_PERMISSIONS_HANDLE: i32 = -1008;
    pub const ERR_INVALID_MDATA_PERMISSION_SET_HANDLE: i32 = -1009;
    pub const ERR_INVALID_SELF_ENCRYPTOR_HANDLE: i32 = -1010;
    pub const ERR_INVALID_SIGN_PUB_KEY_HANDLE: i32 = -1011;
    pub const ERR_INVALID_SELF_ENCRYPTOR_READ_OFFSETS: i32 = -1012;
    pub const ERR_IO_ERROR: i32 = -1013;
    pub const ERR_INVALID_ENCRYPT_SEC_KEY_HANDLE: i32 = -1014;
    pub const ERR_INVALID_FILE_CONTEXT_HANDLE: i32 = -1015;
    pub const ERR_INVALID_FILE_MODE: i32 = -1016;
    pub const ERR_INVALID_SIGN_SEC_KEY_HANDLE: i32 = -1017;
    pub const ERR_UNREGISTERED_CLIENT_ACCESS: i32 = -1018;
    pub const ERR_INVALID_PUB_KEY_HANDLE: i32 = -1019;

    pub const ERR_UNEXPECTED: i32 = -2000;

    // Identity & permission errors.
    pub const ERR_INVALID_OWNERS_SUCCESSOR: i32 = -3001;
    pub const ERR_INVALID_PERMISSIONS_SUCCESSOR: i32 = -3002;
    pub const ERR_SIGN_KEYTYPE_MISMATCH: i32 = -3003;
    pub const ERR_INVALID_SIGNATURE: i32 = -3004;
    pub const ERR_INVALID_PERMISSIONS: i32 = -3005;

    // Coin errors.
    pub const ERR_LOSS_OF_PRECISION: i32 = -4000;
    pub const ERR_EXCESSIVE_VALUE: i32 = -4001;
    pub const ERR_FAILED_TO_PARSE: i32 = -4002;
    pub const ERR_TRANSACTION_ID_EXISTS: i32 = -4003;
    pub const ERR_INSUFFICIENT_BALANCE: i32 = -4004;
    pub const ERR_BALANCE_EXISTS: i32 = -4005;
    pub const ERR_NO_SUCH_BALANCE: i32 = -4006;

    // Login packet errors.
    pub const ERR_EXCEEDED_SIZE: i32 = -5001;
    pub const ERR_NO_SUCH_LOGIN_PACKET: i32 = -5002;
    pub const ERR_LOGIN_PACKET_EXISTS: i32 = -5003;

    // QuicP2P errors.
    pub const ERR_QUIC_P2P: i32 = -6000;
}

/// App error.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum AppError {
    /// Error from safe_core.
    CoreError(CoreError),
    /// IPC error.
    IpcError(IpcError),
    /// NFS error.
    NfsError(NfsError),
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
    /// Invalid encrypt (box_) key handle.
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
            Self::IpcError(ref error) => write!(formatter, "IPC error: {:?}", error),
            Self::NfsError(ref error) => write!(formatter, "NFS error: {}", error),
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
            AppError::UnregisteredClientAccess => write!(
                formatter,
                "Tried to access a client key from an unregistered client",
            ),
            Self::InvalidEncryptPubKeyHandle => {
                write!(formatter, "Invalid encrypt (box_) key handle")
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

impl From<ConfigFileHandlerError> for AppError {
    fn from(err: ConfigFileHandlerError) -> Self {
        Self::Unexpected(err.to_string())
    }
}

impl From<NfsError> for AppError {
    fn from(err: NfsError) -> Self {
        match err {
            NfsError::CoreError(err) => Self::CoreError(err),
            NfsError::EncodeDecodeError(_) => Self::EncodeDecodeError,
            NfsError::SelfEncryption(err) => Self::SelfEncryption(err),
            NfsError::Unexpected(reason) => Self::Unexpected(reason),
            _ => Self::NfsError(err),
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
        Self::from(err.description())
    }
}

impl From<NulError> for AppError {
    fn from(err: NulError) -> Self {
        Self::from(err.description())
    }
}

impl From<RecvError> for AppError {
    fn from(err: RecvError) -> Self {
        Self::from(err.description())
    }
}

impl From<RecvTimeoutError> for AppError {
    fn from(_err: RecvTimeoutError) -> Self {
        // TODO: change this to err.description() once that lands in stable.
        Self::from("mpsc receive error")
    }
}

impl ErrorCode for AppError {
    fn error_code(&self) -> i32 {
        match *self {
            Self::CoreError(ref err) => core_error_code(err),
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
            Self::OperationForbidden => ERR_OPERATION_FORBIDDEN,
            Self::NoSuchContainer(_) => ERR_NO_SUCH_CONTAINER,
            Self::InvalidCipherOptHandle => ERR_INVALID_CIPHER_OPT_HANDLE,
            Self::InvalidEncryptPubKeyHandle => ERR_INVALID_ENCRYPT_PUB_KEY_HANDLE,
            Self::InvalidMDataEntriesHandle => ERR_INVALID_MDATA_ENTRIES_HANDLE,
            Self::InvalidMDataEntryActionsHandle => ERR_INVALID_MDATA_ENTRY_ACTIONS_HANDLE,
            Self::InvalidMDataPermissionsHandle => ERR_INVALID_MDATA_PERMISSIONS_HANDLE,
            Self::InvalidSelfEncryptorHandle => ERR_INVALID_SELF_ENCRYPTOR_HANDLE,
            Self::InvalidSignPubKeyHandle => ERR_INVALID_SIGN_PUB_KEY_HANDLE,
            Self::InvalidSignSecKeyHandle => ERR_INVALID_SIGN_SEC_KEY_HANDLE,
            Self::InvalidEncryptSecKeyHandle => ERR_INVALID_ENCRYPT_SEC_KEY_HANDLE,
            Self::InvalidPubKeyHandle => ERR_INVALID_PUB_KEY_HANDLE,
            Self::InvalidFileContextHandle => ERR_INVALID_FILE_CONTEXT_HANDLE,
            Self::InvalidFileMode => ERR_INVALID_FILE_MODE,
            Self::UnregisteredClientAccess => ERR_UNREGISTERED_CLIENT_ACCESS,
            Self::SelfEncryption(_) => ERR_SELF_ENCRYPTION,
            Self::InvalidSelfEncryptorReadOffsets => ERR_INVALID_SELF_ENCRYPTOR_READ_OFFSETS,
            Self::IoError(_) => ERR_IO_ERROR,
            Self::Unexpected(_) => ERR_UNEXPECTED,
        }
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
        CoreError::RoutingError(_) => ERR_ROUTING_ERROR,
        CoreError::RoutingInterfaceError(_) => ERR_ROUTING_INTERFACE_ERROR,
        CoreError::RoutingClientError(ref err) => match *err {
            ClientError::AccessDenied => ERR_ACCESS_DENIED,
            ClientError::NoSuchAccount => ERR_NO_SUCH_ACCOUNT,
            ClientError::AccountExists => ERR_ACCOUNT_EXISTS,
            ClientError::NoSuchData => ERR_NO_SUCH_DATA,
            ClientError::DataExists => ERR_DATA_EXISTS,
            ClientError::DataTooLarge => ERR_DATA_TOO_LARGE,
            ClientError::NoSuchEntry => ERR_NO_SUCH_ENTRY,
            ClientError::InvalidEntryActions(..) => ERR_INVALID_ENTRY_ACTIONS,
            ClientError::TooManyEntries => ERR_TOO_MANY_ENTRIES,
            ClientError::NoSuchKey => ERR_NO_SUCH_KEY,
            ClientError::InvalidOwners => ERR_INVALID_OWNERS,
            ClientError::InvalidSuccessor(..) => ERR_INVALID_SUCCESSOR,
            ClientError::InvalidOperation => ERR_INVALID_OPERATION,
            ClientError::LowBalance => ERR_LOW_BALANCE,
            ClientError::NetworkFull => ERR_NETWORK_FULL,
            ClientError::NetworkOther(_) => ERR_NETWORK_OTHER,
            ClientError::InvalidInvitation => ERR_INVALID_INVITATION,
            ClientError::InvitationAlreadyClaimed => ERR_INVITATION_ALREADY_CLAIMED,
        },
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
            SndError::InvalidPermissions => ERR_INVALID_PERMISSIONS,
        },
        CoreError::QuicP2p(ref _err) => ERR_QUIC_P2P, // FIXME: use proper error codes
        CoreError::UnsupportedSaltSizeForPwHash => ERR_UNSUPPORTED_SALT_SIZE_FOR_PW_HASH,
        CoreError::UnsuccessfulPwHash => ERR_UNSUCCESSFUL_PW_HASH,
        CoreError::OperationAborted => ERR_OPERATION_ABORTED,
        CoreError::MpidMessagingError(_) => ERR_MPID_MESSAGING_ERROR,
        CoreError::SelfEncryption(_) => ERR_SELF_ENCRYPTION,
        CoreError::RequestTimeout => ERR_REQUEST_TIMEOUT,
        CoreError::ConfigError(_) => ERR_CONFIG_FILE,
        CoreError::IoError(_) => ERR_IO,
        CoreError::Unexpected(_) => ERR_UNEXPECTED,
    }
}
