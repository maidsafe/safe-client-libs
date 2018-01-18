// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement.  This, along with the Licenses can be
// found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

pub use self::codes::*;
use config_file_handler::Error as ConfigFileHandlerError;
use ffi_utils::{ErrorCode, StringError};
use futures::sync::mpsc::SendError;
use maidsafe_utilities::serialisation::SerialisationError;
use routing::ClientError;
use safe_core::{CoreError, SelfEncryptionStorageError};
use safe_core::ipc::IpcError;
use safe_core::nfs::NfsError;
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

    // IPC errors.
    pub const ERR_AUTH_DENIED: i32 = -200;
    pub const ERR_CONTAINERS_DENIED: i32 = -201;
    pub const ERR_INVALID_MSG: i32 = -202;
    pub const ERR_ALREADY_AUTHORISED: i32 = -203;
    pub const ERR_UNKNOWN_APP: i32 = -204;
    pub const ERR_STRING_ERROR: i32 = -205;
    pub const ERR_SHARE_MDATA_DENIED: i32 = -206;
    pub const ERR_INVALID_OWNER: i32 = -207;

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

    pub const ERR_UNEXPECTED: i32 = -2000;
}

/// App error.
#[derive(Debug)]
#[cfg_attr(feature = "cargo-clippy", allow(large_enum_variant))]
pub enum AppError {
    /// Error from safe_core.
    CoreError(CoreError),
    /// IPC error.
    IpcError(IpcError),
    /// NFS error.
    NfsError(NfsError),
    /// Generic encoding / decoding failure.
    EncodeDecodeError,
    /// Forbidden operation
    OperationForbidden,
    /// Container not found
    NoSuchContainer,
    /// Invalid file mode (e.g. trying to write when file is opened for reading only)
    InvalidFileMode,

    /// Invalid CipherOpt handle
    InvalidCipherOptHandle,
    /// Invalid encrypt (box_) key handle
    InvalidEncryptPubKeyHandle,
    /// Invalid secret key handle
    InvalidEncryptSecKeyHandle,
    /// Invalid MutableData entries handle
    InvalidMDataEntriesHandle,
    /// Invalid MutableData entry actions handle
    InvalidMDataEntryActionsHandle,
    /// Invalid MutableData permissions handle
    InvalidMDataPermissionsHandle,
    /// Invalid Self Encryptor handle
    InvalidSelfEncryptorHandle,
    /// Invalid public sign key handle
    InvalidSignPubKeyHandle,
    /// Invalid secret sign key handle
    InvalidSignSecKeyHandle,
    /// Invalid file writer handle
    InvalidFileContextHandle,

    /// Error while self-encrypting data
    SelfEncryption(SelfEncryptionError<SelfEncryptionStorageError>),
    /// Invalid offsets (from-position and length combination) provided for
    /// reading form SelfEncryptor. Would have probably caused an overflow.
    InvalidSelfEncryptorReadOffsets,
    /// Input/output Error
    IoError(IoError),
    /// Unexpected error
    Unexpected(String),
}

impl Display for AppError {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        match *self {
            AppError::CoreError(ref error) => write!(formatter, "Core error: {}", error),
            AppError::IpcError(ref error) => write!(formatter, "IPC error: {:?}", error),
            AppError::NfsError(ref error) => write!(formatter, "NFS error: {}", error),
            AppError::EncodeDecodeError => write!(formatter, "Serialisation error"),
            AppError::OperationForbidden => write!(formatter, "Forbidden operation"),
            AppError::NoSuchContainer => write!(formatter, "Container not found"),
            AppError::InvalidCipherOptHandle => write!(formatter, "Invalid CipherOpt handle"),
            AppError::InvalidFileMode => {
                write!(
                    formatter,
                    "Invalid file mode (e.g. trying to write when \
                       file is opened for reading only)"
                )
            }
            AppError::InvalidEncryptPubKeyHandle => {
                write!(formatter, "Invalid encrypt (box_) key handle")
            }
            AppError::InvalidMDataEntriesHandle => {
                write!(formatter, "Invalid MutableData entries handle")
            }
            AppError::InvalidMDataEntryActionsHandle => {
                write!(formatter, "Invalid MutableData entry actions handle")
            }
            AppError::InvalidMDataPermissionsHandle => {
                write!(formatter, "Invalid MutableData permissions handle")
            }
            AppError::InvalidSelfEncryptorHandle => {
                write!(formatter, "Invalid Self Encryptor handle")
            }
            AppError::InvalidSignPubKeyHandle => {
                write!(formatter, "Invalid sign public key handle")
            }
            AppError::InvalidSignSecKeyHandle => {
                write!(formatter, "Invalid sign secret key handle")
            }
            AppError::InvalidEncryptSecKeyHandle => write!(formatter, "Invalid secret key handle"),
            AppError::InvalidFileContextHandle => write!(formatter, "Invalid file context handle"),
            AppError::SelfEncryption(ref error) => {
                write!(formatter, "Self-encryption error: {}", error)
            }
            AppError::InvalidSelfEncryptorReadOffsets => {
                write!(
                    formatter,
                    "Invalid offsets (from-position \
                        and length combination) provided for \
                        reading form SelfEncryptor. Would have \
                        probably caused an overflow."
                )
            }
            AppError::IoError(ref error) => write!(formatter, "I/O error: {}", error),
            AppError::Unexpected(ref error) => {
                write!(formatter, "Unexpected (probably a logic error): {}", error)
            }
        }
    }
}

impl From<CoreError> for AppError {
    fn from(err: CoreError) -> Self {
        match err {
            CoreError::Unexpected(reason) => AppError::Unexpected(reason),
            _ => AppError::CoreError(err),
        }
    }
}

impl From<IpcError> for AppError {
    fn from(err: IpcError) -> Self {
        match err {
            IpcError::EncodeDecodeError => AppError::EncodeDecodeError,
            IpcError::Unexpected(reason) => AppError::Unexpected(reason),
            _ => AppError::IpcError(err),
        }
    }
}

impl From<ConfigFileHandlerError> for AppError {
    fn from(err: ConfigFileHandlerError) -> Self {
        AppError::Unexpected(err.to_string())
    }
}

impl From<NfsError> for AppError {
    fn from(err: NfsError) -> Self {
        match err {
            NfsError::CoreError(err) => AppError::CoreError(err),
            NfsError::EncodeDecodeError(_) => AppError::EncodeDecodeError,
            NfsError::SelfEncryption(err) => AppError::SelfEncryption(err),
            NfsError::Unexpected(reason) => AppError::Unexpected(reason),
            _ => AppError::NfsError(err),
        }
    }
}

impl From<SerialisationError> for AppError {
    fn from(_err: SerialisationError) -> Self {
        AppError::EncodeDecodeError
    }
}

impl From<Utf8Error> for AppError {
    fn from(_err: Utf8Error) -> Self {
        AppError::EncodeDecodeError
    }
}

impl From<StringError> for AppError {
    fn from(_err: StringError) -> Self {
        AppError::EncodeDecodeError
    }
}

impl From<SelfEncryptionError<SelfEncryptionStorageError>> for AppError {
    fn from(err: SelfEncryptionError<SelfEncryptionStorageError>) -> Self {
        AppError::SelfEncryption(err)
    }
}

impl From<IoError> for AppError {
    fn from(err: IoError) -> Self {
        AppError::IoError(err)
    }
}

impl<'a> From<&'a str> for AppError {
    fn from(s: &'a str) -> Self {
        AppError::Unexpected(s.to_string())
    }
}

impl From<String> for AppError {
    fn from(s: String) -> Self {
        AppError::Unexpected(s)
    }
}

impl<T: 'static> From<SendError<T>> for AppError {
    fn from(err: SendError<T>) -> Self {
        AppError::from(err.description())
    }
}

impl From<NulError> for AppError {
    fn from(err: NulError) -> Self {
        AppError::from(err.description())
    }
}

impl From<RecvError> for AppError {
    fn from(err: RecvError) -> Self {
        AppError::from(err.description())
    }
}

impl From<RecvTimeoutError> for AppError {
    fn from(_err: RecvTimeoutError) -> Self {
        // TODO: change this to err.description() once that lands in stable.
        AppError::from("mpsc receive error")
    }
}


impl ErrorCode for AppError {
    fn error_code(&self) -> i32 {
        match *self {
            AppError::CoreError(ref err) => core_error_code(err),
            AppError::IpcError(ref err) => {
                match *err {
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
                }
            }
            AppError::NfsError(ref err) => {
                match *err {
                    NfsError::CoreError(ref err) => core_error_code(err),
                    NfsError::FileExists => ERR_FILE_EXISTS,
                    NfsError::FileNotFound => ERR_FILE_NOT_FOUND,
                    NfsError::InvalidRange => ERR_INVALID_RANGE,
                    NfsError::EncodeDecodeError(_) => ERR_ENCODE_DECODE_ERROR,
                    NfsError::SelfEncryption(_) => ERR_SELF_ENCRYPTION,
                    NfsError::Unexpected(_) => ERR_UNEXPECTED,
                }
            }
            AppError::EncodeDecodeError => ERR_ENCODE_DECODE_ERROR,
            AppError::OperationForbidden => ERR_OPERATION_FORBIDDEN,
            AppError::NoSuchContainer => ERR_NO_SUCH_CONTAINER,
            AppError::InvalidCipherOptHandle => ERR_INVALID_CIPHER_OPT_HANDLE,
            AppError::InvalidEncryptPubKeyHandle => ERR_INVALID_ENCRYPT_PUB_KEY_HANDLE,
            AppError::InvalidMDataEntriesHandle => ERR_INVALID_MDATA_ENTRIES_HANDLE,
            AppError::InvalidMDataEntryActionsHandle => ERR_INVALID_MDATA_ENTRY_ACTIONS_HANDLE,
            AppError::InvalidMDataPermissionsHandle => ERR_INVALID_MDATA_PERMISSIONS_HANDLE,
            AppError::InvalidSelfEncryptorHandle => ERR_INVALID_SELF_ENCRYPTOR_HANDLE,
            AppError::InvalidSignPubKeyHandle => ERR_INVALID_SIGN_PUB_KEY_HANDLE,
            AppError::InvalidSignSecKeyHandle => ERR_INVALID_SIGN_SEC_KEY_HANDLE,
            AppError::InvalidEncryptSecKeyHandle => ERR_INVALID_ENCRYPT_SEC_KEY_HANDLE,
            AppError::InvalidFileContextHandle => ERR_INVALID_FILE_CONTEXT_HANDLE,
            AppError::InvalidFileMode => ERR_INVALID_FILE_MODE,
            AppError::SelfEncryption(_) => ERR_SELF_ENCRYPTION,
            AppError::InvalidSelfEncryptorReadOffsets => ERR_INVALID_SELF_ENCRYPTOR_READ_OFFSETS,
            AppError::IoError(_) => ERR_IO_ERROR,
            AppError::Unexpected(_) => ERR_UNEXPECTED,
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
        CoreError::RoutingClientError(ref err) => {
            match *err {
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
            }
        }
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
