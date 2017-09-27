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

//! Errors thrown by Authenticator routines

pub use self::codes::*;
use config_file_handler::Error as ConfigFileHandlerError;
use ffi_utils::ErrorCode;
use futures::sync::mpsc::SendError;
use maidsafe_utilities::serialisation::SerialisationError;
use routing::ClientError;
use safe_core::CoreError;
use safe_core::ipc::IpcError;
use safe_core::nfs::NfsError;
use std::error::Error;
use std::ffi::NulError;
use std::fmt::{self, Display, Formatter};
use std::io::Error as IoError;
use std::str::Utf8Error;
use std::string::FromUtf8Error;
use std::sync::mpsc::RecvError;

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

    // routing Client errors
    pub const ERR_ACCESS_DENIED: i32 = -100;
    pub const ERR_NO_SUCH_ACCOUNT: i32 = -101;
    pub const ERR_ACCOUNT_EXISTS: i32 = -102;
    pub const ERR_NO_SUCH_DATA: i32 = -103;
    pub const ERR_DATA_EXISTS: i32 = -104;
    pub const ERR_DATA_TOO_LARGE: i32 = -105;
    pub const ERR_NO_SUCH_ENTRY: i32 = -106;
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
    pub const ERR_INVALID_ENTRY_ACTIONS: i32 = -118;

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

    // Authenticator errors
    pub const ERR_IO_ERROR: i32 = -1013;
    pub const ERR_ACCOUNT_CONTAINERS_CREATION: i32 = -1014;
    pub const ERR_UNEXPECTED: i32 = -2000;
}

/// Authenticator errors
#[cfg_attr(feature = "cargo-clippy", allow(large_enum_variant))]
#[derive(Debug)]
pub enum AuthError {
    /// Unexpected - Probably a Logic error
    Unexpected(String),
    /// Error from safe_core.
    CoreError(CoreError),
    /// Input/output error
    IoError(IoError),
    /// NFS error
    NfsError(NfsError),
    /// Serialisation error
    EncodeDecodeError,
    /// IPC error
    IpcError(IpcError),
    /// Failure during the creation of standard account containers.
    AccountContainersCreation(String),
}

impl Display for AuthError {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        match *self {
            AuthError::Unexpected(ref error) => {
                write!(formatter, "Unexpected (probably a logic error): {}", error)
            }
            AuthError::CoreError(ref error) => write!(formatter, "Core error: {}", error),
            AuthError::IoError(ref error) => write!(formatter, "I/O error: {}", error),
            AuthError::NfsError(ref error) => write!(formatter, "NFS error: {:?}", error),
            AuthError::EncodeDecodeError => write!(formatter, "Serialisation error"),
            AuthError::IpcError(ref error) => write!(formatter, "IPC error: {:?}", error),
            AuthError::AccountContainersCreation(ref reason) => {
                write!(
                    formatter,
                    "Account containers creation error: {}. Login to attempt recovery.",
                    reason
                )
            }
        }
    }
}

impl Into<IpcError> for AuthError {
    fn into(self) -> IpcError {
        match self {
            AuthError::Unexpected(desc) => IpcError::Unexpected(desc),
            AuthError::IpcError(err) => err,
            err => IpcError::Unexpected(format!("{:?}", err)),
        }
    }
}

impl<T: 'static> From<SendError<T>> for AuthError {
    fn from(error: SendError<T>) -> AuthError {
        AuthError::Unexpected(error.description().to_owned())
    }
}

impl From<ConfigFileHandlerError> for AuthError {
    fn from(error: ConfigFileHandlerError) -> AuthError {
        AuthError::from(error.to_string())
    }
}

impl From<CoreError> for AuthError {
    fn from(error: CoreError) -> AuthError {
        AuthError::CoreError(error)
    }
}

impl From<IpcError> for AuthError {
    fn from(error: IpcError) -> AuthError {
        AuthError::IpcError(error)
    }
}

impl From<RecvError> for AuthError {
    fn from(error: RecvError) -> AuthError {
        AuthError::from(error.description())
    }
}

impl From<NulError> for AuthError {
    fn from(error: NulError) -> AuthError {
        AuthError::from(error.description())
    }
}

impl From<IoError> for AuthError {
    fn from(error: IoError) -> AuthError {
        AuthError::IoError(error)
    }
}

impl<'a> From<&'a str> for AuthError {
    fn from(error: &'a str) -> AuthError {
        AuthError::Unexpected(error.to_owned())
    }
}

impl From<String> for AuthError {
    fn from(error: String) -> AuthError {
        AuthError::Unexpected(error)
    }
}

impl From<NfsError> for AuthError {
    fn from(error: NfsError) -> AuthError {
        AuthError::NfsError(error)
    }
}

impl From<SerialisationError> for AuthError {
    fn from(_err: SerialisationError) -> AuthError {
        AuthError::EncodeDecodeError
    }
}

impl From<Utf8Error> for AuthError {
    fn from(_err: Utf8Error) -> Self {
        AuthError::EncodeDecodeError
    }
}

impl From<FromUtf8Error> for AuthError {
    fn from(_err: FromUtf8Error) -> Self {
        AuthError::EncodeDecodeError
    }
}

impl ErrorCode for AuthError {
    fn error_code(&self) -> i32 {
        match *self {
            AuthError::CoreError(ref err) => core_error_code(err),
            AuthError::IpcError(ref err) => {
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
            AuthError::NfsError(ref err) => {
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
            AuthError::EncodeDecodeError => ERR_ENCODE_DECODE_ERROR,
            AuthError::IoError(_) => ERR_IO_ERROR,
            AuthError::AccountContainersCreation(_) => ERR_ACCOUNT_CONTAINERS_CREATION,
            AuthError::Unexpected(_) => ERR_UNEXPECTED,
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
                ClientError::TooManyEntries => ERR_TOO_MANY_ENTRIES,
                ClientError::InvalidEntryActions(_) => ERR_INVALID_ENTRY_ACTIONS,
                ClientError::NoSuchKey => ERR_NO_SUCH_KEY,
                ClientError::InvalidOwners => ERR_INVALID_OWNERS,
                ClientError::InvalidSuccessor(_) => ERR_INVALID_SUCCESSOR,
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
        CoreError::Unexpected(_) => ERR_UNEXPECTED,
    }
}
