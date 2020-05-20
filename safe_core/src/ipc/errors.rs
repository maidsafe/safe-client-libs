// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use bincode::Error as SerialisationError;
use data_encoding::DecodeError;
use ffi_utils::StringError;
use futures::channel::mpsc::SendError;
use safe_nd::XorName;
use serde::{Deserialize, Serialize};
use std::ffi::NulError;
use std::fmt::{self, Display, Formatter};
use std::str::Utf8Error;
use threshold_crypto::error::FromBytesError;

/// Ipc error.
#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
pub enum IpcError {
    /// Authentication denied.
    AuthDenied,
    /// Containers denied.
    ContainersDenied,
    /// Invalid IPC message.
    InvalidMsg,
    /// Generic encoding / decoding failure.
    EncodeDecodeError,
    /// String conversion error.
    StringError(StringError),
    /// App is already authorised.
    AlreadyAuthorised,
    /// App is not registered.
    UnknownApp,
    /// User denied request for shared access to MD.
    ShareMDataDenied,
    /// Requested shared access to non-owned MD.
    InvalidOwner(Vec<(XorName, u64)>),
    /// Message sent between mock and non-mock versions.
    IncompatibleMockStatus,

    /// Unexpected error.
    Unexpected(String),
}

// impl Display for IpcError {
//     fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
//         match *self {
//             Self::Unexpected(ref error) => {
//                 write!(formatter, "Unexpected (probably a logic error): {}", error)
//             }
//             Self::StringError(ref error) => write!(formatter, "String error: {:?}", error),
//             Self::InvalidOwner(ref error) => write!(formatter, "Invalid Owner: {:?}", error),

//             Self::AuthDenied => write!(formatter, "Auth denied error"),
//             Self::ContainersDenied => write!(formatter, "Containers denied error"),
//             Self::InvalidMsg => write!(formatter, "Invalid IPC error: "),
//             Self::EncodeDecodeError => write!(formatter, "Serialisation error"),
//             Self::AlreadyAuthorised => write!(formatter, "Already Authorised error"),

//             Self::UnknownApp=> write!(
//                 formatter,
//                 "Unknown app error"
//             ),
//             Self::ShareMDataDenied => {
//                 write!(formatter, "Share Mdata access denied.")
//             }
//             Self::IncompatibleMockStatus => write!(
//                 formatter,
//                 "Incompatible Mock status. Attempting to communicate between mock and non-mock."
//             ),
//         }
//     }
// }

impl From<SendError> for IpcError {
    fn from(error: SendError) -> Self {
        Self::Unexpected(error.to_string())
    }
}

impl From<Utf8Error> for IpcError {
    fn from(_err: Utf8Error) -> Self {
        Self::EncodeDecodeError
    }
}

impl From<DecodeError> for IpcError {
    fn from(_err: DecodeError) -> Self {
        Self::EncodeDecodeError
    }
}

impl From<SerialisationError> for IpcError {
    fn from(_err: SerialisationError) -> Self {
        Self::EncodeDecodeError
    }
}

impl From<StringError> for IpcError {
    fn from(err: StringError) -> Self {
        Self::StringError(err)
    }
}

impl From<NulError> for IpcError {
    fn from(error: NulError) -> Self {
        Self::from(error.to_string())
    }
}

impl<'a> From<&'a str> for IpcError {
    fn from(s: &'a str) -> Self {
        Self::Unexpected(s.to_string())
    }
}

impl From<String> for IpcError {
    fn from(s: String) -> Self {
        Self::Unexpected(s)
    }
}

impl From<FromBytesError> for IpcError {
    fn from(err: FromBytesError) -> Self {
        Self::from(err.to_string())
    }
}
