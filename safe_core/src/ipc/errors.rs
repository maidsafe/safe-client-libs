// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use data_encoding::DecodeError;
use ffi_utils::StringError;
use futures::sync::mpsc::SendError;
use maidsafe_utilities::serialisation::SerialisationError;
use routing::XorName;
use std::error::Error;
use std::ffi::NulError;
use std::str::Utf8Error;

/// Ipc error
#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
pub enum IpcError {
    /// Authentication denied
    AuthDenied,
    /// Containers denied
    ContainersDenied,
    /// Invalid IPC message
    InvalidMsg,
    /// Generic encoding / decoding failure.
    EncodeDecodeError,
    /// String conversion error
    StringError(StringError),
    /// App is already authorised
    AlreadyAuthorised,
    /// App is not registered
    UnknownApp,
    /// User denied request for shared access to MD
    ShareMDataDenied,
    /// Requested shared access to non-owned MD
    InvalidOwner(Vec<(XorName, u64)>),
    /// Unexpected error
    Unexpected(String),
}

impl<T: 'static> From<SendError<T>> for IpcError {
    fn from(error: SendError<T>) -> IpcError {
        IpcError::Unexpected(error.description().to_owned())
    }
}

impl From<Utf8Error> for IpcError {
    fn from(_err: Utf8Error) -> Self {
        IpcError::EncodeDecodeError
    }
}

impl From<DecodeError> for IpcError {
    fn from(_err: DecodeError) -> Self {
        IpcError::EncodeDecodeError
    }
}

impl From<SerialisationError> for IpcError {
    fn from(_err: SerialisationError) -> Self {
        IpcError::EncodeDecodeError
    }
}

impl From<StringError> for IpcError {
    fn from(err: StringError) -> Self {
        IpcError::StringError(err)
    }
}

impl From<NulError> for IpcError {
    fn from(error: NulError) -> Self {
        IpcError::from(error.description())
    }
}

impl<'a> From<&'a str> for IpcError {
    fn from(s: &'a str) -> Self {
        IpcError::Unexpected(s.to_string())
    }
}

impl From<String> for IpcError {
    fn from(s: String) -> Self {
        IpcError::Unexpected(s)
    }
}
