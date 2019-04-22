// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

/// Request module.
pub mod req;
/// Response module.
pub mod resp;

mod errors;

pub use self::errors::IpcError;
pub use self::req::{
    AppExchangeInfo, AuthReq, ContainersReq, IpcReq, Permission, ShareMData, ShareMDataReq,
};
pub use self::resp::{
    access_container_enc_key, AccessContInfo, AccessContainerEntry, AppKeys, AuthGranted, IpcResp,
};

use data_encoding::BASE32_NOPAD;
#[cfg(any(test, feature = "testing"))]
use ffi_utils;
use maidsafe_utilities::serialisation::{deserialise, serialise};
use rand::{self, Rng};
pub use routing::BootstrapConfig;
use std::u32;

/// IPC message.
#[cfg_attr(feature = "cargo-clippy", allow(clippy::large_enum_variant))]
#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub enum IpcMsg {
    /// Request.
    Req {
        /// Request ID.
        req_id: u32,
        /// Request.
        req: IpcReq,
    },
    /// Response.
    Resp {
        /// Request ID.
        req_id: u32,
        /// Response.
        resp: IpcResp,
    },
    /// Revoked.
    Revoked {
        /// Application ID.
        app_id: String,
    },
    /// Generic error like couldn't parse IpcMsg etc.
    Err(IpcError),
}

/// Encode `IpcMsg` into string, using base32 encoding.
pub fn encode_msg(msg: &IpcMsg) -> Result<String, IpcError> {
    // We also add a multicodec compatible prefix. For more details please follow
    // https://github.com/multiformats/multicodec/blob/master/table.csv
    let msg = (msg, cfg!(feature = "mock-network"));
    Ok(format!("b{}", BASE32_NOPAD.encode(&serialise(&msg)?)))
}

/// Encode `IpcMsg` into string, using base64 encoding.
///
/// For testing purposes only.
#[cfg(any(test, feature = "testing"))]
pub fn encode_msg_64(msg: &IpcMsg) -> Result<String, IpcError> {
    Ok(ffi_utils::base64_encode(&serialise(msg)?))
}

/// Decode `IpcMsg` encoded with base32 encoding.
// FIXME: bug in clippy - comparison on cfg!(..) deemed a needless bool comparison
#[cfg_attr(feature = "cargo-clippy", allow(clippy::bool_comparison))]
pub fn decode_msg(encoded: &str) -> Result<IpcMsg, IpcError> {
    let mut chars = encoded.chars();
    let decoded = match chars.next().ok_or(IpcError::InvalidMsg)? {
        // Encoded as base32
        'b' | 'B' => BASE32_NOPAD.decode(chars.as_str().as_bytes())?,
        // Fail if not encoded as base32
        _ => return Err(IpcError::EncodeDecodeError),
    };

    let (msg, mock): (IpcMsg, bool) = deserialise(&decoded)?;
    if mock != cfg!(feature = "mock-network") {
        return Err(IpcError::IncompatibleMockStatus);
    }

    Ok(msg)
}

/// Decode `IpcMsg` encoded with base64 encoding.
///
/// For testing purposes only.
#[cfg(any(test, feature = "testing"))]
pub fn decode_msg_64(encoded: &str) -> Result<IpcMsg, IpcError> {
    Ok(deserialise(
        &ffi_utils::base64_decode(encoded).map_err(|_| IpcError::EncodeDecodeError)?,
    )?)
}

/// Generate unique request ID.
pub fn gen_req_id() -> u32 {
    // Generate the number in range 1..MAX inclusive.
    rand::thread_rng().gen_range(0, u32::MAX) + 1
}
