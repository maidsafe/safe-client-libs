// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net
// Commercial License, version 1.0 or later, or (2) The General Public License
// (GPL), version 3, depending on which licence you accepted on initial access
// to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project
// generally, you agree to be bound by the terms of the MaidSafe Contributor
// Agreement, version 1.0.
// This, along with the Licenses can be found in the root directory of this
// project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network
// Software distributed under the GPL Licence is distributed on an "AS IS"
// BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
//
// Please review the Licences for the specific language governing permissions
// and limitations relating to use of the SAFE Network Software.

/// Request module
pub mod req;
/// Response module
pub mod resp;

mod errors;

use ffi_utils::{base64_decode, base64_encode};
use maidsafe_utilities::serialisation::{deserialise, serialise};
pub use self::errors::IpcError;
pub use self::req::{AppExchangeInfo, AuthReq, ContainersReq, IpcReq};
pub use self::req::ffi::Permission;
pub use self::resp::{AccessContInfo, AppKeys, AuthGranted, IpcResp};

// TODO: replace with `crust::Config`
/// Placeholder for `crust::Config`
#[derive(Clone, RustcEncodable, RustcDecodable, Debug, Eq, PartialEq)]
pub struct Config;

#[derive(RustcEncodable, RustcDecodable, Debug)]
/// IPC message
pub enum IpcMsg {
    /// Request
    Req {
        /// Request ID
        req_id: u32,
        /// Request
        req: IpcReq,
    },
    /// Response
    Resp {
        /// Request ID
        req_id: u32,
        /// Response
        resp: IpcResp,
    },
    /// Revoked
    Revoked {
        /// Application ID
        app_id: String,
    },
    /// Generic error like couldn't parse IpcMsg etc.
    Err(IpcError),
}

/// Encode `IpcMsg` into string, using base64 encoding.
pub fn encode_msg(msg: &IpcMsg, prefix: &str) -> Result<String, IpcError> {
    let payload = base64_encode(&serialise(msg)?);
    Ok(format!("{}:{}", prefix, payload))
}

/// Decode `IpcMsg` encoded with base64 encoding.
pub fn decode_msg(encoded: &str) -> Result<IpcMsg, IpcError> {
    // stip prefix.
    let payload = if let Some(index) = encoded.find(':') {
        encoded.split_at(index + 1).1
    } else {
        encoded
    };

    Ok(deserialise(&base64_decode(payload)?)?)
}
