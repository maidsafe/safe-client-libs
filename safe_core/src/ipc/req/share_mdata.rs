// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{permission_set_clone_from_repr_c, permission_set_into_repr_c, AppExchangeInfo};
use ffi::ipc::req as ffi;
use ffi_utils::{vec_into_raw_parts, ReprC};
use ipc::errors::IpcError;
use routing::{PermissionSet, XorName};
use std::slice;

/// Represents a request to share mutable data.
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct ShareMDataReq {
    /// Info about the app requesting shared access.
    pub app: AppExchangeInfo,
    /// List of MD names & type tags and permissions that need to be shared.
    pub mdata: Vec<ShareMData>,
}

/// For use in `ShareMDataReq`. Represents a specific `MutableData` that is being shared.
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct ShareMData {
    /// The mutable data type.
    pub type_tag: u64,
    /// The mutable data name.
    pub name: XorName,
    /// The permissions being requested.
    pub perms: PermissionSet,
}

impl ShareMDataReq {
    /// Construct FFI wrapper for the native Rust object, consuming self.
    pub fn into_repr_c(self) -> Result<ffi::ShareMDataReq, IpcError> {
        let mdata_repr_c: Vec<_> = self
            .mdata
            .into_iter()
            .map(|md| md.into_repr_c())
            .collect::<Result<_, _>>()?;

        let (mdata, mdata_len, mdata_cap) = vec_into_raw_parts(mdata_repr_c);

        Ok(ffi::ShareMDataReq {
            app: self.app.into_repr_c()?,
            mdata,
            mdata_len,
            mdata_cap,
        })
    }
}

impl ReprC for ShareMDataReq {
    type C = *const ffi::ShareMDataReq;
    type Error = IpcError;

    unsafe fn clone_from_repr_c(raw: *const ffi::ShareMDataReq) -> Result<Self, IpcError> {
        Ok(ShareMDataReq {
            app: AppExchangeInfo::clone_from_repr_c(&(*raw).app)?,
            mdata: {
                let mdata = slice::from_raw_parts((*raw).mdata, (*raw).mdata_len);
                mdata
                    .into_iter()
                    .map(|c| ShareMData::clone_from_repr_c(c))
                    .collect::<Result<_, _>>()?
            },
        })
    }
}

impl ShareMData {
    /// Construct FFI wrapper for the native Rust object, consuming self.
    pub fn into_repr_c(self) -> Result<ffi::ShareMData, IpcError> {
        Ok(ffi::ShareMData {
            type_tag: self.type_tag,
            name: self.name.0,
            perms: permission_set_into_repr_c(self.perms),
        })
    }
}

impl ReprC for ShareMData {
    type C = *const ffi::ShareMData;
    type Error = IpcError;

    unsafe fn clone_from_repr_c(raw: *const ffi::ShareMData) -> Result<Self, IpcError> {
        Ok(ShareMData {
            type_tag: (*raw).type_tag,
            name: XorName((*raw).name),
            perms: permission_set_clone_from_repr_c((*raw).perms)?,
        })
    }
}
