// Copyright 2017 MaidSafe.net limited.
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

use super::{AppExchangeInfo, ContainerPermissions, containers_from_repr_c, containers_into_vec};
use ffi::ipc::req as ffi;
use ffi_utils::{ReprC, StringError, vec_into_raw_parts};
use ipc::errors::IpcError;
use std::collections::HashMap;

/// Containers request
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Debug)]
pub struct ContainersReq {
    /// Exchange info
    pub app: AppExchangeInfo,
    /// Requested containers
    pub containers: HashMap<String, ContainerPermissions>,
}

impl ContainersReq {
    /// Consumes the object and returns the FFI counterpart.
    ///
    /// You're now responsible for freeing the subobjects memory once you're
    /// done.
    pub fn into_repr_c(self) -> Result<ffi::ContainersReq, IpcError> {
        let ContainersReq { app, containers } = self;

        let containers = containers_into_vec(containers).map_err(StringError::from)?;
        let (containers_ptr, containers_len, containers_cap) = vec_into_raw_parts(containers);

        Ok(ffi::ContainersReq {
            app: app.into_repr_c()?,
            containers: containers_ptr,
            containers_len,
            containers_cap,
        })
    }
}

impl ReprC for ContainersReq {
    type C = *const ffi::ContainersReq;
    type Error = IpcError;

    /// Constructs the object from the FFI counterpart.
    ///
    /// After calling this functions, the subobjects memory is owned by the
    /// resulting object.
    unsafe fn clone_from_repr_c(repr_c: *const ffi::ContainersReq) -> Result<Self, IpcError> {
        Ok(ContainersReq {
            app: AppExchangeInfo::clone_from_repr_c(&(*repr_c).app)?,
            containers: containers_from_repr_c((*repr_c).containers, (*repr_c).containers_len)?,
        })
    }
}
