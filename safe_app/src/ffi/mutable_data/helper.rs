// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::errors::AppError;
use crate::ffi::object_cache::{MDataPermissionsHandle, PubKeyHandle};
use crate::object_cache::ObjectCache;
use safe_nd::{MDataPermissionSet, PublicKey};
use std::collections::BTreeMap;

// Retrieve the sign key corresponding to the handle from the object cache
pub fn get_user(object_cache: &ObjectCache, handle: PubKeyHandle) -> Result<PublicKey, AppError> {
    let user = {
        let sign_key = object_cache.get_pub_key(handle)?;
        *sign_key
    };

    Ok(user)
}

// Insert the permissions into the object cache.
pub fn insert_permissions(
    object_cache: &ObjectCache,
    permissions: BTreeMap<PublicKey, MDataPermissionSet>,
) -> MDataPermissionsHandle {
    object_cache.insert_mdata_permissions(permissions)
}

// Retrieve permissions from the object cache.
pub fn get_permissions(
    object_cache: &ObjectCache,
    handle: MDataPermissionsHandle,
) -> Result<BTreeMap<PublicKey, MDataPermissionSet>, AppError> {
    let output = object_cache.get_mdata_permissions(handle)?.clone();

    Ok(output)
}
