// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

#![allow(unsafe_code)]

mod auth;
mod containers;
mod share_mdata;

pub use self::auth::AuthReq;
pub use self::containers::ContainersReq;
pub use self::share_mdata::{ShareMData, ShareMDataReq};

use crate::ffi::ipc::req::{
    AppExchangeInfo as FfiAppExchangeInfo, ContainerPermissions as FfiContainerPermissions,
    PermissionSet as FfiPermissionSet,
};
use crate::ipc::errors::IpcError;
use ffi_utils::{from_c_str, ReprC, StringError};
use routing::{Action, PermissionSet};
use std::collections::{BTreeSet, HashMap};
use std::ffi::{CString, NulError};
use std::{ptr, slice};

/// Permission enum - use for internal storage only
#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum Permission {
    /// Read
    Read,
    /// Insert
    Insert,
    /// Update
    Update,
    /// Delete
    Delete,
    /// Modify permissions
    ManagePermissions,
}

/// Permissions stored internally in the access container.
/// In FFI represented as `ffi::PermissionSet`
pub type ContainerPermissions = BTreeSet<Permission>;

/// IPC request.
// TODO: `TransOwnership` variant
#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub enum IpcReq {
    /// Authentication request.
    Auth(AuthReq),
    /// Containers request.
    Containers(ContainersReq),
    /// Unregistered client authenticator request.
    /// Takes arbitrary user data as `Vec<u8>`, returns bootstrap config.
    Unregistered(Vec<u8>),
    /// Share mutable data.
    ShareMData(ShareMDataReq),
}

/// Consumes the object and returns the wrapped raw pointer.
/// Converts a container name + a set of permissions into an FFI
/// representation `ContainerPermissions`.
///
/// You're now responsible for freeing this memory once you're done.
/// However, notice that the `ffi::ContainerPermissions` struct has
/// a `Drop` impl, so when it goes out of a scope, it will free allocated
/// strings automatically.
pub fn containers_into_vec<ContainersIter>(
    containers: ContainersIter,
) -> Result<Vec<FfiContainerPermissions>, NulError>
where
    ContainersIter: IntoIterator<Item = (String, ContainerPermissions)>,
{
    containers
        .into_iter()
        .map(|(cont_name, access)| {
            Ok(FfiContainerPermissions {
                cont_name: CString::new(cont_name)?.into_raw(),
                access: container_perms_into_repr_c(&access),
            })
        })
        .collect()
}

/// Transform a set of container permissions into its FFI representation
pub fn container_perms_into_repr_c(perms: &ContainerPermissions) -> FfiPermissionSet {
    let mut output = FfiPermissionSet::default();

    for perm in perms {
        match *perm {
            Permission::Read => {
                output.read = true;
            }
            Permission::Insert => {
                output.insert = true;
            }
            Permission::Update => {
                output.update = true;
            }
            Permission::Delete => {
                output.delete = true;
            }
            Permission::ManagePermissions => output.manage_permissions = true,
        }
    }

    output
}

/// Transform an FFI representation into container permissions
pub fn container_perms_from_repr_c(
    perms: FfiPermissionSet,
) -> Result<ContainerPermissions, IpcError> {
    let mut output = BTreeSet::new();

    if perms.read {
        let _ = output.insert(Permission::Read);
    }
    if perms.insert {
        let _ = output.insert(Permission::Insert);
    }
    if perms.update {
        let _ = output.insert(Permission::Update);
    }
    if perms.delete {
        let _ = output.insert(Permission::Delete);
    }
    if perms.manage_permissions {
        let _ = output.insert(Permission::ManagePermissions);
    }

    if output.is_empty() {
        Err(IpcError::from("No permissions were provided"))
    } else {
        Ok(output)
    }
}

/// Transforms a collection of container permissions into `routing::PermissionSet`
pub fn container_perms_into_permission_set<'a, Iter>(permissions: Iter) -> PermissionSet
where
    Iter: IntoIterator<Item = &'a Permission>,
{
    let mut ps = PermissionSet::new();

    for access in permissions {
        ps = match *access {
            Permission::Read => ps,
            Permission::Insert => ps.allow(Action::Insert),
            Permission::Update => ps.allow(Action::Update),
            Permission::Delete => ps.allow(Action::Delete),
            Permission::ManagePermissions => ps.allow(Action::ManagePermissions),
        };
    }

    ps
}

/// Constructs the object from a raw pointer.
///
/// After calling this function, the raw pointer is owned by the resulting
/// object.
#[allow(unsafe_code)]
pub unsafe fn containers_from_repr_c(
    raw: *const FfiContainerPermissions,
    len: usize,
) -> Result<HashMap<String, ContainerPermissions>, IpcError> {
    slice::from_raw_parts(raw, len)
        .iter()
        .map(|raw| {
            Ok((
                from_c_str(raw.cont_name)?,
                container_perms_from_repr_c(raw.access)?,
            ))
        })
        .collect()
}

/// Convert a `PermissionSet` into its C representation.
pub fn permission_set_into_repr_c(perms: PermissionSet) -> FfiPermissionSet {
    FfiPermissionSet {
        read: true,
        insert: perms.is_allowed(Action::Insert).unwrap_or(false),
        update: perms.is_allowed(Action::Update).unwrap_or(false),
        delete: perms.is_allowed(Action::Delete).unwrap_or(false),
        manage_permissions: perms.is_allowed(Action::ManagePermissions).unwrap_or(false),
    }
}

/// Create a `PermissionSet` from its C representation.
pub fn permission_set_clone_from_repr_c(
    perms: FfiPermissionSet,
) -> Result<PermissionSet, IpcError> {
    let mut pm = PermissionSet::new();

    if perms.read && !perms.insert && !perms.update && !perms.delete && !perms.manage_permissions {
        // If only `read` is set to true, return an error
        return Err(IpcError::from("Can't convert only the read permission"));
    }

    if perms.insert {
        pm = pm.allow(Action::Insert);
    }

    if perms.update {
        pm = pm.allow(Action::Update);
    }

    if perms.delete {
        pm = pm.allow(Action::Delete);
    }

    if perms.manage_permissions {
        pm = pm.allow(Action::ManagePermissions);
    }

    Ok(pm)
}

/// Represents an application ID in the process of asking permissions
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Debug)]
pub struct AppExchangeInfo {
    /// The ID. It must be unique.
    pub id: String,
    /// Reserved by the frontend.
    pub scope: Option<String>,
    /// The application friendly-name.
    pub name: String,
    /// The application provider/vendor (e.g. MaidSafe)
    pub vendor: String,
}

impl AppExchangeInfo {
    /// Construct FFI wrapper for the native Rust object, consuming self.
    pub fn into_repr_c(self) -> Result<FfiAppExchangeInfo, IpcError> {
        let AppExchangeInfo {
            id,
            scope,
            name,
            vendor,
        } = self;

        Ok(FfiAppExchangeInfo {
            id: CString::new(id).map_err(StringError::from)?.into_raw(),
            scope: if let Some(scope) = scope {
                CString::new(scope).map_err(StringError::from)?.into_raw()
            } else {
                ptr::null()
            },
            name: CString::new(name).map_err(StringError::from)?.into_raw(),
            vendor: CString::new(vendor).map_err(StringError::from)?.into_raw(),
        })
    }
}

impl ReprC for AppExchangeInfo {
    type C = *const FfiAppExchangeInfo;
    type Error = IpcError;

    /// Constructs the object from a raw pointer.
    ///
    /// After calling this function, the raw pointer is owned by the resulting object.
    unsafe fn clone_from_repr_c(repr_c: Self::C) -> Result<Self, Self::Error> {
        let FfiAppExchangeInfo {
            id,
            scope,
            name,
            vendor,
        } = *repr_c;

        Ok(Self {
            id: from_c_str(id).map_err(StringError::from)?,
            scope: if scope.is_null() {
                None
            } else {
                Some(from_c_str(scope).map_err(StringError::from)?)
            },
            name: from_c_str(name).map_err(StringError::from)?,
            vendor: from_c_str(vendor).map_err(StringError::from)?,
        })
    }
}

#[cfg(test)]
#[allow(unsafe_code)]
mod tests {
    use super::*;
    use crate::ffi::ipc::req::PermissionSet as FfiPermissionSet;
    use ffi_utils::ReprC;
    use std::collections::HashMap;
    use std::ffi::CStr;

    // Test converting `ContainerPermissions` to its FFI representation and back again.
    #[test]
    fn container_permissions() {
        let mut cp = HashMap::new();
        let _ = cp.insert("foobar".to_string(), btree_set![Permission::Insert]);

        let ffi_cp = unwrap!(containers_into_vec(cp));
        assert_eq!(ffi_cp.len(), 1);

        let cp = unsafe { unwrap!(containers_from_repr_c(ffi_cp.as_ptr(), 1)) };

        assert!(cp.contains_key("foobar"));
        assert_eq!(unwrap!(cp.get("foobar")), &btree_set![Permission::Insert]);
    }

    // Test that cloning an empty `ContainerPermissions` from FFI produces an error.
    #[test]
    fn empty_container_permissions() {
        // Expect an error for an empty permission set
        let mut cp = HashMap::new();
        let _ = cp.insert("foobar".to_string(), Default::default());

        let ffi_cp = unwrap!(containers_into_vec(cp));
        assert_eq!(ffi_cp.len(), 1);

        let cp = unsafe { containers_from_repr_c(ffi_cp.as_ptr(), 1) };
        assert!(cp.is_err());
    }

    // Test cloning a permission set for the following two cases:
    // 1. If only the `read` perm is set - return an error.
    // 2. The `read` perm should be ignored in all other cases.
    #[test]
    fn permissions_set_conversion() {
        // It should return an error in case if we have set only the `read` perm
        let ps = FfiPermissionSet {
            read: true,
            insert: false,
            update: false,
            delete: false,
            manage_permissions: false,
        };

        let res = permission_set_clone_from_repr_c(ps);
        assert!(res.is_err());

        // It should ignore `read` perms in all other cases
        let ps = FfiPermissionSet {
            read: true,
            insert: false,
            update: true,
            delete: true,
            manage_permissions: false,
        };

        let res = unwrap!(permission_set_clone_from_repr_c(ps));
        assert!(unwrap!(res.is_allowed(Action::Update)));
        assert!(unwrap!(res.is_allowed(Action::Delete)));
        assert!(res.is_allowed(Action::Insert).is_none());
        assert!(res.is_allowed(Action::ManagePermissions).is_none());
    }

    // Testing converting an `AppExchangeInfo` object to its FFI representation and back again.
    #[test]
    fn app_exchange_info() {
        let a = AppExchangeInfo {
            id: "myid".to_string(),
            scope: Some("hi".to_string()),
            name: "bubi".to_string(),
            vendor: "hey girl".to_string(),
        };

        let ffi_a = unwrap!(a.into_repr_c());

        unsafe {
            assert_eq!(unwrap!(CStr::from_ptr(ffi_a.id).to_str()), "myid");
            assert_eq!(unwrap!(CStr::from_ptr(ffi_a.scope).to_str()), "hi");
            assert_eq!(unwrap!(CStr::from_ptr(ffi_a.name).to_str()), "bubi");
            assert_eq!(unwrap!(CStr::from_ptr(ffi_a.vendor).to_str()), "hey girl");
        }

        let mut a = unsafe { unwrap!(AppExchangeInfo::clone_from_repr_c(&ffi_a)) };

        assert_eq!(a.id, "myid");
        assert_eq!(a.scope, Some("hi".to_string()));
        assert_eq!(a.name, "bubi");
        assert_eq!(a.vendor, "hey girl");

        a.scope = None;

        let ffi_a = unwrap!(a.into_repr_c());

        unsafe {
            assert_eq!(unwrap!(CStr::from_ptr(ffi_a.id).to_str()), "myid");
            assert!(ffi_a.scope.is_null());
            assert_eq!(unwrap!(CStr::from_ptr(ffi_a.name).to_str()), "bubi");
            assert_eq!(unwrap!(CStr::from_ptr(ffi_a.vendor).to_str()), "hey girl");
        }
    }

    // Test converting an `AuthReq` object to its FFI representation and back again.
    #[test]
    fn auth_request() {
        let app = AppExchangeInfo {
            id: "1".to_string(),
            scope: Some("2".to_string()),
            name: "3".to_string(),
            vendor: "4".to_string(),
        };

        let a = AuthReq {
            app,
            app_container: false,
            containers: HashMap::new(),
        };

        let ffi = unwrap!(a.into_repr_c());

        assert_eq!(ffi.app_container, false);
        assert_eq!(ffi.containers_len, 0);

        let a = unsafe { unwrap!(AuthReq::clone_from_repr_c(&ffi)) };

        assert_eq!(a.app.id, "1");
        assert_eq!(a.app.scope, Some("2".to_string()));
        assert_eq!(a.app.name, "3");
        assert_eq!(a.app.vendor, "4");
        assert_eq!(a.app_container, false);
        assert_eq!(a.containers.len(), 0);
    }

    // Test converting a `ContainersReq` object to its FFI representation and back again.
    #[test]
    fn containers_req() {
        let app = AppExchangeInfo {
            id: "1".to_string(),
            scope: Some("2".to_string()),
            name: "3".to_string(),
            vendor: "4".to_string(),
        };

        let a = ContainersReq {
            app,
            containers: HashMap::new(),
        };

        let ffi = unwrap!(a.into_repr_c());

        assert_eq!(ffi.containers_len, 0);

        let a = unsafe { unwrap!(ContainersReq::clone_from_repr_c(&ffi)) };

        assert_eq!(a.app.id, "1");
        assert_eq!(a.app.scope, Some("2".to_string()));
        assert_eq!(a.app.name, "3");
        assert_eq!(a.app.vendor, "4");
        assert_eq!(a.containers.len(), 0);
    }
}
