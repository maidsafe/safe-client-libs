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

/// Ffi module
pub mod ffi;

use ffi_utils::{FfiString, ffi_string_free};
use ipc::errors::IpcError;
use self::ffi::Permission;
use std::collections::{BTreeSet, HashMap};
use std::mem;

/// IPC request
// TODO: `TransOwnership` variant
#[derive(RustcEncodable, RustcDecodable, Debug)]
pub enum IpcReq {
    /// Authentication request
    Auth(AuthReq),
    /// Containers request
    Containers(ContainersReq),
}

/// Represents an authorization request
#[derive(Clone, Debug, Eq, PartialEq, RustcEncodable, RustcDecodable)]
pub struct AuthReq {
    /// The application identifier for this request
    pub app: AppExchangeInfo,
    /// `true` if the app wants dedicated container for itself. `false`
    /// otherwise.
    pub app_container: bool,
    /// The list of containers it wishes to access (and desired permissions).
    pub containers: HashMap<String, BTreeSet<Permission>>,
}

/// Converts a container name + a set of permissions into an FFI
/// representation `ContainerPermissions`. You're now responsible for
/// freeing this memory once you're done.
pub fn container_perm_into_repr_c(cont_name: String,
                                  access: BTreeSet<Permission>)
                                  -> ffi::ContainerPermissions {
    ffi::ContainerPermissions {
        cont_name: FfiString::from_string(cont_name),
        access: ffi::PermissionArray::from_vec(access.into_iter().collect()),
    }
}

/// Consumes the object and returns the wrapped raw pointer
///
/// You're now responsible for freeing this memory once you're done.
pub fn containers_into_repr_c(containers: HashMap<String, BTreeSet<Permission>>)
                              -> ffi::ContainerPermissionsArray {
    let mut container_perms = Vec::new();
    for (key, access) in containers {
        container_perms.push(container_perm_into_repr_c(key, access));
    }
    ffi::ContainerPermissionsArray::from_vec(container_perms)
}

/// Constructs the object from a raw pointer.
///
/// After calling this function, the raw pointer is owned by the resulting
/// object.
#[allow(unsafe_code)]
pub unsafe fn containers_from_repr_c(raw: ffi::ContainerPermissionsArray)
                                     -> Result<HashMap<String, BTreeSet<Permission>>, IpcError> {
    let mut result = HashMap::new();
    let vec = raw.into_vec();

    for raw in vec {
        let cont_name = raw.cont_name.to_string();
        ffi_string_free(raw.cont_name);

        let _ = result.insert(cont_name?, raw.access.into_vec().into_iter().collect());
    }

    Ok(result)
}

impl AuthReq {
    /// Consumes the object and returns the FFI counterpart.
    ///
    /// You're now responsible for freeing the subobjects memory once you're
    /// done.
    pub fn into_repr_c(self) -> ffi::AuthReq {
        let AuthReq { app, app_container, containers } = self;

        let containers = containers_into_repr_c(containers);

        ffi::AuthReq {
            app: app.into_repr_c(),
            app_container: app_container,
            containers: containers,
        }
    }

    /// Constructs the object from the FFI counterpart.
    ///
    /// After calling this function, the subobjects memory is owned by the
    /// resulting object.
    #[allow(unsafe_code)]
    pub unsafe fn from_repr_c(repr_c: ffi::AuthReq) -> Result<Self, IpcError> {
        let ffi::AuthReq { app, app_container, containers } = repr_c;

        Ok(AuthReq {
            app: AppExchangeInfo::from_repr_c(app)?,
            app_container: app_container,
            containers: containers_from_repr_c(containers)?,
        })
    }
}

/// Containers request
#[derive(Clone, Eq, PartialEq, RustcEncodable, RustcDecodable, Debug)]
pub struct ContainersReq {
    /// Exchange info
    pub app: AppExchangeInfo,
    /// Requested containers
    pub containers: HashMap<String, BTreeSet<Permission>>,
}

impl ContainersReq {
    /// Consumes the object and returns the FFI counterpart.
    ///
    /// You're now responsible for freeing the subobjects memory once you're
    /// done.
    pub fn into_repr_c(self) -> ffi::ContainersReq {
        let ContainersReq { app, containers } = self;

        ffi::ContainersReq {
            app: app.into_repr_c(),
            containers: containers_into_repr_c(containers),
        }
    }

    /// Constructs the object from the FFI counterpart.
    ///
    /// After calling this functions, the subobjects memory is owned by the
    /// resulting object.
    #[allow(unsafe_code)]
    pub unsafe fn from_repr_c(repr_c: ffi::ContainersReq) -> Result<Self, IpcError> {
        let ffi::ContainersReq { app, containers } = repr_c;
        Ok(ContainersReq {
            app: AppExchangeInfo::from_repr_c(app)?,
            containers: containers_from_repr_c(containers)?,
        })
    }
}

/// Represents an application ID in the process of asking permissions
#[derive(Clone, Eq, PartialEq, RustcEncodable, RustcDecodable, Debug)]
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
    /// Consumes the object and returns the wrapped raw pointer
    ///
    /// You're now responsible for freeing this memory once you're done.
    pub fn into_repr_c(self) -> ffi::AppExchangeInfo {
        let AppExchangeInfo { id, scope, name, vendor } = self;

        let (s_ptr, s_len, s_cap) = match scope {
            Some(ref s) => (s.as_ptr(), s.len(), s.capacity()),
            None => (0 as *const u8, 0, 0),
        };

        mem::forget(scope);

        ffi::AppExchangeInfo {
            id: FfiString::from_string(id),
            scope: s_ptr,
            scope_len: s_len,
            scope_cap: s_cap,
            name: FfiString::from_string(name),
            vendor: FfiString::from_string(vendor),
        }
    }

    /// Constructs the object from a raw pointer.
    ///
    /// After calling this function, the raw pointer is owned by the resulting
    /// object.
    #[allow(unsafe_code)]
    pub unsafe fn from_repr_c(raw: ffi::AppExchangeInfo) -> Result<Self, IpcError> {
        let scope = match (raw.scope, raw.scope_len, raw.scope_cap) {
            (p, _, _) if p.is_null() => None,
            (p, l, c) => Some(String::from_raw_parts(p as *mut u8, l, c)),
        };

        let id = raw.id.to_string();
        let name = raw.name.to_string();
        let vendor = raw.vendor.to_string();

        ffi_string_free(raw.id);
        ffi_string_free(raw.name);
        ffi_string_free(raw.vendor);

        Ok(AppExchangeInfo {
            id: id?,
            scope: scope,
            name: name?,
            vendor: vendor?,
        })
    }
}

#[cfg(test)]
#[allow(unsafe_code)]
mod tests {
    use std::collections::HashMap;
    use super::*;

    #[test]
    fn container_permissions() {
        let mut cp = HashMap::new();
        let _ = cp.insert("foobar".to_string(), Default::default());

        let ffi_cp = containers_into_repr_c(cp);
        assert_eq!(ffi_cp.len, 1);

        let cp = unsafe { unwrap!(containers_from_repr_c(ffi_cp)) };

        assert!(cp.contains_key("foobar"));
        assert!(unwrap!(cp.get("foobar")).is_empty());

        // If test runs under special mode (e.g. Valgrind) we can detect memory
        // leaks
        unsafe {
            ffi::container_permissions_array_free(containers_into_repr_c(cp));
        }
    }

    #[test]
    fn app_exchange_info() {
        let a = AppExchangeInfo {
            id: "myid".to_string(),
            scope: Some("hi".to_string()),
            name: "bubi".to_string(),
            vendor: "hey girl".to_string(),
        };

        let ffi_a = a.into_repr_c();

        unsafe {
            assert_eq!(unwrap!(ffi_a.id.as_str()), "myid");
            assert_eq!(ffi_a.scope_len, 2);
            assert_eq!(unwrap!(ffi_a.name.as_str()), "bubi");
            assert_eq!(unwrap!(ffi_a.vendor.as_str()), "hey girl");
        }

        let mut a = unsafe { unwrap!(AppExchangeInfo::from_repr_c(ffi_a)) };

        assert_eq!(a.id, "myid");
        assert_eq!(a.scope, Some("hi".to_string()));
        assert_eq!(a.name, "bubi");
        assert_eq!(a.vendor, "hey girl");

        a.scope = None;

        let ffi_a = a.into_repr_c();

        unsafe {
            assert_eq!(unwrap!(ffi_a.id.as_str()), "myid");
            assert_eq!(ffi_a.scope, 0 as *const u8);
            assert_eq!(ffi_a.scope_len, 0);
            assert_eq!(ffi_a.scope_cap, 0);
            assert_eq!(unwrap!(ffi_a.name.as_str()), "bubi");
            assert_eq!(unwrap!(ffi_a.vendor.as_str()), "hey girl");
        }

        unsafe { ffi::app_exchange_info_drop(ffi_a) };
    }

    #[test]
    fn auth_request() {
        let app = AppExchangeInfo {
            id: "1".to_string(),
            scope: Some("2".to_string()),
            name: "3".to_string(),
            vendor: "4".to_string(),
        };

        let a = AuthReq {
            app: app,
            app_container: false,
            containers: HashMap::new(),
        };

        let ffi = a.into_repr_c();

        assert_eq!(ffi.app_container, false);
        assert_eq!(ffi.containers.len, 0);

        let a = unsafe { unwrap!(AuthReq::from_repr_c(ffi)) };

        assert_eq!(a.app.id, "1");
        assert_eq!(a.app.scope, Some("2".to_string()));
        assert_eq!(a.app.name, "3");
        assert_eq!(a.app.vendor, "4");
        assert_eq!(a.app_container, false);
        assert_eq!(a.containers.len(), 0);

        unsafe { ffi::auth_request_drop(a.into_repr_c()) };
    }

    #[test]
    fn containers_req() {
        let app = AppExchangeInfo {
            id: "1".to_string(),
            scope: Some("2".to_string()),
            name: "3".to_string(),
            vendor: "4".to_string(),
        };

        let a = ContainersReq {
            app: app,
            containers: HashMap::new(),
        };

        let ffi = a.into_repr_c();

        assert_eq!(ffi.containers.len, 0);

        let a = unsafe { unwrap!(ContainersReq::from_repr_c(ffi)) };

        assert_eq!(a.app.id, "1");
        assert_eq!(a.app.scope, Some("2".to_string()));
        assert_eq!(a.app.name, "3");
        assert_eq!(a.app.vendor, "4");
        assert_eq!(a.containers.len(), 0);

        unsafe { ffi::containers_req_drop(a.into_repr_c()) };
    }
}
