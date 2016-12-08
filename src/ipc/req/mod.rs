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

use self::ffi::PermissionAccess;
use std::mem;
use util::ffi::FfiString;
use util::ffi::string::ffi_string_free;

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
#[derive(RustcEncodable, RustcDecodable, Debug)]
pub struct AuthReq {
    /// The application identifier for this request
    pub app: AppExchangeInfo,
    /// `true` if the app wants dedicated container for itself. `false`
    /// otherwise.
    pub app_container: bool,
    /// The list of containers it wishes to access (and desired permissions).
    pub containers: Vec<ContainerPermission>,
}

impl AuthReq {
    /// Consumes the object and returns the FFI counterpart.
    ///
    /// You're now responsible for freeing the subobjects memory once you're
    /// done.
    pub fn into_repr_c(self) -> ffi::AuthReq {
        let AuthReq { app, app_container, containers } = self;

        let containers: Vec<_> = containers.into_iter()
            .map(|c| c.into_repr_c())
            .collect();

        ffi::AuthReq {
            app: app.into_repr_c(),
            app_container: app_container,
            containers: ffi::ContainerPermissionArray::from_vec(containers),
        }
    }

    /// Constructs the object from the FFI counterpart.
    ///
    /// After calling this function, the subobjects memory is owned by the
    /// resulting object.
    #[allow(unsafe_code)]
    pub unsafe fn from_repr_c(repr_c: ffi::AuthReq) -> Self {
        let ffi::AuthReq { app, app_container, containers } = repr_c;
        let containers: Vec<_> = containers.into_vec()
            .into_iter()
            .map(|c| ContainerPermission::from_repr_c(c))
            .collect();
        AuthReq {
            app: AppExchangeInfo::from_repr_c(app),
            app_container: app_container,
            containers: containers,
        }
    }
}

/// Containers request
#[derive(RustcEncodable, RustcDecodable, Debug)]
pub struct ContainersReq {
    /// Exchange info
    pub app: AppExchangeInfo,
    /// Requested containers
    pub containers: Vec<ContainerPermission>,
}

impl ContainersReq {
    /// Consumes the object and returns the FFI counterpart.
    ///
    /// You're now responsible for freeing the subobjects memory once you're
    /// done.
    pub fn into_repr_c(self) -> ffi::ContainersReq {
        let ContainersReq { app, containers } = self;
        let containers: Vec<_> = containers.into_iter()
            .map(|c| c.into_repr_c())
            .collect();

        ffi::ContainersReq {
            app: app.into_repr_c(),
            containers: ffi::ContainerPermissionArray::from_vec(containers),
        }
    }

    /// Constructs the object from the FFI counterpart.
    ///
    /// After calling this functions, the subobjects memory is owned by the
    /// resulting object.
    #[allow(unsafe_code)]
    pub unsafe fn from_repr_c(repr_c: ffi::ContainersReq) -> Self {
        let ffi::ContainersReq { app, containers } = repr_c;
        let containers: Vec<_> = containers.into_vec()
            .into_iter()
            .map(|c| ContainerPermission::from_repr_c(c))
            .collect();
        ContainersReq {
            app: AppExchangeInfo::from_repr_c(app),
            containers: containers,
        }
    }
}

/// Represents an application ID in the process of asking permissions
#[derive(RustcEncodable, RustcDecodable, Debug)]
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
    pub unsafe fn from_repr_c(raw: ffi::AppExchangeInfo) -> Self {
        let scope = match (raw.scope, raw.scope_len, raw.scope_cap) {
            (p, _, _) if p.is_null() => None,
            (p, l, c) => Some(String::from_raw_parts(p as *mut u8, l, c)),
        };

        let r = AppExchangeInfo {
            id: unwrap!(raw.id.to_string()),
            scope: scope,
            name: unwrap!(raw.name.to_string()),
            vendor: unwrap!(raw.vendor.to_string()),
        };
        ffi_string_free(raw.id);
        ffi_string_free(raw.name);
        ffi_string_free(raw.vendor);
        r
    }
}

/// Represents the set of permissions for a given container
#[derive(RustcEncodable, RustcDecodable, Debug)]
pub struct ContainerPermission {
    /// The id
    pub container_key: String,
    /// The permissions
    pub access: Vec<PermissionAccess>,
}

impl ContainerPermission {
    /// Consumes the object and returns the wrapped raw pointer
    ///
    /// You're now responsible for freeing this memory once you're done.
    pub fn into_repr_c(self) -> ffi::ContainerPermission {
        let ContainerPermission { container_key, access } = self;

        ffi::ContainerPermission {
            container_key: FfiString::from_string(container_key),
            access: ffi::PermissionAccessArray::from_vec(access),
        }
    }

    /// Constructs the object from a raw pointer.
    ///
    /// After calling this function, the raw pointer is owned by the resulting
    /// object.
    #[allow(unsafe_code)]
    pub unsafe fn from_repr_c(raw: ffi::ContainerPermission) -> Self {
        let r = ContainerPermission {
            container_key: unwrap!(raw.container_key.to_string()),
            access: raw.access.into_vec(),
        };
        ffi_string_free(raw.container_key);
        r
    }
}

#[cfg(test)]
#[allow(unsafe_code)]
mod tests {
    use super::*;

    #[test]
    fn container_permission() {
        let cp = ContainerPermission {
            container_key: "foobar".to_string(),
            access: vec![],
        };

        let ffi_cp = cp.into_repr_c();

        unsafe {
            assert_eq!(unwrap!(ffi_cp.container_key.as_str()), "foobar");
            assert_eq!(ffi_cp.access.len, 0);
        }

        let cp = unsafe { ContainerPermission::from_repr_c(ffi_cp) };

        assert_eq!(cp.container_key, "foobar");
        assert_eq!(cp.access, vec![]);

        // If test runs under special mode (e.g. Valgrind) we can detect memory
        // leaks
        unsafe {
            ffi::container_permission_drop(cp.into_repr_c());
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

        let mut a = unsafe { AppExchangeInfo::from_repr_c(ffi_a) };

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
            containers: vec![],
        };

        let ffi = a.into_repr_c();

        assert_eq!(ffi.app_container, false);
        assert_eq!(ffi.containers.len, 0);

        let a = unsafe { AuthReq::from_repr_c(ffi) };

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
            containers: vec![],
        };

        let ffi = a.into_repr_c();

        assert_eq!(ffi.containers.len, 0);

        let a = unsafe { ContainersReq::from_repr_c(ffi) };

        assert_eq!(a.app.id, "1");
        assert_eq!(a.app.scope, Some("2".to_string()));
        assert_eq!(a.app.name, "3");
        assert_eq!(a.app.vendor, "4");
        assert_eq!(a.containers.len(), 0);

        unsafe { ffi::containers_req_drop(a.into_repr_c()) };
    }
}
