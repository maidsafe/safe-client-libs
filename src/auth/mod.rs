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

use routing::XorName;
use rust_sodium::crypto::{box_, secretbox, sign};
use std::mem;

/// TODO: doc
pub mod ffi;

use self::ffi::PermissionAccess;

// TODO: replace with `crust::Config`
/// empty doc
pub struct Config;

/// TODO: doc
pub struct ContainerPermission {
    /// TODO: doc
    pub container_key: String,
    /// TODO: doc
    pub access: Vec<PermissionAccess>,
}

impl ContainerPermission {
    /// TODO: doc
    pub fn into_raw(self) -> *mut ffi::ContainerPermission {
        let ContainerPermission { container_key, mut access } = self;

        let ck_ptr = container_key.as_ptr();
        let ck_len = container_key.len();
        let ck_cap = container_key.capacity();

        mem::forget(container_key);

        let a_ptr = access.as_mut_ptr();
        let a_len = access.len();
        let a_cap = access.capacity();

        mem::forget(access);

        Box::into_raw(Box::new(ffi::ContainerPermission {
            container_key: ck_ptr,
            container_key_len: ck_len,
            container_key_cap: ck_cap,
            access: a_ptr,
            access_len: a_len,
            access_cap: a_cap,
        }))
    }

    /// TODO: doc
    #[allow(unsafe_code)]
    pub unsafe fn from_raw(raw: *mut ffi::ContainerPermission) -> Self {
        let raw = Box::from_raw(raw);
        let ck = String::from_raw_parts(raw.container_key as *mut u8,
                                        raw.container_key_len,
                                        raw.container_key_cap);
        let a = Vec::from_raw_parts(raw.access, raw.access_len, raw.access_cap);
        ContainerPermission {
            container_key: ck,
            access: a,
        }
    }
}

/// TODO: doc
pub struct AppExchangeInfo {
    /// TODO: doc
    pub id: String,
    /// TODO: doc
    pub scope: Option<String>,
    /// TODO: doc
    pub name: String,
    /// TODO: doc
    pub vendor: String,
}

impl AppExchangeInfo {
    /// TODO: doc
    pub fn into_raw(self) -> *mut ffi::AppExchangeInfo {
        let AppExchangeInfo { id, scope, name, vendor } = self;

        let id_ptr = id.as_ptr();
        let id_len = id.len();
        let id_cap = id.capacity();

        mem::forget(id);

        let (s_ptr, s_len, s_cap) = match scope {
            Some(ref s) => (s.as_ptr(), s.len(), s.capacity()),
            None => (0 as *const u8, 0, 0),
        };

        mem::forget(scope);

        let n_ptr = name.as_ptr();
        let n_len = name.len();
        let n_cap = name.capacity();

        mem::forget(name);

        let v_ptr = vendor.as_ptr();
        let v_len = vendor.len();
        let v_cap = vendor.capacity();

        mem::forget(vendor);

        Box::into_raw(Box::new(ffi::AppExchangeInfo {
            id: id_ptr,
            id_len: id_len,
            id_cap: id_cap,
            scope: s_ptr,
            scope_len: s_len,
            scope_cap: s_cap,
            name: n_ptr,
            name_len: n_len,
            name_cap: n_cap,
            vendor: v_ptr,
            vendor_len: v_len,
            vendor_cap: v_cap,
        }))
    }

    /// TODO: doc
    #[allow(unsafe_code)]
    pub unsafe fn from_raw(raw: *mut ffi::AppExchangeInfo) -> Self {
        let raw = Box::from_raw(raw);
        let id = String::from_raw_parts(raw.id as *mut u8, raw.id_len, raw.id_cap);
        let scope = match (raw.scope, raw.scope_len, raw.scope_cap) {
            (p, _, _) if p == 0 as *const u8 => None,
            (p, l, c) => Some(String::from_raw_parts(p as *mut u8, l, c)),
        };
        let name = String::from_raw_parts(raw.name as *mut u8, raw.name_len, raw.name_cap);
        let vendor = String::from_raw_parts(raw.vendor as *mut u8, raw.vendor_len, raw.vendor_cap);

        AppExchangeInfo {
            id: id,
            scope: scope,
            name: name,
            vendor: vendor,
        }
    }
}

/// TODO: doc
pub struct AuthRequest {
    /// TODO: doc
    pub app: AppExchangeInfo,
    /// TODO: doc
    pub app_container: bool,
    /// TODO: doc
    pub containers: Vec<ContainerPermission>,
}

impl AuthRequest {
    /// TODO: doc
    pub fn into_raw(self) -> *mut ffi::AuthRequest {
        let AuthRequest { app, app_container, containers } = self;

        let mut containers: Vec<_> = containers.into_iter()
            .map(|c| c.into_raw())
            .collect();

        let c_ptr = containers.as_mut_ptr();
        let c_len = containers.len();
        let c_cap = containers.capacity();

        mem::forget(containers);

        Box::into_raw(Box::new(ffi::AuthRequest {
            app: app.into_raw(),
            app_container: app_container,
            containers: c_ptr,
            containers_len: c_len,
            containers_cap: c_cap,
        }))
    }

    /// TODO: doc
    #[allow(unsafe_code)]
    pub unsafe fn from_raw(raw: *mut ffi::AuthRequest) -> Self {
        let raw = Box::from_raw(raw);
        let app = AppExchangeInfo::from_raw(raw.app);
        let containers =
            Vec::from_raw_parts(raw.containers, raw.containers_len, raw.containers_cap)
                .into_iter()
                .map(|c| ContainerPermission::from_raw(c))
                .collect();
        AuthRequest {
            app: app,
            app_container: raw.app_container,
            containers: containers,
        }
    }
}

/// TODO: doc
pub struct AppAccessToken {
    /// TODO: doc
    pub enc_key: secretbox::Key,
    /// TODO: doc
    pub sign_pk: sign::PublicKey,
    /// TODO: doc
    pub sign_sk: sign::SecretKey,
    /// TODO: doc
    pub enc_pk: box_::PublicKey,
    /// TODO: doc
    pub enc_sk: box_::SecretKey,
}

impl AppAccessToken {
    /// TODO: doc
    pub fn into_raw(self) -> *mut ffi::AppAccessToken {
        let AppAccessToken { enc_key, sign_pk, sign_sk, enc_pk, enc_sk } = self;
        Box::into_raw(Box::new(ffi::AppAccessToken {
            enc_key: enc_key.0,
            sign_pk: sign_pk.0,
            sign_sk: sign_sk.0,
            enc_pk: enc_pk.0,
            enc_sk: enc_sk.0,
        }))
    }

    /// TODO: doc
    #[allow(unsafe_code)]
    pub unsafe fn from_raw(raw: *mut ffi::AppAccessToken) -> Self {
        let raw = Box::from_raw(raw);
        AppAccessToken {
            enc_key: secretbox::Key::from_slice(&raw.enc_key)
                .expect("Only fails if struct layout in code is wrong"),
            sign_pk: sign::PublicKey::from_slice(&raw.sign_pk)
                .expect("Only fails if struct layout in code is wrong"),
            sign_sk: sign::SecretKey::from_slice(&raw.sign_sk)
                .expect("Only fails if struct layout in code is wrong"),
            enc_pk: box_::PublicKey::from_slice(&raw.enc_pk)
                .expect("Only fails if struct layout in code is wrong"),
            enc_sk: box_::SecretKey::from_slice(&raw.enc_sk)
                .expect("Only fails if struct layout in code is wrong"),
        }
    }
}

/// TODO: doc
pub enum AuthResponse {
    /// TODO: doc
    Granted {
        /// TODO: doc
        access_token: AppAccessToken,
        /// TODO: doc
        bootstrap_config: Config,
        /// TODO: doc
        access_container: Option<(XorName, u64, secretbox::Nonce)>,
    },
    /// TODO: doc
    Denied,
}
