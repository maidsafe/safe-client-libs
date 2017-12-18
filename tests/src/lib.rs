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

//! Integration tests for Safe Client Libs.

#![cfg(test)]

// For explanation of lint checks, run `rustc -W help` or see
// https://github.
// com/maidsafe/QA/blob/master/Documentation/Rust%20Lint%20Checks.md
#![forbid(exceeding_bitshifts, mutable_transmutes, no_mangle_const_items,
          unknown_crate_types, warnings)]
#![deny(bad_style, deprecated, improper_ctypes, missing_docs,
        non_shorthand_field_patterns, overflowing_literals, plugin_as_library,
        private_no_mangle_fns, private_no_mangle_statics, stable_features,
        unconditional_recursion, unknown_lints, unused,
        unused_allocation, unused_attributes, unused_comparisons, unused_features,
        unused_parens, while_true)]
#![warn(trivial_casts, trivial_numeric_casts, unused_extern_crates, unused_import_braces,
        unused_qualifications, unused_results)]
#![allow(box_pointers, missing_copy_implementations, missing_debug_implementations,
         variant_size_differences)]

#![cfg_attr(feature="cargo-clippy", deny(clippy, unicode_not_nfc, wrong_pub_self_convention,
                                         option_unwrap_used))]
#![cfg_attr(feature="cargo-clippy", allow(use_debug, too_many_arguments))]

extern crate ffi_utils;
extern crate safe_app;
extern crate safe_authenticator;
#[macro_use]
extern crate safe_core;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
#[macro_use]
extern crate unwrap;

use ffi_utils::{FfiResult, ReprC, StringError, from_c_str};
use ffi_utils::test_utils::{call_0, call_1, call_2, call_vec};
use safe_app::App;
use safe_app::ffi::app_registered;
use safe_app::ffi::ipc::*;
use safe_authenticator::{AuthError, Authenticator};
use safe_authenticator::ffi::*;
use safe_authenticator::ffi::apps::*;
use safe_authenticator::ffi::ipc::*;
use safe_authenticator::test_utils::*;
use safe_core::{CoreError, utils};
use safe_core::ffi::ipc::resp::AuthGranted as FfiAuthGranted;
use safe_core::ipc::{AuthGranted, Permission};
use safe_core::ipc::req::{AppExchangeInfo, AuthReq, ContainerPermissions};
use safe_core::nfs::NfsError;
use std::collections::HashMap;
use std::env;
use std::ffi::CString;
use std::fs::File;
use std::io;
use std::io::{Read, Write};
use std::os::raw::c_void;

// Configuration for tests.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct TestConfig {
    /// Developer options.
    pub test_account: AccountConfig,
}

// Configuration for accounts.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct AccountConfig {
    acc_locator: String, // account secret
    acc_password: String,
}

// Gets account credentials from the env vars "TEST_ACC_LOCATOR" and "TEST_ACC_PASSWORD".
// If not found, reads the `tests.config` config file and returns it or panics if this fails.
fn get_config() -> TestConfig {
    let env_locator = env::var("TEST_ACC_LOCATOR");
    let env_password = env::var("TEST_ACC_PASSWORD");
    let env = env_locator.iter().zip(env_password.iter()).next();

    match env {
        Some((acc_locator, acc_password)) => {
            TestConfig {
                test_account: AccountConfig {
                    acc_locator: acc_locator.clone(),
                    acc_password: acc_password.clone(),
                },
            }
        }
        None => {
            let file = unwrap!(File::open("tests.config"));
            unwrap!(serde_json::from_reader(file))
        }
    }
}

#[test]
fn authorisation_and_revocation() {
    let test_acc = get_config().test_account;
    let locator = unwrap!(CString::new(test_acc.acc_locator.clone()));
    let password = unwrap!(CString::new(test_acc.acc_password.clone()));

    // Copy crust.config file to <exe>.crust.config
    {
        let exe_path = unwrap!(env::current_exe());
        let exe_path = exe_path.as_path();

        // Test `auth_exe_file_stem`
        let auth_exe: String = unsafe { unwrap!(call_1(|ud, cb| auth_exe_file_stem(ud, cb))) };
        assert_eq!(auth_exe, unwrap!(unwrap!(exe_path.file_name()).to_str()));

        let crust_config_file = format!("{}.crust.config", unwrap!(exe_path.to_str()));
        println!("Copying crust.config to \"{}\"", crust_config_file);

        let config_contents = unwrap!(read_file_str("crust.config"));
        unwrap!(write_file_str(&crust_config_file, &config_contents));
    }

    // Login to the Authenticator
    println!(
        "Logging in\n... locator: {}\n... password: {}",
        test_acc.acc_locator,
        test_acc.acc_password
    );
    let auth_h: *mut Authenticator = unsafe {
        unwrap!(call_1(|ud, cb| {
            login(locator.as_ptr(), password.as_ptr(), ud, disconnect_cb, cb)
        }))
    };

    // Create and authorise an app
    let app_id = unwrap!(utils::generate_readable_string(10));
    let ffi_app_id = unwrap!(CString::new(app_id.clone()));
    println!("App ID: {}", app_id);

    let app_info = AppExchangeInfo {
        id: app_id.clone(),
        scope: None,
        name: app_id.clone(), // Use ID for name so the app is easier to find in Browser.
        vendor: unwrap!(utils::generate_readable_string(10)),
    };

    println!("Authorising app...");
    let auth_granted = ffi_authorise_app(auth_h, &app_info);

    // Register the app.
    println!("Registering app...");
    let _app: *mut App = unsafe {
        unwrap!(call_1(|ud, cb| {
            app_registered(
                ffi_app_id.as_ptr(),
                &unwrap!(auth_granted.clone().into_repr_c()),
                ud,
                disconnect_cb,
                cb,
            )
        }))
    };

    // Get a list of registered apps, confirm our app is in it.
    let registered_apps: Vec<RegisteredAppId> =
        unsafe { unwrap!(call_vec(|ud, cb| auth_registered_apps(auth_h, ud, cb))) };
    let any = registered_apps.iter().any(|registered_app_id| {
        registered_app_id.0 == app_id
    });
    assert!(any);

    // Put file into container.
    println!("Creating file...");
    let file_name = format!("{}.mp4", unwrap!(utils::generate_readable_string(10)));
    println!("File name: {}", file_name.clone());

    let videos_md = unsafe {
        let mut ac_entries = access_container(&*auth_h, app_id.clone(), auth_granted.clone());
        let (videos_md, _) = unwrap!(ac_entries.remove("_videos"));
        unwrap!(create_file(
            &*auth_h,
            videos_md.clone(),
            file_name.as_str(),
            vec![1; 10],
        ));
        videos_md
    };

    // The app can access the file.
    unsafe {
        let _ = unwrap!(fetch_file(&*auth_h, videos_md.clone(), file_name.as_str()));
    }

    // Revoke our app.
    println!("Revoking app...");
    let _: String = unsafe {
        unwrap!(call_1(|ud, cb| {
            auth_revoke_app(auth_h, ffi_app_id.as_ptr(), ud, cb)
        }))
    };

    // Get list of revoked apps, confirm our app is in it.
    let revoked_apps: Vec<AppExchangeInfo> =
        unsafe { unwrap!(call_vec(|ud, cb| auth_revoked_apps(auth_h, ud, cb))) };
    assert!(revoked_apps.iter().any(
        |revoked_app| revoked_app.id == app_id,
    ));

    // The app is no longer in the access container.
    unsafe {
        let ac = try_access_container(&*auth_h, app_id.clone(), auth_granted.clone());
        assert!(ac.is_none());

        // The app can no longer access the file.
        match fetch_file(&*auth_h, videos_md.clone(), file_name.as_str()) {
            Err(AuthError::NfsError(NfsError::CoreError(CoreError::EncodeDecodeError(..)))) => (),
            x => panic!("Unexpected {:?}", x),
        }
    }

    // Re-authorise the app.
    println!("Re-authorising app...");
    let auth_granted = ffi_authorise_app(auth_h, &app_info);

    println!("Re-registering app...");
    let _app: *mut App = unsafe {
        unwrap!(call_1(|ud, cb| {
            app_registered(
                ffi_app_id.as_ptr(),
                &unwrap!(auth_granted.clone().into_repr_c()),
                ud,
                disconnect_cb,
                cb,
            )
        }))
    };

    // Get a list of registered apps, confirm our app is in it.
    let registered_apps: Vec<RegisteredAppId> =
        unsafe { unwrap!(call_vec(|ud, cb| auth_registered_apps(auth_h, ud, cb))) };
    let any = registered_apps.iter().any(|registered_app_id| {
        registered_app_id.0 == app_id
    });
    assert!(any);

    // The app can access the file again.
    unsafe {
        let mut ac_entries = access_container(&*auth_h, app_id.clone(), auth_granted.clone());
        let (videos_md, _) = unwrap!(ac_entries.remove("_videos"));
        let _ = unwrap!(fetch_file(&*auth_h, videos_md.clone(), file_name));
    };

    // Revoke our app.
    println!("Revoking app...");
    let _: String = unsafe {
        unwrap!(call_1(|ud, cb| {
            auth_revoke_app(auth_h, ffi_app_id.as_ptr(), ud, cb)
        }))
    };

    // Remove the revoked app
    unsafe {
        unwrap!(call_0(|ud, cb| {
            auth_rm_revoked_app(auth_h, ffi_app_id.as_ptr(), ud, cb)
        }))
    }
}

// Authorises the app.
fn ffi_authorise_app(auth_h: *mut Authenticator, app_info: &AppExchangeInfo) -> AuthGranted {
    let auth_req = AuthReq {
        app: app_info.clone(),
        app_container: false,
        containers: create_containers_req(),
    };
    let ffi_auth_req = unwrap!(auth_req.clone().into_repr_c());

    let (req_id, _encoded): (u32, String) =
        unsafe { unwrap!(call_2(|ud, cb| encode_auth_req(&ffi_auth_req, ud, cb))) };

    let encoded_auth_resp: String = unsafe {
        unwrap!(call_1(|ud, cb| {
            let auth_req = unwrap!(auth_req.into_repr_c());
            encode_auth_resp(
                auth_h,
                &auth_req,
                req_id,
                true, // is_granted
                ud,
                cb,
            )
        }))
    };
    let encoded_auth_resp = unwrap!(CString::new(encoded_auth_resp));

    let mut context = Context {
        unexpected_cb: false,
        req_id: 0,
        auth_granted: None,
    };

    let context_ptr: *mut Context = &mut context;
    unsafe {
        decode_ipc_msg(
            encoded_auth_resp.as_ptr(),
            context_ptr as *mut c_void,
            auth_cb,
            unregistered_cb,
            containers_cb,
            share_mdata_cb,
            revoked_cb,
            err_cb,
        );
    }

    assert!(!context.unexpected_cb);
    assert_eq!(context.req_id, req_id);

    unwrap!(context.auth_granted)
}

// Creates a containers request asking for "videos with all the permissions possible".
pub fn create_containers_req() -> HashMap<String, ContainerPermissions> {
    let mut containers = HashMap::new();
    let _ = containers.insert(
        "_videos".to_owned(),
        btree_set![
            Permission::Read,
            Permission::Insert,
            Permission::Update,
            Permission::Delete,
            Permission::ManagePermissions,
        ],
    );
    containers
}

struct Context {
    unexpected_cb: bool,
    req_id: u32,
    auth_granted: Option<AuthGranted>,
}

extern "C" fn auth_cb(ctx: *mut c_void, req_id: u32, auth_granted: *const FfiAuthGranted) {
    unsafe {
        let auth_granted = unwrap!(AuthGranted::clone_from_repr_c(auth_granted));

        let ctx = ctx as *mut Context;
        (*ctx).req_id = req_id;
        (*ctx).auth_granted = Some(auth_granted);
    }
}

extern "C" fn containers_cb(ctx: *mut c_void, _req_id: u32) {
    unsafe {
        let ctx = ctx as *mut Context;
        (*ctx).unexpected_cb = true;
    }
}

extern "C" fn share_mdata_cb(ctx: *mut c_void, _req_id: u32) {
    unsafe {
        let ctx = ctx as *mut Context;
        (*ctx).unexpected_cb = true;
    }
}

extern "C" fn revoked_cb(ctx: *mut c_void) {
    unsafe {
        let ctx = ctx as *mut Context;
        (*ctx).unexpected_cb = true;
    }
}

extern "C" fn unregistered_cb(
    ctx: *mut c_void,
    _req_id: u32,
    _bootstrap_cfg_ptr: *const u8,
    _bootstrap_cfg_len: usize,
) {
    unsafe {
        let ctx = ctx as *mut Context;
        (*ctx).unexpected_cb = true;
    }
}

extern "C" fn err_cb(ctx: *mut c_void, _res: *const FfiResult, _req_id: u32) {
    unsafe {
        let ctx = ctx as *mut Context;
        (*ctx).unexpected_cb = true;
    }
}

extern "C" fn disconnect_cb(_user_data: *mut c_void) {
    panic!("Disconnect callback")
}

struct RegisteredAppId(String);
impl ReprC for RegisteredAppId {
    type C = *const RegisteredApp;
    type Error = StringError;

    unsafe fn clone_from_repr_c(repr_c: Self::C) -> Result<Self, Self::Error> {
        Ok(RegisteredAppId(from_c_str((*repr_c).app_info.id)?))
    }
}

// Reads a file and returns its contents in a string.
fn read_file_str(fname: &str) -> io::Result<String> {
    // Open the path in read-only mode
    let mut file = File::open(fname)?;

    let mut contents = String::new();
    let _ = file.read_to_string(&mut contents)?;

    Ok(contents)
}

// Writes a string to a file.
fn write_file_str(fname: &str, contents: &str) -> io::Result<()> {
    // Open a file in write-only mode
    let mut file = File::create(fname)?;

    file.write_all(contents.as_bytes())?;

    Ok(())
}
