// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use ffi_utils::test_utils::{call_0, call_1, call_2, call_vec};
use ffi_utils::{from_c_str, FfiResult, ReprC, StringError};
use safe_app::ffi::app_registered;
use safe_app::ffi::ipc::*;
use safe_app::ffi::mdata_info::mdata_info_random_public;
use safe_app::ffi::mutable_data::entries::{
    mdata_entries_insert, mdata_entries_new, mdata_list_entries,
};
use safe_app::ffi::mutable_data::entry_actions::{
    mdata_entry_actions_delete, mdata_entry_actions_insert, mdata_entry_actions_new,
    mdata_entry_actions_update,
};
use safe_app::ffi::mutable_data::permissions::{
    mdata_permissions_insert, mdata_permissions_new, USER_ANYONE,
};
use safe_app::ffi::mutable_data::{mdata_entries, mdata_mutate_entries, mdata_put};
use safe_app::{Action, App, PermissionSet};
use safe_authenticator::ffi::apps::*;
use safe_authenticator::ffi::ipc::*;
use safe_authenticator::ffi::*;
use safe_authenticator::test_utils::*;
use safe_authenticator::{AuthError, Authenticator};
use safe_core::ffi::ipc::resp::AuthGranted as FfiAuthGranted;
use safe_core::ipc::req::{
    permission_set_into_repr_c, AppExchangeInfo, AuthReq, ContainerPermissions,
};
use safe_core::ipc::resp::{MDataEntry, MDataKey, MDataValue};
use safe_core::ipc::{AuthGranted, Permission};
use safe_core::nfs::{Mode, NfsError};
use safe_core::MDataInfo;
use safe_core::{utils, CoreError};
use serde_json;
use std::collections::HashMap;
use std::env;
use std::ffi::CString;
use std::fs::File;
use std::io;
use std::io::{Read, Write};
use std::os::raw::c_void;

static READ_WRITE_APP_ID: &str = "0123456789";
static READ_WRITE_FILE_NAME: &str = "test.mp4";

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
        Some((acc_locator, acc_password)) => TestConfig {
            test_account: AccountConfig {
                acc_locator: acc_locator.clone(),
                acc_password: acc_password.clone(),
            },
        },
        None => {
            let file = unwrap!(File::open("tests.config"));
            unwrap!(serde_json::from_reader(file))
        }
    }
}

// Copies over crust.config and logs into the Authenticator.
fn setup_test() -> *mut Authenticator {
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

    let test_acc = get_config().test_account;
    let locator = unwrap!(CString::new(test_acc.acc_locator.clone()));
    let password = unwrap!(CString::new(test_acc.acc_password.clone()));

    // Login to the Authenticator.
    println!(
        "Logging in\n... locator: {}\n... password: {}",
        test_acc.acc_locator, test_acc.acc_password
    );
    let auth_h: *mut Authenticator = unsafe {
        unwrap!(call_1(|ud, cb| login(
            locator.as_ptr(),
            password.as_ptr(),
            ud,
            disconnect_cb,
            cb
        )))
    };
    auth_h
}

// Write data for the `read_data` step. This must be run before `read_data`.
//
// This test in conjunction with `read_data` is useful for verifying data compatibility after
// making possibly breaking changes.
#[ignore]
#[test]
fn write_data() {
    let auth_h = setup_test();

    let app_id = READ_WRITE_APP_ID;
    let file_name = READ_WRITE_FILE_NAME;

    let ffi_app_id = unwrap!(CString::new(app_id));
    println!("App ID: {}", app_id);

    let app_info = AppExchangeInfo {
        id: app_id.to_string(),
        scope: None,
        // Use ID for name so the app is easier to find in Browser.
        name: app_id.to_string(),
        vendor: app_id.to_string(),
    };

    println!("Authorising app...");
    let auth_granted = ffi_authorise_app(auth_h, &app_info);

    // Register the app.
    println!("Registering app...");
    let _app: *mut App = unsafe {
        unwrap!(call_1(|ud, cb| app_registered(
            ffi_app_id.as_ptr(),
            &unwrap!(auth_granted.clone().into_repr_c()),
            ud,
            disconnect_cb,
            cb,
        )))
    };

    // Put file into container.
    println!("File name: {}", file_name);

    unsafe {
        let mut ac_entries = access_container(&*auth_h, app_id, auth_granted.clone());
        let (videos_md, _) = unwrap!(ac_entries.remove("_videos"));

        match fetch_file(&*auth_h, videos_md.clone(), file_name) {
            Ok(file) => {
                println!("Writing to file...");

                unwrap!(write_file(
                    &*auth_h,
                    file,
                    Mode::Overwrite,
                    videos_md.enc_key().cloned(),
                    vec![1; 10],
                ));
            }
            Err(e) => {
                println!("Could not fetch file: {:?}", e);
                println!("Creating file...");

                unwrap!(create_file(
                    &*auth_h,
                    videos_md.clone(),
                    file_name,
                    vec![1; 10],
                ));
            }
        }
    }

    println!("Data written successfully.");
}

// Test that data written during the `write_data` step can be read successfully. `write_data` must
// be run first.
//
// This test in conjunction with `write_data` is useful for verifying data compatibility after
// making possibly breaking changes.
#[ignore]
#[test]
fn read_data() {
    let auth_h = setup_test();

    let app_id = READ_WRITE_APP_ID;
    let file_name = READ_WRITE_FILE_NAME;

    let _ffi_app_id = unwrap!(CString::new(app_id));
    println!("App ID: {}", app_id);

    let app_info = AppExchangeInfo {
        id: app_id.to_string(),
        scope: None,
        name: app_id.to_string(),
        vendor: app_id.to_string(),
    };

    // Authorise the app.
    println!("Authorising app...");
    let auth_granted = ffi_authorise_app(auth_h, &app_info);

    // Get a list of registered apps, confirm our app is in it.
    let registered_apps: Vec<RegisteredAppId> =
        unsafe { unwrap!(call_vec(|ud, cb| auth_registered_apps(auth_h, ud, cb))) };
    let any = registered_apps
        .iter()
        .any(|registered_app_id| registered_app_id.0 == app_id);
    assert!(any);

    let videos_md = unsafe {
        let mut ac_entries = access_container(&*auth_h, app_id, auth_granted.clone());
        let (videos_md, _) = unwrap!(ac_entries.remove("_videos"));
        videos_md
    };

    // The app can access the file.
    println!("Confirming we can read written data...");
    unsafe {
        let file = unwrap!(fetch_file(&*auth_h, videos_md.clone(), file_name));

        let content = unwrap!(read_file(&*auth_h, file, videos_md.enc_key().cloned()));
        assert_eq!(content, vec![1; 10]);
    }

    println!("Data read successfully.");
}

// Test that basic mdata operations work on the real network.
#[ignore]
#[test]
fn mdata_operations() {
    let auth_h = setup_test();

    // Create and authorise an app.
    let app_id = unwrap!(utils::generate_readable_string(10));
    let ffi_app_id = unwrap!(CString::new(app_id.clone()));
    println!("App ID: {}", app_id);

    let app_info = AppExchangeInfo {
        id: app_id.clone(),
        scope: None,
        name: app_id.clone(), // Use ID for name so the app is easier to find in Browser.
        vendor: app_id.clone(),
    };

    println!("Authorising app...");

    let auth_granted = ffi_authorise_app(auth_h, &app_info);

    println!("Registering app...");

    let app: *mut App = unsafe {
        unwrap!(call_1(|ud, cb| app_registered(
            ffi_app_id.as_ptr(),
            &unwrap!(auth_granted.clone().into_repr_c()),
            ud,
            disconnect_cb,
            cb,
        )))
    };

    println!("Creating random mdata...");

    let type_tag = 15_000;
    let mdata_info: MDataInfo =
        unsafe { unwrap!(call_1(|ud, cb| mdata_info_random_public(type_tag, ud, cb))) };
    let mdata_info = mdata_info.into_repr_c();

    // Create permissions for anyone
    let perms_h = unsafe { unwrap!(call_1(|ud, cb| mdata_permissions_new(app, ud, cb))) };
    {
        // Create a permissions set
        let perms_set = PermissionSet::new()
            .allow(Action::Insert)
            .allow(Action::Update)
            .allow(Action::Delete);

        unsafe {
            unwrap!(call_0(|ud, cb| mdata_permissions_insert(
                app,
                perms_h,
                USER_ANYONE,
                &permission_set_into_repr_c(perms_set),
                ud,
                cb,
            )))
        };
    }

    let entries_h = unsafe { unwrap!(call_1(|ud, cb| mdata_entries_new(app, ud, cb))) };

    let key0 = b"random_key_1".to_vec();
    let value0 = b"Scotland to try Scotch whisky".to_vec();
    let key1 = b"random_key_2".to_vec();
    let value1 = b"Patagonia before I'm too old".to_vec();
    let value1_2 = b"Bogota before I'm too old".to_vec();
    let key2 = b"random_key_3".to_vec();
    let value2 = b"Cyprus for falafels and kebab".to_vec();

    unsafe {
        unwrap!(call_0(|ud, cb| mdata_entries_insert(
            app,
            entries_h,
            key0.as_ptr(),
            key0.len(),
            value0.as_ptr(),
            value0.len(),
            ud,
            cb
        )));
        unwrap!(call_0(|ud, cb| mdata_entries_insert(
            app,
            entries_h,
            key1.as_ptr(),
            key1.len(),
            value1.as_ptr(),
            value1.len(),
            ud,
            cb
        )));
    }

    // Put the entries to the mdata.
    unsafe {
        unwrap!(call_0(|ud, cb| mdata_put(
            app,
            &mdata_info,
            perms_h,
            entries_h,
            ud,
            cb
        )))
    };

    println!("Getting the list of mdata entries...");

    let entries: Vec<MDataEntry> = unsafe {
        unwrap!(call_vec(|ud, cb| mdata_list_entries(
            app, entries_h, ud, cb
        )))
    };

    assert_eq!(entries[0].key, MDataKey(key0.clone()));
    assert_eq!(
        entries[0].value,
        MDataValue {
            content: value0,
            entry_version: 0
        }
    );
    assert_eq!(entries[1].key, MDataKey(key1.clone()));
    assert_eq!(
        entries[1].value,
        MDataValue {
            content: value1,
            entry_version: 0
        }
    );

    println!("Inserting, mutating, and deleting the entries...");

    let actions_h = unsafe { unwrap!(call_1(|ud, cb| mdata_entry_actions_new(app, ud, cb))) };

    unsafe {
        unwrap!(call_0(|ud, cb| mdata_entry_actions_insert(
            app,
            actions_h,
            key2.as_ptr(),
            key2.len(),
            value2.as_ptr(),
            value2.len(),
            ud,
            cb
        )));

        unwrap!(call_0(|ud, cb| mdata_entry_actions_update(
            app,
            actions_h,
            key1.as_ptr(),
            key1.len(),
            value1_2.as_ptr(),
            value1_2.len(),
            1,
            ud,
            cb
        )));

        unwrap!(call_0(|ud, cb| mdata_entry_actions_delete(
            app,
            actions_h,
            key0.as_ptr(),
            key0.len(),
            1,
            ud,
            cb
        )))
    }

    // Apply the mutation.
    unsafe {
        unwrap!(call_0(|ud, cb| mdata_mutate_entries(
            app,
            &mdata_info,
            actions_h,
            ud,
            cb
        )))
    }

    println!("Getting the list of mdata entries...");

    let entries_h = unsafe { unwrap!(call_1(|ud, cb| mdata_entries(app, &mdata_info, ud, cb))) };

    let entries: Vec<MDataEntry> = unsafe {
        unwrap!(call_vec(|ud, cb| mdata_list_entries(
            app, entries_h, ud, cb
        )))
    };

    assert_eq!(entries[0].key, MDataKey(key0));
    assert_eq!(
        entries[0].value,
        MDataValue {
            content: b"".to_vec(),
            entry_version: 1
        }
    );
    assert_eq!(entries[1].key, MDataKey(key1));
    assert_eq!(
        entries[1].value,
        MDataValue {
            content: value1_2,
            entry_version: 1
        }
    );
    assert_eq!(entries[2].key, MDataKey(key2));
    assert_eq!(
        entries[2].value,
        MDataValue {
            content: value2,
            entry_version: 0
        }
    );
}

#[ignore]
#[test]
fn authorisation_and_revocation() {
    let auth_h = setup_test();

    // Create and authorise an app.
    let app_id = unwrap!(utils::generate_readable_string(10));
    let ffi_app_id = unwrap!(CString::new(app_id.clone()));
    println!("App ID: {}", app_id);

    let app_info = AppExchangeInfo {
        id: app_id.clone(),
        scope: None,
        name: app_id.clone(), // Use ID for name so the app is easier to find in Browser.
        vendor: app_id.clone(),
    };

    println!("Authorising app...");

    let auth_granted = ffi_authorise_app(auth_h, &app_info);

    println!("Registering app...");

    let _app: *mut App = unsafe {
        unwrap!(call_1(|ud, cb| app_registered(
            ffi_app_id.as_ptr(),
            &unwrap!(auth_granted.clone().into_repr_c()),
            ud,
            disconnect_cb,
            cb,
        )))
    };

    // Get a list of registered apps, confirm our app is in it.
    let registered_apps: Vec<RegisteredAppId> =
        unsafe { unwrap!(call_vec(|ud, cb| auth_registered_apps(auth_h, ud, cb))) };
    let any = registered_apps
        .iter()
        .any(|registered_app_id| registered_app_id.0 == app_id);
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

    println!("Revoking app...");

    let _: String = unsafe {
        unwrap!(call_1(|ud, cb| auth_revoke_app(
            auth_h,
            ffi_app_id.as_ptr(),
            ud,
            cb
        )))
    };

    // Get list of revoked apps, confirm our app is in it.
    let revoked_apps: Vec<AppExchangeInfo> =
        unsafe { unwrap!(call_vec(|ud, cb| auth_revoked_apps(auth_h, ud, cb))) };
    assert!(revoked_apps
        .iter()
        .any(|revoked_app| revoked_app.id == app_id,));

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

    println!("Re-authorising app...");

    let auth_granted = ffi_authorise_app(auth_h, &app_info);

    println!("Re-registering app...");

    let _app: *mut App = unsafe {
        unwrap!(call_1(|ud, cb| app_registered(
            ffi_app_id.as_ptr(),
            &unwrap!(auth_granted.clone().into_repr_c()),
            ud,
            disconnect_cb,
            cb,
        )))
    };

    // Get a list of registered apps, confirm our app is in it.
    let registered_apps: Vec<RegisteredAppId> =
        unsafe { unwrap!(call_vec(|ud, cb| auth_registered_apps(auth_h, ud, cb))) };
    let any = registered_apps
        .iter()
        .any(|registered_app_id| registered_app_id.0 == app_id);
    assert!(any);

    // The app can access the file again.
    unsafe {
        let mut ac_entries = access_container(&*auth_h, app_id.clone(), auth_granted.clone());
        let (videos_md, _) = unwrap!(ac_entries.remove("_videos"));
        let _ = unwrap!(fetch_file(&*auth_h, videos_md.clone(), file_name));
    };

    println!("Revoking app...");

    let _: String = unsafe {
        unwrap!(call_1(|ud, cb| auth_revoke_app(
            auth_h,
            ffi_app_id.as_ptr(),
            ud,
            cb
        )))
    };

    // Remove the revoked app
    unsafe {
        unwrap!(call_0(|ud, cb| auth_rm_revoked_app(
            auth_h,
            ffi_app_id.as_ptr(),
            ud,
            cb
        )))
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
                auth_h, &auth_req, req_id, true, // is_granted
                ud, cb,
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
fn create_containers_req() -> HashMap<String, ContainerPermissions> {
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
    _bootstrap_cfg: *const u8,
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
