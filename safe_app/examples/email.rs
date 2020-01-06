// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net
// Commercial License, version 1.0 or later, or (2) The General Public License
// (GPL), version 3, depending on which licence you accepted on initial access
// to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project
// generally, you agree to be bound by the terms of the MaidSafe Contributor
// Agreement, version 1.0. This, along with the Licenses can be found in the
// root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network
// Software distributed under the GPL Licence is distributed on an "AS IS"
// BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
//
// Please review the Licences for the specific language governing permissions
// and limitations relating to use of the SAFE Network Software.

//! Email Example

// For explanation of lint checks, run `rustc -W help`.
#![warn(
    missing_docs,
    trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    unused_results
)]

use ffi_utils::test_utils::{call_0, call_1, call_2, call_vec};
use ffi_utils::FfiResult;
use ffi_utils::ReprC;
use safe_app::entry_actions::{mdata_entry_actions_insert, mdata_entry_actions_new};
use safe_app::ffi::app_registered;
use safe_app::ffi::ipc::encode_auth_req;
use safe_app::mutable_data::permissions::{
    mdata_permissions_insert, mdata_permissions_len, mdata_permissions_new,
};
use safe_app::mutable_data::{
    mdata_list_user_permissions, mdata_mutate_entries, mdata_put, seq_mdata_list_values,
    ENTRIES_EMPTY,
};
use safe_app::{decode_ipc_msg, run, App, MDataPermissionsHandle};
use safe_authenticator::ffi::ipc::encode_auth_resp;
use safe_authenticator::{create_acc, ffi::login, Authenticator};
use safe_core::client::Client;
use safe_core::core_structs::MDataValue;
use safe_core::ffi::ipc::req::PermissionSet as FfiPermissionSet;
use safe_core::ffi::ipc::resp::AuthGranted as FfiAuthGranted;
use safe_core::ipc::req::{permission_set_clone_from_repr_c, permission_set_into_repr_c};
use safe_core::ipc::{AppExchangeInfo, AuthGranted, AuthReq};
use safe_core::MDataInfo as NativeMDataInfo;
use safe_nd::{AppPermissions, MDataAction, MDataAddress, MDataPermissionSet, XorName};
use std::ffi::CString;
use std::os::raw::c_void;
use tiny_keccak::sha3_256;
use unwrap::unwrap;

fn account_creation(sec_0: CString, sec_1: CString) -> *mut Authenticator {
    println!("\nTrying to create an account ...");
    unsafe {
        let res =
            call_1(|ud, cb| create_acc(sec_0.as_ptr(), sec_1.as_ptr(), ud, disconnect_cb, cb));
        match res {
            Err(-5003) => {
                println!("\nLogin Packet already exists. Logging in. . .");
                account_login(sec_0, sec_1)
            }
            Ok(auth) => auth,
            Err(e) => {
                println!("\nError code:{:?} while creating Account. Try again", e);
                network_login()
            }
        }
    }
}

fn account_login(sec_0: CString, sec_1: CString) -> *mut Authenticator {
    println!("\nTrying to log in ...");
    let res = unsafe {
        call_1(|ud, cb| login(sec_0.as_ptr(), sec_1.as_ptr(), ud, print_disconnect_cb, cb))
    };
    match res {
        Ok(auth) => auth,
        Err(e) => {
            println!("\nError code:{} while logging in. Try again", e);
            network_login()
        }
    }
}

fn network_login() -> *mut Authenticator {
    println!("\nDo you already have an account created (enter Y for yes) ?");
    let mut user_option = String::new();
    let _ = std::io::stdin().read_line(&mut user_option);
    user_option = user_option.trim().to_string();
    if user_option != "Y" && user_option != "y" {
        println!("\n\tAccount Creation");
        println!("\t================");
    } else {
        println!("\n\n\tAccount Login");
        println!("\t====================");
    }

    let mut secret_0 = String::new();
    let mut secret_1 = String::new();
    println!("\n------------ Enter account-locator ---------------");
    let _ = std::io::stdin().read_line(&mut secret_0);
    secret_0 = secret_0.trim().to_string();
    println!("\n------------ Enter password ---------------");
    let _ = std::io::stdin().read_line(&mut secret_1);
    secret_1 = secret_1.trim().to_string();
    let c_sec_0 = unwrap!(CString::new(secret_0));
    let c_sec_1 = unwrap!(CString::new(secret_1));

    if user_option != "Y" && user_option != "y" {
        account_creation(c_sec_0, c_sec_1)
    } else {
        account_login(c_sec_0, c_sec_1)
    }
}

fn create_email(app: &App) {
    // Read the email-id to be created
    let mut email = String::new();
    println!("\nEnter email name of choice:");
    let _ = std::io::stdin().read_line(&mut email);
    email = email.trim().to_string();
    let email_md_address = XorName(sha3_256(email.as_bytes()));

    // Initialize Mutable Data PermissionSet
    let perm_set = MDataPermissionSet::new()
        .allow(MDataAction::Read)
        .allow(MDataAction::Insert);

    // Initialize App's Public Key handle
    let app_pk_handle = unwrap!(run(&app, move |client, context| {
        Ok(context
            .object_cache()
            .insert_pub_sign_key(client.public_key()))
    }));

    // Create an empty permissions handle
    let perms_h: MDataPermissionsHandle =
        unsafe { unwrap!(call_1(|ud, cb| mdata_permissions_new(app, ud, cb))) };

    {
        let ffi_perm_set = permission_set_into_repr_c(perm_set);
        assert!(ffi_perm_set.insert);

        // Assign permissions for the empty handle
        let len: usize = unsafe {
            unwrap!(call_0(|ud, cb| mdata_permissions_insert(
                app,
                perms_h,
                app_pk_handle,
                &ffi_perm_set,
                ud,
                cb
            )));
            unwrap!(call_1(|ud, cb| mdata_permissions_len(app, perms_h, ud, cb),))
        };
        assert_eq!(len, 1);
    }

    // Create a new public MDataInfo
    let native_user_md_info: NativeMDataInfo = NativeMDataInfo::new_public(MDataAddress::Seq {
        name: email_md_address,
        tag: 10000,
    });

    // Convert MDataInfo into it's C representation
    let ffi_user_md_info = native_user_md_info.into_repr_c();

    // Write the Mutable Data in the network
    let res = unsafe {
        call_0(|ud, cb| mdata_put(app, &ffi_user_md_info, perms_h, ENTRIES_EMPTY, ud, cb))
    };

    match res {
        Err(-104) => {
            println!("\nThe Email-id already exists. Try creating a different one");
            return;
        }
        Ok(()) => println!("\nEmail created successfully !"),
        Err(_) => println!("\nError creating Email ID"),
    }

    // Test the PermissionSet
    let test_perm_set: FfiPermissionSet = unsafe {
        unwrap!(call_1(|ud, cb| mdata_list_user_permissions(
            app,
            &ffi_user_md_info,
            app_pk_handle,
            ud,
            cb
        )))
    };

    let test_perm_set = unwrap!(permission_set_clone_from_repr_c(test_perm_set));
    assert!(test_perm_set.is_allowed(MDataAction::Insert));
    assert!(test_perm_set.is_allowed(MDataAction::Read));
    assert!(!test_perm_set.is_allowed(MDataAction::Update));
}

fn send_email(app: &App) {
    let mut email = String::new();
    println!("\nEnter peer email address:");
    let _ = std::io::stdin().read_line(&mut email);
    email = email.trim().to_string();
    let peer_inbox = XorName(sha3_256(email.as_bytes()));

    let mut msg = String::new();
    println!("\nEnter message:");
    let _ = std::io::stdin().read_line(&mut msg);
    msg = msg.trim().to_string();
    let hashed_msg = sha3_256(msg.clone().as_bytes());

    // Prepare handle for inserting entry into peer's inbox MD.
    let actions_h = unsafe { unwrap!(call_1(|ud, cb| mdata_entry_actions_new(app, ud, cb))) };
    unsafe {
        unwrap!(call_0(|ud, cb| mdata_entry_actions_insert(
            app,
            actions_h,
            hashed_msg.as_ptr(),
            hashed_msg.len(),
            msg.as_ptr(),
            msg.len(),
            ud,
            cb
        )));
    }

    let peer_email_md_info: NativeMDataInfo = NativeMDataInfo::new_public(MDataAddress::Seq {
        name: peer_inbox,
        tag: 10000,
    });
    let ffi_peer_email_md_info = peer_email_md_info.into_repr_c();

    // Inserting into peer's inbox
    let res = unsafe {
        call_0(|ud, cb| mdata_mutate_entries(app, &ffi_peer_email_md_info, actions_h, ud, cb))
    };

    match res {
        Ok(()) => println!("\nEmail sent successfully !"),
        Err(-100) => println!("\nAccess Denied. Email-id under a different App"),
        Err(e) => println!("\nError code:{} while sending email.", e),
    }
}

fn read_email(app: &App) {
    let mut email = String::new();
    println!("\nEnter your email address:");
    let _ = std::io::stdin().read_line(&mut email);
    email = email.trim().to_string();
    let email_md_address = XorName(sha3_256(email.as_bytes()));

    let email_md_info = NativeMDataInfo::new_public(MDataAddress::Seq {
        name: email_md_address,
        tag: 10000,
    });
    let email_md_info = email_md_info.into_repr_c();

    let res: Result<Vec<MDataValue>, i32> =
        unsafe { call_vec(|ud, cb| seq_mdata_list_values(app, &email_md_info, ud, cb)) };

    match res {
        Ok(emails) => {
            let num_of_emails = emails.len();
            println!(
                "\n================ You have a total of {} email(s). ================",
                num_of_emails
            );

            for email in emails {
                let data = unwrap!(String::from_utf8(email.content));
                println!("\nEmail:\n{}", data);
            }
            println!("\n================ All Emails read successfully ! ================");
        }
        Err(-100) => println!("\nAccess Denied. Email-id under a different App."),
        Err(-103) => println!("\nNo Such Email-id."),
        Err(e) => println!("\nError code:{} while reading email.", e),
    }
}

fn main() {
    let name = "EmailApp".to_string();
    let id = "EmailApp".to_string();
    let vendor = "MaidSafe".to_string();
    let ffi_app_id = unwrap!(CString::new(id.clone()));
    let app_info = AppExchangeInfo {
        id,
        scope: None,
        name,
        vendor,
    };

    let auth_h = network_login();
    assert!(!auth_h.is_null());
    let auth_granted = ffi_authorise_app(auth_h, &app_info);

    // Register the app.
    println!("Registering app ...");
    let app: *mut App = unsafe {
        unwrap!(call_1(|ud, cb| app_registered(
            ffi_app_id.as_ptr(),
            &unwrap!(auth_granted.clone().into_repr_c()),
            ud,
            disconnect_cb,
            cb,
        )))
    };

    loop {
        let mut opt = String::new();
        println!(" ===================== SELECT AN OPTION ===================== ");
        println!(
            "\n0) Create Email\n1) Send Email\n2) Read Email\nx) Anything else to \
             exit\nEnter Option:"
        );
        let _ = std::io::stdin().read_line(&mut opt);
        opt = opt.trim().to_string();
        match &opt[..] {
            "0" => unsafe { create_email(&(*app)) },
            "1" => unsafe { send_email(&(*app)) },
            "2" => unsafe { read_email(&(*app)) },
            _ => break,
        }
    }
    println!("============================================================\n");
}

fn ffi_authorise_app(auth_h: *mut Authenticator, app_info: &AppExchangeInfo) -> AuthGranted {
    let auth_req = AuthReq {
        app: app_info.clone(),
        app_container: true,
        app_permissions: AppPermissions {
            transfer_coins: true,
            perform_mutations: true,
            get_balance: true,
        },
        containers: Default::default(),
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
    panic!("Disconnect callback");
}

extern "C" fn print_disconnect_cb(_user_data: *mut c_void) {
    println!("Fetched LoginPacket successfully. Disconnecting the throw-client and logging in ...");
}
