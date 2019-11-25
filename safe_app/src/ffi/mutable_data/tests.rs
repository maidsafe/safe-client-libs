// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::errors::{ERR_ACCESS_DENIED, ERR_INVALID_SUCCESSOR, ERR_NO_SUCH_ENTRY};
use crate::ffi::mdata_info::*;
use crate::ffi::mutable_data::entries::*;
use crate::ffi::mutable_data::entry_actions::*;
use crate::ffi::mutable_data::permissions::*;
use crate::ffi::mutable_data::*;
use crate::ffi::object_cache::MDataPermissionsHandle;
use crate::permissions::UserPermissionSet;
use crate::run;
use crate::test_utils::create_app;
use ffi_utils::test_utils::{
    call_0, call_1, call_vec, call_vec_u8, send_via_user_data, sender_as_user_data,
};
use ffi_utils::{vec_clone_from_raw_parts, FfiResult};
use safe_core::ffi::ipc::req::PermissionSet as FfiPermissionSet;
use safe_core::ffi::MDataInfo;
use safe_core::ipc::req::{permission_set_clone_from_repr_c, permission_set_into_repr_c};
use safe_core::ipc::resp::{MDataKey, MDataValue};
use safe_core::MDataInfo as NativeMDataInfo;
use safe_nd::{MDataAction, MDataPermissionSet};
use std::sync::mpsc;

// The usual test to insert, update, delete and list all permissions from the FFI point of view.
#[test]
fn permissions_crud_ffi() {
    let app = create_app();

    // Create a permissions set
    let perm_set = MDataPermissionSet::new()
        .allow(MDataAction::Read)
        .allow(MDataAction::Insert)
        .allow(MDataAction::ManagePermissions);

    let app_pk_handle = unwrap!(run(&app, move |client, context| {
        Ok(context
            .object_cache()
            .insert_pub_sign_key(client.public_key()))
    }));

    // Create permissions
    let perms_h: MDataPermissionsHandle =
        unsafe { unwrap!(call_1(|ud, cb| mdata_permissions_new(&app, ud, cb))) };

    {
        let ffi_perm_set = permission_set_into_repr_c(perm_set.clone());
        assert!(ffi_perm_set.insert);

        // Create permissions for the app
        let len: usize = unsafe {
            unwrap!(call_0(|ud, cb| mdata_permissions_insert(
                &app,
                perms_h,
                app_pk_handle,
                &ffi_perm_set,
                ud,
                cb
            )));
            unwrap!(call_1(|ud, cb| mdata_permissions_len(
                &app, perms_h, ud, cb
            ),))
        };
        assert_eq!(len, 1);

        let perm_set2: FfiPermissionSet = unsafe {
            unwrap!(call_1(|ud, cb| mdata_permissions_get(
                &app,
                perms_h,
                app_pk_handle,
                ud,
                cb
            )))
        };
        assert!(perm_set2.insert);
        let perm_set2 = unwrap!(permission_set_clone_from_repr_c(perm_set2));

        assert!(perm_set2.is_allowed(MDataAction::Insert));
        assert!(!perm_set2.is_allowed(MDataAction::Update));

        let result: Vec<UserPermissionSet> = unsafe {
            unwrap!(call_vec(|ud, cb| mdata_list_permission_sets(
                &app, perms_h, ud, cb
            ),))
        };

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].perm_set, perm_set);
        unwrap!(run(&app, move |_, context| {
            let key = *unwrap!(context.object_cache().get_pub_sign_key(result[0].user_h));
            let expected = *unwrap!(context.object_cache().get_pub_sign_key(app_pk_handle));
            assert_eq!(key, expected);
            Ok(())
        }));
    }

    // Try to create an empty public MD
    let md_info_pub: NativeMDataInfo = unsafe {
        unwrap!(call_1(|ud, cb| mdata_info_random_public(
            true, 10_000, ud, cb
        )))
    };
    let md_info_pub = md_info_pub.into_repr_c();

    unsafe {
        unwrap!(call_0(|ud, cb| mdata_put(
            &app,
            &md_info_pub,
            perms_h,
            ENTRIES_EMPTY,
            ud,
            cb
        )))
    };

    {
        let read_perm_set: FfiPermissionSet = unsafe {
            unwrap!(call_1(|ud, cb| mdata_list_user_permissions(
                &app,
                &md_info_pub,
                app_pk_handle,
                ud,
                cb
            )))
        };
        let read_perm_set = unwrap!(permission_set_clone_from_repr_c(read_perm_set));
        assert!(read_perm_set.is_allowed(MDataAction::Insert));
        assert!(read_perm_set.is_allowed(MDataAction::ManagePermissions));
        assert!(!read_perm_set.is_allowed(MDataAction::Update));

        // Create a new permissions set
        let perm_set_new = MDataPermissionSet::new().allow(MDataAction::ManagePermissions);

        let result = unsafe {
            // Should fail due to invalid version
            call_0(|ud, cb| {
                mdata_set_user_permissions(
                    &app,
                    &md_info_pub,
                    app_pk_handle,
                    &permission_set_into_repr_c(perm_set_new.clone()),
                    0,
                    ud,
                    cb,
                );
            })
        };

        match result {
            Err(ERR_INVALID_SUCCESSOR) => (),
            _ => panic!("Invalid version specified has succeeded"),
        };

        let result = unsafe {
            // Should succeed
            unwrap!(call_0(|ud, cb| {
                mdata_set_user_permissions(
                    &app,
                    &md_info_pub,
                    app_pk_handle,
                    &permission_set_into_repr_c(perm_set_new.clone()),
                    1,
                    ud,
                    cb,
                );
            }));

            // Delete the permission set - should succeed
            unwrap!(call_0(|ud, cb| {
                mdata_del_user_permissions(&app, &md_info_pub, app_pk_handle, 2, ud, cb);
            }));

            // Try to change permissions - should fail
            call_0(|ud, cb| {
                mdata_set_user_permissions(
                    &app,
                    &md_info_pub,
                    app_pk_handle,
                    &permission_set_into_repr_c(perm_set_new.clone()),
                    3,
                    ud,
                    cb,
                );
            })
        };

        match result {
            Err(ERR_ACCESS_DENIED) => (),
            _ => panic!("Changed permissions without permission"),
        };

        let result: Result<FfiPermissionSet, i32> = unsafe {
            call_1(|ud, cb| mdata_list_user_permissions(&app, &md_info_pub, app_pk_handle, ud, cb))
        };

        match result {
            Err(ERR_ACCESS_DENIED) => (),
            _ => panic!("User permissions listed without key"),
        }
    }
}

//  The usual test to insert, update, delete and list all entry-keys/values from the FFI point of
//  view.
#[test]
fn entries_crud_ffi() {
    let app = create_app();

    const KEY: &[u8] = b"hello";
    const VALUE: &[u8] = b"world";

    // Create a permissions set
    let perm_set = MDataPermissionSet::new()
        .allow(MDataAction::Read)
        .allow(MDataAction::Insert);

    // Create permissions
    let perms_h: MDataPermissionsHandle =
        unsafe { unwrap!(call_1(|ud, cb| mdata_permissions_new(&app, ud, cb))) };

    let app_pk_handle = unwrap!(run(&app, move |client, context| {
        Ok(context
            .object_cache()
            .insert_pub_sign_key(client.public_key()))
    }));

    unsafe {
        unwrap!(call_0(|ud, cb| mdata_permissions_insert(
            &app,
            perms_h,
            app_pk_handle,
            &permission_set_into_repr_c(perm_set),
            ud,
            cb,
        )))
    }

    // Try to create an empty public MD
    let md_info_pub: NativeMDataInfo = unsafe {
        unwrap!(call_1(|ud, cb| mdata_info_random_public(
            true, 10_000, ud, cb
        )))
    };
    let md_info_pub = md_info_pub.into_repr_c();

    unsafe {
        unwrap!(call_0(|ud, cb| mdata_put(
            &app,
            &md_info_pub,
            perms_h,
            ENTRIES_EMPTY,
            ud,
            cb
        )))
    };

    // Try to create a MD instance using the same name & type tag - it should fail.
    let res =
        unsafe { call_0(|ud, cb| mdata_put(&app, &md_info_pub, perms_h, ENTRIES_EMPTY, ud, cb)) };
    match res {
        Err(_) => (),
        x => panic!("Failed test: unexpected {:?}, expected error", x),
    }

    // Try to create a MD instance using the same name & a different type tag - it should pass.
    let xor_name = md_info_pub.name;
    let md_info_pub_2 = MDataInfo {
        seq: true,
        name: xor_name,
        type_tag: 10_001,
        has_enc_info: false,
        enc_key: Default::default(),
        enc_nonce: Default::default(),
        has_new_enc_info: false,
        new_enc_key: Default::default(),
        new_enc_nonce: Default::default(),
    };

    unsafe {
        unwrap!(call_0(|ud, cb| mdata_put(
            &app,
            &md_info_pub_2,
            perms_h,
            ENTRIES_EMPTY,
            ud,
            cb
        )))
    };

    // Try to add entries to a public MD
    let actions_h: MDataEntryActionsHandle =
        unsafe { unwrap!(call_1(|ud, cb| mdata_entry_actions_new(&app, ud, cb))) };

    unsafe {
        unwrap!(call_0(|ud, cb| mdata_entry_actions_insert(
            &app,
            actions_h,
            KEY.as_ptr(),
            KEY.len(),
            VALUE.as_ptr(),
            VALUE.len(),
            ud,
            cb,
        )))
    };

    unsafe {
        unwrap!(call_0(|ud, cb| mdata_mutate_entries(
            &app,
            &md_info_pub,
            actions_h,
            ud,
            cb
        )))
    }

    // Retrieve added entry
    {
        let (tx, rx) = mpsc::channel::<Result<Vec<u8>, i32>>();
        let mut ud = Default::default();

        unsafe {
            mdata_get_value(
                &app,
                &md_info_pub,
                KEY.as_ptr(),
                KEY.len(),
                sender_as_user_data(&tx, &mut ud),
                get_value_cb,
            )
        };

        let result = unwrap!(rx.recv());
        assert_eq!(&unwrap!(result), &VALUE, "got back invalid value");
    }

    // Check the version of a public MD
    let ver: u64 = unsafe {
        unwrap!(call_1(|ud, cb| mdata_get_version(
            &app,
            &md_info_pub,
            ud,
            cb
        ),))
    };
    assert_eq!(ver, 0);

    // Check that permissions on the public MD haven't changed
    let read_perm_set: FfiPermissionSet = unsafe {
        unwrap!(call_1(|ud, cb| mdata_list_user_permissions(
            &app,
            &md_info_pub,
            app_pk_handle,
            ud,
            cb
        )))
    };
    let read_perm_set = unwrap!(permission_set_clone_from_repr_c(read_perm_set));

    assert!(read_perm_set.is_allowed(MDataAction::Insert));
    assert!(!read_perm_set.is_allowed(MDataAction::Update));

    // Try to create a private MD
    let md_info_priv: NativeMDataInfo = unsafe {
        unwrap!(call_1(|ud, cb| mdata_info_random_private(
            true, 10_001, ud, cb
        )))
    };
    let md_info_priv = md_info_priv.into_repr_c();

    unsafe {
        unwrap!(call_0(|ud, cb| mdata_put(
            &app,
            &md_info_priv,
            perms_h,
            ENTRIES_EMPTY,
            ud,
            cb
        )))
    };

    // Check the version of a private MD
    let ver: u64 = unsafe {
        unwrap!(call_1(|ud, cb| mdata_get_version(
            &app,
            &md_info_priv,
            ud,
            cb
        ),))
    };
    assert_eq!(ver, 0);

    // Try to add entries to a private MD
    let key_enc = unsafe {
        unwrap!(call_vec_u8(|ud, cb| mdata_info_encrypt_entry_key(
            &md_info_priv,
            KEY.as_ptr(),
            KEY.len(),
            ud,
            cb
        )))
    };
    let value_enc = unsafe {
        unwrap!(call_vec_u8(|ud, cb| mdata_info_encrypt_entry_value(
            &md_info_priv,
            VALUE.as_ptr(),
            VALUE.len(),
            ud,
            cb
        )))
    };

    let actions_priv_h: MDataEntryActionsHandle =
        unsafe { unwrap!(call_1(|ud, cb| mdata_entry_actions_new(&app, ud, cb))) };

    unsafe {
        unwrap!(call_0(|ud, cb| mdata_entry_actions_insert(
            &app,
            actions_priv_h,
            key_enc.as_ptr(),
            key_enc.len(),
            value_enc.as_ptr(),
            value_enc.len(),
            ud,
            cb,
        )))
    };

    unsafe {
        unwrap!(call_0(|ud, cb| mdata_mutate_entries(
            &app,
            &md_info_priv,
            actions_priv_h,
            ud,
            cb
        )))
    }

    // Try to fetch the serialised size of MD
    {
        let size: u64 = unsafe {
            unwrap!(call_1(|ud, cb| mdata_serialised_size(
                &app,
                &md_info_priv,
                ud,
                cb
            ),))
        };
        assert!(size > 0);

        let size: u64 = unsafe {
            unwrap!(call_1(|ud, cb| mdata_serialised_size(
                &app,
                &md_info_pub,
                ud,
                cb
            ),))
        };
        assert!(size > 0);
    }

    // Retrieve added entry from private MD
    {
        let (tx, rx) = mpsc::channel::<Result<Vec<u8>, i32>>();
        let mut ud = Default::default();

        unsafe {
            mdata_get_value(
                &app,
                &md_info_priv,
                key_enc.as_ptr(),
                key_enc.len(),
                sender_as_user_data(&tx, &mut ud),
                get_value_cb,
            )
        };

        let result = unwrap!(rx.recv());
        let got_value_enc = unwrap!(result);
        assert_eq!(&got_value_enc, &value_enc, "got back invalid value");

        let decrypted = unsafe {
            unwrap!(call_vec_u8(|ud, cb| mdata_info_decrypt(
                &md_info_priv,
                got_value_enc.as_ptr(),
                got_value_enc.len(),
                ud,
                cb,
            )))
        };
        assert_eq!(&decrypted, &VALUE, "decrypted invalid value");
    }

    // Check mdata_entries
    {
        let entries_h =
            unsafe { unwrap!(call_1(|ud, cb| mdata_entries(&app, &md_info_priv, ud, cb))) };

        // Try with a fake entry key, expect error.
        let (tx, rx) = mpsc::channel::<Result<Vec<u8>, i32>>();
        let mut ud = Default::default();

        let fake_key = vec![0];
        unsafe {
            seq_mdata_entries_get(
                &app,
                entries_h,
                fake_key.as_ptr(),
                fake_key.len(),
                sender_as_user_data(&tx, &mut ud),
                get_value_cb,
            )
        };

        let result = unwrap!(rx.recv());
        match result {
            Err(ERR_NO_SUCH_ENTRY) => (),
            _ => panic!("Got mdata entry with a fake entry key"),
        };

        // Try with the real encrypted entry key.
        let (tx, rx) = mpsc::channel::<Result<Vec<u8>, i32>>();
        let mut ud = Default::default();

        unsafe {
            seq_mdata_entries_get(
                &app,
                entries_h,
                key_enc.as_ptr(),
                key_enc.len(),
                sender_as_user_data(&tx, &mut ud),
                get_value_cb,
            )
        };

        let result = unwrap!(rx.recv());
        let got_value_enc = unwrap!(result);
        assert_eq!(&got_value_enc, &value_enc, "got back invalid value");

        let decrypted = unsafe {
            unwrap!(call_vec_u8(|ud, cb| mdata_info_decrypt(
                &md_info_priv,
                got_value_enc.as_ptr(),
                got_value_enc.len(),
                ud,
                cb,
            )))
        };
        assert_eq!(&decrypted, &VALUE, "decrypted invalid value");

        unsafe {
            unwrap!(call_0(|ud, cb| seq_mdata_entries_free(
                &app, entries_h, ud, cb
            )))
        }
    }

    // Check mdata_list_keys
    {
        let keys_list: Vec<MDataKey> = unsafe {
            unwrap!(call_vec(|ud, cb| mdata_list_keys(
                &app,
                &md_info_priv,
                ud,
                cb
            ),))
        };
        assert_eq!(keys_list.len(), 1);

        let decrypted = unsafe {
            unwrap!(call_vec_u8(|ud, cb| mdata_info_decrypt(
                &md_info_priv,
                keys_list[0].0.as_ptr(),
                keys_list[0].0.len(),
                ud,
                cb,
            )))
        };
        assert_eq!(&decrypted, &KEY, "decrypted invalid key");
    }

    // Check mdata_list_values
    {
        let vals_list: Vec<MDataValue> = unsafe {
            unwrap!(call_vec(|ud, cb| seq_mdata_list_values(
                &app,
                &md_info_priv,
                ud,
                cb
            ),))
        };
        assert_eq!(vals_list.len(), 1);

        let decrypted = unsafe {
            unwrap!(call_vec_u8(|ud, cb| mdata_info_decrypt(
                &md_info_priv,
                vals_list[0].content.as_ptr(),
                vals_list[0].content.len(),
                ud,
                cb,
            )))
        };
        assert_eq!(&decrypted, &VALUE, "decrypted invalid value");
    }

    // Free everything.
    unsafe {
        unwrap!(call_0(|ud, cb| mdata_permissions_free(
            &app, perms_h, ud, cb
        ),));
    }

    extern "C" fn get_value_cb(
        user_data: *mut c_void,
        res: *const FfiResult,
        val: *const u8,
        len: usize,
        _version: u64,
    ) {
        unsafe {
            let result: Result<Vec<u8>, i32> = if (*res).error_code == 0 {
                Ok(vec_clone_from_raw_parts(val, len))
            } else {
                Err((*res).error_code)
            };

            send_via_user_data(user_data, result);
        }
    }
}
