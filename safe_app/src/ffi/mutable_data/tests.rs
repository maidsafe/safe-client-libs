// Copyright 2016 MaidSafe.net limited.
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

use errors::{ERR_ACCESS_DENIED, ERR_INVALID_SUCCESSOR, ERR_NO_SUCH_ENTRY, ERR_NO_SUCH_KEY};
use ffi::mdata_info::*;
use ffi::mutable_data::*;
use ffi::mutable_data::entries::*;
use ffi::mutable_data::entry_actions::*;
use ffi::mutable_data::permissions::*;
use ffi_utils::{FfiResult, vec_clone_from_raw_parts};
use ffi_utils::test_utils::{call_0, call_1, call_2, call_vec_u8, send_via_user_data,
                            sender_as_user_data};
use object_cache::{MDataInfoHandle, MDataPermissionSetHandle, MDataPermissionsHandle};
use routing::XOR_NAME_LEN;
use std::sync::mpsc;
use std::time::Duration;
use test_utils::create_app;

// The usual test to insert, update, delete and list all permissions from the FFI point of view.
#[test]
fn permissions_crud_ffi() {
    let app = create_app();

    // Create a permissions set
    let perm_set_h: MDataPermissionSetHandle =
        unsafe { unwrap!(call_1(|ud, cb| mdata_permission_set_new(&app, ud, cb))) };

    // Test permission setting
    {
        unsafe {
            unwrap!(call_0(|ud, cb| {
                mdata_permission_set_allow(&app, perm_set_h, MDataAction::Update, ud, cb)
            }));
        }

        let permission_value: PermissionValue = unsafe {
            unwrap!(call_1(|ud, cb| {
                mdata_permission_set_is_allowed(&app, perm_set_h, MDataAction::Update, ud, cb)
            }))
        };
        assert_eq!(permission_value, PermissionValue::Allowed);

        unsafe {
            unwrap!(call_0(|ud, cb| {
                mdata_permission_set_deny(&app, perm_set_h, MDataAction::Update, ud, cb)
            }));
        }

        let permission_value: PermissionValue = unsafe {
            unwrap!(call_1(|ud, cb| {
                mdata_permission_set_is_allowed(&app, perm_set_h, MDataAction::Update, ud, cb)
            }))
        };
        assert_eq!(permission_value, PermissionValue::Denied);

        unsafe {
            unwrap!(call_0(|ud, cb| {
                mdata_permission_set_clear(&app, perm_set_h, MDataAction::Update, ud, cb)
            }));
        }

        let permission_value: PermissionValue = unsafe {
            unwrap!(call_1(|ud, cb| {
                mdata_permission_set_is_allowed(&app, perm_set_h, MDataAction::Update, ud, cb)
            }))
        };
        assert_eq!(permission_value, PermissionValue::NotSet);

        let permission_value: PermissionValue = unsafe {
            unwrap!(call_1(|ud, cb| {
                mdata_permission_set_is_allowed(
                    &app,
                    perm_set_h,
                    MDataAction::ManagePermissions,
                    ud,
                    cb,
                )
            }))
        };
        assert_eq!(permission_value, PermissionValue::NotSet);

        // Allow Insert and ManagePermissions
        unsafe {
            unwrap!(call_0(|ud, cb| {
                mdata_permission_set_allow(&app, perm_set_h, MDataAction::Insert, ud, cb)
            }));
            unwrap!(call_0(|ud, cb| {
                mdata_permission_set_allow(&app, perm_set_h, MDataAction::ManagePermissions, ud, cb)
            }))
        };

        let permission_value: PermissionValue = unsafe {
            unwrap!(call_1(|ud, cb| {
                mdata_permission_set_is_allowed(
                    &app,
                    perm_set_h,
                    MDataAction::ManagePermissions,
                    ud,
                    cb,
                )
            }))
        };
        assert_eq!(permission_value, PermissionValue::Allowed);
    }

    // Create permissions
    let perms_h: MDataPermissionsHandle =
        unsafe { unwrap!(call_1(|ud, cb| mdata_permissions_new(&app, ud, cb))) };

    {
        // Create permissions for anyone
        let len: usize = unsafe {
            unwrap!(call_0(|ud, cb| {
                mdata_permissions_insert(&app, perms_h, USER_ANYONE, perm_set_h, ud, cb)
            }));
            unwrap!(call_1(
                |ud, cb| mdata_permissions_len(&app, perms_h, ud, cb),
            ))
        };
        assert_eq!(len, 1);

        let perm_set2_h = unsafe {
            unwrap!(call_1(|ud, cb| {
                mdata_permissions_get(&app, perms_h, USER_ANYONE, ud, cb)
            }))
        };

        let permission_value: PermissionValue = unsafe {
            unwrap!(call_1(|ud, cb| {
                mdata_permission_set_is_allowed(&app, perm_set2_h, MDataAction::Insert, ud, cb)
            }))
        };
        assert_eq!(permission_value, PermissionValue::Allowed);

        let permission_value: PermissionValue = unsafe {
            unwrap!(call_1(|ud, cb| {
                mdata_permission_set_is_allowed(&app, perm_set2_h, MDataAction::Update, ud, cb)
            }))
        };
        assert_eq!(permission_value, PermissionValue::NotSet);

        let (tx, rx) = mpsc::channel::<Option<(SignKeyHandle, MDataPermissionSetHandle)>>();
        let ud = sender_as_user_data(&tx);

        unsafe { mdata_permissions_for_each(&app, perms_h, ud, iter_perms_cb, iter_perms_done_cb) };

        let mut result: Vec<Option<(SignKeyHandle, MDataPermissionSetHandle)>> = Vec::new();
        result.push(unwrap!(rx.recv_timeout(Duration::from_millis(1000))));
        result.push(unwrap!(rx.recv_timeout(Duration::from_millis(1000))));
        assert_eq!(result.len(), 2);
    }

    // Try to create an empty public MD
    let md_info_pub_h: MDataInfoHandle = unsafe {
        unwrap!(call_1(
            |ud, cb| mdata_info_random_public(&app, 10000, ud, cb),
        ))
    };

    unsafe {
        unwrap!(call_0(|ud, cb| {
            mdata_put(&app, md_info_pub_h, perms_h, ENTRIES_EMPTY, ud, cb)
        }))
    };

    {
        let read_perm_set_h: MDataPermissionSetHandle = unsafe {
            unwrap!(call_1(|ud, cb| {
                mdata_list_user_permissions(&app, md_info_pub_h, USER_ANYONE, ud, cb)
            }))
        };
        let permission_value: PermissionValue = unsafe {
            unwrap!(call_1(|ud, cb| {
                mdata_permission_set_is_allowed(&app, read_perm_set_h, MDataAction::Insert, ud, cb)
            }))
        };
        assert_eq!(permission_value, PermissionValue::Allowed);

        let permission_value: PermissionValue = unsafe {
            unwrap!(call_1(|ud, cb| {
                mdata_permission_set_is_allowed(&app, read_perm_set_h, MDataAction::Update, ud, cb)
            }))
        };
        assert_eq!(permission_value, PermissionValue::NotSet);

        let permission_value: PermissionValue = unsafe {
            unwrap!(call_1(|ud, cb| {
                mdata_permission_set_is_allowed(
                    &app,
                    read_perm_set_h,
                    MDataAction::ManagePermissions,
                    ud,
                    cb,
                )
            }))
        };
        assert_eq!(permission_value, PermissionValue::Allowed);

        // Create a new permissions set
        let perm_set_new_h: MDataPermissionSetHandle =
            unsafe { unwrap!(call_1(|ud, cb| mdata_permission_set_new(&app, ud, cb))) };

        unsafe {
            unwrap!(call_0(|ud, cb| {
                mdata_permission_set_allow(
                    &app,
                    perm_set_new_h,
                    MDataAction::ManagePermissions,
                    ud,
                    cb,
                )
            }))
        };

        let permission_value: PermissionValue = unsafe {
            unwrap!(call_1(|ud, cb| {
                mdata_permission_set_is_allowed(
                    &app,
                    perm_set_h,
                    MDataAction::ManagePermissions,
                    ud,
                    cb,
                )
            }))
        };
        assert_eq!(permission_value, PermissionValue::Allowed);

        let result = unsafe {
            // Should fail due to invalid version
            call_0(|ud, cb| {
                mdata_set_user_permissions(
                    &app,
                    md_info_pub_h,
                    USER_ANYONE,
                    perm_set_new_h,
                    0,
                    ud,
                    cb,
                );
            })
        };

        match result {
            Err(ERR_INVALID_SUCCESSOR) => (),
            _ => panic!("Changed permissions without permission"),
        };

        let result = unsafe {
            // Should succeed
            unwrap!(call_0(|ud, cb| {
                mdata_set_user_permissions(
                    &app,
                    md_info_pub_h,
                    USER_ANYONE,
                    perm_set_new_h,
                    1,
                    ud,
                    cb,
                );
            }));

            // Delete the permission set - should succeed
            unwrap!(call_0(|ud, cb| {
                mdata_del_user_permissions(&app, md_info_pub_h, USER_ANYONE, 2, ud, cb);
            }));

            // Try to change permissions - should fail
            call_0(|ud, cb| {
                mdata_set_user_permissions(
                    &app,
                    md_info_pub_h,
                    USER_ANYONE,
                    perm_set_new_h,
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

        let result: Result<MDataPermissionSetHandle, i32> = unsafe {
            call_1(|ud, cb| {
                mdata_list_user_permissions(&app, md_info_pub_h, USER_ANYONE, ud, cb)
            })
        };

        match result {
            Err(ERR_NO_SUCH_KEY) => (),
            _ => panic!("User permissions listed without key"),
        }
    }

    extern "C" fn iter_perms_cb(
        user_data: *mut c_void,
        key_h: SignKeyHandle,
        perm_set_h: MDataPermissionSetHandle,
    ) {
        assert_eq!(key_h, USER_ANYONE);

        let result: Option<(SignKeyHandle, MDataPermissionSetHandle)> = Some((key_h, perm_set_h));
        unsafe {
            send_via_user_data(user_data, result);
        }
    }

    extern "C" fn iter_perms_done_cb(user_data: *mut c_void, _res: FfiResult) {
        unsafe {
            send_via_user_data::<Option<(SignKeyHandle, MDataPermissionSetHandle)>>(
                user_data,
                None,
            );
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
    let perm_set_h: MDataPermissionSetHandle =
        unsafe { unwrap!(call_1(|ud, cb| mdata_permission_set_new(&app, ud, cb))) };

    unsafe {
        unwrap!(call_0(|ud, cb| {
            mdata_permission_set_allow(&app, perm_set_h, MDataAction::Insert, ud, cb)
        }))
    };

    // Create permissions
    let perms_h: MDataPermissionsHandle =
        unsafe { unwrap!(call_1(|ud, cb| mdata_permissions_new(&app, ud, cb))) };

    unsafe {
        unwrap!(call_0(|ud, cb| {
            mdata_permissions_insert(&app, perms_h, USER_ANYONE, perm_set_h, ud, cb)
        }))
    }

    // Try to create an empty public MD
    let md_info_pub_h: MDataInfoHandle = unsafe {
        unwrap!(call_1(
            |ud, cb| mdata_info_random_public(&app, 10000, ud, cb),
        ))
    };

    unsafe {
        unwrap!(call_0(|ud, cb| {
            mdata_put(&app, md_info_pub_h, perms_h, ENTRIES_EMPTY, ud, cb)
        }))
    };

    // Try to create a MD instance using the same name & type tag - it should fail.
    let res = unsafe {
        call_0(|ud, cb| {
            mdata_put(&app, md_info_pub_h, perms_h, ENTRIES_EMPTY, ud, cb)
        })
    };
    match res {
        Err(_) => (),
        x => panic!("Failed test: unexpected {:?}, expected error", x),
    }

    // Try to create a MD instance using the same name & a different type tag - it should pass.
    let (xor_name, type_tag): ([u8; XOR_NAME_LEN], u64) = unsafe {
        unwrap!(call_2(|ud, cb| {
            mdata_info_extract_name_and_type_tag(&app, md_info_pub_h, ud, cb)
        }))
    };
    assert_eq!(type_tag, 10000);

    let md_info_pub_2_h: MDataInfoHandle = unsafe {
        unwrap!(call_1(|ud, cb| {
            mdata_info_new_public(&app, &xor_name, 10001, ud, cb)
        }))
    };
    let (xor_name2, type_tag2): ([u8; XOR_NAME_LEN], u64) = unsafe {
        unwrap!(call_2(|ud, cb| {
            mdata_info_extract_name_and_type_tag(&app, md_info_pub_2_h, ud, cb)
        }))
    };
    assert_eq!(xor_name, xor_name2);
    assert_eq!(type_tag2, 10001);

    unsafe {
        unwrap!(call_0(|ud, cb| {
            mdata_put(&app, md_info_pub_2_h, perms_h, ENTRIES_EMPTY, ud, cb)
        }))
    };

    // Try to add entries to a public MD
    let actions_h: MDataEntryActionsHandle =
        unsafe { unwrap!(call_1(|ud, cb| mdata_entry_actions_new(&app, ud, cb))) };

    unsafe {
        unwrap!(call_0(|ud, cb| {
            mdata_entry_actions_insert(
                &app,
                actions_h,
                KEY.as_ptr(),
                KEY.len(),
                VALUE.as_ptr(),
                VALUE.len(),
                ud,
                cb,
            )
        }))
    };

    unsafe {
        unwrap!(call_0(|ud, cb| {
            mdata_mutate_entries(&app, md_info_pub_h, actions_h, ud, cb)
        }))
    }

    // Retrieve added entry
    {
        let (tx, rx) = mpsc::channel::<Result<Vec<u8>, i32>>();
        let ud = sender_as_user_data(&tx);

        unsafe {
            mdata_get_value(
                &app,
                md_info_pub_h,
                KEY.as_ptr(),
                KEY.len(),
                ud,
                get_value_cb,
            )
        };

        let result = unwrap!(rx.recv());
        assert_eq!(&unwrap!(result), &VALUE, "got back invalid value");
    }

    // Check the version of a public MD
    let ver: u64 = unsafe {
        unwrap!(call_1(
            |ud, cb| mdata_get_version(&app, md_info_pub_h, ud, cb),
        ))
    };
    assert_eq!(ver, 0);

    // Check that permissions on the public MD haven't changed
    {
        let read_perms_h: MDataPermissionsHandle = unsafe {
            unwrap!(call_1(
                |ud, cb| mdata_list_permissions(&app, md_info_pub_h, ud, cb),
            ))
        };

        let perm_set_h = unsafe {
            unwrap!(call_1(|ud, cb| {
                mdata_permissions_get(&app, read_perms_h, USER_ANYONE, ud, cb)
            }))
        };

        let permission_value: PermissionValue = unsafe {
            unwrap!(call_1(|ud, cb| {
                mdata_permission_set_is_allowed(&app, perm_set_h, MDataAction::Insert, ud, cb)
            }))
        };
        assert_eq!(permission_value, PermissionValue::Allowed);

        let permission_value: PermissionValue = unsafe {
            unwrap!(call_1(|ud, cb| {
                mdata_permission_set_is_allowed(&app, perm_set_h, MDataAction::Update, ud, cb)
            }))
        };
        assert_eq!(permission_value, PermissionValue::NotSet);
    }

    // Try to create a private MD
    let md_info_priv_h = unsafe {
        unwrap!(call_1(
            |ud, cb| mdata_info_random_private(&app, 10001, ud, cb),
        ))
    };
    let (_xor_name, type_tag): ([u8; XOR_NAME_LEN], u64) = unsafe {
        unwrap!(call_2(|ud, cb| {
            mdata_info_extract_name_and_type_tag(&app, md_info_priv_h, ud, cb)
        }))
    };
    assert_eq!(type_tag, 10001);

    unsafe {
        unwrap!(call_0(|ud, cb| {
            mdata_put(&app, md_info_priv_h, perms_h, ENTRIES_EMPTY, ud, cb)
        }))
    };

    // Check the version of a private MD
    let ver: u64 = unsafe {
        unwrap!(call_1(
            |ud, cb| mdata_get_version(&app, md_info_priv_h, ud, cb),
        ))
    };
    assert_eq!(ver, 0);

    // Try to add entries to a private MD
    let key_enc = unsafe {
        unwrap!(call_vec_u8(|ud, cb| {
            mdata_info_encrypt_entry_key(&app, md_info_priv_h, KEY.as_ptr(), KEY.len(), ud, cb)
        }))
    };
    let value_enc = unsafe {
        unwrap!(call_vec_u8(|ud, cb| {
            mdata_info_encrypt_entry_value(
                &app,
                md_info_priv_h,
                VALUE.as_ptr(),
                VALUE.len(),
                ud,
                cb,
            )
        }))
    };

    let actions_priv_h: MDataEntryActionsHandle =
        unsafe { unwrap!(call_1(|ud, cb| mdata_entry_actions_new(&app, ud, cb))) };

    unsafe {
        unwrap!(call_0(|ud, cb| {
            mdata_entry_actions_insert(
                &app,
                actions_priv_h,
                key_enc.as_ptr(),
                key_enc.len(),
                value_enc.as_ptr(),
                value_enc.len(),
                ud,
                cb,
            )
        }))
    };

    unsafe {
        unwrap!(call_0(|ud, cb| {
            mdata_mutate_entries(&app, md_info_priv_h, actions_priv_h, ud, cb)
        }))
    }

    // Try to fetch the serialised size of MD
    {
        let size: u64 = unsafe {
            unwrap!(call_1(
                |ud, cb| mdata_serialised_size(&app, md_info_priv_h, ud, cb),
            ))
        };
        assert!(size > 0);

        let size: u64 = unsafe {
            unwrap!(call_1(
                |ud, cb| mdata_serialised_size(&app, md_info_pub_h, ud, cb),
            ))
        };
        assert!(size > 0);
    }

    // Retrieve added entry from private MD
    {
        let (tx, rx) = mpsc::channel::<Result<Vec<u8>, i32>>();
        let ud = sender_as_user_data(&tx);

        unsafe {
            mdata_get_value(
                &app,
                md_info_priv_h,
                key_enc.as_ptr(),
                key_enc.len(),
                ud,
                get_value_cb,
            )
        };

        let result = unwrap!(rx.recv());
        let got_value_enc = unwrap!(result);
        assert_eq!(&got_value_enc, &value_enc, "got back invalid value");

        let decrypted = unsafe {
            unwrap!(call_vec_u8(|ud, cb| {
                mdata_info_decrypt(
                    &app,
                    md_info_priv_h,
                    got_value_enc.as_ptr(),
                    got_value_enc.len(),
                    ud,
                    cb,
                )
            }))
        };
        assert_eq!(&decrypted, &VALUE, "decrypted invalid value");
    }

    // Check mdata_list_entries
    {
        let entries_list_h = unsafe {
            unwrap!(call_1(
                |ud, cb| mdata_list_entries(&app, md_info_priv_h, ud, cb),
            ))
        };

        // Try with a fake entry key, expect error.
        let (tx, rx) = mpsc::channel::<Result<Vec<u8>, i32>>();
        let ud = sender_as_user_data(&tx);

        let fake_key = vec![0];
        unsafe {
            mdata_entries_get(
                &app,
                entries_list_h,
                fake_key.as_ptr(),
                fake_key.len(),
                ud,
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
        let ud = sender_as_user_data(&tx);

        unsafe {
            mdata_entries_get(
                &app,
                entries_list_h,
                key_enc.as_ptr(),
                key_enc.len(),
                ud,
                get_value_cb,
            )
        };

        let result = unwrap!(rx.recv());
        let got_value_enc = unwrap!(result);
        assert_eq!(&got_value_enc, &value_enc, "got back invalid value");

        let decrypted = unsafe {
            unwrap!(call_vec_u8(|ud, cb| {
                mdata_info_decrypt(
                    &app,
                    md_info_priv_h,
                    got_value_enc.as_ptr(),
                    got_value_enc.len(),
                    ud,
                    cb,
                )
            }))
        };
        assert_eq!(&decrypted, &VALUE, "decrypted invalid value");

        unsafe {
            unwrap!(call_0(
                |ud, cb| mdata_entries_free(&app, entries_list_h, ud, cb),
            ))
        }
    }

    // Check mdata_list_keys
    {
        let keys_list_h = unsafe {
            unwrap!(call_1(
                |ud, cb| mdata_list_keys(&app, md_info_priv_h, ud, cb),
            ))
        };

        let (tx, rx) = mpsc::channel::<Option<Vec<u8>>>();
        let ud = sender_as_user_data(&tx);

        unsafe { mdata_keys_for_each(&app, keys_list_h, ud, iter_vec_u8_cb, iter_done_cb) };

        let mut result: Vec<Option<Vec<u8>>> = Vec::new();
        result.push(unwrap!(rx.recv_timeout(Duration::from_millis(1000))));
        result.push(unwrap!(rx.recv_timeout(Duration::from_millis(1000))));
        assert_eq!(result.len(), 2);

        if let Some(ref got_key_enc) = result[0] {
            let decrypted = unsafe {
                unwrap!(call_vec_u8(|ud, cb| {
                    mdata_info_decrypt(
                        &app,
                        md_info_priv_h,
                        got_key_enc.as_ptr(),
                        got_key_enc.len(),
                        ud,
                        cb,
                    )
                }))
            };
            assert_eq!(&decrypted, &KEY, "decrypted invalid key");
        } else {
            panic!("Failed test: expected Some(Vec<u8>), got None");
        }
    }

    // Check mdata_list_values
    {
        let vals_list_h = unsafe {
            unwrap!(call_1(
                |ud, cb| mdata_list_values(&app, md_info_priv_h, ud, cb),
            ))
        };

        let (tx, rx) = mpsc::channel::<Option<Vec<u8>>>();
        let ud = sender_as_user_data(&tx);

        unsafe { mdata_values_for_each(&app, vals_list_h, ud, iter_value_cb, iter_done_cb) };

        let mut result: Vec<Option<Vec<u8>>> = Vec::new();
        result.push(unwrap!(rx.recv_timeout(Duration::from_millis(1000))));
        result.push(unwrap!(rx.recv_timeout(Duration::from_millis(1000))));
        assert_eq!(result.len(), 2);

        if let Some(ref got_value_enc) = result[0] {
            let decrypted = unsafe {
                unwrap!(call_vec_u8(|ud, cb| {
                    mdata_info_decrypt(
                        &app,
                        md_info_priv_h,
                        got_value_enc.as_ptr(),
                        got_value_enc.len(),
                        ud,
                        cb,
                    )
                }))
            };
            assert_eq!(&decrypted, &VALUE, "decrypted invalid value");
        } else {
            panic!("Failed test: expected Some(Vec<u8>), got None");
        }
    }

    // Free everything.
    unsafe {
        unwrap!(call_0(
            |ud, cb| mdata_permission_set_free(&app, perm_set_h, ud, cb),
        ));
        unwrap!(call_0(
            |ud, cb| mdata_permissions_free(&app, perms_h, ud, cb),
        ));
        unwrap!(call_0(
            |ud, cb| mdata_info_free(&app, md_info_pub_h, ud, cb),
        ));
        unwrap!(call_0(
            |ud, cb| mdata_info_free(&app, md_info_priv_h, ud, cb),
        ));
    }

    extern "C" fn get_value_cb(
        user_data: *mut c_void,
        res: FfiResult,
        val: *const u8,
        len: usize,
        _version: u64,
    ) {
        let result: Result<Vec<u8>, i32> = if res.error_code == 0 {
            Ok(unsafe { vec_clone_from_raw_parts(val, len) })
        } else {
            Err(res.error_code)
        };
        unsafe {
            send_via_user_data(user_data, result);
        }
    }

    extern "C" fn iter_value_cb(user_data: *mut c_void, val: *const u8, len: usize, _version: u64) {
        let result: Option<Vec<u8>> = Some(unsafe { vec_clone_from_raw_parts(val, len) });
        unsafe {
            send_via_user_data(user_data, result);
        }
    }

    extern "C" fn iter_vec_u8_cb(user_data: *mut c_void, val: *const u8, len: usize) {
        let result: Option<Vec<u8>> = Some(unsafe { vec_clone_from_raw_parts(val, len) });
        unsafe {
            send_via_user_data(user_data, result);
        }
    }

    extern "C" fn iter_done_cb(user_data: *mut c_void, _res: FfiResult) {
        unsafe {
            send_via_user_data::<Option<Vec<u8>>>(user_data, None);
        }
    }
}
