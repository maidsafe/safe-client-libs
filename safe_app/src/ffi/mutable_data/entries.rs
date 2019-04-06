// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

//! FFI for mutable data entries, keys and values.

use crate::errors::AppError;
use crate::ffi::helper::send_sync;
use crate::ffi::object_cache::MDataEntriesHandle;
use ffi_utils::callback::Callback;
use ffi_utils::{
    catch_unwind_cb, vec_clone_from_raw_parts, FfiResult, OpaqueCtx, SafePtr, FFI_RESULT_OK,
};
use routing::{ClientError, Value};
use safe_core::ffi::ipc::resp::{MDataEntry, MDataKey, MDataValue};
use safe_core::CoreError;
use std::collections::BTreeMap;
use std::os::raw::c_void;
use crate::App;

/// Create new empty entries.
#[no_mangle]
pub unsafe extern "C" fn mdata_entries_new(
    app: *const App,
    user_data: *mut c_void,
    o_cb: extern "C" fn(
        user_data: *mut c_void,
        result: *const FfiResult,
        entries_h: MDataEntriesHandle,
    ),
) {
    catch_unwind_cb(user_data, o_cb, || {
        send_sync(app, user_data, o_cb, |_, context| {
            Ok(context
                .object_cache()
                .insert_mdata_entries(Default::default()))
        })
    })
}

/// Insert an entry to the entries.
#[no_mangle]
pub unsafe extern "C" fn mdata_entries_insert(
    app: *const App,
    entries_h: MDataEntriesHandle,
    key: *const u8,
    key_len: usize,
    value: *const u8,
    value_len: usize,
    user_data: *mut c_void,
    o_cb: extern "C" fn(user_data: *mut c_void, result: *const FfiResult),
) {
    catch_unwind_cb(user_data, o_cb, || {
        let key = vec_clone_from_raw_parts(key, key_len);
        let value = vec_clone_from_raw_parts(value, value_len);

        with_entries(app, entries_h, user_data, o_cb, |entries| {
            let _ = entries.insert(
                key,
                Value {
                    content: value,
                    entry_version: 0,
                },
            );

            Ok(())
        })
    })
}

/// Returns the number of entries.
#[no_mangle]
pub unsafe extern "C" fn mdata_entries_len(
    app: *const App,
    entries_h: MDataEntriesHandle,
    user_data: *mut c_void,
    o_cb: extern "C" fn(user_data: *mut c_void, result: *const FfiResult, len: usize),
) {
    catch_unwind_cb(user_data, o_cb, || {
        with_entries(app, entries_h, user_data, o_cb, |entries| Ok(entries.len()))
    })
}

/// Get the entry value at the given key.
///
/// The caller must NOT free the content pointer.
#[no_mangle]
pub unsafe extern "C" fn mdata_entries_get(
    app: *const App,
    entries_h: MDataEntriesHandle,
    key: *const u8,
    key_len: usize,
    user_data: *mut c_void,
    o_cb: extern "C" fn(
        user_data: *mut c_void,
        result: *const FfiResult,
        content: *const u8,
        content_len: usize,
        version: u64,
    ),
) {
    catch_unwind_cb(user_data, o_cb, || {
        let user_data = OpaqueCtx(user_data);
        let key = vec_clone_from_raw_parts(key, key_len);

        (*app).send(move |_, context| {
            let entries = try_cb!(
                context.object_cache().get_mdata_entries(entries_h),
                user_data,
                o_cb
            );

            let value = entries
                .get(&key)
                .ok_or(ClientError::NoSuchEntry)
                .map_err(CoreError::from)
                .map_err(AppError::from);
            let value = try_cb!(value, user_data, o_cb);

            o_cb(
                user_data.0,
                FFI_RESULT_OK,
                value.content.as_safe_ptr(),
                value.content.len(),
                value.entry_version,
            );

            None
        })
    })
}

/// Return a list of the entries.
#[no_mangle]
pub unsafe extern "C" fn mdata_list_entries(
    app: *const App,
    entries_h: MDataEntriesHandle,
    user_data: *mut c_void,
    o_cb: extern "C" fn(
        user_data: *mut c_void,
        result: *const FfiResult,
        entries: *const MDataEntry,
        entries_len: usize,
    ),
) {
    let user_data = OpaqueCtx(user_data);

    catch_unwind_cb(user_data, o_cb, || {
        (*app).send(move |_client, context| {
            let entries = try_cb!(
                context.object_cache().get_mdata_entries(entries_h),
                user_data.0,
                o_cb
            );

            let entries_vec: Vec<MDataEntry> = entries
                .iter()
                .map(|(key, value)| MDataEntry {
                    key: MDataKey {
                        key: key.as_safe_ptr(),
                        key_len: key.len(),
                    },
                    value: MDataValue {
                        content: value.content.as_safe_ptr(),
                        content_len: value.content.len(),
                        entry_version: value.entry_version,
                    },
                }).collect();

            o_cb(
                user_data.0,
                FFI_RESULT_OK,
                entries_vec.as_safe_ptr(),
                entries_vec.len(),
            );

            None
        })
    })
}

/// Free the entries from memory.
#[no_mangle]
pub unsafe extern "C" fn mdata_entries_free(
    app: *const App,
    entries_h: MDataEntriesHandle,
    user_data: *mut c_void,
    o_cb: extern "C" fn(user_data: *mut c_void, result: *const FfiResult),
) {
    catch_unwind_cb(user_data, o_cb, || {
        send_sync(app, user_data, o_cb, move |_, context| {
            let _ = context.object_cache().remove_mdata_entries(entries_h)?;
            Ok(())
        })
    })
}

// -------------- Helpers --------------------------

unsafe fn with_entries<C, F>(
    app: *const App,
    entries_h: MDataEntriesHandle,
    user_data: *mut c_void,
    o_cb: C,
    f: F,
) -> Result<(), AppError>
where
    C: Callback + Copy + Send + 'static,
    F: FnOnce(&mut BTreeMap<Vec<u8>, Value>) -> Result<C::Args, AppError> + Send + 'static,
{
    send_sync(app, user_data, o_cb, move |_, context| {
        let mut entries = context.object_cache().get_mdata_entries(entries_h)?;
        f(&mut *entries)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ffi::mdata_info::*;
    use crate::ffi::mutable_data::entry_actions::*;
    use crate::ffi::mutable_data::permissions::*;
    use crate::ffi::mutable_data::*;
    use crate::ffi::object_cache::MDataEntryActionsHandle;
    use ffi_utils::test_utils::{
        call_0, call_1, call_vec, send_via_user_data, sender_as_user_data,
    };
    use ffi_utils::vec_clone_from_raw_parts;
    use routing::{Action, PermissionSet, Value};
    use safe_core::ipc::resp::{MDataEntry, MDataKey, MDataValue};
    use safe_core::utils;
    use std::os::raw::c_void;
    use std::sync::mpsc;
    use crate::test_utils::{create_app, run_now};

    // Test mdata entries operations.
    #[test]
    fn entries() {
        // Setup
        let app = create_app();

        let key0 = b"key0".to_vec();
        let key1 = b"key1".to_vec();

        let value0 = Value {
            content: unwrap!(utils::generate_random_vector(10)),
            entry_version: 0,
        };

        let value1 = Value {
            content: unwrap!(utils::generate_random_vector(10)),
            entry_version: 2,
        };

        let entries = btree_map![key0.clone() => value0.clone(),
                                 key1.clone() => value1.clone()];

        let handle0 = run_now(&app, move |_, context| {
            context.object_cache().insert_mdata_entries(entries)
        });

        let len1: usize =
            unsafe { unwrap!(call_1(|ud, cb| mdata_entries_len(&app, handle0, ud, cb))) };

        let handle1 = unsafe {
            let handle = unwrap!(call_1(|ud, cb| mdata_entries_new(&app, ud, cb)));
            unwrap!(call_0(|ud, cb| mdata_entries_insert(
                &app,
                handle,
                key0.as_ptr(),
                key0.len(),
                value0.content.as_ptr(),
                value0.content.len(),
                ud,
                cb,
            )));
            unwrap!(call_0(|ud, cb| mdata_entries_insert(
                &app,
                handle,
                key1.as_ptr(),
                key1.len(),
                value1.content.as_ptr(),
                value1.content.len(),
                ud,
                cb,
            )));
            handle
        };

        let len2: usize =
            unsafe { unwrap!(call_1(|ud, cb| mdata_entries_len(&app, handle1, ud, cb))) };

        assert_eq!(len1, len2);

        let (tx, rx) = mpsc::channel::<Value>();

        extern "C" fn get_cb(
            user_data: *mut c_void,
            res: *const FfiResult,
            ptr: *const u8,
            len: usize,
            version: u64,
        ) {
            unsafe {
                assert_eq!((*res).error_code, 0);

                let value = vec_clone_from_raw_parts(ptr, len);
                let value = Value {
                    content: value,
                    entry_version: version,
                };

                send_via_user_data(user_data, value)
            }
        }

        let mut ud = Default::default();

        // Key 0
        unsafe {
            mdata_entries_get(
                &app,
                handle0,
                key0.as_ptr(),
                key0.len(),
                sender_as_user_data(&tx, &mut ud),
                get_cb,
            );
        };
        let value = unwrap!(rx.recv());
        assert_eq!(value, value0);

        // Key 1
        unsafe {
            mdata_entries_get(
                &app,
                handle0,
                key1.as_ptr(),
                key1.len(),
                sender_as_user_data(&tx, &mut ud),
                get_cb,
            );
        };
        let value = unwrap!(rx.recv());
        assert_eq!(value, value1);

        // Get list of entries, verify number of entries
        let entries: Vec<MDataEntry> =
            unsafe { unwrap!(call_vec(|ud, cb| mdata_list_entries(&app, handle0, ud, cb))) };

        assert_eq!(entries.len(), 2);

        assert!(entries.contains(&MDataEntry {
            key: MDataKey(key0),
            value: MDataValue::from_routing(value0),
        }));
        assert!(entries.contains(&MDataEntry {
            key: MDataKey(key1),
            value: MDataValue::from_routing(value1),
        }));

        // Free
        unsafe {
            unwrap!(call_0(|ud, cb| mdata_entries_free(&app, handle0, ud, cb)));
            unwrap!(call_0(|ud, cb| mdata_entries_free(&app, handle1, ud, cb)))
        }
    }

    // Test mdata keys/values operations.
    #[test]
    fn keys_and_values() {
        // Setup
        let app = create_app();

        let key0 = b"key0".to_vec();
        let key1 = b"key1".to_vec();

        let value0 = MDataValue {
            content: unwrap!(utils::generate_random_vector(10)),
            entry_version: 0,
        };

        let value1 = MDataValue {
            content: unwrap!(utils::generate_random_vector(10)),
            entry_version: 0,
        };

        // Create a permissions set
        let perms_set = PermissionSet::new().allow(Action::Insert);

        // Create permissions for anyone
        let perms_h: MDataPermissionsHandle =
            unsafe { unwrap!(call_1(|ud, cb| mdata_permissions_new(&app, ud, cb))) };

        unsafe {
            unwrap!(call_0(|ud, cb| mdata_permissions_insert(
                &app,
                perms_h,
                USER_ANYONE,
                &permission_set_into_repr_c(perms_set),
                ud,
                cb,
            )))
        };

        // Create an empty public mdata
        let md_info: NativeMDataInfo =
            unsafe { unwrap!(call_1(|ud, cb| mdata_info_random_public(10_000, ud, cb))) };
        let md_info = md_info.into_repr_c();

        unsafe {
            unwrap!(call_0(|ud, cb| mdata_put(
                &app,
                &md_info,
                perms_h,
                ENTRIES_EMPTY,
                ud,
                cb
            )))
        };

        // Get list of keys, verify number of keys
        let keys: Vec<NativeMDataKey> =
            unsafe { unwrap!(call_vec(|ud, cb| mdata_list_keys(&app, &md_info, ud, cb))) };

        assert_eq!(keys.len(), 0);

        // Ditto for values
        let values: Vec<MDataValue> =
            unsafe { unwrap!(call_vec(|ud, cb| mdata_list_values(&app, &md_info, ud, cb))) };

        assert_eq!(values.len(), 0);

        // Add entries to a public MD
        let actions_h: MDataEntryActionsHandle =
            unsafe { unwrap!(call_1(|ud, cb| mdata_entry_actions_new(&app, ud, cb))) };

        {
            unsafe {
                unwrap!(call_0(|ud, cb| mdata_entry_actions_insert(
                    &app,
                    actions_h,
                    key0.as_ptr(),
                    key0.len(),
                    value0.content.as_ptr(),
                    value0.content.len(),
                    ud,
                    cb,
                )))
            };

            unsafe {
                unwrap!(call_0(|ud, cb| mdata_entry_actions_insert(
                    &app,
                    actions_h,
                    key1.as_ptr(),
                    key1.len(),
                    value1.content.as_ptr(),
                    value1.content.len(),
                    ud,
                    cb,
                )))
            };
        }

        unsafe {
            unwrap!(call_0(|ud, cb| mdata_mutate_entries(
                &app, &md_info, actions_h, ud, cb
            )))
        }

        // Get the keys and values handles again
        let keys: Vec<MDataKey> =
            unsafe { unwrap!(call_vec(|ud, cb| mdata_list_keys(&app, &md_info, ud, cb))) };
        assert_eq!(keys.len(), 2);

        assert!(keys.contains(&MDataKey(key0)));
        assert!(keys.contains(&MDataKey(key1)));

        let values: Vec<MDataValue> =
            unsafe { unwrap!(call_vec(|ud, cb| mdata_list_values(&app, &md_info, ud, cb))) };
        assert_eq!(values.len(), 2);

        assert!(values.contains(&value0));
        assert!(values.contains(&value1));
    }
}
