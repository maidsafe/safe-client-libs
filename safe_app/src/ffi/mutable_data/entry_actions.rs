// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

//! FFI for mutable data entry actions.

use crate::ffi::helper::send_sync;
use crate::ffi::object_cache::MDataEntryActionsHandle;
use ffi_utils::{catch_unwind_cb, vec_clone_from_raw_parts, FfiResult};
use routing::{EntryAction, Value};
use std::os::raw::c_void;
use crate::App;

/// Create new entry actions.
#[no_mangle]
pub unsafe extern "C" fn mdata_entry_actions_new(
    app: *const App,
    user_data: *mut c_void,
    o_cb: extern "C" fn(
        user_data: *mut c_void,
        result: *const FfiResult,
        entry_actions_h: MDataEntryActionsHandle,
    ),
) {
    catch_unwind_cb(user_data, o_cb, || {
        send_sync(app, user_data, o_cb, |_, context| {
            let actions = Default::default();
            Ok(context.object_cache().insert_mdata_entry_actions(actions))
        })
    })
}

/// Add action to insert new entry.
#[no_mangle]
pub unsafe extern "C" fn mdata_entry_actions_insert(
    app: *const App,
    actions_h: MDataEntryActionsHandle,
    key: *const u8,
    key_len: usize,
    value: *const u8,
    value_len: usize,
    user_data: *mut c_void,
    o_cb: extern "C" fn(user_data: *mut c_void, result: *const FfiResult),
) {
    add_action(app, actions_h, key, key_len, user_data, o_cb, || {
        EntryAction::Ins(Value {
            content: vec_clone_from_raw_parts(value, value_len),
            entry_version: 0,
        })
    })
}

/// Add action to update existing entry.
#[no_mangle]
pub unsafe extern "C" fn mdata_entry_actions_update(
    app: *const App,
    actions_h: MDataEntryActionsHandle,
    key: *const u8,
    key_len: usize,
    value: *const u8,
    value_len: usize,
    entry_version: u64,
    user_data: *mut c_void,
    o_cb: extern "C" fn(user_data: *mut c_void, result: *const FfiResult),
) {
    add_action(app, actions_h, key, key_len, user_data, o_cb, || {
        EntryAction::Update(Value {
            content: vec_clone_from_raw_parts(value, value_len),
            entry_version,
        })
    })
}

/// Add action to delete existing entry.
#[no_mangle]
pub unsafe extern "C" fn mdata_entry_actions_delete(
    app: *const App,
    actions_h: MDataEntryActionsHandle,
    key: *const u8,
    key_len: usize,
    entry_version: u64,
    user_data: *mut c_void,
    o_cb: extern "C" fn(user_data: *mut c_void, result: *const FfiResult),
) {
    add_action(app, actions_h, key, key_len, user_data, o_cb, || {
        EntryAction::Del(entry_version)
    })
}

/// Free the entry actions from memory
#[no_mangle]
pub unsafe extern "C" fn mdata_entry_actions_free(
    app: *const App,
    actions_h: MDataEntryActionsHandle,
    user_data: *mut c_void,
    o_cb: extern "C" fn(user_data: *mut c_void, result: *const FfiResult),
) {
    catch_unwind_cb(user_data, o_cb, || {
        send_sync(app, user_data, o_cb, move |_, context| {
            let _ = context
                .object_cache()
                .remove_mdata_entry_actions(actions_h)?;
            Ok(())
        })
    })
}

// Add new action to the entry actions stored in the object cache. The action
// to add is the result of the passed in lambda `f`.
unsafe fn add_action<F>(
    app: *const App,
    actions_h: MDataEntryActionsHandle,
    key: *const u8,
    key_len: usize,
    user_data: *mut c_void,
    o_cb: extern "C" fn(user_data: *mut c_void, result: *const FfiResult),
    f: F,
) where
    F: FnOnce() -> EntryAction,
{
    catch_unwind_cb(user_data, o_cb, || {
        let key = vec_clone_from_raw_parts(key, key_len);
        let action = f();

        send_sync(app, user_data, o_cb, move |_, context| {
            let mut actions = context.object_cache().get_mdata_entry_actions(actions_h)?;
            let _ = actions.insert(key, action);
            Ok(())
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ffi_utils::test_utils::{call_0, call_1};
    use routing::{EntryAction, Value};
    use safe_core::utils;
    use crate::test_utils::{create_app, run_now};

    // Test entry action basics such as insert, update, and delete.
    #[test]
    fn basics() {
        let app = create_app();

        let handle = unsafe { unwrap!(call_1(|ud, cb| mdata_entry_actions_new(&app, ud, cb))) };

        run_now(&app, move |_, context| {
            let actions = unwrap!(context.object_cache().get_mdata_entry_actions(handle));
            assert!(actions.is_empty());
        });

        let key0 = b"key0".to_vec();
        let key1 = b"key1".to_vec();
        let key2 = b"key2".to_vec();

        let value0 = unwrap!(utils::generate_random_vector(10));
        let value1 = unwrap!(utils::generate_random_vector(10));

        let version1 = 4;
        let version2 = 8;

        unsafe {
            unwrap!(call_0(|ud, cb| mdata_entry_actions_insert(
                &app,
                handle,
                key0.as_ptr(),
                key0.len(),
                value0.as_ptr(),
                value0.len(),
                ud,
                cb,
            )));

            unwrap!(call_0(|ud, cb| mdata_entry_actions_update(
                &app,
                handle,
                key1.as_ptr(),
                key1.len(),
                value1.as_ptr(),
                value1.len(),
                version1,
                ud,
                cb,
            )));

            unwrap!(call_0(|ud, cb| mdata_entry_actions_delete(
                &app,
                handle,
                key2.as_ptr(),
                key2.len(),
                version2,
                ud,
                cb,
            )));
        }

        run_now(&app, move |_, context| {
            let actions = unwrap!(context.object_cache().get_mdata_entry_actions(handle));
            assert_eq!(actions.len(), 3);

            match *unwrap!(actions.get(&key0)) {
                EntryAction::Ins(Value {
                    ref content,
                    entry_version: 0,
                })
                    if *content == value0 =>
                {
                    ()
                }
                _ => panic!("Unexpected action"),
            }

            match *unwrap!(actions.get(&key1)) {
                EntryAction::Update(Value {
                    ref content,
                    entry_version,
                })
                    if *content == value1 && entry_version == version1 =>
                {
                    ()
                }
                _ => panic!("Unexpected action"),
            }

            match *unwrap!(actions.get(&key2)) {
                EntryAction::Del(version) if version == version2 => (),
                _ => panic!("Unexpected action"),
            }
        });

        unsafe {
            unwrap!(call_0(|ud, cb| mdata_entry_actions_free(
                &app, handle, ud, cb
            ),))
        };

        run_now(&app, move |_, context| {
            assert!(
                context
                    .object_cache()
                    .get_mdata_entry_actions(handle)
                    .is_err()
            )
        });
    }
}
