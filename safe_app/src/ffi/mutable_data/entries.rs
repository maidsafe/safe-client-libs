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

//! FFI for mutable data entries, keys and values.

use App;
use errors::AppError;
use ffi::helper::send_sync;
use ffi_utils::{FFI_RESULT_OK, FfiResult, OpaqueCtx, SafePtr, catch_unwind_cb,
                vec_clone_from_raw_parts};
use ffi_utils::callback::Callback;
use object_cache::{MDataEntriesHandle, MDataKeysHandle, MDataValuesHandle};
use routing::{ClientError, Value};
use safe_core::CoreError;
use std::collections::{BTreeMap, BTreeSet};
use std::os::raw::c_void;

/// Create new empty entries.
#[no_mangle]
pub unsafe extern "C" fn mdata_entries_new(
    app: *const App,
    user_data: *mut c_void,
    o_cb: extern "C" fn(*mut c_void, FfiResult, MDataEntriesHandle),
) {
    catch_unwind_cb(user_data, o_cb, || {
        send_sync(app, user_data, o_cb, |_, context| {
            Ok(context.object_cache().insert_mdata_entries(
                Default::default(),
            ))
        })
    })
}

/// Insert an entry to the entries.
#[no_mangle]
pub unsafe extern "C" fn mdata_entries_insert(
    app: *const App,
    entries_h: MDataEntriesHandle,
    key_ptr: *const u8,
    key_len: usize,
    value_ptr: *const u8,
    value_len: usize,
    user_data: *mut c_void,
    o_cb: extern "C" fn(*mut c_void, FfiResult),
) {
    catch_unwind_cb(user_data, o_cb, || {
        let key = vec_clone_from_raw_parts(key_ptr, key_len);
        let value = vec_clone_from_raw_parts(value_ptr, value_len);

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
    o_cb: extern "C" fn(*mut c_void, FfiResult, usize),
) {
    catch_unwind_cb(user_data, o_cb, || {
        with_entries(app, entries_h, user_data, o_cb, |entries| Ok(entries.len()))
    })
}

/// Get the entry value at the given key.
/// The callbacks arguments are: user data, error code, pointer to value,
/// value length, entry version. The caller must NOT free the pointer.
#[no_mangle]
pub unsafe extern "C" fn mdata_entries_get(
    app: *const App,
    entries_h: MDataEntriesHandle,
    key_ptr: *const u8,
    key_len: usize,
    user_data: *mut c_void,
    o_cb: extern "C" fn(*mut c_void, FfiResult, *const u8, usize, u64),
) {
    catch_unwind_cb(user_data, o_cb, || {
        let user_data = OpaqueCtx(user_data);
        let key = vec_clone_from_raw_parts(key_ptr, key_len);

        (*app).send(move |_, context| {
            let entries = context.object_cache().get_mdata_entries(entries_h);
            let entries = try_cb!(entries, user_data, o_cb);

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

/// Iterate over the entries.
///
/// The `o_each_cb` callback is invoked once for each entry,
/// passing user data, pointer to key, key length, pointer to value, value length
/// and entry version in that order.
///
/// The `o_done_cb` callback is invoked after the iteration is done, or in case of error.
#[no_mangle]
pub unsafe extern "C" fn mdata_entries_for_each(
    app: *const App,
    entries_h: MDataEntriesHandle,
    user_data: *mut c_void,
    o_each_cb: extern "C" fn(*mut c_void, *const u8, usize, *const u8, usize, u64),
    o_done_cb: extern "C" fn(*mut c_void, FfiResult),
) {
    catch_unwind_cb(user_data, o_done_cb, || {
        let user_data = OpaqueCtx(user_data);

        with_entries(app, entries_h, user_data.0, o_done_cb, move |entries| {
            for (key, value) in entries {
                o_each_cb(
                    user_data.0,
                    key.as_safe_ptr(),
                    key.len(),
                    value.content.as_safe_ptr(),
                    value.content.len(),
                    value.entry_version,
                );
            }

            Ok(())
        })
    })
}

/// Free the entries from memory.
#[no_mangle]
pub unsafe extern "C" fn mdata_entries_free(
    app: *const App,
    entries_h: MDataEntriesHandle,
    user_data: *mut c_void,
    o_cb: extern "C" fn(*mut c_void, FfiResult),
) {
    catch_unwind_cb(user_data, o_cb, || {
        send_sync(app, user_data, o_cb, move |_, context| {
            let _ = context.object_cache().remove_mdata_entries(entries_h)?;
            Ok(())
        })
    })
}

/// Returns the number of keys.
#[no_mangle]
pub unsafe extern "C" fn mdata_keys_len(
    app: *const App,
    keys_h: MDataKeysHandle,
    user_data: *mut c_void,
    o_cb: extern "C" fn(*mut c_void, FfiResult, usize),
) {
    catch_unwind_cb(user_data, o_cb, || {
        with_keys(app, keys_h, user_data, o_cb, |keys| Ok(keys.len()))
    })
}

/// Iterate over the keys.
///
/// The `o_each_cb` callback is invoked once for each key,
/// passing user data, pointer to key and key length.
///
/// The `o_done_cb` callback is invoked after the iteration is done, or in case of error.
#[no_mangle]
pub unsafe extern "C" fn mdata_keys_for_each(
    app: *const App,
    keys_h: MDataKeysHandle,
    user_data: *mut c_void,
    o_each_cb: unsafe extern "C" fn(*mut c_void, *const u8, usize),
    o_done_cb: extern "C" fn(*mut c_void, FfiResult),
) {
    catch_unwind_cb(user_data, o_done_cb, || {
        let user_data = OpaqueCtx(user_data);

        with_keys(app, keys_h, user_data.0, o_done_cb, move |keys| {
            for key in keys {
                o_each_cb(user_data.0, key.as_safe_ptr(), key.len());
            }

            Ok(())
        })
    })
}

/// Free the keys from memory.
#[no_mangle]
pub unsafe extern "C" fn mdata_keys_free(
    app: *const App,
    keys_h: MDataKeysHandle,
    user_data: *mut c_void,
    o_cb: extern "C" fn(*mut c_void, FfiResult),
) {
    catch_unwind_cb(user_data, o_cb, || {
        send_sync(app, user_data, o_cb, move |_, context| {
            let _ = context.object_cache().remove_mdata_keys(keys_h)?;
            Ok(())
        })
    })
}

/// Returns the number of values.
#[no_mangle]
pub unsafe extern "C" fn mdata_values_len(
    app: *const App,
    values_h: MDataValuesHandle,
    user_data: *mut c_void,
    o_cb: extern "C" fn(*mut c_void, FfiResult, usize),
) {
    catch_unwind_cb(user_data, o_cb, || {
        with_values(app, values_h, user_data, o_cb, |values| Ok(values.len()))
    })
}

/// Iterate over the values.
///
/// The `o_each_cb` callback is invoked once for each value,
/// passing user data, pointer to value, value length and entry version.
///
/// The `o_done_cb` callback is invoked after the iteration is done, or in case of error.
#[no_mangle]
pub unsafe extern "C" fn mdata_values_for_each(
    app: *const App,
    values_h: MDataValuesHandle,
    user_data: *mut c_void,
    o_each_cb: unsafe extern "C" fn(*mut c_void, *const u8, usize, u64),
    o_done_cb: extern "C" fn(*mut c_void, FfiResult),
) {
    catch_unwind_cb(user_data, o_done_cb, || {
        let user_data = OpaqueCtx(user_data);

        with_values(app, values_h, user_data.0, o_done_cb, move |values| {
            for value in values {
                o_each_cb(
                    user_data.0,
                    value.content.as_safe_ptr(),
                    value.content.len(),
                    value.entry_version,
                );
            }

            Ok(())
        })
    })
}

/// Free the values from memory.
#[no_mangle]
pub unsafe extern "C" fn mdata_values_free(
    app: *const App,
    values_h: MDataValuesHandle,
    user_data: *mut c_void,
    o_cb: extern "C" fn(*mut c_void, FfiResult),
) {
    catch_unwind_cb(user_data, o_cb, || {
        send_sync(app, user_data, o_cb, move |_, context| {
            let _ = context.object_cache().remove_mdata_values(values_h)?;
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

unsafe fn with_keys<C, F>(
    app: *const App,
    keys_h: MDataKeysHandle,
    user_data: *mut c_void,
    o_cb: C,
    f: F,
) -> Result<(), AppError>
where
    C: Callback + Copy + Send + 'static,
    F: FnOnce(&BTreeSet<Vec<u8>>) -> Result<C::Args, AppError> + Send + 'static,
{
    send_sync(app, user_data, o_cb, move |_, context| {
        let keys = context.object_cache().get_mdata_keys(keys_h)?;
        f(&*keys)
    })
}

unsafe fn with_values<C, F>(
    app: *const App,
    values_h: MDataValuesHandle,
    user_data: *mut c_void,
    o_cb: C,
    f: F,
) -> Result<(), AppError>
where
    C: Callback + Copy + Send + 'static,
    F: FnOnce(&Vec<Value>) -> Result<C::Args, AppError> + Send + 'static,
{
    send_sync(app, user_data, o_cb, move |_, context| {
        let values = context.object_cache().get_mdata_values(values_h)?;
        f(&*values)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ffi_utils::test_utils::{call_1, send_via_user_data, sender_as_user_data};
    use ffi_utils::vec_clone_from_raw_parts;
    use routing::Value;
    use safe_core::utils;
    use std::collections::BTreeMap;
    use std::os::raw::c_void;
    use std::sync::mpsc::{self, Sender};
    use test_utils::{create_app, run_now};

    // Test entry FFI operations.
    #[test]
    fn entries() {
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

        let entries =
            btree_map![key0.clone() => value0.clone(),
                                 key1.clone() => value1.clone()];

        let handle = run_now(&app, move |_, context| {
            context.object_cache().insert_mdata_entries(entries)
        });

        let len: usize =
            unsafe { unwrap!(call_1(|ud, cb| mdata_entries_len(&app, handle, ud, cb))) };
        assert_eq!(len, 2);

        let (tx, rx) = mpsc::channel::<Value>();

        extern "C" fn get_cb(
            user_data: *mut c_void,
            res: FfiResult,
            ptr: *const u8,
            len: usize,
            version: u64,
        ) {
            assert_eq!(res.error_code, 0);

            unsafe {
                let value = vec_clone_from_raw_parts(ptr, len);
                let value = Value {
                    content: value,
                    entry_version: version,
                };

                send_via_user_data(user_data, value)
            }
        }

        // key 0
        unsafe {
            mdata_entries_get(
                &app,
                handle,
                key0.as_ptr(),
                key0.len(),
                sender_as_user_data(&tx),
                get_cb,
            );
        };
        let value = unwrap!(rx.recv());
        assert_eq!(value, value0);

        // key 1
        unsafe {
            mdata_entries_get(
                &app,
                handle,
                key1.as_ptr(),
                key1.len(),
                sender_as_user_data(&tx),
                get_cb,
            );
        };
        let value = unwrap!(rx.recv());
        assert_eq!(value, value1);

        // iteration
        let (tx, rx) = mpsc::channel::<()>();
        let mut user_data = (tx, BTreeMap::<Vec<u8>, Value>::new());

        extern "C" fn entry_cb(
            user_data: *mut c_void,
            key_ptr: *const u8,
            key_len: usize,
            value_ptr: *const u8,
            value_len: usize,
            entry_version: u64,
        ) {
            unsafe {
                let key = vec_clone_from_raw_parts(key_ptr, key_len);
                let value = Value {
                    content: vec_clone_from_raw_parts(value_ptr, value_len),
                    entry_version: entry_version,
                };

                let user_data = user_data as *mut (Sender<()>, BTreeMap<_, _>);
                let _ = (*user_data).1.insert(key, value);
            }
        }

        extern "C" fn done_cb(user_data: *mut c_void, res: FfiResult) {
            assert_eq!(res.error_code, 0);
            let user_data = user_data as *mut (Sender<_>, BTreeMap<Vec<u8>, Value>);

            unsafe {
                unwrap!((*user_data).0.send(()));
            }
        }

        unsafe {
            let user_data: *mut _ = &mut user_data;
            mdata_entries_for_each(&app, handle, user_data as *mut c_void, entry_cb, done_cb)
        }

        unwrap!(rx.recv());
        let entries = user_data.1;

        assert_eq!(entries.len(), 2);
        assert_eq!(*unwrap!(entries.get(&key0)), value0);
        assert_eq!(*unwrap!(entries.get(&key1)), value1);
    }

    // TODO: implement this test
    #[test]
    fn keys() {}

    // TODO: implement this test
    #[test]
    fn values() {}
}
