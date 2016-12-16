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

//! FFI for mutable data entries, keys and values.

use App;
use errors::AppError;
use ffi::helper::send_sync;
use ffi_utils::{OpaqueCtx, catch_unwind_cb, u8_ptr_to_vec};
use ffi_utils::callback::Callback;
use object_cache::{MDataEntriesHandle, MDataKeysHandle, MDataValuesHandle};
use routing::{ClientError, Value};
use safe_core::CoreError;
use std::collections::{BTreeMap, BTreeSet};
use std::os::raw::c_void;

/// Create new empty entries.
#[no_mangle]
pub unsafe extern "C" fn mdata_entries_new(app: *const App,
                                           user_data: *mut c_void,
                                           o_cb: extern "C" fn(*mut c_void,
                                                               i32,
                                                               MDataEntriesHandle)) {
    catch_unwind_cb(user_data, o_cb, || {
        send_sync(app,
                  user_data,
                  o_cb,
                  |context| Ok(context.object_cache().insert_mdata_entries(Default::default())))
    })
}

/// Insert an entry to the entries.
#[no_mangle]
pub unsafe extern "C" fn mdata_entries_insert(app: *const App,
                                              entries_h: MDataEntriesHandle,
                                              key_ptr: *const u8,
                                              key_len: usize,
                                              value_ptr: *const u8,
                                              value_len: usize,
                                              user_data: *mut c_void,
                                              o_cb: extern "C" fn(*mut c_void, i32)) {
    catch_unwind_cb(user_data, o_cb, || {
        let key = u8_ptr_to_vec(key_ptr, key_len);
        let value = u8_ptr_to_vec(value_ptr, value_len);

        with_entries(app, entries_h, user_data, o_cb, |entries| {
            let _ = entries.insert(key,
                                   Value {
                                       content: value,
                                       entry_version: 0,
                                   });

            Ok(())
        })
    })
}

/// Returns the number of entries.
#[no_mangle]
pub unsafe extern "C" fn mdata_entries_len(app: *const App,
                                           entries_h: MDataEntriesHandle,
                                           user_data: *mut c_void,
                                           o_cb: extern "C" fn(*mut c_void, i32, usize)) {
    catch_unwind_cb(user_data,
                    o_cb,
                    || with_entries(app, entries_h, user_data, o_cb, |entries| Ok(entries.len())))
}

/// Get the entry value at the given key.
/// The callbacks arguments are: user data, error code, pointer to value,
/// value length, entry version. The caller must NOT free the pointer.
#[no_mangle]
pub unsafe extern "C" fn mdata_entries_get(app: *const App,
                                           entries_h: MDataEntriesHandle,
                                           key_ptr: *const u8,
                                           key_len: usize,
                                           user_data: *mut c_void,
                                           o_cb: extern "C" fn(*mut c_void,
                                                               i32,
                                                               *const u8,
                                                               usize,
                                                               u64)) {
    catch_unwind_cb(user_data, o_cb, || {
        let key = u8_ptr_to_vec(key_ptr, key_len);

        with_entries(app, entries_h, user_data, o_cb, move |entries| {
            let value = entries.get(&key)
                .ok_or(ClientError::NoSuchEntry)
                .map_err(CoreError::from)
                .map_err(AppError::from)?;

            Ok((value.content.as_ptr(), value.content.len(), value.entry_version))
        })
    })
}

/// Iterate over the entries.
///
/// The `entry_cb` callback is invoked once for each entry,
/// passing user data, pointer to key, key length, pointer to value, value length
/// and entry version in that order.
///
/// The `o_cb` callback is invoked after the iteration is done, or in case of error.
#[no_mangle]
pub unsafe extern "C" fn mdata_entries_for_each(app: *const App,
                                                entries_h: MDataEntriesHandle,
                                                entry_cb: extern "C" fn(*mut c_void,
                                                                        *const u8,
                                                                        usize,
                                                                        *const u8,
                                                                        usize,
                                                                        u64),
                                                user_data: *mut c_void,
                                                o_cb: extern "C" fn(*mut c_void, i32)) {
    catch_unwind_cb(user_data, o_cb, || {
        let user_data = OpaqueCtx(user_data);

        with_entries(app, entries_h, user_data.0, o_cb, move |entries| {
            for (key, value) in entries {
                entry_cb(user_data.0,
                         key.as_ptr(),
                         key.len(),
                         value.content.as_ptr(),
                         value.content.len(),
                         value.entry_version);
            }

            Ok(())
        })
    })
}

/// Free the entries from memory.
#[no_mangle]
pub unsafe extern "C" fn mdata_entries_free(app: *const App,
                                            entries_h: MDataEntriesHandle,
                                            user_data: *mut c_void,
                                            o_cb: extern "C" fn(*mut c_void, i32)) {
    catch_unwind_cb(user_data, o_cb, || {
        send_sync(app, user_data, o_cb, move |context| {
            let _ = context.object_cache().remove_mdata_entries(entries_h)?;
            Ok(())
        })
    })
}

/// Returns the number of keys.
#[no_mangle]
pub unsafe extern "C" fn mdata_keys_len(app: *const App,
                                        keys_h: MDataKeysHandle,
                                        user_data: *mut c_void,
                                        o_cb: extern "C" fn(*mut c_void, i32, usize)) {
    catch_unwind_cb(user_data,
                    o_cb,
                    || with_keys(app, keys_h, user_data, o_cb, |keys| Ok(keys.len())))
}

/// Iterate over the keys.
///
/// The `key_cb` callback is invoked once for each key,
/// passing user data, pointer to key and key length.
///
/// The `o_cb` callback is invoked after the iteration is done, or in case of error.
#[no_mangle]
pub unsafe extern "C" fn mdata_keys_for_each(app: *const App,
                                             keys_h: MDataKeysHandle,
                                             key_cb: unsafe extern "C" fn(*mut c_void,
                                                                          *const u8,
                                                                          usize),
                                             user_data: *mut c_void,
                                             o_cb: extern "C" fn(*mut c_void, i32)) {
    catch_unwind_cb(user_data, o_cb, || {
        let user_data = OpaqueCtx(user_data);

        with_keys(app, keys_h, user_data.0, o_cb, move |keys| {
            for key in keys {
                key_cb(user_data.0, key.as_ptr(), key.len());
            }

            Ok(())
        })
    })
}

/// Free the keys from memory.
#[no_mangle]
pub unsafe extern "C" fn mdata_keys_free(app: *const App,
                                         keys_h: MDataKeysHandle,
                                         user_data: *mut c_void,
                                         o_cb: extern "C" fn(*mut c_void, i32)) {
    catch_unwind_cb(user_data, o_cb, || {
        send_sync(app, user_data, o_cb, move |context| {
            let _ = context.object_cache().remove_mdata_keys(keys_h)?;
            Ok(())
        })
    })
}

/// Returns the number of values.
#[no_mangle]
pub unsafe extern "C" fn mdata_values_len(app: *const App,
                                          values_h: MDataValuesHandle,
                                          user_data: *mut c_void,
                                          o_cb: extern "C" fn(*mut c_void, i32, usize)) {
    catch_unwind_cb(user_data,
                    o_cb,
                    || with_values(app, values_h, user_data, o_cb, |values| Ok(values.len())))
}

/// Iterate over the values.
///
/// The `value_cb` callback is invoked once for each value,
/// passing user data, pointer to value, value length and entry version.
///
/// The `o_cb` callback is invoked after the iteration is done, or in case of error.
#[no_mangle]
pub unsafe extern "C" fn mdata_values_for_each(app: *const App,
                                               values_h: MDataValuesHandle,
                                               value_cb: unsafe extern "C" fn(*mut c_void,
                                                                              *const u8,
                                                                              usize,
                                                                              u64),
                                               user_data: *mut c_void,
                                               o_cb: extern "C" fn(*mut c_void, i32)) {
    catch_unwind_cb(user_data, o_cb, || {
        let user_data = OpaqueCtx(user_data);

        with_values(app, values_h, user_data.0, o_cb, move |values| {
            for value in values {
                value_cb(user_data.0,
                         value.content.as_ptr(),
                         value.content.len(),
                         value.entry_version);
            }

            Ok(())
        })
    })
}

/// Free the values from memory.
#[no_mangle]
pub unsafe extern "C" fn mdata_values_free(app: *const App,
                                           values_h: MDataValuesHandle,
                                           user_data: *mut c_void,
                                           o_cb: extern "C" fn(*mut c_void, i32)) {
    catch_unwind_cb(user_data, o_cb, || {
        send_sync(app, user_data, o_cb, move |context| {
            let _ = context.object_cache().remove_mdata_values(values_h)?;
            Ok(())
        })
    })
}

// -------------- Helpers --------------------------

unsafe fn with_entries<C, F>(app: *const App,
                             entries_h: MDataEntriesHandle,
                             user_data: *mut c_void,
                             o_cb: C,
                             f: F)
                             -> Result<(), AppError>
    where C: Callback + Copy + Send + 'static,
          F: FnOnce(&mut BTreeMap<Vec<u8>, Value>) -> Result<C::Args, AppError> + Send + 'static
{
    send_sync(app, user_data, o_cb, move |context| {
        let mut entries = context.object_cache().get_mdata_entries(entries_h)?;
        f(&mut *entries)
    })
}

unsafe fn with_keys<C, F>(app: *const App,
                          keys_h: MDataKeysHandle,
                          user_data: *mut c_void,
                          o_cb: C,
                          f: F)
                          -> Result<(), AppError>
    where C: Callback + Copy + Send + 'static,
          F: FnOnce(&BTreeSet<Vec<u8>>) -> Result<C::Args, AppError> + Send + 'static
{
    send_sync(app, user_data, o_cb, move |context| {
        let keys = context.object_cache().get_mdata_keys(keys_h)?;
        f(&*keys)
    })
}

unsafe fn with_values<C, F>(app: *const App,
                            values_h: MDataValuesHandle,
                            user_data: *mut c_void,
                            o_cb: C,
                            f: F)
                            -> Result<(), AppError>
    where C: Callback + Copy + Send + 'static,
          F: FnOnce(&Vec<Value>) -> Result<C::Args, AppError> + Send + 'static
{
    send_sync(app, user_data, o_cb, move |context| {
        let values = context.object_cache().get_mdata_values(values_h)?;
        f(&*values)
    })
}

#[cfg(test)]
mod tests {
    use ffi_utils::test_utils::{call_1, call_3};
    use ffi_utils::u8_ptr_to_vec;
    use routing::Value;
    use safe_core::utils;
    use std::collections::BTreeMap;
    use std::os::raw::c_void;
    use std::slice;
    use std::sync::mpsc::{self, Sender};
    use super::*;
    use test_utils::{create_app, run_now};

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

        let entries = btree_map![key0.clone() => value0.clone(),
                                 key1.clone() => value1.clone()];

        let handle = run_now(&app, move |_, context| {
            context.object_cache().insert_mdata_entries(entries)
        });

        let len = unsafe { unwrap!(call_1(|ud, cb| mdata_entries_len(&app, handle, ud, cb))) };
        assert_eq!(len, 2);

        // key 0
        let (content, version) = unsafe {
            let (ptr, len, version) = unwrap!(call_3(|ud, cb| {
                mdata_entries_get(&app, handle, key0.as_ptr(), key0.len(), ud, cb)
            }));

            let content = slice::from_raw_parts(ptr, len);
            (content, version)
        };
        assert_eq!(content, &value0.content[..]);
        assert_eq!(version, value0.entry_version);

        // key 1
        let (content, version) = unsafe {
            let (ptr, len, version) = unwrap!(call_3(|ud, cb| {
                mdata_entries_get(&app, handle, key1.as_ptr(), key1.len(), ud, cb)
            }));

            let content = slice::from_raw_parts(ptr, len);
            (content, version)
        };
        assert_eq!(content, &value1.content[..]);
        assert_eq!(version, value1.entry_version);

        // iteration
        let (tx, rx) = mpsc::channel::<()>();
        let mut user_data = (tx, BTreeMap::<Vec<u8>, Value>::new());

        extern "C" fn entry_cb(user_data: *mut c_void,
                               key_ptr: *const u8,
                               key_len: usize,
                               value_ptr: *const u8,
                               value_len: usize,
                               entry_version: u64) {
            unsafe {
                let key = u8_ptr_to_vec(key_ptr, key_len);
                let value = Value {
                    content: u8_ptr_to_vec(value_ptr, value_len),
                    entry_version: entry_version,
                };

                let user_data = user_data as *mut (Sender<()>, BTreeMap<_, _>);
                let _ = (*user_data).1.insert(key, value);
            }
        }

        extern "C" fn done_cb(user_data: *mut c_void, error_code: i32) {
            assert_eq!(error_code, 0);
            let user_data = user_data as *mut (Sender<_>, BTreeMap<Vec<u8>, Value>);

            unsafe {
                unwrap!((*user_data).0.send(()));
            }
        }

        unsafe {
            let user_data: *mut _ = &mut user_data;
            mdata_entries_for_each(&app, handle, entry_cb, user_data as *mut c_void, done_cb)
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
