// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

pub mod entries;
pub mod entry_actions;
pub mod metadata;
pub mod permissions;

mod helper;
#[cfg(test)]
mod tests;

use crate::errors::AppError;
use crate::ffi::errors::Error;
use crate::ffi::helper::send;
use crate::ffi::object_cache::{
    MDataEntriesHandle, MDataEntryActionsHandle, MDataPermissionsHandle, SignPubKeyHandle,
    NULL_OBJECT_HANDLE,
};
use crate::ffi::GET_NEXT_VERSION;
use crate::App;
use bincode::serialized_size;
use ffi_utils::{
    catch_unwind_cb, vec_clone_from_raw_parts, FfiResult, OpaqueCtx, ReprC, SafePtr, FFI_RESULT_OK,
};
use futures::future::{self, Either};
use futures::Future;
use safe_core::ffi::ipc::req::PermissionSet;
use safe_core::ffi::ipc::resp::MDataKey;
use safe_core::ffi::ipc::resp::MDataValue;
use safe_core::ffi::MDataInfo;
use safe_core::ipc::req::{permission_set_clone_from_repr_c, permission_set_into_repr_c};
use safe_core::core_structs::{MDataKey as NativeMDataKey, MDataValue as NativeMDataValue};
use safe_core::{Client, FutureExt, MDataInfo as NativeMDataInfo};
use safe_nd::{
    EntryError, Error as SndError, MDataPermissionSet, MDataSeqEntryAction, MDataSeqValue,
    PublicKey, SeqMutableData,
};
use std::collections::BTreeMap;
use std::os::raw::c_void;

/// Special value that represents an empty permission set.
#[no_mangle]
pub static PERMISSIONS_EMPTY: MDataPermissionsHandle = NULL_OBJECT_HANDLE;

/// Special value that represents an empty entry set.
#[no_mangle]
pub static ENTRIES_EMPTY: MDataEntriesHandle = NULL_OBJECT_HANDLE;

/// Create new mutable data and put it on the network.
///
/// `permissions_h` is a handle to permissions to be set on the mutable data.
/// If `PERMISSIONS_EMPTY`, the permissions will be empty.
///
/// `entries_h` is a handle to entries for the mutable data.
/// If `ENTRIES_EMPTY`, the entries will be empty.
#[no_mangle]
pub unsafe extern "C" fn mdata_put(
    app: *const App,
    info: *const MDataInfo,
    permissions_h: MDataPermissionsHandle,
    entries_h: MDataEntriesHandle,
    user_data: *mut c_void,
    o_cb: extern "C" fn(user_data: *mut c_void, result: *const FfiResult),
) {
    catch_unwind_cb(user_data, o_cb, || {
        let info = NativeMDataInfo::clone_from_repr_c(info)?;
        let user_data = OpaqueCtx(user_data);

        (*app)
            .send(move |client, context| {
                let owner_key = client.owner_key();

                let permissions = if permissions_h == PERMISSIONS_EMPTY {
                    BTreeMap::<PublicKey, MDataPermissionSet>::default()
                } else {
                    try_cb!(
                        helper::get_permissions(context.object_cache(), permissions_h)
                            .map_err(Error::from),
                        user_data,
                        o_cb
                    )
                };

                let entries = if entries_h == ENTRIES_EMPTY {
                    BTreeMap::<Vec<u8>, MDataSeqValue>::default()
                } else {
                    try_cb!(
                        context
                            .object_cache()
                            .get_seq_mdata_entries(entries_h)
                            .map_err(Error::from),
                        user_data,
                        o_cb
                    )
                    .clone()
                };

                let data = SeqMutableData::new_with_data(
                    info.name(),
                    info.type_tag(),
                    entries,
                    permissions,
                    owner_key,
                );

                client
                    .put_seq_mutable_data(data)
                    .map_err(Error::from)
                    .then(move |result| {
                        call_result_cb!(result, user_data, o_cb);
                        Ok(())
                    })
                    .into_box()
                    .into()
            })
            .map_err(Error::from)
    })
}

/// Get version of the mutable data.
#[no_mangle]
pub unsafe extern "C" fn mdata_get_version(
    app: *const App,
    info: *const MDataInfo,
    user_data: *mut c_void,
    o_cb: extern "C" fn(user_data: *mut c_void, result: *const FfiResult, version: u64),
) {
    catch_unwind_cb(user_data, o_cb, || {
        let info = NativeMDataInfo::clone_from_repr_c(info)?;

        send(app, user_data, o_cb, move |client, _| {
            client.get_mdata_version(*info.address())
        })
    });
}

/// Get size of serialised mutable data.
#[no_mangle]
pub unsafe extern "C" fn mdata_serialised_size(
    app: *const App,
    info: *const MDataInfo,
    user_data: *mut c_void,
    o_cb: extern "C" fn(user_data: *mut c_void, result: *const FfiResult, serialised_size: u64),
) {
    catch_unwind_cb(user_data, o_cb, || {
        let info = NativeMDataInfo::clone_from_repr_c(info)?;

        send(app, user_data, o_cb, move |client, _| {
            client
                .get_seq_mdata(info.name(), info.type_tag())
                .map_err(AppError::from)
                .and_then(move |mdata| serialized_size(&mdata).map_err(AppError::from))
        })
    })
}

/// Get value at the given key from the mutable data.
///
/// Please notice that if a value is fetched from a private `MutableData`,
/// it's not automatically decrypted.
#[no_mangle]
pub unsafe extern "C" fn mdata_get_value(
    app: *const App,
    info: *const MDataInfo,
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
        let info = NativeMDataInfo::clone_from_repr_c(info)?;

        (*app).send(move |client, _| {
            client
                .get_seq_mdata_value(info.name(), info.type_tag(), key)
                .and_then(move |value| Ok((value.data, value.version)))
                .map(move |(content, version)| {
                    o_cb(
                        user_data.0,
                        FFI_RESULT_OK,
                        content.as_safe_ptr(),
                        content.len(),
                        version,
                    );
                })
                .map_err(Error::from)
                .map_err(move |err| {
                    call_result_cb!(Err::<(), _>(err), user_data, o_cb);
                })
                .into_box()
                .into()
        })
    })
}

/// Get a handle to the complete list of entries in the mutable data.
#[no_mangle]
pub unsafe extern "C" fn mdata_entries(
    app: *const App,
    info: *const MDataInfo,
    user_data: *mut c_void,
    o_cb: extern "C" fn(
        user_data: *mut c_void,
        result: *const FfiResult,
        entries_h: MDataEntriesHandle,
    ),
) {
    catch_unwind_cb(user_data, o_cb, || {
        let info = NativeMDataInfo::clone_from_repr_c(info)?;

        send(app, user_data, o_cb, move |client, context| {
            let context = context.clone();

            client
                .list_seq_mdata_entries(info.name(), info.type_tag())
                .map_err(AppError::from)
                .and_then(move |entries| {
                    Ok(context.object_cache().insert_seq_mdata_entries(entries))
                })
        })
    })
}

/// Get list of all keys in the mutable data.
#[no_mangle]
pub unsafe extern "C" fn mdata_list_keys(
    app: *const App,
    info: *const MDataInfo,
    user_data: *mut c_void,
    o_cb: extern "C" fn(
        user_data: *mut c_void,
        result: *const FfiResult,
        keys: *const MDataKey,
        keys_len: usize,
    ),
) {
    let user_data = OpaqueCtx(user_data);

    catch_unwind_cb(user_data, o_cb, || {
        let info = NativeMDataInfo::clone_from_repr_c(info)?;

        (*app).send(move |client, _context| {
            client
                .list_mdata_keys(*info.address())
                .map_err(Error::from)
                .then(move |result| {
                    match result {
                        Ok(keys) => {
                            let repr_c: Vec<_> = keys
                                .into_iter()
                                .map(|vec| NativeMDataKey::from_bytes(&vec))
                                .map(NativeMDataKey::into_repr_c)
                                .collect();

                            o_cb(
                                user_data.0,
                                FFI_RESULT_OK,
                                repr_c.as_safe_ptr(),
                                repr_c.len(),
                            )
                        }
                        Err(..) => {
                            call_result_cb!(result, user_data, o_cb);
                        }
                    }
                    Ok(())
                })
                .into_box()
                .into()
        })
    })
}

/// Get list of all values in the mutable data.
#[no_mangle]
pub unsafe extern "C" fn seq_mdata_list_values(
    app: *const App,
    info: *const MDataInfo,
    user_data: *mut c_void,
    o_cb: extern "C" fn(
        user_data: *mut c_void,
        result: *const FfiResult,
        values: *const MDataValue,
        values_len: usize,
    ),
) {
    let user_data = OpaqueCtx(user_data);

    catch_unwind_cb(user_data, o_cb, || {
        let info = NativeMDataInfo::clone_from_repr_c(info)?;

        (*app).send(move |client, _context| {
            client
                .list_seq_mdata_values(info.name(), info.type_tag())
                .map_err(Error::from)
                .then(move |result| {
                    match result {
                        Ok(values) => {
                            let repr_c: Vec<_> = values
                                .into_iter()
                                .map(NativeMDataValue::from_routing)
                                .map(NativeMDataValue::into_repr_c)
                                .collect();

                            o_cb(
                                user_data.0,
                                FFI_RESULT_OK,
                                repr_c.as_safe_ptr(),
                                repr_c.len(),
                            )
                        }
                        Err(..) => {
                            call_result_cb!(result, user_data, o_cb);
                        }
                    }
                    Ok(())
                })
                .into_box()
                .into()
        })
    })
}

/// Mutate entries of the mutable data.
#[no_mangle]
pub unsafe extern "C" fn mdata_mutate_entries(
    app: *const App,
    info: *const MDataInfo,
    actions_h: MDataEntryActionsHandle,
    user_data: *mut c_void,
    o_cb: extern "C" fn(user_data: *mut c_void, result: *const FfiResult),
) {
    catch_unwind_cb(user_data, o_cb, || {
        let user_data = OpaqueCtx(user_data);
        let info = NativeMDataInfo::clone_from_repr_c(info)?;

        (*app).send(move |client, context| {
            let c2 = client.clone();

            let mut actions = try_cb!(
                context
                    .object_cache()
                    .get_seq_mdata_entry_actions(actions_h)
                    .map_err(Error::from),
                user_data,
                o_cb
            )
            .clone();
            let name = info.name();
            let type_tag = info.type_tag();

            // Check if any of the versions are `GET_NEXT_VERSION`. If so, get the entries for the
            // mdata from the network, calculate the versions for all applicable keys, and update
            // `actions`.

            let mut get_version_for_keys = vec![];

            for (key, action) in actions.actions().iter() {
                match action {
                    MDataSeqEntryAction::Update(_) | MDataSeqEntryAction::Del(_) => {
                        if action.version() == GET_NEXT_VERSION {
                            get_version_for_keys.push(key.clone());
                        }
                    }
                    // `GET_NEXT_VERSION` is not possible for insert.
                    MDataSeqEntryAction::Ins(_) => (),
                }
            }

            if !get_version_for_keys.is_empty() {
                // To minimize network requests, get all entries at once instead of individual
                // values for each key.
                let fut = client
                    .list_seq_mdata_entries(name, type_tag)
                    .and_then(move |entries| {
                        let mut errors = BTreeMap::new();

                        for key in get_version_for_keys {
                            // Get the next version.
                            let version = if let Some(entry) = entries.get(&key) {
                                entry.version + 1
                            } else {
                                // The key doesn't exist, and insert is not compatible with
                                // `GET_NEXT_VERSION`.
                                let _ = errors.insert(key.clone(), EntryError::NoSuchEntry);
                                continue;
                            };

                            // Update the version on the action.
                            // Unwrap is okay as the key is guaranteed to exist.
                            let mut action = unwrap!(actions.actions().get(&key)).clone();
                            action.set_version(version);
                            actions.add_action(key.to_vec(), action);
                        }

                        // Return any errors that occurred.
                        if !errors.is_empty() {
                            return err!(SndError::InvalidEntryActions(errors));
                        }

                        ok!(actions)
                    });

                Either::A(fut)
            } else {
                // No changes to the actions necessary.
                Either::B(future::ok(actions))
            }
            .and_then(move |actions| c2.mutate_seq_mdata_entries(name, type_tag, actions))
            .map_err(Error::from)
            .then(move |result| {
                call_result_cb!(result, user_data, o_cb);
                Ok(())
            })
            .into_box()
            .into()
        })
    })
}

/// Get list of all permissions set on the mutable data.
#[no_mangle]
pub unsafe extern "C" fn mdata_list_permissions(
    app: *const App,
    info: *const MDataInfo,
    user_data: *mut c_void,
    o_cb: extern "C" fn(
        user_data: *mut c_void,
        result: *const FfiResult,
        perm_h: MDataPermissionsHandle,
    ),
) {
    catch_unwind_cb(user_data, o_cb, || {
        let info = NativeMDataInfo::clone_from_repr_c(info)?;

        send(app, user_data, o_cb, move |client, context| {
            let context = context.clone();

            client
                .list_mdata_permissions(*info.address())
                .map(move |perms| helper::insert_permissions(context.object_cache(), perms))
        })
    })
}

/// Get list of permissions set on the mutable data for the given user.
///
/// User is either handle to a signing key or `USER_ANYONE`.
#[no_mangle]
pub unsafe extern "C" fn mdata_list_user_permissions(
    app: *const App,
    info: *const MDataInfo,
    user_h: SignPubKeyHandle,
    user_data: *mut c_void,
    o_cb: extern "C" fn(
        user_data: *mut c_void,
        result: *const FfiResult,
        perm_set: *const PermissionSet,
    ),
) {
    catch_unwind_cb(user_data, o_cb, || {
        let user_data = OpaqueCtx(user_data);
        let info = NativeMDataInfo::clone_from_repr_c(info)?;

        (*app).send(move |client, context| {
            let user = try_cb!(
                helper::get_user(context.object_cache(), user_h),
                user_data,
                o_cb
            );

            client
                .list_mdata_user_permissions(*info.address(), user)
                .map(move |set| {
                    let perm_set = permission_set_into_repr_c(set);
                    o_cb(user_data.0, FFI_RESULT_OK, &perm_set);
                })
                .map_err(Error::from)
                .map_err(move |err| {
                    call_result_cb!(Err::<(), _>(err), user_data, o_cb);
                })
                .into_box()
                .into()
        })
    })
}

/// Set permissions set on the mutable data for the given user.
///
/// User is either handle to a signing key or `USER_ANYONE`.
#[no_mangle]
pub unsafe extern "C" fn mdata_set_user_permissions(
    app: *const App,
    info: *const MDataInfo,
    user_h: SignPubKeyHandle,
    permission_set: *const PermissionSet,
    version: u64,
    user_data: *mut c_void,
    o_cb: extern "C" fn(user_data: *mut c_void, result: *const FfiResult),
) {
    catch_unwind_cb(user_data, o_cb, || {
        let user_data = OpaqueCtx(user_data);
        let info = NativeMDataInfo::clone_from_repr_c(info)?;
        let permission_set = *permission_set;

        (*app).send(move |client, context| {
            let user = try_cb!(
                helper::get_user(context.object_cache(), user_h),
                user_data,
                o_cb
            );
            let permission_set = unwrap!(permission_set_clone_from_repr_c(permission_set));

            client
                .set_mdata_user_permissions(*info.address(), user, permission_set, version)
                .map_err(Error::from)
                .then(move |result| {
                    call_result_cb!(result, user_data, o_cb);
                    Ok(())
                })
                .into_box()
                .into()
        })
    })
}

/// Delete permissions set on the mutable data for the given user.
///
/// User is either handle to a signing key or `USER_ANYONE`.
#[no_mangle]
pub unsafe extern "C" fn mdata_del_user_permissions(
    app: *const App,
    info: *const MDataInfo,
    user_h: SignPubKeyHandle,
    version: u64,
    user_data: *mut c_void,
    o_cb: extern "C" fn(user_data: *mut c_void, result: *const FfiResult),
) {
    catch_unwind_cb(user_data, o_cb, || {
        let user_data = OpaqueCtx(user_data);
        let info = NativeMDataInfo::clone_from_repr_c(info)?;

        (*app).send(move |client, context| {
            let user = try_cb!(
                helper::get_user(context.object_cache(), user_h),
                user_data,
                o_cb
            );

            client
                .del_mdata_user_permissions(*info.address(), user, version)
                .map_err(Error::from)
                .then(move |result| {
                    call_result_cb!(result, user_data, o_cb);
                    Ok(())
                })
                .into_box()
                .into()
        })
    })
}
