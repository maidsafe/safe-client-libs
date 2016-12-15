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

use app::errors::AppError;
use app::object_cache::{MDataPermissionsHandle, ObjectCache, SignKeyHandle};
use core::MDataInfo;
use routing::{EntryAction, PermissionSet, User, Value};
use std::collections::{BTreeMap, BTreeSet};

// Retrieve the sign key corresponding to the handle from the object cache and wrap it
// in `User`. If the handle is 0, return `User::Anyone`.
pub fn get_user(object_cache: &ObjectCache, handle: SignKeyHandle) -> Result<User, AppError> {
    let user = if handle != 0 {
        let sign_key = object_cache.get_sign_key(handle)?;
        User::Key(*sign_key)
    } else {
        User::Anyone
    };

    Ok(user)
}

// Insert the permissions into the object cache.
pub fn insert_permissions(object_cache: &ObjectCache,
                          permissions: BTreeMap<User, PermissionSet>)
                          -> MDataPermissionsHandle {
    let permissions = permissions.into_iter()
        .map(|(user, permission_set)| {
            let user_h = match user {
                User::Anyone => 0,
                User::Key(key) => object_cache.insert_sign_key(key),
            };
            let permission_set_h = object_cache.insert_mdata_permission_set(permission_set);

            (user_h, permission_set_h)
        })
        .collect();

    object_cache.insert_mdata_permissions(permissions)
}

// Retrieve permissions from the object cache.
pub fn get_permissions(object_cache: &ObjectCache,
                       handle: MDataPermissionsHandle)
                       -> Result<BTreeMap<User, PermissionSet>, AppError> {
    let input = object_cache.get_mdata_permissions(handle)?.clone();
    let mut output = BTreeMap::new();

    for (user_h, permission_set_h) in input {
        let user = get_user(object_cache, user_h)?;
        let permission_set = *object_cache.get_mdata_permission_set(permission_set_h)?;

        let _ = output.insert(user, permission_set);
    }

    Ok(output)
}

// Encrypt the entries (both keys and values) using the `MDataInfo`.
pub fn encrypt_entries(entries: &BTreeMap<Vec<u8>, Value>,
                       info: &MDataInfo)
                       -> Result<BTreeMap<Vec<u8>, Value>, AppError> {
    let mut output = BTreeMap::new();

    for (key, value) in entries {
        let encrypted_key = info.enc_entry_key(key)?;
        let encrypted_value = encrypt_value(value, info)?;
        let _ = output.insert(encrypted_key, encrypted_value);
    }

    Ok(output)
}

// Encrypt entry actions using the `MDataInfo`. The effect of this is that the entries
// mutated by the encrypted actions will end up encrypted using the `MDataInfo`.
pub fn encrypt_entry_actions(actions: &BTreeMap<Vec<u8>, EntryAction>,
                             info: &MDataInfo)
                             -> Result<BTreeMap<Vec<u8>, EntryAction>, AppError> {
    let mut output = BTreeMap::new();

    for (key, action) in actions {
        let encrypted_key = info.enc_entry_key(key)?;
        let encrypted_action = match *action {
            EntryAction::Ins(ref value) => EntryAction::Ins(encrypt_value(value, info)?),
            EntryAction::Update(ref value) => EntryAction::Update(encrypt_value(value, info)?),
            EntryAction::Del(version) => EntryAction::Del(version),
        };

        let _ = output.insert(encrypted_key, encrypted_action);
    }

    Ok(output)
}

// Decrypt entries using the `MDataInfo`.
pub fn decrypt_entries(entries: &BTreeMap<Vec<u8>, Value>,
                       info: &MDataInfo)
                       -> Result<BTreeMap<Vec<u8>, Value>, AppError> {
    let mut output = BTreeMap::new();

    for (key, value) in entries {
        let decrypted_key = info.decrypt(key)?;
        let decrypted_value = decrypt_value(value, info)?;

        let _ = output.insert(decrypted_key, decrypted_value);
    }

    Ok(output)
}

// Decrypt all keys using the `MDataInfo`.
pub fn decrypt_keys(keys: &BTreeSet<Vec<u8>>,
                    info: &MDataInfo)
                    -> Result<BTreeSet<Vec<u8>>, AppError> {
    let mut output = BTreeSet::new();

    for key in keys {
        let _ = output.insert(info.decrypt(key)?);
    }

    Ok(output)
}

// Decrypt all values using the `MDataInfo`.
pub fn decrypt_values(values: &[Value], info: &MDataInfo) -> Result<Vec<Value>, AppError> {
    let mut output = Vec::with_capacity(values.len());

    for value in values {
        output.push(decrypt_value(value, info)?);
    }

    Ok(output)
}

fn encrypt_value(value: &Value, info: &MDataInfo) -> Result<Value, AppError> {
    Ok(Value {
        content: info.enc_entry_value(&value.content)?,
        entry_version: value.entry_version,
    })
}

fn decrypt_value(value: &Value, info: &MDataInfo) -> Result<Value, AppError> {
    Ok(Value {
        content: info.decrypt(&value.content)?,
        entry_version: value.entry_version,
    })
}
