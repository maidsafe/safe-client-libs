// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

//! This module implements storage (cache) for objects that have to be passed
//! across FFI boundaries.

use super::errors::AppError;
use crate::cipher_opt::CipherOpt;
use crate::client::AppClient;
use crate::ffi::nfs::FileContext;
use crate::ffi::object_cache::*;
use routing::{EntryAction, PermissionSet, User, Value};
use rust_sodium::crypto::{box_, sign};
use safe_core::crypto::{shared_box, shared_sign};
use safe_core::SelfEncryptionStorage;
use self_encryption::{SelfEncryptor, SequentialEncryptor};
use std::cell::{Cell, RefCell, RefMut};
use std::collections::{BTreeMap, HashMap};

/// Contains session object cache
pub struct ObjectCache {
    handle_gen: HandleGenerator,
    cipher_opt: Store<CipherOpt>,
    encrypt_key: Store<box_::PublicKey>,
    secret_key: Store<shared_box::SecretKey>,
    mdata_entries: Store<BTreeMap<Vec<u8>, Value>>,
    mdata_entry_actions: Store<BTreeMap<Vec<u8>, EntryAction>>,
    mdata_permissions: Store<BTreeMap<User, PermissionSet>>,
    se_reader: Store<SelfEncryptor<SelfEncryptionStorage<AppClient>>>,
    se_writer: Store<SequentialEncryptor<SelfEncryptionStorage<AppClient>>>,
    pub_sign_key: Store<sign::PublicKey>,
    sec_sign_key: Store<shared_sign::SecretKey>,
    file: Store<FileContext>,
}

impl ObjectCache {
    /// Construct object cache.
    pub fn new() -> Self {
        ObjectCache {
            handle_gen: HandleGenerator::new(),
            cipher_opt: Store::new(),
            encrypt_key: Store::new(),
            secret_key: Store::new(),
            mdata_entries: Store::new(),
            mdata_entry_actions: Store::new(),
            mdata_permissions: Store::new(),
            se_reader: Store::new(),
            se_writer: Store::new(),
            pub_sign_key: Store::new(),
            sec_sign_key: Store::new(),
            file: Store::new(),
        }
    }

    /// Reset the object cache by removing all objects stored in it.
    pub fn reset(&self) {
        self.handle_gen.reset();
        self.cipher_opt.clear();
        self.encrypt_key.clear();
        self.secret_key.clear();
        self.mdata_entries.clear();
        self.mdata_entry_actions.clear();
        self.mdata_permissions.clear();
        self.se_reader.clear();
        self.se_writer.clear();
        self.pub_sign_key.clear();
        self.sec_sign_key.clear();
        self.file.clear();
    }
}

macro_rules! impl_cache {
    ($name:ident, $ty:ty, $handle:ty, $error:ident, $get:ident, $insert:ident, $remove:ident) => {
        impl ObjectCache {
            /// Insert object into the object cache, returning a new handle to it.
            pub fn $insert(&self, value: $ty) -> $handle {
                let handle = self.handle_gen.gen();
                self.$name.insert(handle, value);
                handle
            }

            /// Retrieve object from the object cache, returning mutable reference to it.
            pub fn $get(&self, handle: $handle) -> Result<RefMut<$ty>, AppError> {
                self.$name.get(handle).ok_or(AppError::$error)
            }

            /// Remove object from the object cache and return it.
            pub fn $remove(&self, handle: $handle) -> Result<$ty, AppError> {
                self.$name.remove(handle).ok_or(AppError::$error)
            }
        }
    };
}

impl_cache!(
    cipher_opt,
    CipherOpt,
    CipherOptHandle,
    InvalidCipherOptHandle,
    get_cipher_opt,
    insert_cipher_opt,
    remove_cipher_opt
);
impl_cache!(
    encrypt_key,
    box_::PublicKey,
    EncryptPubKeyHandle,
    InvalidEncryptPubKeyHandle,
    get_encrypt_key,
    insert_encrypt_key,
    remove_encrypt_key
);
impl_cache!(
    secret_key,
    shared_box::SecretKey,
    EncryptSecKeyHandle,
    InvalidEncryptSecKeyHandle,
    get_secret_key,
    insert_secret_key,
    remove_secret_key
);
impl_cache!(
    mdata_entries,
    BTreeMap<Vec<u8>, Value>,
    MDataEntriesHandle,
    InvalidMDataEntriesHandle,
    get_mdata_entries,
    insert_mdata_entries,
    remove_mdata_entries
);
impl_cache!(
    mdata_entry_actions,
    BTreeMap<Vec<u8>, EntryAction>,
    MDataEntryActionsHandle,
    InvalidMDataEntryActionsHandle,
    get_mdata_entry_actions,
    insert_mdata_entry_actions,
    remove_mdata_entry_actions
);
impl_cache!(mdata_permissions,
            BTreeMap<User, PermissionSet>,
            MDataPermissionsHandle,
            InvalidMDataPermissionsHandle,
            get_mdata_permissions,
            insert_mdata_permissions,
            remove_mdata_permissions);
impl_cache!(
    se_reader,
    SelfEncryptor<SelfEncryptionStorage<AppClient>>,
    SelfEncryptorReaderHandle,
    InvalidSelfEncryptorHandle,
    get_se_reader,
    insert_se_reader,
    remove_se_reader
);
impl_cache!(
    se_writer,
    SequentialEncryptor<SelfEncryptionStorage<AppClient>>,
    SelfEncryptorWriterHandle,
    InvalidSelfEncryptorHandle,
    get_se_writer,
    insert_se_writer,
    remove_se_writer
);
impl_cache!(
    pub_sign_key,
    sign::PublicKey,
    SignPubKeyHandle,
    InvalidSignPubKeyHandle,
    get_pub_sign_key,
    insert_pub_sign_key,
    remove_pub_sign_key
);
impl_cache!(
    sec_sign_key,
    shared_sign::SecretKey,
    SignSecKeyHandle,
    InvalidSignSecKeyHandle,
    get_sec_sign_key,
    insert_sec_sign_key,
    remove_sec_sign_key
);
impl_cache!(
    file,
    FileContext,
    FileContextHandle,
    InvalidFileContextHandle,
    get_file,
    insert_file,
    remove_file
);

impl Default for ObjectCache {
    fn default() -> Self {
        Self::new()
    }
}

// Generator of unique object handles.
struct HandleGenerator(Cell<ObjectHandle>);

impl HandleGenerator {
    fn new() -> Self {
        HandleGenerator(Cell::new(NULL_OBJECT_HANDLE))
    }

    fn gen(&self) -> ObjectHandle {
        let value = self.0.get().wrapping_add(1);
        self.0.set(value);
        value
    }

    fn reset(&self) {
        self.0.set(NULL_OBJECT_HANDLE)
    }
}

struct Store<V> {
    inner: RefCell<HashMap<ObjectHandle, V>>,
}

impl<V> Store<V> {
    fn new() -> Self {
        Store {
            inner: RefCell::new(HashMap::new()),
        }
    }

    fn get(&self, handle: ObjectHandle) -> Option<RefMut<V>> {
        // TODO: find a way to avoid double lookup here.
        let mut inner = self.inner.borrow_mut();
        if inner.get_mut(&handle).is_some() {
            Some(RefMut::map(inner, |i| unwrap!(i.get_mut(&handle))))
        } else {
            None
        }
    }

    fn insert(&self, handle: ObjectHandle, value: V) {
        let _ = self.inner.borrow_mut().insert(handle, value);
    }

    fn remove(&self, handle: ObjectHandle) -> Option<V> {
        self.inner.borrow_mut().remove(&handle)
    }

    fn clear(&self) {
        self.inner.borrow_mut().clear()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rust_sodium::crypto::sign;

    // Test resetting the object cache.
    #[test]
    fn reset() {
        let object_cache = ObjectCache::new();
        let (pk, _) = sign::gen_keypair();

        let handle = object_cache.insert_pub_sign_key(pk);
        assert!(object_cache.get_pub_sign_key(handle).is_ok());

        object_cache.reset();
        assert!(object_cache.get_pub_sign_key(handle).is_err());
    }
}
