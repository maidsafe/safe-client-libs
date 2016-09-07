// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

// TODO Remove

use ffi::errors::FfiError;
use ffi::low_level_api::{AppendableDataHandle, CipherOptHandle, DataIdHandle, EncryptKeyHandle,
                         ObjectHandle, SelfEncryptorReaderHandle, SelfEncryptorWriterHandle,
                         SignKeyHandle, StructDataHandle};
use ffi::low_level_api::appendable_data::AppendableData;
use ffi::low_level_api::cipher_opt::CipherOpt;
use ffi::low_level_api::immut_data::{SelfEncryptorReaderWrapper, SelfEncryptorWriterWrapper};
use lru_cache::LruCache;
use routing::{DataIdentifier, StructuredData};
use rust_sodium::crypto::{box_, sign};
use std::sync::{Mutex, ONCE_INIT, Once};
use std::u64;

const DEFAULT_CAPACITY: usize = 100;

pub fn object_cache() -> &'static Mutex<ObjectCache> {
    static mut OBJECT_CACHE: *const Mutex<ObjectCache> = 0 as *const Mutex<ObjectCache>;
    static ONCE: Once = ONCE_INIT;

    unsafe {
        ONCE.call_once(|| OBJECT_CACHE = Box::into_raw(Box::new(Default::default())));
        &*OBJECT_CACHE
    }
}

// TODO Instead of this make each field a Mutex - that way operation on one handle does not block
// operations on others.
pub struct ObjectCache {
    new_handle: ObjectHandle,
    pub struct_data: LruCache<StructDataHandle, StructuredData>,
    pub data_id: LruCache<DataIdHandle, DataIdentifier>,
    pub appendable_data: LruCache<AppendableDataHandle, AppendableData>,
    pub se_reader: LruCache<SelfEncryptorReaderHandle, SelfEncryptorReaderWrapper>,
    pub se_writer: LruCache<SelfEncryptorWriterHandle, SelfEncryptorWriterWrapper>,
    pub cipher_opt: LruCache<CipherOptHandle, CipherOpt>,
    pub encrypt_key: LruCache<EncryptKeyHandle, box_::PublicKey>,
    pub sign_key: LruCache<SignKeyHandle, sign::PublicKey>,
}

impl ObjectCache {
    pub fn new_handle(&mut self) -> ObjectHandle {
        self.new_handle = self.new_handle.wrapping_add(1);
        self.new_handle
    }

    #[allow(unused)]
    pub fn reset(&mut self) {
        self.new_handle = u64::MAX;

        self.struct_data.clear();
        self.data_id.clear();
        self.appendable_data.clear();
        self.se_reader.clear();
        self.se_writer.clear();
        self.cipher_opt.clear();
        self.encrypt_key.clear();
        self.sign_key.clear();
    }

    pub fn insert_appendable_data(&mut self, data: AppendableData) -> AppendableDataHandle {
        let handle = self.new_handle();
        let _ = self.appendable_data.insert(handle, data);

        handle
    }

    pub fn get_appendable_data(&mut self,
                               handle: AppendableDataHandle)
                               -> Result<&mut AppendableData, FfiError> {
        self.appendable_data
            .get_mut(&handle)
            .ok_or(FfiError::InvalidAppendableDataHandle)
    }

    pub fn get_data_id(&mut self, handle: DataIdHandle)
                       -> Result<&mut DataIdentifier, FfiError> {

        self.data_id.get_mut(&handle).ok_or(FfiError::InvalidDataIdHandle)
    }

    pub fn get_encrypt_key(&mut self,
                           handle: EncryptKeyHandle)
                        -> Result<&mut box_::PublicKey, FfiError> {
        self.encrypt_key.get_mut(&handle).ok_or(FfiError::InvalidEncryptKeyHandle)
    }

    pub fn get_sign_key(&mut self,
                        handle: SignKeyHandle)
                        -> Result<&mut sign::PublicKey, FfiError> {
        self.sign_key.get_mut(&handle).ok_or(FfiError::InvalidSignKeyHandle)
    }
}

impl Default for ObjectCache {
    fn default() -> Self {
        ObjectCache {
            new_handle: u64::MAX,
            struct_data: LruCache::new(DEFAULT_CAPACITY),
            data_id: LruCache::new(DEFAULT_CAPACITY),
            appendable_data: LruCache::new(DEFAULT_CAPACITY),
            se_reader: LruCache::new(DEFAULT_CAPACITY),
            se_writer: LruCache::new(DEFAULT_CAPACITY),
            cipher_opt: LruCache::new(DEFAULT_CAPACITY),
            encrypt_key: LruCache::new(DEFAULT_CAPACITY),
            sign_key: LruCache::new(DEFAULT_CAPACITY),
        }
    }
}
