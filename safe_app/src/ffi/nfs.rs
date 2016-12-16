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

use App;
use errors::AppError;
use ffi::helper::send_with_mdata_info;
use ffi_utils::{FfiString, catch_unwind_cb, u8_vec_to_ptr};
use ffi_utils::callback::CallbackArgs;
use futures::Future;
use object_cache::MDataInfoHandle;
use routing::{XOR_NAME_LEN, XorName};
use safe_core::nfs::File as NativeFile;
use safe_core::nfs::file_helper;
use std::os::raw::c_void;
use std::ptr;
use std::slice;
use time;
use time::Tm;

/// FFI-wrapper for `File`.
#[repr(C)]
pub struct File {
    /// File size in bytes.
    pub size: u64,
    /// Creation time.
    pub created: Tm,
    /// Modification time.
    pub modified: Tm,
    /// Pointer to the user metadata.
    pub user_metadata_ptr: *mut u8,
    /// Size of the user metadata.
    pub user_metadata_len: usize,
    /// Capacity of the user metadata (internal field).
    pub user_metadata_cap: usize,
    /// Name of the `ImmutableData` containing the content of this file.
    pub data_map_name: [u8; XOR_NAME_LEN],
}

impl File {
    /// Construct FFI wrapper for the native rust `File`, consuming the file.
    pub fn from_native(file: NativeFile) -> Self {
        // TODO: move the metadata, not clone.
        let user_metadata = file.user_metadata().to_vec();
        let (user_metadata_ptr, user_metadata_len, user_metadata_cap) =
            u8_vec_to_ptr(user_metadata);

        File {
            size: file.size(),
            created: *file.created_time(),
            modified: *file.modified_time(),
            user_metadata_ptr: user_metadata_ptr,
            user_metadata_len: user_metadata_len,
            user_metadata_cap: user_metadata_cap,
            data_map_name: file.data_map_name().0,
        }
    }

    /// Convert to the native rust equivalent, consuming self.
    pub unsafe fn into_native(self) -> NativeFile {
        let user_metadata = Vec::from_raw_parts(self.user_metadata_ptr,
                                                self.user_metadata_len,
                                                self.user_metadata_cap);

        let mut file = NativeFile::new(user_metadata);
        file.set_size(self.size);
        file.set_created_time(self.created);
        file.set_modified_time(self.modified);
        file.set_data_map_name(XorName(self.data_map_name));
        file
    }

    /// Convert to the native rust equivalent by cloning the internal data, preserving self.
    pub unsafe fn to_native(&self) -> NativeFile {
        let user_metadata = slice::from_raw_parts(self.user_metadata_ptr, self.user_metadata_len)
            .to_vec();

        let mut file = NativeFile::new(user_metadata);
        file.set_size(self.size);
        file.set_created_time(self.created);
        file.set_modified_time(self.modified);
        file.set_data_map_name(XorName(self.data_map_name));
        file
    }
}

impl CallbackArgs for File {
    fn default() -> Self {
        let tm = time::now_utc();

        File {
            size: 0,
            created: tm,
            modified: tm,
            user_metadata_ptr: ptr::null_mut(),
            user_metadata_len: 0,
            user_metadata_cap: 0,
            data_map_name: Default::default(),
        }
    }
}

/// Free the file from memory.
#[no_mangle]
pub unsafe extern "C" fn file_free(file: File) {
    let _ = file.into_native();
}

/// Retrieve file with the given name, and its version, from the directory.
#[no_mangle]
pub unsafe extern "C" fn file_fetch(app: *const App,
                                    parent_h: MDataInfoHandle,
                                    file_name: FfiString,
                                    user_data: *mut c_void,
                                    o_cb: extern "C" fn(*mut c_void, i32, File, u64)) {
    catch_unwind_cb(user_data, o_cb, || {
        let file_name = file_name.to_string()?;

        send_with_mdata_info(app, parent_h, user_data, o_cb, move |client, _, parent| {
            file_helper::fetch(client.clone(), parent.clone(), file_name)
                .map(|(version, file)| (File::from_native(file), version))
                .map_err(AppError::from)
        })
    })
}

/// Insert the file into the parent directory.
#[no_mangle]
pub unsafe extern "C" fn file_insert(app: *const App,
                                     parent_h: MDataInfoHandle,
                                     file_name: FfiString,
                                     file: File,
                                     user_data: *mut c_void,
                                     o_cb: extern "C" fn(*mut c_void, i32)) {
    catch_unwind_cb(user_data, o_cb, || {
        let file = file.to_native();
        let file_name = file_name.to_string()?;

        send_with_mdata_info(app, parent_h, user_data, o_cb, move |client, _, parent| {
            file_helper::insert(client.clone(), parent.clone(), file_name, file)
        })
    })
}

/// Update (replace) file at the given name with the new file.
/// If `version` is 0, the correct version is obtained automatically.
#[no_mangle]
pub unsafe extern "C" fn file_update(app: *const App,
                                     parent_h: MDataInfoHandle,
                                     file_name: FfiString,
                                     file: File,
                                     version: u64,
                                     user_data: *mut c_void,
                                     o_cb: extern "C" fn(*mut c_void, i32)) {
    catch_unwind_cb(user_data, o_cb, || {
        let file = file.to_native();
        let file_name = file_name.to_string()?;

        send_with_mdata_info(app, parent_h, user_data, o_cb, move |client, _, parent| {
            file_helper::update(client.clone(), parent.clone(), file_name, file, version)
        })
    })
}

#[cfg(test)]
mod tests {
    use App;
    use errors::AppError;
    use ffi::cipher_opt::CipherOpt;
    use ffi::immutable_data::*;
    use ffi_utils::{ErrorCode, FfiString};
    use ffi_utils::test_utils::{call_0, call_1, call_2, call_3};
    use object_cache::CipherOptHandle;
    use routing::{XOR_NAME_LEN, XorName};
    use safe_core::{DIR_TAG, MDataInfo};
    use safe_core::ipc::Permission;
    use safe_core::nfs::File as NativeFile;
    use safe_core::nfs::NfsError;
    use std::collections::HashMap;
    use super::*;
    use test_utils::{create_app_with_access, run_now};

    #[test]
    fn basics() {
        let container_info = unwrap!(MDataInfo::random_private(DIR_TAG));

        let mut container_permissions = HashMap::new();
        let _ = container_permissions.insert("_test".to_string(),
                                             (container_info.clone(),
                                              btree_set![Permission::Read,
                                                         Permission::Insert,
                                                         Permission::Update,
                                                         Permission::Delete]));

        let app = create_app_with_access(container_permissions, true);

        let container_info_h = run_now(&app, move |_, context| {
            context.object_cache().insert_mdata_info(container_info)
        });

        let file_name0 = "file0.txt";
        let ffi_file_name0 = FfiString::from_string(file_name0);

        // fetching non-existing file fails.
        let res =
            unsafe { call_2(|ud, cb| file_fetch(&app, container_info_h, ffi_file_name0, ud, cb)) };

        match res {
            Err(code) if code == AppError::from(NfsError::FileNotFound).error_code() => (),
            Err(x) => panic!("Unexpected: {:?}", x),
            Ok(_) => panic!("Unexpected success"),
        }

        // Create empty file.
        let user_metadata = b"metadata".to_vec();
        let file = NativeFile::new(user_metadata.clone());
        let ffi_file = File::from_native(file);

        unsafe {
            unwrap!(call_0(|ud, cb| {
                file_insert(&app, container_info_h, ffi_file_name0, ffi_file, ud, cb)
            }))
        }

        // Fetch it back.
        let (retrieved_file, retrieved_version) = {
            unsafe {
                let (file, version) = unwrap!(call_2(|ud, cb| {
                    file_fetch(&app, container_info_h, ffi_file_name0, ud, cb)
                }));
                (file.into_native(), version)
            }
        };
        assert_eq!(retrieved_file.user_metadata(), &user_metadata[..]);
        assert_eq!(retrieved_file.size(), 0);
        assert_eq!(retrieved_version, 0);

        // Create non-empty file.
        let cipher_opt_h = run_now(&app, |_, context| {
            context.object_cache().insert_cipher_opt(CipherOpt::PlainText)
        });

        let content = b"hello world";
        let content_name = unsafe { put_file_content(&app, content, cipher_opt_h) };

        let mut file = NativeFile::new(Vec::new());
        file.set_data_map_name(content_name);
        let ffi_file = File::from_native(file);

        let file_name1 = "file1.txt";
        let ffi_file_name1 = FfiString::from_string(file_name1);

        unsafe {
            unwrap!(call_0(|ud, cb| {
                file_insert(&app, container_info_h, ffi_file_name1, ffi_file, ud, cb)
            }))
        }

        // Fetch it back.
        let (ffi_file, _) = {
            unsafe {
                unwrap!(call_2(|ud, cb| file_fetch(&app, container_info_h, ffi_file_name1, ud, cb)))
            }
        };

        // Read the content.
        let retrieved_content = unsafe { get_file_content(&app, ffi_file.data_map_name) };
        assert_eq!(retrieved_content, content);
    }

    // FIXME: rustfmt is choking on this.
    #[cfg_attr(rustfmt, rustfmt_skip)]
    unsafe fn put_file_content(app: &App,
                               content: &[u8],
                               cipher_opt_h: CipherOptHandle)
                               -> XorName {
        let writer_h = unwrap!(call_1(|ud, cb| idata_new_self_encryptor(app, ud, cb)));
        unwrap!(call_0(|ud, cb| {
            idata_write_to_self_encryptor(app, writer_h, content.as_ptr(), content.len(), ud, cb)
        }));
        let name = unwrap!(call_1(|ud, cb| {
            idata_close_self_encryptor(app, writer_h, cipher_opt_h, ud, cb)
        }));

        XorName(name)
    }

    // FIXME: rustfmt is choking on this.
    #[cfg_attr(rustfmt, rustfmt_skip)]
    unsafe fn get_file_content(app: &App, name: [u8; XOR_NAME_LEN]) -> Vec<u8> {
        let reader_h = unwrap!(call_1(|ud, cb| {
            idata_fetch_self_encryptor(app, name, ud, cb)
        }));
        let size = unwrap!(call_1(|ud, cb| {
            idata_size(app, reader_h, ud, cb)
        }));

        let (ptr, len, cap) = unwrap!(call_3(|ud, cb| {
            idata_read_from_self_encryptor(app, reader_h, 0, size, ud, cb)
        }));

        Vec::from_raw_parts(ptr, len, cap)
    }
}
