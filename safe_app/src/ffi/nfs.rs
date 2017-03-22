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
use ffi_utils::{OpaqueCtx, ReprC, catch_unwind_cb, from_c_str};
use futures::Future;
use object_cache::MDataInfoHandle;
use safe_core::FutureExt;
use safe_core::nfs::File as NativeFile;
use safe_core::nfs::ffi::File;
use safe_core::nfs::file_helper;
use std::os::raw::{c_char, c_void};
use std::ptr;

/// Retrieve file with the given name, and its version, from the directory.
#[no_mangle]
pub unsafe extern "C" fn file_fetch(app: *const App,
                                    parent_h: MDataInfoHandle,
                                    file_name: *const c_char,
                                    user_data: *mut c_void,
                                    o_cb: extern "C" fn(*mut c_void, i32, *const File, u64)) {
    catch_unwind_cb(user_data, o_cb, || {
        let file_name = from_c_str(file_name)?;
        let user_data = OpaqueCtx(user_data);

        (*app).send(move |client, context| {
            let parent = try_cb!(context.object_cache().get_mdata_info(parent_h),
                                 user_data.0,
                                 o_cb);

            file_helper::fetch(client.clone(), parent.clone(), file_name)
                .map(move |(version, file)| {
                         let ffi_file = file.into_repr_c();
                         o_cb(user_data.0, 0, &ffi_file, version)
                     })
                .map_err(AppError::from)
                .map_err(move |err| o_cb(user_data.0, ffi_error_code!(err), ptr::null(), 0))
                .into_box()
                .into()
        })
    })
}

/// Insert the file into the parent directory.
#[no_mangle]
pub unsafe extern "C" fn file_insert(app: *const App,
                                     parent_h: MDataInfoHandle,
                                     file_name: *const c_char,
                                     file: *const File,
                                     user_data: *mut c_void,
                                     o_cb: extern "C" fn(*mut c_void, i32)) {
    catch_unwind_cb(user_data, o_cb, || {
        let file = NativeFile::clone_from_repr_c(file)?;
        let file_name = from_c_str(file_name)?;

        send_with_mdata_info(app, parent_h, user_data, o_cb, move |client, _, parent| {
            file_helper::insert(client.clone(), parent.clone(), file_name, &file)
        })
    })
}

/// Update (replace) file at the given name with the new file.
/// If `version` is 0, the correct version is obtained automatically.
#[no_mangle]
pub unsafe extern "C" fn file_update(app: *const App,
                                     parent_h: MDataInfoHandle,
                                     file_name: *const c_char,
                                     file: *const File,
                                     version: u64,
                                     user_data: *mut c_void,
                                     o_cb: extern "C" fn(*mut c_void, i32)) {
    catch_unwind_cb(user_data, o_cb, || {
        let file = NativeFile::clone_from_repr_c(file)?;
        let file_name = from_c_str(file_name)?;

        send_with_mdata_info(app, parent_h, user_data, o_cb, move |client, _, parent| {
            file_helper::update(client.clone(), parent.clone(), file_name, &file, version)
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use App;
    use errors::AppError;
    use ffi::cipher_opt::CipherOpt;
    use ffi::immutable_data::*;
    use ffi_utils::ErrorCode;
    use ffi_utils::test_utils::{call_0, call_1, call_2, call_vec_u8};
    use futures::Future;
    use object_cache::CipherOptHandle;
    use routing::{XOR_NAME_LEN, XorName};
    use safe_core::ipc::Permission;
    use safe_core::nfs::File as NativeFile;
    use safe_core::nfs::NfsError;
    use std::collections::HashMap;
    use std::ffi::CString;
    use test_utils::{create_app_with_access, run, run_now};

    #[test]
    fn basics() {
        let mut container_permissions = HashMap::new();
        let _ = container_permissions.insert("_videos".to_string(),
                                             btree_set![Permission::Read,
                                                        Permission::Insert,
                                                        Permission::Update,
                                                        Permission::Delete]);

        let app = create_app_with_access(container_permissions);

        let container_info_h = run(&app, move |client, context| {
            let context = context.clone();

            context.get_container_mdata_info(client, "_videos")
                .map(move |info| context.object_cache().insert_mdata_info(info))
        });

        let file_name0 = "file0.txt";
        let ffi_file_name0 = unwrap!(CString::new(file_name0));

        // fetching non-existing file fails.
        let res: Result<(NativeFile, u64), i32> = unsafe {
            call_2(|ud, cb| file_fetch(&app, container_info_h, ffi_file_name0.as_ptr(), ud, cb))
        };

        match res {
            Err(code) if code == AppError::from(NfsError::FileNotFound).error_code() => (),
            Err(x) => panic!("Unexpected: {:?}", x),
            Ok(_) => panic!("Unexpected success"),
        }

        // Create empty file.
        let user_metadata = b"metadata".to_vec();
        let file = NativeFile::new(user_metadata.clone());
        let ffi_file = file.into_repr_c();

        unsafe {
            unwrap!(call_0(|ud, cb| {
                file_insert(&app,
                            container_info_h,
                            ffi_file_name0.as_ptr(),
                            &ffi_file,
                            ud,
                            cb)
            }))
        }

        // Fetch it back.
        let (retrieved_file, retrieved_version): (NativeFile, u64) = unsafe {
            unwrap!(call_2(|ud, cb| {
                               file_fetch(&app, container_info_h, ffi_file_name0.as_ptr(), ud, cb)
                           }))
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
        let ffi_file = file.into_repr_c();

        let file_name1 = "file1.txt";
        let ffi_file_name1 = unwrap!(CString::new(file_name1));

        unsafe {
            unwrap!(call_0(|ud, cb| {
                file_insert(&app,
                            container_info_h,
                            ffi_file_name1.as_ptr(),
                            &ffi_file,
                            ud,
                            cb)
            }))
        }

        // Fetch it back.
        let (file, _version): (NativeFile, u64) = {
            unsafe {
                unwrap!(call_2(|ud, cb| {
                    file_fetch(&app, container_info_h, ffi_file_name1.as_ptr(), ud, cb)
                }))
            }
        };

        // Read the content.
        let retrieved_content = unsafe { get_file_content(&app, file.data_map_name().0) };
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
            idata_fetch_self_encryptor(app, &name, ud, cb)
        }));
        let size = unwrap!(call_1(|ud, cb| {
            idata_size(app, reader_h, ud, cb)
        }));

        unwrap!(call_vec_u8(|ud, cb| {
            idata_read_from_self_encryptor(app, reader_h, 0, size, ud, cb)
        }))
    }
}
