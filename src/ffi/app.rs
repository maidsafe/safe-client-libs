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

//! Structure representing application registered with the launcher + set of
//! FFI operations on it.

// TODO(Spandan) - Run through this and make interfaces efficient (return
// references instead of copies etc.) and uniform (i.e. not use get_ prefix for
// mem functions.

use core::{Client, FutureExt};
use ffi::{AppHandle, FfiError, FfiFuture, OpaqueCtx, Session, helper, launcher_config};
use futures::{self, Future};
use nfs::DirId;
use rust_sodium::crypto::{box_, secretbox};
use std::os::raw::c_void;

/// Represents an application connected to the launcher.
#[derive(RustcEncodable, RustcDecodable, Debug, Clone)]
pub enum App {
    /// Unregistered application
    Unregistered,
    /// Authorised application
    Registered {
        /// Application directory
        app_dir_id: DirId,
        /// Defines whether the application has access to SAFE Drive
        safe_drive_access: bool,
        /// Asymmetric encryption keys of the app
        asym_enc_keys: (box_::PublicKey, box_::SecretKey),
        /// Symmetric encryption key of the app
        sym_key: secretbox::Key,
    },
}

impl App {
    /// Get app root directory key
    pub fn sym_key(&self) -> Result<secretbox::Key, FfiError> {
        if let App::Registered { ref sym_key, .. } = *self {
            Ok(sym_key.clone())
        } else {
            Err(FfiError::OperationForbiddenForApp)
        }
    }

    /// Get asymmetric encryption key for the app
    pub fn asym_enc_keys(&self) -> Result<(box_::PublicKey, box_::SecretKey), FfiError> {
        if let App::Registered { ref asym_enc_keys, .. } = *self {
            Ok(asym_enc_keys.clone())
        } else {
            Err(FfiError::OperationForbiddenForApp)
        }
    }

    /// Get app root directory ID
    pub fn app_dir(&self) -> Result<DirId, FfiError> {
        if let App::Registered { ref app_dir_id, .. } = *self {
            Ok(app_dir_id.clone())
        } else {
            Err(FfiError::OperationForbiddenForApp)
        }
    }

    /// Get root directory: for shared paths, this is the SAFEdrive directory,
    /// otherwise it's the app directory.
    pub fn root_dir(&self, client: Client, is_shared: bool) -> Box<FfiFuture<DirId>> {
        if is_shared {
            if let App::Registered { ref safe_drive_access, .. } = *self {
                if !safe_drive_access {
                    return err!(FfiError::PermissionDenied);
                }
                helper::safe_drive_metadata(client.clone())
                    .map(move |dir_meta| dir_meta.id())
                    .into_box()
            } else {
                err!(FfiError::from("Safe Drive directory is not available for an unregistered \
                                     app"))
            }
        } else {
            futures::done(self.app_dir()).into_box()
        }
    }
}

/// Register an app with the launcher. The returned app handle must be disposed
/// of by calling `drop_app` once no longer needed.
#[no_mangle]
pub unsafe extern "C" fn register_app(session: *mut Session,
                                      app_name: *const u8,
                                      app_name_len: usize,
                                      unique_token: *const u8,
                                      token_len: usize,
                                      vendor: *const u8,
                                      vendor_len: usize,
                                      safe_drive_access: bool,
                                      user_data: *mut c_void,
                                      o_cb: unsafe extern "C" fn(*mut c_void, i32, AppHandle)) {
    let user_data = OpaqueCtx(user_data);

    let _ = helper::catch_unwind_cb(user_data, o_cb, || {
        let app_name = helper::c_utf8_to_string(app_name, app_name_len)?;
        let unique_token = helper::c_utf8_to_string(unique_token, token_len)?;
        let vendor = helper::c_utf8_to_string(vendor, vendor_len)?;

        (*session).send(move |client, object_cache| {
            let object_cache = object_cache.clone();
            let fut =
                launcher_config::app(client, app_name, unique_token, vendor, safe_drive_access)
                    .map_err(move |e| o_cb(user_data.0, ffi_error_code!(e), 0))
                    .map(move |app| {
                        let app_handle = object_cache.insert_app(app);
                        o_cb(user_data.0, 0, app_handle);
                    })
                    .into_box();
            Some(fut)
        })
    });
}

/// Register an anonymous app with the launcher. Can access only public data
#[no_mangle]
pub unsafe extern "C" fn create_unregistered_app(session: *mut Session,
                                                 user_data: *mut c_void,
                                                 o_cb: extern "C" fn(*mut c_void, i32, AppHandle)) {
    helper::catch_unwind_cb(user_data, o_cb, || {
        let user_data = OpaqueCtx(user_data);
        (*session).send(move |_, object_cache| {
            let app_handle = object_cache.insert_app(App::Unregistered);
            o_cb(user_data.0, 0, app_handle);
            None
        })
    })
}
