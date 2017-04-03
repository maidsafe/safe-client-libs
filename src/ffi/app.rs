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

//! Structure representing application registered with the launcher + set of
//! FFI operations on it.

// TODO(Spandan) - Run through this and make interfaces efficient (return references instead of
// copies etc.) and uniform (i.e. not use get_ prefix for mem functions.

use super::errors::FfiError;
use super::helper;
use super::launcher_config_handler::ConfigHandler;
use super::session::{Session, SessionHandle};
use core::client::Client;
use libc::int32_t;
use nfs::metadata::directory_key::DirectoryKey;
use rust_sodium::crypto::{box_, secretbox};
use std::sync::{Arc, Mutex};

/// Represents an application connected to the launcher.
pub struct App {
    session: Arc<Mutex<Session>>,
    app_dir_key: Option<DirectoryKey>,
    safe_drive_access: bool,
    asym_keys: Option<(box_::PublicKey, box_::SecretKey)>,
    sym_key: Option<secretbox::Key>,
}

impl App {
    /// Create new app for registered client.
    pub fn registered(session: Arc<Mutex<Session>>,
                      app_name: String,
                      unique_token: String,
                      vendor: String,
                      safe_drive_access: bool)
                      -> Result<Self, FfiError> {
        let client = unwrap!(session.lock()).get_client();
        let handler = ConfigHandler::new(client);
        let app_info = handler.get_app_info(app_name, unique_token, vendor)?;

        Ok(App {
               session: session,
               app_dir_key: Some(app_info.app_root_dir_key),
               safe_drive_access: safe_drive_access,
               asym_keys: Some(app_info.asym_keys),
               sym_key: Some(app_info.sym_key),
           })
    }

    /// Create new app for unregistered client.
    pub fn unregistered(session: Arc<Mutex<Session>>) -> Self {
        App {
            session: session,
            app_dir_key: None,
            safe_drive_access: false,
            asym_keys: None,
            sym_key: None,
        }
    }

    /// Get the client.
    pub fn get_client(&self) -> Arc<Mutex<Client>> {
        unwrap!(self.session.lock()).get_client()
    }

    // TODO Maybe change all of these to operation forbidden for app
    /// Get app root directory key
    pub fn get_app_dir_key(&self) -> Option<DirectoryKey> {
        self.app_dir_key
    }

    /// Get app asym_keys
    pub fn asym_keys(&self) -> Result<&(box_::PublicKey, box_::SecretKey), FfiError> {
        self.asym_keys
            .as_ref()
            .ok_or(FfiError::OperationForbiddenForApp)
    }

    /// Get app root directory key
    pub fn sym_key(&self) -> Result<&secretbox::Key, FfiError> {
        self.sym_key
            .as_ref()
            .ok_or(FfiError::OperationForbiddenForApp)
    }

    /// Get SAFEdrive directory key.
    pub fn get_safe_drive_dir_key(&self) -> Option<DirectoryKey> {
        *unwrap!(self.session.lock()).get_safe_drive_dir_key()
    }

    /// Has this app access to the SAFEdrive?
    pub fn has_safe_drive_access(&self) -> bool {
        self.safe_drive_access
    }

    /// Get root directory key: for shared paths, this is the SAFEdrive directory,
    /// otherwise it's the app directory.
    pub fn get_root_dir_key(&self, is_shared: bool) -> Result<DirectoryKey, FfiError> {
        if is_shared {
            if !self.has_safe_drive_access() {
                return Err(FfiError::PermissionDenied);
            }

            self.get_safe_drive_dir_key()
                .ok_or_else(|| FfiError::from("Safe Drive directory key is not present"))
        } else {
            self.get_app_dir_key()
                .ok_or_else(|| FfiError::from("Application directory key is not present"))
        }
    }
}

/// Register an app with the launcher. The returned app handle must be disposed
/// of by calling `drop_app` once no longer needed.
#[no_mangle]
pub unsafe extern "C" fn register_app(session_handle: *mut SessionHandle,
                                      app_name: *const u8,
                                      app_name_len: usize,
                                      unique_token: *const u8,
                                      token_len: usize,
                                      vendor: *const u8,
                                      vendor_len: usize,
                                      safe_drive_access: bool,
                                      app_handle: *mut *mut App)
                                      -> int32_t {
    helper::catch_unwind_i32(|| {
        let app_name = ffi_try!(helper::c_utf8_to_string(app_name, app_name_len));
        let unique_token = ffi_try!(helper::c_utf8_to_string(unique_token, token_len));
        let vendor = ffi_try!(helper::c_utf8_to_string(vendor, vendor_len));

        let session = (*session_handle).clone();

        let app =
            ffi_try!(App::registered(session, app_name, unique_token, vendor, safe_drive_access));

        *app_handle = Box::into_raw(Box::new(app));
        0
    })
}

/// Register an annonymous app with the launcher. Can access only public data
#[no_mangle]
pub unsafe extern "C" fn create_unauthorised_app(session_handle: *mut SessionHandle,
                                                 app_handle: *mut *mut App)
                                                 -> int32_t {
    helper::catch_unwind_i32(|| {
                                 let session = (*session_handle).clone();
                                 let app = App::unregistered(session);

                                 *app_handle = Box::into_raw(Box::new(app));
                                 0
                             })
}

/// Discard and clean up the previously allocated app.
#[no_mangle]
pub unsafe extern "C" fn drop_app(app_handle: *mut App) {
    let _ = Box::from_raw(app_handle);
}
