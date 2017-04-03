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

//! Session management

use super::errors::FfiError;
use super::helper;
use core::client::Client;
use core::translated_events::NetworkEvent;
use libc::{int32_t, int64_t};
use maidsafe_utilities::thread::{self, Joiner};
use nfs::metadata::directory_key::DirectoryKey;
use std::ptr;
use std::sync::{Arc, Mutex};
use std::sync::mpsc::{self, Sender};

/// Represents user session on the SAFE network. There should be one session per launcher.
#[cfg_attr(feature="cargo-clippy", allow(type_complexity))]
pub struct Session {
    client: Arc<Mutex<Client>>,
    safe_drive_dir_key: Option<DirectoryKey>,

    network_event_observers: Arc<Mutex<Vec<extern "C" fn(i32)>>>,
    network_thread: Option<(Sender<NetworkEvent>, Joiner)>,
}

impl Session {
    /// Create unregistered client.
    pub fn create_unregistered_client() -> Result<Self, FfiError> {
        let client = Client::create_unregistered_client()?;
        let client = Arc::new(Mutex::new(client));

        Ok(Session {
               client: client,
               safe_drive_dir_key: None,
               network_event_observers: Default::default(),
               network_thread: None,
           })
    }

    /// Create new account.
    pub fn create_account(locator: &str,
                          password: &str,
                          invitation: &str)
                          -> Result<Self, FfiError> {
        let client = Client::create_account(locator, password, invitation)?;
        let client = Arc::new(Mutex::new(client));

        let safe_drive_dir_key = helper::get_safe_drive_key(client.clone())?;

        Ok(Session {
               client: client,
               safe_drive_dir_key: Some(safe_drive_dir_key),
               network_event_observers: Default::default(),
               network_thread: None,
           })
    }

    /// Log in to existing account.
    pub fn log_in(locator: &str, password: &str) -> Result<Self, FfiError> {
        let client = Client::log_in(locator, password)?;
        let client = Arc::new(Mutex::new(client));

        let safe_drive_dir_key = helper::get_safe_drive_key(client.clone())?;

        Ok(Session {
               client: client,
               safe_drive_dir_key: Some(safe_drive_dir_key),
               network_event_observers: Default::default(),
               network_thread: None,
           })
    }

    /// Get the client.
    pub fn get_client(&self) -> Arc<Mutex<Client>> {
        self.client.clone()
    }

    /// Get SAFEdrive directory key.
    pub fn get_safe_drive_dir_key(&self) -> &Option<DirectoryKey> {
        &self.safe_drive_dir_key
    }

    fn register_network_event_observer(&mut self, callback: extern "C" fn(i32)) {
        unwrap!(self.network_event_observers.lock()).push(callback);

        if self.network_thread.is_none() {
            let callbacks = self.network_event_observers.clone();

            let (tx, rx) = mpsc::channel();
            let cloned_tx = tx.clone();
            unwrap!(self.client.lock()).add_network_event_observer(tx);

            let joiner = thread::named("FfiNetworkEventObserver",
                                       move || while let Ok(event) = rx.recv() {
                                           if let NetworkEvent::Terminated = event {
                                               trace!("FFI exiting the network event notifier /
                                                       thread.");
                                               break;
                                           }

                                           let callbacks = &*unwrap!(callbacks.lock());
                                           info!("Informing {:?} to {} FFI network event /
                                                  observers.",
                                                 event,
                                                 callbacks.len());
                                           let event_ffi_val = event.into();

                                           for cb in callbacks {
                                               cb(event_ffi_val);
                                           }
                                       });

            self.network_thread = Some((cloned_tx, joiner));
        }
    }

    fn get_account_info(&self) -> Result<(u64, u64), FfiError> {
        let mut client = unwrap!(self.client.lock());
        let getter = client.get_account_info(None)?;
        Ok(getter.get()?)
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        debug!("Session is now being dropped.");

        if let Some((terminator, _joiner)) = self.network_thread.take() {
            let _ = terminator.send(NetworkEvent::Terminated);
        }
    }
}

/// Clonable handle to Session.
pub type SessionHandle = Arc<Mutex<Session>>;

/// Create a session as an unregistered client. This or any one of the other companion functions to
/// get a session must be called before initiating any operation allowed by this crate.
#[no_mangle]
pub unsafe extern "C" fn create_unregistered_client(session_handle: *mut *mut SessionHandle)
                                                    -> int32_t {
    helper::catch_unwind_i32(|| {
                                 trace!("FFI create unregistered client.");

                                 let session = ffi_try!(Session::create_unregistered_client());
                                 *session_handle = allocate_handle(session);
                                 0
                             })
}

/// Create a registered client. This or any one of the other companion functions to get a
/// session must be called before initiating any operation allowed by this crate. `session_handle`
/// is a pointer to a pointer and must point to a valid pointer not junk, else the consequences are
/// undefined.
#[no_mangle]
pub unsafe extern "C" fn create_account(account_locator: *const u8,
                                        account_locator_len: usize,
                                        account_password: *const u8,
                                        account_password_len: usize,
                                        invitation: *const u8,
                                        invitation_len: usize,
                                        session_handle: *mut *mut SessionHandle)
                                        -> int32_t {
    helper::catch_unwind_i32(|| {
        trace!("FFI create a client account.");

        let acc_locator = ffi_try!(helper::c_utf8_to_str(account_locator, account_locator_len));
        let acc_password = ffi_try!(helper::c_utf8_to_str(account_password, account_password_len));
        let invitation = ffi_try!(helper::c_utf8_to_str(invitation, invitation_len));
        let session = ffi_try!(Session::create_account(acc_locator, acc_password, invitation));

        *session_handle = allocate_handle(session);
        0
    })
}

/// Log into a registered client. This or any one of the other companion functions to get a
/// session must be called before initiating any operation allowed by this crate. `session_handle`
/// is a pointer to a pointer and must point to a valid pointer not junk, else the consequences are
/// undefined.
#[no_mangle]
pub unsafe extern "C" fn log_in(account_locator: *const u8,
                                account_locator_len: usize,
                                account_password: *const u8,
                                account_password_len: usize,
                                session_handle: *mut *mut SessionHandle)
                                -> int32_t {
    helper::catch_unwind_i32(|| {
        trace!("FFI login a registered client.");

        let acc_locator = ffi_try!(helper::c_utf8_to_str(account_locator, account_locator_len));
        let acc_password = ffi_try!(helper::c_utf8_to_str(account_password, account_password_len));
        let session = ffi_try!(Session::log_in(acc_locator, acc_password));

        *session_handle = allocate_handle(session);
        0
    })
}

/// Register an observer to network events like Connected, Disconnected etc. as provided by the
/// core module
#[no_mangle]
pub unsafe extern "C" fn register_network_event_observer(session_handle: *mut SessionHandle,
                                                         callback: extern "C" fn(i32))
                                                         -> int32_t {
    helper::catch_unwind_i32(|| {
                                 trace!("FFI register a network event observer.");
                                 unwrap!((*session_handle).lock())
                                     .register_network_event_observer(callback);
                                 0
                             })
}


/// Return the amount of calls that were done to `get`
#[no_mangle]
pub unsafe extern "C" fn client_issued_gets(session_handle: *const SessionHandle) -> int64_t {
    helper::catch_unwind_i64(|| {
                                 trace!("FFI retrieve client issued GETs.");
                                 let session = unwrap!((*session_handle).lock());
                                 let client = unwrap!(session.client.lock());
                                 client.issued_gets() as int64_t
                             })
}

/// Return the amount of calls that were done to `put`
#[no_mangle]
pub unsafe extern "C" fn client_issued_puts(session_handle: *const SessionHandle) -> int64_t {
    helper::catch_unwind_i64(|| {
                                 trace!("FFI retrieve client issued PUTs.");
                                 let session = unwrap!((*session_handle).lock());
                                 let client = unwrap!(session.client.lock());
                                 client.issued_puts() as int64_t
                             })
}

/// Return the amount of calls that were done to `post`
#[no_mangle]
pub unsafe extern "C" fn client_issued_posts(session_handle: *const SessionHandle) -> int64_t {
    helper::catch_unwind_i64(|| {
                                 trace!("FFI retrieve client issued POSTs.");
                                 let session = unwrap!((*session_handle).lock());
                                 let client = unwrap!(session.client.lock());
                                 client.issued_posts() as int64_t
                             })
}

/// Return the amount of calls that were done to `delete`
#[no_mangle]
pub unsafe extern "C" fn client_issued_deletes(session_handle: *const SessionHandle) -> int64_t {
    helper::catch_unwind_i64(|| {
                                 trace!("FFI retrieve client issued DELETEs.");
                                 let session = unwrap!((*session_handle).lock());
                                 let client = unwrap!(session.client.lock());
                                 client.issued_deletes() as int64_t
                             })
}

/// Return the amount of calls that were done to `append`
#[no_mangle]
pub unsafe extern "C" fn client_issued_appends(session_handle: *const SessionHandle) -> int64_t {
    helper::catch_unwind_i64(|| {
                                 trace!("FFI retrieve client issued APPENDs.");
                                 let session = unwrap!((*session_handle).lock());
                                 let client = unwrap!(session.client.lock());
                                 client.issued_appends() as int64_t
                             })
}

/// Get data from the network. This is non-blocking. `data_stored` means number
/// of chunks Put. `space_available` means number of chunks which can still be
/// Put.
#[no_mangle]
pub unsafe extern "C" fn get_account_info(session_handle: *const SessionHandle,
                                          data_stored: *mut u64,
                                          space_available: *mut u64)
                                          -> i32 {
    helper::catch_unwind_i32(|| {
        trace!("FFI get account information.");

        let res = ffi_try!(unwrap!((*session_handle).lock()).get_account_info());
        ptr::write(data_stored, res.0);
        ptr::write(space_available, res.1);

        0
    })
}

/// Discard and clean up the previously allocated session. Use this only if the session is obtained
/// from one of the session obtainment functions in this crate (`create_account`, `log_in`,
/// `create_unregistered_client`). Using `session` after a call to this functions is
/// undefined behaviour.
#[no_mangle]
pub unsafe extern "C" fn drop_session(session: *mut SessionHandle) {
    let _ = Box::from_raw(session);
}


unsafe fn allocate_handle(session: Session) -> *mut SessionHandle {
    Box::into_raw(Box::new(Arc::new(Mutex::new(session))))
}

#[cfg(test)]
mod test {
    use super::*;
    use ffi::test_utils;
    use std::ptr;

    #[test]
    fn create_account_and_log_in() {
        let acc_locator = test_utils::generate_random_cstring(10);
        let acc_password = test_utils::generate_random_cstring(10);
        let invitation = test_utils::generate_random_cstring(10);

        {
            let mut session_handle: *mut SessionHandle = ptr::null_mut();

            unsafe {
                let session_handle_ptr = &mut session_handle;

                assert_eq!(create_account(acc_locator.as_ptr() as *const u8,
                                          10,
                                          acc_password.as_ptr() as *const u8,
                                          10,
                                          invitation.as_ptr() as *const u8,
                                          10,
                                          session_handle_ptr),
                           0);
            }

            assert!(!session_handle.is_null());
            unsafe { drop_session(session_handle) };
        }

        {
            let mut session_handle: *mut SessionHandle = ptr::null_mut();

            unsafe {
                let session_handle_ptr = &mut session_handle;

                assert_eq!(log_in(acc_locator.as_ptr() as *const u8,
                                  10,
                                  acc_password.as_ptr() as *const u8,
                                  10,
                                  session_handle_ptr),
                           0);
            }

            assert!(!session_handle.is_null());
            unsafe { drop_session(session_handle) };
        }
    }
}
