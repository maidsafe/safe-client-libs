// Copyright 2015 MaidSafe.net limited.
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

//! This module provides FFI-bindings to the Client Modules (`core`, `nfs`, `dns`)
//! In the current implementation the allocations made by this crate are managed within the crate
//! itself and is guaranteed that management of such allocations will not be pushed beyond the FFI
//! boundary. This has a 2-fold outcome: firstly, the passing of data is done by filling of the
//! allocations passed by the caller and is caller's responsibility to manage those. For this every
//! function that fills an allocated memory also has a companion function to return the size of
//! data which the caller can call to find out how much space needs to be allocated in the first
//! place. Second and consequently, the caller does not have to bother calling functions within
//! this crate which only serve to free resources allocated by the crate itself. This otherwise
//! would be error prone and cumbersome. Instead the caller can use whatever idiom in his language
//! to manage memory much more naturally and conveniently (eg., RAII idioms etc)
//!
//! The only exception to the above rule is the obtainment of the client engine itself. The client
//! engine is allocated and managed by the crate. This is necessary because it serves as a context
//! to all operations provided by the crate. Hence the user will obtain the engine on calling any
//! one of the functions to create it and must preserve it for all subsequent operations. When
//! done, to release the resources, `drop_client` may be called.


#[macro_use]mod macros;

mod dns;
mod nfs;
mod config;
mod helper;
mod test_utils;
mod launcher_config_handler;
/// Errors thrown by the FFI operations
pub mod errors;

use std::{mem, ptr};
use std::sync::{Arc, Mutex, mpsc};
use std::sync::mpsc::Sender;

use core::client::Client;
use core::errors::CoreError;
use core::translated_events::NetworkEvent;
use ffi::errors::FfiError;
use libc::{c_char, int32_t};
use maidsafe_utilities::log as safe_log;
use maidsafe_utilities::serialisation::{deserialise, serialise};
use maidsafe_utilities::thread::RaiiThreadJoiner;
use nfs::metadata::directory_key::DirectoryKey;
use rustc_serialize::base64::FromBase64;
use rustc_serialize::{Decodable, Decoder, json};


/// ParameterPacket acts as a holder for the standard parameters that would be needed for performing
/// operations across the modules like nfs and dns
pub struct ParameterPacket {
    /// Client instance used for performing the API operation
    pub client: Arc<Mutex<Client>>,
    /// Root directory of the application
    pub app_root_dir_key: Option<DirectoryKey>,
    /// Denotes whether the application has access to SAFEDrive
    pub safe_drive_access: bool,
    /// SAFEDrive root directory key
    pub safe_drive_dir_key: Option<DirectoryKey>,
}

impl Clone for ParameterPacket {
    fn clone(&self) -> ParameterPacket {
        let app_root_dir_key = if let Some(ref key) = self.app_root_dir_key {
            Some(key.clone())
        } else {
            None
        };
        let safe_drive_dir_key = if let Some(ref key) = self.safe_drive_dir_key {
            Some(key.clone())
        } else {
            None
        };
        ParameterPacket {
            client: self.client.clone(),
            app_root_dir_key: app_root_dir_key,
            safe_drive_access: self.safe_drive_access,
            safe_drive_dir_key: safe_drive_dir_key,
        }
    }
}

/// ResponseType tspecifies the standard Response that is to be expected from the ::Action trait
pub type ResponseType = Result<Option<String>, FfiError>;

/// ICommand trait
pub trait Action {
    /// ICommand executer
    fn execute(&mut self, params: ParameterPacket) -> ResponseType;
}

/// A handle, passed through the FFI.
pub struct FfiHandle {
    client: Arc<Mutex<Client>>,
    network_thread_terminator: Option<Sender<NetworkEvent>>,
    raii_joiner: Option<RaiiThreadJoiner>,

    #[cfg_attr(feature="clippy", allow(type_complexity))]
    network_event_observers: Arc<Mutex<Vec<extern "C" fn(i32)>>>,
}

impl Drop for FfiHandle {
    fn drop(&mut self) {
        if let Some(ref network_thread_terminator) = self.network_thread_terminator {
            let _ = network_thread_terminator.send(NetworkEvent::Terminated);
        }
    }
}

/// This function should be called to enable logging to a file
#[no_mangle]
pub extern "C" fn init_logging() -> int32_t {
    ffi_try!(safe_log::init(false).map_err(CoreError::Unexpected));

    0
}

/// Create an unregistered client. This or any one of the other companion functions to get a
/// client must be called before initiating any operation allowed by this crate.
#[no_mangle]
#[allow(unsafe_code)]
pub extern "C" fn create_unregistered_client(ffi_handle: *mut *mut FfiHandle) -> int32_t {
    unsafe {
        *ffi_handle = cast_to_ffi_handle(ffi_try!(Client::create_unregistered_client()));
    }

    0
}

/// Create a registered client. This or any one of the other companion functions to get a
/// client must be called before initiating any operation allowed by this crate. `client_handle` is
/// a pointer to a pointer and must point to a valid pointer not junk, else the consequences are
/// undefined.
#[no_mangle]
#[allow(unsafe_code)]
pub extern "C" fn create_account(c_keyword: *const c_char,
                                 c_pin: *const c_char,
                                 c_password: *const c_char,
                                 ffi_handle: *mut *mut FfiHandle)
                                 -> int32_t {
    let client = ffi_try!(Client::create_account(ffi_try!(helper::c_char_ptr_to_string(c_keyword)),
                                        ffi_try!(helper::c_char_ptr_to_string(c_pin)),
                                        ffi_try!(helper::c_char_ptr_to_string(c_password))));
    unsafe {
        *ffi_handle = cast_to_ffi_handle(client);
    }

    0
}

/// Log into a registered client. This or any one of the other companion functions to get a
/// client must be called before initiating any operation allowed by this crate. `client_handle` is
/// a pointer to a pointer and must point to a valid pointer not junk, else the consequences are
/// undefined.
#[no_mangle]
#[allow(unsafe_code)]
pub extern "C" fn log_in(c_keyword: *const c_char,
                         c_pin: *const c_char,
                         c_password: *const c_char,
                         ffi_handle: *mut *mut FfiHandle)
                         -> int32_t {
    let client = ffi_try!(Client::log_in(ffi_try!(helper::c_char_ptr_to_string(c_keyword)),
                                         ffi_try!(helper::c_char_ptr_to_string(c_pin)),
                                         ffi_try!(helper::c_char_ptr_to_string(c_password))));
    unsafe {
        *ffi_handle = cast_to_ffi_handle(client);
    }

    0
}

/// Register an observer to network events like Connected, Disconnected etc. as provided by the
/// core module
#[no_mangle]
#[allow(unsafe_code)]
pub extern "C" fn register_network_event_observer(ffi_handle: *mut FfiHandle,
                                                  callback: extern "C" fn(i32)) {
    let mut ffi_handle = unsafe { Box::from_raw(ffi_handle) };

    unwrap!(ffi_handle.network_event_observers.lock()).push(callback);

    if ffi_handle.raii_joiner.is_none() {
        let callbacks = ffi_handle.network_event_observers.clone();

        let (tx, rx) = mpsc::channel();
        let cloned_tx = tx.clone();
        unwrap!(ffi_handle.client.lock()).add_network_event_observer(tx);

        let raii_joiner = RaiiThreadJoiner::new(thread!("FfiNetworkEventObserver", move || {
            while let Ok(event) = rx.recv() {
                if let NetworkEvent::Terminated = event {
                    break;
                }
                let cbs = &*unwrap!(callbacks.lock());
                let event_ffi_val = event.into();
                for cb in cbs {
                    cb(event_ffi_val);
                }
            }
        }));

        ffi_handle.raii_joiner = Some(raii_joiner);
        ffi_handle.network_thread_terminator = Some(cloned_tx);
    }

    mem::forget(ffi_handle);
}

/// Returns key size
#[no_mangle]
#[allow(unsafe_code)]
pub extern "C" fn get_app_dir_key(c_app_name: *const c_char,
                                  c_app_id: *const c_char,
                                  c_vendor: *const c_char,
                                  c_size: *mut int32_t,
                                  c_capacity: *mut int32_t,
                                  c_result: *mut int32_t,
                                  ffi_handle: *mut FfiHandle)
                                  -> *const u8 {
    let client = cast_from_ffi_handle(ffi_handle);
    let app_name: String = ffi_ptr_try!(helper::c_char_ptr_to_string(c_app_name), c_result);
    let app_id: String = ffi_ptr_try!(helper::c_char_ptr_to_string(c_app_id), c_result);
    let vendor: String = ffi_ptr_try!(helper::c_char_ptr_to_string(c_vendor), c_result);
    let handler = launcher_config_handler::ConfigHandler::new(client);
    let dir_key = ffi_ptr_try!(handler.get_app_dir_key(app_name, app_id, vendor), c_result);
    let mut serialised_data = ffi_ptr_try!(serialise(&dir_key).map_err(FfiError::from), c_result);
    serialised_data.shrink_to_fit();
    unsafe {
        ptr::write(c_size, serialised_data.len() as i32);
        ptr::write(c_capacity, serialised_data.capacity() as i32);
        ptr::write(c_result, 0);
    }

    let ptr = serialised_data.as_ptr();
    mem::forget(serialised_data);

    ptr
}

/// Returns Key as base64 string
#[no_mangle]
#[allow(unsafe_code)]
pub extern "C" fn get_safe_drive_key(c_size: *mut int32_t,
                                     c_capacity: *mut int32_t,
                                     c_result: *mut int32_t,
                                     ffi_handle: *mut FfiHandle)
                                     -> *const u8 {
    let client = cast_from_ffi_handle(ffi_handle);
    let dir_key = ffi_ptr_try!(helper::get_safe_drive_key(client), c_result);
    let mut serialised_data = ffi_ptr_try!(serialise(&dir_key).map_err(FfiError::from), c_result);
    serialised_data.shrink_to_fit();
    unsafe {
        ptr::write(c_size, serialised_data.len() as i32);
        ptr::write(c_capacity, serialised_data.capacity() as i32);
        ptr::write(c_result, 0);
    }
    let ptr = serialised_data.as_ptr();
    mem::forget(serialised_data);

    ptr
}

/// Discard and clean up the previously allocated client. Use this only if the client is obtained
/// from one of the client obtainment functions in this crate (`create_account`, `log_in`,
/// `create_unregistered_client`). Using `client_handle` after a call to this functions is
/// undefined behaviour.
#[no_mangle]
#[allow(unsafe_code)]
pub extern "C" fn drop_client(client_handle: *mut FfiHandle) {
    unsafe {
        let _ = Box::from_raw(client_handle);
    }
}

/// General function that can be invoked for performing a API specific operation that will return
/// only result to indicate whether the operation was successful or not.
/// This function would only perform the operation and return 0 or error code
/// c_payload refers to the JSON payload that can be passed as a JSON string.
/// The JSON string should have keys module, action, app_root_dir_key, safe_drive_dir_key,
/// safe_drive_access and data. `data` refers to API specific payload.
#[no_mangle]
pub extern "C" fn execute(c_payload: *const c_char, ffi_handle: *mut FfiHandle) -> int32_t {
    let payload: String = ffi_try!(helper::c_char_ptr_to_string(c_payload));
    let json_request = ffi_try!(parse_result!(json::Json::from_str(&payload), "JSON parse error"));
    let mut json_decoder = json::Decoder::new(json_request);
    let client = cast_from_ffi_handle(ffi_handle);
    let (module, action, parameter_packet) = ffi_try!(get_parameter_packet(client,
                                                                           &mut json_decoder));
    let result = module_parser(module, action, parameter_packet, &mut json_decoder);
    let _ = ffi_try!(result);

    0
}

/// General function that can be invoked for getting data as a resut for an operation.
/// The function return a pointer to a U8 vecotr. The size of the U8 vector and its capacity is
/// written to the out params c_size & c_capacity. The size and capcity would be required for
/// droping the vector The result of the execution is returned in the c_result out param
#[no_mangle]
#[allow(unsafe_code)]
pub extern "C" fn execute_for_content(c_payload: *const c_char,
                                      c_size: *mut int32_t,
                                      c_capacity: *mut int32_t,
                                      c_result: *mut int32_t,
                                      ffi_handle: *mut FfiHandle)
                                      -> *const u8 {
    let payload: String = ffi_ptr_try!(helper::c_char_ptr_to_string(c_payload), c_result);
    let json_request = ffi_ptr_try!(parse_result!(json::Json::from_str(&payload),
                                                  "JSON parse error"),
                                    c_result);
    let mut json_decoder = json::Decoder::new(json_request.clone());
    let client = cast_from_ffi_handle(ffi_handle);
    let (module, action, parameter_packet) =
        ffi_ptr_try!(get_parameter_packet(client, &mut json_decoder), c_result);
    // TODO Krishna: Avoid parsing it twice (line 292). for get_parameter_packet pass the json
    // object and iterate. parse based on keys
    json_decoder = json::Decoder::new(json_request.clone());
    let result = ffi_ptr_try!(module_parser(module, action, parameter_packet, &mut json_decoder),
                              c_result);
    let data = match result {
        Some(response) => response.into_bytes(),
        None => Vec::with_capacity(0),
    };

    unsafe {
        ptr::write(c_size, data.len() as i32);
        ptr::write(c_capacity, data.capacity() as i32);
        ptr::write(c_result, 0);
    };
    let ptr = data.as_ptr();
    mem::forget(data);

    ptr
}

#[no_mangle]
#[allow(unsafe_code)]
/// Drop the vector returned as a result of the execute_for_content fn
pub fn drop_vector(ptr: *mut u8, size: int32_t, capacity: int32_t) {
    let _ = unsafe { Vec::from_raw_parts(ptr, size as usize, capacity as usize) };
}

/// Return the amount of calls that were done to `get`
#[no_mangle]
#[allow(unsafe_code)]
pub extern "C" fn client_issued_gets(ffi_handle: *mut FfiHandle) -> u64 {
    let client = cast_from_ffi_handle(ffi_handle);
    let guard = client.lock().unwrap();
    guard.issued_gets()
}

/// Return the amount of calls that were done to `put`
#[no_mangle]
#[allow(unsafe_code)]
pub extern "C" fn client_issued_puts(ffi_handle: *mut FfiHandle) -> u64 {
    let client = cast_from_ffi_handle(ffi_handle);
    let guard = client.lock().unwrap();
    guard.issued_puts()
}

/// Return the amount of calls that were done to `post`
#[no_mangle]
#[allow(unsafe_code)]
pub extern "C" fn client_issued_posts(ffi_handle: *mut FfiHandle) -> u64 {
    let client = cast_from_ffi_handle(ffi_handle);
    let guard = client.lock().unwrap();
    guard.issued_posts()
}

/// Return the amount of calls that were done to `delete`
#[no_mangle]
#[allow(unsafe_code)]
pub extern "C" fn client_issued_deletes(ffi_handle: *mut FfiHandle) -> u64 {
    let client = cast_from_ffi_handle(ffi_handle);
    let guard = client.lock().unwrap();
    guard.issued_deletes()
}

fn get_parameter_packet<D>(client: Arc<Mutex<Client>>,
                           json_decoder: &mut D)
                           -> Result<(String, String, ParameterPacket), FfiError>
    where D: Decoder,
          D::Error: ::std::fmt::Debug
{

    let module: String =
        try!(parse_result!(json_decoder.read_struct_field("module", 0, Decodable::decode),
                           ""));
    let action: String =
        try!(parse_result!(json_decoder.read_struct_field("action", 1, Decodable::decode),
                           ""));
    let base64_safe_drive_dir_key: Option<String> =
        json_decoder.read_struct_field("safe_drive_dir_key", 2, Decodable::decode)
            .ok();

    let base64_app_dir_key: Option<String> =
        json_decoder.read_struct_field("app_dir_key", 3, Decodable::decode)
            .ok();
    let safe_drive_access: bool = if base64_safe_drive_dir_key.is_none() {
        false
    } else {
        try!(parse_result!(
                json_decoder.read_struct_field("safe_drive_access", 4, Decodable::decode), ""))
    };
    let app_root_dir_key: Option<DirectoryKey> = if let Some(app_dir_key) = base64_app_dir_key {
        let serialised_app_dir_key: Vec<u8> = try!(parse_result!(app_dir_key[..].from_base64(),
                                                                 ""));
        let dir_key: DirectoryKey = try!(deserialise(&serialised_app_dir_key));
        Some(dir_key)
    } else {
        None
    };

    let safe_drive_dir_key: Option<DirectoryKey> = if let Some(safe_dir_key) =
                                                          base64_safe_drive_dir_key {
        let serialised_safe_drive_key: Vec<u8> =
            try!(parse_result!(safe_dir_key[..].from_base64(), ""));
        let dir_key: DirectoryKey = try!(deserialise(&serialised_safe_drive_key));
        Some(dir_key)
    } else {
        None
    };

    Ok((module,
        action,
        ParameterPacket {
        client: client,
        app_root_dir_key: app_root_dir_key,
        safe_drive_access: safe_drive_access,
        safe_drive_dir_key: safe_drive_dir_key,
    }))
}

fn module_parser<D>(module: String,
                    action: String,
                    parameter_packet: ParameterPacket,
                    decoder: &mut D)
                    -> ResponseType
    where D: Decoder,
          D::Error: ::std::fmt::Debug
{
    match &module[..] {
        "dns" => dns::action_dispatcher(action, parameter_packet, decoder),
        "nfs" => nfs::action_dispatcher(action, parameter_packet, decoder),
        _ => unimplemented!(),
    }
}

#[allow(unsafe_code)]
fn cast_to_ffi_handle(client: Client) -> *mut FfiHandle {
    let ffi_handle = Box::new(FfiHandle {
        client: Arc::new(Mutex::new(client)),
        network_thread_terminator: None,
        raii_joiner: None,
        network_event_observers: Arc::new(Mutex::new(Vec::with_capacity(3))),
    });
    Box::into_raw(ffi_handle)
}

#[allow(unsafe_code)]
fn cast_from_ffi_handle(ffi_handle: *mut FfiHandle) -> Arc<Mutex<Client>> {
    unsafe { (*ffi_handle).client.clone() }
}

#[cfg(test)]
mod test {
    #![allow(unsafe_code)]

    use super::*;
    use ffi::errors::FfiError;

    use std::env;
    use std::thread;
    use std::fs::File;
    use std::io::Read;
    use std::error::Error;
    use std::time::Duration;
    use std::ptr;

    fn generate_random_cstring(len: usize) -> Result<::std::ffi::CString, FfiError> {
        let mut cstring_vec = try!(::core::utility::generate_random_vector::<u8>(len));
        // Avoid internal nulls and ensure valid ASCII (thus valid utf8)
        for it in &mut cstring_vec {
            *it %= 128;
            if *it == 0 {
                *it += 1;
            }
        }

        ::std::ffi::CString::new(cstring_vec).map_err(|error| FfiError::from(error.description()))
    }

    #[test]
    fn account_creation_and_login() {
        let cstring_pin = unwrap!(generate_random_cstring(10));
        let cstring_keyword = unwrap!(generate_random_cstring(10));
        let cstring_password = unwrap!(generate_random_cstring(10));

        {
            let mut client_handle: *mut FfiHandle = ptr::null_mut();

            {
                let ptr_to_client_handle = &mut client_handle;

                assert_eq!(create_account(cstring_keyword.as_ptr(),
                                          cstring_pin.as_ptr(),
                                          cstring_password.as_ptr(),
                                          ptr_to_client_handle),
                           0);
            }

            assert!(client_handle != ptr::null_mut());
            drop_client(client_handle);
        }

        {
            let mut client_handle: *mut FfiHandle = ptr::null_mut();

            {
                let ptr_to_client_handle = &mut client_handle;

                assert_eq!(log_in(cstring_keyword.as_ptr(),
                                  cstring_pin.as_ptr(),
                                  cstring_password.as_ptr(),
                                  ptr_to_client_handle),
                           0);
            }

            assert!(client_handle != ptr::null_mut());
            // let size_of_c_uint64 = ::std::mem::size_of::<::libc::int32_t>();
            // let c_size = unsafe { ::libc::malloc(size_of_c_uint64) } as *mut ::libc::int32_t;
            // let c_capacity = unsafe { ::libc::malloc(size_of_c_uint64) } as *mut ::libc::int32_t;
            // let c_result = unsafe { ::libc::malloc(size_of_c_uint64) } as *mut ::libc::int32_t;
            // let ptr = get_safe_drive_key(c_size, c_capacity, c_result, client_handle);
            // unsafe {
            //     let res = *c_result;
            //     assert_eq!(res, 0);
            //     let t = *ptr as *mut u8;
            //     drop_vector(t, *c_size, *c_capacity);
            // }


            drop_client(client_handle);
        }
    }

    // Enable this test when doing explicit file-logging
    #[test]
    #[ignore]
    fn file_logging() {
        assert_eq!(init_logging(), 0);

        let debug_msg = "This is a sample debug message".to_owned();
        let junk_msg = "This message should not exist in the log file".to_owned();

        debug!("{}", debug_msg);

        thread::sleep(Duration::from_secs(1));

        let mut current_exe_path = unwrap!(env::current_exe());

        assert!(current_exe_path.set_extension("log"));

        // Give sometime to the async logging to flush in the background thread
        thread::sleep(Duration::from_millis(50));

        let mut log_file = unwrap!(File::open(current_exe_path));
        let mut file_content = String::new();

        let written = unwrap!(log_file.read_to_string(&mut file_content));
        assert!(written > 0);

        assert!(file_content.contains(&debug_msg[..]));
        assert!(!file_content.contains(&junk_msg[..]));
    }
}
