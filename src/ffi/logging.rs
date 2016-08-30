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

//! Logging.

use config_file_handler::FileHandler;

use core::errors::CoreError;
use libc::int32_t;
use maidsafe_utilities::log as safe_log;
use std::mem;
use std::ptr;
use super::helper;

/// This function should be called to enable logging to a file
#[no_mangle]
pub extern "C" fn init_logging() -> int32_t {
    helper::catch_unwind_i32(|| {
        ffi_try!(safe_log::init(false).map_err(CoreError::Unexpected));
        0
    })
}

/// This function should be called to find where log file will be created. It will additionally
/// create an empty log file in the path in the deduced location and will return the file name
/// along with complete path to it.
#[no_mangle]
pub unsafe extern "C" fn output_log_path(c_output_file_name: *const u8,
                                         c_output_file_name_len: usize,
                                         c_size: *mut int32_t,
                                         c_capacity: *mut int32_t,
                                         c_result: *mut int32_t)
                                         -> *const u8 {
    helper::catch_unwind_ptr(|| {
        let op_file
            = ffi_ptr_try!(helper::c_utf8_to_string(c_output_file_name,
                                                    c_output_file_name_len),
                           c_result);
        let fh = ffi_ptr_try!(FileHandler::<()>::new(&op_file, true)
                                  .map_err(|e| CoreError::Unexpected(format!("{:?}", e))),
                              c_result);
        let op_file_path =
            ffi_ptr_try!(fh.path()
                             .to_path_buf()
                             .into_os_string()
                             .into_string()
                             .map_err(|e| CoreError::Unexpected(format!("{:?}", e))),
                         c_result)
                .into_bytes();

        ptr::write(c_size, op_file_path.len() as i32);
        ptr::write(c_capacity, op_file_path.capacity() as i32);
        ptr::write(c_result, 0);

        let ptr = op_file_path.as_ptr();
        mem::forget(op_file_path);

        ptr
    })
}

#[cfg(test)]
mod test {

    use std::env;
    use std::fs::File;
    use std::io::Read;
    use std::thread;
    use std::time::Duration;
    use super::*;

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
