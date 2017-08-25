// Copyright 2017 MaidSafe.net limited.
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

//! Logging utilities

use super::AppError;
use config_file_handler::FileHandler;
use ffi_utils::{FFI_RESULT_OK, FfiResult, catch_unwind_cb, from_c_str};
use maidsafe_utilities::log;
use std::ffi::CString;
use std::os::raw::{c_char, c_void};

/// This function should be called to enable logging to a file.
/// If `output_file_name_override` is provided, then this path will be used for
/// the log output file.
#[no_mangle]
pub unsafe extern "C" fn app_init_logging(
    output_file_name_override: *const c_char,
    user_data: *mut c_void,
    o_cb: extern "C" fn(*mut c_void, FfiResult),
) {
    catch_unwind_cb(user_data, o_cb, || -> Result<(), AppError> {
        if output_file_name_override.is_null() {
            log::init(false)?;
        } else {
            let output_file_name_override = from_c_str(output_file_name_override)?;
            log::init_with_output_file(false, output_file_name_override)?;
        }
        o_cb(user_data, FFI_RESULT_OK);
        Ok(())
    });
}

/// This function should be called to find where log file will be created. It
/// will additionally create an empty log file in the path in the deduced
/// location and will return the file name along with complete path to it.
#[no_mangle]
pub unsafe extern "C" fn app_output_log_path(
    output_file_name: *const c_char,
    user_data: *mut c_void,
    o_cb: extern "C" fn(*mut c_void, FfiResult, *const c_char),
) {
    catch_unwind_cb(user_data, o_cb, || -> Result<(), AppError> {
        let op_file = from_c_str(output_file_name)?;
        let fh = FileHandler::<()>::new(&op_file, true).map_err(|e| {
            AppError::Unexpected(format!("{}", e))
        })?;
        let op_file_path = CString::new(
            fh.path()
                .to_path_buf()
                .into_os_string()
                .into_string()
                .map_err(|_| {
                    AppError::Unexpected("Couldn't convert OsString".to_string())
                })?
                .into_bytes(),
        )?;
        o_cb(user_data, FFI_RESULT_OK, op_file_path.as_ptr());
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use config_file_handler::current_bin_dir;
    use ffi_utils::test_utils::call_0;
    use std::env;
    use std::fs::{self, File};
    use std::io::Read;
    use std::thread;
    use std::time::Duration;

    // Test logging errors to file.
    #[test]
    fn file_logging() {
        setup_log_config();

        let mut current_exe_path = unwrap!(current_bin_dir());
        current_exe_path.push("secret-log-output.log");

        let log_file_path = unwrap!(CString::new(unwrap!(
            current_exe_path.clone().into_os_string().into_string()
        )));
        unsafe {
            unwrap!(call_0(
                |ud, cb| app_init_logging(log_file_path.as_ptr(), ud, cb),
            ));
        }

        let debug_msg = "This is a sample debug message".to_owned();
        let junk_msg = "This message should not exist in the log file".to_owned();

        error!("{}", debug_msg);
        debug!("{}", junk_msg);

        // Give some time to the async logging to flush in the background thread
        thread::sleep(Duration::from_secs(1));

        let mut log_file = unwrap!(File::open(current_exe_path));
        let mut file_content = String::new();

        let written = unwrap!(log_file.read_to_string(&mut file_content));
        assert!(written > 0);

        assert!(file_content.contains(&debug_msg[..]));
        assert!(!file_content.contains(&junk_msg[..]));
    }

    fn setup_log_config() {
        let mut current_dir = unwrap!(env::current_dir());
        let mut current_bin_dir = unwrap!(current_bin_dir());

        if current_dir.as_path() != current_bin_dir.as_path() {
            // Try to copy log.toml from the current dir to bin dir
            // so that the config_file_handler can find it
            current_dir.push("sample_log_file/log.toml");
            current_bin_dir.push("log.toml");

            let _ = unwrap!(fs::copy(current_dir, current_bin_dir));
        }
    }
}
