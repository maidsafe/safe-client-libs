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

/// Converts a result into a pair of `(error_code: i32, description: CString)`
/// to be used in `FfiResult`
#[macro_export]
macro_rules! ffi_error {
    ($error:expr) => {{
        let err_code = ffi_error_code!($error);
        let err_desc = format!("{}", $error);
        (err_code, unwrap!(::std::ffi::CString::new(err_desc)))
    }}
}

/// Converts a result into a pair of `(error_code: i32, description: CString)`
/// to be used in `FfiResult`
#[macro_export]
macro_rules! ffi_result {
    ($res:expr) => {
        match $res {
            Ok(_) => (0, ::std::ffi::CString::default()),
            Err(error) => ffi_error!(error)
        }
    }
}

#[macro_export]
macro_rules! ffi_result_code {
    ($res:expr) => {
        match $res {
            Ok(_) => 0,
            Err(error) => ffi_error_code!(error),
        }
    }
}

#[macro_export]
macro_rules! ffi_error_code {
    ($err:expr) => {{
        #[cfg_attr(feature = "cargo-clippy", allow(useless_attribute))]
        #[allow(unused)]
        use $crate::ErrorCode;

        let err = &$err;
        let err_str = format!("{:?}", err);
        let err_code = err.error_code();

        debug!("**ERRNO: {}** {}", err_code, err_str);
        err_code
    }}
}

#[macro_export]
macro_rules! call_result_cb {
    ($result:expr, $user_data:expr, $cb:expr) => {
        #[cfg_attr(feature = "cargo-clippy", allow(useless_attribute))]
        #[allow(unused)]
        use $crate::callback::{Callback, CallbackArgs};
        let (error_code, description) = ffi_result!($result);
        $cb.call($user_data.into(), FfiResult {
            error_code,
            description: description.as_ptr()
        }, CallbackArgs::default());
    }
}

#[macro_export]
macro_rules! try_cb {
    ($result:expr, $user_data:expr, $cb:expr) => {
        match $result {
            Ok(value) => value,
            e @ Err(_) => {
                call_result_cb!(e, $user_data, $cb);
                return None;
            }
        }
    }
}
