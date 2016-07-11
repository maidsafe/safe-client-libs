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

macro_rules! ffi_try {
    ($result:expr) => {
        match $result {
            Ok(value)  => value,
            Err(error) => {
                let decorator = ::std::iter::repeat('-').take(50).collect::<String>();
                error!("\n\n {}\n| {:?}\n {}\n\n", decorator, error, decorator);
                return error.into()
            },
        }
    }
}

macro_rules! ffi_ptr_try {
    ($result:expr, $out:expr) => {
        match $result {
            Ok(value)  => value,
            Err(error) => {
                let decorator = ::std::iter::repeat('-').take(50).collect::<String>();
                error!("\n\n {}\n| {:?}\n {}\n\n", decorator, error, decorator);
                ::std::ptr::write($out, error.into());
                return ::std::ptr::null();
            },
        }
    }
}


/// This macro is intended to be used in all cases where we get an Err out of Result<T, U> and want
/// to package it into `safe_core::ffi::errors::FfiError::SpecificParseError(String)`. This is
/// useful because there may be miscellaneous erros while parsing through a valid JSON due to JSON
/// not conforming to certain mandatory requirements. This can then be communicated back to the
/// JSON sending client.
///
/// #Examples
///
/// ```
/// # #[macro_use] extern crate safe_core;
/// # #[allow(unused)]
/// #[derive(Debug)]
/// enum SomeSpecialError {
///     Zero,
///     One,
/// }
///
/// fn f() -> Result<String, SomeSpecialError> {
///     Err(SomeSpecialError::One)
/// }
///
/// fn g() -> Result<(), safe_core::ffi::errors::FfiError> {
///     let _module = try!(parse_result!(f(), ""));
///
///     Ok(())
/// }
///
/// fn main() {
///     if let Err(err) = g() {
///         println!("{:?}", err);
///     }
/// }
/// ```
#[macro_export]
macro_rules! parse_result {
    ($output:expr, $err_statement:expr) => {
        $output.map_err(|e| $crate::ffi::errors::FfiError::SpecificParseError(
            format!("{} {:?}", $err_statement.to_string(), e)))
    }
}
