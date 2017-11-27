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

use super::{ErrorCode, FfiResult};
use super::callback::{Callback, CallbackArgs};
use std::fmt::{Debug, Display};
use std::os::raw::c_void;
use std::panic::{self, AssertUnwindSafe};

fn catch_unwind_result<'a, F, T, E>(f: F) -> Result<T, E>
where
    F: FnOnce() -> Result<T, E>,
    E: Debug + From<&'a str>,
{
    match panic::catch_unwind(AssertUnwindSafe(f)) {
        Err(_) => Err(E::from("panic")),
        Ok(result) => result,
    }
}

/// Catch panics. On error return the error code.
pub fn catch_unwind_error_code<'a, F, E>(f: F) -> i32
where
    F: FnOnce() -> Result<(), E>,
    E: Debug + ErrorCode + From<&'a str>,
{
    ffi_result_code!(catch_unwind_result(f))
}

/// Catch panics. On error call the callback.
pub fn catch_unwind_cb<'a, U, C, F, E>(user_data: U, cb: C, f: F)
where
    U: Into<*mut c_void>,
    C: Callback + Copy,
    F: FnOnce() -> Result<(), E>,
    E: Debug + Display + ErrorCode + From<&'a str>,
{
    if let Err(err) = catch_unwind_result(f) {
        let (error_code, description) = ffi_result!(Err::<(), E>(err));
        let res = FfiResult {
            error_code,
            description: description.as_ptr(),
        };
        cb.call(user_data.into(), &res, CallbackArgs::default());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt;

    #[test]
    fn panic_inside_catch_unwind_result() {
        let mut did_unwind = false;

        let res = catch_unwind_result(|| -> Result<(), TestError> {
            let _probe = DropProbe::new(|| did_unwind = true);
            panic!("simulated panic");
        });

        assert!(res.is_err());
        assert!(did_unwind);
    }

    #[test]
    fn panic_inside_catch_unwind_error_code() {
        let mut did_unwind = false;

        let res = catch_unwind_error_code(|| -> Result<(), TestError> {
            let _probe = DropProbe::new(|| did_unwind = true);
            panic!("simulated panic");
        });

        assert!(res < 0);
        assert!(did_unwind);
    }

    #[test]
    fn panic_inside_catch_unwind_cb() {
        extern "C" fn cb(user_data: *mut c_void, result: *const FfiResult) {
            unsafe {
                let error_code = user_data as *mut i32;
                *error_code = (*result).error_code;
            }
        }

        let mut did_unwind = false;
        let mut error_code = 0;

        let user_data: *mut i32 = &mut error_code;
        let user_data = user_data as *mut c_void;
        let cb: extern "C" fn(_, _) = cb;

        catch_unwind_cb(user_data, cb, || -> Result<(), TestError> {
            let _probe = DropProbe::new(|| did_unwind = true);
            panic!("simulated panic");
        });

        assert!(error_code < 0);
        assert!(did_unwind);
    }

    // Calls a callback on drop.
    struct DropProbe<F: FnOnce()>(Option<F>);

    impl<F: FnOnce()> DropProbe<F> {
        fn new(f: F) -> Self {
            DropProbe(Some(f))
        }
    }

    impl<F: FnOnce()> Drop for DropProbe<F> {
        fn drop(&mut self) {
            if let Some(f) = self.0.take() {
                f()
            }
        }
    }

    // Dummy error type for testing.
    #[derive(Debug)]
    struct TestError;

    impl<'a> From<&'a str> for TestError {
        fn from(_: &'a str) -> Self {
            TestError
        }
    }

    impl ErrorCode for TestError {
        fn error_code(&self) -> i32 {
            -1
        }
    }

    impl Display for TestError {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "Test Error")
        }
    }
}
