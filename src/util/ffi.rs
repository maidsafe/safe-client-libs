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

#![allow(unsafe_code)]

use rand::{OsRng, Rand, Rng};
use std::{io, iter, mem, slice, str};
use std::ffi::CString;
use std::fmt::Debug;
use std::os::raw::c_void;
use std::panic::{self, AssertUnwindSafe};
use std::str::Utf8Error;
use std::string::FromUtf8Error;

/// Logs an error and returns a numeric error code as a result
pub fn ffi_error_code<E: Into<i32> + Debug>(err: E) -> i32 {
    let decorator = iter::repeat('-').take(50).collect::<String>();
    let err_str = format!("{:?}", err);
    let err_code: i32 = err.into();
    info!("\nFFI cross-boundary error propagation:\n {}\n| **ERRNO: {}** {}\n {}\n\n",
          decorator,
          err_code,
          err_str,
          decorator);
    err_code
}

/// Returns a numeric error code for a given result (0 for success)
#[inline]
pub fn ffi_result_code<T, E: Into<i32> + Debug>(res: Result<T, E>) -> i32 {
    match res {
        Ok(_) => 0,
        Err(error) => ffi_error_code(error),
    }
}

/// Type that holds opaque user data handed into FFI functions
#[derive(Clone, Copy)]
pub struct OpaqueCtx(pub *mut c_void);
unsafe impl Send for OpaqueCtx {}

impl Into<*mut c_void> for OpaqueCtx {
    fn into(self) -> *mut c_void {
        self.0
    }
}

fn catch_unwind_result<'a, T, E: Debug + From<&'a str>, F: FnOnce() -> Result<T, E>>
    (f: F)
     -> Result<T, E> {
    match panic::catch_unwind(AssertUnwindSafe(f)) {
        Err(_) => Err(E::from("panic")),
        Ok(result) => result,
    }
}

/// Catch panics. On error return the error code.
pub fn catch_unwind_error_code<'a,
                               E: Debug + Into<i32> + From<&'a str>,
                               F: FnOnce() -> Result<(), E>>
    (f: F)
     -> i32 {
    ffi_result_code(catch_unwind_result(f))
}

/// Converts a byte pointer to String
pub unsafe fn c_utf8_to_string(ptr: *const u8, len: usize) -> Result<String, Utf8Error> {
    c_utf8_to_str(ptr, len).map(|v| v.to_owned())
}

/// Converts a byte pointer to str
pub unsafe fn c_utf8_to_str(ptr: *const u8, len: usize) -> Result<&'static str, Utf8Error> {
    str::from_utf8(slice::from_raw_parts(ptr, len))
}

/// Converts a null pointer to None and a valid pointer to Some(String)
pub unsafe fn c_utf8_to_opt_string(ptr: *const u8,
                                   len: usize)
                                   -> Result<Option<String>, FromUtf8Error> {
    if ptr.is_null() {
        Ok(None)
    } else {
        String::from_utf8(slice::from_raw_parts(ptr, len).to_owned()).map(Some)
    }
}

// TODO: add c_utf8_to_opt_str (return Option<&str> instead of Option<String>)

/// Returns a heap-allocated raw string, usable by C/FFI-boundary. The tuple
/// means (pointer, length in bytes, capacity). Use `misc_u8_ptr_free` to free
/// the memory.
pub fn string_to_c_utf8(s: String) -> (*mut u8, usize, usize) {
    u8_vec_to_ptr(s.into_bytes())
}

/// Converts a byte pointer to Vec<u8>
pub unsafe fn u8_ptr_to_vec(ptr: *const u8, len: usize) -> Vec<u8> {
    slice::from_raw_parts(ptr, len).to_owned()
}

/// Converts null pointer to None and a valid pointer to Some(Vec<u8>)
pub unsafe fn u8_ptr_to_opt_vec(ptr: *const u8, len: usize) -> Option<Vec<u8>> {
    if ptr.is_null() {
        None
    } else {
        Some(u8_ptr_to_vec(ptr, len))
    }
}

/// Converts Vec<u8> to (byte pointer, size, capacity)
pub fn u8_vec_to_ptr(mut v: Vec<u8>) -> (*mut u8, usize, usize) {
    v.shrink_to_fit();
    let ptr = v.as_mut_ptr();
    let len = v.len();
    let cap = v.capacity();
    mem::forget(v);
    (ptr, len, cap)
}

/// Generate a random vector of given length
pub fn generate_random_vector<T>(length: usize) -> io::Result<Vec<T>>
    where T: Rand
{
    let mut os_rng = OsRng::new()?;
    Ok((0..length).map(|_| os_rng.gen()).collect())
}

/// Generates a random C string for tests
pub fn generate_random_cstring(len: usize) -> CString {
    let mut cstring_vec = unwrap!(generate_random_vector::<u8>(len));

    // Avoid internal nulls and ensure valid ASCII (thus valid utf8)
    for it in &mut cstring_vec {
        *it %= 128;
        if *it == 0 {
            *it += 1;
        }
    }

    // Ok to unwrap, as we took care of removing all NULs above.
    unwrap!(CString::new(cstring_vec))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn string_conversion() {
        let (ptr, size, cap) = string_to_c_utf8(String::new());
        assert_eq!(size, 0);
        unsafe {
            let _ = Vec::from_raw_parts(ptr, size, cap);
        }

        let (ptr, size, cap) = string_to_c_utf8("hello world".to_owned());
        assert!(!ptr.is_null());
        assert_eq!(size, 11);
        assert!(cap >= 11);
        unsafe {
            let _ = Vec::from_raw_parts(ptr, size, cap);
        }
    }
}
