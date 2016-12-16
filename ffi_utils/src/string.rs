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

//! Utilities for passing strings across FFI boundaries.

use std::mem;
use std::ptr;
use std::slice;
use std::str::{self, Utf8Error};

/// Wrapper for strings to be passed across FFI boundary.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FfiString {
    /// Pointer to first byte
    pub ptr: *mut u8,
    /// Length in bytes
    pub len: usize,
    /// Capacity in bytes
    pub cap: usize,
}

impl FfiString {
    /// Construct owning `FfiString` from `String`. It has to be deallocated
    /// manually by calling `ffi_string_free`.
    pub fn from_string<T: Into<String>>(s: T) -> Self {
        let s = s.into();
        let ptr = s.as_ptr();
        let len = s.len();
        let cap = s.capacity();
        mem::forget(s);

        FfiString {
            ptr: ptr as *mut _,
            len: len,
            cap: cap,
        }
    }

    /// Construct non-owning `FfiSting` from `&str`.
    pub fn from_str<T: AsRef<str>>(s: T) -> Self {
        let s = s.as_ref();

        FfiString {
            ptr: s.as_ptr() as *mut _,
            len: s.len(),
            cap: s.len(),
        }
    }

    /// Convert this `FfiString` to rust `String` by cloning the data.
    pub unsafe fn to_string(&self) -> Result<String, Utf8Error> {
        let s = slice::from_raw_parts(self.ptr, self.len);
        String::from_utf8(s.to_vec()).map_err(|e| e.utf8_error())
    }

    /// Borrow this `FfiString` as `&str`.
    pub unsafe fn as_str(&self) -> Result<&str, Utf8Error> {
        let s = slice::from_raw_parts(self.ptr, self.len);
        str::from_utf8(s)
    }
}

impl Default for FfiString {
    fn default() -> Self {
        FfiString {
            ptr: ptr::null_mut(),
            len: 0,
            cap: 0,
        }
    }
}

/// Free the string from memory.
#[no_mangle]
pub unsafe extern "C" fn ffi_string_free(s: FfiString) {
    let _ = String::from_raw_parts(s.ptr, s.len, s.cap);
}

#[cfg(test)]
mod tests {
    extern crate rand;
    use self::rand::{Rng, thread_rng};
    use super::*;

    #[test]
    fn conversion() {
        let in_string = random_string(100);
        let ffi_string = FfiString::from_str(&in_string);

        let out_string = unsafe { unwrap!(ffi_string.to_string()) };
        let out_str = unsafe { unwrap!(ffi_string.as_str()) };

        assert_eq!(in_string, out_string);
        assert_eq!(in_string.as_str(), out_str);
    }

    fn random_string(len: usize) -> String {
        let mut rng = thread_rng();
        (0..len).map(|_| rng.gen::<char>()).collect()
    }
}
