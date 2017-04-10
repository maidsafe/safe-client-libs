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

//! FFI utilities

#![doc(html_logo_url =
           "https://raw.githubusercontent.com/maidsafe/QA/master/Images/maidsafe_logo.png",
       html_favicon_url = "http://maidsafe.net/img/favicon.ico",
       html_root_url = "http://maidsafe.github.io/ffi_utils")]

// For explanation of lint checks, run `rustc -W help` or see
// https://github.com/maidsafe/QA/blob/master/Documentation/Rust%20Lint%20Checks.md
#![forbid(exceeding_bitshifts, mutable_transmutes, no_mangle_const_items,
          unknown_crate_types, warnings)]
#![deny(bad_style, deprecated, improper_ctypes, missing_docs,
        non_shorthand_field_patterns, overflowing_literals, plugin_as_library,
        private_no_mangle_fns, private_no_mangle_statics, stable_features,
        unconditional_recursion, unknown_lints, unused,
        unused_allocation, unused_attributes, unused_comparisons, unused_features,
        unused_parens, while_true)]
#![warn(trivial_casts, trivial_numeric_casts, unused_extern_crates, unused_import_braces,
        unused_qualifications, unused_results)]
#![allow(box_pointers, fat_ptr_transmutes, missing_copy_implementations,
         missing_debug_implementations, variant_size_differences)]

#![cfg_attr(feature="cargo-clippy", deny(clippy, unicode_not_nfc, wrong_pub_self_convention,
                                         option_unwrap_used))]
#![cfg_attr(feature="cargo-clippy", allow(use_debug, too_many_arguments))]

extern crate base64 as b64;
#[macro_use]
extern crate log;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate unwrap;

#[macro_use]
mod macros;
mod base64;
mod catch_unwind;
mod repr_c;
mod vec;

pub mod callback;
pub mod test_utils;
pub mod string;

pub use self::base64::{base64_decode, base64_encode};
pub use self::catch_unwind::{catch_unwind_cb, catch_unwind_error_code};
pub use self::repr_c::ReprC;
pub use self::string::{StringError, from_c_str};
pub use self::vec::{vec_clone_from_raw_parts, vec_into_raw_parts};
use std::os::raw::c_void;

/// Type that holds opaque user data handed into FFI functions
#[derive(Clone, Copy)]
pub struct OpaqueCtx(pub *mut c_void);
unsafe impl Send for OpaqueCtx {}

impl Into<*mut c_void> for OpaqueCtx {
    fn into(self) -> *mut c_void {
        self.0
    }
}

/// Trait for types that can be converted to integer error code.
pub trait ErrorCode {
    /// Return the error code corresponding to this instance.
    fn error_code(&self) -> i32;
}
