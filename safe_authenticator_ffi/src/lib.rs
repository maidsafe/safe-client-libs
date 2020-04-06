// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

//! SAFE App.

#![doc(
    html_logo_url = "https://raw.githubusercontent.com/maidsafe/QA/master/Images/
maidsafe_logo.png",
    html_favicon_url = "http://maidsafe.net/img/favicon.ico",
    test(attr(forbid(warnings)))
)]
// For explanation of lint checks, run `rustc -W help`.
#![warn(
    missing_docs,
    trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    unused_results
)]
#![allow(
    // Our unsafe FFI functions are missing safety documentation. It is probably not necessary for
    // us to provide this for every single function as that would be repetitive and verbose.
    clippy::missing_safety_doc,
    unsafe_code
)]

// Export FFI interface

#[cfg(any(test, feature = "testing"))]
pub mod test_utils;
#[cfg(test)]
mod tests;

pub mod ffi;

pub use crate::ffi::apps::*;
pub use crate::ffi::errors::codes::*;
pub use crate::ffi::helpers::*;
pub use crate::ffi::ipc::*;
pub use crate::ffi::logging::*;
pub use crate::ffi::*;
