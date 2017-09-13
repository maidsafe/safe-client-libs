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

//! Build script for generating C header files from FFI modules.

extern crate ffi_utils;
#[macro_use]
extern crate unwrap;

static HEADER_NAME: &'static str = "safe_app";
static HEADER_DIRECTORY: &'static str = "../auto-gen/c-include/";
static ROOT_FILE: &'static str = "src/lib.rs";

fn main() {
    unwrap!(ffi_utils::header_gen::gen_headers(
        HEADER_NAME,
        HEADER_DIRECTORY,
        ROOT_FILE,
    ));
}
