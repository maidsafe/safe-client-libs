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
extern crate routing;
extern crate rust_sodium;

use routing::XOR_NAME_LEN;
use rust_sodium::crypto::{box_, secretbox, sign};
use std::collections::HashMap;
use std::collections::HashSet;
use std::env;

fn main() {
    if env::var("CARGO_FEATURE_BINDINGS").is_err() {
        return;
    }

    gen_bindings_c();
}

fn gen_bindings_c() {
    // Ignore the ffi::arrays module until moz_cheddar can handle it.
    let mut ignore_modules = HashSet::new();
    ignore_modules.insert(String::from("ffi::arrays"));

    let mut custom_code = HashMap::new();
    custom_code.insert(
        String::from("ffi::arrays"),
        format!(
            "typedef unsigned char AsymPublicKey[{}];\n\
             typedef unsigned char AsymSecretKey[{}];\n\
             typedef unsigned char AsymNonce[{}];\n\
             typedef unsigned char SymSecretKey[{}];\n\
             typedef unsigned char SymNonce[{}];\n\
             typedef unsigned char SignPublicKey[{}];\n\
             typedef unsigned char SignSecretKey[{}];\n\
             typedef unsigned char XorNameArray[{}];",
            box_::PUBLICKEYBYTES,
            box_::SECRETKEYBYTES,
            box_::NONCEBYTES,
            secretbox::KEYBYTES,
            secretbox::NONCEBYTES,
            sign::PUBLICKEYBYTES,
            sign::SECRETKEYBYTES,
            XOR_NAME_LEN
        ),
    );

    unwrap!(ffi_utils::header_gen::gen_headers_custom_code(
        &env::var("CARGO_PKG_NAME").unwrap(),
        "../bindings/c/",
        "src/lib.rs",
        &custom_code,
        &ignore_modules,
    ));
}
