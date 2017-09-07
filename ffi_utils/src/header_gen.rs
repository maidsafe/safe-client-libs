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

//! Tools for automatic header generation in build scripts.

extern crate cheddar;

use std::fs::File;
use std::io;
use std::io::{Read, Write};
use std::path::Path;

/// Generate C headers for the current project. Should be called from a build script.
/// Assumes that all modules are submodules of a module called "ffi".
pub fn gen_headers(header_name: &str, header_directory: &str, modules: &[&str]) -> io::Result<()> {
    // Parse submodules
    let mut mod_paths: Vec<String> = Vec::new();

    for module in modules {
        let transformed = module.replace("::", "/");
        // Keep submodules in safe_app/ folder
        let header_path = transformed.replace("ffi", header_name);
        let full_path = format!("{}{}.h", header_directory, header_path);

        cheddar::Cheddar::new()
            .expect("could not read manifest")
            .module(module)
            .expect("malformed module path")
            .run_build(&full_path);

        file_contents_replace(&full_path)?;
        mod_paths.push(header_path);
    }

    // Parse main FFI module into header file safe_app.h

    let path = format!("{}{}.h", header_directory, header_name);
    let mut cheddar = cheddar::Cheddar::new().expect("could not read manifest");
    let mut cheddar = cheddar.module("ffi").expect("malformed module path");

    // Include header files
    for path in mod_paths {
        let _ = cheddar.insert_code(&format!("#include \"{}.h\"\n", path));
    }
    cheddar.run_build(&path);

    file_contents_replace(&path)?;

    Ok(())
}

// Replace occurrences of "c_char" and "c_void" in the file with "char" and "void".
// Remove this if it ever gets fixed in cheddar.
fn file_contents_replace(fname: &str) -> io::Result<()> {
    let contents = read_file_str(fname)?;

    let contents = contents.replace("c_char", "char");
    let contents = contents.replace("c_void", "void");

    write_file_str(fname, &contents)?;
    Ok(())
}

// Reads a file and returns its contents in a string.
fn read_file_str(fname: &str) -> io::Result<String> {
    let path = Path::new(fname);
    // Open the path in read-only mode
    let mut file = File::open(&path)?;

    let mut contents = String::new();
    let _ = file.read_to_string(&mut contents)?;

    Ok(contents)
}

// Writes a string to a file.
fn write_file_str(fname: &str, contents: &str) -> io::Result<()> {
    let path = Path::new(fname);
    // Open a file in write-only mode
    let mut file = File::create(&path)?;

    file.write_all(contents.as_bytes())?;

    Ok(())
}
