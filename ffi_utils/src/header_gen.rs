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
extern crate regex;

use std::collections::HashMap;
use std::collections::HashSet;
use std::fs::File;
use std::io;
use std::io::{Error, Read, Write};
use std::io::ErrorKind::NotFound;

/// Generate C headers for the current project. Should be called from a build script.
/// Assumes that all modules are submodules of "ffi".
pub fn gen_headers(header_name: &str, header_directory: &str, root_file: &str) -> io::Result<()> {
    gen_headers_custom_code(
        header_name,
        header_directory,
        root_file,
        &HashMap::new(),
        &HashSet::new(),
    )
}

/// Generate C headers, inserting custom code and/or ignoring modules.
pub fn gen_headers_custom_code(
    header_name: &str,
    header_directory: &str,
    root_file: &str,
    custom_code: &HashMap<String, String>,
    ignore_modules: &HashSet<String>,
) -> io::Result<()> {
    // Parse submodules

    let modules = parse_root(root_file)?;
    let mut mod_paths: Vec<String> = Vec::new();

    for module in modules {
        let transformed = module.replace("::", "/");
        // Keep submodules in a folder named `header_name`
        let header_path = transformed.replace("ffi", header_name);
        let full_path = format!("{}{}.h", header_directory, header_path);
        let insert_code = match custom_code.get(&module) {
            Some(code) => code,
            None => "",
        };

        let mut cheddar = cheddar::Cheddar::new().expect("could not read manifest");
        let mut cheddar = if !ignore_modules.contains(&module) {
            cheddar.module(&module).expect("malformed module path")
        } else {
            &mut cheddar
        };
        cheddar.insert_code(insert_code).run_build(&full_path);

        file_contents_replace(&full_path)?;
        mod_paths.push(header_path);
    }

    // Parse main FFI module into header file

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

// Parse given root file (such as lib.rs) and return all `pub use`d modules starting with `ffi::`.
fn parse_root(fname: &str) -> io::Result<Vec<String>> {
    let contents = read_file_str(fname)?;
    let mut modules = Vec::new();
    let mut found = false;
    let re_pub_use = unwrap!(regex::Regex::new(r"^pub use ffi::.*\*;$"));
    let re_module = unwrap!(regex::Regex::new(r"ffi::.*\*"));

    for line in contents.lines() {
        if re_pub_use.is_match(line) {
            let mat = unwrap!(re_module.find(line));
            let module = String::from(&line[mat.start()..mat.end() - 3]);
            if module == "ffi" {
                found = true;
            } else {
                modules.push(module)
            }
        }
    }

    if !found {
        // No top-level "ffi" module was found.
        Err(Error::new(
            NotFound,
            "Consider adding `pub use ffi::*;` to lib.rs.",
        ))
    } else {
        Ok(modules)
    }
}

// Replace occurrences of "c_char" and "c_void" in the file with "char" and "void".
// Remove this if it ever gets fixed in cheddar.
fn file_contents_replace(fname: &str) -> io::Result<()> {
    let contents = read_file_str(fname)?;
    // Check for word boundaries when replacing.
    let re_char = unwrap!(regex::Regex::new(r"\bc_char\b"));
    let re_void = unwrap!(regex::Regex::new(r"\bc_void\b"));

    let contents = re_char.replace_all(&contents, "char");
    let contents = re_void.replace_all(&contents, "void");

    write_file_str(fname, &contents)?;
    Ok(())
}

// Reads a file and returns its contents in a string.
fn read_file_str(fname: &str) -> io::Result<String> {
    // Open the path in read-only mode
    let mut file = File::open(fname)?;

    let mut contents = String::new();
    let _ = file.read_to_string(&mut contents)?;

    Ok(contents)
}

// Writes a string to a file.
fn write_file_str(fname: &str, contents: &str) -> io::Result<()> {
    // Open a file in write-only mode
    let mut file = File::create(fname)?;

    file.write_all(contents.as_bytes())?;

    Ok(())
}
