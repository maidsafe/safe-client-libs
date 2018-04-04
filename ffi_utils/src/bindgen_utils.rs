// Copyright 2018 MaidSafe.net limited.
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

//! Utilities for binding generators.

use std::fs;
use std::io;
use std::path::Path;
use walkdir::WalkDir;

/// Recursively copy all files with the given extension from the source to the
/// targt directories.
pub fn copy_files<S: AsRef<Path>, T: AsRef<Path>>(
    source: S,
    target: T,
    extension: &str,
) -> io::Result<()> {
    let source = source.as_ref();
    let target = target.as_ref();

    for entry in WalkDir::new(source) {
        let entry = entry?;

        if entry.path().is_file() {
            if entry
                .path()
                .to_str()
                .map(|s| s.ends_with(extension))
                .unwrap_or(false)
            {
                let source_path = entry.path();
                let target_path =
                    target.join(source_path.strip_prefix(source).unwrap_or(&source_path));

                let _ = fs::copy(source_path, target_path)?;
            }
        }
    }

    Ok(())
}
