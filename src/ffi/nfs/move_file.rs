// Copyright 2015 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use ffi::{helper, ParameterPacket, ResponseType, Action};
use nfs::directory_listing::DirectoryListing;
use ffi::errors::FfiError;
use nfs::errors::NfsError::DirectoryAlreadyExistsWithSameName;
use nfs::helper::directory_helper::DirectoryHelper;

#[derive(RustcDecodable, Debug)]
pub struct MoveFile {
    src_path: String,
    is_src_path_shared: bool,
    dest_path: String,
    is_dest_path_shared: bool,
    retain_source: bool,
}

impl MoveFile {
    fn get_directory_and_file(&self,
                              params: &ParameterPacket,
                              shared: bool,
                              path: &str)
                              -> Result<(DirectoryListing, String), FfiError> {
        let start_dir_key = if shared {
            try!(params.clone()
                .safe_drive_dir_key
                .ok_or(FfiError::from("Safe Drive directory key is not present")))
        } else {
            try!(params.clone()
                .app_root_dir_key
                .ok_or(FfiError::from("Application directory key is not present")))
        };

        let mut tokens = helper::tokenise_path(path, false);
        let file_name = try!(tokens.pop().ok_or(FfiError::PathNotFound));
        let directory_listing = try!(helper::get_final_subdirectory(params.client.clone(),
                                                                    &tokens,
                                                                    Some(&start_dir_key)));
        Ok((directory_listing, file_name))
    }

    fn get_directory(&self,
                     params: &ParameterPacket,
                     shared: bool,
                     path: &str)
                     -> Result<DirectoryListing, FfiError> {
        let start_dir_key = if shared {
            try!(params.clone()
                .safe_drive_dir_key
                .ok_or(FfiError::from("Safe Drive directory key is not present")))
        } else {
            try!(params.clone()
                .app_root_dir_key
                .ok_or(FfiError::from("Application directory key is not present")))
        };

        let tokens = helper::tokenise_path(path, false);
        helper::get_final_subdirectory(params.client.clone(), &tokens, Some(&start_dir_key))
    }
}

impl Action for MoveFile {
    fn execute(&mut self, params: ParameterPacket) -> ResponseType {
        if (self.is_src_path_shared || self.is_dest_path_shared) && !params.safe_drive_access {
            return Err(FfiError::PermissionDenied);
        }
        let directory_helper = DirectoryHelper::new(params.client.clone());
        let (mut src_dir, src_file_name) =
            try!(self.get_directory_and_file(&params, self.is_src_path_shared, &self.src_path));
        let mut dest_dir =
            try!(self.get_directory(&params, self.is_dest_path_shared, &self.dest_path));
        if dest_dir.find_file(&src_file_name).is_some() {
            return Err(FfiError::from(DirectoryAlreadyExistsWithSameName));
        }
        let file = match src_dir.find_file(&src_file_name).map(|file| file.clone()) {
            Some(file) => file,
            None => return Err(FfiError::PathNotFound),
        };
        dest_dir.upsert_file(file);
        let _ = try!(directory_helper.update(&dest_dir));
        if !self.retain_source {
            try!(src_dir.remove_file(&src_file_name));
            let _ = try!(directory_helper.update(&src_dir));
        }
        Ok(None)
    }
}
