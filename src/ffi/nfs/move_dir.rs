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
pub struct MoveDirectory {
    src_path: String,
    is_src_path_shared: bool,
    dest_path: String,
    is_dest_path_shared: bool,
    retain_source: bool,
}

impl MoveDirectory {
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

impl Action for MoveDirectory {
    fn execute(&mut self, params: ParameterPacket) -> ResponseType {
        if (self.is_src_path_shared || self.is_dest_path_shared) && !params.safe_drive_access {
            return Err(FfiError::PermissionDenied);
        }
        let directory_helper = DirectoryHelper::new(params.client.clone());
        let mut src_dir =
            try!(self.get_directory(&params, self.is_src_path_shared, &self.src_path));
        let mut dest_dir =
            try!(self.get_directory(&params, self.is_dest_path_shared, &self.dest_path));
        if dest_dir.find_sub_directory(src_dir.get_metadata().get_name()).is_some() {
            return Err(FfiError::from(DirectoryAlreadyExistsWithSameName));
        }
        let org_parent_of_src_dir = src_dir.get_metadata().get_key().clone();
        if self.retain_source {
            let name = src_dir.get_metadata().get_name().to_owned();
            let user_metadata = src_dir.get_metadata().get_user_metadata().to_owned();
            let access_level = src_dir.get_metadata().get_access_level().clone();
            let created_time = *src_dir.get_metadata().get_created_time();
            let modified_time = *src_dir.get_metadata().get_modified_time();
            let mut dir = try!(DirectoryListing::new(name,
                                                     src_dir.get_metadata()
                                                         .get_key()
                                                         .get_type_tag(),
                                                     user_metadata,
                                                     src_dir.get_metadata()
                                                         .get_key()
                                                         .is_versioned(),
                                                     access_level,
                                                     src_dir.get_metadata()
                                                         .get_parent_dir_key()
                                                         .map(|key| key.clone())));
            src_dir.get_files().iter().all(|file| {
                dir.get_mut_files().push(file.clone());
                true
            });
            src_dir.get_sub_directories()
                .iter()
                .all(|sub_dir| {
                    dir.get_mut_sub_directories().push(sub_dir.clone());
                    true
                });
            dir.get_mut_metadata().set_created_time(created_time);
            dir.get_mut_metadata().set_modified_time(modified_time);
            src_dir = dir;
        } else {
            src_dir.get_mut_metadata()
                .set_parent_dir_key(Some(dest_dir.get_metadata().get_key().clone()));
        }
        dest_dir.upsert_sub_directory(src_dir.get_metadata().clone());
        let _ = try!(directory_helper.update(&dest_dir));
        let _ = try!(directory_helper.update(&src_dir));
        if !self.retain_source {
            let mut parent_of_src_dir = try!(directory_helper.get(&org_parent_of_src_dir));
            try!(parent_of_src_dir.remove_sub_directory(dest_dir.get_metadata()
                .get_name()));
            let _ = try!(directory_helper.update(&parent_of_src_dir));
        }
        Ok(None)
    }
}
