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

use ffi::errors::FfiError;
use ffi::{Action, ParameterPacket, ResponseType, helper};
use nfs::directory_listing::DirectoryListing;
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
        let org_parent_of_src_dir = try!(src_dir.get_metadata()
            .get_parent_dir_key()
            .cloned()
            .ok_or(FfiError::from("Parent directory not found")));
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
                                                         .cloned()));
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
        if !self.retain_source {
            let _ = try!(directory_helper.update(&src_dir));
            let mut parent_of_src_dir = try!(directory_helper.get(&org_parent_of_src_dir));
            try!(parent_of_src_dir.remove_sub_directory(src_dir.get_metadata()
                .get_name()));
            let _ = try!(directory_helper.update(&parent_of_src_dir));
        }
        Ok(None)
    }
}

#[cfg(test)]
mod test {
    use ffi::{Action, ParameterPacket, test_utils};
    use nfs::helper::directory_helper::DirectoryHelper;
    use nfs::{AccessLevel, UNVERSIONED_DIRECTORY_LISTING_TAG};
    use super::MoveDirectory;

    fn create_directories(parameter_packet: &ParameterPacket) {
        let dir_helper = DirectoryHelper::new(parameter_packet.client.clone());
        let app_root_dir_key = unwrap!(parameter_packet.clone().app_root_dir_key);
        let mut app_root_dir = unwrap!(dir_helper.get(&app_root_dir_key));
        let _ = unwrap!(dir_helper.create(String::from("ParentA"),
                                          UNVERSIONED_DIRECTORY_LISTING_TAG,
                                          vec![0u8, 0],
                                          false,
                                          AccessLevel::Private,
                                          Some(&mut app_root_dir)));
        let mut app_root_dir = unwrap!(dir_helper.get(&app_root_dir_key));
        let _ = unwrap!(dir_helper.create(String::from("ParentB"),
                                          UNVERSIONED_DIRECTORY_LISTING_TAG,
                                          vec![0u8, 0],
                                          false,
                                          AccessLevel::Private,
                                          Some(&mut app_root_dir)));
    }

    #[test]
    fn move_dir() {
        let parameter_packet = unwrap!(test_utils::get_parameter_packet(false));
        let dir_helper = DirectoryHelper::new(parameter_packet.client.clone());
        let app_root_dir_key = unwrap!(parameter_packet.clone().app_root_dir_key);
        create_directories(&parameter_packet);
        let dest_dir_name = String::from("ParentB");
        let app_root_dir = unwrap!(dir_helper.get(&app_root_dir_key));
        assert_eq!(app_root_dir.get_sub_directories().len(), 2);
        let dest_dir_key = unwrap!(app_root_dir.find_sub_directory(&dest_dir_name)).get_key();
        let dest_dir = unwrap!(dir_helper.get(&dest_dir_key));
        assert_eq!(dest_dir.get_sub_directories().len(), 0);
        let mut request = MoveDirectory {
            src_path: String::from("/ParentA"),
            is_src_path_shared: false,
            dest_path: String::from("/ParentB"),
            is_dest_path_shared: false,
            retain_source: false,
        };
        let _ = unwrap!(request.execute(parameter_packet.clone()));
        let dir_helper = DirectoryHelper::new(parameter_packet.client.clone());
        let app_root_dir_key = unwrap!(parameter_packet.clone().app_root_dir_key);
        let app_root_dir = unwrap!(dir_helper.get(&app_root_dir_key));
        assert_eq!(app_root_dir.get_sub_directories().len(), 1);
        let dest_dir = unwrap!(dir_helper.get(&dest_dir_key));
        assert_eq!(dest_dir.get_sub_directories().len(), 1);
    }


    #[test]
    fn copy_dir() {
        let parameter_packet = unwrap!(test_utils::get_parameter_packet(false));
        let dir_helper = DirectoryHelper::new(parameter_packet.client.clone());
        let app_root_dir_key = unwrap!(parameter_packet.clone().app_root_dir_key);
        create_directories(&parameter_packet);
        let dest_dir_name = String::from("ParentB");
        let app_root_dir = unwrap!(dir_helper.get(&app_root_dir_key));
        assert_eq!(app_root_dir.get_sub_directories().len(), 2);
        let dest_dir_key = unwrap!(app_root_dir.find_sub_directory(&dest_dir_name)).get_key();
        let dest_dir = unwrap!(dir_helper.get(&dest_dir_key));
        assert_eq!(dest_dir.get_sub_directories().len(), 0);
        let mut request = MoveDirectory {
            src_path: String::from("/ParentA"),
            is_src_path_shared: false,
            dest_path: String::from("/ParentB"),
            is_dest_path_shared: false,
            retain_source: true,
        };
        let _ = unwrap!(request.execute(parameter_packet.clone()));
        let dir_helper = DirectoryHelper::new(parameter_packet.client.clone());
        let app_root_dir_key = unwrap!(parameter_packet.clone().app_root_dir_key);
        let app_root_dir = unwrap!(dir_helper.get(&app_root_dir_key));
        assert_eq!(app_root_dir.get_sub_directories().len(), 2);
        let dest_dir = unwrap!(dir_helper.get(&dest_dir_key));
        assert_eq!(dest_dir.get_sub_directories().len(), 1);
    }
}
