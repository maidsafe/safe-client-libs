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
use ffi::errors::FfiError;
use nfs::helper::directory_helper::DirectoryHelper;

#[derive(RustcDecodable, Debug)]
pub struct DeleteDir {
    dir_path: String,
    is_path_shared: bool,
}

impl Action for DeleteDir {
    fn execute(&mut self, params: ParameterPacket) -> ResponseType {
        let mut tokens = helper::tokenise_path(&self.dir_path, false);
        let dir_helper = DirectoryHelper::new(params.client.clone());
        let dir_to_delete = try!(tokens.pop().ok_or(FfiError::InvalidPath));
        let root_dir = if self.is_path_shared {
            try!(dir_helper.get(&try!(params.safe_drive_dir_key
                .ok_or(FfiError::from("Safe Drive directory key is not present")))))
        } else {
            try!(dir_helper.get(&try!(params.app_root_dir_key
                .ok_or(FfiError::from("Application directory key is not present")))))
        };

        let mut parent_dir = if tokens.len() == 0 {
            root_dir
        } else {
            try!(helper::get_final_subdirectory(params.client,
                                                &tokens,
                                                Some(root_dir.get_metadata()
                                                    .get_key())))
        };
        let _ = try!(dir_helper.delete(&mut parent_dir, &dir_to_delete));

        Ok(None)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ffi::{Action, test_utils};
    use nfs::{AccessLevel, UNVERSIONED_DIRECTORY_LISTING_TAG};
    use nfs::helper::directory_helper::DirectoryHelper;

    #[test]
    fn delete_dir() {
        let parameter_packet = unwrap_result!(test_utils::get_parameter_packet(false));

        let dir_helper = DirectoryHelper::new(parameter_packet.client.clone());
        let app_root_dir_key = unwrap_option!(parameter_packet.clone().app_root_dir_key, "");
        let mut app_root_dir = unwrap_result!(dir_helper.get(&app_root_dir_key));
        let _ = unwrap_result!(dir_helper.create("test_dir".to_string(),
                                                 UNVERSIONED_DIRECTORY_LISTING_TAG,
                                                 Vec::new(),
                                                 false,
                                                 AccessLevel::Private,
                                                 Some(&mut app_root_dir)));


        let mut request = DeleteDir {
            dir_path: "/test_dir2".to_string(),
            is_path_shared: false,
        };
        assert!(request.execute(parameter_packet.clone()).is_err());
        app_root_dir = unwrap_result!(dir_helper.get(&app_root_dir_key));
        assert_eq!(app_root_dir.get_sub_directories().len(), 1);
        assert!(app_root_dir.find_sub_directory(&"test_dir".to_string()).is_some());
        request.dir_path = "/test_dir".to_string();
        assert!(request.execute(parameter_packet.clone()).is_ok());
        app_root_dir = unwrap_result!(dir_helper.get(&app_root_dir_key));
        assert_eq!(app_root_dir.get_sub_directories().len(), 0);
        assert!(request.execute(parameter_packet.clone()).is_err());
    }
}
