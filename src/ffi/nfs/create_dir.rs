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
use nfs::{AccessLevel, UNVERSIONED_DIRECTORY_LISTING_TAG, VERSIONED_DIRECTORY_LISTING_TAG};
use nfs::helper::directory_helper::DirectoryHelper;

#[derive(RustcDecodable, Debug)]
pub struct CreateDir {
    dir_path: String,
    is_private: bool,
    is_versioned: bool,
    user_metadata: String,
    is_path_shared: bool,
}

impl Action for CreateDir {
    fn execute(&mut self, params: ParameterPacket) -> ResponseType {
        use rustc_serialize::base64::FromBase64;

        if self.is_path_shared && !params.safe_drive_access {
            return Err(FfiError::PermissionDenied);
        }

        let mut tokens = helper::tokenise_path(&self.dir_path, false);
        let dir_to_create = try!(tokens.pop().ok_or(FfiError::InvalidPath));

        let start_dir_key = if self.is_path_shared {
            try!(params.safe_drive_dir_key
                .ok_or(FfiError::from("Safe Drive directory key is not present")))
        } else {
            try!(params.app_root_dir_key
                .ok_or(FfiError::from("Application directory key is not present")))
        };

        let mut parent_sub_dir = try!(helper::get_final_subdirectory(params.client.clone(),
                                                                     &tokens,
                                                                     Some(&start_dir_key)));

        let dir_helper = DirectoryHelper::new(params.client);

        let access_level = if self.is_private {
            AccessLevel::Private
        } else {
            AccessLevel::Public
        };

        let tag = if self.is_versioned {
            VERSIONED_DIRECTORY_LISTING_TAG
        } else {
            UNVERSIONED_DIRECTORY_LISTING_TAG
        };

        let bin_metadata = try!(parse_result!(self.user_metadata.from_base64(),
                                              "Faild Converting from Base64."));

        let _ = try!(dir_helper.create(dir_to_create,
                                       tag,
                                       bin_metadata,
                                       self.is_versioned,
                                       access_level,
                                       Some(&mut parent_sub_dir)));

        Ok(None)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ffi::{Action, test_utils};
    use nfs::helper::directory_helper::DirectoryHelper;

    #[test]
    fn create_dir() {
        let parameter_packet = unwrap!(test_utils::get_parameter_packet(false));

        let mut request = CreateDir {
            dir_path: "/".to_string(),
            is_private: true,
            is_versioned: false,
            user_metadata: "InNhbXBsZSBtZXRhZGF0YSI=".to_string(),
            is_path_shared: false,
        };
        assert!(request.execute(parameter_packet.clone()).is_err());

        request.dir_path = "/test_dir/secondlevel".to_string();
        assert!(request.execute(parameter_packet.clone()).is_err());

        request.dir_path = "/test_dir".to_string();
        assert!(request.execute(parameter_packet.clone()).is_ok());

        request.dir_path = "/test_dir2".to_string();
        assert!(request.execute(parameter_packet.clone()).is_ok());

        request.dir_path = "/test_dir/secondlevel".to_string();
        assert!(request.execute(parameter_packet.clone()).is_ok());

        let dir_helper = DirectoryHelper::new(parameter_packet.clone().client);
        let app_dir = unwrap!(dir_helper.get(&unwrap!(parameter_packet.clone()
                                                                        .app_root_dir_key)));
        assert!(app_dir.find_sub_directory(&"test_dir".to_string()).is_some());
        assert!(app_dir.find_sub_directory(&"test_dir2".to_string()).is_some());
        assert_eq!(app_dir.get_sub_directories().len(), 2);

        let test_dir_key = unwrap!(app_dir.find_sub_directory(&"test_dir".to_string()),
                                          "Directory not found")
            .get_key();
        let test_dir = unwrap!(dir_helper.get(test_dir_key));
        assert!(test_dir.find_sub_directory(&"secondlevel".to_string()).is_some());
    }
}
