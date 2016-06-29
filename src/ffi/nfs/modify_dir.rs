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

use ffi::{Action, ParameterPacket, ResponseType, helper};
use ffi::errors::FfiError;
use nfs::helper::directory_helper::DirectoryHelper;

#[derive(RustcDecodable, Debug)]
pub struct ModifyDir {
    dir_path: String,
    new_values: OptionalParams,
    is_path_shared: bool,
}

impl Action for ModifyDir {
    fn execute(&mut self, params: ParameterPacket) -> ResponseType {
        use rustc_serialize::base64::FromBase64;

        if !(self.new_values.name.is_some() || self.new_values.user_metadata.is_some()) {
            return Err(FfiError::from("Optional parameters could not be parsed"));
        }

        if self.is_path_shared && !params.safe_drive_access {
            return Err(FfiError::PermissionDenied);
        }

        let start_dir_key = if self.is_path_shared {
            try!(params.safe_drive_dir_key
                .ok_or(FfiError::from("Safe Drive directory key is not present")))
        } else {
            try!(params.app_root_dir_key
                .ok_or(FfiError::from("Application directory key is not present")))
        };

        let tokens = helper::tokenise_path(&self.dir_path, false);
        let mut dir_to_modify = try!(helper::get_final_subdirectory(params.client.clone(),
                                                                    &tokens,
                                                                    Some(&start_dir_key)));

        let directory_helper = DirectoryHelper::new(params.client);
        if let Some(ref name) = self.new_values.name {
            dir_to_modify.get_mut_metadata().set_name(name.clone());
        }

        if let Some(ref metadata_base64) = self.new_values.user_metadata {
            let metadata = try!(parse_result!(metadata_base64.from_base64(),
                                              "Failed to convert from base64"));
            dir_to_modify.get_mut_metadata().set_user_metadata(metadata);
        }

        let _ = try!(directory_helper.update(&dir_to_modify));

        Ok(None)
    }
}

#[derive(Debug, RustcDecodable)]
struct OptionalParams {
    pub name: Option<String>,
    pub user_metadata: Option<String>,
}

#[cfg(test)]
mod test {
    use super::*;
    use ffi::{Action, ParameterPacket, config, test_utils};
    use rustc_serialize::base64::ToBase64;
    use nfs::{AccessLevel, UNVERSIONED_DIRECTORY_LISTING_TAG};
    use nfs::helper::directory_helper::DirectoryHelper;

    const TEST_DIR_NAME: &'static str = "test_dir";
    const METADATA_BASE64: &'static str = "c2FtcGxlIHRleHQ=";

    fn create_test_dir(parameter_packet: &ParameterPacket) {
        let app_root_dir_key = unwrap!(parameter_packet.clone().app_root_dir_key);
        let dir_helper = DirectoryHelper::new(parameter_packet.client.clone());
        let mut app_root_dir = unwrap!(dir_helper.get(&app_root_dir_key));
        let _ = unwrap!(dir_helper.create(TEST_DIR_NAME.to_string(),
                                          UNVERSIONED_DIRECTORY_LISTING_TAG,
                                          Vec::new(),
                                          false,
                                          AccessLevel::Private,
                                          Some(&mut app_root_dir)));
    }

    #[test]
    fn rename_dir() {
        let parameter_packet = unwrap!(test_utils::get_parameter_packet(false));

        create_test_dir(&parameter_packet);

        let values = super::OptionalParams {
            name: Some("new_test_dir".to_string()),
            user_metadata: None,
        };

        let mut request = ModifyDir {
            dir_path: format!("/{}", TEST_DIR_NAME),
            new_values: values,
            is_path_shared: false,
        };

        let app_root_dir_key = unwrap!(parameter_packet.clone().app_root_dir_key);
        let dir_helper = DirectoryHelper::new(parameter_packet.client.clone());
        let mut app_root_dir = unwrap!(dir_helper.get(&app_root_dir_key));
        assert_eq!(app_root_dir.get_sub_directories().len(), 1);
        assert!(app_root_dir.find_sub_directory(&TEST_DIR_NAME.to_string()).is_some());
        assert!(request.execute(parameter_packet).is_ok());
        app_root_dir = unwrap!(dir_helper.get(&app_root_dir_key));
        assert_eq!(app_root_dir.get_sub_directories().len(), 1);
        assert!(app_root_dir.find_sub_directory(&TEST_DIR_NAME.to_string()).is_none());
        assert!(app_root_dir.find_sub_directory(&"new_test_dir".to_string()).is_some());
    }

    #[test]
    fn dir_update_user_metadata() {
        let parameter_packet = unwrap!(test_utils::get_parameter_packet(false));

        create_test_dir(&parameter_packet);

        let values = super::OptionalParams {
            name: None,
            user_metadata: Some(METADATA_BASE64.to_string()),
        };

        let mut request = ModifyDir {
            dir_path: format!("/{}", TEST_DIR_NAME),
            new_values: values,
            is_path_shared: false,
        };

        let app_root_dir_key = unwrap!(parameter_packet.clone().app_root_dir_key);
        let dir_helper = DirectoryHelper::new(parameter_packet.client.clone());
        let app_root_dir = unwrap!(dir_helper.get(&app_root_dir_key));
        let directory_key = unwrap!(app_root_dir.find_sub_directory(&TEST_DIR_NAME.to_string()),
                                    "Directory not found")
            .get_key();
        let mut directory_to_modify = unwrap!(dir_helper.get(directory_key));
        assert_eq!(directory_to_modify.get_metadata().get_user_metadata().len(),
                   0);
        assert!(request.execute(parameter_packet).is_ok());
        directory_to_modify = unwrap!(dir_helper.get(directory_key));
        assert!(directory_to_modify.get_metadata().get_user_metadata().len() > 0);
        assert_eq!(directory_to_modify.get_metadata()
                       .get_user_metadata()
                       .to_base64(config::get_base64_config()),
                   METADATA_BASE64.to_string());
    }
}
