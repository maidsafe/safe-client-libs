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
use ffi::nfs::directory_response::convert_to_response;

#[derive(RustcDecodable, Debug)]
pub struct GetDir {
    dir_path: String,
    is_path_shared: bool,
}

impl Action for GetDir {
    fn execute(&mut self, params: ParameterPacket) -> ResponseType {
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
        let dir_fetched = try!(helper::get_final_subdirectory(params.client.clone(),
                                                              &tokens,
                                                              Some(&start_dir_key)));

        let response = convert_to_response(dir_fetched);

        Ok(Some(try!(::rustc_serialize::json::encode(&response))))
    }
}

#[cfg(test)]
mod test {
    use ffi::{Action, ParameterPacket, test_utils};
    use nfs::helper::directory_helper::DirectoryHelper;
    use nfs::{AccessLevel, UNVERSIONED_DIRECTORY_LISTING_TAG};

    const TEST_DIR_NAME: &'static str = "test_dir";

    fn create_test_dir(parameter_packet: &ParameterPacket) {
        let app_dir_key = unwrap!(parameter_packet.clone().app_root_dir_key);
        let dir_helper = DirectoryHelper::new(parameter_packet.client.clone());
        let mut app_root_dir = unwrap!(dir_helper.get(&app_dir_key));
        let _ = unwrap!(dir_helper.create(TEST_DIR_NAME.to_string(),
                                                 UNVERSIONED_DIRECTORY_LISTING_TAG,
                                                 Vec::new(),
                                                 false,
                                                 AccessLevel::Private,
                                                 Some(&mut app_root_dir)));
    }

    #[test]
    fn get_dir() {
        let parameter_packet = unwrap!(test_utils::get_parameter_packet(false));

        create_test_dir(&parameter_packet);

        let mut request = super::GetDir {
            dir_path: format!("/{}", TEST_DIR_NAME),
            is_path_shared: false,
        };

        assert!(unwrap!(request.execute(parameter_packet.clone())).is_some());

        request.dir_path = "/does_not_exixts".to_string();
        assert!(request.execute(parameter_packet).is_err());
    }

}
