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
use nfs::helper::file_helper::FileHelper;

#[derive(RustcDecodable, Debug)]
pub struct CreateFile {
    file_path: String,
    user_metadata: String,
    is_path_shared: bool,
}

impl Action for CreateFile {
    fn execute(&mut self, params: ParameterPacket) -> ResponseType {
        use rustc_serialize::base64::FromBase64;

        if self.is_path_shared && !params.safe_drive_access {
            return Err(FfiError::PermissionDenied);
        };

        let start_dir_key = if self.is_path_shared {
            try!(params.safe_drive_dir_key
                .ok_or(FfiError::from("Safe Drive directory key is not present")))
        } else {
            try!(params.app_root_dir_key
                .ok_or(FfiError::from("Application directory key is not present")))
        };

        let mut tokens = helper::tokenise_path(&self.file_path, false);
        let file_name = try!(tokens.pop().ok_or(FfiError::InvalidPath));

        let file_directory = try!(helper::get_final_subdirectory(params.client.clone(),
                                                                 &tokens,
                                                                 Some(&start_dir_key)));

        let mut file_helper = FileHelper::new(params.client);
        let bin_metadata = try!(parse_result!(self.user_metadata.from_base64(),
                                              "Failed Converting from Base64."));

        let writer = try!(file_helper.create(file_name, bin_metadata, file_directory));
        let _ = try!(writer.close());

        Ok(None)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ffi::{Action, test_utils};
    use nfs::helper::directory_helper::DirectoryHelper;

    #[test]
    fn create_file() {
        let parameter_packet = unwrap!(test_utils::get_parameter_packet(false));

        let mut request = CreateFile {
            file_path: "/test.txt".to_string(),
            user_metadata: "InNhbXBsZSBtZXRhZGF0YSI=".to_string(),
            is_path_shared: false,
        };
        assert!(request.execute(parameter_packet.clone()).is_ok());

        let dir_helper = DirectoryHelper::new(parameter_packet.client);
        let app_dir =
            unwrap!(dir_helper.get(&unwrap!(parameter_packet.app_root_dir_key)));
        assert!(app_dir.find_file(&"test.txt".to_string()).is_some());
    }
}
