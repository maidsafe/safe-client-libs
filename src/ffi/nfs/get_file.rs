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
use ffi::nfs::file_response::get_response;
use rustc_serialize::json;

#[derive(RustcDecodable, Debug)]
pub struct GetFile {
    offset: i64,
    length: i64,
    file_path: String,
    is_path_shared: bool,
    include_metadata: bool,
}

impl Action for GetFile {
    fn execute(&mut self, params: ParameterPacket) -> ResponseType {
        use rustc_serialize::json::ToJson;

        if self.is_path_shared && !params.safe_drive_access {
            return Err(FfiError::PermissionDenied);
        }

        let mut tokens = helper::tokenise_path(&self.file_path, false);
        let file_name = try!(tokens.pop().ok_or(FfiError::InvalidPath));

        let start_dir_key = if self.is_path_shared {
            try!(params.safe_drive_dir_key
                .ok_or(FfiError::from("Safe Drive directory key is not present")))
        } else {
            try!(params.app_root_dir_key
                .ok_or(FfiError::from("Application directory key is not present")))
        };

        let file_dir = try!(helper::get_final_subdirectory(params.client.clone(),
                                                           &tokens,
                                                           Some(&start_dir_key)));
        let file = try!(file_dir.find_file(&file_name)
            .ok_or(FfiError::InvalidPath));

        let response = try!(get_response(file,
                                         params.client,
                                         self.offset,
                                         self.length,
                                         self.include_metadata));

        Ok(Some(try!(json::encode(&response.to_json()))))
    }
}


#[cfg(test)]
mod test {
    use ffi::{Action, ParameterPacket, test_utils};
    use nfs::helper::file_helper::FileHelper;
    use nfs::helper::directory_helper::DirectoryHelper;

    const TEST_FILE_NAME: &'static str = "test_file.txt";

    fn create_test_file(parameter_packet: &ParameterPacket) {
        let app_dir_key = unwrap!(parameter_packet.clone().app_root_dir_key);
        let mut file_helper = FileHelper::new(parameter_packet.client.clone());
        let dir_helper = DirectoryHelper::new(parameter_packet.client.clone());
        let app_root_dir = unwrap!(dir_helper.get(&app_dir_key));
        let mut writer = unwrap!(file_helper.create(TEST_FILE_NAME.to_string(),
                                                           Vec::new(),
                                                           app_root_dir));
        let data = vec![10u8; 20];
        writer.write(&data[..], 0).expect("");
        let _ = unwrap!(writer.close());
    }


    #[test]
    fn get_file() {
        let parameter_packet = unwrap!(test_utils::get_parameter_packet(false));

        create_test_file(&parameter_packet);

        let mut request = super::GetFile {
            offset: 0,
            length: 0,
            file_path: format!("/{}", TEST_FILE_NAME),
            is_path_shared: false,
            include_metadata: true,
        };

        assert!(unwrap!(request.execute(parameter_packet.clone())).is_some());

        request.file_path = "/does_not_exixts".to_string();
        assert!(request.execute(parameter_packet).is_err());
    }

}
