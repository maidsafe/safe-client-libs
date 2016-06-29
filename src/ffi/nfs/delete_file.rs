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
use nfs::helper::file_helper::FileHelper;

#[derive(RustcDecodable, Debug)]
pub struct DeleteFile {
    file_path: String,
    is_path_shared: bool,
}

impl Action for DeleteFile {
    fn execute(&mut self, params: ParameterPacket) -> ResponseType {
        let start_dir_key = if self.is_path_shared {
            try!(params.safe_drive_dir_key
                .ok_or(FfiError::from("Safe Drive directory key is not present")))
        } else {
            try!(params.app_root_dir_key
                .ok_or(FfiError::from("Application directory key is not present")))
        };

        let mut tokens = helper::tokenise_path(&self.file_path, false);
        let file_name = try!(tokens.pop().ok_or(FfiError::InvalidPath));
        let mut dir_of_file = try!(helper::get_final_subdirectory(params.client.clone(),
                                                                  &tokens,
                                                                  Some(&start_dir_key)));

        let file_helper = FileHelper::new(params.client);
        let _ = try!(file_helper.delete(file_name, &mut dir_of_file));

        Ok(None)
    }
}


#[cfg(test)]
mod test {
    use super::*;
    use ffi::{Action, test_utils};
    use nfs::helper::file_helper::FileHelper;
    use nfs::helper::directory_helper::DirectoryHelper;

    #[test]
    fn delete_file() {
        let parameter_packet = unwrap!(test_utils::get_parameter_packet(false));

        let mut file_helper = FileHelper::new(parameter_packet.client.clone());
        let dir_helper = DirectoryHelper::new(parameter_packet.client.clone());
        let app_root_dir_key = unwrap!(parameter_packet.clone().app_root_dir_key);
        let mut app_root_dir = unwrap!(dir_helper.get(&app_root_dir_key));
        let writer =
            unwrap!(file_helper.create("test_file.txt".to_string(), Vec::new(), app_root_dir));
        let _ = unwrap!(writer.close());

        let mut request = DeleteFile {
            file_path: "/test_file.txt".to_string(),
            is_path_shared: false,
        };

        app_root_dir = unwrap!(dir_helper.get(&app_root_dir_key));
        assert_eq!(app_root_dir.get_files().len(), 1);
        assert!(app_root_dir.find_file(&"test_file.txt".to_string()).is_some());
        assert!(request.execute(parameter_packet.clone()).is_ok());
        app_root_dir = unwrap!(dir_helper.get(&app_root_dir_key));
        assert_eq!(app_root_dir.get_files().len(), 0);
        assert!(request.execute(parameter_packet.clone()).is_err());
    }
}
