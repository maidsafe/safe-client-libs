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
use ffi::{helper, ParameterPacket, ResponseType, Action};
use rustc_serialize::json;

#[derive(RustcDecodable, Debug)]
pub struct GetFileMetadata {
    file_path: String,
    is_path_shared: bool,
}

impl Action for GetFileMetadata {
    fn execute(&mut self, params: ParameterPacket) -> ResponseType {

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

        Ok(Some(try!(json::encode(file.get_metadata()))))
    }
}
