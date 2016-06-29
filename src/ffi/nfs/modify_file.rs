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

use ffi::{Action, helper, ParameterPacket, ResponseType};
use ffi::errors::FfiError;
use nfs::helper::file_helper::FileHelper;
use nfs::helper::writer::Mode;

#[derive(RustcDecodable, Debug)]
pub struct ModifyFile {
    file_path: String,
    new_values: OptionalParams,
    is_path_shared: bool,
}

impl Action for ModifyFile {
    fn execute(&mut self, params: ParameterPacket) -> ResponseType {
        use rustc_serialize::base64::FromBase64;

        if self.is_path_shared && !params.safe_drive_access {
            return Err(FfiError::PermissionDenied);
        }

        if self.new_values.name.is_none() && self.new_values.user_metadata.is_none() &&
           self.new_values.content.is_none() {
            return Err(FfiError::from("Optional parameters could not be parsed"));
        }

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

        let mut file = try!(dir_of_file.find_file(&file_name)
            .cloned()
            .ok_or(FfiError::InvalidPath));

        let mut file_helper = FileHelper::new(params.client);

        let mut metadata_updated = false;
        if let Some(ref name) = self.new_values.name {
            file.get_mut_metadata().set_name(name.clone());
            metadata_updated = true;
        }

        if let Some(ref metadata_base64) = self.new_values.user_metadata {
            let metadata = try!(parse_result!(metadata_base64.from_base64(),
                                              "Failed to convert from base64"));
            file.get_mut_metadata().set_user_metadata(metadata);
            metadata_updated = true;
        }

        if metadata_updated {
            let _ = try!(file_helper.update_metadata(file.clone(), &mut dir_of_file));
        }

        if let Some(ref file_content_params) = self.new_values.content {
            let (mode, offset) = match file_content_params.offset {
                Some(offset) => (Mode::Modify, offset),
                None => (Mode::Overwrite, 0),
            };
            let mut writer = try!(file_helper.update_content(file.clone(), mode, dir_of_file));
            let bytes = try!(parse_result!(file_content_params.bytes.from_base64(),
                                           "Failed to convert from base64"));
            try!(writer.write(&bytes[..], offset));
            let _ = try!(writer.close());
        }

        Ok(None)
    }
}

#[derive(RustcDecodable, Debug)]
struct OptionalParams {
    pub name: Option<String>,
    pub content: Option<FileContentParams>,
    pub user_metadata: Option<String>,
}

#[derive(RustcDecodable, Debug)]
struct FileContentParams {
    pub bytes: String,
    pub offset: Option<u64>,
}

#[cfg(test)]
mod test {
    use super::{ModifyFile, FileContentParams, OptionalParams};
    use ffi::{config, Action, ParameterPacket, test_utils};
    use rustc_serialize::base64::ToBase64;
    use nfs::helper::directory_helper::DirectoryHelper;
    use nfs::helper::file_helper::FileHelper;

    const TEST_FILE_NAME: &'static str = "test_file.txt";
    const METADATA_BASE64: &'static str = "c2FtcGxlIHRleHQ=";

    fn create_test_file(parameter_packet: &ParameterPacket) {
        let app_root_dir_key = unwrap!(parameter_packet.clone().app_root_dir_key);
        let mut file_helper = FileHelper::new(parameter_packet.client.clone());
        let dir_helper = DirectoryHelper::new(parameter_packet.client.clone());
        let app_root_dir = unwrap!(dir_helper.get(&app_root_dir_key));
        let writer = unwrap!(file_helper.create(TEST_FILE_NAME.to_string(),
                                                       Vec::new(),
                                                       app_root_dir));
        let _ = unwrap!(writer.close());
    }

    #[test]
    fn file_rename() {
        let parameter_packet = unwrap!(test_utils::get_parameter_packet(false));

        create_test_file(&parameter_packet);

        let values = OptionalParams {
            name: Some("new_test_file.txt".to_string()),
            content: None,
            user_metadata: None,
        };

        let mut request = ModifyFile {
            file_path: format!("/{}", TEST_FILE_NAME),
            new_values: values,
            is_path_shared: false,
        };

        let app_root_dir_key = unwrap!(parameter_packet.clone().app_root_dir_key);
        let dir_helper = DirectoryHelper::new(parameter_packet.client.clone());
        let mut app_root_dir = unwrap!(dir_helper.get(&app_root_dir_key));
        assert_eq!(app_root_dir.get_files().len(), 1);
        assert!(app_root_dir.find_file(&TEST_FILE_NAME.to_string()).is_some());

        assert!(request.execute(parameter_packet).is_ok());
        app_root_dir = unwrap!(dir_helper.get(&app_root_dir_key));
        assert_eq!(app_root_dir.get_files().len(), 1);
        assert!(app_root_dir.find_file(&TEST_FILE_NAME.to_string()).is_none());
        assert!(app_root_dir.find_file(&"new_test_file.txt".to_string()).is_some());
    }

    #[test]
    fn file_update_user_metadata() {
        let parameter_packet = unwrap!(test_utils::get_parameter_packet(false));

        create_test_file(&parameter_packet);

        let values = OptionalParams {
            name: None,
            content: None,
            user_metadata: Some(METADATA_BASE64.to_string()),
        };

        let mut request = ModifyFile {
            file_path: format!("/{}", TEST_FILE_NAME),
            new_values: values,
            is_path_shared: false,
        };

        let app_root_dir_key = unwrap!(parameter_packet.clone().app_root_dir_key);
        let dir_helper = DirectoryHelper::new(parameter_packet.client.clone());
        let app_root_dir = unwrap!(dir_helper.get(&app_root_dir_key));
        let file = unwrap!(app_root_dir.find_file(&TEST_FILE_NAME.to_string()),
                                  "File not found");
        assert_eq!(file.get_metadata().get_user_metadata().len(), 0);
        assert!(request.execute(parameter_packet).is_ok());
        let app_root_dir = unwrap!(dir_helper.get(&app_root_dir_key));
        let file = unwrap!(app_root_dir.find_file(&TEST_FILE_NAME.to_string()),
                                  "File not found");
        assert!(file.get_metadata().get_user_metadata().len() > 0);
        assert_eq!(file.get_metadata()
                       .get_user_metadata()
                       .to_base64(config::get_base64_config()),
                   METADATA_BASE64.to_string());
    }

    #[test]
    fn file_update_content() {
        let parameter_packet = unwrap!(test_utils::get_parameter_packet(false));

        create_test_file(&parameter_packet);

        let content = FileContentParams {
            bytes: METADATA_BASE64.to_string(),
            offset: None,
        };

        let values = OptionalParams {
            name: None,
            content: Some(content),
            user_metadata: None,
        };

        let mut request = ModifyFile {
            file_path: format!("/{}", TEST_FILE_NAME),
            new_values: values,
            is_path_shared: false,
        };

        let app_root_dir_key = unwrap!(parameter_packet.clone().app_root_dir_key);
        let dir_helper = DirectoryHelper::new(parameter_packet.client.clone());
        let app_root_dir = unwrap!(dir_helper.get(&app_root_dir_key));
        let file = unwrap!(app_root_dir.find_file(&TEST_FILE_NAME.to_string()),
                                  "File not found");
        assert_eq!(file.get_metadata().get_size(), 0);
        assert!(request.execute(parameter_packet.clone()).is_ok());
        let app_root_dir = unwrap!(dir_helper.get(&app_root_dir_key));
        let file = unwrap!(app_root_dir.find_file(&TEST_FILE_NAME.to_string()),
                                  "File not found");
        let file_size = file.get_metadata().get_size();
        assert!(file_size > 0);
        let mut file_helper = FileHelper::new(parameter_packet.client.clone());
        let mut reader = file_helper.read(file).expect("");
        let size = reader.size();
        assert_eq!(size, file_size);
        let data = unwrap!(reader.read(0, size));
        assert_eq!(data.to_base64(config::get_base64_config()),
                   METADATA_BASE64.to_string());
        // Uploading in smaller chunks
        let file_size = 8011;
        let batch_size = 1000;
        let mut i = 0;

        while i < file_size {
            let content = FileContentParams {
                bytes: METADATA_BASE64.to_string(),
                offset: Some(i), // offset: Some(i * batch_size),
            };

            let values = OptionalParams {
                name: None,
                content: Some(content),
                user_metadata: None,
            };

            request = ModifyFile {
                file_path: format!("/{}", TEST_FILE_NAME),
                new_values: values,
                is_path_shared: false,
            };
            assert!(request.execute(parameter_packet.clone()).is_ok());
            i += batch_size;
        }

        let app_root_dir = unwrap!(dir_helper.get(&app_root_dir_key));
        let file = unwrap!(app_root_dir.find_file(&TEST_FILE_NAME.to_string())
                                      .cloned(),
                                  "File not found");
        assert_eq!(file.get_datamap().len(), file_size);
    }
}
