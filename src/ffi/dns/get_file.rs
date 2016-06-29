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

use dns::dns_operations::DnsOperations;
use ffi::{helper, ParameterPacket, ResponseType, Action};
use ffi::errors::FfiError;
use ffi::nfs::file_response::get_response;
use rustc_serialize::json;

#[derive(RustcDecodable, Debug)]
pub struct GetFile {
    pub long_name: String,
    pub service_name: String,
    pub offset: i64,
    pub length: i64,
    pub file_path: String,
    pub include_metadata: bool,
}

impl Action for GetFile {
    fn execute(&mut self, params: ParameterPacket) -> ResponseType {
        let dns_operations = match params.app_root_dir_key {
            Some(_) => try!(DnsOperations::new(params.client.clone())),
            None => DnsOperations::new_unregistered(params.client.clone()),
        };
        let directory_key = try!(dns_operations.get_service_home_directory_key(&self.long_name,
                                                                               &self.service_name,
                                                                               None));
        let mut tokens = helper::tokenise_path(&self.file_path, false);
        let file_name = try!(tokens.pop().ok_or(FfiError::InvalidPath));
        let file_dir = try!(helper::get_final_subdirectory(params.client.clone(),
                                                           &tokens,
                                                           Some(&directory_key)));
        let file = try!(file_dir.find_file(&file_name).ok_or(FfiError::InvalidPath));
        let response = try!(get_response(file,
                                         params.client,
                                         self.offset,
                                         self.length,
                                         self.include_metadata));

        Ok(Some(try!(json::encode(&response))))
    }
}


#[cfg(test)]
mod test {
    use super::*;
    use core::utility;
    use sodiumoxide::crypto::box_;
    use dns::dns_operations::DnsOperations;
    use ffi::{Action, test_utils, ParameterPacket, errors};
    use nfs::{AccessLevel, UNVERSIONED_DIRECTORY_LISTING_TAG};
    use nfs::metadata::directory_key::DirectoryKey;
    use nfs::helper::file_helper::FileHelper;
    use nfs::helper::directory_helper::DirectoryHelper;

    fn create_public_file(params: &ParameterPacket,
                          file_name: String,
                          file_content: Vec<u8>)
                          -> Result<DirectoryKey, errors::FfiError> {
        let directory_helper = DirectoryHelper::new(params.clone().client);
        let mut file_directory = try!(directory_helper.get(&try!(params.clone()
            .app_root_dir_key
            .ok_or(errors::FfiError::from("Application directory key is not present")))));

        let (file_directory, _) = try!(directory_helper.create(String::from("public-dir"),
                                                               UNVERSIONED_DIRECTORY_LISTING_TAG,
                                                               vec![0u8; 0],
                                                               false,
                                                               AccessLevel::Public,
                                                               Some(&mut file_directory)));
        let mut file_helper = FileHelper::new(params.clone().client);
        let bin_metadata = vec![0u8; 0];

        let key = file_directory.get_key().clone();
        let mut writer = try!(file_helper.create(file_name, bin_metadata, file_directory));
        try!(writer.write(&file_content[..], 0));
        let _ = try!(writer.close());

        Ok(key)
    }

    fn register_service(params: &ParameterPacket,
                        service_name: String,
                        public_name: String,
                        directory_key: DirectoryKey)
                        -> Result<(), errors::FfiError> {
        let (msg_public_key, msg_secret_key) = box_::gen_keypair();
        let services = vec![(service_name.clone(), (directory_key.clone()))];
        let public_signing_key = *try!(unwrap!(params.client.lock())
            .get_public_signing_key());
        let secret_signing_key =
            try!(unwrap!(params.client.lock()).get_secret_signing_key()).clone();
        let dns_operation = try!(DnsOperations::new(params.client
            .clone()));
        try!(dns_operation.register_dns(public_name.clone(),
                                        &msg_public_key,
                                        &msg_secret_key,
                                        &services,
                                        vec![public_signing_key],
                                        &secret_signing_key,
                                        None));
        Ok(())
    }

    #[test]
    fn get_public_file_using_registerd_client() {
        let parameter_packet = unwrap!(test_utils::get_parameter_packet(false));
        let file_name = String::from("index.html");
        let file_content = String::from("<html><title>Home</title></html>");
        let public_directory_key = unwrap!(create_public_file(&parameter_packet,
                                                                     file_name.clone(),
                                                                     file_content.into_bytes()));
        let service_name = String::from("www");
        let public_name = unwrap!(utility::generate_random_string(10));
        unwrap!(register_service(&parameter_packet,
                                        service_name.clone(),
                                        public_name.clone(),
                                        public_directory_key));

        // Fecth the file using the same client
        let mut request = GetFile {
            long_name: public_name,
            service_name: service_name,
            offset: 0i64,
            length: 0i64,
            file_path: file_name,
            include_metadata: false,
        };
        assert!(request.execute(parameter_packet).is_ok());
        // Fetch the file using a new client
        let new_parameter_packet = unwrap!(test_utils::get_parameter_packet(false));
        assert!(request.execute(new_parameter_packet).is_ok());
        // Fetch the file using an unregisterd client
        let unreg_parameter_packet =
            unwrap!(test_utils::get_unregistered_parameter_packet());
        assert!(request.execute(unreg_parameter_packet).is_ok());
    }
}
