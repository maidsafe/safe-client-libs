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
use ffi::{helper, Action, ParameterPacket, ResponseType};
use ffi::errors::FfiError;
use sodiumoxide::crypto::box_;

#[derive(RustcDecodable, Debug)]
pub struct RegisterDns {
    pub long_name: String,
    pub service_name: String,
    pub is_path_shared: bool,
    pub service_home_dir_path: String,
}

impl Action for RegisterDns {
    fn execute(&mut self, params: ParameterPacket) -> ResponseType {
        if self.is_path_shared && !params.safe_drive_access {
            return Err(FfiError::PermissionDenied);
        }

        let tokens = helper::tokenise_path(&self.service_home_dir_path, false);

        let start_dir_key = if self.is_path_shared {
            try!(params.safe_drive_dir_key
                .ok_or(FfiError::from("Safe Drive directory key is not present")))
        } else {
            try!(params.app_root_dir_key
                .ok_or(FfiError::from("Application directory key is not present")))
        };

        let dir_to_map = try!(helper::get_final_subdirectory(params.client.clone(),
                                                             &tokens,
                                                             Some(&start_dir_key)));

        let (msg_public_key, msg_secret_key) = box_::gen_keypair();
        let services = vec![(self.service_name.clone(), (dir_to_map.get_key().clone()))];
        let public_signing_key =
            *try!(unwrap_result!(params.client.lock()).get_public_signing_key());
        let secret_signing_key =
            try!(unwrap_result!(params.client.lock()).get_secret_signing_key()).clone();
        let dns_operation = try!(DnsOperations::new(params.client
            .clone()));
        try!(dns_operation.register_dns(self.long_name.clone(),
                                        &msg_public_key,
                                        &msg_secret_key,
                                        &services,
                                        vec![public_signing_key],
                                        &secret_signing_key,
                                        None));
        Ok(None)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ffi::Action;
    use ffi::test_utils::get_parameter_packet;
    use core::utility;
    use nfs::helper::directory_helper::DirectoryHelper;
    use nfs::{AccessLevel, UNVERSIONED_DIRECTORY_LISTING_TAG};

    const TEST_DIR_NAME: &'static str = "test_dir";

    #[test]
    fn register_dns() {
        let parameter_packet = unwrap_result!(get_parameter_packet(false));

        let dir_helper = DirectoryHelper::new(parameter_packet.client.clone());
        let mut app_root_dir =
            unwrap_result!(dir_helper.get(&unwrap_option!(parameter_packet.clone()
                                                              .app_root_dir_key,
                                                          "")));
        let _ = unwrap_result!(dir_helper.create(TEST_DIR_NAME.to_string(),
                                                 UNVERSIONED_DIRECTORY_LISTING_TAG,
                                                 Vec::new(),
                                                 false,
                                                 AccessLevel::Public,
                                                 Some(&mut app_root_dir)));
        let public_name = unwrap_result!(utility::generate_random_string(10));
        let mut request = RegisterDns {
            long_name: public_name,
            service_name: "www".to_string(),
            is_path_shared: false,
            service_home_dir_path: "/test_dir2".to_string(),
        };
        assert!(request.execute(parameter_packet.clone()).is_err());
        request.service_home_dir_path = format!("/{}", TEST_DIR_NAME);
        assert!(request.execute(parameter_packet).is_ok());
    }
}
