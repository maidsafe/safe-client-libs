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
use ffi::{Action, ParameterPacket, ResponseType};
use sodiumoxide::crypto::box_;

#[derive(RustcDecodable, Debug)]
pub struct RegisterPublicId {
    pub long_name: String,
}

impl Action for RegisterPublicId {
    fn execute(&mut self, params: ParameterPacket) -> ResponseType {
        let (msg_public_key, msg_secret_key) = box_::gen_keypair();
        let services = vec![];
        let public_signing_key = *try!(unwrap!(params.client.lock()).get_public_signing_key());
        let secret_signing_key = try!(unwrap!(params.client.lock()).get_secret_signing_key())
            .clone();
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

    #[test]
    fn register_public_id() {
        let parameter_packet = unwrap!(get_parameter_packet(false));
        let public_name = unwrap!(utility::generate_random_string(10));
        let mut request = RegisterPublicId { long_name: public_name.clone() };
        assert!(request.execute(parameter_packet.clone()).is_ok());
        // let parameter_packet = unwrap!(get_parameter_packet(false));
        // let mut request = RegisterPublicId { long_name: public_name };
        // assert!(request.execute(parameter_packet.clone()).is_err());
    }
}
