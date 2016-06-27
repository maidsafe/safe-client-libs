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
use ffi::{ParameterPacket, ResponseType, Action};
use rustc_serialize::json;

#[derive(RustcDecodable, Debug)]
pub struct GetServices {
    pub long_name: String,
}

impl Action for GetServices {
    fn execute(&mut self, params: ParameterPacket) -> ResponseType {
        let dns_ops = try!(DnsOperations::new(params.client));
        let list = try!(dns_ops.get_all_services(&self.long_name, None));

        Ok(Some(try!(json::encode(&list))))
    }
}
