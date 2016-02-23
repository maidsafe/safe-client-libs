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

use client::Client;
use xor_name::XorName;
use std::sync::{Arc, Mutex};
use routing::{ImmutableData, ImmutableDataType, Data, DataRequest};

/// Network storage is the concrete type which self-encryption crate will use to put or get data
/// from the network
pub struct SelfEncryptionStorage {
    client: Arc<Mutex<Client>>,
}

impl SelfEncryptionStorage {
    /// Create a new SelfEncryptionStorage instance
    pub fn new(client: Arc<Mutex<Client>>) -> Arc<SelfEncryptionStorage> {
        Arc::new(SelfEncryptionStorage { client: client })
    }
}

impl ::self_encryption::Storage for SelfEncryptionStorage {
    fn get(&self, name: Vec<u8>) -> Vec<u8> {
        let mut name_id = [0u8; 64];
        assert_eq!(name.len(), 64);
        for i in 0..64 {
            name_id[i] = name[i];
        }

        let mut client = unwrap_result!(self.client.lock());
        let immutable_data_request = DataRequest::Immutable(XorName::new(name_id),
                                                                ImmutableDataType::Normal);
        match unwrap_result!(client.get(immutable_data_request, None)).get() {
            Ok(ref data) => {
                match data {
                    &Data::Immutable(ref rxd_data) => rxd_data.value().clone(),
                    _ => Vec::new(),
                }
            }
            Err(_) => Vec::new(),
        }
    }

    fn put(&self, _: Vec<u8>, data: Vec<u8>) {
        let immutable_data = ImmutableData::new(ImmutableDataType::Normal, data);
        unwrap_result!(unwrap_result!(self.client.lock())
                           .put(Data::Immutable(immutable_data), None));
    }
}
