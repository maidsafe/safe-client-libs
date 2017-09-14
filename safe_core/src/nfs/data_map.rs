// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement.  This, along with the Licenses can be
// found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

//! `DataMap` utilities

use client::Client;
use crypto::shared_secretbox;
use futures::{Future, future};
use immutable_data;
use maidsafe_utilities::serialisation::{deserialise, serialise};
use nfs::NfsFuture;
use routing::XorName;
use self_encryption::DataMap;
use utils::FutureExt;

// Get `DataMap` from the network.
// If the `DataMap` is encrypted, an `encryption_key` must be passed in to decrypt it.
pub fn get<T: 'static>(
    client: &Client<T>,
    name: &XorName,
    encryption_key: Option<shared_secretbox::Key>,
) -> Box<NfsFuture<DataMap>> {
    immutable_data::get_value(client, name, encryption_key)
        .map_err(From::from)
        .and_then(move |content| deserialise(&content).map_err(From::from))
        .into_box()
}

// Put `DataMap` on the network.
// If `encryption_key` is passed in, the `DataMap` will be encrypted.
pub fn put<T: 'static>(
    client: &Client<T>,
    data_map: &DataMap,
    encryption_key: Option<shared_secretbox::Key>,
) -> Box<NfsFuture<XorName>> {
    let client = client.clone();
    let client2 = client.clone();

    future::result(serialise(&data_map))
        .map_err(From::from)
        .and_then(move |encoded| {
            immutable_data::create(&client, &encoded, encryption_key)
        })
        .and_then(move |data| {
            let name = *data.name();
            client2.put_idata(data).map(move |_| name)
        })
        .map_err(From::from)
        .into_box()
}
