// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net
// Commercial License, version 1.0 or later, or (2) The General Public License
// (GPL), version 3, depending on which licence you accepted on initial access
// to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project
// generally, you agree to be bound by the terms of the MaidSafe Contributor
// Agreement, version 1.0.
// This, along with the Licenses can be found in the root directory of this
// project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network
// Software distributed under the GPL Licence is distributed on an "AS IS"
// BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
//
// Please review the Licences for the specific language governing permissions
// and limitations relating to use of the SAFE Network Software.

//! `DataMap` utilities

use core::{Client, FutureExt, immutable_data};
use futures::{Future, future};
use maidsafe_utilities::serialisation::{deserialise, serialise};
use nfs::NfsFuture;
use routing::XorName;
use self_encryption::DataMap;

// GET `DataMap` from the network.
pub fn get(client: &Client, name: &XorName) -> Box<NfsFuture<DataMap>> {
    immutable_data::get_value(client, name, None)
        .map_err(From::from)
        .and_then(move |content| deserialise(&content).map_err(From::from))
        .into_box()
}

// PUT `DataMap` on the network.
pub fn put(client: &Client, data_map: DataMap) -> Box<NfsFuture<XorName>> {
    let client = client.clone();
    let client2 = client.clone();

    future::result(serialise(&data_map))
        .map_err(From::from)
        .and_then(move |encoded| immutable_data::create(&client, encoded, None))
        .and_then(move |data| {
            let name = *data.name();
            client2.put_idata(data).map(move |_| name)
        })
        .map_err(From::from)
        .into_box()
}
