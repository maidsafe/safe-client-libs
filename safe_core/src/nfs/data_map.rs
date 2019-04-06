// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! `DataMap` utilities

use crate::client::Client;
use crate::crypto::shared_secretbox;
use futures::{future, Future};
use crate::immutable_data;
use maidsafe_utilities::serialisation::{deserialise, serialise};
use crate::nfs::NfsFuture;
use routing::XorName;
use self_encryption::DataMap;
use crate::utils::FutureExt;

// Get `DataMap` from the network.
// If the `DataMap` is encrypted, an `encryption_key` must be passed in to decrypt it.
pub fn get(
    client: &impl Client,
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
pub fn put(
    client: &impl Client,
    data_map: &DataMap,
    encryption_key: Option<shared_secretbox::Key>,
) -> Box<NfsFuture<XorName>> {
    let client = client.clone();
    let client2 = client.clone();

    future::result(serialise(&data_map))
        .map_err(From::from)
        .and_then(move |encoded| immutable_data::create(&client, &encoded, encryption_key))
        .and_then(move |data| {
            let name = *data.name();
            client2.put_idata(data).map(move |_| name)
        }).map_err(From::from)
        .into_box()
}
