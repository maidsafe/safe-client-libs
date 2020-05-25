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
use crate::immutable_data;
use crate::nfs::NfsError;
use bincode::{deserialize, serialize};
use safe_nd::{IDataAddress, XorName};
use self_encryption::DataMap;

// Get `DataMap` from the network.
// If the `DataMap` is encrypted, an `encryption_key` must be passed in to decrypt it.
pub async fn get(
    client: &(impl Client + 'static),
    address: IDataAddress,
    encryption_key: Option<shared_secretbox::Key>,
) -> Result<DataMap, NfsError> {
    let content = immutable_data::get_value(client, address, None, None, encryption_key).await?;

    deserialize(&content).map_err(From::from)
}

// Put `DataMap` on the network.
// If `encryption_key` is passed in, the `DataMap` will be encrypted.
pub async fn put(
    client: &(impl Client + 'static),
    data_map: &DataMap,
    published: bool,
    encryption_key: Option<shared_secretbox::Key>,
) -> Result<XorName, NfsError> {
    let client = client.clone();
    let client2 = client.clone();

    let encoded = serialize(&data_map)?;

    let data = immutable_data::create(&client, &encoded, published, encryption_key).await?;

    let name = *data.name();
    client2.put_idata(data).await?;

    Ok(name)
}
