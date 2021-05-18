// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use anyhow::{Context, Result};
use sn_client::{utils::test_utils::read_network_conn_info, Client};
use sn_url::{SafeContentType, SafeUrl, DEFAULT_XORURL_BASE};
use std::io::{stdout, Write};

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    println!("Creating a Client...");
    let bootstrap_contacts = read_network_conn_info()?;

    let client = Client::new(None, None, Some(bootstrap_contacts)).await?;

    let pk = client.public_key().await;
    println!("Client Public Key: {}", pk);

    let random_num: u64 = rand::random();
    let raw_data = format!("Hello Safe World #{}", random_num);
    println!("Storing data on Blob: {}", raw_data);

    let address = client.store_public_blob(raw_data.as_bytes()).await?;
    let xorurl = SafeUrl::encode_blob(*address.name(), SafeContentType::Raw, DEFAULT_XORURL_BASE)?;
    println!("Blob stored at xorurl: {}", xorurl);

    let data = client.read_blob(address, None, None).await?;
    println!("Blob read from {:?}:", address);
    stdout()
        .write_all(&data)
        .context("Failed to print out the content of the Blob")?;

    Ok(())
}
