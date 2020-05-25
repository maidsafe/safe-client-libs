// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! Integration tests for Safe Client Libs.

#![cfg(test)]
// For explanation of lint checks, run `rustc -W help`.
#![deny(unsafe_code)]
#![warn(
    missing_docs,
    trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    unused_results
)]

use safe_app::{App, AppError, Client, PubImmutableData};
use safe_core::utils;
use safe_core::utils::test_utils::random_client;
use unwrap::unwrap;

// Test unregistered clients.
// 1. Have a registered client PUT something on the network.
// 2. Try to read it as unregistered.
#[tokio::test]
async fn unregistered_client() -> Result<(), AppError> {
    let orig_data = PubImmutableData::new(unwrap!(utils::generate_random_vector(30)));

    let client = random_client()?;
    // Registered Client PUTs something onto the network.
    {
        let orig_data = orig_data.clone();
        client.put_idata(orig_data).await?;
    }

    // Unregistered Client should be able to retrieve the data.
    let _app = App::unregistered(|| (), None).await?;

    let data = client.get_idata(*orig_data.address()).await?;
    assert_eq!(data, orig_data.into());
    Ok(())
}
