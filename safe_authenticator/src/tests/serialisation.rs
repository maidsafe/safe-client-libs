// Copyright 2017 MaidSafe.net limited.
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

//! These tests ensure binary compatibility between different versions of safe_client_libs.

#![cfg(feature = "use-mock-routing")]

use AuthError;
use AuthFuture;
use Authenticator;
use access_container;
use futures::{Future, future};
use rand::{Rng, SeedableRng, XorShiftRng};
use safe_core::{Client, FutureExt, MDataInfo};
use safe_core::{config_handler, mock_vault_path};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std_dirs::{DEFAULT_PRIVATE_DIRS, DEFAULT_PUBLIC_DIRS};

#[test]
fn write_data() {
    let (stash, vault_path) = setup();

    // Clear the vault store.
    unwrap!(fs::remove_file(vault_path));

    let _auth =
        unwrap!(Authenticator::create_acc(
        stash.locator.clone(),
        stash.password.clone(),
        stash.invitation.clone(),
        |_| (),
    ));

}

#[test]
fn read_data() {
    let (stash, _) = setup();

    let auth = unwrap!(Authenticator::login(
        stash.locator.clone(),
        stash.password.clone(),
        |_| (),
    ));

    unwrap!(auth.send(move |client| {
        let c0 = client.clone();

        // Read access container and ensure all standard containers exists.
        access_container::fetch_authenticator_entry(client)
            .then(move |res| {
                let (_, containers) = unwrap!(res);
                verify_std_dirs(&c0, &containers)
            })
            .then(|res| {
                unwrap!(res);
                Ok(())
            })
            .into_box()
            .into()
    }));
}

fn verify_std_dirs(
    client: &Client<()>,
    actual_containers: &HashMap<String, MDataInfo>,
) -> Box<AuthFuture<()>> {
    let futures: Vec<_> = DEFAULT_PUBLIC_DIRS
        .iter()
        .chain(DEFAULT_PRIVATE_DIRS.iter())
        .map(|expected_container| {
            let mi = unwrap!(actual_containers.get(*expected_container));
            client.get_mdata_version(mi.name, mi.type_tag)
        })
        .collect();

    future::join_all(futures)
        .map_err(AuthError::from)
        .then(|res| {
            let _ = unwrap!(res);
            Ok(())
        })
        .into_box()
}

struct Stash {
    locator: String,
    password: String,
    invitation: String,
}

fn setup() -> (Stash, PathBuf) {
    // File store is required.
    let config = config_handler::get_config();
    let has_file_store = config
        .dev
        .as_ref()
        .map(|dev| dev.mock_in_memory_storage == false)
        .unwrap_or(true);

    assert!(
        has_file_store,
        "This test requires file-backed vault store."
    );

    // IMPORTANT: Use constant seed for repeatability.
    let mut rng = XorShiftRng::from_seed([0, 1, 2, 3]);
    let stash = Stash {
        locator: rng.gen_ascii_chars().take(16).collect(),
        password: rng.gen_ascii_chars().take(16).collect(),
        invitation: String::new(),
    };

    (stash, mock_vault_path(&config))
}
