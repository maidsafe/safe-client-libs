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

use app::{App, AppContext};
use futures::{Future, IntoFuture, future};
use maidsafe_utilities::serialisation::serialise;
use rand;
use routing::{Action, MutableData, PermissionSet, User, Value};
use rust_sodium::crypto::{box_, secretbox, sign};
use rust_sodium::crypto::hash::sha256;
use safe_core::{Client, CoreFuture, FutureExt, MDataInfo, utils};
use safe_core::ipc::{AccessContInfo, AppExchangeInfo, AppKeys, AuthGranted, Config, Permission};
use safe_core::utils::test_utils::random_client;
use std::collections::{BTreeSet, HashMap};
use std::sync::mpsc;
use super::errors::AppError;

const ACCESS_CONTAINER_TAG: u64 = 1000;

// Run the given closure inside the app's event loop. The return value of
// the closure is returned immediately.
pub fn run_now<F, R>(app: &App, f: F) -> R
    where F: FnOnce(&Client, &AppContext) -> R + Send + 'static,
          R: Send + 'static
{
    let (tx, rx) = mpsc::channel();

    unwrap!(app.send(move |client, context| {
        unwrap!(tx.send(f(client, context)));
        None
    }));

    unwrap!(rx.recv())
}

// Run the given closure inside the app event loop. The closure should
// return a future which will then be driven to completion and its result
// returned.
pub fn run<F, I, T>(app: &App, f: F) -> T
    where F: FnOnce(&Client, &AppContext) -> I + Send + 'static,
          I: IntoFuture<Item = T, Error = AppError> + 'static,
          T: Send + 'static
{
    let (tx, rx) = mpsc::channel();

    unwrap!(app.send(move |client, app| {
        let future = f(client, app)
            .into_future()
            .then(move |result| {
                unwrap!(tx.send(result));
                Ok(())
            })
            .into_box();

        Some(future)
    }));

    unwrap!(unwrap!(rx.recv()))
}


/// Create random AuthGranted for testing
pub fn create_random_auth_granted() -> AuthGranted {
    let enc_key = secretbox::gen_key();
    let (sign_pk, sign_sk) = sign::gen_keypair();
    let (enc_pk, enc_sk) = box_::gen_keypair();

    // Create account and authorize the app key.
    let owner_key = random_client(move |client| {
        let owner_key = unwrap!(client.owner_key());
        client.ins_auth_key(sign_pk, 1).map(move |_| owner_key)
    });

    let app_keys = AppKeys {
        owner_key: owner_key,
        enc_key: enc_key,
        sign_pk: sign_pk,
        sign_sk: sign_sk,
        enc_pk: enc_pk,
        enc_sk: enc_sk,
    };

    let access_container = AccessContInfo {
        id: rand::random(),
        tag: ACCESS_CONTAINER_TAG,
        nonce: secretbox::gen_nonce(),
    };

    AuthGranted {
        app_keys: app_keys,
        bootstrap_config: Config,
        access_container: access_container,
    }
}

pub fn create_random_app_info() -> AppExchangeInfo {
    AppExchangeInfo {
        id: unwrap!(utils::generate_random_string(10)),
        scope: None,
        name: unwrap!(utils::generate_random_string(10)),
        vendor: unwrap!(utils::generate_random_string(10)),
    }
}

// Create registered app.
pub fn create_app() -> App {
    unwrap!(App::registered(create_random_app_info(),
                            create_random_auth_granted(),
                            |_network_event| ()))
}

/*
// Create unregistered app.
pub fn create_unregistered_app() -> App {
    unwrap!(App::unregistered(|_| ()))
}
*/

// Create app and grant it access to the specified containers.
// If `create_containers` is true, also create all the containers specified in
// the `access_info` and set their permissions accordingly.
pub fn create_app_with_access(access_info: HashMap<String, (MDataInfo, BTreeSet<Permission>)>,
                              create_containers: bool)
                              -> App {
    let app_info = AppExchangeInfo {
        id: unwrap!(utils::generate_random_string(10)),
        scope: None,
        name: "App Test".to_string(),
        vendor: "MaidSafe Ltd.".to_string(),
    };
    let enc_key = secretbox::gen_key();
    let (sign_pk, sign_sk) = sign::gen_keypair();
    let (enc_pk, enc_sk) = box_::gen_keypair();

    // Create the access container.
    let access_container_info = AccessContInfo {
        id: rand::random(),
        tag: ACCESS_CONTAINER_TAG,
        nonce: secretbox::gen_nonce(),
    };

    let access_container_key =
        unwrap!(utils::symmetric_encrypt(&sha256::hash(app_info.id.as_bytes()).0,
                                         &enc_key,
                                         Some(&access_container_info.nonce)));

    let access_container_value = {
        let value = unwrap!(serialise(&access_info));
        unwrap!(utils::symmetric_encrypt(&value, &enc_key, None))
    };

    let access_container_entries = btree_map![
            access_container_key => Value {
                content: access_container_value,
                entry_version: 0,
            }
        ];

    let access_container_name = access_container_info.id;
    let access_container_type_tag = access_container_info.tag;

    let container_infos: Vec<_> = access_info.into_iter().map(|(_key, (info, _))| info).collect();

    // Put the access container on the network and authorise the app.
    let owner_key = random_client(move |client| {
        let owner_key = unwrap!(client.owner_key());

        let access_container = unwrap!(MutableData::new(access_container_name,
                                                        access_container_type_tag,
                                                        Default::default(),
                                                        access_container_entries,
                                                        btree_set![owner_key]));

        let f1 = client.put_mdata(access_container);
        let f2 = client.ins_auth_key(sign_pk, 1);
        let f3 = if create_containers {
            create_all_mdata(client.clone(), container_infos)
        } else {
            future::ok(()).into_box()
        };

        f1.join3(f2, f3).map(move |_| owner_key)
    });

    let app_keys = AppKeys {
        owner_key: owner_key,
        enc_key: enc_key,
        sign_pk: sign_pk,
        sign_sk: sign_sk,
        enc_pk: enc_pk,
        enc_sk: enc_sk,
    };

    let auth_granted = AuthGranted {
        app_keys: app_keys,
        bootstrap_config: Config,
        access_container: access_container_info,
    };

    unwrap!(App::registered(app_info, auth_granted, |_| ()))
}

fn create_all_mdata(client: Client, infos: Vec<MDataInfo>) -> Box<CoreFuture<()>> {
    let owner_key = unwrap!(client.owner_key());

    // Allow everything for anyone.
    let permissions = {
        let set =
            PermissionSet::new().allow(Action::Insert).allow(Action::Update).allow(Action::Delete);
        btree_map![User::Anyone => set]
    };

    // FIXME: it should not be necessary to `collect` here, but
    // without it the compiler chokes on "reached the recursion limit during
    // monomorphization (selection ambiguity)"
    let futs: Vec<_> = infos.into_iter()
        .map(move |info| {
            let mdata = unwrap!(MutableData::new(info.name,
                                                 info.type_tag,
                                                 permissions.clone(),
                                                 Default::default(),
                                                 btree_set![owner_key]));

            client.put_mdata(mdata)
        })
        .collect();

    future::join_all(futs).map(|_| ()).into_box()
}
