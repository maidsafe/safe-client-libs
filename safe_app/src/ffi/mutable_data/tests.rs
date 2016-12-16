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

use futures::Future;
use maidsafe_utilities::thread;
use rand::{OsRng, Rng};
use routing::{Action, ClientError, EntryAction, MutableData, PermissionSet, User, Value, XorName};
use safe_core::{CoreError, DIR_TAG, FutureExt};
use safe_core::utils::test_utils::random_client;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::mpsc;
use test_utils::create_app;

// MD created by App. App lists it's own sign_pk in owners field: Put should
// fail - Rejected by MaidManagers. Should pass when it lists the owner's
// sign_pk instead
#[test]
fn md_created_by_app_1() {
    let app = create_app();
    let (tx, rx) = mpsc::channel();
    unwrap!(app.send(move |client, _app_context| {
        let mut rng = unwrap!(OsRng::new());

        let mut owners = BTreeSet::new();
        owners.insert(unwrap!(client.public_signing_key()));
        let name: XorName = rng.gen();
        let mdata = unwrap!(MutableData::new(name.clone(),
                                             DIR_TAG,
                                             BTreeMap::new(),
                                             BTreeMap::new(),
                                             owners));
        let cl2 = client.clone();
        client.put_mdata(mdata)
            .then(move |res| {
                match res {
                    Ok(()) => panic!("Put should be rejected by MaidManagers"),
                    Err(CoreError::RoutingClientError(ClientError::InvalidOwners)) => (),
                    Err(x) => panic!("Expected ClientError::InvalidOwners. Got {:?}", x),
                }
                let mut owners = BTreeSet::new();
                owners.insert(unwrap!(cl2.owner_key()));
                let mdata = unwrap!(MutableData::new(name,
                                                     DIR_TAG,
                                                     BTreeMap::new(),
                                                     BTreeMap::new(),
                                                     owners));
                cl2.put_mdata(mdata)
            })
            .map(move |()| unwrap!(tx.send(())))
            .map_err(|e| panic!("{:?}", e))
            .into_box().into()
    }));
    unwrap!(rx.recv());
}

// MD created by App properly: Should pass. App tries to change ownership -
// Should Fail by MaidManagers. App creates it's own account with the
// maid-managers. Now it tries changing ownership by routing it through it's MM
// instead of owners. It should still fail as DataManagers should enforce that
// the request is coming from MM of the owner (listed in the owners field of the
// stored MD).
#[test]
fn md_created_by_app_2() {
    let app = create_app();
    let (tx, rx) = mpsc::channel();
    let (alt_client_tx, alt_client_rx) = mpsc::channel();
    unwrap!(app.send(move |client, _app_context| {
        let mut rng = unwrap!(OsRng::new());
        let sign_pk = unwrap!(client.public_signing_key());

        let mut permissions = BTreeMap::new();
        let _ = permissions.insert(User::Key(sign_pk), {
            let mut s = PermissionSet::new();
            let _ = s.allow(Action::ManagePermissions);
            s
        });

        let mut owners = BTreeSet::new();
        owners.insert(unwrap!(client.owner_key()));

        let name: XorName = rng.gen();
        let mdata =
            unwrap!(MutableData::new(name.clone(), DIR_TAG, permissions, BTreeMap::new(), owners));
        let name2 = name.clone();
        let cl2 = client.clone();
        client.put_mdata(mdata)
            .then(move |res| {
                unwrap!(res);
                cl2.change_mdata_owner(name, DIR_TAG, sign_pk, 2)
            })
            .then(move |res| -> Result<_, ()> {
                match res {
                    Ok(()) => panic!("It should fail"),
                    Err(CoreError::RoutingClientError(ClientError::AccessDenied)) => (),
                    Err(x) => panic!("Expected ClientError::AccessDenied. Got {:?}", x),
                }
                unwrap!(alt_client_tx.send((name2, sign_pk)));
                Ok(())
            })
            .into_box()
            .into()
    }));
    let _joiner = thread::named("Alt client", || {
        random_client(move |client| {
            let (name, sign_pk) = unwrap!(alt_client_rx.recv());
            let cl2 = client.clone();
            client.ins_auth_key(sign_pk, 1)
                .then(move |res| {
                    unwrap!(res);
                    cl2.change_mdata_owner(name, DIR_TAG, sign_pk, 2)
                })
                .then(move |res| -> Result<(), ()> {
                    match res {
                        Ok(()) => panic!("It should fail"),
                        Err(CoreError::RoutingClientError(ClientError::AccessDenied)) => (),
                        Err(x) => panic!("Expected ClientError::AccessDenied. Got {:?}", x),
                    }
                    unwrap!(tx.send(()));
                    Ok(())
                })
        });
    });
    unwrap!(rx.recv());
}

// MD created by owner and given to a permitted App. Owner has listed that app
// is allowed to insert only. App tries to insert -should pass. App tries to
// update - should fail. App tries to change permission to allow itself to
// update - should fail to change permissions.
#[test]
fn md_created_by_app_3() {
    let app = create_app();
    let (tx, rx) = mpsc::channel();
    let (app_sign_pk_tx, app_sign_pk_rx) = mpsc::channel();
    let (name_tx, name_rx) = mpsc::channel();
    unwrap!(app.send(move |client, _app_context| {
        let sign_pk = unwrap!(client.public_signing_key());
        unwrap!(app_sign_pk_tx.send(sign_pk));
        let name: XorName = unwrap!(name_rx.recv());
        let mut actions = BTreeMap::new();
        let _ = actions.insert(vec![1, 2, 3, 4],
                               EntryAction::Ins(Value {
                                   content: vec![2, 3, 5],
                                   entry_version: 1,
                               }));
        let cl2 = client.clone();
        let cl3 = client.clone();
        let name2 = name.clone();
        client.mutate_mdata_entries(name.clone(), DIR_TAG, actions)
            .then(move |res| {
                unwrap!(res);
                let mut actions = BTreeMap::new();
                let _ = actions.insert(vec![1, 2, 3, 4],
                                       EntryAction::Update(Value {
                                           content: vec![2, 8, 5],
                                           entry_version: 2,
                                       }));
                cl2.mutate_mdata_entries(name, DIR_TAG, actions)
            })
            .then(move |res| {
                match res {
                    Ok(()) => panic!("It should fail"),
                    Err(CoreError::RoutingClientError(ClientError::AccessDenied)) => (),
                    Err(x) => panic!("Expected ClientError::AccessDenied. Got {:?}", x),
                }
                let user = User::Key(sign_pk);
                let mut permissions = PermissionSet::new();
                let _ = permissions.allow(Action::Update);
                cl3.set_mdata_user_permissions(name2, DIR_TAG, user, permissions, 2)
            })
            .then(move |res| -> Result<_, ()> {
                match res {
                    Ok(()) => panic!("It should fail"),
                    Err(CoreError::RoutingClientError(ClientError::AccessDenied)) => (),
                    Err(x) => panic!("Expected ClientError::AccessDenied. Got {:?}", x),
                }
                unwrap!(tx.send(()));
                Ok(())
            })
            .into_box()
            .into()
    }));
    let _joiner = thread::named("Alt client", || {
        random_client(move |client| {
            let app_sign_pk = unwrap!(app_sign_pk_rx.recv());
            let mut rng = unwrap!(OsRng::new());

            let mut permissions = BTreeMap::new();
            let _ = permissions.insert(User::Key(app_sign_pk), {
                let mut s = PermissionSet::new();
                let _ = s.allow(Action::Insert);
                s
            });

            let mut owners = BTreeSet::new();
            owners.insert(unwrap!(client.owner_key()));

            let name: XorName = rng.gen();

            let mdata = unwrap!(MutableData::new(name.clone(),
                                                 DIR_TAG,
                                                 permissions,
                                                 BTreeMap::new(),
                                                 owners));
            let cl2 = client.clone();
            client.ins_auth_key(app_sign_pk, 1)
                .and_then(move |()| {
                    cl2.put_mdata(mdata)
                })
                .map(move |()| unwrap!(name_tx.send(name)))
                .map_err(|e| panic!("{:?}", e))
        });
    });
    unwrap!(rx.recv());
}

// MD created by owner and given to a permitted App. Owner has listed that app
// is allowed to manage-permissions only. App tries to insert -should fail. App
// tries to update - should fail. App tries to change permission to allow itself
// to insert and delete - should pass to change permissions. Now App tires to
// insert again - should pass. App tries to update. Should fail. App tries to
// delete - should pass.
#[test]
fn md_created_by_app_4() {
    let app = create_app();
    let (tx, rx) = mpsc::channel();
    let (app_sign_pk_tx, app_sign_pk_rx) = mpsc::channel();
    let (name_tx, name_rx) = mpsc::channel();
    unwrap!(app.send(move |client, _app_context| {
        let sign_pk = unwrap!(client.public_signing_key());
        unwrap!(app_sign_pk_tx.send(sign_pk));
        let name: XorName = unwrap!(name_rx.recv());
        let mut actions = BTreeMap::new();
        let _ = actions.insert(vec![1, 2, 3, 4],
                               EntryAction::Ins(Value {
                                   content: vec![2, 3, 5],
                                   entry_version: 1,
                               }));
        let cl2 = client.clone();
        let cl3 = client.clone();
        let cl4 = client.clone();
        let cl5 = client.clone();
        let cl6 = client.clone();
        let name2 = name.clone();
        let name3 = name.clone();
        let name4 = name.clone();
        let name5 = name.clone();
        client.mutate_mdata_entries(name.clone(), DIR_TAG, actions)
            .then(move |res| {
                match res {
                    Ok(()) => panic!("It should fail"),
                    Err(CoreError::RoutingClientError(ClientError::AccessDenied)) => (),
                    Err(x) => panic!("Expected ClientError::AccessDenied. Got {:?}", x),
                }
                let mut actions = BTreeMap::new();
                let _ = actions.insert(vec![1, 8, 3, 4],
                                       EntryAction::Update(Value {
                                           content: vec![2, 8, 5],
                                           entry_version: 2,
                                       }));
                cl2.mutate_mdata_entries(name, DIR_TAG, actions)
            })
            .then(move |res| {
                match res {
                    Ok(()) => panic!("It should fail"),
                    Err(CoreError::RoutingClientError(ClientError::AccessDenied)) => (),
                    Err(x) => panic!("Expected ClientError::AccessDenied. Got {:?}", x),
                }
                let user = User::Key(sign_pk);
                let mut permissions = PermissionSet::new();
                let _ = permissions.allow(Action::Insert).allow(Action::Delete);
                cl3.set_mdata_user_permissions(name2, DIR_TAG, user,
                                               permissions, 1)
            })
            .then(move |res| {
                unwrap!(res);
                let mut actions = BTreeMap::new();
                let _ = actions.insert(vec![1, 2, 3, 4],
                                       EntryAction::Ins(Value {
                                           content: vec![2, 3, 5],
                                           entry_version: 1,
                                       }));
                cl4.mutate_mdata_entries(name3, DIR_TAG, actions)
            })
            .then(move |res| {
                unwrap!(res);
                let mut actions = BTreeMap::new();
                let _ = actions.insert(vec![1, 2, 3, 4],
                                       EntryAction::Update(Value {
                                           content: vec![2, 8, 5],
                                           entry_version: 2,
                                       }));
                cl5.mutate_mdata_entries(name4, DIR_TAG, actions)
            })
            .then(move |res| {
                match res {
                    Ok(()) => panic!("It should fail"),
                    Err(CoreError::RoutingClientError(ClientError::AccessDenied)) => (),
                    Err(x) => panic!("Expected ClientError::AccessDenied. Got {:?}", x),
                }
                let mut actions = BTreeMap::new();
                let _ = actions.insert(vec![1, 2, 3, 4],
                                       EntryAction::Del(2));
                cl6.mutate_mdata_entries(name5, DIR_TAG, actions)
            })
            .map(move |()| unwrap!(tx.send(())))
            .map_err(|e| panic!("{:?}", e))
            .into_box()
            .into()
    }));
    let _joiner = thread::named("Alt client", || {
        random_client(move |client| {
            let app_sign_pk = unwrap!(app_sign_pk_rx.recv());
            let mut rng = unwrap!(OsRng::new());

            let mut permissions = BTreeMap::new();
            let _ = permissions.insert(User::Key(app_sign_pk), {
                let mut s = PermissionSet::new();
                let _ = s.allow(Action::ManagePermissions);
                s
            });

            let mut data = BTreeMap::new();
            let _ = data.insert(vec![1, 8, 3, 4],
                                Value {
                                    content: vec![1],
                                    entry_version: 1,
                                });

            let mut owners = BTreeSet::new();
            owners.insert(unwrap!(client.owner_key()));

            let name: XorName = rng.gen();

            let mdata = unwrap!(MutableData::new(name.clone(), DIR_TAG, permissions, data, owners));
            let cl2 = client.clone();
            client.ins_auth_key(app_sign_pk, 1)
                .and_then(move |()| {
                    cl2.put_mdata(mdata)
                })
                .map(move |()| unwrap!(name_tx.send(name)))
                .map_err(|e| panic!("{:?}", e))
        });
    });
    unwrap!(rx.recv());
}
