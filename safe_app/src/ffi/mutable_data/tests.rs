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

use futures::Future;
use maidsafe_utilities::thread;
use rand::{OsRng, Rng};
use routing::{Action, ClientError, EntryAction, MutableData, PermissionSet, User, Value, XorName};
use rust_sodium::crypto::sign;
use safe_core::{CoreError, DIR_TAG, FutureExt};
use safe_core::utils::test_utils::random_client;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::mpsc;
use std::time::Duration;
use test_utils::{create_app, run};

// MD created by App. App lists it's own sign_pk in owners field: Put should
// fail - Rejected by MaidManagers. Should pass when it lists the owner's
// sign_pk instead
#[test]
fn md_created_by_app_1() {
    let app = create_app();
    run(&app, |client, _app_context| {
        let mut rng = unwrap!(OsRng::new());

        let mut owners = BTreeSet::new();
        owners.insert(unwrap!(client.public_signing_key()));
        let name: XorName = rng.gen();
        let mdata =
            unwrap!(MutableData::new(name, DIR_TAG, BTreeMap::new(), BTreeMap::new(), owners));
        let cl2 = client.clone();
        client
            .put_mdata(mdata)
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
            .map_err(|e| panic!("{:?}", e))
    });
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
        let _ = permissions.insert(User::Key(sign_pk),
                                   PermissionSet::new().allow(Action::ManagePermissions));

        let owners = btree_set![unwrap!(client.owner_key())];

        let name: XorName = rng.gen();
        let mdata = unwrap!(MutableData::new(name, DIR_TAG, permissions, BTreeMap::new(), owners));
        let name2 = name;
        let cl2 = client.clone();
        client
            .put_mdata(mdata)
            .then(move |res| {
                      unwrap!(res);
                      cl2.change_mdata_owner(name, DIR_TAG, sign_pk, 1)
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
            let cl3 = client.clone();
            client
                .list_auth_keys_and_version()
                .then(move |res| {
                          let (_, version) = unwrap!(res);
                          cl2.ins_auth_key(sign_pk, version + 1)
                      })
                .then(move |res| {
                          unwrap!(res);
                          cl3.change_mdata_owner(name, DIR_TAG, sign_pk, 1)
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
        let name2 = name;
        client
            .mutate_mdata_entries(name, DIR_TAG, actions)
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
                let permissions = PermissionSet::new().allow(Action::Update);
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
            let _ = permissions.insert(User::Key(app_sign_pk),
                                       PermissionSet::new().allow(Action::Insert));

            let mut owners = BTreeSet::new();
            owners.insert(unwrap!(client.owner_key()));

            let name: XorName = rng.gen();

            let mdata =
                unwrap!(MutableData::new(name, DIR_TAG, permissions, BTreeMap::new(), owners));
            let cl2 = client.clone();
            let cl3 = client.clone();

            client.list_auth_keys_and_version()
                .then(move |res| {
                    let (_, version) = unwrap!(res);
                    cl2.ins_auth_key(app_sign_pk, version + 1)
                })
                .then(move |res| {
                    unwrap!(res);
                    cl3.put_mdata(mdata)
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
        let name2 = name;
        let name3 = name;
        let name4 = name;
        let name5 = name;
        client.mutate_mdata_entries(name, DIR_TAG, actions)
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
                let permissions = PermissionSet::new().allow(Action::Insert).allow(Action::Delete);
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
            let _ =
                permissions.insert(User::Key(app_sign_pk),
                                   PermissionSet::new().allow(Action::ManagePermissions));

            let mut data = BTreeMap::new();
            let _ = data.insert(vec![1, 8, 3, 4],
                                Value {
                                    content: vec![1],
                                    entry_version: 1,
                                });

            let mut owners = BTreeSet::new();
            owners.insert(unwrap!(client.owner_key()));

            let name: XorName = rng.gen();

            let mdata = unwrap!(MutableData::new(name, DIR_TAG, permissions, data, owners));
            let cl2 = client.clone();
            let cl3 = client.clone();

            client.list_auth_keys_and_version()
                .then(move |res| {
                    let (_, version) = unwrap!(res);
                    cl2.ins_auth_key(app_sign_pk, version + 1)
                })
                .then(move |res| {
                    unwrap!(res);
                    cl3.put_mdata(mdata)
                })
                .map(move |()| unwrap!(name_tx.send(name)))
                .map_err(|e| panic!("{:?}", e))
        });
    });
    unwrap!(rx.recv());
}

// MD created by App1, with permission to insert by anyone and permission to
// manage-permissions only for itself - should pass. App2 created via another
// random client2 tries to insert (going via client2's MM) into MD of App1 -
// should Pass. App1 should be able to read the data - should pass. App1 changes
// permission to remove the anyone access - should pass. App2 tries to insert
// another data in MD - should fail. App1 tries to get all data from MD - should
// pass and should have no change (since App2 failed to insert)
#[test]
fn multiple_apps() {
    let app1 = create_app();
    let app2 = create_app();
    let (tx, rx) = mpsc::channel();
    let (name_tx, name_rx) = mpsc::channel();
    let (entry_tx, entry_rx) = mpsc::channel();
    let (mutate_again_tx, mutate_again_rx) = mpsc::channel();
    let (final_check_tx, final_check_rx) = mpsc::channel();
    unwrap!(app1.send(move |client, _app_context| {
        let mut rng = unwrap!(OsRng::new());
        let sign_pk = unwrap!(client.public_signing_key());

        let mut permissions = BTreeMap::new();
        let _ = permissions.insert(User::Anyone, PermissionSet::new().allow(Action::Insert));
        let _ = permissions.insert(User::Key(sign_pk),
                                   PermissionSet::new().allow(Action::ManagePermissions));

        let mut owners = BTreeSet::new();
        owners.insert(unwrap!(client.owner_key()));

        let name: XorName = rng.gen();
        let mdata = unwrap!(MutableData::new(name, DIR_TAG, permissions, BTreeMap::new(), owners));
        let cl2 = client.clone();
        let cl3 = client.clone();
        let cl4 = client.clone();
        let name2 = name;
        let name3 = name;
        client
            .put_mdata(mdata)
            .then(move |res| {
                      unwrap!(res);
                      unwrap!(name_tx.send(name));
                      let entry_key: Vec<u8> = unwrap!(entry_rx.recv());
                      cl2.get_mdata_value(name, DIR_TAG, entry_key.clone())
                          .map(move |v| (v, entry_key))
                  })
            .then(move |res| {
                let (value, entry_key) = unwrap!(res);
                assert_eq!(value,
                           Value {
                               content: vec![8],
                               entry_version: 1,
                           });
                cl3.del_mdata_user_permissions(name2, DIR_TAG, User::Anyone, 1)
                    .map(move |()| entry_key)
            })
            .then(move |res| {
                      let entry_key = unwrap!(res);
                      unwrap!(mutate_again_tx.send(()));
                      unwrap!(final_check_rx.recv());
                      cl4.list_mdata_keys(name3, DIR_TAG)
                          .map(move |x| (x, entry_key))
                  })
            .then(move |res| -> Result<_, ()> {
                      let (keys, entry_key) = unwrap!(res);
                      assert_eq!(keys.len(), 1);
                      assert!(keys.contains(&entry_key));
                      unwrap!(tx.send(()));
                      Ok(())
                  })
            .into_box()
            .into()
    }));
    unwrap!(app2.send(move |client, _app_context| {
        let name = unwrap!(name_rx.recv());
        let entry_key = vec![1, 2, 3];

        let mut actions = BTreeMap::new();
        let _ = actions.insert(entry_key.clone(),
                               EntryAction::Ins(Value {
                                                    content: vec![8],
                                                    entry_version: 1,
                                                }));

        let cl2 = client.clone();
        client
            .mutate_mdata_entries(name, DIR_TAG, actions)
            .then(move |res| {
                unwrap!(res);
                unwrap!(entry_tx.send(entry_key));
                unwrap!(mutate_again_rx.recv());

                let mut actions = BTreeMap::new();
                let _ = actions.insert(vec![2, 2, 2],
                                       EntryAction::Ins(Value {
                                                            content: vec![21],
                                                            entry_version: 1,
                                                        }));

                cl2.mutate_mdata_entries(name, DIR_TAG, actions)
            })
            .then(move |res| -> Result<_, ()> {
                match res {
                    Ok(()) => panic!("It should fail"),
                    Err(CoreError::RoutingClientError(ClientError::AccessDenied)) => (),
                    Err(x) => panic!("Expected ClientError::AccessDenied. Got {:?}", x),
                }
                unwrap!(final_check_tx.send(()));
                Ok(())
            })
            .into_box()
            .into()
    }));
    unwrap!(rx.recv());
}

// MD created by App with itself allowed to manage-permissions. Insert
// permission to allow a random-key to perform update operation - should
// pass. Delete this permission without incrementing version of MD - should fail
// version check. Querry the permissions list - should continue to have the
// listed permission for the random-key. Querry the version of the MD in network
// - should pass. Send request to delete that permission again with propely
// incremented version from info from the fetched version - should pass. Querry
// the permissions list - should no longer have the listed permission for the
// random-key.
#[test]
fn permissions_and_version() {
    let app = create_app();
    run(&app, |client, _app_context| {
        let mut rng = unwrap!(OsRng::new());
        let sign_pk = unwrap!(client.public_signing_key());
        let (random_key, _) = sign::gen_keypair();

        let mut permissions = BTreeMap::new();
        let _ = permissions.insert(User::Key(sign_pk),
                                   PermissionSet::new().allow(Action::ManagePermissions));

        let mut owners = BTreeSet::new();
        owners.insert(unwrap!(client.owner_key()));

        let name: XorName = rng.gen();
        let mdata = unwrap!(MutableData::new(name, DIR_TAG, permissions, BTreeMap::new(), owners));
        let cl2 = client.clone();
        let cl3 = client.clone();
        let cl4 = client.clone();
        let cl5 = client.clone();
        let cl6 = client.clone();
        let cl7 = client.clone();
        client
            .put_mdata(mdata)
            .then(move |res| {
                unwrap!(res);
                let permissions = PermissionSet::new().allow(Action::Update);
                cl2.set_mdata_user_permissions(name, DIR_TAG, User::Key(random_key), permissions, 1)
            })
            .then(move |res| {
                      unwrap!(res);
                      cl3.del_mdata_user_permissions(name, DIR_TAG, User::Key(random_key), 1)
                  })
            .then(move |res| {
                      match res {
                          Ok(()) => panic!("It should fail with invalid successor"),
                          Err(CoreError::RoutingClientError(ClientError::InvalidSuccessor)) => (),
                          Err(x) => panic!("Expected ClientError::InvalidSuccessor. Got {:?}", x),
                      }
                      cl4.list_mdata_permissions(name, DIR_TAG)
                  })
            .then(move |res| {
                let permissions = unwrap!(res);
                assert_eq!(permissions.len(), 2);
                assert_eq!(unwrap!(permissions.get(&User::Key(sign_pk)))
                               .is_allowed(Action::Insert),
                           None);
                assert_eq!(unwrap!(permissions.get(&User::Key(sign_pk)))
                               .is_allowed(Action::Update),
                           None);
                assert_eq!(unwrap!(permissions.get(&User::Key(sign_pk)))
                               .is_allowed(Action::Delete),
                           None);
                assert_eq!(unwrap!(permissions.get(&User::Key(sign_pk)))
                               .is_allowed(Action::ManagePermissions),
                           Some(true));
                assert_eq!(unwrap!(permissions.get(&User::Key(random_key)))
                               .is_allowed(Action::Insert),
                           None);
                assert_eq!(unwrap!(permissions.get(&User::Key(random_key)))
                               .is_allowed(Action::Update),
                           Some(true));
                assert_eq!(unwrap!(permissions.get(&User::Key(random_key)))
                               .is_allowed(Action::Delete),
                           None);
                assert_eq!(unwrap!(permissions.get(&User::Key(random_key)))
                               .is_allowed(Action::ManagePermissions),
                           None);
                cl5.get_mdata_version(name, DIR_TAG)
            })
            .then(move |res| {
                      let v = unwrap!(res);
                      assert_eq!(v, 1);
                      cl6.del_mdata_user_permissions(name, DIR_TAG, User::Key(random_key), v + 1)
                  })
            .then(move |res| {
                      unwrap!(res);
                      cl7.list_mdata_permissions(name, DIR_TAG)
                  })
            .map(move |permissions| {
                assert_eq!(permissions.len(), 1);
                assert_eq!(unwrap!(permissions.get(&User::Key(sign_pk)))
                               .is_allowed(Action::Insert),
                           None);
                assert_eq!(unwrap!(permissions.get(&User::Key(sign_pk)))
                               .is_allowed(Action::Update),
                           None);
                assert_eq!(unwrap!(permissions.get(&User::Key(sign_pk)))
                               .is_allowed(Action::Delete),
                           None);
                assert_eq!(unwrap!(permissions.get(&User::Key(sign_pk)))
                               .is_allowed(Action::ManagePermissions),
                           Some(true));
            })
            .map_err(|e| panic!("{:?}", e))
    });
}

// The usual test to insert, update, delete and list all permissions. put in
// some permissions, fetch (list) all of them, add some more, list again, delete
// one or two, list again - all should pass and do the expected (i.e. after list
// do assert that it contains all the expected stuff, don't just pass test if
// the list was successful)
#[test]
fn permissions_crud() {
    let app = create_app();
    run(&app, |client, _app_context| {
        let mut rng = unwrap!(OsRng::new());
        let sign_pk = unwrap!(client.public_signing_key());
        let (random_key_a, _) = sign::gen_keypair();
        let (random_key_b, _) = sign::gen_keypair();

        let mut permissions = BTreeMap::new();
        let _ = permissions.insert(User::Key(sign_pk),
                                   PermissionSet::new().allow(Action::ManagePermissions));

        let mut owners = BTreeSet::new();
        owners.insert(unwrap!(client.owner_key()));

        let name: XorName = rng.gen();
        let mdata = unwrap!(MutableData::new(name, DIR_TAG, permissions, BTreeMap::new(), owners));

        let cl2 = client.clone();
        let cl3 = client.clone();
        let cl4 = client.clone();
        let cl5 = client.clone();
        let cl6 = client.clone();
        let cl7 = client.clone();
        let cl8 = client.clone();
        let cl9 = client.clone();
        let cl10 = client.clone();
        client
            .put_mdata(mdata)
            .then(move |res| {
                unwrap!(res);
                let permissions = PermissionSet::new()
                    .allow(Action::Insert)
                    .allow(Action::Delete);
                cl2.set_mdata_user_permissions(name,
                                               DIR_TAG,
                                               User::Key(random_key_a),
                                               permissions,
                                               1)
            })
            .then(move |res| {
                      unwrap!(res);
                      cl3.list_mdata_permissions(name, DIR_TAG)
                  })
            .then(move |res| {
                {
                    let permissions = unwrap!(res);
                    assert_eq!(permissions.len(), 2);
                    assert_eq!(unwrap!(permissions.get(&User::Key(sign_pk)))
                                   .is_allowed(Action::Insert),
                               None);
                    assert_eq!(unwrap!(permissions.get(&User::Key(sign_pk)))
                                   .is_allowed(Action::Update),
                               None);
                    assert_eq!(unwrap!(permissions.get(&User::Key(sign_pk)))
                                   .is_allowed(Action::Delete),
                               None);
                    assert_eq!(unwrap!(permissions.get(&User::Key(sign_pk)))
                                   .is_allowed(Action::ManagePermissions),
                               Some(true));
                    assert_eq!(unwrap!(permissions.get(&User::Key(random_key_a)))
                                   .is_allowed(Action::Insert),
                               Some(true));
                    assert_eq!(unwrap!(permissions.get(&User::Key(random_key_a)))
                                   .is_allowed(Action::Update),
                               None);
                    assert_eq!(unwrap!(permissions.get(&User::Key(random_key_a)))
                                   .is_allowed(Action::Delete),
                               Some(true));
                    assert_eq!(unwrap!(permissions.get(&User::Key(random_key_a)))
                                   .is_allowed(Action::ManagePermissions),
                               None);
                }

                let permissions = PermissionSet::new().deny(Action::Insert);
                cl4.set_mdata_user_permissions(name,
                                               DIR_TAG,
                                               User::Key(random_key_b),
                                               permissions,
                                               2)
            })
            .then(move |res| {
                      unwrap!(res);
                      cl5.list_mdata_permissions(name, DIR_TAG)
                  })
            .then(move |res| {
                {
                    let permissions = unwrap!(res);
                    assert_eq!(permissions.len(), 3);
                    assert_eq!(unwrap!(permissions.get(&User::Key(sign_pk)))
                                   .is_allowed(Action::Insert),
                               None);
                    assert_eq!(unwrap!(permissions.get(&User::Key(sign_pk)))
                                   .is_allowed(Action::Update),
                               None);
                    assert_eq!(unwrap!(permissions.get(&User::Key(sign_pk)))
                                   .is_allowed(Action::Delete),
                               None);
                    assert_eq!(unwrap!(permissions.get(&User::Key(sign_pk)))
                                   .is_allowed(Action::ManagePermissions),
                               Some(true));
                    assert_eq!(unwrap!(permissions.get(&User::Key(random_key_a)))
                                   .is_allowed(Action::Insert),
                               Some(true));
                    assert_eq!(unwrap!(permissions.get(&User::Key(random_key_a)))
                                   .is_allowed(Action::Update),
                               None);
                    assert_eq!(unwrap!(permissions.get(&User::Key(random_key_a)))
                                   .is_allowed(Action::Delete),
                               Some(true));
                    assert_eq!(unwrap!(permissions.get(&User::Key(random_key_a)))
                                   .is_allowed(Action::ManagePermissions),
                               None);
                    assert_eq!(unwrap!(permissions.get(&User::Key(random_key_b)))
                                   .is_allowed(Action::Insert),
                               Some(false));
                    assert_eq!(unwrap!(permissions.get(&User::Key(random_key_b)))
                                   .is_allowed(Action::Update),
                               None);
                    assert_eq!(unwrap!(permissions.get(&User::Key(random_key_b)))
                                   .is_allowed(Action::Delete),
                               None);
                    assert_eq!(unwrap!(permissions.get(&User::Key(random_key_b)))
                                   .is_allowed(Action::ManagePermissions),
                               None);
                }

                let permissions = PermissionSet::new().deny(Action::Insert);
                cl6.set_mdata_user_permissions(name,
                                               DIR_TAG,
                                               User::Key(random_key_b),
                                               permissions,
                                               3)
            })
            .then(move |res| {
                      unwrap!(res);
                      cl7.del_mdata_user_permissions(name, DIR_TAG, User::Key(random_key_a), 4)
                  })
            .then(move |res| {
                      unwrap!(res);
                      cl8.list_mdata_permissions(name, DIR_TAG)
                  })
            .then(move |res| {
                {
                    let permissions = unwrap!(res);
                    assert_eq!(permissions.len(), 2);
                    assert_eq!(unwrap!(permissions.get(&User::Key(sign_pk)))
                                   .is_allowed(Action::Insert),
                               None);
                    assert_eq!(unwrap!(permissions.get(&User::Key(sign_pk)))
                                   .is_allowed(Action::Update),
                               None);
                    assert_eq!(unwrap!(permissions.get(&User::Key(sign_pk)))
                                   .is_allowed(Action::Delete),
                               None);
                    assert_eq!(unwrap!(permissions.get(&User::Key(sign_pk)))
                                   .is_allowed(Action::ManagePermissions),
                               Some(true));
                    assert_eq!(unwrap!(permissions.get(&User::Key(random_key_b)))
                                   .is_allowed(Action::Insert),
                               Some(false));
                    assert_eq!(unwrap!(permissions.get(&User::Key(random_key_b)))
                                   .is_allowed(Action::Update),
                               None);
                    assert_eq!(unwrap!(permissions.get(&User::Key(random_key_b)))
                                   .is_allowed(Action::Delete),
                               None);
                    assert_eq!(unwrap!(permissions.get(&User::Key(random_key_b)))
                                   .is_allowed(Action::ManagePermissions),
                               None);
                }

                let permissions = PermissionSet::new()
                    .deny(Action::Insert)
                    .deny(Action::Delete);
                cl9.set_mdata_user_permissions(name,
                                               DIR_TAG,
                                               User::Key(random_key_b),
                                               permissions,
                                               5)
            })
            .then(move |res| {
                      unwrap!(res);
                      cl10.list_mdata_permissions(name, DIR_TAG)
                  })
            .then(move |res| -> Result<_, ()> {
                {
                    let permissions = unwrap!(res);
                    assert_eq!(permissions.len(), 2);
                    assert_eq!(unwrap!(permissions.get(&User::Key(sign_pk)))
                                   .is_allowed(Action::Insert),
                               None);
                    assert_eq!(unwrap!(permissions.get(&User::Key(sign_pk)))
                                   .is_allowed(Action::Update),
                               None);
                    assert_eq!(unwrap!(permissions.get(&User::Key(sign_pk)))
                                   .is_allowed(Action::Delete),
                               None);
                    assert_eq!(unwrap!(permissions.get(&User::Key(sign_pk)))
                                   .is_allowed(Action::ManagePermissions),
                               Some(true));
                    assert_eq!(unwrap!(permissions.get(&User::Key(random_key_b)))
                                   .is_allowed(Action::Insert),
                               Some(false));
                    assert_eq!(unwrap!(permissions.get(&User::Key(random_key_b)))
                                   .is_allowed(Action::Update),
                               None);
                    assert_eq!(unwrap!(permissions.get(&User::Key(random_key_b)))
                                   .is_allowed(Action::Delete),
                               Some(false));
                    assert_eq!(unwrap!(permissions.get(&User::Key(random_key_b)))
                                   .is_allowed(Action::ManagePermissions),
                               None);
                }

                Ok(())
            })
            .map_err(|e| panic!("{:?}", e))
    });
}

// The usual test to insert, update, delete and list all entry-keys/values. same
// thing from `permissions_crud` with entry-key/value - the difference is that
// after delete you should still get all the keys - delete does not actually
// delete the entry, only blanks out the entry-value (null vector), the version
// however should have been bumped - so check for those.
#[test]
fn entries_crud() {
    let app = create_app();
    run(&app, |client, _app_context| {
        let mut rng = unwrap!(OsRng::new());
        let sign_pk = unwrap!(client.public_signing_key());

        let mut permissions = BTreeMap::new();
        let _ = permissions.insert(User::Key(sign_pk),
                                   PermissionSet::new()
                                       .allow(Action::Insert)
                                       .allow(Action::Update)
                                       .allow(Action::Delete));

        let mut data = BTreeMap::new();
        let _ = data.insert(vec![0, 0, 1],
                            Value {
                                content: vec![1],
                                entry_version: 1,
                            });
        let _ = data.insert(vec![0, 1, 0],
                            Value {
                                content: vec![2, 8],
                                entry_version: 1,
                            });

        let mut owners = BTreeSet::new();
        owners.insert(unwrap!(client.owner_key()));

        let name: XorName = rng.gen();
        let mdata = unwrap!(MutableData::new(name, DIR_TAG, permissions, data, owners));

        let cl2 = client.clone();
        let cl3 = client.clone();
        let cl4 = client.clone();
        let cl5 = client.clone();
        client
            .put_mdata(mdata)
            .then(move |res| {
                unwrap!(res);
                let mut actions = BTreeMap::new();
                let _ = actions.insert(vec![0, 1, 1],
                                       EntryAction::Ins(Value {
                                                            content: vec![2, 3, 17],
                                                            entry_version: 1,
                                                        }));
                let _ = actions.insert(vec![0, 1, 0],
                                       EntryAction::Update(Value {
                                                               content: vec![2, 8, 64],
                                                               entry_version: 2,
                                                           }));
                let _ = actions.insert(vec![0, 0, 1], EntryAction::Del(2));
                cl2.mutate_mdata_entries(name, DIR_TAG, actions)
            })
            .then(move |res| {
                      unwrap!(res);
                      cl3.list_mdata_entries(name, DIR_TAG)
                  })
            .then(move |res| {
                let entries = unwrap!(res);
                assert_eq!(entries.len(), 3);
                assert_eq!(*unwrap!(entries.get(&vec![0, 0, 1])),
                           Value {
                               content: vec![],
                               entry_version: 2,
                           });
                assert_eq!(*unwrap!(entries.get(&vec![0, 1, 0])),
                           Value {
                               content: vec![2, 8, 64],
                               entry_version: 2,
                           });
                assert_eq!(*unwrap!(entries.get(&vec![0, 1, 1])),
                           Value {
                               content: vec![2, 3, 17],
                               entry_version: 1,
                           });
                let mut actions = BTreeMap::new();
                let _ = actions.insert(vec![1, 0, 0],
                                       EntryAction::Ins(Value {
                                                            content: vec![4, 4, 4, 4],
                                                            entry_version: 1,
                                                        }));
                let _ = actions.insert(vec![0, 1, 0],
                                       EntryAction::Update(Value {
                                                               content: vec![64, 8, 1],
                                                               entry_version: 3,
                                                           }));
                let _ = actions.insert(vec![0, 1, 1], EntryAction::Del(2));
                cl4.mutate_mdata_entries(name, DIR_TAG, actions)
            })
            .then(move |res| {
                      unwrap!(res);
                      cl5.list_mdata_entries(name, DIR_TAG)
                  })
            .then(|res| -> Result<_, ()> {
                let entries = unwrap!(res);
                assert_eq!(entries.len(), 4);
                assert_eq!(*unwrap!(entries.get(&vec![0, 0, 1])),
                           Value {
                               content: vec![],
                               entry_version: 2,
                           });
                assert_eq!(*unwrap!(entries.get(&vec![0, 1, 0])),
                           Value {
                               content: vec![64, 8, 1],
                               entry_version: 3,
                           });
                assert_eq!(*unwrap!(entries.get(&vec![0, 1, 1])),
                           Value {
                               content: vec![],
                               entry_version: 2,
                           });
                assert_eq!(*unwrap!(entries.get(&vec![1, 0, 0])),
                           Value {
                               content: vec![4, 4, 4, 4],
                               entry_version: 1,
                           });
                Ok(())
            })
            .map_err(|e| panic!("{:?}", e))
    });
}

// Test `MutableData` functions from the FFI point of view.
#[test]
fn entries_crud_ffi() {
    use ffi::mdata_info::*;
    use ffi::mutable_data::*;
    use ffi::mutable_data::entry_actions::*;
    use ffi::mutable_data::permissions::*;
    use ffi::mutable_data::entries::*;
    use ffi_utils::vec_clone_from_raw_parts;
    use ffi_utils::test_utils::{call_0, call_1, call_vec_u8, send_via_user_data,
                                sender_as_user_data};
    use object_cache::{MDataEntryActionsHandle, MDataInfoHandle, MDataPermissionSetHandle,
                       MDataPermissionsHandle};

    let app = create_app();

    const KEY: &[u8] = b"hello";
    const VALUE: &[u8] = b"world";

    // Create a permissions set
    let perms_set_h: MDataPermissionSetHandle =
        unsafe { unwrap!(call_1(|ud, cb| mdata_permission_set_new(&app, ud, cb))) };

    unsafe {
        unwrap!(call_0(|ud, cb| {
                           mdata_permissions_set_allow(&app,
                                                       perms_set_h,
                                                       MDataAction::Insert,
                                                       ud,
                                                       cb)
                       }))
    };

    // Create permissions for anyone
    let perms_h: MDataPermissionsHandle =
        unsafe { unwrap!(call_1(|ud, cb| mdata_permissions_new(&app, ud, cb))) };

    unsafe {
        unwrap!(call_0(|ud, cb| {
                           mdata_permissions_insert(&app, perms_h, USER_ANYONE, perms_set_h, ud, cb)
                       }))
    };

    // Try to create an empty public MD
    let md_info_pub_h: MDataInfoHandle =
        unsafe { unwrap!(call_1(|ud, cb| mdata_info_random_public(&app, 10000, ud, cb))) };

    unsafe {
        unwrap!(call_0(|ud, cb| mdata_put(&app, md_info_pub_h, perms_h, ENTRIES_EMPTY, ud, cb)))
    };

    // Try to add entries to a public MD
    let actions_h: MDataEntryActionsHandle =
        unsafe { unwrap!(call_1(|ud, cb| mdata_entry_actions_new(&app, ud, cb))) };

    unsafe {
        unwrap!(call_0(|ud, cb| {
            mdata_entry_actions_insert(&app,
                                       actions_h,
                                       KEY.as_ptr(),
                                       KEY.len(),
                                       VALUE.as_ptr(),
                                       VALUE.len(),
                                       ud,
                                       cb)
        }))
    };

    unsafe {
        unwrap!(call_0(|ud, cb| mdata_mutate_entries(&app, md_info_pub_h, actions_h, ud, cb)))
    }

    // Retrieve added entry
    {
        let (tx, rx) = mpsc::channel::<Result<Vec<u8>, i32>>();
        let ud = sender_as_user_data(&tx);

        unsafe {
            mdata_get_value(&app,
                            md_info_pub_h,
                            KEY.as_ptr(),
                            KEY.len(),
                            ud,
                            get_value_cb)
        };

        let result = unwrap!(rx.recv());
        assert_eq!(&unwrap!(result), &VALUE, "got back invalid value");
    }

    // Check the version of a public MD
    let ver: u64 =
        unsafe { unwrap!(call_1(|ud, cb| mdata_get_version(&app, md_info_pub_h, ud, cb))) };
    assert_eq!(ver, 0);

    // Try to create a private MD
    let md_info_priv_h =
        unsafe { unwrap!(call_1(|ud, cb| mdata_info_random_private(&app, 10001, ud, cb))) };

    unsafe {
        unwrap!(call_0(|ud, cb| mdata_put(&app, md_info_priv_h, perms_h, ENTRIES_EMPTY, ud, cb)))
    };

    // Try to add entries to a private MD
    let key_enc = unsafe {
        unwrap!(call_vec_u8(|ud, cb| {
                                mdata_info_encrypt_entry_key(&app,
                                                             md_info_priv_h,
                                                             KEY.as_ptr(),
                                                             KEY.len(),
                                                             ud,
                                                             cb)
                            }))
    };
    let value_enc = unsafe {
        unwrap!(call_vec_u8(|ud, cb| {
                                mdata_info_encrypt_entry_value(&app,
                                                               md_info_priv_h,
                                                               VALUE.as_ptr(),
                                                               VALUE.len(),
                                                               ud,
                                                               cb)
                            }))
    };

    let actions_priv_h: MDataEntryActionsHandle =
        unsafe { unwrap!(call_1(|ud, cb| mdata_entry_actions_new(&app, ud, cb))) };

    unsafe {
        unwrap!(call_0(|ud, cb| {
            mdata_entry_actions_insert(&app,
                                       actions_priv_h,
                                       key_enc.as_ptr(),
                                       key_enc.len(),
                                       value_enc.as_ptr(),
                                       value_enc.len(),
                                       ud,
                                       cb)
        }))
    };

    unsafe {
        unwrap!(call_0(|ud, cb| mdata_mutate_entries(&app, md_info_priv_h, actions_priv_h, ud, cb)))
    }

    // Retrieve added entry from private MD
    {
        let (tx, rx) = mpsc::channel::<Result<Vec<u8>, i32>>();
        let ud = sender_as_user_data(&tx);

        unsafe {
            mdata_get_value(&app,
                            md_info_priv_h,
                            key_enc.as_ptr(),
                            key_enc.len(),
                            ud,
                            get_value_cb)
        };

        let result = unwrap!(rx.recv());
        let got_value_enc = unwrap!(result);
        assert_eq!(&got_value_enc, &value_enc, "got back invalid value");

        let decrypted = unsafe {
            unwrap!(call_vec_u8(|ud, cb| {
                                    mdata_info_decrypt(&app,
                                                       md_info_priv_h,
                                                       got_value_enc.as_ptr(),
                                                       got_value_enc.len(),
                                                       ud,
                                                       cb)
                                }))
        };
        assert_eq!(&decrypted, &VALUE, "decrypted invalid value");
    }

    // Check mdata_list_entries
    {
        let entries_list_h =
            unsafe { unwrap!(call_1(|ud, cb| mdata_list_entries(&app, md_info_priv_h, ud, cb))) };

        let (tx, rx) = mpsc::channel::<Result<Vec<u8>, i32>>();
        let ud = sender_as_user_data(&tx);

        unsafe {
            mdata_entries_get(&app,
                              entries_list_h,
                              key_enc.as_ptr(),
                              key_enc.len(),
                              ud,
                              get_value_cb)
        };

        let result = unwrap!(rx.recv());
        let got_value_enc = unwrap!(result);
        assert_eq!(&got_value_enc, &value_enc, "got back invalid value");

        let decrypted = unsafe {
            unwrap!(call_vec_u8(|ud, cb| {
                                    mdata_info_decrypt(&app,
                                                       md_info_priv_h,
                                                       got_value_enc.as_ptr(),
                                                       got_value_enc.len(),
                                                       ud,
                                                       cb)
                                }))
        };
        assert_eq!(&decrypted, &VALUE, "decrypted invalid value");

        unsafe { unwrap!(call_0(|ud, cb| mdata_entries_free(&app, entries_list_h, ud, cb))) }
    }

    // Check mdata_list_keys
    {
        let keys_list_h =
            unsafe { unwrap!(call_1(|ud, cb| mdata_list_keys(&app, md_info_priv_h, ud, cb))) };

        let (tx, rx) = mpsc::channel::<Option<Vec<u8>>>();
        let ud = sender_as_user_data(&tx);

        unsafe { mdata_keys_for_each(&app, keys_list_h, iter_vec_u8_cb, ud, iter_done_cb) };

        let mut result: Vec<Option<Vec<u8>>> = Vec::new();
        result.push(unwrap!(rx.recv_timeout(Duration::from_millis(1000))));
        result.push(unwrap!(rx.recv_timeout(Duration::from_millis(1000))));
        assert_eq!(result.len(), 2);

        if let Some(ref got_key_enc) = result[0] {
            let decrypted = unsafe {
                unwrap!(call_vec_u8(|ud, cb| {
                                        mdata_info_decrypt(&app,
                                                           md_info_priv_h,
                                                           got_key_enc.as_ptr(),
                                                           got_key_enc.len(),
                                                           ud,
                                                           cb)
                                    }))
            };
            assert_eq!(&decrypted, &KEY, "decrypted invalid key");
        } else {
            panic!("Failed test: expected Some(Vec<u8>), got None");
        }
    }

    // Check mdata_list_values
    {
        let vals_list_h =
            unsafe { unwrap!(call_1(|ud, cb| mdata_list_values(&app, md_info_priv_h, ud, cb))) };

        let (tx, rx) = mpsc::channel::<Option<Vec<u8>>>();
        let ud = sender_as_user_data(&tx);

        unsafe { mdata_values_for_each(&app, vals_list_h, iter_value_cb, ud, iter_done_cb) };

        let mut result: Vec<Option<Vec<u8>>> = Vec::new();
        result.push(unwrap!(rx.recv_timeout(Duration::from_millis(1000))));
        result.push(unwrap!(rx.recv_timeout(Duration::from_millis(1000))));
        assert_eq!(result.len(), 2);

        if let Some(ref got_value_enc) = result[0] {
            let decrypted = unsafe {
                unwrap!(call_vec_u8(|ud, cb| {
                                        mdata_info_decrypt(&app,
                                                           md_info_priv_h,
                                                           got_value_enc.as_ptr(),
                                                           got_value_enc.len(),
                                                           ud,
                                                           cb)
                                    }))
            };
            assert_eq!(&decrypted, &VALUE, "decrypted invalid value");
        } else {
            panic!("Failed test: expected Some(Vec<u8>), got None");
        }
    }

    extern "C" fn get_value_cb(user_data: *mut c_void,
                               err_code: i32,
                               val: *const u8,
                               len: usize,
                               _version: u64) {
        let result: Result<Vec<u8>, i32> = if err_code == 0 {
            Ok(unsafe { vec_clone_from_raw_parts(val, len) })
        } else {
            Err(err_code)
        };
        unsafe {
            send_via_user_data(user_data, result);
        }
    }

    extern "C" fn iter_value_cb(user_data: *mut c_void,
                                val: *const u8,
                                len: usize,
                                _version: u64) {
        let result: Option<Vec<u8>> = Some(unsafe { vec_clone_from_raw_parts(val, len) });
        unsafe {
            send_via_user_data(user_data, result);
        }
    }

    extern "C" fn iter_vec_u8_cb(user_data: *mut c_void, val: *const u8, len: usize) {
        let result: Option<Vec<u8>> = Some(unsafe { vec_clone_from_raw_parts(val, len) });
        unsafe {
            send_via_user_data(user_data, result);
        }
    }

    extern "C" fn iter_done_cb(user_data: *mut c_void, _err_code: i32) {
        unsafe {
            send_via_user_data::<Option<Vec<u8>>>(user_data, None);
        }
    }
}
