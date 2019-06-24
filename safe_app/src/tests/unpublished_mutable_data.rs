// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::client::AppClient;
use crate::run;
use crate::test_utils::create_app;
// use crate::AppError;
use futures::Future;
use maidsafe_utilities::thread;
use rand::{OsRng, Rng};
use safe_core::utils::test_utils::random_client;
use safe_core::{Client, CoreError, FutureExt, DIR_TAG};
use safe_nd::{Error, PublicKey, XorName};
use safe_nd::{
    MDataAction, MDataAddress, MDataPermissionSet, MDataSeqEntryAction, MDataUnseqEntryAction,
    MDataValue, SeqMutableData, UnseqMutableData,
};
use std::collections::BTreeMap;
use std::sync::mpsc;
use threshold_crypto::SecretKey;

// MD created by owner and given to a permitted App. Owner has listed that app is allowed to insert
// only. App tries to insert - should pass. App tries to update - should fail. App tries to change
// permission to allow itself to update - should fail to change permissions.
#[test]
fn md_created_by_app_1() {
    let app = create_app();
    let (tx, rx) = mpsc::channel();
    let (app_keys_tx, app_keys_rx) = mpsc::channel();
    let (name_tx, name_rx) = mpsc::channel();
    unwrap!(app.send(move |client, _app_context| {
        let sign_pk = unwrap!(client.public_signing_key());
        let bls_pk = unwrap!(client.public_bls_key());
        unwrap!(app_keys_tx.send((sign_pk, bls_pk)));
        let name: XorName = unwrap!(name_rx.recv());
        let mut actions = BTreeMap::new();
        let _ = actions.insert(
            vec![1, 2, 3, 4],
            MDataSeqEntryAction::Ins(MDataValue::new(vec![2, 3, 5], 0)),
        );
        let cl2 = client.clone();
        let cl3 = client.clone();
        let name2 = name;
        client
            .mutate_seq_mdata_entries(name, DIR_TAG, actions)
            .then(move |res| {
                unwrap!(res);
                let mut actions = BTreeMap::new();
                let _ = actions.insert(
                    vec![1, 2, 3, 4],
                    MDataSeqEntryAction::Update(MDataValue::new(vec![2, 8, 5], 1)),
                );
                cl2.mutate_seq_mdata_entries(name, DIR_TAG, actions)
            })
            .then(move |res| {
                match res {
                    Ok(()) => panic!("It should fail"),
                    Err(CoreError::NewRoutingClientError(Error::AccessDenied)) => (),
                    Err(x) => panic!("Expected Error::AccessDenied. Got {:?}", x),
                }
                let user = PublicKey::from(bls_pk);
                let permissions = MDataPermissionSet::new().allow(MDataAction::Update);
                cl3.set_mdata_user_permissions_new(
                    MDataAddress::new_seq(name2, DIR_TAG),
                    user,
                    permissions,
                    2,
                )
            })
            .then(move |res| -> Result<_, ()> {
                match res {
                    Ok(()) => panic!("It should fail"),
                    Err(CoreError::NewRoutingClientError(Error::AccessDenied)) => (),
                    Err(x) => panic!("Expected Error::AccessDenied. Got {:?}", x),
                }
                unwrap!(tx.send(()));
                Ok(())
            })
            .into_box()
            .into()
    }));
    let _joiner = thread::named("Alt client", || {
        random_client(move |client| {
            let (_app_sign_pk, app_bls_pk) = unwrap!(app_keys_rx.recv());
            let mut rng = unwrap!(OsRng::new());

            let mut permissions = BTreeMap::new();
            let _ = permissions.insert(
                PublicKey::from(app_bls_pk),
                MDataPermissionSet::new()
                    .allow(MDataAction::Insert)
                    .allow(MDataAction::Read),
            );

            let owners = unwrap!(client.public_bls_key());

            let name: XorName = XorName(rng.gen());

            let mdata = SeqMutableData::new_with_data(
                name,
                DIR_TAG,
                BTreeMap::new(),
                permissions,
                PublicKey::from(owners),
            );
            let cl2 = client.clone();
            let cl3 = client.clone();

            client
                .list_auth_keys_and_version()
                .then(move |res| {
                    let (_, version) = unwrap!(res);
                    cl2.ins_auth_key(PublicKey::from(app_bls_pk), Default::default(), version + 1)
                })
                .then(move |res| {
                    unwrap!(res);
                    cl3.put_seq_mutable_data(mdata)
                })
                .map(move |()| unwrap!(name_tx.send(name)))
                .map_err(|e| panic!("{:?}", e))
        });
    });
    unwrap!(rx.recv());
}

// MD created by owner and given to a permitted App. Owner has listed that app is allowed to
// manage-permissions only. App tries to insert - should fail. App tries to update - should fail.
// App tries to change permission to allow itself to insert and delete - should pass to change
// permissions. Now App tires to insert again - should pass. App tries to update. Should fail. App
// tries to delete - should pass.
#[test]
fn md_created_by_app_2() {
    let app = create_app();
    let (tx, rx) = mpsc::channel();
    let (app_keys_tx, app_keys_rx) = mpsc::channel();
    let (name_tx, name_rx) = mpsc::channel();
    unwrap!(app.send(move |client, _app_context| {
        let sign_pk = unwrap!(client.public_signing_key());
        let bls_pk = unwrap!(client.public_bls_key());
        unwrap!(app_keys_tx.send((sign_pk, bls_pk)));
        let name: XorName = unwrap!(name_rx.recv());
        let mut actions = BTreeMap::new();
        let _ = actions.insert(vec![1, 2, 3, 4], MDataUnseqEntryAction::Ins(vec![2, 3, 5]));
        let cl2 = client.clone();
        let cl3 = client.clone();
        let cl4 = client.clone();
        let cl5 = client.clone();
        let cl6 = client.clone();
        let name2 = name;
        let name3 = name;
        let name4 = name;
        let name5 = name;
        client
            .mutate_unseq_mdata_entries(name, DIR_TAG, actions)
            .then(move |res| {
                match res {
                    Ok(()) => panic!("It should fail"),
                    Err(CoreError::NewRoutingClientError(Error::AccessDenied)) => (),
                    Err(x) => panic!("Expected Error::AccessDenied. Got {:?}", x),
                }
                let mut actions = BTreeMap::new();
                let _ = actions.insert(
                    vec![1, 8, 3, 4],
                    MDataUnseqEntryAction::Update(vec![2, 8, 5]),
                );
                cl2.mutate_unseq_mdata_entries(name, DIR_TAG, actions)
            })
            .then(move |res| {
                match res {
                    Ok(()) => panic!("It should fail"),
                    Err(CoreError::NewRoutingClientError(Error::AccessDenied)) => (),
                    Err(x) => panic!("Expected Error::AccessDenied. Got {:?}", x),
                }
                let user = PublicKey::from(bls_pk);
                let permissions = MDataPermissionSet::new()
                    .allow(MDataAction::Insert)
                    .allow(MDataAction::Delete);
                cl3.set_mdata_user_permissions_new(
                    MDataAddress::new_unseq(name2, DIR_TAG),
                    user,
                    permissions,
                    1,
                )
            })
            .then(move |res| {
                unwrap!(res);
                let mut actions = BTreeMap::new();
                let _ = actions.insert(vec![1, 2, 3, 4], MDataUnseqEntryAction::Ins(vec![2, 3, 5]));
                cl4.mutate_unseq_mdata_entries(name3, DIR_TAG, actions)
            })
            .then(move |res| {
                unwrap!(res);
                let mut actions = BTreeMap::new();
                let _ = actions.insert(
                    vec![1, 2, 3, 4],
                    MDataUnseqEntryAction::Update(vec![2, 8, 5]),
                );
                cl5.mutate_unseq_mdata_entries(name4, DIR_TAG, actions)
            })
            .then(move |res| {
                match res {
                    Ok(()) => panic!("It should fail"),
                    Err(CoreError::NewRoutingClientError(Error::AccessDenied)) => (),
                    Err(x) => panic!("Expected Error::AccessDenied. Got {:?}", x),
                }
                let mut actions = BTreeMap::new();
                let _ = actions.insert(vec![1, 2, 3, 4], MDataUnseqEntryAction::Del);
                cl6.mutate_unseq_mdata_entries(name5, DIR_TAG, actions)
            })
            .map(move |()| unwrap!(tx.send(())))
            .map_err(|e| panic!("{:?}", e))
            .into_box()
            .into()
    }));
    let _joiner = thread::named("Alt client", || {
        random_client(move |client| {
            let (_app_sign_pk, app_bls_pk) = unwrap!(app_keys_rx.recv());
            let mut rng = unwrap!(OsRng::new());

            let mut permissions = BTreeMap::new();
            let _ = permissions.insert(
                PublicKey::from(app_bls_pk),
                MDataPermissionSet::new().allow(MDataAction::ManagePermissions),
            );

            let mut data = BTreeMap::new();
            let _ = data.insert(vec![1, 8, 3, 4], vec![1]);

            let name: XorName = XorName(rng.gen());

            let mdata = UnseqMutableData::new_with_data(
                name,
                DIR_TAG,
                data,
                permissions,
                PublicKey::from(unwrap!(client.public_bls_key())),
            );
            let cl2 = client.clone();
            let cl3 = client.clone();

            client
                .list_auth_keys_and_version()
                .then(move |res| {
                    let (_, version) = unwrap!(res);
                    cl2.ins_auth_key(PublicKey::from(app_bls_pk), Default::default(), version + 1)
                })
                .then(move |res| {
                    unwrap!(res);
                    cl3.put_unseq_mutable_data(mdata)
                })
                .map(move |()| unwrap!(name_tx.send(name)))
                .map_err(|e| panic!("{:?}", e))
        });
    });
    unwrap!(rx.recv());
}

// MD created by App1, with permission to insert for App2 and permission to manage-permissions only
// for itself - should pass. App2 created via another random client2 tries to insert (going via
// client2's MM) into MD of App1 - should Pass. App1 should be able to read the data - should pass.
// App1 changes permission to remove the anyone access - should pass. App2 tries to insert another
// data in MD - should fail. App1 tries to get all data from MD - should pass and should have no
// change (since App2 failed to insert).
#[test]
fn multiple_apps() {
    let app1 = create_app();
    let app2 = create_app();
    let (tx, rx) = mpsc::channel();
    let (app2_key_tx, app2_key_rx) = mpsc::channel();
    let (name_tx, name_rx) = mpsc::channel();
    let (entry_tx, entry_rx) = mpsc::channel();
    let (mutate_again_tx, mutate_again_rx) = mpsc::channel();
    let (final_check_tx, final_check_rx) = mpsc::channel();
    unwrap!(app1.send(move |client, _app_context| {
        let mut rng = unwrap!(OsRng::new());
        let bls_pk = unwrap!(client.public_bls_key());

        let mut permissions = BTreeMap::new();
        let app2_bls_pk = unwrap!(app2_key_rx.recv());
        let _ = permissions.insert(
            PublicKey::from(app2_bls_pk),
            MDataPermissionSet::new().allow(MDataAction::Insert),
        );
        let _ = permissions.insert(
            PublicKey::from(bls_pk),
            MDataPermissionSet::new()
                .allow(MDataAction::ManagePermissions)
                .allow(MDataAction::Read),
        );

        let name: XorName = XorName(rng.gen());
        let mdata = SeqMutableData::new_with_data(
            name,
            DIR_TAG,
            BTreeMap::new(),
            permissions,
            PublicKey::from(bls_pk),
        );
        let cl2 = client.clone();
        let cl3 = client.clone();
        let cl4 = client.clone();
        let name2 = name;
        let name3 = name;
        client
            .put_seq_mutable_data(mdata)
            .then(move |res| {
                unwrap!(res);
                unwrap!(name_tx.send(name));
                let entry_key: Vec<u8> = unwrap!(entry_rx.recv());
                cl2.get_seq_mdata_value(name, DIR_TAG, entry_key.clone())
                    .map(move |v| (v, entry_key))
            })
            .then(move |res| {
                let (value, entry_key) = unwrap!(res);
                assert_eq!(value, MDataValue::new(vec![8, 9, 9], 0));
                cl3.del_mdata_user_permissions_new(
                    MDataAddress::new_seq(name2, DIR_TAG),
                    PublicKey::from(app2_bls_pk),
                    1,
                )
                .map(move |()| entry_key)
            })
            .then(move |res| {
                let entry_key = unwrap!(res);
                unwrap!(mutate_again_tx.send(()));
                unwrap!(final_check_rx.recv());
                cl4.list_mdata_keys_new(MDataAddress::new_seq(name3, DIR_TAG))
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
        unwrap!(app2_key_tx.send(unwrap!(client.public_bls_key())));
        let name = unwrap!(name_rx.recv());
        let entry_key = vec![1, 2, 3];

        let mut actions = BTreeMap::new();
        let _ = actions.insert(
            entry_key.clone(),
            MDataSeqEntryAction::Ins(MDataValue::new(vec![8, 9, 9], 0)),
        );

        let cl2 = client.clone();
        client
            .mutate_seq_mdata_entries(name, DIR_TAG, actions)
            .then(move |res| {
                unwrap!(res);
                unwrap!(entry_tx.send(entry_key));
                unwrap!(mutate_again_rx.recv());

                let mut actions = BTreeMap::new();
                let _ = actions.insert(
                    vec![2, 2, 2],
                    MDataSeqEntryAction::Ins(MDataValue::new(vec![21], 0)),
                );
                cl2.mutate_seq_mdata_entries(name, DIR_TAG, actions)
            })
            .then(move |res| -> Result<_, ()> {
                match res {
                    Ok(()) => panic!("It should fail"),
                    Err(CoreError::NewRoutingClientError(Error::AccessDenied)) => (),
                    Err(x) => panic!("Expected Error::AccessDenied. Got {:?}", x),
                }
                unwrap!(final_check_tx.send(()));
                Ok(())
            })
            .into_box()
            .into()
    }));
    unwrap!(rx.recv());
}

// MD created by App with itself allowed to manage-permissions. Insert permission to allow a
// random-key to perform update operation - should pass. Delete this permission without incrementing
// version of MD - should fail version check. Query the permissions list - should continue to have
// the listed permission for the random-key. Query the version of the MD in network - should pass.
// Send request to delete that permission again with properly incremented version from info from the
// fetched version - should pass. Query the permissions list - should no longer have the listed
// permission for the random-key.
#[test]
fn permissions_and_version() {
    let app = create_app();
    unwrap!(run(&app, |client: &AppClient, _app_context| {
        let mut rng = unwrap!(OsRng::new());
        let bls_pk = unwrap!(client.public_bls_key());
        let random_key = SecretKey::random().public_key();

        let mut permissions = BTreeMap::new();
        let _ = permissions.insert(
            PublicKey::from(bls_pk),
            MDataPermissionSet::new()
                .allow(MDataAction::ManagePermissions)
                .allow(MDataAction::Read),
        );

        let name: XorName = XorName(rng.gen());
        let mdata = UnseqMutableData::new_with_data(
            name,
            DIR_TAG,
            BTreeMap::new(),
            permissions,
            PublicKey::from(bls_pk),
        );
        let cl2 = client.clone();
        let cl3 = client.clone();
        let cl4 = client.clone();
        let cl5 = client.clone();
        let cl6 = client.clone();
        let cl7 = client.clone();
        client
            .put_unseq_mutable_data(mdata)
            .then(move |res| {
                unwrap!(res);
                let permissions = MDataPermissionSet::new().allow(MDataAction::Update);
                cl2.set_mdata_user_permissions_new(
                    MDataAddress::new_unseq(name, DIR_TAG),
                    PublicKey::from(random_key),
                    permissions,
                    1,
                )
            })
            .then(move |res| {
                unwrap!(res);
                cl3.del_mdata_user_permissions_new(
                    MDataAddress::new_unseq(name, DIR_TAG),
                    PublicKey::from(random_key),
                    1,
                )
            })
            .then(move |res| {
                match res {
                    Ok(()) => panic!("It should fail with invalid successor"),
                    Err(CoreError::NewRoutingClientError(Error::InvalidSuccessor(..))) => (),
                    Err(x) => panic!("Expected Error::InvalidSuccessor. Got {:?}", x),
                }
                cl4.list_mdata_permissions_new(MDataAddress::new_unseq(name, DIR_TAG))
            })
            .then(move |res| {
                let permissions = unwrap!(res);
                assert_eq!(permissions.len(), 2);
                assert!(!unwrap!(permissions.get(&PublicKey::from(bls_pk)))
                    .is_allowed(MDataAction::Insert));
                assert!(unwrap!(permissions.get(&PublicKey::from(bls_pk)))
                    .is_allowed(MDataAction::Read));
                assert!(!unwrap!(permissions.get(&PublicKey::from(bls_pk)))
                    .is_allowed(MDataAction::Update));
                assert!(!unwrap!(permissions.get(&PublicKey::from(bls_pk)))
                    .is_allowed(MDataAction::Delete));
                assert!(unwrap!(permissions.get(&PublicKey::from(bls_pk)))
                    .is_allowed(MDataAction::ManagePermissions));
                assert!(!unwrap!(permissions.get(&PublicKey::from(random_key)))
                    .is_allowed(MDataAction::Insert));
                assert!(!unwrap!(permissions.get(&PublicKey::from(random_key)))
                    .is_allowed(MDataAction::Read));
                assert!(unwrap!(permissions.get(&PublicKey::from(random_key)))
                    .is_allowed(MDataAction::Update));
                assert!(!unwrap!(permissions.get(&PublicKey::from(random_key)))
                    .is_allowed(MDataAction::Delete));
                assert!(!unwrap!(permissions.get(&PublicKey::from(random_key)))
                    .is_allowed(MDataAction::ManagePermissions));
                cl5.get_mdata_version_new(MDataAddress::new_unseq(name, DIR_TAG))
            })
            .then(move |res| {
                let v = unwrap!(res);
                assert_eq!(v, 1);
                cl6.del_mdata_user_permissions_new(
                    MDataAddress::new_unseq(name, DIR_TAG),
                    PublicKey::from(random_key),
                    v + 1,
                )
            })
            .then(move |res| {
                unwrap!(res);
                cl7.list_mdata_permissions_new(MDataAddress::new_unseq(name, DIR_TAG))
            })
            .map(move |permissions| {
                assert_eq!(permissions.len(), 1);
                assert!(!unwrap!(permissions.get(&PublicKey::from(bls_pk)))
                    .is_allowed(MDataAction::Insert));
                assert!(unwrap!(permissions.get(&PublicKey::from(bls_pk)))
                    .is_allowed(MDataAction::Read));
                assert!(!unwrap!(permissions.get(&PublicKey::from(bls_pk)))
                    .is_allowed(MDataAction::Update));
                assert!(!unwrap!(permissions.get(&PublicKey::from(bls_pk)))
                    .is_allowed(MDataAction::Delete));
                assert!(unwrap!(permissions.get(&PublicKey::from(bls_pk)))
                    .is_allowed(MDataAction::ManagePermissions));
            })
            .map_err(|e| panic!("{:?}", e))
    }));
}

// The usual test to insert, update, delete and list all permissions. Put in some permissions, fetch
// (list) all of them, add some more, list again, delete one or two, list again - all should pass
// and do the expected (i.e. after list do assert that it contains all the expected stuff, don't
// just pass test if the list was successful).
#[test]
fn permissions_crud() {
    let app = create_app();
    unwrap!(run(&app, |client: &AppClient, _app_context| {
        let mut rng = unwrap!(OsRng::new());
        let bls_pk = unwrap!(client.public_bls_key());
        let random_key_a = SecretKey::random().public_key();
        let random_key_b = SecretKey::random().public_key();

        let mut permissions = BTreeMap::new();
        let _ = permissions.insert(
            PublicKey::from(bls_pk),
            MDataPermissionSet::new()
                .allow(MDataAction::ManagePermissions)
                .allow(MDataAction::Read),
        );

        let name: XorName = XorName(rng.gen());
        let mdata = UnseqMutableData::new_with_data(
            name,
            DIR_TAG,
            BTreeMap::new(),
            permissions,
            PublicKey::from(bls_pk),
        );

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
            .put_unseq_mutable_data(mdata)
            .then(move |res| {
                unwrap!(res);
                let permissions = MDataPermissionSet::new()
                    .allow(MDataAction::Insert)
                    .allow(MDataAction::Delete);
                cl2.set_mdata_user_permissions_new(
                    MDataAddress::new_unseq(name, DIR_TAG),
                    PublicKey::from(random_key_a),
                    permissions,
                    1,
                )
            })
            .then(move |res| {
                unwrap!(res);
                cl3.list_mdata_permissions_new(MDataAddress::new_unseq(name, DIR_TAG))
            })
            .then(move |res| {
                {
                    let permissions = unwrap!(res);
                    assert_eq!(permissions.len(), 2);
                    assert!(!unwrap!(permissions.get(&PublicKey::from(bls_pk)))
                        .is_allowed(MDataAction::Insert));
                    assert!(!unwrap!(permissions.get(&PublicKey::from(bls_pk)))
                        .is_allowed(MDataAction::Update));
                    assert!(!unwrap!(permissions.get(&PublicKey::from(bls_pk)))
                        .is_allowed(MDataAction::Delete));
                    assert!(unwrap!(permissions.get(&PublicKey::from(bls_pk)))
                        .is_allowed(MDataAction::Read));
                    assert!(unwrap!(permissions.get(&PublicKey::from(bls_pk)))
                        .is_allowed(MDataAction::ManagePermissions));
                    assert!(unwrap!(permissions.get(&PublicKey::from(random_key_a)))
                        .is_allowed(MDataAction::Insert));
                    assert!(!unwrap!(permissions.get(&PublicKey::from(random_key_a)))
                        .is_allowed(MDataAction::Read));
                    assert!(!unwrap!(permissions.get(&PublicKey::from(random_key_a)))
                        .is_allowed(MDataAction::Update));
                    assert!(unwrap!(permissions.get(&PublicKey::from(random_key_a)))
                        .is_allowed(MDataAction::Delete));
                    assert!(!unwrap!(permissions.get(&PublicKey::from(random_key_a)))
                        .is_allowed(MDataAction::ManagePermissions));
                }

                let permissions = MDataPermissionSet::new().allow(MDataAction::Delete);
                cl4.set_mdata_user_permissions_new(
                    MDataAddress::new_unseq(name, DIR_TAG),
                    PublicKey::from(random_key_b),
                    permissions,
                    2,
                )
            })
            .then(move |res| {
                unwrap!(res);
                cl5.list_mdata_permissions_new(MDataAddress::new_unseq(name, DIR_TAG))
            })
            .then(move |res| {
                {
                    let permissions = unwrap!(res);
                    assert_eq!(permissions.len(), 3);
                    assert!(!unwrap!(permissions.get(&PublicKey::from(bls_pk)))
                        .is_allowed(MDataAction::Insert));
                    assert!(!unwrap!(permissions.get(&PublicKey::from(bls_pk)))
                        .is_allowed(MDataAction::Update));
                    assert!(!unwrap!(permissions.get(&PublicKey::from(bls_pk)))
                        .is_allowed(MDataAction::Delete));
                    assert!(unwrap!(permissions.get(&PublicKey::from(bls_pk)))
                        .is_allowed(MDataAction::Read));
                    assert!(unwrap!(permissions.get(&PublicKey::from(bls_pk)))
                        .is_allowed(MDataAction::ManagePermissions));
                    assert!(unwrap!(permissions.get(&PublicKey::from(random_key_a)))
                        .is_allowed(MDataAction::Insert));
                    assert!(!unwrap!(permissions.get(&PublicKey::from(random_key_a)))
                        .is_allowed(MDataAction::Update));
                    assert!(unwrap!(permissions.get(&PublicKey::from(random_key_a)))
                        .is_allowed(MDataAction::Delete));
                    assert!(!unwrap!(permissions.get(&PublicKey::from(random_key_a)))
                        .is_allowed(MDataAction::ManagePermissions));
                    assert!(!unwrap!(permissions.get(&PublicKey::from(random_key_b)))
                        .is_allowed(MDataAction::Insert));
                    assert!(!unwrap!(permissions.get(&PublicKey::from(random_key_b)))
                        .is_allowed(MDataAction::Update));
                    assert!(unwrap!(permissions.get(&PublicKey::from(random_key_b)))
                        .is_allowed(MDataAction::Delete));
                    assert!(!unwrap!(permissions.get(&PublicKey::from(random_key_b)))
                        .is_allowed(MDataAction::ManagePermissions));
                }

                let permissions = MDataPermissionSet::new().allow(MDataAction::Insert);
                cl6.set_mdata_user_permissions_new(
                    MDataAddress::new_unseq(name, DIR_TAG),
                    PublicKey::from(random_key_b),
                    permissions,
                    3,
                )
            })
            .then(move |res| {
                unwrap!(res);
                cl7.del_mdata_user_permissions_new(
                    MDataAddress::new_unseq(name, DIR_TAG),
                    PublicKey::from(random_key_a),
                    4,
                )
            })
            .then(move |res| {
                unwrap!(res);
                cl8.list_mdata_permissions_new(MDataAddress::new_unseq(name, DIR_TAG))
            })
            .then(move |res| {
                {
                    let permissions = unwrap!(res);
                    assert_eq!(permissions.len(), 2);
                    assert!(!unwrap!(permissions.get(&PublicKey::from(bls_pk)))
                        .is_allowed(MDataAction::Insert));
                    assert!(!unwrap!(permissions.get(&PublicKey::from(bls_pk)))
                        .is_allowed(MDataAction::Update));
                    assert!(!unwrap!(permissions.get(&PublicKey::from(bls_pk)))
                        .is_allowed(MDataAction::Delete));
                    assert!(unwrap!(permissions.get(&PublicKey::from(bls_pk)))
                        .is_allowed(MDataAction::Read));
                    assert!(unwrap!(permissions.get(&PublicKey::from(bls_pk)))
                        .is_allowed(MDataAction::ManagePermissions));
                    assert!(unwrap!(permissions.get(&PublicKey::from(random_key_b)))
                        .is_allowed(MDataAction::Insert));
                    assert!(!unwrap!(permissions.get(&PublicKey::from(random_key_b)))
                        .is_allowed(MDataAction::Update));
                    assert!(!unwrap!(permissions.get(&PublicKey::from(random_key_b)))
                        .is_allowed(MDataAction::Delete));
                    assert!(!unwrap!(permissions.get(&PublicKey::from(random_key_b)))
                        .is_allowed(MDataAction::ManagePermissions));
                }

                let permissions = MDataPermissionSet::new()
                    .allow(MDataAction::Insert)
                    .allow(MDataAction::Delete);
                cl9.set_mdata_user_permissions_new(
                    MDataAddress::new_unseq(name, DIR_TAG),
                    PublicKey::from(random_key_b),
                    permissions,
                    5,
                )
            })
            .then(move |res| {
                unwrap!(res);
                cl10.list_mdata_permissions_new(MDataAddress::new_unseq(name, DIR_TAG))
            })
            .then(move |res| -> Result<_, ()> {
                {
                    let permissions = unwrap!(res);
                    assert_eq!(permissions.len(), 2);
                    assert!(!unwrap!(permissions.get(&PublicKey::from(bls_pk)))
                        .is_allowed(MDataAction::Insert));
                    assert!(!unwrap!(permissions.get(&PublicKey::from(bls_pk)))
                        .is_allowed(MDataAction::Update));
                    assert!(!unwrap!(permissions.get(&PublicKey::from(bls_pk)))
                        .is_allowed(MDataAction::Delete));
                    assert!(unwrap!(permissions.get(&PublicKey::from(bls_pk)))
                        .is_allowed(MDataAction::Read));
                    assert!(unwrap!(permissions.get(&PublicKey::from(bls_pk)))
                        .is_allowed(MDataAction::ManagePermissions));
                    assert!(unwrap!(permissions.get(&PublicKey::from(random_key_b)))
                        .is_allowed(MDataAction::Insert));
                    assert!(!unwrap!(permissions.get(&PublicKey::from(random_key_b)))
                        .is_allowed(MDataAction::Update));
                    assert!(unwrap!(permissions.get(&PublicKey::from(random_key_b)))
                        .is_allowed(MDataAction::Delete));
                    assert!(!unwrap!(permissions.get(&PublicKey::from(random_key_b)))
                        .is_allowed(MDataAction::ManagePermissions));
                }

                Ok(())
            })
            .map_err(|e| panic!("{:?}", e))
    }));
}

// The usual test to insert, update, delete and list all entry-keys/values. Same thing from
// `permissions_crud` with entry-key/value. After deleting an entry the key is also removed so we
// should be allowed to re-insert this with version 0.
#[test]
fn sequenced_entries_crud() {
    let app = create_app();
    unwrap!(run(&app, |client: &AppClient, _app_context| {
        let mut rng = unwrap!(OsRng::new());
        let bls_pk = unwrap!(client.public_bls_key());

        let mut permissions = BTreeMap::new();
        let _ = permissions.insert(
            PublicKey::from(bls_pk),
            MDataPermissionSet::new()
                .allow(MDataAction::Read)
                .allow(MDataAction::Insert)
                .allow(MDataAction::Update)
                .allow(MDataAction::Delete),
        );

        let mut data = BTreeMap::new();
        let _ = data.insert(
            vec![0, 0, 1],
            MDataValue {
                data: vec![1],
                version: 0,
            },
        );
        let _ = data.insert(
            vec![0, 1, 0],
            MDataValue {
                data: vec![2, 8],
                version: 0,
            },
        );

        let name: XorName = XorName(rng.gen());
        let mdata = SeqMutableData::new_with_data(
            name,
            DIR_TAG,
            data,
            permissions,
            PublicKey::from(bls_pk),
        );

        let cl2 = client.clone();
        let cl3 = client.clone();
        let cl4 = client.clone();
        let cl5 = client.clone();
        client
            .put_seq_mutable_data(mdata)
            .then(move |res| {
                unwrap!(res);
                let mut actions = BTreeMap::new();
                let _ = actions.insert(
                    vec![0, 1, 1],
                    MDataSeqEntryAction::Ins(MDataValue {
                        data: vec![2, 3, 17],
                        version: 0,
                    }),
                );
                let _ = actions.insert(
                    vec![0, 1, 0],
                    MDataSeqEntryAction::Update(MDataValue {
                        data: vec![2, 8, 64],
                        version: 1,
                    }),
                );
                let _ = actions.insert(vec![0, 0, 1], MDataSeqEntryAction::Del(1));
                cl2.mutate_seq_mdata_entries(name, DIR_TAG, actions)
            })
            .then(move |res| {
                unwrap!(res);
                cl3.list_seq_mdata_entries(name, DIR_TAG)
            })
            .then(move |res| {
                let entries = unwrap!(res);
                assert_eq!(entries.len(), 2);
                assert!(entries.get(&vec![0, 0, 1]).is_none());
                assert_eq!(
                    *unwrap!(entries.get(&vec![0, 1, 0])),
                    MDataValue {
                        data: vec![2, 8, 64],
                        version: 1,
                    }
                );
                assert_eq!(
                    *unwrap!(entries.get(&vec![0, 1, 1])),
                    MDataValue {
                        data: vec![2, 3, 17],
                        version: 0,
                    }
                );
                let mut actions = BTreeMap::new();
                let _ = actions.insert(
                    vec![1, 0, 0],
                    MDataSeqEntryAction::Ins(MDataValue {
                        data: vec![4, 4, 4, 4],
                        version: 0,
                    }),
                );
                let _ = actions.insert(
                    vec![0, 1, 0],
                    MDataSeqEntryAction::Update(MDataValue {
                        data: vec![64, 8, 1],
                        version: 2,
                    }),
                );
                let _ = actions.insert(vec![0, 1, 1], MDataSeqEntryAction::Del(1));
                cl4.mutate_seq_mdata_entries(name, DIR_TAG, actions)
            })
            .then(move |res| {
                unwrap!(res);
                cl5.list_seq_mdata_entries(name, DIR_TAG)
            })
            .then(|res| -> Result<_, ()> {
                let entries = unwrap!(res);
                assert_eq!(entries.len(), 2);
                assert!(entries.get(&vec![0, 0, 1]).is_none());
                assert_eq!(
                    *unwrap!(entries.get(&vec![0, 1, 0])),
                    MDataValue {
                        data: vec![64, 8, 1],
                        version: 2,
                    }
                );
                assert!(entries.get(&vec![0, 1, 1]).is_none());
                assert_eq!(
                    *unwrap!(entries.get(&vec![1, 0, 0])),
                    MDataValue {
                        data: vec![4, 4, 4, 4],
                        version: 0,
                    }
                );
                Ok(())
            })
            .map_err(|e| panic!("{:?}", e))
    }));
}

#[test]
fn unsequenced_entries_crud() {
    let app = create_app();
    unwrap!(run(&app, |client: &AppClient, _app_context| {
        let mut rng = unwrap!(OsRng::new());
        let bls_pk = unwrap!(client.public_bls_key());

        let mut permissions = BTreeMap::new();
        let _ = permissions.insert(
            PublicKey::from(bls_pk),
            MDataPermissionSet::new()
                .allow(MDataAction::Read)
                .allow(MDataAction::Insert)
                .allow(MDataAction::Update)
                .allow(MDataAction::Delete),
        );

        let mut data = BTreeMap::new();
        let _ = data.insert(vec![0, 0, 1], vec![1]);
        let _ = data.insert(vec![0, 1, 0], vec![2, 8]);

        let name: XorName = XorName(rng.gen());
        let mdata = UnseqMutableData::new_with_data(
            name,
            DIR_TAG,
            data,
            permissions,
            PublicKey::from(bls_pk),
        );

        let cl2 = client.clone();
        let cl3 = client.clone();
        let cl4 = client.clone();
        let cl5 = client.clone();
        client
            .put_unseq_mutable_data(mdata)
            .then(move |res| {
                unwrap!(res);
                let mut actions = BTreeMap::new();
                let _ = actions.insert(vec![0, 1, 1], MDataUnseqEntryAction::Ins(vec![2, 3, 17]));
                let _ =
                    actions.insert(vec![0, 1, 0], MDataUnseqEntryAction::Update(vec![2, 8, 64]));
                let _ = actions.insert(vec![0, 0, 1], MDataUnseqEntryAction::Del);
                cl2.mutate_unseq_mdata_entries(name, DIR_TAG, actions)
            })
            .then(move |res| {
                unwrap!(res);
                cl3.list_unseq_mdata_entries(name, DIR_TAG)
            })
            .then(move |res| {
                let entries = unwrap!(res);
                assert_eq!(entries.len(), 2);
                assert!(entries.get(&vec![0, 0, 1]).is_none());
                assert_eq!(*unwrap!(entries.get(&vec![0, 1, 0])), vec![2, 8, 64]);
                assert_eq!(*unwrap!(entries.get(&vec![0, 1, 1])), vec![2, 3, 17],);
                let mut actions = BTreeMap::new();
                let _ = actions.insert(vec![1, 0, 0], MDataUnseqEntryAction::Ins(vec![4, 4, 4, 4]));
                let _ =
                    actions.insert(vec![0, 1, 0], MDataUnseqEntryAction::Update(vec![64, 8, 1]));
                let _ = actions.insert(vec![0, 1, 1], MDataUnseqEntryAction::Del);
                cl4.mutate_unseq_mdata_entries(name, DIR_TAG, actions)
            })
            .then(move |res| {
                unwrap!(res);
                cl5.list_unseq_mdata_entries(name, DIR_TAG)
            })
            .then(|res| -> Result<_, ()> {
                let entries = unwrap!(res);
                assert_eq!(entries.len(), 2);
                assert!(entries.get(&vec![0, 0, 1]).is_none());
                assert_eq!(*unwrap!(entries.get(&vec![0, 1, 0])), vec![64, 8, 1]);
                assert!(entries.get(&vec![0, 1, 1]).is_none());
                assert_eq!(*unwrap!(entries.get(&vec![1, 0, 0])), vec![4, 4, 4, 4]);
                Ok(())
            })
            .map_err(|e| panic!("{:?}", e))
    }));
}
