// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

// FIXME: consider splitting test functions into multiple smaller ones
#![allow(clippy::cognitive_complexity)]
#![allow(unused_imports)] // Remove this after fixing all the tests

use crate::client::mock::vault::Vault;
use crate::client::{SafeKey, COST_OF_PUT};
use crate::config_handler::{Config, DevConfig};
use crate::utils::test_utils::{gen_app_id, gen_client_id};
use crate::{utils, NetworkEvent};

use super::connection_manager::ConnectionManager;
use bincode::serialize;
use futures::sync::mpsc::{self, UnboundedReceiver};
use futures::Future;
use rand::thread_rng;
use safe_nd::{
    AppFullId, AppPermissions, ClientFullId, Coins, Error, IData, MData, MDataAction as NewAction,
    MDataAction, MDataAddress, MDataEntries, MDataPermissionSet as NewPermissionSet,
    MDataPermissionSet, MDataSeqEntryAction, MDataSeqEntryActions, MDataSeqValue, MDataValue,
    MDataValues, Message, MessageId, PubImmutableData, PublicId, PublicKey, Request, RequestType,
    Response, SeqMutableData, UnpubImmutableData, UnseqMutableData, XorName,
};
use std::collections::{BTreeMap, BTreeSet};
use std::convert::TryInto;
use std::str::FromStr;
use std::sync::mpsc as std_mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use threshold_crypto::SecretKey;

// Helper macro to fetch the response for a request and
// assert that the expected error is returned.
macro_rules! send_req_expect_failure {
    ($cm:expr, $sender:expr, $req:expr, $err:path) => {
        let expected_response = $req.error_response($err);
        let response = process_request($cm, $sender, $req);
        assert_eq!(response, expected_response);
    };
}

macro_rules! send_req_expect_ok {
    ($cm:expr, $sender:expr, $req:expr, $res:expr) => {
        let response = process_request($cm, $sender, $req);
        assert_eq!($res, unwrap!(response.try_into()));
    };
}

fn process_request(
    connection_manager: &mut ConnectionManager,
    sender: &SafeKey,
    request: Request,
) -> Response {
    let sign = request.get_type() != RequestType::PublicGet;
    let message_id = MessageId::new();
    let signature = if sign {
        Some(sender.sign(&unwrap!(serialize(&(&request, message_id)))))
    } else {
        None
    };
    let message = Message::Request {
        request,
        message_id,
        signature,
    };
    unwrap!(connection_manager
        .send(&sender.public_id(), &message)
        .wait())
}

// Test the basics idata operations.
#[test]
fn immutable_data_basics() {
    let (mut connection_manager, _, client_safe_key, _) = setup();

    // Construct PubImmutableData
    let orig_data: IData =
        PubImmutableData::new(unwrap!(utils::generate_random_vector(100))).into();

    // GetIData should fail
    let get_request = Request::GetIData(*orig_data.address());
    send_req_expect_failure!(
        &mut connection_manager,
        &client_safe_key,
        get_request.clone(),
        Error::NoSuchData
    );

    // First PutIData should succeed
    let put_request = Request::PutIData(orig_data.clone());
    send_req_expect_ok!(
        &mut connection_manager,
        &client_safe_key,
        put_request.clone(),
        ()
    );

    // Now GetIData should pass
    send_req_expect_ok!(
        &mut connection_manager,
        &client_safe_key,
        get_request.clone(),
        orig_data
    );

    // Initial balance is 10 coins
    let balance = unwrap!(Coins::from_str("10"));
    let balance = unwrap!(balance.checked_sub(*COST_OF_PUT));
    send_req_expect_ok!(
        &mut connection_manager,
        &client_safe_key,
        Request::GetBalance,
        balance
    );

    // Subsequent PutIData for same data should succeed - De-duplication
    send_req_expect_ok!(&mut connection_manager, &client_safe_key, put_request, ());

    // GetIData should succeed
    send_req_expect_ok!(
        &mut connection_manager,
        &client_safe_key,
        get_request,
        orig_data
    );

    // The balance should be deducted twice
    let balance = unwrap!(balance.checked_sub(*COST_OF_PUT));
    send_req_expect_ok!(
        &mut connection_manager,
        &client_safe_key,
        Request::GetBalance,
        balance
    );
}

// Test the basic mdata operations.
#[test]
fn mutable_data_basics() {
    let (mut connection_manager, _, client_safe_key, owner_key) = setup();

    // Construct MutableData
    let name = rand::random();
    let tag = 1000u64;

    let data = SeqMutableData::new(name, tag, owner_key);
    let data1_address = *data.address();

    // Operations on non-existing MutableData should fail.
    send_req_expect_failure!(
        &mut connection_manager,
        &client_safe_key,
        Request::GetMDataVersion(data1_address),
        Error::NoSuchData
    );

    send_req_expect_failure!(
        &mut connection_manager,
        &client_safe_key,
        Request::ListMDataEntries(data1_address),
        Error::NoSuchData
    );

    // PutMData
    send_req_expect_ok!(
        &mut connection_manager,
        &client_safe_key,
        Request::PutMData(data.into()),
        ()
    );

    // It should be possible to put an MData using the same name but a
    // different type tag
    let tag2 = 1001u64;

    let data2: MData = SeqMutableData::new(name, tag2, owner_key).into();
    let data2_address = *data2.address();
    send_req_expect_ok!(
        &mut connection_manager,
        &client_safe_key,
        Request::PutMData(data2.clone()),
        ()
    );

    // GetMDataVersion should respond with 0
    let response = process_request(
        &mut connection_manager,
        &client_safe_key,
        Request::GetMDataVersion(data2_address),
    );
    assert_eq!(response, Response::GetMDataVersion(Ok(0)));

    // GetMData should return the entire MutableData object
    send_req_expect_ok!(
        &mut connection_manager,
        &client_safe_key,
        Request::GetMData(data2_address),
        data2
    );

    // ListMDataEntries, ListMDataKeys and ListMDataValues should all respond
    // with empty collections.
    send_req_expect_ok!(
        &mut connection_manager,
        &client_safe_key,
        Request::ListMDataEntries(data2_address),
        MDataEntries::from(BTreeMap::<_, MDataSeqValue>::new())
    );

    send_req_expect_ok!(
        &mut connection_manager,
        &client_safe_key,
        Request::ListMDataKeys(data2_address),
        BTreeSet::new()
    );

    send_req_expect_ok!(
        &mut connection_manager,
        &client_safe_key,
        Request::ListMDataValues(data2_address),
        MDataValues::from(Vec::<MDataSeqValue>::new())
    );

    // Add couple of entries
    let key0 = b"key0";
    let key1 = b"key1";
    let value0_v0 = unwrap!(utils::generate_random_vector(10));
    let value1_v0 = unwrap!(utils::generate_random_vector(10));

    let actions: MDataSeqEntryActions = btree_map![
        key0.to_vec() => MDataSeqEntryAction::Ins(MDataSeqValue {
            data: value0_v0.clone(),
            version: 0,
        }),
        key1.to_vec() => MDataSeqEntryAction::Ins(MDataSeqValue {
            data: value1_v0.clone(),
            version: 0,
        })
    ]
    .into();

    send_req_expect_ok!(
        &mut connection_manager,
        &client_safe_key,
        Request::MutateMDataEntries {
            address: data2_address,
            actions: actions.into()
        },
        ()
    );

    let response = process_request(
        &mut connection_manager,
        &client_safe_key,
        Request::ListMDataEntries(data2_address),
    );
    let entries: MDataEntries = unwrap!(response.try_into());

    match entries {
        MDataEntries::Seq(entries) => {
            assert_eq!(entries.len(), 2);

            let entry = unwrap!(entries.get(&key0[..]));
            assert_eq!(entry.data, value0_v0);
            assert_eq!(entry.version, 0);

            let entry = unwrap!(entries.get(&key1[..]));
            assert_eq!(entry.data, value1_v0);
            assert_eq!(entry.version, 0);
        }
        _ => panic!("MData type mismatch"),
    }

    // First MData with a diff. type tag still should be empty
    send_req_expect_ok!(
        &mut connection_manager,
        &client_safe_key,
        Request::ListMDataEntries(data1_address),
        MDataEntries::from(BTreeMap::<_, MDataSeqValue>::new())
    );

    // ListMDataKeys
    let response = process_request(
        &mut connection_manager,
        &client_safe_key,
        Request::ListMDataKeys(data2_address),
    );
    match response {
        Response::ListMDataKeys(Ok(keys)) => {
            assert_eq!(keys.len(), 2);
            assert!(keys.contains(&key0[..]));
            assert!(keys.contains(&key1[..]));
        }
        Response::ListMDataKeys(err) => panic!("Unexpected error: {:?}", err),
        res => panic!("Unexpected response: {:?}", res),
    }

    // ListMDataValues
    let response = process_request(
        &mut connection_manager,
        &client_safe_key,
        Request::ListMDataValues(data2_address),
    );
    match response {
        Response::ListMDataValues(Ok(values)) => match values {
            MDataValues::Seq(seq_values) => assert_eq!(seq_values.len(), 2),
            _ => panic!("MData type mismatch"),
        },
        Response::ListMDataValues(err) => panic!("Unexpected error: {:?}", err),
        res => panic!("Unexpected response: {:?}", res),
    }

    send_req_expect_ok!(
        &mut connection_manager,
        &client_safe_key,
        Request::GetMDataValue {
            address: data2_address,
            key: key0.to_vec()
        },
        MDataValue::Seq(MDataSeqValue {
            data: value0_v0,
            version: 0
        })
    );

    // GetMDataValue with non-existing key
    let key2 = b"key2";
    send_req_expect_failure!(
        &mut connection_manager,
        &client_safe_key,
        Request::GetMDataValue {
            address: data2_address,
            key: key2.to_vec()
        },
        Error::NoSuchEntry
    );

    // Mutate the entries: insert, update and delete
    let value0_v1 = unwrap!(utils::generate_random_vector(10));
    let value2_v0 = unwrap!(utils::generate_random_vector(10));
    let actions: MDataSeqEntryActions = btree_map![
        key0.to_vec() => MDataSeqEntryAction::Update(MDataSeqValue {
            data: value0_v1.clone(),
            version: 1,
        }),
        key1.to_vec() => MDataSeqEntryAction::Del(1),
        key2.to_vec() => MDataSeqEntryAction::Ins(MDataSeqValue {
            data: value2_v0.clone(),
            version: 0,
        })
    ]
    .into();

    send_req_expect_ok!(
        &mut connection_manager,
        &client_safe_key,
        Request::MutateMDataEntries {
            address: data2_address,
            actions: actions.into()
        },
        ()
    );

    let response = process_request(
        &mut connection_manager,
        &client_safe_key,
        Request::ListMDataEntries(data2_address),
    );
    let entries: MDataEntries = unwrap!(response.try_into());

    match entries {
        MDataEntries::Seq(entries) => {
            assert_eq!(entries.len(), 2);

            // Updated entry
            let entry = unwrap!(entries.get(&key0[..]));
            assert_eq!(entry.data, value0_v1);
            assert_eq!(entry.version, 1);

            // Deleted entry
            let entry = entries.get(&key1[..]);
            assert!(entry.is_none());

            // Inserted entry
            let entry = unwrap!(entries.get(&key2[..]));
            assert_eq!(entry.data, value2_v0);
            assert_eq!(entry.version, 0);
        }
        _ => panic!("MData type mismatch"),
    }
}

// Test reclamation of deleted mdata.
#[test]
fn mutable_data_reclaim() {
    let (mut connection_manager, _, client_safe_key, owner_key) = setup();

    // Construct MutableData
    let name = rand::random();
    let tag = 1000u64;

    let data = SeqMutableData::new(name, tag, owner_key);
    let address: MDataAddress = *data.address();

    // PutMData
    send_req_expect_ok!(
        &mut connection_manager,
        &client_safe_key,
        Request::PutMData(data.into()),
        ()
    );

    // Mutate the entries: insert, delete and insert again
    let key0 = b"key0";
    let value0 = unwrap!(utils::generate_random_vector(10));
    let actions: MDataSeqEntryActions = btree_map![
        key0.to_vec() => MDataSeqEntryAction::Ins(MDataSeqValue {
            data: value0.clone(),
            version: 0,
        }),
    ]
    .into();

    send_req_expect_ok!(
        &mut connection_manager,
        &client_safe_key,
        Request::MutateMDataEntries {
            address,
            actions: actions.into()
        },
        ()
    );

    let actions: MDataSeqEntryActions = btree_map![
        key0.to_vec() => MDataSeqEntryAction::Update(MDataSeqValue {
            data: value0.clone(),
            version: 1,
        })
    ]
    .into();

    send_req_expect_ok!(
        &mut connection_manager,
        &client_safe_key,
        Request::MutateMDataEntries {
            address,
            actions: actions.into()
        },
        ()
    );

    // GetMDataVersion should respond with 0 as the mdata itself hasn't changed.
    let response = process_request(
        &mut connection_manager,
        &client_safe_key,
        Request::GetMDataVersion(address),
    );
    assert_eq!(response, Response::GetMDataVersion(Ok(0)));

    // Try deleting the entry with an invalid entry_version and make sure it fails
    let actions: MDataSeqEntryActions = btree_map![
        key0.to_vec() => MDataSeqEntryAction::Del(3),
    ]
    .into();

    let response = process_request(
        &mut connection_manager,
        &client_safe_key,
        Request::MutateMDataEntries {
            address,
            actions: actions.into(),
        },
    );
    match response {
        Response::Mutation(Err(Error::InvalidEntryActions(_))) => (),
        Response::Mutation(Ok(())) => panic!("Unexpected success"),
        res => panic!("Unexpected response: {:?}", res),
    }

    // Try deleting the entry with an entry_version of 2 and make sure it succeeds
    let actions: MDataSeqEntryActions = btree_map![
        key0.to_vec() => MDataSeqEntryAction::Del(2),
    ]
    .into();

    send_req_expect_ok!(
        &mut connection_manager,
        &client_safe_key,
        Request::MutateMDataEntries {
            address,
            actions: actions.into()
        },
        ()
    );
}

// Test valid and invalid mdata entry versioning.
#[test]
fn mutable_data_entry_versioning() {
    let (mut connection_manager, _, client_safe_key, owner_key) = setup();

    // Construct MutableData
    let name = rand::random();
    let tag = 1000u64;

    let data = SeqMutableData::new(name, tag, owner_key);
    let address = *data.address();

    // PutMData
    send_req_expect_ok!(
        &mut connection_manager,
        &client_safe_key,
        Request::PutMData(data.into()),
        ()
    );

    // Insert a new entry
    let key = b"key0";
    let value_v0 = unwrap!(utils::generate_random_vector(10));
    let actions: MDataSeqEntryActions = btree_map![
        key.to_vec() => MDataSeqEntryAction::Ins(MDataSeqValue {
            data: value_v0,
            version: 0,
        })
    ]
    .into();

    send_req_expect_ok!(
        &mut connection_manager,
        &client_safe_key,
        Request::MutateMDataEntries {
            address,
            actions: actions.into(),
        },
        ()
    );

    // Attempt to update it without version bump fails.
    let value_v1 = unwrap!(utils::generate_random_vector(10));
    let actions: MDataSeqEntryActions = btree_map![
        key.to_vec() => MDataSeqEntryAction::Update(MDataSeqValue {
            data: value_v1.clone(),
            version: 0,
        })
    ]
    .into();

    let response = process_request(
        &mut connection_manager,
        &client_safe_key,
        Request::MutateMDataEntries {
            address,
            actions: actions.into(),
        },
    );
    match response {
        Response::Mutation(Err(Error::InvalidEntryActions(_))) => (),
        Response::Mutation(Ok(())) => panic!("Unexpected success"),
        res => panic!("Unexpected response: {:?}", res),
    }

    // Attempt to update it with incorrect version fails.
    let actions: MDataSeqEntryActions =
        MDataSeqEntryActions::new().update(key.to_vec(), value_v1.clone(), 314_159_265);
    let response = process_request(
        &mut connection_manager,
        &client_safe_key,
        Request::MutateMDataEntries {
            address,
            actions: actions.into(),
        },
    );
    match response {
        Response::Mutation(Err(Error::InvalidEntryActions(_))) => (),
        Response::Mutation(Ok(())) => panic!("Unexpected success"),
        res => panic!("Unexpected response: {:?}", res),
    }

    // Update with correct version bump succeeds.
    let actions: MDataSeqEntryActions = btree_map![
        key.to_vec() => MDataSeqEntryAction::Update(MDataSeqValue {
            data: value_v1.clone(),
            version: 1,
        })
    ]
    .into();

    send_req_expect_ok!(
        &mut connection_manager,
        &client_safe_key,
        Request::MutateMDataEntries {
            address,
            actions: actions.into(),
        },
        ()
    );

    // Delete without version bump fails.
    let actions: MDataSeqEntryActions = btree_map![
        key.to_vec() => MDataSeqEntryAction::Del(1)
    ]
    .into();

    let response = process_request(
        &mut connection_manager,
        &client_safe_key,
        Request::MutateMDataEntries {
            address,
            actions: actions.into(),
        },
    );
    match response {
        Response::Mutation(Err(Error::InvalidEntryActions(_))) => (),
        Response::Mutation(Ok(())) => panic!("Unexpected success"),
        res => panic!("Unexpected response: {:?}", res),
    }

    // Delete with correct version bump succeeds.
    let actions: MDataSeqEntryActions = btree_map![
        key.to_vec() => MDataSeqEntryAction::Del(2)
    ]
    .into();

    send_req_expect_ok!(
        &mut connection_manager,
        &client_safe_key,
        Request::MutateMDataEntries {
            address,
            actions: actions.into(),
        },
        ()
    );
}

// Test various operations with and without proper permissions.
#[test]
fn mutable_data_permissions() {
    let (mut connection_manager, _, client_safe_key, owner_key) = setup();

    // Construct MutableData with some entries and empty permissions.
    let name = rand::random();
    let tag = 1000u64;

    let key0 = b"key0";
    let value0_v0 = unwrap!(utils::generate_random_vector(10));

    let entries = btree_map![
        key0.to_vec() => MDataSeqValue { data: value0_v0, version: 0 }
    ];

    let data = SeqMutableData::new_with_data(name, tag, entries, Default::default(), owner_key);
    let address: MDataAddress = *data.address();

    // Put it to the network.
    send_req_expect_ok!(
        &mut connection_manager,
        &client_safe_key,
        Request::PutMData(data.into()),
        ()
    );

    // ListMDataPermissions responds with empty collection.
    let response = process_request(
        &mut connection_manager,
        &client_safe_key,
        Request::ListMDataPermissions(address),
    );
    let permissions: BTreeMap<PublicKey, MDataPermissionSet> = unwrap!(response.try_into());
    assert!(permissions.is_empty());

    // Owner can do anything by default.
    let value0_v1 = unwrap!(utils::generate_random_vector(10));
    let actions = MDataSeqEntryActions::new().update(key0.to_vec(), value0_v1, 1);
    send_req_expect_ok!(
        &mut connection_manager,
        &client_safe_key,
        Request::MutateMDataEntries {
            address,
            actions: actions.into()
        },
        ()
    );

    // Create app and authorise it.
    let (app_safe_key, mut connection_manager2, _) = register_new_app(
        &mut connection_manager,
        &client_safe_key,
        AppPermissions {
            get_balance: true,
            transfer_coins: true,
            perform_mutations: true,
        },
    );

    // App can't mutate any entry, by default.
    let value0_v2 = unwrap!(utils::generate_random_vector(10));
    let actions = MDataSeqEntryActions::new().update(key0.to_vec(), value0_v2.clone(), 2);
    let mutation_request = Request::MutateMDataEntries {
        address,
        actions: actions.into(),
    };
    send_req_expect_failure!(
        &mut connection_manager2,
        &app_safe_key,
        mutation_request.clone(),
        Error::AccessDenied
    );

    // App can't grant itself permission to update and read.
    let permissions = MDataPermissionSet::new()
        .allow(MDataAction::Update)
        .allow(MDataAction::Read);
    let update_perms_req = Request::SetMDataUserPermissions {
        address,
        user: app_safe_key.public_key(),
        permissions,
        version: 1,
    };
    send_req_expect_failure!(
        &mut connection_manager,
        &app_safe_key,
        update_perms_req.clone(),
        Error::AccessDenied
    );

    // Verify app still can't update, after the previous attempt to
    // modify its permissions.
    send_req_expect_failure!(
        &mut connection_manager2,
        &app_safe_key,
        mutation_request.clone(),
        Error::AccessDenied
    );

    // Grant read and update permission for app.
    send_req_expect_ok!(
        &mut connection_manager,
        &client_safe_key,
        update_perms_req,
        ()
    );

    // The version is bumped.
    let response = process_request(
        &mut connection_manager,
        &client_safe_key,
        Request::GetMDataVersion(address),
    );
    assert_eq!(response, Response::GetMDataVersion(Ok(1)));

    // App can't insert entries.
    let key1 = b"key1";
    let value1_v0 = unwrap!(utils::generate_random_vector(10));

    let actions: MDataSeqEntryActions = btree_map![
    key1.to_vec() => MDataSeqEntryAction::Ins(MDataSeqValue {
        data: value1_v0.clone(),
        version: 0,
    })
    ]
    .into();

    let insertion_request = Request::MutateMDataEntries {
        address,
        actions: actions.into(),
    };
    send_req_expect_failure!(
        &mut connection_manager2,
        &app_safe_key,
        insertion_request.clone(),
        Error::AccessDenied
    );

    // But it can update an entry.
    let actions: MDataSeqEntryActions = btree_map![
    key0.to_vec() => MDataSeqEntryAction::Update(MDataSeqValue {
        data: value0_v2,
        version: 2,
    })
    ]
    .into();

    send_req_expect_ok!(
        &mut connection_manager2,
        &app_safe_key,
        Request::MutateMDataEntries {
            address,
            actions: actions.into(),
        },
        ()
    );

    // Attempt to modify permissions without proper version bump fails
    let permissions = MDataPermissionSet::new()
        .allow(MDataAction::Read)
        .allow(MDataAction::Insert)
        .allow(MDataAction::Update);
    let invalid_update_perms_req = Request::SetMDataUserPermissions {
        address,
        user: app_safe_key.public_key(),
        permissions: permissions.clone(),
        version: 1,
    };
    let error = Error::InvalidSuccessor(1);
    send_req_expect_failure!(
        &mut connection_manager,
        &client_safe_key,
        invalid_update_perms_req,
        error
    );

    // Modifying permissions with version bump succeeds.
    let valid_update_perms_req = Request::SetMDataUserPermissions {
        address,
        user: app_safe_key.public_key(),
        permissions,
        version: 2,
    };
    send_req_expect_ok!(
        &mut connection_manager,
        &client_safe_key,
        valid_update_perms_req,
        ()
    );

    // App can now update entries.
    send_req_expect_ok!(
        &mut connection_manager2,
        &app_safe_key,
        insertion_request,
        ()
    );

    // Revoke all permissions from app.
    send_req_expect_ok!(
        &mut connection_manager2,
        &client_safe_key,
        Request::DelMDataUserPermissions {
            address,
            user: app_safe_key.public_key(),
            version: 3
        },
        ()
    );

    // App can no longer mutate the entries.
    send_req_expect_failure!(
        &mut connection_manager2,
        &app_safe_key,
        mutation_request.clone(),
        Error::AccessDenied
    );

    // Grant the app permission to manage permissions.
    let permissions = MDataPermissionSet::new().allow(MDataAction::ManagePermissions);
    send_req_expect_ok!(
        &mut connection_manager,
        &client_safe_key,
        Request::SetMDataUserPermissions {
            address,
            user: app_safe_key.public_key(),
            permissions,
            version: 4
        },
        ()
    );

    // The app still can't mutate the entries.
    send_req_expect_failure!(
        &mut connection_manager2,
        &app_safe_key,
        mutation_request.clone(),
        Error::AccessDenied
    );

    // App can modify its own permission.
    let permissions = MDataPermissionSet::new().allow(MDataAction::Update);
    send_req_expect_ok!(
        &mut connection_manager2,
        &app_safe_key,
        Request::SetMDataUserPermissions {
            address,
            user: app_safe_key.public_key(),
            permissions,
            version: 5
        },
        ()
    );

    // The app can now mutate the entries.
    let value1_v1 = unwrap!(utils::generate_random_vector(10));
    let actions = MDataSeqEntryActions::new().update(key1.to_vec(), value1_v1, 1);
    send_req_expect_ok!(
        &mut connection_manager2,
        &app_safe_key,
        Request::MutateMDataEntries {
            address,
            actions: actions.into()
        },
        ()
    );
}

// Test mdata operations with valid and invalid owner.
#[test]
fn mutable_data_ownership() {
    // Create owner's connection manager
    let (mut connection_manager, _, client_safe_key, owner_key) = setup();

    // Create app's connection_manager
    let (app_safe_key, mut connection_manager2, _) = register_new_app(
        &mut connection_manager,
        &client_safe_key,
        AppPermissions {
            get_balance: true,
            transfer_coins: true,
            perform_mutations: true,
        },
    );

    // Attempt to put MutableData using the app sign key as owner key should fail.
    let name = rand::random();
    let tag = 1000u64;
    let data: MData = SeqMutableData::new(name, tag, app_safe_key.public_key()).into();

    send_req_expect_failure!(
        &mut connection_manager2,
        &app_safe_key,
        Request::PutMData(data.clone()),
        Error::InvalidOwners
    );

    // Putting it with correct owner succeeds.
    let data: MData = SeqMutableData::new(name, tag, owner_key).into();

    send_req_expect_ok!(
        &mut connection_manager,
        &app_safe_key,
        Request::PutMData(data),
        ()
    );
}

/*
#[test]
fn pub_idata_rpc() {
    let (mut routing, routing_rx, full_id, _) = setup();
    let coins = unwrap!(Coins::from_str("10"));
    let owner_sk = full_id.bls_key();
    let (_, full_id_new) = create_account(&mut routing, coins, owner_sk);

    let value = unwrap!(utils::generate_random_vector::<u8>(10));
    let data = PubImmutableData::new(value);
    let address = *data.address();

    // Put pub idata. Should succeed.
    {
        let rpc_response =
            routing.req(&routing_rx, RpcRequest::PutIData(data.into()), &full_id_new);
        match rpc_response {
            RpcResponse::Mutation(res) => {
                assert!(res.is_ok());
            }
            _ => panic!("Unexpected"),
        }
    }

    // Get pub idata as an owner. Should succeed.
    {
        let rpc_response = routing.req(&routing_rx, RpcRequest::GetIData(address), &full_id_new);
        match rpc_response {
            RpcResponse::GetIData(res) => {
                let idata: IData = unwrap!(res);
                assert_eq!(*idata.address(), address);
            }
            _ => panic!("Unexpected"),
        }
    }

    let (mut app_routing, app_routing_rx, _, app_full_id_new) = setup();

    // Get pub idata while not being an owner. Should succeed.
    {
        let rpc_response = app_routing.req(
            &app_routing_rx,
            RpcRequest::GetIData(address),
            &app_full_id_new,
        );
        match rpc_response {
            RpcResponse::GetIData(res) => {
                let idata: IData = unwrap!(res);
                assert_eq!(*idata.address(), address);
            }
            _ => panic!("Unexpected"),
        }
    }
}

#[test]
fn unpub_idata_rpc() {
    let (mut owner_routing, owner_routing_rx, full_id, _) = setup();
    let coins = unwrap!(Coins::from_str("10"));
    let owner_sk = full_id.bls_key();
    let (_, full_id_new) = create_account(&mut owner_routing, coins, owner_sk);

    let value = unwrap!(utils::generate_random_vector::<u8>(10));
    let data =
        UnpubImmutableData::new(value, PublicKey::Bls(*full_id.public_id().bls_public_key()));
    let address = *data.address();

    // Construct put request.
    let response = owner_routing.req(
        &owner_routing_rx,
        RpcRequest::PutIData(data.into()),
        &full_id_new,
    );
    match response {
        RpcResponse::Mutation(res) => {
            assert!(res.is_ok());
        }
        _ => panic!("Unexpected response"),
    }

    // Construct get request.
    let rpc_response = owner_routing.req(
        &owner_routing_rx,
        RpcRequest::GetIData(address),
        &full_id_new,
    );
    match rpc_response {
        RpcResponse::GetIData(res) => {
            let idata: IData = unwrap!(res);
            assert_eq!(*idata.address(), address);
        }
        _ => panic!("Unexpected response"),
    }

    let (mut app_routing, app_routing_rx, _, app_full_id_new) = setup();

    // Try to get unpub idata while not being an owner. Should fail.
    {
        let rpc_response = app_routing.req(
            &app_routing_rx,
            RpcRequest::GetIData(address),
            &app_full_id_new,
        );
        match rpc_response {
            RpcResponse::GetIData(res) => match res {
                Ok(_) => panic!("Unexpected"),
                Err(Error::AccessDenied) => (),
                Err(e) => panic!("Unexpected {:?}", e),
            },
            _ => panic!("Unexpected"),
        }
    }

    // Try to delete unpub idata while not being an owner. Should fail.
    {
        let rpc_response = app_routing.req(
            &app_routing_rx,
            RpcRequest::DeleteUnpubIData(address),
            &app_full_id_new,
        );
        match rpc_response {
            RpcResponse::Mutation(res) => match res {
                Ok(_) => panic!("Unexpected"),
                Err(Error::AccessDenied) => (),
                Err(e) => panic!("Unexpected {:?}", e),
            },
            _ => panic!("Unexpected"),
        }
    }
}

#[test]
fn unpub_md() {
    let (mut routing, routing_rx, full_id, _) = setup();
    let coins = unwrap!(Coins::from_str("10"));
    let owner_sk = full_id.bls_key();
    let (_, full_id_new) = create_account(&mut routing, coins, owner_sk);
    let bls_key = full_id.bls_key().public_key();

    let name = XorName(rand::random());
    let tag = 15001;

    let mut permissions: BTreeMap<_, _> = Default::default();
    let _ = permissions.insert(
        PublicKey::Bls(bls_key),
        NewPermissionSet::new().allow(NewAction::Read),
    );
    let data = UnseqMutableData::new_with_data(
        name,
        tag,
        Default::default(),
        permissions,
        PublicKey::from(bls_key),
    );

    // Construct put request.
    let response: RpcResponse = routing.req(
        &routing_rx,
        RpcRequest::PutMData(MData::Unseq(data.clone())),
        &full_id_new,
    );

    match response {
        RpcResponse::Mutation(res) => unwrap!(res),
        _ => panic!("Unexpected response"),
    };

    // Construct get request.
    let rpc_response: RpcResponse = routing.req(
        &routing_rx,
        RpcRequest::GetMData(MDataAddress::Unseq { name, tag }),
        &full_id_new,
    );
    match rpc_response {
        RpcResponse::GetMData(res) => {
            let unpub_mdata: MData = unwrap!(res);
            println!("{:?} :: {}", unpub_mdata.name(), unpub_mdata.tag());
            assert_eq!(*unpub_mdata.name(), name);
            assert_eq!(unpub_mdata.tag(), tag);
        }
        _ => panic!("Unexpected response"),
    }
}

// Test auth key operations with valid and invalid version bumps.
#[test]
fn auth_keys() {
    let (mut routing, routing_rx, full_id, _) = setup_with_config(Config {
        quic_p2p: None,
        dev: Some(DevConfig {
            mock_unlimited_mutations: true,
            mock_in_memory_storage: true,
            mock_vault_path: None,
        }),
    });
    let coins = unwrap!(Coins::from_str("10"));
    let owner_sk = full_id.bls_key();
    let (_, full_id_new) = create_account(&mut routing, coins, owner_sk);

    // Initially, the list of auth keys should be empty and the version should be zero.
    let mut response: RpcResponse = routing.req(
        &routing_rx,
        RpcRequest::ListAuthKeysAndVersion,
        &full_id_new,
    );

    match response {
        RpcResponse::ListAuthKeysAndVersion(res) => match res {
            Ok(keys) => {
                assert_eq!(keys.0.len(), 0);
                assert_eq!(keys.1, 0);
            }
            Err(e) => panic!("Unexpected error: {:?}", e),
        },
        _ => panic!("Unexpected response"),
    }

    let app_key = PublicKey::from(SecretKey::random().public_key());

    // Attempt to insert auth key without proper version bump fails.
    let test_ins_auth_key_req = RpcRequest::InsAuthKey {
        key: app_key,
        version: 0,
        permissions: AppPermissions {
            transfer_coins: true,
        },
    };

    response = routing.req(&routing_rx, test_ins_auth_key_req, &full_id_new);

    match response {
        RpcResponse::Mutation(Ok(())) => panic!("Unexpected Success"),
        RpcResponse::Mutation(Err(Error::InvalidSuccessor(0))) => (),
        _ => panic!("Unexpected Response"),
    }

    // Insert an auth key with proper version bump succeeds.
    let ins_auth_key_req = RpcRequest::InsAuthKey {
        key: app_key,
        version: 1,
        permissions: AppPermissions {
            transfer_coins: true,
        },
    };

    response = routing.req(&routing_rx, ins_auth_key_req, &full_id_new);

    match response {
        RpcResponse::Mutation(Ok(())) => (),
        RpcResponse::Mutation(Err(e)) => panic!("Unexpected Error : {:?}", e),
        _ => panic!("Unexpected Response"),
    }

    response = routing.req(
        &routing_rx,
        RpcRequest::ListAuthKeysAndVersion,
        &full_id_new,
    );

    match response {
        RpcResponse::ListAuthKeysAndVersion(res) => match res {
            Ok(keys) => {
                assert_eq!(unwrap!(keys.0.get(&app_key)).transfer_coins, true);
                assert_eq!(keys.1, 1);
            }
            Err(e) => panic!("Unexpected error: {:?}", e),
        },
        _ => panic!("Unexpected response"),
    }
    // Attempt to delete auth key without proper version bump fails.
    let test_del_auth_key_req = RpcRequest::DelAuthKey {
        key: app_key,
        version: 0,
    };

    response = routing.req(&routing_rx, test_del_auth_key_req, &full_id_new);

    match response {
        RpcResponse::Mutation(Ok(())) => panic!("Unexpected Success"),
        RpcResponse::Mutation(Err(Error::InvalidSuccessor(1))) => (),
        _ => panic!("Unexpected Response"),
    }

    // Attempt to delete non-existing key fails.
    let test_auth_key = PublicKey::from(SecretKey::random().public_key());

    let test1_del_auth_key_req = RpcRequest::DelAuthKey {
        key: test_auth_key,
        version: 2,
    };

    response = routing.req(&routing_rx, test1_del_auth_key_req, &full_id_new);

    match response {
        RpcResponse::Mutation(Ok(())) => panic!("Unexpected Success"),
        RpcResponse::Mutation(Err(Error::NoSuchKey)) => (),
        _ => panic!("Unexpected Response"),
    }

    // Delete auth key with proper version bump succeeds.
    let del_auth_key_req = RpcRequest::DelAuthKey {
        key: app_key,
        version: 2,
    };

    response = routing.req(&routing_rx, del_auth_key_req, &full_id_new);

    match response {
        RpcResponse::Mutation(Ok(())) => (),
        RpcResponse::Mutation(Err(e)) => panic!("Unexpected Error : {:?}", e),
        _ => panic!("Unexpected Response"),
    }

    // Retrieve the list of auth keys and version
    response = routing.req(
        &routing_rx,
        RpcRequest::ListAuthKeysAndVersion,
        &full_id_new,
    );

    match response {
        RpcResponse::ListAuthKeysAndVersion(res) => match res {
            Ok(keys) => {
                assert_eq!(keys.0.len(), 0);
                assert_eq!(keys.1, 2);
            }
            Err(e) => panic!("Unexpected error: {:?}", e),
        },
        _ => panic!("Unexpected response"),
    }
}

// Ensure Get/Mutate AuthKeys Requests and DeleteMData Requests called by AppClients fails.
#[test]
fn auth_actions_from_app() {
    // Creates an App Routing instance
    let (mut app_routing, app_routing_rx, _, app_full_id_new) = setup();

    // Creates a Client Routing instance
    let (mut routing, routing_rx, full_id, _) = setup();
    let owner_key = PublicKey::from(*full_id.public_id().bls_public_key());
    let bls_key = full_id.bls_key().public_key();
    let coins = unwrap!(Coins::from_str("10"));
    let owner_sk = full_id.bls_key();
    let (_, full_id_new) = create_account(&mut routing, coins, owner_sk);

    let name = XorName(rand::random());
    let tag = 15002;

    let mut permissions: BTreeMap<_, _> = Default::default();
    let _ = permissions.insert(
        PublicKey::Bls(bls_key),
        NewPermissionSet::new().allow(NewAction::Read),
    );

    let data =
        UnseqMutableData::new_with_data(name, tag, Default::default(), permissions, owner_key);

    let address = MDataAddress::Unseq { name, tag };

    let response: RpcResponse = routing.req(
        &routing_rx,
        RpcRequest::PutMData(MData::Unseq(data.clone())),
        &full_id_new,
    );

    match response {
        RpcResponse::Mutation(res) => unwrap!(res),
        _ => panic!("Unexpected response"),
    };

    // Assert if the inserted data is correct.
    let rpc_response: RpcResponse = routing.req(
        &routing_rx,
        RpcRequest::GetMData(MDataAddress::Unseq { name, tag }),
        &full_id_new,
    );
    match rpc_response {
        RpcResponse::GetMData(res) => {
            let unpub_mdata: MData = unwrap!(res);
            println!("{:?} :: {}", unpub_mdata.name(), unpub_mdata.tag());
            assert_eq!(*unpub_mdata.name(), name);
            assert_eq!(unpub_mdata.tag(), tag);
        }
        _ => panic!("Unexpected response"),
    }

    // Delete MData called by apps should fail
    let del_mdata_by_app = app_routing.req(
        &app_routing_rx,
        RpcRequest::DeleteMData(address),
        &app_full_id_new,
    );

    match del_mdata_by_app {
        RpcResponse::Mutation(res) => match res {
            Err(Error::AccessDenied) => (),
            Err(e) => panic!("Unexpected error {:?}", e),
            Ok(_) => panic!("Unexpected success"),
        },
        app_req => panic!("Unexpected response {:?}", app_req),
    }

    // List Auth Keys called by apps should fail
    let list_auth_keys_by_app = app_routing.req(
        &app_routing_rx,
        RpcRequest::ListAuthKeysAndVersion,
        &app_full_id_new,
    );

    match list_auth_keys_by_app {
        RpcResponse::ListAuthKeysAndVersion(res) => match res {
            Err(Error::AccessDenied) => (),
            Err(e) => panic!("Unexpected error: {:?}", e),
            Ok(_) => panic!("Unexpected success"),
        },
        _ => panic!("Unexpected response"),
    }

    // Delete Auth Keys called by apps should fail
    let delete_auth_keys_by_app = app_routing.req(
        &app_routing_rx,
        RpcRequest::DelAuthKey {
            key: PublicKey::Bls(bls_key),
            version: 1,
        },
        &app_full_id_new,
    );

    match delete_auth_keys_by_app {
        RpcResponse::Mutation(res) => match res {
            Err(Error::AccessDenied) => (),
            Err(e) => panic!("Unexpected error: {:?}", e),
            Ok(_) => panic!("Unexpected success"),
        },
        _ => panic!("Unexpected response"),
    }
}

// Exhaust the account balance and ensure that mutations fail.
#[test]
fn low_balance_check() {
    for &custom_vault in &[true, false] {
        let (mut routing, routing_rx, full_id, _) = setup_with_config(Config {
            quic_p2p: None,
            dev: Some(DevConfig {
                mock_unlimited_mutations: custom_vault,
                mock_in_memory_storage: true,
                mock_vault_path: None,
            }),
        });
        // let owner_key = PublicKey::from(*full_id.public_id();
        let owner_sk = full_id.bls_key();
        let owner_key: PublicKey = full_id.bls_key().public_key().into();
        let coins = unwrap!(Coins::from_nano(5));
        let (client_mgr, full_id_new) = create_account(&mut routing, coins, owner_sk);

        // Put MutableData so we can test getting it later.
        // Do this before exhausting the balance (below).
        let name = rand::random();
        let tag = 1000u64;

        let data = unwrap!(OldMutableData::new(
            name,
            tag,
            Default::default(),
            Default::default(),
            btree_set!(owner_key),
        ));
        let nae_mgr = Authority::NaeManager(*data.name());

        let msg_id = MessageId::new();
        unwrap!(routing.put_mdata(client_mgr, data, msg_id, owner_key));
        expect_success!(routing_rx, msg_id, Response::PutMData);

        let vec_data = unwrap!(utils::generate_random_vector(10));
        let data = PubImmutableData::new(vec_data);
        let msg_id = MessageId::new();

        // Another mutation should fail/succeed depending on config value.
        let unlimited_muts = match routing.config().dev {
            Some(dev) => dev.mock_unlimited_mutations,
            None => false,
        };

        let rpc_response = routing.req(&routing_rx, RpcRequest::GetBalance, &full_id_new);
        let balance = match rpc_response {
            RpcResponse::GetBalance(res) => unwrap!(res),
            _ => panic!("Unexpected response"),
        };

        // Exhause the account balance by transferring everyting to a new wallet
        let new_balance_owner: PublicKey = SecretKey::random().public_key().into();
        let _ = routing.req(
            &routing_rx,
            RpcRequest::CreateBalance {
                new_balance_owner,
                amount: balance,
                transaction_id: rand::random(),
            },
            &full_id_new,
        );

        if !unlimited_muts {
            assert!(!custom_vault);
            // Attempt to perform another mutation fails on low balance.
            unwrap!(routing.put_idata(client_mgr, data.clone(), msg_id));
            expect_failure!(
                routing_rx,
                msg_id,
                Response::PutIData,
                ClientError::LowBalance
            );
        } else {
            assert!(custom_vault);
            // Attempt to perform another mutation succeeds.
            unwrap!(routing.put_idata(client_mgr, data, msg_id));
            expect_success!(routing_rx, msg_id, Response::PutIData);
        }

        // Try getting MutableData (should succeed regardless of low balance)
        let msg_id = MessageId::new();
        unwrap!(routing.get_mdata(nae_mgr, name, tag, msg_id));
        let mdata = expect_success!(routing_rx, msg_id, Response::GetMData);
        assert!(mdata.serialised_size() > 0);
    }
}

// Test that using an invalid mock-vault path does not work.
#[test]
#[should_panic]
fn invalid_config_mock_vault_path() {
    use std;

    // Don't run this test when SAFE env vars are set.
    if std::env::var("SAFE_MOCK_IN_MEMORY_STORAGE").is_ok()
        || std::env::var("SAFE_MOCK_VAULT_PATH").is_ok()
    {
        // Panic so the test doesn't fail.
        // This test is run in CI with env vars both set and unset.
        panic!("This test should run without SAFE env vars set.");
    }

    // Make sure that using a non-existant mock-vault path fails.
    let (mut routing, _, full_id, _) = setup_with_config(Config {
        quic_p2p: None,
        dev: Some(DevConfig {
            mock_unlimited_mutations: false,
            mock_in_memory_storage: false,
            mock_vault_path: Some(String::from("./this_path_should_not_exist")),
        }),
    });
    let owner_key = PublicKey::from(*full_id.public_id().bls_public_key());

    // `put_mdata` should fail.
    let name = rand::random();
    let tag = 1000u64;

    let data = unwrap!(OldMutableData::new(
        name,
        tag,
        Default::default(),
        Default::default(),
        btree_set!(owner_key),
    ));
    let client_mgr = Authority::ClientManager(owner_key.into());

    let msg_id = MessageId::new();
    unwrap!(routing.put_mdata(client_mgr, data, msg_id, owner_key));
}

// Test setting a custom mock-vault path. Make sure basic operations work as expected.
#[test]
fn config_mock_vault_path() {
    use std;

    // Don't run this test when the env var is set.
    if std::env::var("SAFE_MOCK_IN_MEMORY_STORAGE").is_ok() {
        return;
    }

    // Create temporary directory.
    match std::fs::create_dir("./tmp") {
        Ok(_) => (),
        Err(ref e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
        _ => panic!("Error creating directory"),
    }

    let (mut routing, routing_rx, full_id, _) = setup_with_config(Config {
        quic_p2p: None,
        dev: Some(DevConfig {
            mock_unlimited_mutations: false,
            mock_in_memory_storage: false,
            mock_vault_path: Some(String::from("./tmp")),
        }),
    });
    let owner_key = PublicKey::from(*full_id.public_id().bls_public_key());
    let coins = unwrap!(Coins::from_str("10"));
    let owner_sk = full_id.bls_key();
    let (client_mgr, _) = create_account(&mut routing, coins, owner_sk);

    // Put MutableData. Should succeed.
    let name = rand::random();
    let tag = 1000u64;

    let data = unwrap!(OldMutableData::new(
        name,
        tag,
        Default::default(),
        Default::default(),
        btree_set!(owner_key),
    ));
    let nae_mgr = Authority::NaeManager(*data.name());

    let msg_id = MessageId::new();
    unwrap!(routing.put_mdata(client_mgr, data, msg_id, owner_key));
    expect_success!(routing_rx, msg_id, Response::PutMData);

    // Try getting MutableData back.
    let msg_id = MessageId::new();
    unwrap!(routing.get_mdata(nae_mgr, name, tag, msg_id));
    let mdata = expect_success!(routing_rx, msg_id, Response::GetMData);
    assert!(mdata.serialised_size() > 0);

    unwrap!(std::fs::remove_dir_all("./tmp"));
}

// Test routing request hooks.
#[test]
fn request_hooks() {
    let (mut routing, routing_rx, full_id, _) = setup();

    routing.set_request_hook(move |req| {
        match *req {
            Request::PutMData {
                ref data, msg_id, ..
            } if data.tag() == 10_000u64 => {
                // Send an OK response but don't put data on the mock vault
                Some(Response::PutMData {
                    res: Ok(()),
                    msg_id,
                })
            }
            Request::MutateMDataEntries { tag, msg_id, .. } if tag == 12_345u64 => {
                Some(Response::MutateMDataEntries {
                    res: Err(ClientError::from("hello world")),
                    msg_id,
                })
            }
            // Pass-through
            _ => None,
        }
    });

    // Create account
    let owner_key = PublicKey::from(*full_id.public_id().bls_public_key());
    let coins = unwrap!(Coins::from_str("10"));
    let owner_sk = full_id.bls_key();
    let (client_mgr, _) = create_account(&mut routing, coins, owner_sk);

    // Construct MutableData (but hook won't allow to store it on the network
    // if the tag is 10000)
    let name = rand::random();
    let tag = 10_000u64;

    let data = unwrap!(OldMutableData::new(
        name,
        tag,
        Default::default(),
        Default::default(),
        btree_set!(owner_key)
    ));

    let msg_id = MessageId::new();
    unwrap!(routing.put_mdata(client_mgr, data, msg_id, owner_key));
    expect_success!(routing_rx, msg_id, Response::PutMData);

    // Check that this MData is not available
    let msg_id = MessageId::new();
    unwrap!(routing.get_mdata_version(Authority::NaeManager(name), name, tag, msg_id));
    expect_failure!(
        routing_rx,
        msg_id,
        Response::GetMDataVersion,
        ClientError::NoSuchData
    );

    // Put an MData with a different tag, this should be stored now
    let name = rand::random();
    let tag = 12_345u64;

    let data = unwrap!(OldMutableData::new(
        name,
        tag,
        Default::default(),
        Default::default(),
        btree_set!(owner_key)
    ));

    let msg_id = MessageId::new();
    unwrap!(routing.put_mdata(client_mgr, data, msg_id, owner_key));
    expect_success!(routing_rx, msg_id, Response::PutMData);

    // Try adding some entries - this should fail, as the hook function
    // won't allow to put entries to MD with a tag 12345
    let key0 = b"key0";
    let value0_v0 = unwrap!(utils::generate_random_vector(10));

    let actions = btree_map![
        key0.to_vec() => EntryAction::Ins(Value {
            content: value0_v0.clone(),
            entry_version: 0,
        })
    ];

    let msg_id = MessageId::new();
    unwrap!(routing.mutate_mdata_entries(
        client_mgr,
        name,
        tag,
        actions.clone(),
        msg_id,
        owner_key
    ));
    expect_failure!(
        routing_rx,
        msg_id,
        Response::MutateMDataEntries,
        ClientError::NetworkOther(..)
    );

    // Now remove the hook function and try again - this should succeed now
    routing.remove_request_hook();

    unwrap!(routing.mutate_mdata_entries(client_mgr, name, tag, actions, msg_id, owner_key));
    expect_success!(routing_rx, msg_id, Response::MutateMDataEntries);
}
*/

// Setup a connection manager for a new account with a shared, global vault.
fn setup() -> (
    ConnectionManager,
    UnboundedReceiver<NetworkEvent>,
    SafeKey,
    PublicKey,
) {
    let (mut conn_manager, conn_manager_rx, client_id) = setup_impl();

    let coins = unwrap!(Coins::from_str("10"));
    let client_safe_key = register_client(&mut conn_manager, coins, client_id);
    let owner_key = client_safe_key.public_key();

    (conn_manager, conn_manager_rx, client_safe_key, owner_key)
}

// Setup routing with a new, non-shared vault.
// fn setup_with_config(config: Config) -> (Routing, Receiver<Event>, FullId, SafeKey) {
//     let (mut routing, routing_rx, full_id, full_id_new) = setup_impl();

//     routing.set_vault(&Arc::new(Mutex::new(Vault::new(config))));

//     (routing, routing_rx, full_id, full_id_new)
// }

fn setup_impl() -> (
    ConnectionManager,
    UnboundedReceiver<NetworkEvent>,
    ClientFullId,
) {
    let client_id = gen_client_id();
    let (conn_manager_tx, conn_manager_rx) = mpsc::unbounded();
    let connection_manager = unwrap!(ConnectionManager::new(Default::default(), &conn_manager_tx));

    (connection_manager, conn_manager_rx, client_id)
}

// Create a balance for an account.
// Return the safe key which will be used to sign the requests that follow.
fn register_client(
    conn_manager: &mut ConnectionManager,
    coins: Coins,
    client_id: ClientFullId,
) -> SafeKey {
    let client_public_key = client_id.public_id().public_key();
    conn_manager.create_balance(*client_public_key, coins);

    SafeKey::client(client_id)
}

// Register a new app for an account with the given permissions.
// Return the app's safe key and it's connection manager along with the reciever
// for network events.
fn register_new_app(
    conn_manager: &mut ConnectionManager,
    client_safe_key: &SafeKey,
    permissions: AppPermissions,
) -> (SafeKey, ConnectionManager, UnboundedReceiver<NetworkEvent>) {
    let client_id = unwrap!(client_safe_key.public_id().client_public_id()).clone();
    let app_full_id = gen_app_id(client_id);
    let response = process_request(
        conn_manager,
        client_safe_key,
        Request::ListAuthKeysAndVersion,
    );
    let (_, version): (_, u64) = unwrap!(response.try_into());

    send_req_expect_ok!(
        conn_manager,
        client_safe_key,
        Request::InsAuthKey {
            key: *app_full_id.public_id().public_key(),
            version: version + 1,
            permissions
        },
        ()
    );
    let (conn_manager_tx, conn_manager_rx) = mpsc::unbounded();
    let connection_manager = unwrap!(ConnectionManager::new(Default::default(), &conn_manager_tx));
    (
        SafeKey::app(app_full_id),
        connection_manager,
        conn_manager_rx,
    )
}
