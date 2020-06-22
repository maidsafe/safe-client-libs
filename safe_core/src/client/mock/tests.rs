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
use crate::{utils, NetworkEvent, QuicP2pConfig};

use super::connection_manager::ConnectionManager;
use crate::btree_map;
use bincode::serialize;
use futures::channel::mpsc::{self, UnboundedReceiver};
use futures::Future;
use rand::thread_rng;
use safe_nd::{
    AppFullId, AppPermissions, ClientFullId, ClientRequest, Coins, CoinsRequest, Error, IData,
    IDataRequest, LoginPacketRequest, MData, MDataAction, MDataAddress, MDataEntries,
    MDataEntryActions, MDataPermissionSet, MDataRequest, MDataSeqEntryAction, MDataSeqEntryActions,
    MDataSeqValue, MDataValue, MDataValues, Message, MessageId, PubImmutableData, PublicId,
    PublicKey, Request, RequestType, Response, SeqMutableData, UnpubImmutableData,
    UnseqMutableData, XorName,
};
use std::collections::{BTreeMap, BTreeSet};
use std::convert::TryInto;
use std::str::FromStr;
use std::sync::mpsc as std_mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use threshold_crypto::SecretKey;
use unwrap::unwrap;

// Helper macro to fetch the response for a request and
// assert that the expected error is returned.
macro_rules! send_req_expect_failure {
    ($cm:expr, $sender:expr, $req:expr, $err:path) => {
        let expected_response = $req.error_response($err);
        let response = process_request($cm, $sender, $req).await;
        assert_eq!(response, expected_response);
    };
}

macro_rules! send_req_expect_ok {
    ($cm:expr, $sender:expr, $req:expr, $res:expr) => {
        let response = process_request($cm, $sender, $req).await;
        assert_eq!($res, unwrap!(response.try_into()));
    };
}

async fn process_request(
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
    unwrap!(connection_manager.send(&sender.public_id(), &message).await)
}

// Test the basics idata operations.
#[tokio::test]
async fn immutable_data_basics() {
    let (mut connection_manager, _, client_safe_key, _) = setup(None).await;

    // Construct PubImmutableData
    let orig_data: IData =
        PubImmutableData::new(unwrap!(utils::generate_random_vector(100))).into();

    // IData(IDataRequest::Get should fai)l
    let get_request = Request::IData(IDataRequest::Get(*orig_data.address()));
    send_req_expect_failure!(
        &mut connection_manager,
        &client_safe_key,
        get_request.clone(),
        Error::NoSuchData
    );

    // First IData(IDataRequest::Put should succee)d
    let put_request = Request::IData(IDataRequest::Put(orig_data.clone()));
    send_req_expect_ok!(
        &mut connection_manager,
        &client_safe_key,
        put_request.clone(),
        ()
    );

    // Now IData(IDataRequest::Get should pas)s
    send_req_expect_ok!(
        &mut connection_manager,
        &client_safe_key,
        get_request.clone(),
        orig_data
    );

    // Initial balance is 10 coins
    let balance = unwrap!(Coins::from_str("10"));
    let balance = unwrap!(balance.checked_sub(COST_OF_PUT));
    send_req_expect_ok!(
        &mut connection_manager,
        &client_safe_key,
        Request::Coins(CoinsRequest::GetBalance),
        balance
    );

    // Subsequent IData(IDataRequest::Put for same data should succeed - De-duplicatio)n
    send_req_expect_ok!(&mut connection_manager, &client_safe_key, put_request, ());

    // IData(IDataRequest::Get should succee)d
    send_req_expect_ok!(
        &mut connection_manager,
        &client_safe_key,
        get_request,
        orig_data
    );

    // The balance should be deducted twice
    let balance = unwrap!(balance.checked_sub(COST_OF_PUT));
    send_req_expect_ok!(
        &mut connection_manager,
        &client_safe_key,
        Request::Coins(CoinsRequest::GetBalance),
        balance
    );
}

// Test the basic mdata operations.
#[tokio::test]
async fn mutable_data_basics() {
    let (mut connection_manager, _, client_safe_key, owner_key) = setup(None).await;

    // Construct MutableData
    let name = rand::random();
    let tag = 1000u64;

    let data = SeqMutableData::new(name, tag, owner_key);
    let data1_address = *data.address();

    // Operations on non-existing MutableData should fail.
    send_req_expect_failure!(
        &mut connection_manager,
        &client_safe_key,
        Request::MData(MDataRequest::GetVersion(data1_address)),
        Error::NoSuchData
    );

    send_req_expect_failure!(
        &mut connection_manager,
        &client_safe_key,
        Request::MData(MDataRequest::ListEntries(data1_address)),
        Error::NoSuchData
    );

    // MData(MDataRequest::Put
    send_req_expect_ok!(
        &mut connection_manager,
        &client_safe_key,
        Request::MData(MDataRequest::Put(data.into())),
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
        Request::MData(MDataRequest::Put(data2.clone())),
        ()
    );

    // MData(MDataRequest::GetVersion should respond with )0
    let response = process_request(
        &mut connection_manager,
        &client_safe_key,
        Request::MData(MDataRequest::GetVersion(data2_address)),
    )
    .await;
    assert_eq!(response, Response::GetMDataVersion(Ok(0)));

    // MData(MDataRequest::Get should return the entire MutableData objec)t
    send_req_expect_ok!(
        &mut connection_manager,
        &client_safe_key,
        Request::MData(MDataRequest::Get(data2_address)),
        data2
    );

    // MData(MDataRequest::ListEntries, ListMDataKeys and ListMDataValues should all respon)d
    // with empty collections.
    send_req_expect_ok!(
        &mut connection_manager,
        &client_safe_key,
        Request::MData(MDataRequest::ListEntries(data2_address)),
        MDataEntries::from(BTreeMap::<_, MDataSeqValue>::new())
    );

    send_req_expect_ok!(
        &mut connection_manager,
        &client_safe_key,
        Request::MData(MDataRequest::ListKeys(data2_address)),
        BTreeSet::new()
    );

    send_req_expect_ok!(
        &mut connection_manager,
        &client_safe_key,
        Request::MData(MDataRequest::ListValues(data2_address)),
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
        Request::MData(MDataRequest::MutateEntries {
            address: data2_address,
            actions: actions.into()
        }),
        ()
    );

    let response = process_request(
        &mut connection_manager,
        &client_safe_key,
        Request::MData(MDataRequest::ListEntries(data2_address)),
    )
    .await;
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
        Request::MData(MDataRequest::ListEntries(data1_address)),
        MDataEntries::from(BTreeMap::<_, MDataSeqValue>::new())
    );

    // ListMDataKeys
    let response = process_request(
        &mut connection_manager,
        &client_safe_key,
        Request::MData(MDataRequest::ListKeys(data2_address)),
    )
    .await;
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
        Request::MData(MDataRequest::ListValues(data2_address)),
    )
    .await;
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
        Request::MData(MDataRequest::GetValue {
            address: data2_address,
            key: key0.to_vec()
        }),
        MDataValue::Seq(MDataSeqValue {
            data: value0_v0,
            version: 0,
        })
    );

    // MData(MDataRequest::GetValue with non-existing ke)y
    let key2 = b"key2";
    send_req_expect_failure!(
        &mut connection_manager,
        &client_safe_key,
        Request::MData(MDataRequest::GetValue {
            address: data2_address,
            key: key2.to_vec()
        }),
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
        Request::MData(MDataRequest::MutateEntries {
            address: data2_address,
            actions: actions.into()
        }),
        ()
    );

    let response = process_request(
        &mut connection_manager,
        &client_safe_key,
        Request::MData(MDataRequest::ListEntries(data2_address)),
    )
    .await;
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
#[tokio::test]
async fn mutable_data_reclaim() {
    let (mut connection_manager, _, client_safe_key, owner_key) = setup(None).await;

    // Construct MutableData
    let name = rand::random();
    let tag = 1000u64;

    let data = SeqMutableData::new(name, tag, owner_key);
    let address: MDataAddress = *data.address();

    // MData(MDataRequest::Put
    send_req_expect_ok!(
        &mut connection_manager,
        &client_safe_key,
        Request::MData(MDataRequest::Put(data.into())),
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
        Request::MData(MDataRequest::MutateEntries {
            address,
            actions: actions.into()
        }),
        ()
    );

    let actions: MDataSeqEntryActions = btree_map![
        key0.to_vec() => MDataSeqEntryAction::Update(MDataSeqValue {
            data: value0,
            version: 1,
        })
    ]
    .into();

    send_req_expect_ok!(
        &mut connection_manager,
        &client_safe_key,
        Request::MData(MDataRequest::MutateEntries {
            address,
            actions: actions.into()
        }),
        ()
    );

    // MData(MDataRequest::GetVersion should respond with 0 as the mdata itself hasn't changed).
    let response = process_request(
        &mut connection_manager,
        &client_safe_key,
        Request::MData(MDataRequest::GetVersion(address)),
    )
    .await;
    assert_eq!(response, Response::GetMDataVersion(Ok(0)));

    // Try deleting the entry with an invalid entry_version and make sure it fails
    let actions: MDataSeqEntryActions = btree_map![
        key0.to_vec() => MDataSeqEntryAction::Del(3),
    ]
    .into();

    let response = process_request(
        &mut connection_manager,
        &client_safe_key,
        Request::MData(MDataRequest::MutateEntries {
            address,
            actions: actions.into(),
        }),
    )
    .await;
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
        Request::MData(MDataRequest::MutateEntries {
            address,
            actions: actions.into()
        }),
        ()
    );
}

// Test valid and invalid mdata entry versioning.
#[tokio::test]
async fn mutable_data_entry_versioning() {
    let (mut connection_manager, _, client_safe_key, owner_key) = setup(None).await;

    // Construct MutableData
    let name = rand::random();
    let tag = 1000u64;

    let data = SeqMutableData::new(name, tag, owner_key);
    let address = *data.address();

    // MData(MDataRequest::Put
    send_req_expect_ok!(
        &mut connection_manager,
        &client_safe_key,
        Request::MData(MDataRequest::Put(data.into())),
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
        Request::MData(MDataRequest::MutateEntries {
            address,
            actions: actions.into(),
        }),
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
        Request::MData(MDataRequest::MutateEntries {
            address,
            actions: actions.into(),
        }),
    )
    .await;
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
        Request::MData(MDataRequest::MutateEntries {
            address,
            actions: actions.into(),
        }),
    )
    .await;
    match response {
        Response::Mutation(Err(Error::InvalidEntryActions(_))) => (),
        Response::Mutation(Ok(())) => panic!("Unexpected success"),
        res => panic!("Unexpected response: {:?}", res),
    }

    // Update with correct version bump succeeds.
    let actions: MDataSeqEntryActions = btree_map![
        key.to_vec() => MDataSeqEntryAction::Update(MDataSeqValue {
            data: value_v1,
            version: 1,
        })
    ]
    .into();

    send_req_expect_ok!(
        &mut connection_manager,
        &client_safe_key,
        Request::MData(MDataRequest::MutateEntries {
            address,
            actions: actions.into(),
        }),
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
        Request::MData(MDataRequest::MutateEntries {
            address,
            actions: actions.into(),
        }),
    )
    .await;
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
        Request::MData(MDataRequest::MutateEntries {
            address,
            actions: actions.into(),
        }),
        ()
    );
}

// Test various operations with and without proper permissions.
#[tokio::test]
async fn mutable_data_permissions() {
    let (mut connection_manager, _, client_safe_key, owner_key) = setup(None).await;

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
        Request::MData(MDataRequest::Put(data.into())),
        ()
    );

    // ListMDataPermissions responds with empty collection.
    let response = process_request(
        &mut connection_manager,
        &client_safe_key,
        Request::MData(MDataRequest::ListPermissions(address)),
    )
    .await;
    let permissions: BTreeMap<PublicKey, MDataPermissionSet> = unwrap!(response.try_into());
    assert!(permissions.is_empty());

    // Owner can do anything by default.
    let value0_v1 = unwrap!(utils::generate_random_vector(10));
    let actions = MDataSeqEntryActions::new().update(key0.to_vec(), value0_v1, 1);
    send_req_expect_ok!(
        &mut connection_manager,
        &client_safe_key,
        Request::MData(MDataRequest::MutateEntries {
            address,
            actions: actions.into()
        }),
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
    )
    .await;

    // App can't mutate any entry, by default.
    let value0_v2 = unwrap!(utils::generate_random_vector(10));
    let actions = MDataSeqEntryActions::new().update(key0.to_vec(), value0_v2.clone(), 2);
    let mutation_request = Request::MData(MDataRequest::MutateEntries {
        address,
        actions: actions.into(),
    });
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
    let update_perms_req = Request::MData(MDataRequest::SetUserPermissions {
        address,
        user: app_safe_key.public_key(),
        permissions,
        version: 1,
    });
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
        Request::MData(MDataRequest::GetVersion(address)),
    )
    .await;
    assert_eq!(response, Response::GetMDataVersion(Ok(1)));

    // App can't insert entries.
    let key1 = b"key1";
    let value1_v0 = unwrap!(utils::generate_random_vector(10));

    let actions: MDataSeqEntryActions = btree_map![
    key1.to_vec() => MDataSeqEntryAction::Ins(MDataSeqValue {
        data: value1_v0,
        version: 0,
    })
    ]
    .into();

    let insertion_request = Request::MData(MDataRequest::MutateEntries {
        address,
        actions: actions.into(),
    });
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
        Request::MData(MDataRequest::MutateEntries {
            address,
            actions: actions.into(),
        }),
        ()
    );

    // Attempt to modify permissions without proper version bump fails
    let permissions = MDataPermissionSet::new()
        .allow(MDataAction::Read)
        .allow(MDataAction::Insert)
        .allow(MDataAction::Update);
    let invalid_update_perms_req = Request::MData(MDataRequest::SetUserPermissions {
        address,
        user: app_safe_key.public_key(),
        permissions: permissions.clone(),
        version: 1,
    });
    let error = Error::InvalidSuccessor(1);
    send_req_expect_failure!(
        &mut connection_manager,
        &client_safe_key,
        invalid_update_perms_req,
        error
    );

    // Modifying permissions with version bump succeeds.
    let valid_update_perms_req = Request::MData(MDataRequest::SetUserPermissions {
        address,
        user: app_safe_key.public_key(),
        permissions,
        version: 2,
    });
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
        Request::MData(MDataRequest::DelUserPermissions {
            address,
            user: app_safe_key.public_key(),
            version: 3
        }),
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
        Request::MData(MDataRequest::SetUserPermissions {
            address,
            user: app_safe_key.public_key(),
            permissions,
            version: 4
        }),
        ()
    );

    // The app still can't mutate the entries.
    send_req_expect_failure!(
        &mut connection_manager2,
        &app_safe_key,
        mutation_request,
        Error::AccessDenied
    );

    // App can modify its own permission.
    let permissions = MDataPermissionSet::new().allow(MDataAction::Update);
    send_req_expect_ok!(
        &mut connection_manager2,
        &app_safe_key,
        Request::MData(MDataRequest::SetUserPermissions {
            address,
            user: app_safe_key.public_key(),
            permissions,
            version: 5
        }),
        ()
    );

    // The app can now mutate the entries.
    let value1_v1 = unwrap!(utils::generate_random_vector(10));
    let actions = MDataSeqEntryActions::new().update(key1.to_vec(), value1_v1, 1);
    send_req_expect_ok!(
        &mut connection_manager2,
        &app_safe_key,
        Request::MData(MDataRequest::MutateEntries {
            address,
            actions: actions.into()
        }),
        ()
    );
}

// Test mdata operations with valid and invalid owner.
#[tokio::test]
async fn mutable_data_ownership() {
    // Create owner's connection manager
    let (mut connection_manager, _, client_safe_key, owner_key) = setup(None).await;

    // Create app's connection_manager
    let (app_safe_key, mut connection_manager2, _) = register_new_app(
        &mut connection_manager,
        &client_safe_key,
        AppPermissions {
            get_balance: true,
            transfer_coins: true,
            perform_mutations: true,
        },
    )
    .await;

    // Attempt to put MutableData using the app sign key as owner key should fail.
    let name = rand::random();
    let tag = 1000u64;

    send_req_expect_failure!(
        &mut connection_manager2,
        &app_safe_key,
        Request::MData(MDataRequest::Put(
            SeqMutableData::new(name, tag, app_safe_key.public_key()).into()
        )),
        Error::InvalidOwners
    );

    // Putting it with correct owner succeeds.
    let data: MData = SeqMutableData::new(name, tag, owner_key).into();

    send_req_expect_ok!(
        &mut connection_manager,
        &app_safe_key,
        Request::MData(MDataRequest::Put(data)),
        ()
    );
}

#[tokio::test]
async fn pub_idata_rpc() {
    let (mut connection_manager, _, client_safe_key, _) = setup(None).await;
    let (mut connection_manager2, _, client2_safe_key, _) = setup(None).await;

    // Construct PubImmutableData
    let orig_data: IData =
        PubImmutableData::new(unwrap!(utils::generate_random_vector(100))).into();

    let get_request = Request::IData(IDataRequest::Get(*orig_data.address()));

    // Put pub idata as an owner. Should succeed.
    {
        let put_request = Request::IData(IDataRequest::Put(orig_data.clone()));
        send_req_expect_ok!(&mut connection_manager, &client_safe_key, put_request, ());
    }

    // Get pub idata. Should succeed.
    {
        send_req_expect_ok!(
            &mut connection_manager,
            &client_safe_key,
            get_request.clone(),
            orig_data.clone()
        );
    }

    let app_perms = AppPermissions {
        transfer_coins: true,
        get_balance: true,
        perform_mutations: true,
    };

    let (app_key, mut app_conn_manager, _) =
        register_new_app(&mut connection_manager2, &client2_safe_key, app_perms).await;

    // Get pub idata while not being an owner. Should succeed.
    {
        send_req_expect_ok!(&mut app_conn_manager, &app_key, get_request, orig_data);
    }
}

#[tokio::test]
async fn unpub_idata_rpc() {
    let (mut connection_manager, _, client_safe_key, _) = setup(None).await;

    let value = unwrap!(utils::generate_random_vector::<u8>(10));
    let data: IData = UnpubImmutableData::new(value, client_safe_key.public_key()).into();
    let address = *data.address();

    // Construct put request.
    {
        let put_request = Request::IData(IDataRequest::Put(data.clone()));
        send_req_expect_ok!(&mut connection_manager, &client_safe_key, put_request, ());
    }

    // Construct get request.
    let get_request = Request::IData(IDataRequest::Get(address));
    send_req_expect_ok!(
        &mut connection_manager,
        &client_safe_key,
        get_request.clone(),
        data
    );

    let app_perms = AppPermissions {
        transfer_coins: true,
        get_balance: true,
        perform_mutations: true,
    };

    let (mut conn_manager2, _, client2_safe_key, _) = setup(None).await;
    let (app_key, mut app_conn_manager, _) =
        register_new_app(&mut conn_manager2, &client2_safe_key, app_perms).await;

    // Try to get unpub idata while not being an owner. Should fail.
    send_req_expect_failure!(
        &mut app_conn_manager,
        &app_key,
        get_request,
        Error::AccessDenied
    );

    let del_request = Request::IData(IDataRequest::DeleteUnpub(address));
    // Try to delete unpub idata while not being an owner. Should fail.
    send_req_expect_failure!(
        &mut app_conn_manager,
        &app_key,
        del_request,
        Error::AccessDenied
    );
}

#[tokio::test]
async fn unpub_md() {
    let (mut connection_manager, _, client_safe_key, _) = setup(None).await;

    let name = XorName(rand::random());
    let tag = 15001;

    let data: MData = UnseqMutableData::new(name, tag, client_safe_key.public_key()).into();

    // Put Unseq MData as owner - Should pass.
    send_req_expect_ok!(
        &mut connection_manager,
        &client_safe_key,
        Request::MData(MDataRequest::Put(data.clone())),
        ()
    );

    // Get Unseq MData as owner - Should pass.
    send_req_expect_ok!(
        &mut connection_manager,
        &client_safe_key,
        Request::MData(MDataRequest::Get(*data.address())),
        data
    );
}

// Test auth key operations with valid and invalid version bumps.
#[tokio::test]
async fn auth_keys() {
    let (mut connection_manager, _, client_safe_key, _) = setup(None).await;

    // Initially, the list of auth keys should be empty and the version should be zero.
    let mut response = process_request(
        &mut connection_manager,
        &client_safe_key,
        Request::Client(ClientRequest::ListAuthKeysAndVersion),
    )
    .await;
    let (keys, version): (BTreeMap<_, _>, u64) = unwrap!(response.try_into());
    assert_eq!(keys.len(), 0);
    assert_eq!(version, 0);

    let app_key = PublicKey::from(SecretKey::random().public_key());

    // Attempt to insert auth key without proper version bump fails.
    let test_ins_auth_key_req = Request::Client(ClientRequest::InsAuthKey {
        key: app_key,
        version: 0,
        permissions: AppPermissions {
            transfer_coins: true,
            get_balance: true,
            perform_mutations: true,
        },
    });

    let error = Error::InvalidSuccessor(0);

    send_req_expect_failure!(
        &mut connection_manager,
        &client_safe_key,
        test_ins_auth_key_req,
        error
    );

    // Insert an auth key with proper version bump succeeds.
    let ins_auth_key_req = Request::Client(ClientRequest::InsAuthKey {
        key: app_key,
        version: 1,
        permissions: AppPermissions {
            transfer_coins: true,
            get_balance: true,
            perform_mutations: true,
        },
    });

    send_req_expect_ok!(
        &mut connection_manager,
        &client_safe_key,
        ins_auth_key_req,
        ()
    );

    response = process_request(
        &mut connection_manager,
        &client_safe_key,
        Request::Client(ClientRequest::ListAuthKeysAndVersion),
    )
    .await;

    match response {
        Response::ListAuthKeysAndVersion(res) => match res {
            Ok(keys) => {
                assert_eq!(unwrap!(keys.0.get(&app_key)).transfer_coins, true);
                assert_eq!(unwrap!(keys.0.get(&app_key)).get_balance, true);
                assert_eq!(unwrap!(keys.0.get(&app_key)).perform_mutations, true);
                assert_eq!(keys.1, 1);
            }
            Err(e) => panic!("Unexpected error: {:?}", e),
        },
        res => panic!("Unexpected Response {:?}", res),
    }

    // Attempt to delete auth key without proper version bump fails.
    let test_del_auth_key_req = Request::Client(ClientRequest::DelAuthKey {
        key: app_key,
        version: 0,
    });

    let error = Error::InvalidSuccessor(1);

    send_req_expect_failure!(
        &mut connection_manager,
        &client_safe_key,
        test_del_auth_key_req,
        error
    );

    // Attempt to delete non-existing key fails.
    let test_auth_key = PublicKey::from(SecretKey::random().public_key());

    let test1_del_auth_key_req = Request::Client(ClientRequest::DelAuthKey {
        key: test_auth_key,
        version: 2,
    });

    send_req_expect_failure!(
        &mut connection_manager,
        &client_safe_key,
        test1_del_auth_key_req,
        Error::NoSuchKey
    );

    // Delete auth key with proper version bump succeeds.
    let del_auth_key_req = Request::Client(ClientRequest::DelAuthKey {
        key: app_key,
        version: 2,
    });

    send_req_expect_ok!(
        &mut connection_manager,
        &client_safe_key,
        del_auth_key_req,
        ()
    );

    // Retrieve the list of auth keys and version
    response = process_request(
        &mut connection_manager,
        &client_safe_key,
        Request::Client(ClientRequest::ListAuthKeysAndVersion),
    )
    .await;

    match response {
        Response::ListAuthKeysAndVersion(res) => match res {
            Ok(keys) => {
                assert_eq!(keys.0.len(), 0);
                assert_eq!(keys.1, 2);
            }
            Err(e) => panic!("Unexpected error: {:?}", e),
        },
        res => panic!("Unexpected Response {:?}", res),
    }
}

// Ensure Get/Mutate AuthKeys Requests and DeleteMData Requests called by AppClients fails.
#[tokio::test]
async fn auth_actions_from_app() {
    let (mut connection_manager, _, client_safe_key, owner_key) = setup(None).await;

    let app_perms = AppPermissions {
        transfer_coins: true,
        get_balance: true,
        perform_mutations: true,
    };

    // Creates an App instance
    let (app_key, mut app_conn_manager, _) =
        register_new_app(&mut connection_manager, &client_safe_key, app_perms).await;

    let name = XorName(rand::random());
    let tag = 15002;

    let mut permissions: BTreeMap<_, _> = Default::default();
    let _ = permissions.insert(
        app_key.public_key(),
        MDataPermissionSet::new().allow(MDataAction::Read),
    );

    let data: MData =
        UnseqMutableData::new_with_data(name, tag, Default::default(), permissions, owner_key)
            .into();

    let address = *data.address();

    // Upload MData for testing
    send_req_expect_ok!(
        &mut connection_manager,
        &client_safe_key,
        Request::MData(MDataRequest::Put(data.clone())),
        ()
    );

    // Assert if the inserted data is correct.
    send_req_expect_ok!(
        &mut connection_manager,
        &client_safe_key,
        Request::MData(MDataRequest::Get(address)),
        data
    );

    // Delete MData called by apps should fail
    send_req_expect_failure!(
        &mut app_conn_manager,
        &app_key,
        Request::MData(MDataRequest::Delete(address)),
        Error::AccessDenied
    );

    // List Auth Keys called by apps should fail
    send_req_expect_failure!(
        &mut app_conn_manager,
        &app_key,
        Request::Client(ClientRequest::ListAuthKeysAndVersion),
        Error::AccessDenied
    );

    // Delete Auth Keys called by apps should fail
    send_req_expect_failure!(
        &mut app_conn_manager,
        &app_key,
        Request::Client(ClientRequest::DelAuthKey {
            key: app_key.public_key(),
            version: 1,
        }),
        Error::AccessDenied
    );
}

// Exhaust the account balance and ensure that mutations fail.
#[tokio::test]
async fn low_balance_check() {
    for unlimited in &[true, false] {
        let (mut connection_manager, _, client_safe_key, owner_key) = setup(Some(Config {
            quic_p2p: QuicP2pConfig::default(),
            dev: Some(DevConfig {
                mock_unlimited_coins: *unlimited,
                mock_in_memory_storage: false,
                mock_vault_path: None,
            }),
        }))
        .await;

        let name: XorName = rand::random();
        let tag = 1000u64;

        let data: MData = UnseqMutableData::new(name, tag, owner_key).into();

        // Put MutableData so we can test getting it later.
        // Do this before exhausting the balance (below).
        send_req_expect_ok!(
            &mut connection_manager,
            &client_safe_key,
            Request::MData(MDataRequest::Put(data.clone())),
            ()
        );

        let vec_data = unwrap!(utils::generate_random_vector(10));
        let idata: IData = PubImmutableData::new(vec_data).into();

        let rpc_response = process_request(
            &mut connection_manager,
            &client_safe_key,
            Request::Coins(CoinsRequest::GetBalance),
        )
        .await;
        let balance: Coins = match rpc_response {
            Response::GetBalance(res) => unwrap!(res),
            _ => panic!("Unexpected response"),
        };

        // Exhaust the account balance by transferring everything to a new wallet
        let new_balance_owner: PublicKey = SecretKey::random().public_key().into();
        let response = process_request(
            &mut connection_manager,
            &client_safe_key,
            Request::Coins(CoinsRequest::CreateBalance {
                new_balance_owner,
                amount: unwrap!(balance.checked_sub(COST_OF_PUT)),
                transaction_id: rand::random(),
            }),
        )
        .await;

        match response {
            Response::Transaction(Ok(_)) => (),
            x => panic!("Unexpected Error {:?}", x),
        }

        let response = process_request(
            &mut connection_manager,
            &client_safe_key,
            Request::IData(IDataRequest::Put(idata.clone())),
        )
        .await;
        match response {
            Response::Mutation(res) => assert_eq!(*unlimited, res.is_ok()), // Should succeed if unlimited is true
            res => panic!("Unexpected response {:?}", res),
        }

        // Try getting MutableData (should succeed regardless of low balance)
        send_req_expect_ok!(
            &mut connection_manager,
            &client_safe_key,
            Request::MData(MDataRequest::Get(*data.address())),
            data
        );
    }
}

// Test that using an invalid mock-vault path does not work.
#[tokio::test]
#[should_panic]
async fn invalid_config_mock_vault_path() {
    // Don't run this test when SAFE env vars are set.
    if std::env::var("SAFE_MOCK_IN_MEMORY_STORAGE").is_ok()
        || std::env::var("SAFE_MOCK_VAULT_PATH").is_ok()
    {
        // Panic so the test doesn't fail.
        // This test is run in CI with env vars both set and unset.
        panic!("This test should run without SAFE env vars set.");
    }

    // Make sure that using a non-existant mock-vault path fails.
    let (mut _conn_manager, _, _client_safe_key, _owner_key) = setup(Some(Config {
        quic_p2p: QuicP2pConfig::default(),
        dev: Some(DevConfig {
            mock_unlimited_coins: false,
            mock_in_memory_storage: false,
            mock_vault_path: Some(String::from("./this_path_should_not_exist")),
        }),
    }))
    .await;
}

// Test setting a custom mock-vault path. Make sure basic operations work as expected.
#[tokio::test]
async fn config_mock_vault_path() {
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

    let (mut conn_manager, _, client_safe_key, owner_key) = setup(Some(Config {
        quic_p2p: QuicP2pConfig::default(),
        dev: Some(DevConfig {
            mock_unlimited_coins: false,
            mock_in_memory_storage: false,
            mock_vault_path: Some(String::from("./tmp")),
        }),
    }))
    .await;
    // Put MutableData. Should succeed.
    let name = rand::random();
    let tag = 1000u64;

    let data: MData = UnseqMutableData::new(name, tag, owner_key).into();

    send_req_expect_ok!(
        &mut conn_manager,
        &client_safe_key,
        Request::MData(MDataRequest::Put(data.clone())),
        ()
    );

    // Try getting MutableData back.
    send_req_expect_ok!(
        &mut conn_manager,
        &client_safe_key,
        Request::MData(MDataRequest::Get(*data.address())),
        data
    );

    unwrap!(std::fs::remove_dir_all("./tmp"));
}

// Test routing request hooks.
#[tokio::test]
async fn request_hooks() {
    let (mut conn_manager, _, client_safe_key, owner_key) = setup(None).await;
    let custom_error: Error = Error::NetworkOther("hello world".to_string());
    let expected_error = custom_error.clone();
    conn_manager.set_request_hook(move |req| {
        match *req {
            Request::MData(MDataRequest::Put(ref data)) if data.tag() == 10_000u64 => {
                // Send an OK response but don't put data on the mock vault
                Some(Response::Mutation(Ok(())))
            }
            Request::MData(MDataRequest::MutateEntries { address, .. })
                if address.tag() == 12_345u64 =>
            {
                Some(Response::Mutation(Err(custom_error.clone())))
            }
            // Pass-throug)h
            _ => None,
        }
    });

    // Construct MutableData (but hook won't allow to store it on the network
    // if the tag is 10000)
    let name = rand::random();
    let tag = 10_000u64;

    let data = SeqMutableData::new(name, tag, owner_key);

    send_req_expect_ok!(
        &mut conn_manager,
        &client_safe_key,
        Request::MData(MDataRequest::Put(data.clone().into())),
        ()
    );

    // Check that this MData is not available
    send_req_expect_failure!(
        &mut conn_manager,
        &client_safe_key,
        Request::MData(MDataRequest::GetVersion(*data.address())),
        Error::NoSuchData
    );

    // Put an MData with a different tag, this should be stored now
    let name2 = rand::random();
    let tag2 = 12_345u64;

    let data2 = SeqMutableData::new(name2, tag2, owner_key);

    send_req_expect_ok!(
        &mut conn_manager,
        &client_safe_key,
        Request::MData(MDataRequest::Put(data2.clone().into())),
        ()
    );

    // Try adding some entries - this should fail, as the hook function
    // won't allow to put entries to MD with a tag 12345
    let key0 = b"key0";
    let value0_v0 = unwrap!(utils::generate_random_vector(10));

    let mut seq_actions = MDataSeqEntryActions::new();
    seq_actions.add_action(
        key0.to_vec(),
        MDataSeqEntryAction::Ins(MDataSeqValue {
            data: value0_v0,
            version: 0,
        }),
    );

    let actions: MDataEntryActions = seq_actions.into();

    send_req_expect_failure!(
        &mut conn_manager,
        &client_safe_key,
        Request::MData(MDataRequest::MutateEntries {
            address: *data2.address(),
            actions: actions.clone(),
        }),
        expected_error
    );

    // Now remove the hook function and try again - this should succeed now
    conn_manager.remove_request_hook();

    send_req_expect_ok!(
        &mut conn_manager,
        &client_safe_key,
        Request::MData(MDataRequest::MutateEntries {
            address: *data2.address(),
            actions,
        }),
        ()
    );
}

// Setup a connection manager for a new account with a shared, global vault or with a
// new, non-shared vault by providing a config.
async fn setup(
    vault_config: Option<Config>,
) -> (
    ConnectionManager,
    UnboundedReceiver<NetworkEvent>,
    SafeKey,
    PublicKey,
) {
    let client_id = gen_client_id();
    let (conn_manager_tx, conn_manager_rx) = mpsc::unbounded();
    let mut conn_manager = if let Some(given_config) = vault_config {
        unwrap!(ConnectionManager::new_with_vault(
            given_config,
            &conn_manager_tx
        ))
    } else {
        unwrap!(ConnectionManager::new(Default::default(), &conn_manager_tx))
    };
    let coins = unwrap!(Coins::from_str("10"));
    let client_safe_key = register_client(&mut conn_manager, coins, client_id).await;
    let owner_key = client_safe_key.public_key();
    (conn_manager, conn_manager_rx, client_safe_key, owner_key)
}

// Create a balance for an account.
// Return the safe key which will be used to sign the requests that follow.
async fn register_client(
    conn_manager: &mut ConnectionManager,
    coins: Coins,
    client_id: ClientFullId,
) -> SafeKey {
    let client_public_key = client_id.public_id().public_key();
    conn_manager.create_balance(*client_public_key, coins).await;

    SafeKey::client(client_id)
}

// Register a new app for an account with the given permissions.
// Return the app's safe key and it's connection manager along with the reciever
// for network events.
async fn register_new_app(
    conn_manager: &mut ConnectionManager,
    client_safe_key: &SafeKey,
    permissions: AppPermissions,
) -> (SafeKey, ConnectionManager, UnboundedReceiver<NetworkEvent>) {
    let client_id = unwrap!(client_safe_key.public_id().client_public_id()).clone();
    let app_full_id = gen_app_id(client_id);
    let response = process_request(
        conn_manager,
        client_safe_key,
        Request::Client(ClientRequest::ListAuthKeysAndVersion),
    )
    .await;
    let (_, version): (_, u64) = unwrap!(response.try_into());

    send_req_expect_ok!(
        conn_manager,
        client_safe_key,
        Request::Client(ClientRequest::InsAuthKey {
            key: *app_full_id.public_id().public_key(),
            version: version + 1,
            permissions
        }),
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
