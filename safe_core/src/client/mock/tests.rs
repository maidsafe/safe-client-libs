// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

// FIXME: consider splitting test functions into multiple smaller ones
#![allow(clippy::cognitive_complexity)]

use super::routing::Routing;
use super::DEFAULT_MAX_MUTATIONS;
use crate::client::mock::vault::Vault;
use crate::client::NewFullId;
use crate::config_handler::{Config, DevConfig};
use crate::utils;

use maidsafe_utilities::serialisation::{deserialise, serialise};
use routing::{
    AccountInfo, Action, Authority, ClientError, EntryAction, EntryActions, Event, FullId,
    MutableData, PermissionSet, Request, Response, User, Value, TYPE_TAG_SESSION_PACKET,
};
use safe_nd::{
    AppFullId, ClientFullId, Error, IDataAddress, IDataKind, ImmutableData,
    MDataAction as NewAction, MDataAddress, MDataPermissionSet as NewPermissionSet, Message,
    MessageId, MutableData as NewMutableData, PublicKey, Request as RpcRequest,
    Response as RpcResponse, UnpubImmutableData, UnseqMutableData, XorName,
};
use std::collections::BTreeMap;
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::time::Duration;

// Helper macro to receive a routing event and assert it's a response
// success.
macro_rules! expect_success {
    ($rx:expr, $msg_id:expr, $res:path) => {
        match unwrap!($rx.recv_timeout(Duration::from_secs(10))) {
            Event::Response {
                response: $res { res, msg_id },
                ..
            } => {
                assert_eq!(msg_id, $msg_id);

                match res {
                    Ok(value) => value,
                    Err(err) => panic!("Unexpected error {:?}", err),
                }
            }
            event => panic!("Unexpected event {:?}", event),
        }
    };
}

// Helper macro to receive a routing event and assert it's a response
// failure.
macro_rules! expect_failure {
    ($rx:expr, $msg_id:expr, $res:path, $err:pat) => {
        match unwrap!($rx.recv_timeout(Duration::from_secs(10))) {
            Event::Response {
                response: $res { res, msg_id },
                ..
            } => {
                assert_eq!(msg_id, $msg_id);

                match res {
                    Ok(_) => panic!("Unexpected success"),
                    Err($err) => (),
                    Err(err) => panic!("Unexpected error {:?}", err),
                }
            }
            event => panic!("Unexpected event {:?}", event),
        }
    };
}

impl Routing {
    fn req_as_app(&mut self, rx: &Receiver<Event>, request: RpcRequest) -> RpcResponse {
        let message_id = MessageId::new();
        let signature = if let NewFullId::App(app_full_id) = &self.full_id_new {
            app_full_id.sign(&unwrap!(bincode::serialize(&(message_id, &request))))
        } else {
            panic!("Unsupported operation")
        };
        unwrap!(self.send(
            Authority::ClientManager(new_rand::random()),
            &unwrap!(serialise(&Message::Request {
                request,
                message_id,
                signature: Some(signature),
            }))
        ));
        let response = expect_success!(rx, message_id, Response::RpcResponse);
        unwrap!(deserialise(&response))
    }
    fn req_as_owner(&mut self, rx: &Receiver<Event>, request: RpcRequest) -> RpcResponse {
        let message_id = MessageId::new();
        let signature = if let NewFullId::Client(client_full_id) = &self.full_id_new {
            client_full_id.sign(&unwrap!(bincode::serialize(&(&request, message_id))))
        } else {
            panic!("Unsupported operation")
        };
        unwrap!(self.send(
            Authority::ClientManager(new_rand::random()),
            &unwrap!(serialise(&Message::Request {
                request,
                message_id,
                signature: Some(signature),
            }))
        ));
        let response = expect_success!(rx, message_id, Response::RpcResponse);
        unwrap!(deserialise(&response))
    }
}

// Test the basics idata operations.
#[test]
fn immutable_data_basics() {
    let (mut routing, routing_rx, full_id) = setup();

    // Create account
    let owner_key = PublicKey::from(*full_id.public_id().bls_public_key());
    let client_mgr = create_account(&mut routing, &routing_rx, owner_key);

    // Construct ImmutableData
    let orig_data = ImmutableData::new(unwrap!(utils::generate_random_vector(100)));
    let nae_mgr = Authority::NaeManager(*orig_data.name());

    // GetIData should fail
    let msg_id = MessageId::new();
    unwrap!(routing.get_idata(nae_mgr, *orig_data.name(), msg_id));
    expect_failure!(
        routing_rx,
        msg_id,
        Response::GetIData,
        ClientError::NoSuchData
    );

    // First PutIData should succeed
    let msg_id = MessageId::new();
    unwrap!(routing.put_idata(client_mgr, orig_data.clone(), msg_id));
    expect_success!(routing_rx, msg_id, Response::PutIData);

    // Now GetIData should pass
    let msg_id = MessageId::new();
    unwrap!(routing.get_idata(nae_mgr, *orig_data.name(), msg_id));
    let got_data = expect_success!(routing_rx, msg_id, Response::GetIData);
    assert_eq!(got_data, orig_data);

    // GetAccountInfo should pass and show one mutation performed
    let acct_info = account_info(&mut routing, &routing_rx, client_mgr);
    assert_eq!(acct_info.mutations_done, 1);
    assert_eq!(acct_info.mutations_available, DEFAULT_MAX_MUTATIONS - 1);

    // Subsequent PutIData for same data should succeed - De-duplication
    let msg_id = MessageId::new();
    unwrap!(routing.put_idata(client_mgr, orig_data.clone(), msg_id));
    expect_success!(routing_rx, msg_id, Response::PutIData);

    // GetIData should succeed
    let msg_id = MessageId::new();
    unwrap!(routing.get_idata(nae_mgr, *orig_data.name(), msg_id));
    let got_data = expect_success!(routing_rx, msg_id, Response::GetIData);
    assert_eq!(got_data, orig_data);

    // GetAccountInfo should pass and show two mutations performed
    let acct_info = account_info(&mut routing, &routing_rx, client_mgr);
    assert_eq!(acct_info.mutations_done, 2);
    assert_eq!(acct_info.mutations_available, DEFAULT_MAX_MUTATIONS - 2);
}

// Test the basic mdata operations.
#[test]
fn mutable_data_basics() {
    let (mut routing, routing_rx, full_id) = setup();

    // Create account
    let owner_key = PublicKey::from(*full_id.public_id().bls_public_key());
    let client_mgr = create_account(&mut routing, &routing_rx, owner_key);

    // Construct MutableData
    let name = new_rand::random();
    let tag = 1000u64;

    let data = unwrap!(MutableData::new(
        name,
        tag,
        Default::default(),
        Default::default(),
        btree_set!(owner_key),
    ));
    let nae_mgr = Authority::NaeManager(*data.name());

    // Operations on non-existing MutableData should fail.
    let msg_id = MessageId::new();
    unwrap!(routing.get_mdata_version(nae_mgr, name, tag, msg_id));
    expect_failure!(
        routing_rx,
        msg_id,
        Response::GetMDataVersion,
        ClientError::NoSuchData
    );

    let msg_id = MessageId::new();
    unwrap!(routing.list_mdata_entries(nae_mgr, name, tag, msg_id));
    expect_failure!(
        routing_rx,
        msg_id,
        Response::ListMDataEntries,
        ClientError::NoSuchData
    );

    // PutMData
    let msg_id = MessageId::new();
    unwrap!(routing.put_mdata(client_mgr, data, msg_id, owner_key));
    expect_success!(routing_rx, msg_id, Response::PutMData);

    // It should be possible to put an MData using the same name but a
    // different type tag
    let tag2 = 1001u64;

    let data2 = unwrap!(MutableData::new(
        name,
        tag2,
        Default::default(),
        Default::default(),
        btree_set!(owner_key),
    ));
    let msg_id = MessageId::new();
    unwrap!(routing.put_mdata(client_mgr, data2, msg_id, owner_key));
    expect_success!(routing_rx, msg_id, Response::PutMData);

    // GetMDataVersion should respond with 0
    let msg_id = MessageId::new();
    unwrap!(routing.get_mdata_version(nae_mgr, name, tag, msg_id));
    let version = expect_success!(routing_rx, msg_id, Response::GetMDataVersion);
    assert_eq!(version, 0);

    // GetMData should return the entire MutableData object
    let msg_id = MessageId::new();
    unwrap!(routing.get_mdata(nae_mgr, name, tag, msg_id));
    let mdata = expect_success!(routing_rx, msg_id, Response::GetMData);
    assert!(mdata.serialised_size() > 0);

    // ListMDataEntries, ListMDataKeys and ListMDataValues should all respond
    // with empty collections.
    let msg_id = MessageId::new();
    unwrap!(routing.list_mdata_entries(nae_mgr, name, tag, msg_id));
    let entries = expect_success!(routing_rx, msg_id, Response::ListMDataEntries);
    assert!(entries.is_empty());

    let msg_id = MessageId::new();
    unwrap!(routing.list_mdata_keys(nae_mgr, name, tag, msg_id));
    let keys = expect_success!(routing_rx, msg_id, Response::ListMDataKeys);
    assert!(keys.is_empty());

    let msg_id = MessageId::new();
    unwrap!(routing.list_mdata_values(nae_mgr, name, tag, msg_id));
    let values = expect_success!(routing_rx, msg_id, Response::ListMDataValues);
    assert!(values.is_empty());

    // Add couple of entries
    let key0 = b"key0";
    let key1 = b"key1";
    let value0_v0 = unwrap!(utils::generate_random_vector(10));
    let value1_v0 = unwrap!(utils::generate_random_vector(10));

    let actions = btree_map![
        key0.to_vec() => EntryAction::Ins(Value {
            content: value0_v0.clone(),
            entry_version: 0,
        }),
        key1.to_vec() => EntryAction::Ins(Value {
            content: value1_v0.clone(),
            entry_version: 0,
        })
    ];

    let msg_id = MessageId::new();
    unwrap!(routing.mutate_mdata_entries(client_mgr, name, tag, actions, msg_id, owner_key,));
    expect_success!(routing_rx, msg_id, Response::MutateMDataEntries);

    // ListMDataEntries
    let msg_id = MessageId::new();
    unwrap!(routing.list_mdata_entries(nae_mgr, name, tag, msg_id));
    let entries = expect_success!(routing_rx, msg_id, Response::ListMDataEntries);
    assert_eq!(entries.len(), 2);

    let entry = unwrap!(entries.get(&key0[..]));
    assert_eq!(entry.content, value0_v0);
    assert_eq!(entry.entry_version, 0);

    let entry = unwrap!(entries.get(&key1[..]));
    assert_eq!(entry.content, value1_v0);
    assert_eq!(entry.entry_version, 0);

    // Second MData with a diff. type tag still should be empty
    let msg_id = MessageId::new();
    unwrap!(routing.list_mdata_entries(nae_mgr, name, tag2, msg_id));
    let entries = expect_success!(routing_rx, msg_id, Response::ListMDataEntries);
    assert!(entries.is_empty());

    // ListMDataKeys
    let msg_id = MessageId::new();
    unwrap!(routing.list_mdata_keys(nae_mgr, name, tag, msg_id));
    let keys = expect_success!(routing_rx, msg_id, Response::ListMDataKeys);
    assert_eq!(keys.len(), 2);
    assert!(keys.contains(&key0[..]));
    assert!(keys.contains(&key1[..]));

    // ListMDataValues
    let msg_id = MessageId::new();
    unwrap!(routing.list_mdata_values(nae_mgr, name, tag, msg_id));
    let values = expect_success!(routing_rx, msg_id, Response::ListMDataValues);
    assert_eq!(values.len(), 2);

    // GetMDataValue with existing key
    let msg_id = MessageId::new();
    unwrap!(routing.get_mdata_value(nae_mgr, name, tag, key0.to_vec(), msg_id,));
    let value = expect_success!(routing_rx, msg_id, Response::GetMDataValue);
    assert_eq!(value.content, value0_v0);
    assert_eq!(value.entry_version, 0);

    // GetMDataValue with non-existing key
    let key2 = b"key2";
    let msg_id = MessageId::new();
    unwrap!(routing.get_mdata_value(nae_mgr, name, tag, key2.to_vec(), msg_id,));
    expect_failure!(
        routing_rx,
        msg_id,
        Response::GetMDataValue,
        ClientError::NoSuchEntry
    );

    // Mutate the entries: insert, update and delete
    let value0_v1 = unwrap!(utils::generate_random_vector(10));
    let value2_v0 = unwrap!(utils::generate_random_vector(10));
    let actions = btree_map![
        key0.to_vec() => EntryAction::Update(Value {
            content: value0_v1.clone(),
            entry_version: 1,
        }),
        key1.to_vec() => EntryAction::Del(1),
        key2.to_vec() => EntryAction::Ins(Value {
            content: value2_v0.clone(),
            entry_version: 0,
        })
    ];

    let msg_id = MessageId::new();
    unwrap!(routing.mutate_mdata_entries(client_mgr, name, tag, actions, msg_id, owner_key,));
    expect_success!(routing_rx, msg_id, Response::MutateMDataEntries);

    // ListMDataEntries should respond with modified entries
    let msg_id = MessageId::new();
    unwrap!(routing.list_mdata_entries(nae_mgr, name, tag, msg_id));
    let entries = expect_success!(routing_rx, msg_id, Response::ListMDataEntries);
    assert_eq!(entries.len(), 3);

    // Updated entry
    let entry = unwrap!(entries.get(&key0[..]));
    assert_eq!(entry.content, value0_v1);
    assert_eq!(entry.entry_version, 1);

    // Deleted entry
    let entry = unwrap!(entries.get(&key1[..]));
    assert!(entry.content.is_empty());
    assert_eq!(entry.entry_version, 1);

    // Inserted entry
    let entry = unwrap!(entries.get(&key2[..]));
    assert_eq!(entry.content, value2_v0);
    assert_eq!(entry.entry_version, 0);
}

// Test reclamation of deleted mdata.
#[test]
fn mutable_data_reclaim() {
    let (mut routing, routing_rx, full_id) = setup();

    // Create account
    let owner_key = PublicKey::from(*full_id.public_id().bls_public_key());
    let client_mgr = create_account(&mut routing, &routing_rx, owner_key);

    // Construct MutableData
    let name = new_rand::random();
    let tag = 1000u64;

    let data = unwrap!(MutableData::new(
        name,
        tag,
        Default::default(),
        Default::default(),
        btree_set!(owner_key),
    ));
    let nae_mgr = Authority::NaeManager(*data.name());

    // PutMData
    let msg_id = MessageId::new();
    unwrap!(routing.put_mdata(client_mgr, data, msg_id, owner_key));
    expect_success!(routing_rx, msg_id, Response::PutMData);

    // Mutate the entries: insert, delete and insert again
    let key0 = b"key0";
    let value0 = unwrap!(utils::generate_random_vector(10));
    let actions = btree_map![
        key0.to_vec() => EntryAction::Ins(Value {
            content: value0.clone(),
            entry_version: 0,
        }),
    ];

    let msg_id = MessageId::new();
    unwrap!(routing.mutate_mdata_entries(client_mgr, name, tag, actions, msg_id, owner_key,));
    expect_success!(routing_rx, msg_id, Response::MutateMDataEntries);

    let actions = btree_map![
        key0.to_vec() => EntryAction::Del(1),
    ];

    let msg_id = MessageId::new();
    unwrap!(routing.mutate_mdata_entries(client_mgr, name, tag, actions, msg_id, owner_key,));
    expect_success!(routing_rx, msg_id, Response::MutateMDataEntries);

    let actions = btree_map![
        key0.to_vec() => EntryAction::Update(Value {
            content: value0.clone(),
            entry_version: 2,
        })
    ];

    let msg_id = MessageId::new();
    unwrap!(routing.mutate_mdata_entries(client_mgr, name, tag, actions, msg_id, owner_key,));
    expect_success!(routing_rx, msg_id, Response::MutateMDataEntries);

    // GetMDataVersion should respond with 0 as the mdata itself hasn't changed.
    let msg_id = MessageId::new();
    unwrap!(routing.get_mdata_version(nae_mgr, name, tag, msg_id));
    let version = expect_success!(routing_rx, msg_id, Response::GetMDataVersion);
    assert_eq!(version, 0);

    // Try deleting the entry with an invalid entry_version and make sure it fails
    let actions = btree_map![
        key0.to_vec() => EntryAction::Del(4),
    ];

    let msg_id = MessageId::new();
    unwrap!(routing.mutate_mdata_entries(client_mgr, name, tag, actions, msg_id, owner_key,));
    expect_failure!(
        routing_rx,
        msg_id,
        Response::MutateMDataEntries,
        ClientError::InvalidEntryActions(_)
    );

    // Try deleting the entry with an entry_version of 3 and make sure it succeeds
    let actions = btree_map![
        key0.to_vec() => EntryAction::Del(3),
    ];

    let msg_id = MessageId::new();
    unwrap!(routing.mutate_mdata_entries(client_mgr, name, tag, actions, msg_id, owner_key,));
    expect_success!(routing_rx, msg_id, Response::MutateMDataEntries);
}

// Test valid and invalid mdata entry versioning.
#[test]
fn mutable_data_entry_versioning() {
    let (mut routing, routing_rx, full_id) = setup();

    let owner_key = PublicKey::from(*full_id.public_id().bls_public_key());
    let client_mgr = create_account(&mut routing, &routing_rx, owner_key);

    // Construct MutableData
    let name = new_rand::random();
    let tag = 1000u64;

    let data = unwrap!(MutableData::new(
        name,
        tag,
        Default::default(),
        Default::default(),
        btree_set!(owner_key),
    ));

    // PutMData
    let msg_id = MessageId::new();
    unwrap!(routing.put_mdata(client_mgr, data, msg_id, owner_key));
    expect_success!(routing_rx, msg_id, Response::PutMData);

    // Insert a new entry
    let key = b"key0";
    let value_v0 = unwrap!(utils::generate_random_vector(10));
    let actions = btree_map![
        key.to_vec() => EntryAction::Ins(Value {
            content: value_v0,
            entry_version: 0,
        })
    ];

    let msg_id = MessageId::new();
    unwrap!(routing.mutate_mdata_entries(client_mgr, name, tag, actions, msg_id, owner_key,));
    expect_success!(routing_rx, msg_id, Response::MutateMDataEntries);

    // Attempt to update it without version bump fails.
    let value_v1 = unwrap!(utils::generate_random_vector(10));
    let actions = btree_map![
        key.to_vec() => EntryAction::Update(Value {
            content: value_v1.clone(),
            entry_version: 0,
        })
    ];

    let msg_id = MessageId::new();
    unwrap!(routing.mutate_mdata_entries(client_mgr, name, tag, actions, msg_id, owner_key,));
    expect_failure!(
        routing_rx,
        msg_id,
        Response::MutateMDataEntries,
        ClientError::InvalidEntryActions(_)
    );

    // Attempt to update it with incorrect version fails.
    let actions = EntryActions::new()
        .update(key.to_vec(), value_v1.clone(), 314_159_265)
        .into();
    let msg_id = MessageId::new();
    unwrap!(routing.mutate_mdata_entries(client_mgr, name, tag, actions, msg_id, owner_key));
    expect_failure!(
        routing_rx,
        msg_id,
        Response::MutateMDataEntries,
        ClientError::InvalidEntryActions(_)
    );

    // Update with correct version bump succeeds.
    let actions = btree_map![
        key.to_vec() => EntryAction::Update(Value {
            content: value_v1.clone(),
            entry_version: 1,
        })
    ];

    let msg_id = MessageId::new();
    unwrap!(routing.mutate_mdata_entries(client_mgr, name, tag, actions, msg_id, owner_key));
    expect_success!(routing_rx, msg_id, Response::MutateMDataEntries);

    // Delete without version bump fails.
    let actions = btree_map![
        key.to_vec() => EntryAction::Del(1)
    ];

    let msg_id = MessageId::new();
    unwrap!(routing.mutate_mdata_entries(client_mgr, name, tag, actions, msg_id, owner_key));
    expect_failure!(
        routing_rx,
        msg_id,
        Response::MutateMDataEntries,
        ClientError::InvalidEntryActions(_)
    );

    // Delete with correct version bump succeeds.
    let actions = btree_map![
        key.to_vec() => EntryAction::Del(2)
    ];

    let msg_id = MessageId::new();
    unwrap!(routing.mutate_mdata_entries(client_mgr, name, tag, actions, msg_id, owner_key));
    expect_success!(routing_rx, msg_id, Response::MutateMDataEntries);
}

// Test various operations with and without proper permissions.
#[test]
fn mutable_data_permissions() {
    let (mut routing, routing_rx, full_id) = setup();

    let owner_key = PublicKey::from(*full_id.public_id().bls_public_key());
    let client_mgr = create_account(&mut routing, &routing_rx, owner_key);

    // Construct MutableData with some entries and empty permissions.
    let name = new_rand::random();
    let tag = 1000u64;

    let key0 = b"key0";
    let value0_v0 = unwrap!(utils::generate_random_vector(10));

    let entries = btree_map![
        key0.to_vec() => Value { content: value0_v0, entry_version: 0 }
    ];

    let data = unwrap!(MutableData::new(
        name,
        tag,
        Default::default(),
        entries,
        btree_set!(owner_key)
    ));

    let nae_mgr = Authority::NaeManager(*data.name());

    // Put it to the network.
    let msg_id = MessageId::new();
    unwrap!(routing.put_mdata(client_mgr, data, msg_id, owner_key));
    expect_success!(routing_rx, msg_id, Response::PutMData);

    // ListMDataPermissions responds with empty collection.
    let msg_id = MessageId::new();
    unwrap!(routing.list_mdata_permissions(nae_mgr, name, tag, msg_id));
    let permissions = expect_success!(routing_rx, msg_id, Response::ListMDataPermissions);
    assert!(permissions.is_empty());

    // Owner can do anything by default.
    let value0_v1 = unwrap!(utils::generate_random_vector(10));
    let actions = EntryActions::new()
        .update(key0.to_vec(), value0_v1, 1)
        .into();
    let msg_id = MessageId::new();
    unwrap!(routing.mutate_mdata_entries(client_mgr, name, tag, actions, msg_id, owner_key));
    expect_success!(routing_rx, msg_id, Response::MutateMDataEntries);

    // Create app and authorise it.
    let (mut app_routing, app_routing_rx, app_full_id) = setup();
    let app_sign_key = PublicKey::Bls(*app_full_id.public_id().bls_public_key());

    let response = routing.req_as_owner(&routing_rx, RpcRequest::ListAuthKeysAndVersion);
    let version = match response {
        RpcResponse::ListAuthKeysAndVersion(Ok((_, version))) => version,
        x => panic!("Unexpected response: {:?}", x),
    };

    let response = routing.req_as_owner(
        &routing_rx,
        RpcRequest::InsAuthKey {
            version: version + 1,
            permissions: Default::default(),
            key: app_sign_key,
        },
    );
    match response {
        RpcResponse::InsAuthKey(Ok(())) => (),
        x => panic!("Unexpected response: {:?}", x),
    };

    // App can't mutate any entry, by default.
    let value0_v2 = unwrap!(utils::generate_random_vector(10));
    let actions = EntryActions::new()
        .update(key0.to_vec(), value0_v2.clone(), 2)
        .into();
    let msg_id = MessageId::new();
    unwrap!(app_routing.mutate_mdata_entries(client_mgr, name, tag, actions, msg_id, app_sign_key));
    expect_failure!(
        app_routing_rx,
        msg_id,
        Response::MutateMDataEntries,
        ClientError::AccessDenied
    );

    // App can't grant itself permission to update.
    let perms = PermissionSet::new().allow(Action::Update);
    let msg_id = MessageId::new();
    unwrap!(app_routing.set_mdata_user_permissions(
        client_mgr,
        name,
        tag,
        User::Key(app_sign_key),
        perms,
        1,
        msg_id,
        app_sign_key
    ));
    expect_failure!(
        app_routing_rx,
        msg_id,
        Response::SetMDataUserPermissions,
        ClientError::AccessDenied
    );

    // Verify app still can't update, after the previous attempt to
    // modify its permissions.
    let actions = EntryActions::new()
        .update(key0.to_vec(), value0_v2.clone(), 2)
        .into();
    let msg_id = MessageId::new();
    unwrap!(app_routing.mutate_mdata_entries(client_mgr, name, tag, actions, msg_id, app_sign_key));
    expect_failure!(
        app_routing_rx,
        msg_id,
        Response::MutateMDataEntries,
        ClientError::AccessDenied
    );

    // Grant insert permission for app.
    let perms = PermissionSet::new().allow(Action::Insert);
    let msg_id = MessageId::new();
    unwrap!(routing.set_mdata_user_permissions(
        client_mgr,
        name,
        tag,
        User::Key(app_sign_key),
        perms,
        1,
        msg_id,
        owner_key
    ));
    expect_success!(routing_rx, msg_id, Response::SetMDataUserPermissions);

    // The version is bumped.
    let msg_id = MessageId::new();
    unwrap!(routing.get_mdata_version(nae_mgr, name, tag, msg_id));
    let version = expect_success!(routing_rx, msg_id, Response::GetMDataVersion);
    assert_eq!(version, 1);

    // App still can't update entries.
    let actions = btree_map![
        key0.to_vec() => EntryAction::Update(Value {
            content: value0_v2.clone(),
            entry_version: 2,
        })
    ];

    let msg_id = MessageId::new();
    unwrap!(app_routing.mutate_mdata_entries(client_mgr, name, tag, actions, msg_id, app_sign_key));
    expect_failure!(
        app_routing_rx,
        msg_id,
        Response::MutateMDataEntries,
        ClientError::AccessDenied
    );

    // But it insert new ones.
    let key1 = b"key1";
    let value1_v0 = unwrap!(utils::generate_random_vector(10));
    let actions = btree_map![
        key1.to_vec() => EntryAction::Ins(Value {
            content: value1_v0,
            entry_version: 0,
        })
    ];

    let msg_id = MessageId::new();
    unwrap!(app_routing.mutate_mdata_entries(client_mgr, name, tag, actions, msg_id, app_sign_key));
    expect_success!(app_routing_rx, msg_id, Response::MutateMDataEntries);

    // Attempt to modify permissions without proper version bump fails
    let perms = PermissionSet::new()
        .allow(Action::Insert)
        .allow(Action::Update);
    let msg_id = MessageId::new();
    unwrap!(routing.set_mdata_user_permissions(
        client_mgr,
        name,
        tag,
        User::Key(app_sign_key),
        perms,
        1,
        msg_id,
        owner_key
    ));
    expect_failure!(
        routing_rx,
        msg_id,
        Response::SetMDataUserPermissions,
        ClientError::InvalidSuccessor(_)
    );

    // Modifying permissions with version bump succeeds.
    let perms = PermissionSet::new()
        .allow(Action::Insert)
        .allow(Action::Update);
    let msg_id = MessageId::new();
    unwrap!(routing.set_mdata_user_permissions(
        client_mgr,
        name,
        tag,
        User::Key(app_sign_key),
        perms,
        2,
        msg_id,
        owner_key
    ));
    expect_success!(routing_rx, msg_id, Response::SetMDataUserPermissions);

    // App can now update entries.
    let actions = btree_map![
        key0.to_vec() => EntryAction::Update(Value {
            content: value0_v2,
            entry_version: 2,
        })
    ];

    let msg_id = MessageId::new();
    unwrap!(app_routing.mutate_mdata_entries(client_mgr, name, tag, actions, msg_id, app_sign_key));
    expect_success!(app_routing_rx, msg_id, Response::MutateMDataEntries);

    // Revoke all permissions from app.
    let msg_id = MessageId::new();
    unwrap!(routing.del_mdata_user_permissions(
        client_mgr,
        name,
        tag,
        User::Key(app_sign_key),
        3,
        msg_id,
        owner_key
    ));
    expect_success!(routing_rx, msg_id, Response::DelMDataUserPermissions);

    // App can no longer mutate the entries.
    let key2 = b"key2";
    let value2_v0 = unwrap!(utils::generate_random_vector(10));
    let actions = EntryActions::new().ins(key2.to_vec(), value2_v0, 0).into();
    let msg_id = MessageId::new();
    unwrap!(app_routing.mutate_mdata_entries(client_mgr, name, tag, actions, msg_id, app_sign_key));
    expect_failure!(
        app_routing_rx,
        msg_id,
        Response::MutateMDataEntries,
        ClientError::AccessDenied
    );

    // Grant the app permission to manage permissions.
    let perms = PermissionSet::new().allow(Action::ManagePermissions);
    let msg_id = MessageId::new();
    unwrap!(routing.set_mdata_user_permissions(
        client_mgr,
        name,
        tag,
        User::Key(app_sign_key),
        perms,
        4,
        msg_id,
        owner_key
    ));
    expect_success!(routing_rx, msg_id, Response::SetMDataUserPermissions);

    // The app still can't mutate the entries.
    let value1_v1 = unwrap!(utils::generate_random_vector(10));
    let actions = EntryActions::new()
        .update(key1.to_vec(), value1_v1, 1)
        .into();
    let msg_id = MessageId::new();
    unwrap!(app_routing.mutate_mdata_entries(client_mgr, name, tag, actions, msg_id, app_sign_key));
    expect_failure!(
        app_routing_rx,
        msg_id,
        Response::MutateMDataEntries,
        ClientError::AccessDenied
    );

    // App can modify its own permission.
    let perms = PermissionSet::new().allow(Action::Update);
    let msg_id = MessageId::new();
    unwrap!(app_routing.set_mdata_user_permissions(
        client_mgr,
        name,
        tag,
        User::Key(app_sign_key),
        perms,
        5,
        msg_id,
        app_sign_key
    ));
    expect_success!(app_routing_rx, msg_id, Response::SetMDataUserPermissions);

    // The app can now mutate the entries.
    let value1_v1 = unwrap!(utils::generate_random_vector(10));
    let actions = EntryActions::new()
        .update(key1.to_vec(), value1_v1, 1)
        .into();
    let msg_id = MessageId::new();
    unwrap!(app_routing.mutate_mdata_entries(client_mgr, name, tag, actions, msg_id, app_sign_key));
    expect_success!(app_routing_rx, msg_id, Response::MutateMDataEntries);

    // Create another app and authorise it.
    let (mut app2_routing, app2_routing_rx, app2_full_id) = setup();
    let app2_sign_key = PublicKey::from(*app2_full_id.public_id().bls_public_key());

    let version = match routing.req_as_owner(&routing_rx, RpcRequest::ListAuthKeysAndVersion) {
        RpcResponse::ListAuthKeysAndVersion(Ok((_, version))) => version,
        x => panic!("Unexpected {:?}", x),
    };

    let _ = routing.req_as_owner(
        &routing_rx,
        RpcRequest::InsAuthKey {
            key: app2_sign_key,
            permissions: Default::default(),
            version: version + 1,
        },
    );

    // The new app can't mutate entries
    let key3 = b"key3";
    let value3_v0 = unwrap!(utils::generate_random_vector(10));
    let actions = EntryActions::new()
        .ins(key3.to_vec(), value3_v0.clone(), 0)
        .into();
    let msg_id = MessageId::new();
    unwrap!(app2_routing.mutate_mdata_entries(
        client_mgr,
        name,
        tag,
        actions,
        msg_id,
        app2_sign_key
    ));
    expect_failure!(
        app2_routing_rx,
        msg_id,
        Response::MutateMDataEntries,
        ClientError::AccessDenied
    );

    // Grant insert permission for anyone.
    let perms = PermissionSet::new().allow(Action::Insert);
    let msg_id = MessageId::new();
    unwrap!(routing.set_mdata_user_permissions(
        client_mgr,
        name,
        tag,
        User::Anyone,
        perms,
        6,
        msg_id,
        owner_key
    ));
    expect_success!(routing_rx, msg_id, Response::SetMDataUserPermissions);

    // The new app can now mutate entries
    let actions = EntryActions::new().ins(key3.to_vec(), value3_v0, 0).into();
    let msg_id = MessageId::new();
    unwrap!(app2_routing.mutate_mdata_entries(
        client_mgr,
        name,
        tag,
        actions,
        msg_id,
        app2_sign_key
    ));
    expect_success!(app2_routing_rx, msg_id, Response::MutateMDataEntries);

    // Revoke the insert permission for anyone.
    let msg_id = MessageId::new();
    unwrap!(routing.del_mdata_user_permissions(
        client_mgr,
        name,
        tag,
        User::Anyone,
        7,
        msg_id,
        owner_key
    ));
    expect_success!(routing_rx, msg_id, Response::DelMDataUserPermissions);

    // The new app can now longer mutate entries
    let key4 = b"key4";
    let value4_v0 = unwrap!(utils::generate_random_vector(10));
    let actions = EntryActions::new()
        .ins(key4.to_vec(), value4_v0.clone(), 0)
        .into();
    let msg_id = MessageId::new();
    unwrap!(app2_routing.mutate_mdata_entries(
        client_mgr,
        name,
        tag,
        actions,
        msg_id,
        app2_sign_key
    ));
    expect_failure!(
        app2_routing_rx,
        msg_id,
        Response::MutateMDataEntries,
        ClientError::AccessDenied
    );
}

// Test mdata operations with valid and invalid owners.
#[test]
fn mutable_data_ownership() {
    // Create owner's routing client
    let (mut owner_routing, owner_routing_rx, owner_full_id) = setup();

    let owner_key = PublicKey::from(*owner_full_id.public_id().bls_public_key());
    let client_mgr = create_account(&mut owner_routing, &owner_routing_rx, owner_key);

    // Create app's routing client and authorise the app.
    let (mut app_routing, app_routing_rx, app_full_id) = setup();
    let app_sign_key = PublicKey::from(*app_full_id.public_id().bls_public_key());

    let _resp = owner_routing.req_as_owner(
        &owner_routing_rx,
        RpcRequest::InsAuthKey {
            key: app_sign_key,
            version: 1,
            permissions: Default::default(),
        },
    );

    // Attempt to put MutableData using the app sign key as owner key should fail.
    let name = new_rand::random();
    let tag = 1000u64;
    let data = unwrap!(MutableData::new(
        name,
        tag,
        Default::default(),
        Default::default(),
        btree_set![app_sign_key]
    ));

    let msg_id = MessageId::new();
    unwrap!(app_routing.put_mdata(client_mgr, data, msg_id, app_sign_key));
    expect_failure!(
        app_routing_rx,
        msg_id,
        Response::PutMData,
        ClientError::InvalidOwners
    );

    // Putting it with correct owner succeeds.
    let data = unwrap!(MutableData::new(
        name,
        tag,
        Default::default(),
        Default::default(),
        btree_set![owner_key]
    ));

    let msg_id = MessageId::new();
    unwrap!(owner_routing.put_mdata(client_mgr, data, msg_id, owner_key));
    expect_success!(owner_routing_rx, msg_id, Response::PutMData);

    // Attempt to change owner by app should fail.
    let msg_id = MessageId::new();
    unwrap!(app_routing.change_mdata_owner(
        client_mgr,
        name,
        tag,
        btree_set![app_sign_key],
        1,
        msg_id
    ));
    expect_failure!(
        app_routing_rx,
        msg_id,
        Response::ChangeMDataOwner,
        ClientError::AccessDenied
    );

    // Attempt to change owner by app via its own account should fail.
    let app_client_mgr = create_account(&mut app_routing, &app_routing_rx, app_sign_key);
    let msg_id = MessageId::new();
    unwrap!(app_routing.change_mdata_owner(
        app_client_mgr,
        name,
        tag,
        btree_set![app_sign_key],
        1,
        msg_id
    ));
    expect_failure!(
        app_routing_rx,
        msg_id,
        Response::ChangeMDataOwner,
        ClientError::AccessDenied
    );

    // Changing the owner by owner should succeed.
    let msg_id = MessageId::new();
    unwrap!(owner_routing.change_mdata_owner(
        client_mgr,
        name,
        tag,
        btree_set![app_sign_key],
        1,
        msg_id
    ));
    expect_success!(owner_routing_rx, msg_id, Response::ChangeMDataOwner);
}

#[test]
fn pub_idata_rpc() {
    let (mut routing, routing_rx, full_id) = setup();
    let owner_key = PublicKey::from(*full_id.public_id().bls_public_key());
    let _client_mgr = create_account(&mut routing, &routing_rx, owner_key);

    let value = unwrap!(utils::generate_random_vector::<u8>(10));
    let data = ImmutableData::new(value);
    let name = *data.name();

    // Put pub idata. Should succeed.
    {
        let rpc_response = routing.req_as_owner(&routing_rx, RpcRequest::PutIData(data.into()));
        match rpc_response {
            RpcResponse::PutIData(res) => {
                assert!(res.is_ok());
            }
            _ => panic!("Unexpected"),
        }
    }

    // Get pub idata as an owner. Should succeed.
    {
        let rpc_response =
            routing.req_as_owner(&routing_rx, RpcRequest::GetIData(IDataAddress::Pub(name)));
        match rpc_response {
            RpcResponse::GetIData(res) => {
                let kind: IDataKind = unwrap!(res);
                assert_eq!(*kind.name(), name);
                assert!(kind.published());
            }
            _ => panic!("Unexpected"),
        }
    }

    let (mut app_routing, app_routing_rx, _app_full_id) = setup();

    // Get pub idata while not being an owner. Should succeed.
    {
        let rpc_response = app_routing.req_as_app(
            &app_routing_rx,
            RpcRequest::GetIData(IDataAddress::Pub(name)),
        );
        match rpc_response {
            RpcResponse::GetIData(res) => {
                let kind: IDataKind = unwrap!(res);
                assert_eq!(*kind.name(), name);
                assert!(kind.published());
            }
            _ => panic!("Unexpected"),
        }
    }
}

#[test]
fn unpub_idata_rpc() {
    let (mut routing, routing_rx, full_id) = setup();
    let owner_key = PublicKey::from(*full_id.public_id().bls_public_key());
    let _client_mgr = create_account(&mut routing, &routing_rx, owner_key);

    let value = unwrap!(utils::generate_random_vector::<u8>(10));
    let data = UnpubImmutableData::new(value, *full_id.public_id().bls_public_key());
    let name = *data.name();

    // Construct put request.
    let response = routing.req_as_owner(&routing_rx, RpcRequest::PutIData(data.into()));
    match response {
        RpcResponse::PutIData(res) => {
            assert!(res.is_ok());
        }
        _ => panic!("Unexpected response"),
    }

    // Get unpub idata. Should succeed.
    let rpc_response =
        routing.req_as_owner(&routing_rx, RpcRequest::GetIData(IDataAddress::Unpub(name)));
    match rpc_response {
        RpcResponse::GetIData(res) => {
            let kind: IDataKind = unwrap!(res);
            assert_eq!(*kind.name(), name);
            assert!(!kind.published());
        }
        _ => panic!("Unexpected response"),
    }

    let (mut app_routing, app_routing_rx, _app_full_id) = setup();

    // Try to get unpub idata while not being an owner. Should fail.
    {
        let rpc_response = app_routing.req_as_app(
            &app_routing_rx,
            RpcRequest::GetIData(IDataAddress::Unpub(name)),
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
        let rpc_response = app_routing.req_as_app(
            &app_routing_rx,
            RpcRequest::DeleteUnpubIData(IDataAddress::Unpub(name)),
        );
        match rpc_response {
            RpcResponse::DeleteUnpubIData(res) => match res {
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
    let (mut routing, routing_rx, full_id) = setup();
    let owner_key = PublicKey::from(*full_id.public_id().bls_public_key());
    let _client_mgr = create_account(&mut routing, &routing_rx, owner_key);
    let bls_key = full_id.bls_key().public_key();

    let name = XorName(new_rand::random());
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
    let response: RpcResponse =
        routing.req_as_owner(&routing_rx, RpcRequest::PutUnseqMData(data.clone()));

    match response {
        RpcResponse::PutUnseqMData(res) => unwrap!(res),
        _ => panic!("Unexpected response"),
    };

    // Construct get request.
    let rpc_response: RpcResponse = routing.req_as_owner(
        &routing_rx,
        RpcRequest::GetMData(MDataAddress::new_unseq(name, tag)),
    );
    match rpc_response {
        RpcResponse::GetUnseqMData(res) => {
            let unpub_mdata: UnseqMutableData = unwrap!(res);
            println!("{:?} :: {}", unpub_mdata.name(), unpub_mdata.tag());
            assert_eq!(*unpub_mdata.name(), name);
            assert_eq!(unpub_mdata.tag(), tag);
        }
        _ => panic!("Unexpected response"),
    }
}

// Test auth key operations with valid and invalid version bumps.
// #[test]
// fn auth_keys() {
//     let (mut routing, routing_rx, full_id) = setup();
//     let owner_key = PublicKey::from(*full_id.public_id().bls_public_key());
//     let client_mgr = create_account(&mut routing, &routing_rx, owner_key);

//     let (auth_key1, _) = sign::gen_keypair();
//     let (auth_key2, _) = sign::gen_keypair();

//     // Initially, the list of auth keys should be empty and the version should be zero.
//     let msg_id = MessageId::new();
//     unwrap!(routing.list_auth_keys_and_version(client_mgr, msg_id));
//     let (auth_keys, version) =
//         expect_success!(routing_rx, msg_id, Response::ListAuthKeysAndVersion);
//     assert!(auth_keys.is_empty());
//     assert_eq!(version, 0);

//     // Attempt to insert an auth key without proper version bump fails.
//     let msg_id = MessageId::new();
//     unwrap!(routing.ins_auth_key(client_mgr, auth_key1, Default::default(), 0, msg_id));
//     expect_failure!(
//         routing_rx,
//         msg_id,
//         Response::InsAuthKey,
//         ClientError::InvalidSuccessor(_)
//     );

//     // Insert an auth key with proper version bump succeeds.
//     let msg_id = MessageId::new();
//     unwrap!(routing.ins_auth_key(client_mgr, auth_key1, Default::default(), 1, msg_id));
//     expect_success!(routing_rx, msg_id, Response::InsAuthKey);

//     // Retrieve the list of auth keys and version
//     let msg_id = MessageId::new();
//     unwrap!(routing.list_auth_keys_and_version(client_mgr, msg_id));
//     let (auth_keys, version) =
//         expect_success!(routing_rx, msg_id, Response::ListAuthKeysAndVersion);
//     assert_eq!(auth_keys.len(), 1);
//     assert!(auth_keys.contains(&auth_key1));
//     assert_eq!(version, 1);

//     // Attempt to delete auth key without proper version bump fails.
//     let msg_id = MessageId::new();
//     unwrap!(routing.del_auth_key(client_mgr, auth_key1, 1, msg_id));
//     expect_failure!(
//         routing_rx,
//         msg_id,
//         Response::DelAuthKey,
//         ClientError::InvalidSuccessor(_)
//     );

//     // Attempt to delete non-existing key fails.
//     let msg_id = MessageId::new();
//     unwrap!(routing.del_auth_key(client_mgr, auth_key2, 2, msg_id));
//     expect_failure!(
//         routing_rx,
//         msg_id,
//         Response::DelAuthKey,
//         ClientError::NoSuchKey
//     );

//     // Delete auth key with proper version bump succeeds.
//     let msg_id = MessageId::new();
//     unwrap!(routing.del_auth_key(client_mgr, auth_key1, 2, msg_id));
//     expect_success!(routing_rx, msg_id, Response::DelAuthKey);

//     // Retrieve the list of auth keys and version
//     let msg_id = MessageId::new();
//     unwrap!(routing.list_auth_keys_and_version(client_mgr, msg_id));
//     let (auth_keys, version) =
//         expect_success!(routing_rx, msg_id, Response::ListAuthKeysAndVersion);
//     assert!(auth_keys.is_empty());
//     assert_eq!(version, 2);
// }

// Exhaust the account balance and ensure that mutations fail.
#[test]
fn low_balance_check() {
    for &custom_vault in &[true, false] {
        let (mut routing, routing_rx, full_id) = setup_with_config(Config {
            dev: Some(DevConfig {
                mock_unlimited_mutations: custom_vault,
                mock_in_memory_storage: true,
                mock_vault_path: None,
            }),
        });
        let owner_key = PublicKey::from(*full_id.public_id().bls_public_key());
        let client_mgr = create_account(&mut routing, &routing_rx, owner_key);

        // Put MutableData so we can test getting it later.
        // Do this before exhausting the balance (below).
        let name = new_rand::random();
        let tag = 1000u64;

        let data = unwrap!(MutableData::new(
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
        let data = ImmutableData::new(vec_data);
        let msg_id = MessageId::new();

        // Another mutation should fail/succeed depending on config value.
        let unlimited_muts = match routing.config().dev {
            Some(dev) => dev.mock_unlimited_mutations,
            None => false,
        };

        let mut mutations_available =
            account_info(&mut routing, &routing_rx, client_mgr).mutations_available;

        // Exhaust the account balance manually.
        loop {
            unwrap!(routing.put_idata(client_mgr, data.clone(), msg_id));
            expect_success!(routing_rx, msg_id, Response::PutIData);

            mutations_available -= 1;

            // Get the account info at each iteration of loop.
            let acct_info = account_info(&mut routing, &routing_rx, client_mgr);
            if acct_info.mutations_available == 0 || mutations_available == 0 {
                break;
            }
        }

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
    let (mut routing, routing_rx, full_id) = setup_with_config(Config {
        dev: Some(DevConfig {
            mock_unlimited_mutations: false,
            mock_in_memory_storage: false,
            mock_vault_path: Some(String::from("./this_path_should_not_exist")),
        }),
    });
    let owner_key = PublicKey::from(*full_id.public_id().bls_public_key());

    // This does a `put_mdata`. This should fail.
    let _ = create_account(&mut routing, &routing_rx, owner_key);
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

    let (mut routing, routing_rx, full_id) = setup_with_config(Config {
        dev: Some(DevConfig {
            mock_unlimited_mutations: false,
            mock_in_memory_storage: false,
            mock_vault_path: Some(String::from("./tmp")),
        }),
    });
    let owner_key = PublicKey::from(*full_id.public_id().bls_public_key());
    let client_mgr = create_account(&mut routing, &routing_rx, owner_key);

    // Put MutableData. Should succeed.
    let name = new_rand::random();
    let tag = 1000u64;

    let data = unwrap!(MutableData::new(
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
    let (mut routing, routing_rx, full_id) = setup();

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
    let client_mgr = create_account(&mut routing, &routing_rx, owner_key);

    // Construct MutableData (but hook won't allow to store it on the network
    // if the tag is 10000)
    let name = new_rand::random();
    let tag = 10_000u64;

    let data = unwrap!(MutableData::new(
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
    let name = new_rand::random();
    let tag = 12_345u64;

    let data = unwrap!(MutableData::new(
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

// Setup routing with a shared, global vault.
fn setup() -> (Routing, Receiver<Event>, FullId) {
    let (routing, routing_rx, full_id) = setup_impl();

    (routing, routing_rx, full_id)
}

// Setup routing with a new, non-shared vault.
fn setup_with_config(config: Config) -> (Routing, Receiver<Event>, FullId) {
    let (mut routing, routing_rx, full_id) = setup_impl();

    routing.set_vault(&Arc::new(Mutex::new(Vault::new(config))));

    (routing, routing_rx, full_id)
}

fn setup_impl() -> (Routing, Receiver<Event>, FullId) {
    let full_id = FullId::new();
    let bls_sk = full_id.bls_key().clone();
    let bls_pk = bls_sk.public_key();
    let (routing_tx, routing_rx) = mpsc::channel();
    let routing = unwrap!(Routing::new(
        routing_tx,
        Some(full_id.clone()),
        Some(NewFullId::App(AppFullId::with_keys(
            bls_sk,
            PublicKey::from(bls_pk),
        ))),
        None,
        Duration::new(0, 0),
    ));

    // Wait until connection is established.
    match unwrap!(routing_rx.recv_timeout(Duration::from_secs(10))) {
        Event::Connected => (),
        e => panic!("Unexpected event {:?}", e),
    }

    (routing, routing_rx, full_id)
}

// Create account, put it to the network and return `ClientManager` authority for it.
fn create_account(
    routing: &mut Routing,
    routing_rx: &Receiver<Event>,
    owner_key: PublicKey,
) -> Authority<XorName> {
    let account_name = XorName::from(owner_key);
    let account_data = unwrap!(MutableData::new(
        account_name,
        TYPE_TAG_SESSION_PACKET,
        Default::default(),
        Default::default(),
        btree_set![owner_key]
    ));

    routing.full_id_new = NewFullId::Client(ClientFullId::with_bls_key(
        routing.full_id.bls_key().clone(),
    ));

    let msg_id = MessageId::new();
    unwrap!(routing.put_mdata(
        Authority::ClientManager(account_name),
        account_data,
        msg_id,
        owner_key
    ));
    expect_success!(routing_rx, msg_id, Response::PutMData);

    Authority::ClientManager(account_name)
}

fn account_info(
    routing: &mut Routing,
    routing_rx: &Receiver<Event>,
    dst: Authority<XorName>,
) -> AccountInfo {
    let msg_id = MessageId::new();
    unwrap!(routing.get_account_info(dst, msg_id));
    expect_success!(routing_rx, msg_id, Response::GetAccountInfo)
}
