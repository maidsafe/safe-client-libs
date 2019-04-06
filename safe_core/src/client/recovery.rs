// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::Client;
use crate::errors::CoreError;
use crate::event_loop::CoreFuture;
use futures::future::{self, Either, Loop};
use futures::Future;
use routing::{
    Action, ClientError, EntryAction, EntryError, MutableData, PermissionSet, User, Value, XorName,
};
use rust_sodium::crypto::sign;
use std::collections::BTreeMap;
use crate::utils::FutureExt;

const MAX_ATTEMPTS: usize = 10;

/// Puts mutable data on the network and tries to recover from errors.
///
/// If the data already exists, it tries to mutate it so its entries and permissions
/// are the same as those of the data being put, except it wont delete existing
/// entries or remove existing permissions.
pub fn put_mdata(client: &impl Client, data: MutableData) -> Box<CoreFuture<()>> {
    let client2 = client.clone();

    client
        .put_mdata(data.clone())
        .or_else(move |error| match error {
            CoreError::RoutingClientError(ClientError::DataExists) => {
                Either::A(update_mdata(&client2, data))
            }
            error => Either::B(future::err(error)),
        }).into_box()
}

/// Mutates mutable data entries and tries to recover from errors.
pub fn mutate_mdata_entries(
    client: &impl Client,
    name: XorName,
    tag: u64,
    actions: BTreeMap<Vec<u8>, EntryAction>,
) -> Box<CoreFuture<()>> {
    let state = (0, actions);
    let client = client.clone();

    future::loop_fn(state, move |(attempts, actions)| {
        client
            .mutate_mdata_entries(name, tag, actions.clone())
            .map(|_| Loop::Break(()))
            .or_else(move |error| match error {
                CoreError::RoutingClientError(ClientError::InvalidEntryActions(errors)) => {
                    if attempts < MAX_ATTEMPTS {
                        let actions = fix_entry_actions(actions, &errors);
                        Ok(Loop::Continue((attempts + 1, actions)))
                    } else {
                        Err(CoreError::RoutingClientError(
                            ClientError::InvalidEntryActions(errors),
                        ))
                    }
                }
                CoreError::RequestTimeout => {
                    if attempts < MAX_ATTEMPTS {
                        Ok(Loop::Continue((attempts + 1, actions)))
                    } else {
                        Err(CoreError::RequestTimeout)
                    }
                }
                error => Err(error),
            })
    }).into_box()
}

/// Sets user permission on the mutable data and tries to recover from errors.
pub fn set_mdata_user_permissions(
    client: &impl Client,
    name: XorName,
    tag: u64,
    user: User,
    permissions: PermissionSet,
    version: u64,
) -> Box<CoreFuture<()>> {
    let state = (0, version);
    let client = client.clone();

    future::loop_fn(state, move |(attempts, version)| {
        client
            .set_mdata_user_permissions(name, tag, user, permissions, version)
            .map(|_| Loop::Break(()))
            .or_else(move |error| match error {
                CoreError::RoutingClientError(ClientError::InvalidSuccessor(current_version)) => {
                    if attempts < MAX_ATTEMPTS {
                        Ok(Loop::Continue((attempts + 1, current_version + 1)))
                    } else {
                        Err(error)
                    }
                }
                CoreError::RequestTimeout => {
                    if attempts < MAX_ATTEMPTS {
                        Ok(Loop::Continue((attempts + 1, version)))
                    } else {
                        Err(CoreError::RequestTimeout)
                    }
                }
                error => Err(error),
            })
    }).into_box()
}

/// Deletes user permission on the mutable data and tries to recover from errors.
pub fn del_mdata_user_permissions(
    client: &impl Client,
    name: XorName,
    tag: u64,
    user: User,
    version: u64,
) -> Box<CoreFuture<()>> {
    let state = (0, version);
    let client = client.clone();

    future::loop_fn(state, move |(attempts, version)| {
        client
            .del_mdata_user_permissions(name, tag, user, version)
            .map(|_| Loop::Break(()))
            .or_else(move |error| match error {
                CoreError::RoutingClientError(ClientError::NoSuchKey) => Ok(Loop::Break(())),
                CoreError::RoutingClientError(ClientError::InvalidSuccessor(current_version)) => {
                    if attempts < MAX_ATTEMPTS {
                        Ok(Loop::Continue((attempts + 1, current_version + 1)))
                    } else {
                        Err(error)
                    }
                }
                CoreError::RequestTimeout => {
                    if attempts < MAX_ATTEMPTS {
                        Ok(Loop::Continue((attempts + 1, version)))
                    } else {
                        Err(CoreError::RequestTimeout)
                    }
                }
                error => Err(error),
            })
    }).into_box()
}

fn update_mdata(client: &impl Client, data: MutableData) -> Box<CoreFuture<()>> {
    let client2 = client.clone();
    let client3 = client.clone();

    let f0 = client.list_mdata_entries(*data.name(), data.tag());
    let f1 = client.list_mdata_permissions(*data.name(), data.tag());
    let f2 = client.get_mdata_version(*data.name(), data.tag());

    f0.join3(f1, f2)
        .and_then(move |(entries, permissions, version)| {
            update_mdata_permissions(
                &client2,
                *data.name(),
                data.tag(),
                &permissions,
                data.permissions().clone(),
                version + 1,
            ).map(move |_| (data, entries))
        }).and_then(move |(data, entries)| {
            update_mdata_entries(
                &client3,
                *data.name(),
                data.tag(),
                &entries,
                data.entries().clone(),
            )
        }).into_box()
}

// Update the mutable data on the network so it has all the `desired_entries`.
fn update_mdata_entries(
    client: &impl Client,
    name: XorName,
    tag: u64,
    current_entries: &BTreeMap<Vec<u8>, Value>,
    desired_entries: BTreeMap<Vec<u8>, Value>,
) -> Box<CoreFuture<()>> {
    let actions = desired_entries
        .into_iter()
        .filter_map(|(key, value)| {
            if let Some(current_value) = current_entries.get(&key) {
                if current_value.entry_version <= value.entry_version {
                    Some((key, EntryAction::Update(value)))
                } else {
                    None
                }
            } else {
                Some((key, EntryAction::Ins(value)))
            }
        }).collect();

    mutate_mdata_entries(client, name, tag, actions)
}

fn update_mdata_permissions(
    client: &impl Client,
    name: XorName,
    tag: u64,
    current_permissions: &BTreeMap<User, PermissionSet>,
    desired_permissions: BTreeMap<User, PermissionSet>,
    version: u64,
) -> Box<CoreFuture<()>> {
    let permissions: Vec<_> = desired_permissions
        .into_iter()
        .map(|(user, desired_set)| {
            if let Some(current_set) = current_permissions.get(&user) {
                (user, union_permission_sets(*current_set, desired_set))
            } else {
                (user, desired_set)
            }
        }).collect();

    let state = (client.clone(), permissions, version);
    future::loop_fn(state, move |(client, mut permissions, version)| {
        if let Some((user, set)) = permissions.pop() {
            let f = set_mdata_user_permissions(&client, name, tag, user, set, version)
                .map(move |_| Loop::Continue((client, permissions, version + 1)));
            Either::A(f)
        } else {
            Either::B(future::ok(Loop::Break(())))
        }
    }).into_box()
}

// Modify the given entry actions to fix the entry errors.
fn fix_entry_actions(
    actions: BTreeMap<Vec<u8>, EntryAction>,
    errors: &BTreeMap<Vec<u8>, EntryError>,
) -> BTreeMap<Vec<u8>, EntryAction> {
    actions
        .into_iter()
        .filter_map(|(key, action)| {
            if let Some(error) = errors.get(&key) {
                if let Some(action) = fix_entry_action(action, error) {
                    Some((key, action))
                } else {
                    None
                }
            } else {
                Some((key, action))
            }
        }).collect()
}

fn fix_entry_action(action: EntryAction, error: &EntryError) -> Option<EntryAction> {
    match (action, *error) {
        (EntryAction::Ins(value), EntryError::EntryExists(current_version))
        | (EntryAction::Update(value), EntryError::InvalidSuccessor(current_version)) => {
            Some(EntryAction::Update(Value {
                content: value.content,
                entry_version: current_version + 1,
            }))
        }
        (EntryAction::Update(value), EntryError::NoSuchEntry) => Some(EntryAction::Ins(value)),
        (EntryAction::Del(_), EntryError::NoSuchEntry) => None,
        (EntryAction::Del(_), EntryError::InvalidSuccessor(current_version)) => {
            Some(EntryAction::Del(current_version + 1))
        }
        (action, _) => Some(action),
    }
}

// Create union of the two permission sets, preferring allows to deny's.
fn union_permission_sets(a: PermissionSet, b: PermissionSet) -> PermissionSet {
    let actions = [
        Action::Insert,
        Action::Update,
        Action::Delete,
        Action::ManagePermissions,
    ];
    actions
        .into_iter()
        .fold(PermissionSet::new(), |set, &action| {
            match (a.is_allowed(action), b.is_allowed(action)) {
                (Some(true), _) | (_, Some(true)) => set.allow(action),
                (Some(false), _) | (_, Some(false)) => set.deny(action),
                _ => set,
            }
        })
}

/// Insert key to maid managers.
/// Covers the `InvalidSuccessor` error case (it should not fail if the key already exists).
pub fn ins_auth_key(
    client: &impl Client,
    key: sign::PublicKey,
    version: u64,
) -> Box<CoreFuture<()>> {
    let state = (0, version);
    let client = client.clone();

    future::loop_fn(state, move |(attempts, version)| {
        client
            .ins_auth_key(key, version)
            .map(|_| Loop::Break(()))
            .or_else(move |error| match error {
                CoreError::RoutingClientError(ClientError::InvalidSuccessor(current_version)) => {
                    if attempts < MAX_ATTEMPTS {
                        Ok(Loop::Continue((attempts + 1, current_version + 1)))
                    } else {
                        Err(error)
                    }
                }
                CoreError::RequestTimeout => {
                    if attempts < MAX_ATTEMPTS {
                        Ok(Loop::Continue((attempts + 1, version)))
                    } else {
                        Err(CoreError::RequestTimeout)
                    }
                }
                error => Err(error),
            })
    }).into_box()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test modifying given entry actions to fix entry errors
    #[test]
    fn test_fix_entry_actions() {
        let mut actions = BTreeMap::new();
        let _ = actions.insert(
            vec![0],
            EntryAction::Ins(Value {
                content: vec![0],
                entry_version: 0,
            }),
        );
        let _ = actions.insert(
            vec![1],
            EntryAction::Ins(Value {
                content: vec![1],
                entry_version: 0,
            }),
        );
        let _ = actions.insert(
            vec![2],
            EntryAction::Update(Value {
                content: vec![2],
                entry_version: 1,
            }),
        );
        let _ = actions.insert(
            vec![3],
            EntryAction::Update(Value {
                content: vec![3],
                entry_version: 1,
            }),
        );
        let _ = actions.insert(
            vec![4],
            EntryAction::Update(Value {
                content: vec![4],
                entry_version: 1,
            }),
        );
        let _ = actions.insert(vec![5], EntryAction::Del(1));
        let _ = actions.insert(vec![6], EntryAction::Del(1));
        let _ = actions.insert(vec![7], EntryAction::Del(1));

        let mut errors = BTreeMap::new();
        let _ = errors.insert(vec![1], EntryError::EntryExists(2));
        let _ = errors.insert(vec![3], EntryError::NoSuchEntry);
        let _ = errors.insert(vec![4], EntryError::InvalidSuccessor(2));
        let _ = errors.insert(vec![6], EntryError::NoSuchEntry);
        let _ = errors.insert(vec![7], EntryError::InvalidSuccessor(2));

        let actions = fix_entry_actions(actions, &errors);

        // 0: insert is OK.
        assert_eq!(
            *unwrap!(actions.get([0].as_ref())),
            EntryAction::Ins(Value {
                content: vec![0],
                entry_version: 0,
            })
        );

        // 1: insert is transformed to update
        assert_eq!(
            *unwrap!(actions.get([1].as_ref())),
            EntryAction::Update(Value {
                content: vec![1],
                entry_version: 3,
            })
        );

        // 2: update is OK.
        assert_eq!(
            *unwrap!(actions.get([2].as_ref())),
            EntryAction::Update(Value {
                content: vec![2],
                entry_version: 1,
            })
        );

        // 3: update is transformed to insert.
        assert_eq!(
            *unwrap!(actions.get([3].as_ref())),
            EntryAction::Ins(Value {
                content: vec![3],
                entry_version: 1,
            })
        );

        // 4: update version is fixed.
        assert_eq!(
            *unwrap!(actions.get([4].as_ref())),
            EntryAction::Update(Value {
                content: vec![4],
                entry_version: 3,
            })
        );

        // 5: delete is OK.
        assert_eq!(*unwrap!(actions.get([5].as_ref())), EntryAction::Del(1));

        // 6: delete action is removed, as there is nothing to delete.
        assert!(actions.get([6].as_ref()).is_none());

        // 7: delete version is fixed.
        assert_eq!(*unwrap!(actions.get([7].as_ref())), EntryAction::Del(3));
    }

    // Test creating a union of two permission sets
    #[test]
    fn test_union_permission_sets() {
        let a = PermissionSet::new()
            .allow(Action::Insert)
            .deny(Action::Update)
            .deny(Action::ManagePermissions);
        let b = PermissionSet::new()
            .allow(Action::Update)
            .allow(Action::Delete);

        let c = union_permission_sets(a, b);
        assert_eq!(c.is_allowed(Action::Insert), Some(true));
        assert_eq!(c.is_allowed(Action::Update), Some(true));
        assert_eq!(c.is_allowed(Action::Delete), Some(true));
        assert_eq!(c.is_allowed(Action::ManagePermissions), Some(false));
    }
}

#[cfg(all(test, feature = "use-mock-routing"))]
mod tests_with_mock_routing {
    use super::*;
    use rand;
    use routing::{Action, EntryActions, MutableData};
    use rust_sodium::crypto::sign;
    use utils::test_utils::random_client;

    // Test putting mdata and recovering from errors
    #[test]
    fn put_mdata_with_recovery() {
        random_client(|client| {
            let client2 = client.clone();
            let client3 = client.clone();
            let client4 = client.clone();

            let name = rand::random();
            let tag = 10_000;
            let owners = btree_set![unwrap!(client.public_signing_key())];

            let entries = btree_map![
                vec![0] => Value {
                    content: vec![0, 0],
                    entry_version: 0,
                },
                vec![1] => Value {
                    content: vec![1, 0],
                    entry_version: 1,
                },
                vec![2] => Value {
                    content: vec![2, 0],
                    entry_version: 0,
                }
            ];
            let permissions = btree_map![
                User::Anyone => PermissionSet::new().allow(Action::Insert)
            ];
            let data0 = unwrap!(MutableData::new(
                name,
                tag,
                permissions,
                entries,
                owners.clone(),
            ));

            let entries = btree_map![
                vec![0] => Value {
                    content: vec![0, 1],
                    entry_version: 1,
                },
                vec![1] => Value {
                    content: vec![1, 1],
                    entry_version: 0,
                },
                vec![3] => Value {
                    content: vec![3, 1],
                    entry_version: 0,
                }
            ];

            let user = User::Key(sign::gen_keypair().0);
            let permissions = btree_map![
                User::Anyone => PermissionSet::new().allow(Action::Insert).allow(Action::Update),
                user => PermissionSet::new().allow(Action::Delete)
            ];

            let data1 = unwrap!(MutableData::new(name, tag, permissions, entries, owners));

            client
                .put_mdata(data0)
                .then(move |res| {
                    unwrap!(res);
                    put_mdata(&client2, data1)
                }).then(move |res| {
                    unwrap!(res);
                    client3.list_mdata_entries(name, tag)
                }).then(move |res| {
                    let entries = unwrap!(res);
                    assert_eq!(entries.len(), 4);
                    assert_eq!(
                        *unwrap!(entries.get([0].as_ref())),
                        Value {
                            content: vec![0, 1],
                            entry_version: 1,
                        }
                    );
                    assert_eq!(
                        *unwrap!(entries.get([1].as_ref())),
                        Value {
                            content: vec![1, 0],
                            entry_version: 1,
                        }
                    );

                    client4.list_mdata_permissions(name, tag)
                }).then(move |res| {
                    let permissions = unwrap!(res);
                    assert_eq!(permissions.len(), 2);
                    assert_eq!(
                        *unwrap!(permissions.get(&User::Anyone)),
                        PermissionSet::new()
                            .allow(Action::Insert)
                            .allow(Action::Update)
                    );
                    assert_eq!(
                        *unwrap!(permissions.get(&user)),
                        PermissionSet::new().allow(Action::Delete)
                    );

                    Ok::<_, CoreError>(())
                })
        })
    }

    // Test mutating mdata entries and recovering from errors
    #[test]
    fn mutate_mdata_entries_with_recovery() {
        random_client(|client| {
            let client2 = client.clone();
            let client3 = client.clone();

            let name = rand::random();
            let tag = 10_000;
            let entries = btree_map![
                vec![1] => Value {
                    content: vec![1],
                    entry_version: 0,
                },
                vec![2] => Value {
                    content: vec![2],
                    entry_version: 0,
                },
                vec![4] => Value {
                    content: vec![4],
                    entry_version: 0,
                },
                vec![5] => Value {
                    content: vec![5],
                    entry_version: 0,
                },
                vec![7] => Value {
                    content: vec![7],
                    entry_version: 0,
                }
            ];
            let owners = btree_set![unwrap!(client.public_signing_key())];
            let data = unwrap!(MutableData::new(
                name,
                tag,
                Default::default(),
                entries,
                owners,
            ));

            client
                .put_mdata(data)
                .then(move |res| {
                    unwrap!(res);

                    let actions = EntryActions::new()
                        .ins(vec![0], vec![0], 0)       // normal insert
                        .ins(vec![1], vec![1, 0], 0)    // insert to existing entry
                        .update(vec![2], vec![2, 0], 1) // normal update
                        .update(vec![3], vec![3], 1)    // update of non-existing entry
                        .update(vec![4], vec![4, 0], 0) // update with invalid version
                        .del(vec![5], 1)                // normal delete
                        .del(vec![6], 1)                // delete of non-existing entry
                        .del(vec![7], 0)                // delete with invalid version
                        .into();

                    mutate_mdata_entries(&client2, name, tag, actions)
                }).then(move |res| {
                    unwrap!(res);
                    client3.list_mdata_entries(name, tag)
                }).then(move |res| {
                    let entries = unwrap!(res);
                    assert_eq!(entries.len(), 7);

                    assert_eq!(
                        *unwrap!(entries.get([0].as_ref())),
                        Value {
                            content: vec![0],
                            entry_version: 0,
                        }
                    );
                    assert_eq!(
                        *unwrap!(entries.get([1].as_ref())),
                        Value {
                            content: vec![1, 0],
                            entry_version: 1,
                        }
                    );
                    assert_eq!(
                        *unwrap!(entries.get([2].as_ref())),
                        Value {
                            content: vec![2, 0],
                            entry_version: 1,
                        }
                    );
                    assert_eq!(
                        *unwrap!(entries.get([3].as_ref())),
                        Value {
                            content: vec![3],
                            entry_version: 1,
                        }
                    );
                    assert_eq!(
                        *unwrap!(entries.get([4].as_ref())),
                        Value {
                            content: vec![4, 0],
                            entry_version: 1,
                        }
                    );
                    assert_eq!(
                        *unwrap!(entries.get([5].as_ref())),
                        Value {
                            content: vec![],
                            entry_version: 1,
                        }
                    );
                    assert!(entries.get([6].as_ref()).is_none());
                    assert_eq!(
                        *unwrap!(entries.get([7].as_ref())),
                        Value {
                            content: vec![],
                            entry_version: 1,
                        }
                    );

                    Ok::<_, CoreError>(())
                })
        })
    }

    // Test setting and deleting user permissions and recovering from errors
    #[test]
    fn set_and_del_mdata_user_permissions_with_recovery() {
        random_client(|client| {
            let client2 = client.clone();
            let client3 = client.clone();
            let client4 = client.clone();
            let client5 = client.clone();
            let client6 = client.clone();

            let name = rand::random();
            let tag = 10_000;
            let owners = btree_set![unwrap!(client.public_signing_key())];
            let data = unwrap!(MutableData::new(
                name,
                tag,
                Default::default(),
                Default::default(),
                owners,
            ));

            let user0 = User::Key(sign::gen_keypair().0);
            let user1 = User::Key(sign::gen_keypair().0);
            let permissions = PermissionSet::new().allow(Action::Insert);

            client
                .put_mdata(data)
                .then(move |res| {
                    unwrap!(res);
                    // set with invalid version
                    set_mdata_user_permissions(&client2, name, tag, user0, permissions, 0)
                }).then(move |res| {
                    unwrap!(res);
                    client3.list_mdata_user_permissions(name, tag, user0)
                }).then(move |res| {
                    let retrieved_permissions = unwrap!(res);
                    assert_eq!(retrieved_permissions, permissions);

                    // delete with invalid version
                    del_mdata_user_permissions(&client4, name, tag, user0, 0)
                }).then(move |res| {
                    unwrap!(res);
                    client5.list_mdata_user_permissions(name, tag, user0)
                }).then(move |res| {
                    match res {
                        Err(CoreError::RoutingClientError(ClientError::NoSuchKey)) => (),
                        x => panic!("Unexpected {:?}", x),
                    }

                    // delete of non-existing user
                    del_mdata_user_permissions(&client6, name, tag, user1, 3)
                }).then(move |res| {
                    unwrap!(res);
                    Ok::<_, CoreError>(())
                })
        })
    }
}
