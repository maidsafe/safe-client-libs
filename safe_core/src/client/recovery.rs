// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::Client;
use crate::client::AuthActions;
use crate::errors::CoreError;
use crate::event_loop::CoreFuture;
use crate::utils::FutureExt;
use futures::future::{self, Either, Loop};
use futures::Future;
use safe_nd::{
    AppPermissions, EntryError, Error as SndError, MDataAction, MDataAddress, MDataPermissionSet,
    MDataSeqEntries, MDataSeqEntryAction, MDataSeqEntryActions, MDataSeqValue, PublicKey,
    SeqMutableData,
};
use std::collections::BTreeMap;

const MAX_ATTEMPTS: usize = 10;

/// Puts mutable data on the network and tries to recover from errors.
///
/// If the data already exists, it tries to mutate it so its entries and permissions
/// are the same as those of the data being put, except it wont delete existing
/// entries or remove existing permissions.
pub fn put_mdata(client: &impl Client, data: SeqMutableData) -> Box<CoreFuture<()>> {
    let client2 = client.clone();

    client
        .put_seq_mutable_data(data.clone())
        .or_else(move |error| match error {
            CoreError::DataError(SndError::DataExists) => Either::A(update_mdata(&client2, data)),
            error => Either::B(future::err(error)),
        })
        .into_box()
}

/// Mutates mutable data entries and tries to recover from errors.
pub fn mutate_mdata_entries(
    client: &impl Client,
    address: MDataAddress,
    actions: MDataSeqEntryActions,
) -> Box<CoreFuture<()>> {
    let state = (0, actions);
    let client = client.clone();

    future::loop_fn(state, move |(attempts, actions)| {
        client
            .mutate_seq_mdata_entries(*address.name(), address.tag(), actions.clone())
            .map(|_| Loop::Break(()))
            .or_else(move |error| match error {
                CoreError::DataError(SndError::InvalidEntryActions(errors)) => {
                    if attempts < MAX_ATTEMPTS {
                        let actions = fix_entry_actions(actions, &errors);
                        Ok(Loop::Continue((attempts + 1, actions.into())))
                    } else {
                        Err(CoreError::DataError(SndError::InvalidEntryActions(errors)))
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
    })
    .into_box()
}

/// Sets user permission on the mutable data and tries to recover from errors.
pub fn set_mdata_user_permissions(
    client: &impl Client,
    address: MDataAddress,
    user: PublicKey,
    permissions: MDataPermissionSet,
    version: u64,
) -> Box<CoreFuture<()>> {
    let state = (0, version);
    let client = client.clone();

    future::loop_fn(state, move |(attempts, version)| {
        client
            .set_mdata_user_permissions_new(address, user, permissions.clone(), version)
            .map(|_| Loop::Break(()))
            .or_else(move |error| match error {
                CoreError::DataError(SndError::InvalidSuccessor(current_version)) => {
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
    })
    .into_box()
}

/// Deletes user permission on the mutable data and tries to recover from errors.
pub fn del_mdata_user_permissions(
    client: &impl Client,
    address: MDataAddress,
    user: PublicKey,
    version: u64,
) -> Box<CoreFuture<()>> {
    let state = (0, version);
    let client = client.clone();

    future::loop_fn(state, move |(attempts, version)| {
        client
            .del_mdata_user_permissions_new(address, user, version)
            .map(|_| Loop::Break(()))
            .or_else(move |error| match error {
                CoreError::DataError(SndError::NoSuchKey) => Ok(Loop::Break(())),
                CoreError::DataError(SndError::InvalidSuccessor(current_version)) => {
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
    })
    .into_box()
}

fn update_mdata(client: &impl Client, data: SeqMutableData) -> Box<CoreFuture<()>> {
    let client2 = client.clone();
    let client3 = client.clone();

    let address = *data.address();
    let f0 = client.list_seq_mdata_entries(*data.name(), data.tag());
    let f1 = client.list_mdata_permissions_new(address);
    let f2 = client.get_mdata_version_new(address);

    f0.join3(f1, f2)
        .and_then(move |(entries, permissions, version)| {
            update_mdata_permissions(
                &client2,
                address,
                &permissions,
                data.permissions().clone(),
                version + 1,
            )
            .map(move |_| (data, entries))
        })
        .and_then(move |(data, entries)| {
            update_mdata_entries(&client3, address, &entries, data.entries().clone())
        })
        .into_box()
}

// Update the mutable data on the network so it has all the `desired_entries`.
fn update_mdata_entries(
    client: &impl Client,
    address: MDataAddress,
    current_entries: &MDataSeqEntries,
    desired_entries: MDataSeqEntries,
) -> Box<CoreFuture<()>> {
    let actions = desired_entries
        .into_iter()
        .filter_map(|(key, value)| {
            if let Some(current_value) = current_entries.get(&key) {
                if current_value.version <= value.version {
                    Some((key, MDataSeqEntryAction::Update(value)))
                } else {
                    None
                }
            } else {
                Some((key, MDataSeqEntryAction::Ins(value)))
            }
        })
        .collect::<BTreeMap<_, _>>();

    mutate_mdata_entries(client, address, actions.into())
}

fn update_mdata_permissions(
    client: &impl Client,
    address: MDataAddress,
    current_permissions: &BTreeMap<PublicKey, MDataPermissionSet>,
    desired_permissions: BTreeMap<PublicKey, MDataPermissionSet>,
    version: u64,
) -> Box<CoreFuture<()>> {
    let permissions: Vec<_> = desired_permissions
        .into_iter()
        .map(|(user, desired_set)| {
            if let Some(current_set) = current_permissions.get(&user) {
                (
                    user,
                    union_permission_sets(current_set.clone(), desired_set),
                )
            } else {
                (user, desired_set)
            }
        })
        .collect();

    let state = (client.clone(), permissions, version);
    future::loop_fn(state, move |(client, mut permissions, version)| {
        if let Some((user, set)) = permissions.pop() {
            let f = set_mdata_user_permissions(&client, address, user, set, version)
                .map(move |_| Loop::Continue((client, permissions, version + 1)));
            Either::A(f)
        } else {
            Either::B(future::ok(Loop::Break(())))
        }
    })
    .into_box()
}

// Modify the given entry actions to fix the entry errors.
fn fix_entry_actions(
    actions: MDataSeqEntryActions,
    errors: &BTreeMap<Vec<u8>, EntryError>,
) -> BTreeMap<Vec<u8>, MDataSeqEntryAction> {
    actions
        .into_actions()
        .into_iter()
        .fold(BTreeMap::new(), |mut fixed_action, (key, action)| {
            if let Some(error) = errors.get(&key) {
                if let Some(action) = fix_entry_action(&action, error) {
                    let _ = fixed_action.insert(key, action);
                }
            } else {
                let _ = fixed_action.insert(key, action);
            }
            fixed_action
        })
}

fn fix_entry_action(
    action: &MDataSeqEntryAction,
    error: &EntryError,
) -> Option<MDataSeqEntryAction> {
    match (action, error) {
        (MDataSeqEntryAction::Ins(value), EntryError::EntryExists(current_version))
        | (MDataSeqEntryAction::Update(value), EntryError::InvalidSuccessor(current_version)) => {
            Some(MDataSeqEntryAction::Update(MDataSeqValue {
                data: value.data.clone(),
                version: (current_version + 1).into(),
            }))
        }
        (MDataSeqEntryAction::Update(value), EntryError::NoSuchEntry) => {
            Some(MDataSeqEntryAction::Ins(value.clone()))
        }
        (MDataSeqEntryAction::Del(_), EntryError::NoSuchEntry) => None,
        (MDataSeqEntryAction::Del(_), EntryError::InvalidSuccessor(current_version)) => {
            Some(MDataSeqEntryAction::Del((current_version + 1).into()))
        }
        (action, _) => Some(action.clone()),
    }
}

// Create union of the two permission sets, preferring allows to deny's.
fn union_permission_sets(a: MDataPermissionSet, b: MDataPermissionSet) -> MDataPermissionSet {
    let actions = [
        MDataAction::Insert,
        MDataAction::Update,
        MDataAction::Delete,
        MDataAction::ManagePermissions,
    ];
    actions
        .iter()
        .fold(MDataPermissionSet::new(), |set, &action| {
            if a.is_allowed(action) | b.is_allowed(action) {
                set.allow(action)
            } else if !a.is_allowed(action) | !b.is_allowed(action) {
                set.deny(action)
            } else {
                set
            }
        })
}

/// Insert key to maid managers.
/// Covers the `InvalidSuccessor` error case (it should not fail if the key already exists).
pub fn ins_auth_key(
    client: &(impl Client + AuthActions),
    key: PublicKey,
    permissions: AppPermissions,
    version: u64,
) -> Box<CoreFuture<()>> {
    let state = (0, version);
    let client = client.clone();

    future::loop_fn(state, move |(attempts, version)| {
        client
            .ins_auth_key(key, permissions, version)
            .map(|_| Loop::Break(()))
            .or_else(move |error| match error {
                CoreError::DataError(SndError::InvalidSuccessor(current_version)) => {
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
    })
    .into_box()
}

#[cfg(test)]
mod tests {
    use super::*;
    use safe_nd::MDataSeqValue;

    // Test modifying given entry actions to fix entry errors
    #[test]
    fn test_fix_entry_actions() {
        let actions = MDataSeqEntryActions::new()
            .ins(vec![0], vec![0], 0)
            .ins(vec![1], vec![1], 0)
            .update(vec![2], vec![2], 1)
            .update(vec![3], vec![3], 1)
            .update(vec![4], vec![4], 1)
            .del(vec![5], 1)
            .del(vec![6], 1)
            .del(vec![7], 1);

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
            MDataSeqEntryAction::Ins(MDataSeqValue {
                data: vec![0],
                version: 0,
            })
        );

        // 1: insert is transformed to update
        assert_eq!(
            *unwrap!(actions.get([1].as_ref())),
            MDataSeqEntryAction::Update(MDataSeqValue {
                data: vec![1],
                version: 3,
            })
        );

        // 2: update is OK.
        assert_eq!(
            *unwrap!(actions.get([2].as_ref())),
            MDataSeqEntryAction::Update(MDataSeqValue {
                data: vec![2],
                version: 1,
            })
        );

        // 3: update is transformed to insert.
        assert_eq!(
            *unwrap!(actions.get([3].as_ref())),
            MDataSeqEntryAction::Ins(MDataSeqValue {
                data: vec![3],
                version: 1,
            })
        );

        // 4: update version is fixed.
        assert_eq!(
            *unwrap!(actions.get([4].as_ref())),
            MDataSeqEntryAction::Update(MDataSeqValue {
                data: vec![4],
                version: 3,
            })
        );

        // 5: delete is OK.
        assert_eq!(
            *unwrap!(actions.get([5].as_ref())),
            MDataSeqEntryAction::Del(1)
        );

        // 6: delete action is removed, as there is nothing to delete.
        assert!(actions.get([6].as_ref()).is_none());

        // 7: delete version is fixed.
        assert_eq!(
            *unwrap!(actions.get([7].as_ref())),
            MDataSeqEntryAction::Del(3)
        );
    }

    // Test creating a union of two permission sets
    #[test]
    fn test_union_permission_sets() {
        let a = MDataPermissionSet::new()
            .allow(MDataAction::Insert)
            .deny(MDataAction::Update)
            .deny(MDataAction::ManagePermissions);
        let b = MDataPermissionSet::new()
            .allow(MDataAction::Update)
            .allow(MDataAction::Delete);

        let c = union_permission_sets(a, b);
        assert_eq!(c.is_allowed(MDataAction::Insert), true);
        assert_eq!(c.is_allowed(MDataAction::Update), true);
        assert_eq!(c.is_allowed(MDataAction::Delete), true);
        assert_eq!(c.is_allowed(MDataAction::ManagePermissions), false);
    }
}

#[cfg(all(test, feature = "mock-network"))]
mod tests_with_mock_routing {
    use super::*;
    use crate::utils::test_utils::random_client;
    use safe_nd::{MDataSeqValue, XorName};

    // Test putting mdata and recovering from errors
    #[test]
    fn put_mdata_with_recovery() {
        random_client(|client| {
            let client2 = client.clone();
            let client3 = client.clone();
            let client4 = client.clone();

            let name = new_rand::random();
            let tag = 10_000;
            let owners = client.public_key();

            let entries = btree_map![
                 vec![0] => MDataSeqValue {
                    data: vec![0, 0],
                    version: 0,
                },
                 vec![1] => MDataSeqValue {
                    data: vec![1, 0],
                    version: 1,
                },
                 vec![2] => MDataSeqValue {
                    data: vec![2, 0],
                    version: 0,
                }
            ];

            let bls_sk = threshold_crypto::SecretKey::random();
            let user = PublicKey::from(bls_sk.public_key());

            let permissions = btree_map![
                user => MDataPermissionSet::new().allow(MDataAction::Insert)
            ];
            let data0 = SeqMutableData::new_with_data(name, tag, entries, permissions, owners);

            let entries1 = btree_map![
                vec![0] => MDataSeqValue {
                    data: vec![0, 1],
                    version: 1,
                },
                vec![1] => MDataSeqValue {
                    data: vec![1, 1],
                    version: 0,
                },
                vec![3] => MDataSeqValue {
                    data: vec![3, 1],
                    version: 0,
                }
            ];

            let bls_sk = threshold_crypto::SecretKey::random();
            let user = PublicKey::from(bls_sk.public_key());

            let permissions = btree_map![
               user => MDataPermissionSet::new().allow(MDataAction::Delete)
            ];

            let data1 = SeqMutableData::new_with_data(name, tag, entries1, permissions, owners);

            client
                .put_seq_mutable_data(data0)
                .then(move |res| {
                    unwrap!(res);
                    put_mdata(&client2, data1)
                })
                .then(move |res| {
                    unwrap!(res);
                    client3.list_seq_mdata_entries(name, tag)
                })
                .then(move |res| {
                    let entries = unwrap!(res);
                    assert_eq!(entries.len(), 4);
                    assert_eq!(
                        *unwrap!(entries.get([0].as_ref())),
                        MDataSeqValue {
                            data: vec![0, 1],
                            version: 1,
                        }
                    );
                    assert_eq!(
                        *unwrap!(entries.get([1].as_ref())),
                        MDataSeqValue {
                            data: vec![1, 0],
                            version: 1,
                        }
                    );

                    client4.list_mdata_permissions_new(MDataAddress::Seq { name, tag })
                })
                .then(move |res| {
                    let permissions = unwrap!(res);
                    assert_eq!(permissions.len(), 2);
                    assert_eq!(
                        *unwrap!(permissions.get(&user)),
                        MDataPermissionSet::new().allow(MDataAction::Delete)
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

            let name: XorName = new_rand::random();
            let tag = 10_000;
            let entries = btree_map![
                vec![1] => MDataSeqValue {
                    data: vec![1],
                    version: 0,
                },
                vec![2] => MDataSeqValue {
                    data: vec![2],
                    version: 0,
                },
                vec![4] => MDataSeqValue {
                    data: vec![4],
                    version: 0,
                },
                vec![5] => MDataSeqValue {
                    data: vec![5],
                    version: 0,
                },
                vec![7] => MDataSeqValue {
                    data: vec![7],
                    version: 0,
                }
            ];
            let owners = client.public_key();
            let data =
                SeqMutableData::new_with_data(name, tag, entries, Default::default(), owners);

            client
                .put_seq_mutable_data(data)
                .then(move |res| {
                    unwrap!(res);

                    let actions = MDataSeqEntryActions::new()
                        .ins(vec![0], vec![0], 0) // normal insert
                        .ins(vec![1], vec![1, 0], 0) // insert to existing entry
                        .update(vec![2], vec![2, 0], 1) // normal update
                        .update(vec![3], vec![3], 1) // update of non-existing entry
                        .update(vec![4], vec![4, 0], 0) // update with invalid version
                        .del(vec![5], 1) // normal delete
                        .del(vec![6], 1) // delete of non-existing entry
                        .del(vec![7], 0); // delete with invalid version

                    mutate_mdata_entries(&client2, MDataAddress::Seq { name, tag }, actions)
                })
                .then(move |res| {
                    unwrap!(res);
                    client3.list_seq_mdata_entries(name, tag)
                })
                .then(move |res| {
                    let entries = unwrap!(res);
                    assert_eq!(entries.len(), 5);

                    assert_eq!(
                        *unwrap!(entries.get([0].as_ref())),
                        MDataSeqValue {
                            data: vec![0],
                            version: 0,
                        }
                    );
                    assert_eq!(
                        *unwrap!(entries.get([1].as_ref())),
                        MDataSeqValue {
                            data: vec![1, 0],
                            version: 1,
                        }
                    );
                    assert_eq!(
                        *unwrap!(entries.get([2].as_ref())),
                        MDataSeqValue {
                            data: vec![2, 0],
                            version: 1,
                        }
                    );
                    assert_eq!(
                        *unwrap!(entries.get([3].as_ref())),
                        MDataSeqValue {
                            data: vec![3],
                            version: 1,
                        }
                    );
                    assert_eq!(
                        *unwrap!(entries.get([4].as_ref())),
                        MDataSeqValue {
                            data: vec![4, 0],
                            version: 1,
                        }
                    );
                    assert!(entries.get([5].as_ref()).is_none());
                    assert!(entries.get([6].as_ref()).is_none());
                    assert!(entries.get([7].as_ref()).is_none());

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

            let name: XorName = new_rand::random();
            let tag = 10_000;
            let owners = client.public_key();
            let data = SeqMutableData::new_with_data(
                name,
                tag,
                Default::default(),
                Default::default(),
                owners,
            );
            let address = *data.address();
            let bls_sk1 = threshold_crypto::SecretKey::random();
            let bls_sk2 = threshold_crypto::SecretKey::random();

            let user0 = PublicKey::from(bls_sk1.public_key());
            let user1 = PublicKey::from(bls_sk2.public_key());

            client
                .put_seq_mutable_data(data)
                .then(move |res| {
                    unwrap!(res);
                    // set with invalid version
                    set_mdata_user_permissions(
                        &client2,
                        address,
                        user0,
                        MDataPermissionSet::new().allow(MDataAction::Insert),
                        0,
                    )
                })
                .then(move |res| {
                    unwrap!(res);
                    client3.list_mdata_user_permissions_new(address, user0)
                })
                .then(move |res| {
                    let retrieved_permissions = unwrap!(res);
                    assert_eq!(
                        retrieved_permissions,
                        MDataPermissionSet::new().allow(MDataAction::Insert)
                    );

                    // delete with invalid version
                    del_mdata_user_permissions(&client4, address, user0, 0)
                })
                .then(move |res| {
                    unwrap!(res);
                    client5.list_mdata_user_permissions_new(address, user0)
                })
                .then(move |res| {
                    match res {
                        Err(CoreError::DataError(SndError::NoSuchKey)) => (),
                        x => panic!("Unexpected {:?}", x),
                    }

                    // delete of non-existing user
                    del_mdata_user_permissions(&client6, address, user1, 3)
                })
                .then(move |res| {
                    unwrap!(res);
                    Ok::<_, CoreError>(())
                })
        })
    }
}
