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

use super::Client;
use errors::CoreError;
use event_loop::CoreFuture;
use futures::Future;
use futures::future::{self, Loop};
use routing::{ClientError, EntryAction, EntryError, Value, XorName};
use std::collections::BTreeMap;
use utils::FutureExt;

const MAX_ATTEMPTS: usize = 10;

/// Mutates mutable data entries and tries to recover from errors.
pub fn mutate_mdata_entries<T: 'static>(client: &Client<T>,
                                        name: XorName,
                                        tag: u64,
                                        actions: BTreeMap<Vec<u8>, EntryAction>)
                                        -> Box<CoreFuture<()>> {
    let state = MutateEntriesState {
        client: client.clone(),
        actions: actions,
        attempts: 0,
    };

    future::loop_fn(state, move |state| {
        state.client
            .mutate_mdata_entries(name, tag, state.actions.clone())
            .map(|_| Loop::Break(()))
            .or_else(move |error| match error {
                CoreError::RoutingClientError(ClientError::InvalidEntryActions(errors)) => {
                    if state.attempts < MAX_ATTEMPTS {
                        Ok(Loop::Continue(state.next(&errors)))
                    } else {
                        Err(CoreError::RoutingClientError(ClientError::InvalidEntryActions(errors)))
                    }
                }
                error => Err(error)
            })
    })
            .into_box()
}

struct MutateEntriesState<T> {
    client: Client<T>,
    actions: BTreeMap<Vec<u8>, EntryAction>,
    attempts: usize,
}

impl<T> MutateEntriesState<T> {
    fn next(mut self, errors: &BTreeMap<Vec<u8>, EntryError>) -> Self {
        self.actions = fix_entry_actions(self.actions, errors);
        self.attempts += 1;
        self
    }
}

// Modify the given entry actions to fix the entry errors.
fn fix_entry_actions(actions: BTreeMap<Vec<u8>, EntryAction>,
                     errors: &BTreeMap<Vec<u8>, EntryError>)
                     -> BTreeMap<Vec<u8>, EntryAction> {
    actions
        .into_iter()
        .filter_map(|(key, action)| if let Some(error) = errors.get(&key) {
                        if let Some(action) = fix_entry_action(action, error) {
                            Some((key, action))
                        } else {
                            None
                        }
                    } else {
                        Some((key, action))
                    })
        .collect()
}

fn fix_entry_action(action: EntryAction, error: &EntryError) -> Option<EntryAction> {
    match (action, *error) {
        (EntryAction::Ins(value), EntryError::EntryExists(current_version)) => {
            Some(EntryAction::Update(Value {
                                         content: value.content,
                                         entry_version: current_version + 1,
                                     }))
        }
        (EntryAction::Update(value), EntryError::NoSuchEntry) => Some(EntryAction::Ins(value)),
        (EntryAction::Update(value), EntryError::InvalidSuccessor(current_version)) => {
            Some(EntryAction::Update(Value {
                                         content: value.content,
                                         entry_version: current_version + 1,
                                     }))
        }
        (EntryAction::Del(_), EntryError::NoSuchEntry) => None,
        (EntryAction::Del(_), EntryError::InvalidSuccessor(current_version)) => {
            Some(EntryAction::Del(current_version + 1))
        }
        (action, _) => Some(action),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixing_entry_actions() {
        let mut actions = BTreeMap::new();
        let _ = actions.insert(vec![0],
                               EntryAction::Ins(Value {
                                                    content: vec![0],
                                                    entry_version: 0,
                                                }));
        let _ = actions.insert(vec![1],
                               EntryAction::Ins(Value {
                                                    content: vec![1],
                                                    entry_version: 0,
                                                }));
        let _ = actions.insert(vec![2],
                               EntryAction::Update(Value {
                                                       content: vec![2],
                                                       entry_version: 1,
                                                   }));
        let _ = actions.insert(vec![3],
                               EntryAction::Update(Value {
                                                       content: vec![3],
                                                       entry_version: 1,
                                                   }));
        let _ = actions.insert(vec![4],
                               EntryAction::Update(Value {
                                                       content: vec![4],
                                                       entry_version: 1,
                                                   }));
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
        assert_eq!(*unwrap!(actions.get([0].as_ref())),
                   EntryAction::Ins(Value {
                                        content: vec![0],
                                        entry_version: 0,
                                    }));

        // 1: insert is transformed to update
        assert_eq!(*unwrap!(actions.get([1].as_ref())),
                   EntryAction::Update(Value {
                                           content: vec![1],
                                           entry_version: 3,
                                       }));

        // 2: update is OK.
        assert_eq!(*unwrap!(actions.get([2].as_ref())),
                   EntryAction::Update(Value {
                                           content: vec![2],
                                           entry_version: 1,
                                       }));

        // 3: update is transformed to insert.
        assert_eq!(*unwrap!(actions.get([3].as_ref())),
                   EntryAction::Ins(Value {
                                        content: vec![3],
                                        entry_version: 1,
                                    }));

        // 4: update version is fixed.
        assert_eq!(*unwrap!(actions.get([4].as_ref())),
                   EntryAction::Update(Value {
                                           content: vec![4],
                                           entry_version: 3,
                                       }));

        // 5: delete is OK.
        assert_eq!(*unwrap!(actions.get([5].as_ref())), EntryAction::Del(1));

        // 6: delete action is removed, as there is nothing to delete.
        assert!(actions.get([6].as_ref()).is_none());

        // 7: delete version is fixed.
        assert_eq!(*unwrap!(actions.get([7].as_ref())), EntryAction::Del(3));
    }

}

#[cfg(all(test, feature = "use-mock-routing"))]
mod tests_with_mock_routing {
    use super::*;
    use rand;
    use routing::{EntryActions, MutableData};
    use utils::test_utils::random_client;

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
            let data = unwrap!(MutableData::new(name, tag, Default::default(), entries, owners));

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
                })
                .then(move |res| {
                          unwrap!(res);
                          client3.list_mdata_entries(name, tag)
                      })
                .then(move |res| {
                    let entries = unwrap!(res);
                    assert_eq!(entries.len(), 7);

                    assert_eq!(*unwrap!(entries.get([0].as_ref())),
                               Value {
                                   content: vec![0],
                                   entry_version: 0,
                               });
                    assert_eq!(*unwrap!(entries.get([1].as_ref())),
                               Value {
                                   content: vec![1, 0],
                                   entry_version: 1,
                               });
                    assert_eq!(*unwrap!(entries.get([2].as_ref())),
                               Value {
                                   content: vec![2, 0],
                                   entry_version: 1,
                               });
                    assert_eq!(*unwrap!(entries.get([3].as_ref())),
                               Value {
                                   content: vec![3],
                                   entry_version: 1,
                               });
                    assert_eq!(*unwrap!(entries.get([4].as_ref())),
                               Value {
                                   content: vec![4, 0],
                                   entry_version: 1,
                               });
                    assert_eq!(*unwrap!(entries.get([5].as_ref())),
                               Value {
                                   content: vec![],
                                   entry_version: 1,
                               });
                    assert!(entries.get([6].as_ref()).is_none());
                    assert_eq!(*unwrap!(entries.get([7].as_ref())),
                               Value {
                                   content: vec![],
                                   entry_version: 1,
                               });

                    Ok::<_, CoreError>(())
                })
        })
    }
}
