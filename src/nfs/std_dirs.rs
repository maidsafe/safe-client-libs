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


use core::{Client, DIR_TAG, FutureExt};
// [#use_macros]
use futures::{Future, future};
use maidsafe_utilities::serialisation::serialise;
use nfs::{DEFAULT_PRIVATE_DIRS, DEFAULT_PUBLIC_DIRS, NfsError, NfsFuture};
use nfs::dir::create_dir;
use routing::{EntryAction, Value};
use std::collections::BTreeMap;

/// A registration helper function to create the set of default dirs
/// in the users root directory.
/// Note: It does not check whether those might exits already.
pub fn create_std_dirs(client: Client) -> Box<NfsFuture<()>> {
    let root_dir = fry!(client.user_root_dir());
    let mut creations = vec![];
    for _ in DEFAULT_PRIVATE_DIRS.iter() {
        creations.push(create_dir(&client, false))
    }
    for _ in DEFAULT_PUBLIC_DIRS.iter() {
        creations.push(create_dir(&client, true))
    }

    future::join_all(creations)
        .and_then(move |results| {
            // let results = fry!(res);
            let mut actions = BTreeMap::new();
            for (dir, name) in results.iter().zip(DEFAULT_PRIVATE_DIRS.iter()
                .chain(DEFAULT_PUBLIC_DIRS.iter())) {
                let serialised_dir = fry!(serialise(dir));
                let encrypted_key = fry!(root_dir.enc_entry_key(Vec::from(name.clone())));
                let encrypted_value = fry!(root_dir.enc_entry_value(serialised_dir));
                let _ = actions.insert(encrypted_key,
                                       EntryAction::Ins(Value {
                                           content: encrypted_value,
                                           entry_version: 0,
                                       }));
            }
            client.mutate_mdata_entries(root_dir.name, DIR_TAG, actions)
                .map_err(NfsError::from)
                .into_box()
        })
        .into_box()
}



#[cfg(test)]
mod tests {
    use core::DIR_TAG;
    use core::utility::test_utils::{finish, random_client};
    use futures::Future;
    use nfs::{DEFAULT_PRIVATE_DIRS, DEFAULT_PUBLIC_DIRS};
    use super::*;

    #[test]
    fn creates_default_dirs() {
        random_client(move |client| {
            let cl2 = client.clone();
            create_std_dirs(client.clone()).then(move |res| {
                let _ = unwrap!(res);
                let root_dir = unwrap!(cl2.user_root_dir());
                cl2.list_mdata_entries(root_dir.name, DIR_TAG)
                    .then(move |mdata_entries| {
                        let root_mdata = unwrap!(mdata_entries);
                        assert_eq!(root_mdata.len(),
                                   DEFAULT_PUBLIC_DIRS.len() + DEFAULT_PRIVATE_DIRS.len());
                        for key in DEFAULT_PUBLIC_DIRS.iter().chain(DEFAULT_PRIVATE_DIRS.iter()) {
                            // let's check whether all our entires have been created properly
                            let enc_key = root_dir.enc_entry_key(Vec::from(key.clone())).unwrap();
                            assert_ne!(enc_key, Vec::from(key.clone()));
                            assert_eq!(root_mdata.contains_key(&enc_key), true);
                            assert_ne!(root_mdata.contains_key(&Vec::from(key.clone())), true);
                        }
                        finish()
                    })
            })
        });
    }
}
