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


use core::{Client, CoreError, CoreFuture, DEFAULT_PRIVATE_DIRS, DEFAULT_PUBLIC_DIRS, DIR_TAG,
           FutureExt};
//[#use_macros]
use futures::{Future, future};
use maidsafe_utilities::serialisation::serialise;
use routing::{EntryAction, Value};
use std::collections::BTreeMap;


pub fn create_std_dirs(client: Client) -> Box<CoreFuture<()>> {
    if let Some(root_dir) = client.user_root_dir() {

        let mut creations = vec![];
        for _ in DEFAULT_PRIVATE_DIRS.iter() {
            creations.push(client.create_new_dir(false))
        }
        for _ in DEFAULT_PUBLIC_DIRS.iter() {
            creations.push(client.create_new_dir(true))
        }

        future::join_all(creations)
            .then(move |res| {
                let results = res.unwrap();
                let mut actions = BTreeMap::new();
                for (idx, name) in DEFAULT_PRIVATE_DIRS.iter()
                    .chain(DEFAULT_PUBLIC_DIRS.iter())
                    .enumerate() {
                    let dir = results.get(idx).unwrap();
                    let _ = actions.insert(root_dir.encrypt_key(Vec::from(name.clone())).unwrap(),
                                           EntryAction::Ins(Value {
                                               content:
                                                   root_dir.encrypt_value(serialise(dir).unwrap())
                                                   .unwrap(),
                                               entry_version: 0,
                                           }));
                }
                client.mutate_mdata_entries(root_dir.name, DIR_TAG, actions)
            })
            .into_box()
    } else {
        err!(CoreError::OperationForbiddenForClient)
    }

}



#[cfg(test)]
mod tests {
    use core::{DEFAULT_PRIVATE_DIRS, DEFAULT_PUBLIC_DIRS, DIR_TAG};
    use core::utility::test_utils::{finish, random_client};
    use futures::Future;
    use super::*;

    #[test]
    fn creates_default_dirs() {
        random_client(move |client| {
            let cl2 = client.clone();
            create_std_dirs(client.clone()).then(move |_| {
                let root_dir = cl2.user_root_dir().unwrap();
                cl2.list_mdata_entries(root_dir.name, DIR_TAG)
                    .then(move |mdata_entries| {
                        let root_mdata = mdata_entries.unwrap();
                        assert_eq!(root_mdata.len(),
                                   DEFAULT_PUBLIC_DIRS.len() + DEFAULT_PRIVATE_DIRS.len());
                        for key in DEFAULT_PUBLIC_DIRS.iter().chain(DEFAULT_PRIVATE_DIRS.iter()) {
                            // let's check whether all our entires have been created properly
                            let enc_key = root_dir.encrypt_key(Vec::from(key.clone())).unwrap();
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
