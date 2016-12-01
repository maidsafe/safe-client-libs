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


use core::{Client, CoreError, DIR_TAG, Dir, FutureExt};
// [#use_macros]
use futures::Future;
use nfs::{NfsError, NfsFuture};
use routing::MutableData;
use std::collections::{BTreeMap, BTreeSet};

/// create a new directory emulation
pub fn create_dir(client: &Client, is_public: bool) -> Box<NfsFuture<Dir>> {
    match client.owner_sign_key() {
        Ok(pub_key) => {
            let dir = Dir::random(DIR_TAG, is_public);
            let mut owners = BTreeSet::new();
            owners.insert(pub_key);
            let dir_md = fry!(MutableData::new(dir.name,
                                               dir.type_tag,
                                               BTreeMap::new(),
                                               BTreeMap::new(),
                                               owners)
                .map_err(CoreError::from));
            client.put_mdata(dir_md)
                .and_then(|()| Ok(dir))
                .map_err(NfsError::from)
                .into_box()
        }
        Err(err) => err!(NfsError::from(err)).into_box(),
    }
}
