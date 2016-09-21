// Copyright 2015 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use nfs::AccessLevel;
use routing::XorName;
use rust_sodium::crypto::secretbox;
use std::cmp::Ordering;

/// DirectoryKey represnts the meta information about a directory
/// A directory can be feteched with the DirectoryKey
#[derive(Debug, RustcEncodable, RustcDecodable, PartialEq, Eq, Clone)]
pub struct DirectoryKey {
    id: XorName,
    type_tag: u64,
    versioned: bool,
    secret_key: Option<secretbox::Key>,
}

impl DirectoryKey {
    /// Creates a new instance of DirectoryKey
    pub fn new(directory_id: XorName,
               type_tag: u64,
               versioned: bool,
               secret_key: Option<secretbox::Key>)
               -> DirectoryKey {
        DirectoryKey {
            id: directory_id,
            type_tag: type_tag,
            versioned: versioned,
            secret_key: secret_key,
        }
    }

    /// Returns the id
    pub fn id(&self) -> &XorName {
        &self.id
    }

    /// Returns the type_tag
    pub fn type_tag(&self) -> u64 {
        self.type_tag
    }

    /// Returns true if the directory represented by the key is versioned, else returns false
    pub fn versioned(&self) -> bool {
        self.versioned
    }

    /// Returns the accesslevel of the directory represented by the key
    pub fn access_level(&self) -> AccessLevel {
        match self.secret_key {
            Some(_) => AccessLevel::Private,
            None => AccessLevel::Public,
        }
    }

    /// Returns the secret key used to encrypt/decrypt the directory (if any).
    pub fn secret_key(&self) -> Option<&secretbox::Key> {
        self.secret_key.as_ref()
    }
}

impl Ord for DirectoryKey {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.id, self.type_tag, self.versioned).cmp(&(other.id, other.type_tag, other.versioned))
    }
}

impl PartialOrd for DirectoryKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(test)]
mod test {
    use maidsafe_utilities::serialisation::{deserialise, serialise};
    use nfs::AccessLevel;
    use rand;
    use routing::XorName;
    use rust_sodium::crypto::secretbox;
    use super::*;

    /// Should be able to serialise & deserialise the DirectoryKey
    #[test]
    fn serailise_and_deserialise_directory_key() {
        let id: XorName = rand::random();
        let tag = 10u64;
        let versioned = false;
        let secret_key = Some(secretbox::gen_key());

        let directory_key = DirectoryKey::new(id, tag, versioned, secret_key.clone());

        let serialised = unwrap!(serialise(&directory_key));
        let deserilaised_key: DirectoryKey = unwrap!(deserialise(&serialised));
        assert_eq!(*deserilaised_key.id(), id);
        assert_eq!(deserilaised_key.access_level(), AccessLevel::Private);
        assert_eq!(deserilaised_key.secret_key(), secret_key.as_ref());
        assert_eq!(deserilaised_key.versioned(), versioned);
        assert_eq!(deserilaised_key.type_tag(), tag);
    }
}
