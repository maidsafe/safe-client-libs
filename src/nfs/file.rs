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

use self_encryption;
use std::fmt;
use nfs::metadata::Metadata;

#[derive(RustcEncodable, RustcDecodable, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct File {
    metadata: Metadata,
    datamap: self_encryption::datamap::DataMap
}

impl File {
    pub fn new(metadata: Metadata, datamap: self_encryption::datamap::DataMap) -> File {
        File {
            metadata: metadata,
            datamap: datamap
        }
    }

    pub fn get_name(&self) -> &String {
        self.get_metadata().get_name()
    }
    pub fn get_metadata(&self) -> &Metadata {
        &self.metadata
    }

    pub fn get_mut_metadata(&mut self) -> &mut Metadata {
        &mut self.metadata
    }

    pub fn get_datamap(&self) -> &self_encryption::datamap::DataMap {
        &self.datamap
    }

    pub fn set_datamap(&mut self, datamap: self_encryption::datamap::DataMap) {
        self.datamap = datamap;
    }

}

impl fmt::Debug for File {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "metadata: {}", self.get_metadata())
    }
}

impl fmt::Display for File {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "metadata: {}", self.get_metadata())
    }
}


#[cfg(test)]
mod test {
    use super::*;
    use self_encryption;
    use cbor;
    use nfs::metadata::Metadata;

    #[test]
    fn serialise() {
        let obj_before = File::new(Metadata::new("Home".to_string(),
             "{mime:\"application/json\"}".to_string().into_bytes()),
              self_encryption::datamap::DataMap::None);

        let mut e = cbor::Encoder::from_memory();
        e.encode(&[&obj_before]).unwrap();

        let mut d = cbor::Decoder::from_bytes(e.as_bytes());
        let obj_after: File = d.decode().next().unwrap().unwrap();

        assert_eq!(obj_before, obj_after);
    }
}
