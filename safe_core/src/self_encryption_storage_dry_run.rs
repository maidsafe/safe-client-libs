// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::self_encryption_storage::SelfEncryptionStorageError;
use super::CoreError;
use futures::{self, Future};
use safe_nd::{IData, PubImmutableData, PublicKey, UnpubImmutableData};
use self_encryption::Storage;
use threshold_crypto::SecretKey;

/// Network storage is the concrete type which self-encryption crate will use
/// to put or get data from the network.
pub struct SelfEncryptionStorageDryRun {
    published: bool,
}

impl SelfEncryptionStorageDryRun {
    /// Create a new SelfEncryptionStorageDryRun instance.
    pub fn new(published: bool) -> Self {
        Self { published }
    }
}

impl Storage for SelfEncryptionStorageDryRun {
    type Error = SelfEncryptionStorageError;

    fn get(&self, _name: &[u8]) -> Box<dyn Future<Item = Vec<u8>, Error = Self::Error>> {
        trace!("Self encrypt invoked GetIData dry run.");
        let err = CoreError::Unexpected("Cannot get from storage since it's a dry run.".to_owned());
        let err = SelfEncryptionStorageError::from(err);
        Box::new(futures::failed(err))
    }

    fn put(
        &mut self,
        _: Vec<u8>,
        _data: Vec<u8>,
    ) -> Box<dyn Future<Item = (), Error = Self::Error>> {
        trace!("Self encrypt invoked PutIData dry run.");
        let err = CoreError::Unexpected("Cannot put to storage since it's a dry run.".to_owned());
        let err = SelfEncryptionStorageError::from(err);
        Box::new(futures::failed(err))
    }

    fn generate_address(&self, data: &[u8]) -> Vec<u8> {
        let idata: IData = if self.published {
            PubImmutableData::new(data.to_vec()).into()
        } else {
            let pk = PublicKey::Bls(SecretKey::random().public_key());
            UnpubImmutableData::new(data.to_vec(), pk).into()
        };
        idata.name().0.to_vec()
    }
}
