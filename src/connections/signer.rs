// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::Error;
use futures::lock::Mutex;
use sn_data_types::{Keypair, PublicKey, Signature};
use std::sync::Arc;

#[derive(Clone)]
pub struct Signer {
    keypair: Arc<Mutex<Keypair>>,
    public_key: PublicKey,
}

impl Signer {
    pub fn new(keypair: Keypair) -> Self {
        let public_key = keypair.public_key();
        Self {
            keypair: Arc::new(Mutex::new(keypair)),
            public_key,
        }
    }

    pub fn public_key(&self) -> PublicKey {
        self.public_key
    }

    pub async fn sign(&self, data: &[u8]) -> Result<Signature, Error> {
        Ok(self.keypair.lock().await.sign(data))
    }
}
