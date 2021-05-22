// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::Client;
use crate::errors::Error;
use log::debug;
use sn_data_types::{PublicKey, Signature};
use sn_messaging::client::{ClientSigned, Cmd};

impl Client {
    /// Send a Cmd to the network
    pub(crate) async fn send_signed_command(
        &self,
        cmd: Cmd,
        client_pk: PublicKey,
        signature: Signature,
    ) -> Result<(), Error> {
        debug!("Sending Cmd: {:?}", cmd);
        let client_signed = ClientSigned {
            public_key: client_pk,
            signature,
        };

        self.session.send_cmd(cmd, client_signed).await
    }

    // Send a Cmd to the network without awaiting for a response.
    // This function is a helper private to this module.
    pub(crate) async fn send_cmd(&self, cmd: Cmd) -> Result<(), Error> {
        let client_pk = self.public_key();
        let signature = self.keypair.sign(b"TODO");

        self.send_signed_command(cmd, client_pk, signature).await
    }
}
