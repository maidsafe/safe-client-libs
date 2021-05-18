// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use sn_data_types::TransferAgreementProof;
use sn_transfers::ActorEvent;

use crate::{Client, Error};

/// Handle Write API msg_contents for a given Client.
impl Client {
    /// Apply a successfull payment locally after TransferRegistration has been sent to the network.
    pub(crate) async fn apply_write_payment_to_local_actor(
        &self,
        debit_proof: TransferAgreementProof,
    ) -> Result<(), Error> {
        let mut actor = self.transfer_actor.lock().await;
        // First register with local actor, then reply.
        let register_event = actor
            .register(debit_proof.clone())?
            .ok_or(Error::NoTransferEventsForLocalActor)?;

        actor.apply(ActorEvent::TransferRegistrationSent(register_event))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{errors::TransfersError, utils::test_utils::create_test_client_with};
    use anyhow::{bail, Result};
    use rand::rngs::OsRng;
    use sn_data_types::{Keypair, Sequence};
    use xor_name::XorName;

    #[cfg(feature = "simulated-payouts")]
    #[tokio::test]
    pub async fn transfer_actor_with_no_balance_cannot_store_data() -> Result<()> {
        let keypair = Keypair::new_ed25519(&mut OsRng);
        let authority = keypair.public_key();
        let data = Sequence::new_public(
            authority,
            authority.to_string(),
            XorName::random(),
            33323,
            None,
        );

        let initial_actor = create_test_client_with(Some(keypair)).await?;

        match initial_actor.pay_and_write_sequence_to_network(data).await {
            Err(Error::Transfer(TransfersError::InsufficientBalance)) => Ok(()),
            res => bail!(
                "Unexpected response from mutation msg_content from 0 balance key: {:?}",
                res
            ),
        }
    }
}
