use sn_data_types::TransferAgreementProof;
use sn_transfers::ActorEvent;

use crate::client::Client;
use crate::errors::Error;

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

#[cfg(all(test, feature = "simulated-payouts"))]
pub mod exported_tests {
    use super::*;
    use crate::errors::TransfersError;
    use anyhow::{bail, Result};
    use rand::rngs::OsRng;
    use sn_data_types::{Keypair, Sequence};
    use std::sync::Arc;
    use xor_name::XorName;

    #[cfg(feature = "simulated-payouts")]
    pub async fn transfer_actor_with_no_balance_cannot_store_data() -> Result<()> {
        let keypair = Arc::new(Keypair::new_ed25519(&mut OsRng));
        let pk = keypair.public_key();
        let data = Sequence::new_public(pk, pk.to_string(), XorName::random(), 33323);

        let initial_actor = Client::new(Some(keypair), None).await?;
        match initial_actor.pay_and_write_sequence_to_network(data).await {
            Err(Error::Transfer(TransfersError::InsufficientBalance)) => {
                // Ok(())
                // assert!(e
                //     .to_string()
                //     .contains("Could not get history for key PublicKey"));
            }
            res => bail!(
                "Unexpected response from mutation msg_contentsuest from 0 balance key: {:?}",
                res
            ),
        }

        Ok(())
    }
}

// TODO: Do we need "new" to actually instantiate with a transfer?...
#[cfg(all(test, feature = "simulated-payouts"))]
mod tests {
    use super::exported_tests;
    use anyhow::Result;

    #[tokio::test]
    #[cfg(feature = "simulated-payouts")]
    async fn transfer_actor_with_no_balance_cannot_store_data() -> Result<()> {
        exported_tests::transfer_actor_with_no_balance_cannot_store_data().await
    }
}
