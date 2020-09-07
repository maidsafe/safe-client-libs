use sn_data_types::DebitAgreementProof;
use sn_transfers::ActorEvent;

use crate::client::Client;
use crate::errors::CoreError;

/// Handle Write API msg_contents for a given Client.
impl Client {
    /// Apply a successfull payment locally after TransferRegistration has been sent to the network.
    pub(crate) async fn apply_write_payment_to_local_actor(
        &mut self,
        debit_proof: DebitAgreementProof,
    ) -> Result<(), CoreError> {
        let mut actor = self.transfer_actor.lock().await;
        // First register with local actor, then reply.
        let register_event = actor
            .register(debit_proof.clone())?
            .ok_or_else(|| CoreError::from("No events to register for proof."))?;

        actor.apply(ActorEvent::TransferRegistrationSent(register_event))?;

        Ok(())
    }
}

#[cfg(all(test, feature = "simulated-payouts"))]
pub mod exported_tests {
    use super::*;
    use crate::crypto::shared_box;
    use sn_data_types::{PublicKey, Sequence};
    use xor_name::XorName;

    #[cfg(feature = "simulated-payouts")]
    pub async fn transfer_actor_with_no_balance_cannot_store_data() -> Result<(), CoreError> {
        let (sk, pk) = shared_box::gen_bls_keypair();
        let pk = PublicKey::Bls(pk);

        let data = Sequence::new_pub(pk, XorName::random(), 33323);

        let mut initial_actor = Client::new(Some(sk.clone())).await?;

        match initial_actor.pay_and_write_sequence_to_network(data).await {
            Err(CoreError::DataError(e)) => {
                assert_eq!(e.to_string(), "Not enough money to complete this operation");
            }
            res => panic!(
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
    use super::CoreError;

    #[tokio::test]
    #[cfg(feature = "simulated-payouts")]
    async fn transfer_actor_with_no_balance_cannot_store_data() -> Result<(), CoreError> {
        exported_tests::transfer_actor_with_no_balance_cannot_store_data().await
    }
}
