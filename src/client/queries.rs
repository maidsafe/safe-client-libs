use bincode::serialize;
use bytes::Bytes;
use sn_data_types::Message;
use sn_data_types::{PublicKey, Query, QueryResponse, Signature, TransferQuery};

use crate::client::Client;
use crate::errors::ClientError;

use log::info;

/// Handle all Money transfers and Write API requests for a given ClientId.
impl Client {
    /// Send a signed Query Message to the network, serialising it and including
    /// the provided public key and signature as the origin of the message,
    /// and awaiting for a response from the network.
    pub async fn send_signed_query_msg(
        &mut self,
        msg: &Message,
        pk: PublicKey,
        signature: Signature,
    ) -> Result<QueryResponse, ClientError> {
        let msg_bytes = self
            .connection_manager
            .lock()
            .await
            .serialise_in_envelope(msg, Some((pk, signature)))?;

        self.connection_manager
            .lock()
            .await
            .send_signed_query(msg_bytes)
            .await
    }

    /// Generate a network Query message to get the current balance for
    /// this TransferActor PK (by default) or any other...
    pub async fn generate_balance_query_msg(
        &mut self,
        pk: Option<PublicKey>,
    ) -> Result<(Message, Bytes), ClientError> {
        let public_key = pk.unwrap_or(self.public_key().await);
        info!("Generating Query message to get balance for {:?}", pk);

        let msg_contents = Query::Transfer(TransferQuery::GetBalance(public_key));

        let msg = Self::create_query_message(msg_contents);

        let msg_bytes = Bytes::from(serialize(&msg)?);

        Ok((msg, msg_bytes))
    }
}

#[allow(missing_docs)]
#[cfg(any(test, feature = "simulated-payouts", feature = "testing"))]
pub mod exported_tests {
    use super::*;
    use rand::rngs::OsRng;
    use sn_data_types::{Keypair, Money};
    use std::str::FromStr;

    // 1. Create a client A w/10 Money by default.
    // 2. Generate balance query message.
    // 3. Sign and send query message.
    // 4. Assert Client A's balance is correct.
    pub async fn test_get_balance() -> Result<(), ClientError> {
        let mut client = Client::new(None, None).await?;
        let mut rng = OsRng;
        let keypair = Keypair::new_ed25519(&mut rng);

        let (msg, msg_bytes) = client
            .generate_balance_query_msg(Some(keypair.public_key()))
            .await?;

        // sign message with client's pk
        let signature = keypair.sign(&msg_bytes);

        // send signed message to the network
        let balance = match client
            .send_signed_query_msg(&msg, keypair.public_key(), signature)
            .await
        {
            Ok(QueryResponse::GetBalance(balance)) => balance.map_err(ClientError::from),
            _ => Err(ClientError::from(
                "Unexpected response when querying balance",
            )),
        }?;

        // Assert if client's money is correct.
        assert_eq!(balance, Money::from_str("10")?);

        Ok(())
    }
}

#[allow(missing_docs)]
#[cfg(any(test, feature = "simulated-payouts"))]
mod tests {
    #[cfg(test)]
    use super::exported_tests;
    #[cfg(test)]
    use super::ClientError;

    #[tokio::test]
    async fn test_get_balance() -> Result<(), ClientError> {
        exported_tests::test_get_balance().await
    }
}
