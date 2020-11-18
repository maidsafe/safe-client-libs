use bincode::serialize;
use bytes::Bytes;
use sn_data_types::{
    Cmd, DataCmd, DebitAgreementProof, Message, PublicKey, Sequence, SequenceAddress,
    SequenceEntry, SequenceWrite, Signature, SequenceDataWriteOp
};
use xor_name::XorName;

use crate::client::Client;
use crate::errors::ClientError;

use log::{info, trace};

/// Handle all Money transfers and Write API requests for a given ClientId.
impl Client {
    /// Send a signed Command Message to the network, serialising it and including
    /// the provided public key and signature as the origin of the message,
    /// without awaiting for a response.
    pub async fn send_signed_cmd_msg(
        &mut self,
        msg: &Message,
        pk: PublicKey,
        signature: Signature,
    ) -> Result<(), ClientError> {
        let msg_bytes = self
            .connection_manager
            .lock()
            .await
            .serialise_in_envelope(msg, Some((pk, signature)))?;

        self.connection_manager
            .lock()
            .await
            .send_signed_cmd(msg_bytes)
            .await?;

        // Store/update in local CRDT replica if the Command corresponds to a CRDT op
        if let Message::Cmd {
            cmd:
                Cmd::Data {
                    cmd: DataCmd::Sequence(SequenceWrite::New(data)),
                    ..
                },
            ..
        } = msg
        {
            // Update local Sequence CRDT replica
            let _ = self
                .sequence_cache
                .lock()
                .await
                .put(*data.address(), data.clone());
        }

        Ok(())
    }

    /// Generate a network Command message to create Public Sequence Data.
    /// A tag must be supplied.
    /// A xorname must be supplied, this can be random or deterministic as per your apps needs.
    /// The payment proof obtained from the network for this operation also needs
    /// to be supplied since this is a write operation.
    pub async fn generate_store_pub_sequence_cmd(
        &mut self,
        name: XorName,
        tag: u64,
        payment: DebitAgreementProof,
    ) -> Result<(Message, Bytes, SequenceAddress), ClientError> {
        trace!("Store Public Sequence Data {:?}", name);
        let pk = self.public_key().await;
        let actor = serde_json::to_string(&(pk, self.instance_id.clone()))?;
        let data = Sequence::new_public(pk, actor, name, tag);
        let address = *data.address();

        let cmd = DataCmd::Sequence(SequenceWrite::New(data));

        // The _actual_ message
        let msg_content = Cmd::Data { cmd, payment };
        let (msg, msg_bytes) = Self::create_serialised_cmd_message(msg_content)?;

        Ok((msg, msg_bytes, address))
    }

    /// Generate a network CRDT operation to sign
    pub async fn generate_unsigned_sequence_append_op(
        &mut self,
        address: SequenceAddress,
        entry: SequenceEntry,
    ) -> Result<(SequenceDataWriteOp<SequenceEntry>, Bytes), ClientError> {


        // // First we fetch it so we can get the causality info,
        // // either from local CRDT replica or from the network if not found
        // // FIXME: this is currently using the Client's default key for the signature
        // // ...perhaps we need the user to get the Sequence first, to refresh/update the
        // // local replica, and then here we simply use the local replica always
        let mut sequence = self.get_sequence(address).await?;
        let op = sequence.create_unsigned_append_op(entry)?;

        let bytes = Bytes::from( serialize(&op.crdt_op).map_err(|_| "Could not serialize op")? );

        Ok( ( op, bytes ) )
    }
    
    /// Generate a network Command message to append an entry to a Sequence.
    /// Public or private isn't important for append. You can append to either
    /// (though the data you append will be Public or Private).
    /// The payment proof obtained from the network for this operation also needs
    /// to be supplied since this is a write operation.
    pub async fn generate_append_to_sequence_cmd(
        &mut self,
        payment: DebitAgreementProof,
        signed_op: SequenceDataWriteOp<SequenceEntry>
    ) -> Result<(Message, Bytes), ClientError> {

        if let None = signed_op.signature
        {
            return Err(ClientError::Unexpected("Sequence Op must be signed.".to_string())) ;
        }

        let cmd = DataCmd::Sequence(SequenceWrite::Edit(signed_op));

        // The _actual_ message
        let msg_content = Cmd::Data { cmd, payment };
        Self::create_serialised_cmd_message(msg_content)
    }

    // Private helper to create a Query mesasge and its serialised bytes
    fn create_serialised_cmd_message(msg_content: Cmd) -> Result<(Message, Bytes), ClientError> {
        let msg = Self::create_cmd_message(msg_content);
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
    // 2. Generate a seq
    pub async fn test_send_seq_append() -> Result<(), ClientError> {
        let mut client = Client::new(None, None).await?;
        let mut rng = OsRng;
        let keypair = Keypair::new_ed25519(&mut rng);
        let tag = 43_000u64;

        let payment_proof = self.create_write_payment_proof(&cmd).await?;


        // let (msg, msg_bytes) = client
        //     .generate_store_pub_sequence_cmd(XorName::random(), tag, payment )
        //     .await?;

        // sign message with client's pk
        let signature = keypair.sign(&msg_bytes);

        // // send signed message to the network
        // // let balance = match client
        // //     .send_signed_query_msg(&msg, keypair.public_key(), signature)
        // //     .await
        // // {
        // //     Ok(QueryResponse::GetBalance(balance)) => balance.map_err(ClientError::from),
        // //     _ => Err(ClientError::from(
        // //         "Unexpected response when querying balance",
        // //     )),
        // // }?;

        // // Assert if client's money is correct.
        // assert_eq!(balance, Money::from_str("10")?);

        Ok(())
    }
}
