use bincode::serialize;
use bytes::Bytes;
use sn_data_types::{
    Cmd, DataCmd, DebitAgreementProof, Message, PublicKey, Sequence, SequenceAddress,
    SequenceWrite, Signature,
};
use xor_name::XorName;

use crate::client::Client;
use crate::errors::ClientError;

use log::trace;

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

        // Store in local CRDT replica if the Command corresponds to a CRDT op
        //let _ = self.sequence_cache.lock().await.put(*data.address(), data);

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
        let msg_contents = Cmd::Data { cmd, payment };
        let msg = Self::create_cmd_message(msg_contents);

        let msg_bytes = Bytes::from(serialize(&msg)?);

        Ok((msg, msg_bytes, address))
    }
}
