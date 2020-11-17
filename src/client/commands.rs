use bincode::serialize;
use bytes::Bytes;
use sn_data_types::{
    Cmd, DataCmd, DebitAgreementProof, Message, PublicKey, Sequence, SequenceAddress,
    SequenceEntry, SequenceWrite, Signature,
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

    /// Generate a network Command message to append an entry to a Sequence.
    /// Public or private isn't important for append. You can append to either
    /// (though the data you append will be Public or Private).
    /// The payment proof obtained from the network for this operation also needs
    /// to be supplied since this is a write operation.
    pub async fn generate_append_to_sequence_cmd(
        &mut self,
        address: SequenceAddress,
        entry: SequenceEntry,
        payment: DebitAgreementProof,
    ) -> Result<(Message, Bytes), ClientError> {
        // First we fetch it so we can get the causality info,
        // either from local CRDT replica or from the network if not found
        // FIXME: this is currently using the Client's default key for the signature
        // ...perhaps we need the user to get the Sequence first, to refresh/update the
        // local replica, and then here we simply use the local replica always
        let mut sequence = self.get_sequence(address).await?;

        // We can now generate the append operation
        let op = sequence.create_append_op(entry)?;

        let cmd = DataCmd::Sequence(SequenceWrite::Edit(op));

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
