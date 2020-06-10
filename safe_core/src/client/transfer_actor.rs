use safe_nd::{
    AData, ADataAddress, ADataAppendOperation, ADataEntries, ADataEntry, ADataIndex, ADataIndices,
    ADataOwner, ADataPermissions, ADataPubPermissionSet, ADataPubPermissions, ADataRequest,
    ADataUnpubPermissionSet, ADataUnpubPermissions, ADataUser, AppPermissions, ClientFullId,
    ClientRequest, DebitAgreementProof, IData, IDataAddress, IDataRequest, LoginPacket,
    LoginPacketRequest, MData, MDataAddress, MDataEntries, MDataEntryActions, MDataPermissionSet,
    MDataRequest, MDataSeqEntries, MDataSeqEntryActions, MDataSeqValue, MDataUnseqEntryActions,
    MDataValue, MDataValues, Message, MessageId, Money, MoneyRequest, PublicId, PublicKey, Request,
    RequestType, Response, SeqMutableData, Transfer, TransferRegistered, UnseqMutableData, XorName,
};
use safe_transfers::{ReplicaValidator, TransferActor as SafeTransferActor};

use crate::client::ConnectionManager;
use crate::client::{sign_request, Client, SafeKey};
use crate::errors::CoreError;
use crdts::Dot;
use futures::channel::mpsc;
use futures::stream::StreamExt;
use log::trace;
use rand::thread_rng;
use std::collections::HashMap;
use std::iter::Iterator;
use std::str::FromStr;

use threshold_crypto::{SecretKey, SecretKeySet};

fn get_history() {
    // DO THINGS
}

fn build_transfer(from: Dot<PublicKey>, to: PublicKey, amount: Money) -> Transfer {
    Transfer {
        id: from,
        to,
        amount,
    }
}

#[derive(Clone, Debug)]
pub struct TransferActor {
    transfer_actor: SafeTransferActor<ClientTransferValidator>,

    // Todo, do we need this Arc for clonability? When are we cloinging
    pending_validations: HashMap<MessageId, mpsc::UnboundedSender<DebitAgreementProof>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientTransferValidator {}

impl ReplicaValidator for ClientTransferValidator {
    fn is_valid(&self, _replica_group: PublicKey) -> bool {
        true
    }
}

/// Handle all transfers and messaging around transfers for a given client.
impl TransferActor {
    pub async fn new(
        validator: ClientTransferValidator,
        safe_key: SafeKey,
        _cm: ConnectionManager,
    ) -> Result<Self, CoreError> {
        // we need transfer history and to pass this into account.

        // TODO: Better handling of client...
        let _balance = get_history();

        // fake bls keyset for our "replica", which currently doesn't exist locally or do anything if it did.
        let bls_secret_key = SecretKeySet::random(1, &mut thread_rng());
        let replicas_id = bls_secret_key.public_keys();

        // let new_balance = Money::from_nano(10 );

        let _sender = Dot::new(PublicKey::from(SecretKey::random().public_key()), 0);

        // let new_balance_owner = client_id.public_id().public_key();

        // TODO: fake initial transfer.... This history will need to be in sync with _actual_ replicas eventually
        // let transfer = build_transfer(sender, new_balance_owner, new_balance);

        // TODO: actually send this transfer....

        // replica validator on client is more os less bunk (for now). Everything is validated at the section. Here
        // we _could_ do basic balance check validations for example...

        // TODO: Handle this error when None... would this ever be None?
        let transfer_actor = SafeTransferActor::new(safe_key, replicas_id, validator);
        // .ok_or(CoreError::from("Safe Transfers Actor could not be instantiated".to_string()))?;
        let pending_validations: HashMap<MessageId, mpsc::UnboundedSender<DebitAgreementProof>> =
            HashMap::new();
        Ok(Self {
            transfer_actor,
            pending_validations,
        })
    }

    // TODO get_local_balance
    // is SafeKey needed here for an actor?
    // Send as vs use this need to be sorted ooooot
    pub fn get_local_balance(&self, _safe_key: SafeKey) -> Result<Money, CoreError> {
        Ok(self.transfer_actor.balance())
    }

    pub fn receive(&mut self, response: Response, message_id: &MessageId) -> Result<(), CoreError> {
        let validation = match response {
            Response::TransferValidation(res) => res?,
            _ => {
                return Err(CoreError::from(format!(
                    "Unexpected response received at TransferActor, {:?}",
                    response
                )))
            }
        };

        // TODO: where should we handle this error? On receive. Or via send?
        let transfer_validation = self.transfer_actor.receive(validation)?;

        // if we have a proof, lets send it back to our waiting send func...
        if let Some(proof) = transfer_validation.proof {
            let mut sender = self
                .pending_validations
                .remove(message_id)
                .ok_or(CoreError::from(
                    "No pending validation found for debit proof.",
                ))?;
            sender.unbounded_send(proof);
            sender.disconnect()
        };

        Ok(())
    }

    /// Get the current coin balance.
    async fn get_balance_from_network(
        client_id: &ClientFullId,
        cm: &mut ConnectionManager,
    ) -> Result<Money, CoreError>
    where
        Self: Sized,
    {
        // first get history and rehydrate

        trace!("Get balance for {:?}", client_id);

        let identity = SafeKey::client(client_id.clone());
        let pub_id = identity.public_id();

        // let xorname = *pub_id.name();
        let message = sign_request(
            Request::Money(MoneyRequest::GetBalance(pub_id.public_key())),
            &client_id.clone(),
        );

        let _bootstrapped = cm.bootstrap(identity).await;

        // This is a normal response manager request. We want quorum on this for now...
        let _res = cm.send(&pub_id, &message).await?;

        // TODO return actual things..
        Ok(Money::from_str("10")?)
    }

    // TODO: remove need for passing cm
    /// Send money as....
    pub async fn send_money_as(
        &mut self,
        safe_key: SafeKey,
        mut cm: ConnectionManager,
        to: PublicKey,
        amount: Money,
    ) -> Result<Response, CoreError> {
        //set up message
        let message_id = MessageId::new();

        let signed_transfer = self.transfer_actor.transfer(amount, to)?.signed_transfer;
        let request = Request::Money(MoneyRequest::ValidateTransfer { signed_transfer });

        // TODO: remove this unwrap
        let signature = Some(safe_key.sign(&unwrap::unwrap!(bincode::serialize(&(
            &request, message_id
        )))));

        let message = Message::Request {
            request,
            message_id: message_id.clone(),
            signature,
        };

        let pub_id = safe_key.public_id();

        let _bootstrapped = cm.bootstrap(safe_key.clone()).await;

        let proof: DebitAgreementProof = self
            .await_validation(message_id, &pub_id, &message, cm.clone())
            .await?;

        // register the transaction now
        let registration_message_id = MessageId::new();

        let register_transaction_request = Request::Money(MoneyRequest::RegisterTransfer { proof });

        let register_signature = Some(safe_key.sign(&unwrap::unwrap!(bincode::serialize(&(
            &register_transaction_request,
            registration_message_id
        )))));
        let message = Message::Request {
            request: register_transaction_request,
            message_id: registration_message_id.clone(),
            signature: register_signature,
        };

        cm.send(&pub_id, &message).await
    }

    /// Send message and await validation and constructin of DebitAgreementProof
    async fn await_validation(
        &mut self,
        message_id: MessageId,
        pub_id: &PublicId,
        message: &Message,
        mut cm: ConnectionManager,
    ) -> Result<DebitAgreementProof, CoreError> {
        let (sender, mut receiver) = mpsc::unbounded::<DebitAgreementProof>();

        self.pending_validations.insert(message_id, sender);

        cm.send_for_validation(&pub_id, &message, self).await?;

        match receiver.next().await {
            Some(res) => Ok(res),
            None => Err(CoreError::from(
                "No debit proof returned from client transfer actor.",
            )),
        }
    }
}

// TODO: start setting up some tests for this.
// update response_manager test for this case....
// THEN: Try out an integration test w/ core
// ensure actor is created there.

#[cfg(test)]
mod tests {

    // use rand::seq::SliceRandom;
    // use rand::thread_rng;
    use crate::client::attempt_bootstrap;
    use crate::config_handler::Config;

    use super::*;

    #[tokio::test]
    async fn transfer_actor_creation() {
        let mut rng = rand::thread_rng();
        let client_safe_key = SafeKey::client(ClientFullId::new_ed25519(&mut rng));

        let (net_sender, _net_receiver) = mpsc::unbounded();
        //net_tx ?
        // let on_network_event =
        //     |net_event| trace!("Unexpected NetworkEvent occurred: {:?}", net_event);

        // Create the connection manager
        let connection_manager = attempt_bootstrap(
            &Config::new().quic_p2p,
            &net_sender,
            client_safe_key.clone(),
        )
        .await
        .unwrap();

        let validator = ClientTransferValidator {};
        // Here for now, Actor with 10 setup, as before
        // transfer actor handles all our responses and proof aggregation
        let _transfer_actor =
            TransferActor::new(validator, client_safe_key, connection_manager.clone())
                .await
                .unwrap();
    }
}
