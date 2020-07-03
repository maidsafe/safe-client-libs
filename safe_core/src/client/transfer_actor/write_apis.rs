use safe_nd::{
    DebitAgreementProof, IData, IDataRequest, LoginPacket, LoginPacketRequest, MData, MDataAddress,
    MDataEntryActions, MDataPermissionSet, MDataRequest, Money, MoneyRequest, PublicKey, Request,
    Response, SData, SDataMutationOperation, SDataOwner, SDataPrivPermissions, SDataPubPermissions,
    SDataRequest,
};
use safe_transfers::ActorEvent;

use crate::client::TransferActor;
use crate::errors::CoreError;
use log::info;

/// Handle Write API requests for a given TransferActor.
impl TransferActor {
    /// Creates passed login packet for a new account
    pub async fn create_login_for(
        &mut self,
        new_owner: PublicKey,
        amount: Money,
        login_packet: LoginPacket,
    ) -> Result<Response, CoreError> {
        let _cm = self.connection_manager();

        let mut cm = self.connection_manager();

        //set up message
        let safe_key = self.safe_key.clone();
        info!(
            "Create login for: Sending money from {:?}, to {:?}",
            safe_key.public_key(),
            new_owner
        );

        // -------------------------------------------
        //  Setup our transfer _to_ the new account.
        // -------------------------------------------

        // --------------------------
        // Payment for PUT
        // --------------------------
        let payment_proof = self.create_put_payment_proof().await?;

        // First: Lets make a req for the amount we want to transfer (almost certainly more than PUT cost)
        let signed_transfer = self
            .transfer_actor
            .lock()
            .await
            .transfer(amount, new_owner)?
            .signed_transfer;

        let request = Request::Money(MoneyRequest::ValidateTransfer { signed_transfer });

        let (transfer_message, message_id) = self.create_network_message(request)?;

        // setup connection manager
        let _bootstrapped = cm.bootstrap(safe_key.clone()).await;

        // #[cfg(feature = "mock-network")]
        // {
        //     // no waiting on validation needed for mock
        //     return cm.send(&pub_id, &message).await;
        // }

        let transfer_to_account_debit_proof: DebitAgreementProof = self
            .await_validation(message_id, &safe_key.public_id(), &transfer_message)
            .await?;

        //---------------------------------
        // Finally do the _actual_ request
        //---------------------------------

        let login_packet_for_req = Request::LoginPacket(LoginPacketRequest::CreateFor {
            new_owner,
            // TODO: this is a temp clone here to get reqs going. This needs to be two different debits
            optional_debit_proof: Some(transfer_to_account_debit_proof.clone()),
            new_login_packet: login_packet,
            debit_proof: payment_proof.clone(),
        });

        let (message, _msg_id) = self.create_network_message(login_packet_for_req)?;

        let response = cm.send(&self.safe_key.public_id(), &message).await?;

        self.apply_success_write_locally(response, payment_proof)
            .await
    }

    /// Delete mutable data user permission
    pub async fn mutable_data_del_user_permissions(
        &mut self,
        address: MDataAddress,
        user: PublicKey,
        version: u64,
    ) -> Result<Response, CoreError> {
        let mut cm = self.connection_manager();

        // --------------------------
        // Payment for PUT
        // --------------------------
        let payment_proof = self.create_put_payment_proof().await?;

        //---------------------------------
        // The _actual_ request
        //---------------------------------

        let req = Request::MData(MDataRequest::DelUserPermissions {
            address,
            user,
            version,
            debit_proof: payment_proof.clone(),
        });

        let (message, _msg_id) = self.create_network_message(req)?;

        let response = cm.send(&self.safe_key.public_id(), &message).await?;

        self.apply_success_write_locally(response, payment_proof)
            .await
    }

    /// Set mutable data user permissions
    pub async fn mutable_data_set_user_permissions(
        &mut self,
        address: MDataAddress,
        user: PublicKey,
        permissions: MDataPermissionSet,
        version: u64,
    ) -> Result<Response, CoreError> {
        let mut cm = self.connection_manager();

        // --------------------------
        // Payment for PUT
        // --------------------------
        let payment_proof = self.create_put_payment_proof().await?;

        //---------------------------------
        // The _actual_ request
        //---------------------------------

        let req = Request::MData(MDataRequest::SetUserPermissions {
            address,
            user,
            permissions,
            version,
            debit_proof: payment_proof.clone(),
        });

        let (message, _msg_id) = self.create_network_message(req)?;

        // TODO what will be the correct reponse here?... We have it validated, so registered?
        let response = cm.send(&self.safe_key.public_id(), &message).await?;

        self.apply_success_write_locally(response, payment_proof)
            .await
    }

    /// Mutate mutable data user entries
    pub async fn mutable_data_mutate_entries(
        &mut self,
        address: MDataAddress,
        actions: MDataEntryActions,
    ) -> Result<Response, CoreError> {
        let mut cm = self.connection_manager();

        // --------------------------
        // Payment for PUT
        // --------------------------
        let payment_proof = self.create_put_payment_proof().await?;

        //---------------------------------
        // The _actual_ request
        //---------------------------------

        let req = Request::MData(MDataRequest::MutateEntries {
            address,
            actions,
            debit_proof: payment_proof.clone(),
        });

        let (message, _msg_id) = self.create_network_message(req)?;

        let response = cm.send(&self.safe_key.public_id(), &message).await?;

        self.apply_success_write_locally(response, payment_proof)
            .await
    }

    /// Mutate sequence data owners
    pub async fn sequenced_data_mutate_owner(
        &mut self,
        op: SDataMutationOperation<SDataOwner>,
    ) -> Result<Response, CoreError> {
        let mut cm = self.connection_manager();

        // --------------------------
        // Payment for PUT
        // --------------------------
        let payment_proof = self.create_put_payment_proof().await?;

        //---------------------------------
        // The _actual_ request
        //---------------------------------

        let req = Request::SData(SDataRequest::MutateOwner {
            op,
            debit_proof: payment_proof.clone(),
        });

        let (message, _msg_id) = self.create_network_message(req)?;

        let response = cm.send(&self.safe_key.public_id(), &message).await?;

        self.apply_success_write_locally(response, payment_proof)
            .await
    }

    /// Mutate sequenced data private permissions
    /// Wraps requests for payment validation and mutation
    pub async fn sequenced_data_mutate_priv_permissions(
        &mut self,
        op: SDataMutationOperation<SDataPrivPermissions>,
    ) -> Result<Response, CoreError> {
        let mut cm = self.connection_manager();

        // --------------------------
        // Payment for PUT
        // --------------------------
        let payment_proof = self.create_put_payment_proof().await?;

        //---------------------------------
        // The _actual_ request
        //---------------------------------

        let req = Request::SData(SDataRequest::MutatePrivPermissions {
            op,
            debit_proof: payment_proof.clone(),
        });

        let (message, _msg_id) = self.create_network_message(req)?;

        let response = cm.send(&self.safe_key.public_id(), &message).await?;

        self.apply_success_write_locally(response, payment_proof)
            .await
    }

    /// Mutate sequenced data public permissions
    /// Wraps requests for payment validation and mutation
    pub async fn sequenced_data_mutate_pub_permissions(
        &mut self,
        op: SDataMutationOperation<SDataPubPermissions>,
    ) -> Result<Response, CoreError> {
        let mut cm = self.connection_manager();

        // --------------------------
        // Payment for PUT
        // --------------------------
        let payment_proof = self.create_put_payment_proof().await?;

        //---------------------------------
        // The _actual_ request
        //---------------------------------

        let req = Request::SData(SDataRequest::MutatePubPermissions {
            op,
            debit_proof: payment_proof.clone(),
        });

        let (message, _msg_id) = self.create_network_message(req)?;

        let response = cm.send(&self.safe_key.public_id(), &message).await?;

        self.apply_success_write_locally(response, payment_proof)
            .await
    }

    /// Append data to a sequenced data object
    /// Wraps requests for payment validation and mutation
    pub async fn sequenced_data_append(
        &mut self,
        op: SDataMutationOperation<Vec<u8>>,
    ) -> Result<Response, CoreError> {
        let mut cm = self.connection_manager();

        // --------------------------
        // Payment for PUT
        // --------------------------
        let payment_proof = self.create_put_payment_proof().await?;

        //---------------------------------
        // The _actual_ request
        //---------------------------------
        let req = Request::SData(SDataRequest::Mutate {
            op,
            debit_proof: payment_proof.clone(),
        });
        let (message, _msg_id) = self.create_network_message(req)?;
        let response = cm.send(&self.safe_key.public_id(), &message).await?;

        self.apply_success_write_locally(response, payment_proof)
            .await
    }

    /// Store a new public sequenced data object
    /// Wraps requests for payment validation and mutation
    pub async fn store_sequenced_data(&mut self, data: SData) -> Result<Response, CoreError> {
        let mut cm = self.connection_manager();

        // --------------------------
        // Payment for PUT
        // --------------------------
        let payment_proof = self.create_put_payment_proof().await?;

        //---------------------------------
        // The _actual_ request
        //---------------------------------
        let req = Request::SData(SDataRequest::Store {
            data,
            debit_proof: payment_proof.clone(),
        });
        let (message, _msg_id) = self.create_network_message(req)?;
        let response = cm.send(&self.safe_key.public_id(), &message).await?;

        self.apply_success_write_locally(response, payment_proof)
            .await
    }

    /// Store a new public mutable data object
    /// Wraps requests for payment validation and mutation
    pub async fn store_mutable_data(&mut self, data: MData) -> Result<Response, CoreError> {
        let mut cm = self.connection_manager();

        // --------------------------
        // Payment for PUT
        // --------------------------
        let payment_proof = self.create_put_payment_proof().await?;

        //---------------------------------
        // The _actual_ request
        //---------------------------------
        let req = Request::MData(MDataRequest::Put {
            data,
            debit_proof: payment_proof.clone(),
        });
        let (message, _msg_id) = self.create_network_message(req)?;
        let response = cm.send(&self.safe_key.public_id(), &message).await?;
        println!("STORE MD COME IN..... response: {:?}", response);
        self.apply_success_write_locally(response, payment_proof)
            .await
    }

    /// Store a new immutabledata object
    /// Wraps requests for payment validation and mutation
    pub async fn store_immutable_data(&mut self, data: IData) -> Result<Response, CoreError> {
        let mut cm = self.connection_manager();

        // --------------------------
        // Payment for PUT
        // --------------------------
        let payment_proof = self.create_put_payment_proof().await?;

        //---------------------------------
        // The _actual_ request
        //---------------------------------
        let req = Request::IData(IDataRequest::Put {
            data,
            debit_proof: payment_proof.clone(),
        });
        let (message, _msg_id) = self.create_network_message(req)?;
        let response = cm.send(&self.safe_key.public_id(), &message).await?;

        self.apply_success_write_locally(response, payment_proof)
            .await
    }

    /// Store a new login packet
    /// Wraps requests for payment validation and mutation
    pub async fn store_login_packet(
        &mut self,
        login_packet: LoginPacket,
    ) -> Result<Response, CoreError> {
        info!("Store login packet");
        let mut cm = self.connection_manager();

        // --------------------------
        // Payment for PUT
        // --------------------------
        let payment_proof = self.create_put_payment_proof().await?;

        //---------------------------------
        // The _actual_ request
        //---------------------------------
        let req = Request::LoginPacket(LoginPacketRequest::Create {
            login_packet,
            debit_proof: payment_proof.clone(),
        });

        let (message, _msg_id) = self.create_network_message(req)?;

        let response = cm.send(&self.safe_key.public_id(), &message).await?;

        self.apply_success_write_locally(response, payment_proof)
            .await
    }

    async fn apply_success_write_locally(
        &mut self,
        response: Response,
        debit_proof: DebitAgreementProof,
    ) -> Result<Response, CoreError> {
        match response.clone() {
            Response::Mutation(result) => {
                let mut actor = self.transfer_actor.lock().await;
                // First register with local actor, then reply.
                let register_event = actor.register(debit_proof.clone())?;

                actor.apply(ActorEvent::TransferRegistrationSent(register_event));

                Ok(response)
            }
            _ => Err(CoreError::from(format!(
                "Unexpected response received for write request: {:?}",
                response
            ))),
        }
    }
}

// TODO: Do we need "new" to actually instantiate with a transfer?...
#[cfg(all(test, feature = "simulated-payouts"))]
mod tests {

    use super::*;
    use crate::client::transfer_actor::test_utils::get_keys_and_connection_manager;
    use safe_nd::{Error as SndError, XorName};

    #[tokio::test]
    #[cfg(feature = "simulated-payouts")]
    async fn transfer_actor_with_no_balance_cannot_store_data() -> Result<(), CoreError> {
        let (safe_key, cm) = get_keys_and_connection_manager().await;

        let data = SData::new_pub(safe_key.public_key(), XorName::default(), 33323);

        let mut initial_actor =
            TransferActor::new_no_initial_balance(safe_key.clone(), cm.clone()).await?;

        match initial_actor.store_sequenced_data(data).await {
            Err(CoreError::DataError(e)) => {
                assert_eq!(e.to_string(), "Not enough money to complete this operation");
            }
            res => panic!(
                "Unexpected response from mutation request from 0 balance key: {:?}",
                res
            ),
        }

        Ok(())
    }
}
