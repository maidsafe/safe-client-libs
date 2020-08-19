// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::errors::CoreError;
use crate::Client;
use log::trace;
use safe_nd::{
    Cmd, DataCmd, DataQuery, DebitAgreementProof, PublicKey, Query, QueryResponse, Sequence,
    SequenceAction, SequenceAddress, SequenceEntries, SequenceEntry, SequenceIndex, SequenceOwner,
    SequencePrivUserPermissions, SequencePrivatePermissions, SequencePubUserPermissions,
    SequencePublicPermissions, SequenceRead, SequenceUser, SequenceUserPermissions, SequenceWrite,
    SequenceWriteOp,
};
use std::collections::BTreeMap;
use xor_name::XorName;

fn wrap_seq_read(read: SequenceRead) -> Query {
    Query::Data(DataQuery::Sequence(read))
}

fn wrap_seq_write(write: SequenceWrite, payment: DebitAgreementProof) -> Cmd {
    Cmd::Data {
        cmd: DataCmd::Sequence(write),
        payment,
    }
}

impl Client {
    /// Mutate sequence data owners
    pub async fn set_sequence_owner(
        &mut self,
        op: SequenceWriteOp<SequenceOwner>,
    ) -> Result<(), CoreError> {
        // --------------------------
        // Payment for PUT
        // --------------------------
        let payment_proof = self.create_write_payment_proof().await?;

        //---------------------------------
        // The _actual_ message
        //---------------------------------
        let msg_contents = wrap_seq_write(SequenceWrite::SetOwner(op), payment_proof.clone());
        let message = Self::create_cmd_message(msg_contents);
        let _ = self.connection_manager.send_cmd(&message).await?;

        self.apply_write_payment_to_local_actor(payment_proof).await
    }

    /// Mutate sequenced data private permissions
    /// Wraps msg_contents for payment validation and mutation
    pub async fn edit_sequence_private_perms(
        &mut self,
        op: SequenceWriteOp<SequencePrivatePermissions>,
    ) -> Result<(), CoreError> {
        // --------------------------
        // Payment for PUT
        // --------------------------
        let payment_proof = self.create_write_payment_proof().await?;

        //---------------------------------
        // The _actual_ message
        //---------------------------------
        let msg_contents = wrap_seq_write(
            SequenceWrite::SetPrivatePermissions(op),
            payment_proof.clone(),
        );
        let message = Self::create_cmd_message(msg_contents);
        let _ = self.connection_manager.send_cmd(&message).await?;

        self.apply_write_payment_to_local_actor(payment_proof).await
    }

    /// Mutate sequenced data public permissions
    /// Wraps msg_contents for payment validation and mutation
    pub async fn edit_sequence_public_perms(
        &mut self,
        op: SequenceWriteOp<SequencePublicPermissions>,
    ) -> Result<(), CoreError> {
        // --------------------------
        // Payment for PUT
        // --------------------------
        let payment_proof = self.create_write_payment_proof().await?;

        //---------------------------------
        // The _actual_ message
        //---------------------------------
        let msg_contents = wrap_seq_write(
            SequenceWrite::SetPublicPermissions(op),
            payment_proof.clone(),
        );
        let message = Self::create_cmd_message(msg_contents);
        let _ = self.connection_manager.send_cmd(&message).await?;

        self.apply_write_payment_to_local_actor(payment_proof).await
    }

    /// Append data to a sequenced data object
    /// Wraps msg_contents for payment validation and mutation
    pub async fn append_to_sequence(
        &mut self,
        op: SequenceWriteOp<Vec<u8>>,
    ) -> Result<(), CoreError> {
        // --------------------------
        // Payment for PUT
        // --------------------------
        let payment_proof = self.create_write_payment_proof().await?;

        //---------------------------------
        // The _actual_ message
        //---------------------------------
        let msg_contents = wrap_seq_write(SequenceWrite::Edit(op), payment_proof.clone());
        let message = Self::create_cmd_message(msg_contents);
        let _ = self.connection_manager.send_cmd(&message).await?;

        self.apply_write_payment_to_local_actor(payment_proof).await
    }

    /// Store a new public sequenced data object
    /// Wraps msg_contents for payment validation and mutation
    pub async fn new_sequence(&mut self, data: Sequence) -> Result<(), CoreError> {
        // --------------------------
        // Payment for PUT
        // --------------------------
        let payment_proof = self.create_write_payment_proof().await?;

        //---------------------------------
        // The _actual_ message
        //---------------------------------
        let msg_contents = wrap_seq_write(SequenceWrite::New(data), payment_proof.clone());
        let message = Self::create_cmd_message(msg_contents);
        let _ = self.connection_manager.send_cmd(&message).await?;

        self.apply_write_payment_to_local_actor(payment_proof).await
    }

    /// Delete sequence
    pub async fn delete_sequence(&mut self, address: SequenceAddress) -> Result<(), CoreError> {
        // --------------------------
        // Payment for PUT
        // --------------------------
        let payment_proof = self.create_write_payment_proof().await?;

        //---------------------------------
        // The _actual_ message
        //---------------------------------
        let msg_contents = wrap_seq_write(SequenceWrite::Delete(address), payment_proof.clone());
        let message = Self::create_cmd_message(msg_contents);
        let _ = self.connection_manager.send_cmd(&message).await?;

        self.apply_write_payment_to_local_actor(payment_proof).await
    }

    // ======= Sequence Data =======
    //
    /// Store Private Sequence Data into the Network
    async fn store_private_sequence(
        &mut self,
        name: XorName,
        tag: u64,
        owner: PublicKey,
        permissions: BTreeMap<PublicKey, SequencePrivUserPermissions>,
    ) -> Result<SequenceAddress, CoreError> {
        trace!("Store Private Sequence Data {:?}", name);
        let mut data = Sequence::new_private(self.public_key().await, name, tag);
        let address = *data.address();
        let _ = data.set_private_permissions(permissions)?;
        let _ = data.set_owner(owner);

        self.new_sequence(data.clone()).await?;

        // Store in local Sequence CRDT replica
        let _ = self.sequence_cache.lock().await.put(*data.address(), data);

        Ok(address)
    }

    /// Store Public Sequence Data into the Network
    async fn store_pub_sequence(
        &mut self,
        name: XorName,
        tag: u64,
        owner: PublicKey,
        permissions: BTreeMap<SequenceUser, SequencePubUserPermissions>,
    ) -> Result<SequenceAddress, CoreError> {
        trace!("Store Public Sequence Data {:?}", name);
        let mut data = Sequence::new_pub(self.public_key().await, name, tag);
        let address = *data.address();
        let _ = data.set_pub_permissions(permissions)?;
        let _ = data.set_owner(owner);

        self.new_sequence(data.clone()).await?;

        // Store in local Sequence CRDT replica
        let _ = self.sequence_cache.lock().await.put(*data.address(), data);

        Ok(address)
    }

    /// Get Sequence Data from the Network
    async fn get_sequence(&mut self, address: SequenceAddress) -> Result<Sequence, CoreError> {
        trace!("Get Sequence Data at {:?}", address.name());
        // First try to fetch it from local CRDT replica
        // TODO: implement some logic to refresh data from the network if local replica
        // is too old, to mitigate the risk of successfully apply mutations locally but which
        // can fail on other replicas, e.g. due to being out of sync with permissions/owner
        if let Some(sequence) = self.sequence_cache.lock().await.get(&address) {
            trace!("Sequence found in local CRDT replica");
            return Ok(sequence.clone());
        }

        trace!("Sequence not found in local CRDT replica");
        // Let's fetch it from the network then
        let sequence = match self
            .send_query(wrap_seq_read(SequenceRead::Get(address)))
            .await?
        {
            QueryResponse::GetSequence(res) => res.map_err(CoreError::from),
            _ => Err(CoreError::ReceivedUnexpectedEvent),
        }?;

        trace!("Store Sequence in local CRDT replica");
        // Store in local Sequence CRDT replica
        let _ = self
            .sequence_cache
            .lock()
            .await
            .put(*sequence.address(), sequence.clone());

        Ok(sequence)
    }

    /// Get the last data entry from a Sequence Data.
    async fn get_sequence_last_entry(
        &mut self,
        address: SequenceAddress,
    ) -> Result<(u64, SequenceEntry), CoreError> {
        trace!(
            "Get latest entry from Sequence Data at {:?}",
            address.name()
        );

        let sequence = self.get_sequence(address).await?;
        match sequence.last_entry() {
            Some(entry) => Ok((sequence.entries_index() - 1, entry.to_vec())),
            None => Err(CoreError::from(safe_nd::Error::NoSuchEntry)),
        }
    }

    /// Get a set of Entries for the requested range from a Sequence.
    async fn get_sequence_range(
        &mut self,
        address: SequenceAddress,
        range: (SequenceIndex, SequenceIndex),
    ) -> Result<SequenceEntries, CoreError> {
        trace!(
            "Get range of entries from Sequence Data at {:?}",
            address.name()
        );

        let sequence = self.get_sequence(address).await?;
        sequence
            .in_range(range.0, range.1)
            .ok_or_else(|| CoreError::from(safe_nd::Error::NoSuchEntry))
    }

    /// Append to Sequence Data
    async fn sequence_append(
        &mut self,
        address: SequenceAddress,
        entry: SequenceEntry,
    ) -> Result<(), CoreError> {
        // First we fetch it so we can get the causality info,
        // either from local CRDT replica or from the network if not found
        let mut sequence = self.get_sequence(address).await?;

        // We do a permissions check just to make sure it won't fail when the operation
        // is broadcasted to the network, assuming our replica is in sync and up to date
        // with the permissions and ownership information compared with the replicas on the network.
        sequence.check_permission(SequenceAction::Append, self.public_id().await.public_key())?;

        // We can now append the entry to the Sequence
        let op = sequence.append(entry);

        // Update the local Sequence CRDT replica
        let _ = self
            .sequence_cache
            .lock()
            .await
            .put(*sequence.address(), sequence.clone());
        // Finally we can send the mutation to the network's replicas
        self.append_to_sequence(op).await
    }

    /// Get the set of Permissions of a Public Sequence.
    async fn get_sequence_pub_permissions(
        &mut self,
        address: SequenceAddress,
    ) -> Result<SequencePublicPermissions, CoreError> {
        trace!(
            "Get permissions from Public Sequence Data at {:?}",
            address.name()
        );

        // TODO: perhaps we want to grab it directly from the network and update local replica
        let sequence = self.get_sequence(address).await?;
        let perms = sequence
            .pub_permissions(sequence.permissions_index() - 1)
            .map_err(CoreError::from)?;

        Ok(perms.clone())
    }

    /// Get the set of Permissions of a Private Sequence.
    async fn get_sequence_private_permissions(
        &mut self,
        address: SequenceAddress,
    ) -> Result<SequencePrivatePermissions, CoreError> {
        trace!(
            "Get permissions from Private Sequence Data at {:?}",
            address.name()
        );

        // TODO: perhaps we want to grab it directly from the network and update local replica
        let sequence = self.get_sequence(address).await?;
        let perms = sequence
            .private_permissions(sequence.permissions_index() - 1)
            .map_err(CoreError::from)?;

        Ok(perms.clone())
    }

    /// Get the set of Permissions for a specific user in a Sequence.
    async fn get_sequence_user_permissions(
        &mut self,
        address: SequenceAddress,
        user: SequenceUser,
    ) -> Result<SequenceUserPermissions, CoreError> {
        trace!(
            "Get permissions for user {:?} from Sequence Data at {:?}",
            user,
            address.name()
        );

        // TODO: perhaps we want to grab it directly from the network and update local replica
        let sequence = self.get_sequence(address).await?;
        let perms = sequence
            .user_permissions(user, sequence.permissions_index() - 1)
            .map_err(CoreError::from)?;

        Ok(perms)
    }

    /// Set permissions to Public Sequence Data
    async fn sequence_set_pub_permissions(
        &mut self,
        address: SequenceAddress,
        permissions: BTreeMap<SequenceUser, SequencePubUserPermissions>,
    ) -> Result<(), CoreError> {
        // First we fetch it either from local CRDT replica or from the network if not found
        let mut sequence = self.get_sequence(address).await?;

        // We do a permissions check just to make sure it won't fail when the operation
        // is broadcasted to the network, assuming our replica is in sync and up to date
        // with the permissions information compared with the replicas on the network.
        sequence.check_permission(
            SequenceAction::ManagePermissions,
            self.public_id().await.public_key(),
        )?;

        // We can now set the new permissions to the Sequence
        let op = sequence.set_pub_permissions(permissions)?;

        // Update the local Sequence CRDT replica
        let _ = self
            .sequence_cache
            .lock()
            .await
            .put(*sequence.address(), sequence.clone());

        // Finally we can send the mutation to the network's replicas
        self.edit_sequence_public_perms(op).await
    }

    /// Set permissions to Private Sequence Data
    async fn sequence_set_private_permissions(
        &mut self,
        address: SequenceAddress,
        permissions: BTreeMap<PublicKey, SequencePrivUserPermissions>,
    ) -> Result<(), CoreError> {
        // First we fetch it either from local CRDT replica or from the network if not found
        let mut sequence = self.get_sequence(address).await?;

        // We do a permissions check just to make sure it won't fail when the operation
        // is broadcasted to the network, assuming our replica is in sync and up to date
        // with the permissions information compared with the replicas on the network.
        // TODO: if it fails, try to sync-up perms with rmeote replicas and try once more
        sequence.check_permission(
            SequenceAction::ManagePermissions,
            self.public_id().await.public_key(),
        )?;

        // We can now set the new permissions to the Sequence
        let op = sequence.set_private_permissions(permissions)?;

        // Update the local Sequence CRDT replica
        let _ = self
            .sequence_cache
            .lock()
            .await
            .put(*sequence.address(), sequence.clone());

        // Finally we can send the mutation to the network's replicas
        self.edit_sequence_private_perms(op).await
    }

    /// Get the owner of a Sequence.
    async fn get_sequence_owner(
        &mut self,
        address: SequenceAddress,
    ) -> Result<SequenceOwner, CoreError> {
        trace!("Get owner of the Sequence Data at {:?}", address.name());

        // TODO: perhaps we want to grab it directly from the network and update local replica
        let sequence = self.get_sequence(address).await?;
        let owner = sequence.owner(sequence.owners_index() - 1).ok_or_else(|| {
            CoreError::from("Unexpectedly failed to obtain current owner of Sequence")
        })?;

        Ok(*owner)
    }

    /// Set the new owner of a Sequence Data
    async fn sequence_set_owner(
        &mut self,
        address: SequenceAddress,
        owner: PublicKey,
    ) -> Result<(), CoreError> {
        // First we fetch it either from local CRDT replica or from the network if not found
        let mut sequence = self.get_sequence(address).await?;

        // We do a permissions check just to make sure it won't fail when the operation
        // is broadcasted to the network, assuming our replica is in sync and up to date
        // with the ownership information compared with the replicas on the network.
        sequence.check_permission(
            SequenceAction::ManagePermissions,
            self.public_id().await.public_key(),
        )?;

        // We can now set the new owner to the Sequence
        let op = sequence.set_owner(owner);

        // Update the local Sequence CRDT replica
        let _ = self
            .sequence_cache
            .lock()
            .await
            .put(*sequence.address(), sequence.clone());

        // Finally we can send the mutation to the network's replicas
        self.set_sequence_owner(op).await
    }

    // ========== END of Sequence Data functions =========
}

#[allow(missing_docs)]
#[cfg(any(test, feature = "simulated-payouts"))]
pub mod exported_tests {
    use super::*;
    use crate::utils::test_utils::gen_bls_keypair;
    use safe_nd::{Error as SndError, Money, SequencePrivUserPermissions};
    use std::str::FromStr;
    use unwrap::unwrap;
    use xor_name::XorName;

    pub async fn sequence_deletions_should_cost_put_price() -> Result<(), CoreError> {
        let name = XorName(rand::random());
        let tag = 10;
        let mut client = Client::new(None).await?;
        let owner = client.public_key().await;
        let perms = BTreeMap::<PublicKey, SequencePrivUserPermissions>::new();
        let sequence_address = client
            .store_private_sequence(name, tag, owner, perms)
            .await?;

        let balance_before_delete = client.get_balance(None).await?;
        client.delete_sequence(sequence_address).await?;
        let new_balance = client.get_balance(None).await?;

        // make sure we have _some_ balance
        assert_ne!(balance_before_delete, Money::from_str("0")?);
        assert_ne!(balance_before_delete, new_balance);

        Ok(())
    }

    /// Sequence data tests ///

    pub async fn sequence_basics_test() -> Result<(), CoreError> {
        let mut client = Client::new(None).await?;

        let name = XorName(rand::random());
        let tag = 15000;
        let owner = client.public_key().await;

        // store a Private Sequence
        let mut perms = BTreeMap::<PublicKey, SequencePrivUserPermissions>::new();
        let _ = perms.insert(owner, SequencePrivUserPermissions::new(true, true, true));
        let address = client
            .store_private_sequence(name, tag, owner, perms)
            .await?;
        let sequence = client.get_sequence(address).await?;
        assert!(sequence.is_private());
        assert_eq!(*sequence.name(), name);
        assert_eq!(sequence.tag(), tag);
        assert_eq!(sequence.permissions_index(), 1);
        assert_eq!(sequence.owners_index(), 1);
        assert_eq!(sequence.entries_index(), 0);

        // store a Public Sequence
        let mut perms = BTreeMap::<SequenceUser, SequencePubUserPermissions>::new();
        let _ = perms.insert(
            SequenceUser::Anyone,
            SequencePubUserPermissions::new(true, true),
        );
        let address = client.store_pub_sequence(name, tag, owner, perms).await?;
        let sequence = client.get_sequence(address).await?;
        assert!(sequence.is_pub());
        assert_eq!(*sequence.name(), name);
        assert_eq!(sequence.tag(), tag);
        assert_eq!(sequence.permissions_index(), 1);
        assert_eq!(sequence.owners_index(), 1);
        assert_eq!(sequence.entries_index(), 0);

        Ok(())
    }

    pub async fn sequence_private_permissions_test() -> Result<(), CoreError> {
        let mut client = Client::new(None).await?;

        let name = XorName(rand::random());
        let tag = 15000;
        let owner = client.public_key().await;
        let mut perms = BTreeMap::<PublicKey, SequencePrivUserPermissions>::new();
        let _ = perms.insert(owner, SequencePrivUserPermissions::new(true, true, true));
        let address = client
            .store_private_sequence(name, tag, owner, perms)
            .await?;

        let data = client.get_sequence(address).await?;
        assert_eq!(data.entries_index(), 0);
        assert_eq!(data.owners_index(), 1);
        assert_eq!(data.permissions_index(), 1);

        let private_permissions = client.get_sequence_private_permissions(address).await?;
        let user_perms = private_permissions
            .permissions
            .get(&owner)
            .ok_or_else(|| CoreError::from("Unexpectedly failed to get user permissions"))?;
        assert!(user_perms.is_allowed(SequenceAction::Read));
        assert!(user_perms.is_allowed(SequenceAction::Append));
        assert!(user_perms.is_allowed(SequenceAction::ManagePermissions));

        match client
            .get_sequence_user_permissions(address, SequenceUser::Key(owner))
            .await?
        {
            SequenceUserPermissions::Priv(user_perms) => {
                assert!(user_perms.is_allowed(SequenceAction::Read));
                assert!(user_perms.is_allowed(SequenceAction::Append));
                assert!(user_perms.is_allowed(SequenceAction::ManagePermissions));
            }
            SequenceUserPermissions::Public(_) => {
                return Err(CoreError::from(
                    "Unexpectedly obtained incorrect user permissions",
                ))
            }
        }

        let sim_client = gen_bls_keypair().public_key();
        let mut perms2 = BTreeMap::<PublicKey, SequencePrivUserPermissions>::new();
        let _ = perms2.insert(
            sim_client,
            SequencePrivUserPermissions::new(false, true, false),
        );
        client
            .sequence_set_private_permissions(address, perms2)
            .await?;

        let private_permissions = client.get_sequence_private_permissions(address).await?;
        let user_perms = private_permissions
            .permissions
            .get(&sim_client)
            .ok_or_else(|| CoreError::from("Unexpectedly failed to get user permissions"))?;
        assert!(!user_perms.is_allowed(SequenceAction::Read));
        assert!(user_perms.is_allowed(SequenceAction::Append));
        assert!(!user_perms.is_allowed(SequenceAction::ManagePermissions));

        match client
            .get_sequence_user_permissions(address, SequenceUser::Key(sim_client))
            .await?
        {
            SequenceUserPermissions::Priv(user_perms) => {
                assert!(!user_perms.is_allowed(SequenceAction::Read));
                assert!(user_perms.is_allowed(SequenceAction::Append));
                assert!(!user_perms.is_allowed(SequenceAction::ManagePermissions));
                Ok(())
            }
            SequenceUserPermissions::Public(_) => Err(CoreError::from(
                "Unexpectedly obtained incorrect user permissions",
            )),
        }
    }

    pub async fn sequence_pub_permissions_test() -> Result<(), CoreError> {
        let mut client = Client::new(None).await?;

        let name = XorName(rand::random());
        let tag = 15000;
        let owner = client.public_key().await;
        let mut perms = BTreeMap::<SequenceUser, SequencePubUserPermissions>::new();
        let _ = perms.insert(
            SequenceUser::Key(owner),
            SequencePubUserPermissions::new(None, true),
        );
        let address = client.store_pub_sequence(name, tag, owner, perms).await?;

        let data = client.get_sequence(address).await?;
        assert_eq!(data.entries_index(), 0);
        assert_eq!(data.owners_index(), 1);
        assert_eq!(data.permissions_index(), 1);

        let pub_permissions = client.get_sequence_pub_permissions(address).await?;
        let user_perms = pub_permissions
            .permissions
            .get(&SequenceUser::Key(owner))
            .ok_or_else(|| CoreError::from("Unexpectedly failed to get user permissions"))?;
        assert_eq!(Some(true), user_perms.is_allowed(SequenceAction::Read));
        assert_eq!(None, user_perms.is_allowed(SequenceAction::Append));
        assert_eq!(
            Some(true),
            user_perms.is_allowed(SequenceAction::ManagePermissions)
        );

        match client
            .get_sequence_user_permissions(address, SequenceUser::Key(owner))
            .await?
        {
            SequenceUserPermissions::Public(user_perms) => {
                assert_eq!(Some(true), user_perms.is_allowed(SequenceAction::Read));
                assert_eq!(None, user_perms.is_allowed(SequenceAction::Append));
                assert_eq!(
                    Some(true),
                    user_perms.is_allowed(SequenceAction::ManagePermissions)
                );
            }
            SequenceUserPermissions::Priv(_) => {
                return Err(CoreError::from(
                    "Unexpectedly obtained incorrect user permissions",
                ))
            }
        }

        let sim_client = gen_bls_keypair().public_key();
        let mut perms2 = BTreeMap::<SequenceUser, SequencePubUserPermissions>::new();
        let _ = perms2.insert(
            SequenceUser::Key(sim_client),
            SequencePubUserPermissions::new(false, false),
        );
        client.sequence_set_pub_permissions(address, perms2).await?;

        let pub_permissions = client.get_sequence_pub_permissions(address).await?;
        let user_perms = pub_permissions
            .permissions
            .get(&SequenceUser::Key(sim_client))
            .ok_or_else(|| CoreError::from("Unexpectedly failed to get user permissions"))?;
        assert_eq!(Some(true), user_perms.is_allowed(SequenceAction::Read));
        assert_eq!(Some(false), user_perms.is_allowed(SequenceAction::Append));
        assert_eq!(
            Some(false),
            user_perms.is_allowed(SequenceAction::ManagePermissions)
        );

        match client
            .get_sequence_user_permissions(address, SequenceUser::Key(sim_client))
            .await?
        {
            SequenceUserPermissions::Public(user_perms) => {
                assert_eq!(Some(true), user_perms.is_allowed(SequenceAction::Read));
                assert_eq!(Some(false), user_perms.is_allowed(SequenceAction::Append));
                assert_eq!(
                    Some(false),
                    user_perms.is_allowed(SequenceAction::ManagePermissions)
                );
                Ok(())
            }
            SequenceUserPermissions::Priv(_) => Err(CoreError::from(
                "Unexpectedly obtained incorrect user permissions",
            )),
        }
    }

    pub async fn sequence_append_test() -> Result<(), CoreError> {
        let name = XorName(rand::random());
        let tag = 10;
        let mut client = Client::new(None).await?;

        let owner = client.public_key().await;
        let mut perms = BTreeMap::<SequenceUser, SequencePubUserPermissions>::new();
        let _ = perms.insert(
            SequenceUser::Key(owner),
            SequencePubUserPermissions::new(true, true),
        );
        let address = client.store_pub_sequence(name, tag, owner, perms).await?;

        client.sequence_append(address, b"VALUE1".to_vec()).await?;

        let (index, data) = client.get_sequence_last_entry(address).await?;
        assert_eq!(0, index);
        assert_eq!(unwrap!(std::str::from_utf8(&data)), "VALUE1");

        client.sequence_append(address, b"VALUE2".to_vec()).await?;

        let (index, data) = client.get_sequence_last_entry(address).await?;
        assert_eq!(1, index);
        assert_eq!(unwrap!(std::str::from_utf8(&data)), "VALUE2");

        let data = client
            .get_sequence_range(
                address,
                (SequenceIndex::FromStart(0), SequenceIndex::FromEnd(0)),
            )
            .await?;
        assert_eq!(unwrap!(std::str::from_utf8(&data[0])), "VALUE1");
        assert_eq!(unwrap!(std::str::from_utf8(&data[1])), "VALUE2");

        Ok(())
    }

    pub async fn sequence_owner_test() -> Result<(), CoreError> {
        let name = XorName(rand::random());
        let tag = 10;
        let mut client = Client::new(None).await?;

        let owner = client.public_key().await;
        let mut perms = BTreeMap::<PublicKey, SequencePrivUserPermissions>::new();
        let _ = perms.insert(owner, SequencePrivUserPermissions::new(true, true, true));
        let address = client
            .store_private_sequence(name, tag, owner, perms)
            .await?;

        client.sequence_append(address, b"VALUE1".to_vec()).await?;
        client.sequence_append(address, b"VALUE2".to_vec()).await?;

        let data = client.get_sequence(address).await?;
        assert_eq!(data.entries_index(), 2);
        assert_eq!(data.owners_index(), 1);
        assert_eq!(data.permissions_index(), 1);

        let current_owner = client.get_sequence_owner(address).await?;
        assert_eq!(owner, current_owner.public_key);

        let sim_client = gen_bls_keypair().public_key();
        client.sequence_set_owner(address, sim_client).await?;

        let current_owner = client.get_sequence_owner(address).await?;
        assert_eq!(sim_client, current_owner.public_key);

        Ok(())
    }

    pub async fn sequence_can_delete_private_test() -> Result<(), CoreError> {
        let mut client = Client::new(None).await?;

        let name = XorName(rand::random());
        let tag = 15000;
        let owner = client.public_key().await;

        // store a Private Sequence
        let mut perms = BTreeMap::<PublicKey, SequencePrivUserPermissions>::new();
        let _ = perms.insert(owner, SequencePrivUserPermissions::new(true, true, true));
        let address = client
            .store_private_sequence(name, tag, owner, perms)
            .await?;
        let sequence = client.get_sequence(address).await?;
        assert!(sequence.is_private());

        client.delete_sequence(address).await?;

        match client.get_sequence(address).await {
            Err(CoreError::DataError(SndError::NoSuchData)) => Ok(()),
            Err(err) => {
                return Err(CoreError::from(format!(
                    "Unexpected error returned when deleting a nonexisting Private Sequence: {}",
                    err
                )))
            }
            Ok(_res) => {
                return Err(CoreError::from(
                    "Unexpectedly retrieved a deleted Private Sequence!",
                ))
            }
        }
    }

    pub async fn sequence_cannot_delete_public_test() -> Result<(), CoreError> {
        let mut client = Client::new(None).await?;

        let name = XorName(rand::random());
        let tag = 15000;
        let owner = client.public_key().await;

        // store a Public Sequence
        let mut perms = BTreeMap::<SequenceUser, SequencePubUserPermissions>::new();
        let _ = perms.insert(
            SequenceUser::Anyone,
            SequencePubUserPermissions::new(true, true),
        );
        let address = client.store_pub_sequence(name, tag, owner, perms).await?;
        let sequence = client.get_sequence(address).await?;
        assert!(sequence.is_pub());

        client.delete_sequence(address).await?;

        // Check that our data still exists.
        match client.get_sequence(address).await {
            Err(CoreError::DataError(SndError::InvalidOperation)) => Ok(()),
            Err(err) => {
                return Err(CoreError::from(format!(
                    "Unexpected error returned when attempting to get a Public Sequence: {}",
                    err
                )))
            }
            Ok(_data) => Ok(()),
        }
    }
}

#[allow(missing_docs)]
#[cfg(any(test, feature = "simulated-payouts"))]
mod tests {
    use super::exported_tests;
    use super::CoreError;

    #[tokio::test]
    async fn sequence_deletions_should_cost_put_price() -> Result<(), CoreError> {
        exported_tests::sequence_deletions_should_cost_put_price().await
    }

    #[tokio::test]
    async fn sequence_basics_test() -> Result<(), CoreError> {
        exported_tests::sequence_basics_test().await
    }

    #[tokio::test]
    async fn sequence_private_permissions_test() -> Result<(), CoreError> {
        exported_tests::sequence_private_permissions_test().await
    }

    #[tokio::test]
    async fn sequence_pub_permissions_test() -> Result<(), CoreError> {
        exported_tests::sequence_pub_permissions_test().await
    }

    #[tokio::test]
    async fn sequence_append_test() -> Result<(), CoreError> {
        exported_tests::sequence_append_test().await
    }

    #[tokio::test]
    async fn sequence_owner_test() -> Result<(), CoreError> {
        exported_tests::sequence_owner_test().await
    }

    #[tokio::test]
    async fn sequence_can_delete_private_test() -> Result<(), CoreError> {
        exported_tests::sequence_can_delete_private_test().await
    }

    #[tokio::test]
    async fn sequence_cannot_delete_public_test() -> Result<(), CoreError> {
        exported_tests::sequence_cannot_delete_public_test().await
    }
}
