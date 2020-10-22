// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::errors::ClientError;
use crate::Client;
use log::trace;
use sn_data_types::{
    Cmd, DataCmd, DataQuery, PublicKey, Query, QueryResponse, Sequence, SequenceAction,
    SequenceAddress, SequenceDataWriteOp, SequenceEntries, SequenceEntry, SequenceIndex,
    SequencePermissions, SequencePrivatePermissions, SequencePublicPermissions, SequenceRead,
    SequenceUser, SequenceWrite,
};
use std::collections::BTreeMap;
use xor_name::XorName;

fn wrap_seq_read(read: SequenceRead) -> Query {
    Query::Data(DataQuery::Sequence(read))
}

impl Client {
    //----------------------
    // Write Operations
    //---------------------

    /// Create Private Sequence Data on to the Network
    ///
    /// Creates a private sequence on the network which can be appended to.
    /// Private data can be removed from the network at a later date.
    ///
    /// A tag must be supplied.
    /// A xorname must be supplied, this can be random or deterministic as per your apps needs.
    ///
    /// # Examples
    ///
    /// Store data
    ///
    /// ```no_run
    /// # extern crate tokio; use sn_client::ClientError; use std::str::FromStr;
    /// use sn_client::Client;
    /// use sn_data_types::{ClientFullId, PublicKey, Money, SequencePrivatePermissions};
    /// use std::collections::BTreeMap;
    /// use xor_name::XorName;
    /// use rand::rngs::OsRng;
    /// # #[tokio::main] async fn main() { let _: Result<(), ClientError> = futures::executor::block_on( async {
    /// // Let's use an existing client, with a pre-existing balance to be used for write payments.
    /// let id = ClientFullId::new_ed25519(&mut OsRng);
    /// let mut client = Client::new(Some(id)).await?;
    /// # let initial_balance = Money::from_str("100")?; client.trigger_simulated_farming_payout(initial_balance).await?;
    /// let name = XorName::random();
    /// let tag = 10;
    /// let owner = client.public_key().await;
    /// let mut perms = BTreeMap::<PublicKey, SequencePrivatePermissions>::new();
    ///
    /// // Set the access permissions
    /// let _ = perms.insert(
    ///    owner,
    ///    SequencePrivatePermissions::new(true, true, true),
    /// );
    ///
    /// // The returned address can then be used to `append` data to.
    /// let _address = client.store_private_sequence(None, name, tag, owner, perms).await?;
    /// # let balance_after_write = client.get_local_balance().await; assert_ne!(initial_balance, balance_after_write); Ok(()) } ); }
    /// ```
    pub async fn store_private_sequence(
        &mut self,
        sequence: Option<SequenceEntries>,
        name: XorName,
        tag: u64,
        owner: PublicKey,
        permissions: BTreeMap<PublicKey, SequencePrivatePermissions>,
    ) -> Result<SequenceAddress, ClientError> {
        trace!("Store Private Sequence Data {:?}", name);
        let mut data = Sequence::new_private(owner, name, tag);
        let address = *data.address();
        let _ = data.set_private_policy(owner, permissions)?;

        if let Some(entries) = sequence {
            for entry in entries {
                let _op = data.append(entry);
            }
        }

        self.pay_and_write_sequence_to_network(data.clone()).await?;

        // Store in local Sequence CRDT replica
        let _ = self.sequence_cache.lock().await.put(*data.address(), data);

        Ok(address)
    }

    /// Create Public Sequence Data into the Network
    ///
    /// Creates a public sequence on the network which can be appended to.
    /// Public data can _not_ be removed from the network at a later date.
    ///
    /// A tag must be supplied.
    /// A xorname must be supplied, this can be random or deterministic as per your apps needs.
    ///
    /// # Examples
    ///
    /// Store data
    ///
    /// ```no_run
    /// # extern crate tokio; use sn_client::ClientError; use std::str::FromStr;
    /// use sn_client::Client;
    /// use sn_data_types::{ClientFullId, SequenceUser, Money, SequencePublicPermissions};
    /// use std::collections::BTreeMap;
    /// use xor_name::XorName;
    /// use rand::rngs::OsRng;
    /// # #[tokio::main] async fn main() { let _: Result<(), ClientError> = futures::executor::block_on( async {
    /// // Let's use an existing client, with a pre-existing balance to be used for write payments.
    /// let id = ClientFullId::new_ed25519(&mut OsRng);
    /// let mut client = Client::new(Some(id)).await?;
    /// # let initial_balance = Money::from_str("100")?; client.trigger_simulated_farming_payout(initial_balance).await?;
    /// let name = XorName::random();
    /// let tag = 10;
    /// let owner = client.public_key().await;
    /// let mut perms = BTreeMap::<SequenceUser, SequencePublicPermissions>::new();
    ///
    /// // Set the access permissions
    /// let _ = perms.insert(
    ///    SequenceUser::Key(owner),
    ///    SequencePublicPermissions::new(true, true),
    /// );
    ///
    /// // The returned address can then be used to `append` data to.
    /// let _address = client.store_public_sequence(None, name, tag, owner, perms).await?;
    /// # let balance_after_write = client.get_local_balance().await; assert_ne!(initial_balance, balance_after_write); Ok(()) } ); }
    /// ```
    pub async fn store_public_sequence(
        &mut self,
        sequence: Option<SequenceEntries>,
        name: XorName,
        tag: u64,
        owner: PublicKey,
        permissions: BTreeMap<SequenceUser, SequencePublicPermissions>,
    ) -> Result<SequenceAddress, ClientError> {
        trace!("Store Public Sequence Data {:?}", name);
        let mut data = Sequence::new_public(owner, name, tag);
        let address = *data.address();
        let _ = data.set_public_policy(owner, permissions)?;

        if let Some(entries) = sequence {
            for entry in entries {
                let _op = data.append(entry);
            }
        }

        self.pay_and_write_sequence_to_network(data.clone()).await?;

        // Store in local Sequence CRDT replica
        let _ = self.sequence_cache.lock().await.put(*data.address(), data);

        Ok(address)
    }

    /// Delete sequence
    ///
    /// You're only able to delete a PrivateSequence. Public data can no be removed from the network.
    ///
    /// # Examples
    ///
    /// Delete data
    ///
    /// ```no_run
    /// # extern crate tokio; use sn_client::ClientError; use std::str::FromStr;
    /// use sn_client::Client;
    /// use sn_data_types::{ClientFullId, PublicKey, Money, SequencePrivatePermissions};
    /// use std::collections::BTreeMap;
    /// use xor_name::XorName;
    /// use rand::rngs::OsRng;
    /// # #[tokio::main] async fn main() { let _: Result<(), ClientError> = futures::executor::block_on( async {
    /// // Let's use an existing client, with a pre-existing balance to be used for write payments.
    /// let id = ClientFullId::new_ed25519(&mut OsRng);
    /// let mut client = Client::new(Some(id)).await?;
    /// # let initial_balance = Money::from_str("100")?; client.trigger_simulated_farming_payout(initial_balance).await?;
    /// let name = XorName::random();
    /// let tag = 10;
    /// let owner = client.public_key().await;
    /// let mut perms = BTreeMap::<PublicKey, SequencePrivatePermissions>::new();
    ///
    /// // Set the access permissions
    /// let _ = perms.insert(
    ///    owner,
    ///    SequencePrivatePermissions::new(true, true, true),
    /// );
    ///
    /// // The returned address can then be used to `append` data to.
    /// let address = client.store_private_sequence(None, name, tag, owner, perms).await?;
    ///
    /// client.delete_sequence(address).await?;
    /// # let balance_after_write = client.get_local_balance().await; assert_ne!(initial_balance, balance_after_write); Ok(()) } ); }
    /// ```
    pub async fn delete_sequence(&mut self, address: SequenceAddress) -> Result<(), ClientError> {
        let cmd = DataCmd::Sequence(SequenceWrite::Delete(address));
        // Payment for PUT
        let payment_proof = self.create_write_payment_proof(&cmd).await?;

        // The _actual_ message
        let msg_contents = Cmd::Data {
            cmd,
            payment: payment_proof.clone(),
        };
        let message = Self::create_cmd_message(msg_contents);
        let _ = self
            .connection_manager
            .lock()
            .await
            .send_cmd(&message)
            .await?;

        self.apply_write_payment_to_local_actor(payment_proof).await
    }

    /// Append to Sequence
    ///
    /// Public or private isn't important for append. You can append to either (though the data you append will be Public or Private).
    ///
    /// # Examples
    /// ```no_run
    /// # extern crate tokio; use sn_client::ClientError; use std::str::FromStr;
    /// use sn_client::Client;
    /// use sn_data_types::{ClientFullId, PublicKey, Money, SequencePrivatePermissions};
    /// use std::collections::BTreeMap;
    /// use xor_name::XorName;
    /// use rand::rngs::OsRng;
    /// # #[tokio::main] async fn main() { let _: Result<(), ClientError> = futures::executor::block_on( async {
    /// // Let's use an existing client, with a pre-existing balance to be used for write payments.
    /// let id = ClientFullId::new_ed25519(&mut OsRng);
    /// let mut client = Client::new(Some(id)).await?;
    /// # let initial_balance = Money::from_str("100")?; client.trigger_simulated_farming_payout(initial_balance).await?;
    /// let name = XorName::random();
    /// let tag = 10;
    /// let owner = client.public_key().await;
    /// let mut perms = BTreeMap::<PublicKey, SequencePrivatePermissions>::new();
    ///
    /// // Set the access permissions
    /// let _ = perms.insert(
    ///    owner,
    ///    SequencePrivatePermissions::new(true, true, true),
    /// );
    ///
    /// // The returned address can then be used to `append` data to.
    /// let address = client.store_private_sequence(None, name, tag, owner, perms).await?;
    ///
    /// client.append_to_sequence(address, b"New Entry Value".to_vec()).await?;
    /// # let balance_after_write = client.get_local_balance().await; assert_ne!(initial_balance, balance_after_write); Ok(()) } ); }
    /// ```
    pub async fn append_to_sequence(
        &mut self,
        address: SequenceAddress,
        entry: SequenceEntry,
    ) -> Result<(), ClientError> {
        // First we fetch it so we can get the causality info,
        // either from local CRDT replica or from the network if not found
        let mut sequence = self.get_sequence(address).await?;

        // We do a permissions check just to make sure it won't fail when the operation
        // is broadcasted to the network, assuming our replica is in sync and up to date
        // with the permissions and ownership information compared with the replicas on the network.
        sequence.check_permission(SequenceAction::Append, self.public_id().await.public_key())?;

        // We can now append the entry to the Sequence
        let op = sequence.append(entry)?;

        // Update the local Sequence CRDT replica
        let _ = self
            .sequence_cache
            .lock()
            .await
            .put(*sequence.address(), sequence.clone());
        // Finally we can send the mutation to the network's replicas
        self.pay_and_write_append_to_sequence_to_network(op).await
    }

    /// Append data to a sequenced data object
    /// Wraps msg_contents for payment validation and mutation
    async fn pay_and_write_append_to_sequence_to_network(
        &mut self,
        op: SequenceDataWriteOp<Vec<u8>>,
    ) -> Result<(), ClientError> {
        let cmd = DataCmd::Sequence(SequenceWrite::Edit(op));
        // Payment for PUT
        let payment_proof = self.create_write_payment_proof(&cmd).await?;

        // The _actual_ message
        let msg_contents = Cmd::Data {
            cmd,
            payment: payment_proof.clone(),
        };
        let message = Self::create_cmd_message(msg_contents);
        let _ = self
            .connection_manager
            .lock()
            .await
            .send_cmd(&message)
            .await?;

        self.apply_write_payment_to_local_actor(payment_proof).await
    }

    /// Store a new public sequenced data object
    /// Wraps msg_contents for payment validation and mutation
    pub(crate) async fn pay_and_write_sequence_to_network(
        &mut self,
        data: Sequence,
    ) -> Result<(), ClientError> {
        let cmd = DataCmd::Sequence(SequenceWrite::New(data));
        // Payment for PUT
        let payment_proof = self.create_write_payment_proof(&cmd).await?;

        // The _actual_ message
        let msg_contents = Cmd::Data {
            cmd,
            payment: payment_proof.clone(),
        };
        let message = Self::create_cmd_message(msg_contents);
        let _ = self
            .connection_manager
            .lock()
            .await
            .send_cmd(&message)
            .await?;

        self.apply_write_payment_to_local_actor(payment_proof).await
    }

    //----------------------
    // Get Sequence
    //---------------------

    /// Get Sequence Data from the Network
    ///
    /// # Examples
    /// ```no_run
    /// # extern crate tokio; use sn_client::ClientError; use std::str::FromStr;
    /// use sn_client::Client;
    /// use sn_data_types::{ClientFullId, PublicKey, Money, SequencePrivatePermissions};
    /// use std::collections::BTreeMap;
    /// use xor_name::XorName;
    /// use rand::rngs::OsRng;
    /// # #[tokio::main] async fn main() { let _: Result<(), ClientError> = futures::executor::block_on( async {
    /// // Let's use an existing client, with a pre-existing balance to be used for write payments.
    /// let id = ClientFullId::new_ed25519(&mut OsRng);
    /// let mut client = Client::new(Some(id)).await?;
    /// # let initial_balance = Money::from_str("100")?; client.trigger_simulated_farming_payout(initial_balance).await?;
    /// let name = XorName::random();
    /// let tag = 10;
    /// let owner = client.public_key().await;
    /// let mut perms = BTreeMap::<PublicKey, SequencePrivatePermissions>::new();
    ///
    /// // Set the access permissions
    /// let _ = perms.insert(
    ///    owner,
    ///    SequencePrivatePermissions::new(true, true, true),
    /// );
    ///
    /// // The returned address can then be used to `append` data to.
    /// let address = client.store_private_sequence(None, name, tag, owner, perms).await?;
    ///
    /// let _data = client.get_sequence(address).await?;
    ///
    /// # let balance_after_write = client.get_local_balance().await; assert_ne!(initial_balance, balance_after_write); Ok(()) } ); }
    /// ```
    pub async fn get_sequence(
        &mut self,
        address: SequenceAddress,
    ) -> Result<Sequence, ClientError> {
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
            QueryResponse::GetSequence(res) => res.map_err(ClientError::from),
            _ => Err(ClientError::ReceivedUnexpectedEvent),
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
    ///
    /// # Examples
    /// ```no_run
    /// # extern crate tokio; use sn_client::ClientError; use std::str::FromStr;
    /// use sn_client::Client;
    /// use sn_data_types::{ClientFullId, PublicKey, Money, SequencePrivatePermissions};
    /// use std::collections::BTreeMap;
    /// use xor_name::XorName;
    /// use rand::rngs::OsRng;
    /// # #[tokio::main] async fn main() { let _: Result<(), ClientError> = futures::executor::block_on( async {
    /// // Let's use an existing client, with a pre-existing balance to be used for write payments.
    /// let id = ClientFullId::new_ed25519(&mut OsRng);
    /// let mut client = Client::new(Some(id)).await?;
    /// # let initial_balance = Money::from_str("100")?; client.trigger_simulated_farming_payout(initial_balance).await?;
    /// let name = XorName::random();
    /// let tag = 10;
    /// let owner = client.public_key().await;
    /// let mut perms = BTreeMap::<PublicKey, SequencePrivatePermissions>::new();
    ///
    /// // Set the access permissions
    /// let _ = perms.insert(
    ///    owner,
    ///    SequencePrivatePermissions::new(true, true, true),
    /// );
    ///
    /// // The returned address can then be used to `append` data to.
    /// let address = client.store_private_sequence(None, name, tag, owner, perms).await?;
    /// client.append_to_sequence(address, b"New Entry Value".to_vec()).await?;
    /// client.append_to_sequence(address, b"Another New Entry Value".to_vec()).await?;
    ///
    /// // Now we can retrieve the alst entry in the sequence:
    /// let (_position, last_entry) = client.get_sequence_last_entry(address).await?;
    ///
    /// assert_eq!(last_entry, b"Another New Entry Value".to_vec());
    ///
    /// # let balance_after_write = client.get_local_balance().await; assert_ne!(initial_balance, balance_after_write); Ok(()) } ); }
    /// ```
    pub async fn get_sequence_last_entry(
        &mut self,
        address: SequenceAddress,
    ) -> Result<(u64, SequenceEntry), ClientError> {
        trace!(
            "Get latest entry from Sequence Data at {:?}",
            address.name()
        );

        let sequence = self.get_sequence(address).await?;
        match sequence.last_entry() {
            Some(entry) => Ok((sequence.len() - 1, entry.to_vec())),
            None => Err(ClientError::from(sn_data_types::Error::NoSuchEntry)),
        }
    }

    /// Get a set of Entries for the requested range from a Sequence.
    ///
    /// # Examples
    /// ```no_run
    /// # extern crate tokio; use sn_client::ClientError; use std::str::FromStr;
    /// use sn_client::Client;
    /// use sn_data_types::{ClientFullId, PublicKey, Money, SequencePrivatePermissions, SequenceIndex};
    /// use std::collections::BTreeMap;
    /// use xor_name::XorName;
    /// use rand::rngs::OsRng;
    /// # #[tokio::main] async fn main() { let _: Result<(), ClientError> = futures::executor::block_on( async {
    /// // Let's use an existing client, with a pre-existing balance to be used for write payments.
    /// let id = ClientFullId::new_ed25519(&mut OsRng);
    /// let mut client = Client::new(Some(id)).await?;
    /// # let initial_balance = Money::from_str("100")?; client.trigger_simulated_farming_payout(initial_balance).await?;
    /// let name = XorName::random();
    /// let tag = 10;
    /// let owner = client.public_key().await;
    /// let mut perms = BTreeMap::<PublicKey, SequencePrivatePermissions>::new();
    ///
    /// // Set the access permissions
    /// let _ = perms.insert(
    ///    owner,
    ///    SequencePrivatePermissions::new(true, true, true),
    /// );
    ///
    /// // The returned address can then be used to `append` data to.
    /// let address = client.store_private_sequence(None, name, tag, owner, perms).await?;
    /// client.append_to_sequence(address, b"New Entry Value".to_vec()).await?;
    /// client.append_to_sequence(address, b"Another New Entry Value".to_vec()).await?;
    /// client.append_to_sequence(address, b"Third Entry Value".to_vec()).await?;
    ///
    /// // Now we can retrieve the alst entry in the sequence:
    /// let entries = client.get_sequence_range(address, (SequenceIndex::FromStart(1), SequenceIndex::FromEnd(0) )).await?;
    ///
    /// assert_eq!(entries[0], b"Another New Entry Value".to_vec());
    /// assert_eq!(entries[1], b"Third Entry Value".to_vec());
    ///
    /// # let balance_after_write = client.get_local_balance().await; assert_ne!(initial_balance, balance_after_write); Ok(()) } ); }
    /// ```
    pub async fn get_sequence_range(
        &mut self,
        address: SequenceAddress,
        range: (SequenceIndex, SequenceIndex),
    ) -> Result<SequenceEntries, ClientError> {
        trace!(
            "Get range of entries from Sequence Data at {:?}",
            address.name()
        );

        let sequence = self.get_sequence(address).await?;
        sequence
            .in_range(range.0, range.1)
            .ok_or_else(|| ClientError::from(sn_data_types::Error::NoSuchEntry))
    }

    //----------------------
    // Ownership
    //---------------------

    /// Get the owner of a Sequence.
    ///
    /// # Examples
    /// ```no_run
    /// # extern crate tokio; use sn_client::ClientError; use std::str::FromStr;
    /// use sn_client::Client;
    /// use sn_data_types::{ClientFullId, PublicKey, Money, SequencePrivatePermissions};
    /// use std::collections::BTreeMap;
    /// use xor_name::XorName;
    /// use rand::rngs::OsRng;
    /// # #[tokio::main] async fn main() { let _: Result<(), ClientError> = futures::executor::block_on( async {
    /// // Let's use an existing client, with a pre-existing balance to be used for write payments.
    /// let id = ClientFullId::new_ed25519(&mut OsRng);
    /// let mut client = Client::new(Some(id)).await?;
    /// # let initial_balance = Money::from_str("100")?; client.trigger_simulated_farming_payout(initial_balance).await?;
    /// let name = XorName::random();
    /// let tag = 10;
    /// let owner = client.public_key().await;
    /// let mut perms = BTreeMap::<PublicKey, SequencePrivatePermissions>::new();
    ///
    /// // Set the access permissions
    /// let _ = perms.insert(
    ///    owner,
    ///    SequencePrivatePermissions::new(true, true, true),
    /// );
    ///
    /// // The returned address can then be used to `append` data to.
    /// let address = client.store_private_sequence(None, name, tag, owner, perms).await?;
    ///
    /// let seq_owner = client.get_sequence_owner(address).await?;
    /// assert_eq!(seq_owner, owner);
    /// # let balance_after_write = client.get_local_balance().await; assert_ne!(initial_balance, balance_after_write); Ok(()) } ); }
    /// ```
    pub async fn get_sequence_owner(
        &mut self,
        address: SequenceAddress,
    ) -> Result<PublicKey, ClientError> {
        trace!("Get owner of the Sequence Data at {:?}", address.name());

        // TODO: perhaps we want to grab it directly from the network and update local replica
        let sequence = self.get_sequence(address).await?;

        let owner = match &sequence {
            Sequence::Public(_seq) => sequence.public_policy(sequence.policy_version())?.owner,
            Sequence::Private(_seq) => sequence.private_policy(sequence.policy_version())?.owner,
        };

        Ok(owner)
    }

    /// Set the new owner of a Sequence Data
    /// Update sequence data owners
    ///
    /// # Examples
    /// ```no_run
    /// # extern crate tokio; use sn_client::ClientError; use std::str::FromStr;
    /// use sn_client::Client;
    /// use sn_data_types::{ClientFullId, PublicKey, Money, SequencePrivatePermissions};
    /// use std::collections::BTreeMap;
    /// use xor_name::XorName;
    /// use rand::rngs::OsRng;
    /// use threshold_crypto::SecretKey;
    /// # #[tokio::main] async fn main() { let _: Result<(), ClientError> = futures::executor::block_on( async {
    /// // Let's use an existing client, with a pre-existing balance to be used for write payments.
    /// let id = ClientFullId::new_ed25519(&mut OsRng);
    /// let mut client = Client::new(Some(id)).await?;
    /// # let initial_balance = Money::from_str("100")?; client.trigger_simulated_farming_payout(initial_balance).await?;
    /// let name = XorName::random();
    /// let tag = 10;
    /// let owner = client.public_key().await;
    /// let new_owner = PublicKey::from( SecretKey::random().public_key() );
    /// let mut perms = BTreeMap::<PublicKey, SequencePrivatePermissions>::new();
    ///
    /// // Set the access permissions
    /// let _ = perms.insert(
    ///    owner,
    ///    SequencePrivatePermissions::new(true, true, true),
    /// );
    ///
    /// // The returned address can then be used to `append` data to.
    /// let address = client.store_private_sequence(None, name, tag, owner, perms).await?;
    ///
    /// let _ = client.set_private_sequence_owner(address, new_owner).await?;
    /// # let balance_after_write = client.get_local_balance().await; assert_ne!(initial_balance, balance_after_write); Ok(()) } ); }
    /// ```
    pub async fn set_private_sequence_owner(
        &mut self,
        address: SequenceAddress,
        owner: PublicKey,
    ) -> Result<(), ClientError> {
        // First we fetch it either from local CRDT replica or from the network if not found
        let mut sequence = self.get_sequence(address).await?;

        let pk = self.public_key().await;
        // We do a permissions check just to make sure it won't fail when the operation
        // is broadcasted to the network, assuming our replica is in sync and up to date
        // with the ownership information compared with the replicas on the network.
        sequence.check_permission(SequenceAction::Admin, pk)?;

        // get current policy permissions
        let permissions = sequence
            .private_policy(sequence.policy_version())?
            .permissions
            .clone();

        // set new owner against this
        let op = sequence.set_private_policy(owner, permissions)?;

        // Update the local Sequence CRDT replica
        let _ = self
            .sequence_cache
            .lock()
            .await
            .put(*sequence.address(), sequence.clone());

        let cmd = DataCmd::Sequence(SequenceWrite::SetPrivatePolicy(op));

        // Payment for PUT
        let payment_proof = self.create_write_payment_proof(&cmd).await?;

        // The _actual_ message
        let msg_contents = Cmd::Data {
            cmd,
            payment: payment_proof.clone(),
        };
        let message = Self::create_cmd_message(msg_contents);
        let _ = self
            .connection_manager
            .lock()
            .await
            .send_cmd(&message)
            .await?;

        self.apply_write_payment_to_local_actor(payment_proof).await
    }

    //----------------------
    // Permissions
    //---------------------

    /// Get the set of Permissions of a Public Sequence.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # extern crate tokio; use sn_client::ClientError; use std::str::FromStr;
    /// use sn_client::Client;
    /// use sn_data_types::{ClientFullId, Money, SequenceUser,SequencePublicPermissions};
    /// use std::collections::BTreeMap;
    /// use xor_name::XorName;
    /// use rand::rngs::OsRng;
    /// # #[tokio::main] async fn main() { let _: Result<(), ClientError> = futures::executor::block_on( async {
    /// // Let's use an existing client, with a pre-existing balance to be used for write payments.
    /// let id = ClientFullId::new_ed25519(&mut OsRng);
    /// let mut client = Client::new(Some(id)).await?;
    /// # let initial_balance = Money::from_str("100")?; client.trigger_simulated_farming_payout(initial_balance).await?;
    /// let name = XorName::random();
    /// let tag = 10;
    /// let owner = client.public_key().await;
    /// let mut perms = BTreeMap::<SequenceUser, SequencePublicPermissions>::new();
    ///
    /// // Set the access permissions
    /// let _ = perms.insert(
    ///    SequenceUser::Key(owner),
    ///    SequencePublicPermissions::new(true, true),
    /// );
    ///
    /// // The returned address can then be used to `append` data to.
    /// let address = client.store_public_sequence(None, name, tag, owner, perms).await?;
    ///
    /// let _permissions = client.get_sequence_pub_permissions_for_user(address, owner).await?;
    /// # let balance_after_write = client.get_local_balance().await; assert_ne!(initial_balance, balance_after_write); Ok(()) } ); }
    /// ```
    pub async fn get_sequence_pub_permissions_for_user(
        &mut self,
        address: SequenceAddress,
        user: PublicKey,
    ) -> Result<SequencePublicPermissions, ClientError> {
        trace!(
            "Get permissions from Public Sequence Data at {:?}",
            address.name()
        );

        // TODO: perhaps we want to grab it directly from the network and update local replica
        let sequence = self.get_sequence(address).await?;
        let perms = match sequence
            .permissions(SequenceUser::Key(user), sequence.policy_version() - 1)
            .map_err(ClientError::from)?
        {
            SequencePermissions::Public(perms) => perms,
            _ => return Err(ClientError::from("Expected public permission set.")),
        };

        Ok(perms)
    }

    /// Get the set of Permissions of a Private Sequence.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # extern crate tokio; use sn_client::ClientError; use std::str::FromStr;
    /// use sn_client::Client;
    /// use sn_data_types::{ClientFullId, PublicKey, Money, SequencePrivatePermissions};
    /// use std::collections::BTreeMap;
    /// use xor_name::XorName;
    /// use rand::rngs::OsRng;
    /// # #[tokio::main] async fn main() { let _: Result<(), ClientError> = futures::executor::block_on( async {
    /// // Let's use an existing client, with a pre-existing balance to be used for write payments.
    /// let id = ClientFullId::new_ed25519(&mut OsRng);
    /// let mut client = Client::new(Some(id)).await?;
    /// # let initial_balance = Money::from_str("100")?; client.trigger_simulated_farming_payout(initial_balance).await?;
    /// let name = XorName::random();
    /// let tag = 10;
    /// let owner = client.public_key().await;
    /// let mut perms = BTreeMap::<PublicKey, SequencePrivatePermissions>::new();
    ///
    /// // Set the access permissions
    /// let _ = perms.insert(
    ///    owner,
    ///    SequencePrivatePermissions::new(true, true, true),
    /// );
    ///
    /// // The returned address can then be used to `append` data to.
    /// let address = client.store_private_sequence(None, name, tag, owner, perms).await?;
    ///
    /// let _permissions = client.get_sequence_private_permissions_for_user(address, owner).await?;
    /// # let balance_after_write = client.get_local_balance().await; assert_ne!(initial_balance, balance_after_write); Ok(()) } ); }
    /// ```
    pub async fn get_sequence_private_permissions_for_user(
        &mut self,
        address: SequenceAddress,
        user: PublicKey,
    ) -> Result<SequencePrivatePermissions, ClientError> {
        trace!(
            "Get permissions from Private Sequence Data at {:?}",
            address.name()
        );

        // TODO: perhaps we want to grab it directly from the network and update local replica
        let sequence = self.get_sequence(address).await?;
        let perms = match sequence
            .permissions(SequenceUser::Key(user), sequence.policy_version() - 1)
            .map_err(ClientError::from)?
        {
            SequencePermissions::Private(perms) => perms,
            _ => return Err(ClientError::from("Expected private permission set.")),
        };

        Ok(perms)
    }

    /// Get the set of Permissions for a specific user in a Sequence.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # extern crate tokio; use sn_client::ClientError; use std::str::FromStr;
    /// use sn_client::Client;
    /// use sn_data_types::{ClientFullId, PublicKey, Money, SequencePrivatePermissions};
    /// use std::collections::BTreeMap;
    /// use xor_name::XorName;
    /// use rand::rngs::OsRng;
    /// # #[tokio::main] async fn main() { let _: Result<(), ClientError> = futures::executor::block_on( async {
    /// // Let's use an existing client, with a pre-existing balance to be used for write payments.
    /// let id = ClientFullId::new_ed25519(&mut OsRng);
    /// let mut client = Client::new(Some(id)).await?;
    /// # let initial_balance = Money::from_str("100")?; client.trigger_simulated_farming_payout(initial_balance).await?;
    /// let name = XorName::random();
    /// let tag = 10;
    /// let owner = client.public_key().await;
    /// let mut perms = BTreeMap::<PublicKey, SequencePrivatePermissions>::new();
    ///
    /// // Set the access permissions
    /// let _ = perms.insert(
    ///    owner,
    ///    SequencePrivatePermissions::new(true, true, true),
    /// );
    ///
    /// // The returned address can then be used to `append` data to.
    /// let address = client.store_private_sequence(None, name, tag, owner, perms).await?;
    ///
    /// let _permissions = client.get_sequence_pub_permissions_for_user(address, owner).await?;
    /// # let balance_after_write = client.get_local_balance().await; assert_ne!(initial_balance, balance_after_write); Ok(()) } ); }
    /// ```
    pub async fn get_sequence_permissions(
        &mut self,
        address: SequenceAddress,
        user: SequenceUser,
    ) -> Result<SequencePermissions, ClientError> {
        trace!(
            "Get permissions for user {:?} from Sequence Data at {:?}",
            user,
            address.name()
        );

        // TODO: perhaps we want to grab it directly from the network and update local replica
        let sequence = self.get_sequence(address).await?;
        let perms = sequence
            .permissions(user, sequence.policy_version() - 1)
            .map_err(ClientError::from)?;

        Ok(perms)
    }

    /// Set permissions for a PublicKey on a Public Sequence
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # extern crate tokio; use sn_client::ClientError; use std::str::FromStr;
    /// use sn_client::Client;
    /// use sn_data_types::{ClientFullId, PublicKey, SequenceUser, Money, SequencePublicPermissions};
    /// use std::collections::BTreeMap;
    /// use xor_name::XorName;
    /// use rand::rngs::OsRng;
    /// use threshold_crypto::SecretKey;
    /// # #[tokio::main] async fn main() { let _: Result<(), ClientError> = futures::executor::block_on( async {
    /// // Let's use an existing client, with a pre-existing balance to be used for write payments.
    /// let id = ClientFullId::new_ed25519(&mut OsRng);
    /// let mut client = Client::new(Some(id)).await?;
    /// # let initial_balance = Money::from_str("100")?; client.trigger_simulated_farming_payout(initial_balance).await?;
    /// let name = XorName::random();
    /// let tag = 10;
    /// let owner = client.public_key().await;
    /// let another_key = PublicKey::from( SecretKey::random().public_key() );
    /// let mut perms = BTreeMap::<SequenceUser, SequencePublicPermissions>::new();
    ///
    /// // Set the access permissions
    /// let _ = perms.insert(
    ///    SequenceUser::Key(owner),
    ///    SequencePublicPermissions::new(true, true),
    /// );
    ///
    /// // The returned address can then be used to `append` data to.
    /// let address = client.store_public_sequence(None, name, tag, owner, perms).await?;
    ///
    /// let mut perms2 = BTreeMap::<SequenceUser, SequencePublicPermissions>::new();
    /// let _ = perms2.insert(
    ///     SequenceUser::Key(another_key),
    ///     SequencePublicPermissions::new(false, false),
    ///  );
    /// let _ = client.sequence_set_public_permissions(address, perms2).await?;
    /// # let balance_after_write = client.get_local_balance().await; assert_ne!(initial_balance, balance_after_write); Ok(()) } ); }
    /// ```
    pub async fn sequence_set_public_permissions(
        &mut self,
        address: SequenceAddress,
        permissions: BTreeMap<SequenceUser, SequencePublicPermissions>,
    ) -> Result<(), ClientError> {
        // First we fetch it either from local CRDT replica or from the network if not found
        let mut sequence = self.get_sequence(address).await?;

        // We do a permissions check just to make sure it won't fail when the operation
        // is broadcasted to the network, assuming our replica is in sync and up to date
        // with the permissions information compared with the replicas on the network.
        sequence.check_permission(SequenceAction::Admin, self.public_id().await.public_key())?;

        // We can now set the new permissions to the Sequence
        let op = sequence.set_public_policy(self.public_key().await, permissions)?;

        // Update the local Sequence CRDT replica
        let _ = self
            .sequence_cache
            .lock()
            .await
            .put(*sequence.address(), sequence.clone());

        let cmd = DataCmd::Sequence(SequenceWrite::SetPublicPolicy(op));
        // Payment for PUT
        let payment_proof = self.create_write_payment_proof(&cmd).await?;

        // The _actual_ message
        let msg_contents = Cmd::Data {
            cmd,
            payment: payment_proof.clone(),
        };
        let message = Self::create_cmd_message(msg_contents);
        let _ = self
            .connection_manager
            .lock()
            .await
            .send_cmd(&message)
            .await?;

        self.apply_write_payment_to_local_actor(payment_proof).await
    }

    /// Set permissions for a PublicKey on a private sequence
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # extern crate tokio; use sn_client::ClientError; use std::str::FromStr;
    /// use sn_client::Client;
    /// use sn_data_types::{ClientFullId, PublicKey, Money, SequencePrivatePermissions};
    /// use std::collections::BTreeMap;
    /// use xor_name::XorName;
    /// use rand::rngs::OsRng;
    /// use threshold_crypto::SecretKey;
    /// # #[tokio::main] async fn main() { let _: Result<(), ClientError> = futures::executor::block_on( async {
    /// // Let's use an existing client, with a pre-existing balance to be used for write payments.
    /// let id = ClientFullId::new_ed25519(&mut OsRng);
    /// let mut client = Client::new(Some(id)).await?;
    /// # let initial_balance = Money::from_str("100")?; client.trigger_simulated_farming_payout(initial_balance).await?;
    /// let name = XorName::random();
    /// let tag = 10;
    /// let owner = client.public_key().await;
    /// let another_key = PublicKey::from( SecretKey::random().public_key() );
    /// let mut perms = BTreeMap::<PublicKey, SequencePrivatePermissions>::new();
    ///
    /// // Set the access permissions
    /// let _ = perms.insert(
    ///    owner,
    ///    SequencePrivatePermissions::new(true, true, true),
    /// );
    ///
    /// // The returned address can then be used to `append` data to.
    /// let address = client.store_private_sequence(None, name, tag, owner, perms).await?;
    ///
    /// let mut perms2 = BTreeMap::<PublicKey, SequencePrivatePermissions>::new();
    /// let _ = perms2.insert(
    ///     another_key,
    ///     SequencePrivatePermissions::new(false, false, false),
    ///  );
    /// let _ = client.sequence_set_private_permissions(address, perms2).await?;
    /// # let balance_after_write = client.get_local_balance().await; assert_ne!(initial_balance, balance_after_write); Ok(()) } ); }
    /// ```
    pub async fn sequence_set_private_permissions(
        &mut self,
        address: SequenceAddress,
        permissions: BTreeMap<PublicKey, SequencePrivatePermissions>,
    ) -> Result<(), ClientError> {
        // First we fetch it either from local CRDT replica or from the network if not found
        let mut sequence = self.get_sequence(address).await?;

        // We do a permissions check just to make sure it won't fail when the operation
        // is broadcasted to the network, assuming our replica is in sync and up to date
        // with the permissions information compared with the replicas on the network.
        // TODO: if it fails, try to sync-up perms with rmeote replicas and try once more
        sequence.check_permission(SequenceAction::Admin, self.public_id().await.public_key())?;

        // We can now set the new permissions to the Sequence
        let op = sequence.set_private_policy(self.public_key().await, permissions)?;

        // Update the local Sequence CRDT replica
        let _ = self
            .sequence_cache
            .lock()
            .await
            .put(*sequence.address(), sequence.clone());

        let cmd = DataCmd::Sequence(SequenceWrite::SetPrivatePolicy(op));

        // Payment for PUT
        let payment_proof = self.create_write_payment_proof(&cmd).await?;

        // The _actual_ message
        let msg_contents = Cmd::Data {
            cmd,
            payment: payment_proof.clone(),
        };
        let message = Self::create_cmd_message(msg_contents);
        let _ = self
            .connection_manager
            .lock()
            .await
            .send_cmd(&message)
            .await?;

        self.apply_write_payment_to_local_actor(payment_proof).await
    }
}

#[allow(missing_docs)]
#[cfg(any(test, feature = "simulated-payouts", feature = "testing"))]
pub mod exported_tests {
    use super::*;
    use crate::utils::test_utils::gen_bls_keypair;
    use sn_data_types::{Error as SndError, Money, SequencePrivatePermissions};
    use std::str::FromStr;
    use unwrap::unwrap;
    use xor_name::XorName;

    pub async fn sequence_deletions_should_cost_put_price() -> Result<(), ClientError> {
        let name = XorName(rand::random());
        let tag = 10;
        let mut client = Client::new(None).await?;
        let owner = client.public_key().await;
        let perms = BTreeMap::<PublicKey, SequencePrivatePermissions>::new();
        let sequence_address = client
            .store_private_sequence(None, name, tag, owner, perms)
            .await?;

        let balance_before_delete = client.get_balance().await?;
        client.delete_sequence(sequence_address).await?;
        let new_balance = client.get_balance().await?;

        // make sure we have _some_ balance
        assert_ne!(balance_before_delete, Money::from_str("0")?);
        assert_ne!(balance_before_delete, new_balance);

        Ok(())
    }

    /// Sequence data tests ///

    pub async fn sequence_basics_test() -> Result<(), ClientError> {
        let mut client = Client::new(None).await?;

        let name = XorName(rand::random());
        let tag = 15000;
        let owner = client.public_key().await;

        // store a Private Sequence
        let mut perms = BTreeMap::<PublicKey, SequencePrivatePermissions>::new();
        let _ = perms.insert(owner, SequencePrivatePermissions::new(true, true, true));
        let address = client
            .store_private_sequence(None, name, tag, owner, perms)
            .await?;
        let sequence = client.get_sequence(address).await?;
        assert!(sequence.is_private());
        assert_eq!(*sequence.name(), name);
        assert_eq!(sequence.tag(), tag);
        assert_eq!(sequence.policy_version(), 1);
        assert_eq!(sequence.policy_version(), 1);
        assert_eq!(sequence.len(), 0);

        // store a Public Sequence
        let mut perms = BTreeMap::<SequenceUser, SequencePublicPermissions>::new();
        let _ = perms.insert(
            SequenceUser::Anyone,
            SequencePublicPermissions::new(true, true),
        );
        let address = client
            .store_public_sequence(None, name, tag, owner, perms)
            .await?;
        let sequence = client.get_sequence(address).await?;
        assert!(sequence.is_pub());
        assert_eq!(*sequence.name(), name);
        assert_eq!(sequence.tag(), tag);
        assert_eq!(sequence.policy_version(), 1);
        assert_eq!(sequence.policy_version(), 1);
        assert_eq!(sequence.len(), 0);

        Ok(())
    }

    pub async fn sequence_private_permissions_test() -> Result<(), ClientError> {
        let mut client = Client::new(None).await?;

        let name = XorName(rand::random());
        let tag = 15000;
        let owner = client.public_key().await;
        let mut perms = BTreeMap::<PublicKey, SequencePrivatePermissions>::new();
        let _ = perms.insert(owner, SequencePrivatePermissions::new(true, true, true));
        let address = client
            .store_private_sequence(None, name, tag, owner, perms)
            .await?;

        let data = client.get_sequence(address).await?;
        assert_eq!(data.len(), 0);
        assert_eq!(data.policy_version(), 1);

        let user_perms = client
            .get_sequence_private_permissions_for_user(address, owner)
            .await?;

        assert!(user_perms.is_allowed(SequenceAction::Read));
        assert!(user_perms.is_allowed(SequenceAction::Append));
        assert!(user_perms.is_allowed(SequenceAction::Admin));

        match client
            .get_sequence_permissions(address, SequenceUser::Key(owner))
            .await?
        {
            SequencePermissions::Private(user_perms) => {
                assert!(user_perms.is_allowed(SequenceAction::Read));
                assert!(user_perms.is_allowed(SequenceAction::Append));
                assert!(user_perms.is_allowed(SequenceAction::Admin));
            }
            SequencePermissions::Public(_) => {
                return Err(ClientError::from(
                    "Unexpectedly obtained incorrect user permissions",
                ))
            }
        }

        let sim_client = gen_bls_keypair().public_key();
        let mut perms2 = BTreeMap::<PublicKey, SequencePrivatePermissions>::new();
        let _ = perms2.insert(
            sim_client,
            SequencePrivatePermissions::new(false, true, false),
        );
        client
            .sequence_set_private_permissions(address, perms2)
            .await?;

        let user_perms = client
            .get_sequence_private_permissions_for_user(address, sim_client)
            .await?;

        assert!(!user_perms.is_allowed(SequenceAction::Read));
        assert!(user_perms.is_allowed(SequenceAction::Append));
        assert!(!user_perms.is_allowed(SequenceAction::Admin));

        match client
            .get_sequence_permissions(address, SequenceUser::Key(sim_client))
            .await?
        {
            SequencePermissions::Private(user_perms) => {
                assert!(!user_perms.is_allowed(SequenceAction::Read));
                assert!(user_perms.is_allowed(SequenceAction::Append));
                assert!(!user_perms.is_allowed(SequenceAction::Admin));
                Ok(())
            }
            SequencePermissions::Public(_) => Err(ClientError::from(
                "Unexpectedly obtained incorrect user permissions",
            )),
        }
    }

    pub async fn sequence_pub_permissions_test() -> Result<(), ClientError> {
        let mut client = Client::new(None).await?;

        let name = XorName(rand::random());
        let tag = 15000;
        let owner = client.public_key().await;
        let mut perms = BTreeMap::<SequenceUser, SequencePublicPermissions>::new();
        let _ = perms.insert(
            SequenceUser::Key(owner),
            SequencePublicPermissions::new(None, true),
        );
        let address = client
            .store_public_sequence(None, name, tag, owner, perms)
            .await?;

        let data = client.get_sequence(address).await?;
        assert_eq!(data.len(), 0);
        assert_eq!(data.policy_version(), 1);

        let user_perms = client
            .get_sequence_pub_permissions_for_user(address, owner)
            .await?;

        assert_eq!(Some(true), user_perms.is_allowed(SequenceAction::Read));
        assert_eq!(None, user_perms.is_allowed(SequenceAction::Append));
        assert_eq!(Some(true), user_perms.is_allowed(SequenceAction::Admin));

        match client
            .get_sequence_permissions(address, SequenceUser::Key(owner))
            .await?
        {
            SequencePermissions::Public(user_perms) => {
                assert_eq!(Some(true), user_perms.is_allowed(SequenceAction::Read));
                assert_eq!(None, user_perms.is_allowed(SequenceAction::Append));
                assert_eq!(Some(true), user_perms.is_allowed(SequenceAction::Admin));
            }
            SequencePermissions::Private(_) => {
                return Err(ClientError::from(
                    "Unexpectedly obtained incorrect user permissions",
                ))
            }
        }

        let sim_client = gen_bls_keypair().public_key();
        let mut perms2 = BTreeMap::<SequenceUser, SequencePublicPermissions>::new();
        let _ = perms2.insert(
            SequenceUser::Key(sim_client),
            SequencePublicPermissions::new(false, false),
        );
        client
            .sequence_set_public_permissions(address, perms2)
            .await?;

        let user_perms = client
            .get_sequence_pub_permissions_for_user(address, sim_client)
            .await?;
        assert_eq!(Some(true), user_perms.is_allowed(SequenceAction::Read));
        assert_eq!(Some(false), user_perms.is_allowed(SequenceAction::Append));
        assert_eq!(Some(false), user_perms.is_allowed(SequenceAction::Admin));

        match client
            .get_sequence_permissions(address, SequenceUser::Key(sim_client))
            .await?
        {
            SequencePermissions::Public(user_perms) => {
                assert_eq!(Some(true), user_perms.is_allowed(SequenceAction::Read));
                assert_eq!(Some(false), user_perms.is_allowed(SequenceAction::Append));
                assert_eq!(Some(false), user_perms.is_allowed(SequenceAction::Admin));
                Ok(())
            }
            SequencePermissions::Private(_) => Err(ClientError::from(
                "Unexpectedly obtained incorrect user permissions",
            )),
        }
    }

    pub async fn append_to_sequence_test() -> Result<(), ClientError> {
        let name = XorName(rand::random());
        let tag = 10;
        let mut client = Client::new(None).await?;

        let owner = client.public_key().await;
        let mut perms = BTreeMap::<SequenceUser, SequencePublicPermissions>::new();
        let _ = perms.insert(
            SequenceUser::Key(owner),
            SequencePublicPermissions::new(true, true),
        );
        let address = client
            .store_public_sequence(None, name, tag, owner, perms)
            .await?;

        client
            .append_to_sequence(address, b"VALUE1".to_vec())
            .await?;

        let (index, data) = client.get_sequence_last_entry(address).await?;
        assert_eq!(0, index);
        assert_eq!(unwrap!(std::str::from_utf8(&data)), "VALUE1");

        client
            .append_to_sequence(address, b"VALUE2".to_vec())
            .await?;

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

    pub async fn sequence_owner_test() -> Result<(), ClientError> {
        let name = XorName(rand::random());
        let tag = 10;
        let mut client = Client::new(None).await?;

        let owner = client.public_key().await;
        let mut perms = BTreeMap::<PublicKey, SequencePrivatePermissions>::new();
        let _ = perms.insert(owner, SequencePrivatePermissions::new(true, true, true));
        let address = client
            .store_private_sequence(None, name, tag, owner, perms)
            .await?;

        client
            .append_to_sequence(address, b"VALUE1".to_vec())
            .await?;
        client
            .append_to_sequence(address, b"VALUE2".to_vec())
            .await?;

        let data = client.get_sequence(address).await?;
        assert_eq!(data.len(), 2);
        assert_eq!(data.policy_version(), 1);
        // assert_eq!(data.permissions_index(), 1);

        let current_owner = client.get_sequence_owner(address).await?;
        assert_eq!(owner, current_owner);

        let sim_client = gen_bls_keypair().public_key();
        client
            .set_private_sequence_owner(address, sim_client)
            .await?;

        let current_owner = client.get_sequence_owner(address).await?;
        assert_eq!(sim_client, current_owner);

        Ok(())
    }

    pub async fn sequence_can_delete_private_test() -> Result<(), ClientError> {
        let mut client = Client::new(None).await?;

        let name = XorName(rand::random());
        let tag = 15000;
        let owner = client.public_key().await;

        // store a Private Sequence
        let mut perms = BTreeMap::<PublicKey, SequencePrivatePermissions>::new();
        let _ = perms.insert(owner, SequencePrivatePermissions::new(true, true, true));
        let address = client
            .store_private_sequence(None, name, tag, owner, perms)
            .await?;
        let sequence = client.get_sequence(address).await?;
        assert!(sequence.is_private());

        client.delete_sequence(address).await?;

        match client.get_sequence(address).await {
            Err(ClientError::DataError(SndError::NoSuchData)) => Ok(()),
            Err(err) => Err(ClientError::from(format!(
                "Unexpected error returned when deleting a nonexisting Private Sequence: {}",
                err
            ))),
            Ok(_res) => Err(ClientError::from(
                "Unexpectedly retrieved a deleted Private Sequence!",
            )),
        }
    }

    pub async fn sequence_cannot_delete_public_test() -> Result<(), ClientError> {
        let mut client = Client::new(None).await?;

        let name = XorName(rand::random());
        let tag = 15000;
        let owner = client.public_key().await;

        // store a Public Sequence
        let mut perms = BTreeMap::<SequenceUser, SequencePublicPermissions>::new();
        let _ = perms.insert(
            SequenceUser::Anyone,
            SequencePublicPermissions::new(true, true),
        );
        let address = client
            .store_public_sequence(None, name, tag, owner, perms)
            .await?;
        let sequence = client.get_sequence(address).await?;
        assert!(sequence.is_pub());

        client.delete_sequence(address).await?;

        // Check that our data still exists.
        match client.get_sequence(address).await {
            Err(ClientError::DataError(SndError::InvalidOperation)) => Ok(()),
            Err(err) => Err(ClientError::from(format!(
                "Unexpected error returned when attempting to get a Public Sequence: {}",
                err
            ))),
            Ok(_data) => Ok(()),
        }
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
    async fn sequence_deletions_should_cost_put_price() -> Result<(), ClientError> {
        exported_tests::sequence_deletions_should_cost_put_price().await
    }

    #[tokio::test]
    async fn sequence_basics_test() -> Result<(), ClientError> {
        exported_tests::sequence_basics_test().await
    }

    #[tokio::test]
    async fn sequence_private_permissions_test() -> Result<(), ClientError> {
        exported_tests::sequence_private_permissions_test().await
    }

    #[tokio::test]
    async fn sequence_pub_permissions_test() -> Result<(), ClientError> {
        exported_tests::sequence_pub_permissions_test().await
    }

    #[tokio::test]
    async fn append_to_sequence_test() -> Result<(), ClientError> {
        exported_tests::append_to_sequence_test().await
    }

    #[tokio::test]
    async fn sequence_owner_test() -> Result<(), ClientError> {
        exported_tests::sequence_owner_test().await
    }

    #[tokio::test]
    async fn sequence_can_delete_private_test() -> Result<(), ClientError> {
        exported_tests::sequence_can_delete_private_test().await
    }

    #[tokio::test]
    async fn sequence_cannot_delete_public_test() -> Result<(), ClientError> {
        exported_tests::sequence_cannot_delete_public_test().await
    }
}
