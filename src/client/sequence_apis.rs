// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::errors::Error;
use crate::Client;
use log::{debug, trace};
use sn_data_types::{
    PublicKey, Sequence, SequenceAddress, SequenceDataWriteOp, SequenceEntries, SequenceEntry,
    SequenceIndex, SequencePermissions, SequencePrivatePermissions, SequencePublicPermissions,
    SequenceUser,
};
use sn_messaging::{Cmd, DataCmd, DataQuery, Query, QueryResponse, SequenceRead, SequenceWrite};
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
    /// # extern crate tokio; use sn_client::Error; use std::str::FromStr;
    /// use sn_client::Client;
    /// use sn_data_types::{Keypair, PublicKey, Token, SequencePrivatePermissions};
    /// use std::collections::BTreeMap;
    /// use xor_name::XorName;
    /// use rand::rngs::OsRng;
    /// # #[tokio::main] async fn main() { let _: Result<(), Error> = futures::executor::block_on( async {
    /// // Let's use an existing client, with a pre-existing balance to be used for write payments.
    /// let id = std::sync::Keypair::new_ed25519(&mut OsRng);

    /// let mut client = Client::new(Some(id), None).await?;
    /// # let initial_balance = Token::from_str("100")?; client.trigger_simulated_farming_payout(initial_balance).await?;
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
        &self,
        sequence: Option<SequenceEntries>,
        name: XorName,
        tag: u64,
        owner: PublicKey,
        permissions: BTreeMap<PublicKey, SequencePrivatePermissions>,
    ) -> Result<SequenceAddress, Error> {
        trace!("Store Private Sequence Data {:?}", name);
        let pk = self.public_key().await;
        let mut data = Sequence::new_private(pk, pk.to_string(), name, tag);
        let address = *data.address();

        let mut op = data.create_unsigned_private_policy_op(owner, permissions)?;
        let bytes = bincode::serialize(&op.crdt_op)?;
        let signature = self.keypair.sign(&bytes);
        op.signature = Some(signature);

        data.apply_private_policy_op(op.clone())?;

        if let Some(entries) = sequence {
            for entry in entries {
                let mut op = data.create_unsigned_append_op(entry)?;
                let bytes = bincode::serialize(&op.crdt_op)?;
                let signature = self.keypair.sign(&bytes);
                op.signature = Some(signature);
                data.apply_data_op(op.clone())?;
            }
        }

        self.pay_and_write_sequence_to_network(data.clone()).await?;

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
    /// # extern crate tokio; use sn_client::Error; use std::str::FromStr;
    /// use sn_client::Client;
    /// use sn_data_types::{Keypair, SequenceUser, Token, SequencePublicPermissions};
    /// use std::collections::BTreeMap;
    /// use xor_name::XorName;
    /// use rand::rngs::OsRng;
    /// # #[tokio::main] async fn main() { let _: Result<(), Error> = futures::executor::block_on( async {
    /// // Let's use an existing client, with a pre-existing balance to be used for write payments.
    /// let id = std::sync::Keypair::new_ed25519(&mut OsRng);

    /// let mut client = Client::new(Some(id), None).await?;
    /// # let initial_balance = Token::from_str("100")?; client.trigger_simulated_farming_payout(initial_balance).await?;
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
        &self,
        sequence: Option<SequenceEntries>,
        name: XorName,
        tag: u64,
        owner: PublicKey,
        permissions: BTreeMap<SequenceUser, SequencePublicPermissions>,
    ) -> Result<SequenceAddress, Error> {
        trace!("Store Public Sequence Data {:?}", name);
        let pk = self.public_key().await;
        let mut data = Sequence::new_public(pk, pk.to_string(), name, tag);
        let address = *data.address();

        let mut op = data.create_unsigned_public_policy_op(owner, permissions)?;
        let bytes = bincode::serialize(&op.crdt_op)?;
        let signature = self.keypair.sign(&bytes);
        op.signature = Some(signature);
        data.apply_public_policy_op(op.clone())?;

        if let Some(entries) = sequence {
            for entry in entries {
                let mut op = data.create_unsigned_append_op(entry)?;
                let bytes = bincode::serialize(&op.crdt_op)?;
                let signature = self.keypair.sign(&bytes);
                op.signature = Some(signature);
                data.apply_data_op(op.clone())?;
            }
        }

        self.pay_and_write_sequence_to_network(data.clone()).await?;

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
    /// # extern crate tokio; use sn_client::Error; use std::str::FromStr;
    /// use sn_client::Client;
    /// use sn_data_types::{Keypair, PublicKey, Token, SequencePrivatePermissions};
    /// use std::collections::BTreeMap;
    /// use xor_name::XorName;
    /// use rand::rngs::OsRng;
    /// # #[tokio::main] async fn main() { let _: Result<(), Error> = futures::executor::block_on( async {
    /// // Let's use an existing client, with a pre-existing balance to be used for write payments.
    /// let id = std::sync::Keypair::new_ed25519(&mut OsRng);

    /// let mut client = Client::new(Some(id), None).await?;
    /// # let initial_balance = Token::from_str("100")?; client.trigger_simulated_farming_payout(initial_balance).await?;
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
    pub async fn delete_sequence(&self, address: SequenceAddress) -> Result<(), Error> {
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
    /// # extern crate tokio; use sn_client::Error; use std::str::FromStr;
    /// use sn_client::Client;
    /// use sn_data_types::{Keypair, PublicKey, Token, SequencePrivatePermissions};
    /// use std::collections::BTreeMap;
    /// use xor_name::XorName;
    /// use rand::rngs::OsRng;
    /// # #[tokio::main] async fn main() { let _: Result<(), Error> = futures::executor::block_on( async {
    /// // Let's use an existing client, with a pre-existing balance to be used for write payments.
    /// let id = std::sync::Keypair::new_ed25519(&mut OsRng);

    /// let mut client = Client::new(Some(id), None).await?;
    /// # let initial_balance = Token::from_str("100")?; client.trigger_simulated_farming_payout(initial_balance).await?;
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
        &self,
        address: SequenceAddress,
        entry: SequenceEntry,
    ) -> Result<(), Error> {
        // First we fetch it so we can get the causality info,
        // either from local CRDT replica or from the network if not found
        let mut sequence = self.get_sequence(address).await?;

        // We can now append the entry to the Sequence
        let mut op = sequence.create_unsigned_append_op(entry)?;
        let bytes = bincode::serialize(&op.crdt_op)?;
        let signature = self.keypair.sign(&bytes);
        op.signature = Some(signature);
        sequence.apply_data_op(op.clone())?;

        // Finally we can send the mutation to the network's replicas
        self.pay_and_write_append_to_sequence_to_network(op).await
    }

    /// Append data to a sequenced data object
    /// Wraps msg_contents for payment validation and mutation
    async fn pay_and_write_append_to_sequence_to_network(
        &self,
        op: SequenceDataWriteOp<Vec<u8>>,
    ) -> Result<(), Error> {
        let cmd = DataCmd::Sequence(SequenceWrite::Edit(op));

        self.pay_and_send_data_command(cmd).await
    }

    /// Store a new public sequenced data object
    /// Wraps msg_contents for payment validation and mutation
    pub(crate) async fn pay_and_write_sequence_to_network(
        &self,
        data: Sequence,
    ) -> Result<(), Error> {
        debug!("Attempting to pay and write data to network");
        let cmd = DataCmd::Sequence(SequenceWrite::New(data));

        self.pay_and_send_data_command(cmd).await
    }

    //----------------------
    // Get Sequence
    //---------------------

    /// Get Sequence Data from the Network
    ///
    /// # Examples
    /// ```no_run
    /// # extern crate tokio; use sn_client::Error; use std::str::FromStr;
    /// use sn_client::Client;
    /// use sn_data_types::{Keypair, PublicKey, Token, SequencePrivatePermissions};
    /// use std::collections::BTreeMap;
    /// use xor_name::XorName;
    /// use rand::rngs::OsRng;
    /// # #[tokio::main] async fn main() { let _: Result<(), Error> = futures::executor::block_on( async {
    /// // Let's use an existing client, with a pre-existing balance to be used for write payments.
    /// let id = std::sync::Keypair::new_ed25519(&mut OsRng);

    /// let mut client = Client::new(Some(id), None).await?;
    /// # let initial_balance = Token::from_str("100")?; client.trigger_simulated_farming_payout(initial_balance).await?;
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
    pub async fn get_sequence(&self, address: SequenceAddress) -> Result<Sequence, Error> {
        trace!("Get Sequence Data at {:?}", address.name());
        // Let's fetch it from the network then
        let sequence = match self
            .send_query(wrap_seq_read(SequenceRead::Get(address)))
            .await?
        {
            QueryResponse::GetSequence(res) => res.map_err(Error::from),
            _ => Err(Error::ReceivedUnexpectedEvent),
        }?;

        Ok(sequence)
    }

    /// Get the last data entry from a Sequence Data.
    ///
    /// # Examples
    /// ```no_run
    /// # extern crate tokio; use sn_client::Error; use std::str::FromStr;
    /// use sn_client::Client;
    /// use sn_data_types::{Keypair, PublicKey, Token, SequencePrivatePermissions};
    /// use std::collections::BTreeMap;
    /// use xor_name::XorName;
    /// use rand::rngs::OsRng;
    /// # #[tokio::main] async fn main() { let _: Result<(), Error> = futures::executor::block_on( async {
    /// // Let's use an existing client, with a pre-existing balance to be used for write payments.
    /// let id = std::sync::Keypair::new_ed25519(&mut OsRng);

    /// let mut client = Client::new(Some(id), None).await?;
    /// # let initial_balance = Token::from_str("100")?; client.trigger_simulated_farming_payout(initial_balance).await?;
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
        &self,
        address: SequenceAddress,
    ) -> Result<(u64, SequenceEntry), Error> {
        trace!(
            "Get latest entry from Sequence Data at {:?}",
            address.name()
        );

        let sequence = self.get_sequence(address).await?;
        // TODO: do we need to query with some specific PK?
        match sequence.last_entry(None)? {
            Some(entry) => Ok((sequence.len(None)? - 1, entry.to_vec())),
            None => Err(Error::from(sn_data_types::Error::NoSuchEntry)),
        }
    }

    /// Get Sequence Data from the Network at a specific version
    ///
    /// # Examples
    /// ```no_run
    /// # extern crate tokio; use sn_client::Error; use std::str::FromStr;
    /// use sn_client::Client;
    /// use sn_data_types::{Keypair, PublicKey, Token, SequencePrivatePermissions};
    /// use std::collections::BTreeMap;
    /// use xor_name::XorName;
    /// use rand::rngs::OsRng;
    /// # #[tokio::main] async fn main() { let _: Result<(), Error> = futures::executor::block_on( async {
    /// // Let's use an existing client, with a pre-existing balance to be used for write payments.
    /// let id = std::sync::Keypair::new_ed25519(&mut OsRng);

    /// let mut client = Client::new(Some(id), None).await?;
    /// # let initial_balance = Token::from_str("100")?; client.trigger_simulated_farming_payout(initial_balance).await?;
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
    /// let entry_v1 = client.get_sequence_entry(address, 1).await?;
    ///
    /// assert_eq!(entry_v1, b"Another New Entry Value".to_vec());
    /// # Ok(()) } ); }
    /// ```
    pub async fn get_sequence_entry(
        &self,
        address: SequenceAddress,
        index_from_start: u64,
    ) -> Result<SequenceEntry, Error> {
        trace!(
            "Get entry at index {:?} from Sequence Data {:?}",
            index_from_start,
            address.name()
        );

        let sequence = self.get_sequence(address).await?;
        let index = SequenceIndex::FromStart(index_from_start);
        match sequence.get(index, None)? {
            Some(entry) => Ok(entry.to_vec()),
            None => Err(Error::from(sn_data_types::Error::NoSuchEntry)),
        }
    }

    /// Get a set of Entries for the requested range from a Sequence.
    ///
    /// # Examples
    /// ```no_run
    /// # extern crate tokio; use sn_client::Error; use std::str::FromStr;
    /// use sn_client::Client;
    /// use sn_data_types::{Keypair, PublicKey, Token, SequencePrivatePermissions, SequenceIndex};
    /// use std::collections::BTreeMap;
    /// use xor_name::XorName;
    /// use rand::rngs::OsRng;
    /// # #[tokio::main] async fn main() { let _: Result<(), Error> = futures::executor::block_on( async {
    /// // Let's use an existing client, with a pre-existing balance to be used for write payments.
    /// let id = std::sync::Keypair::new_ed25519(&mut OsRng);

    /// let mut client = Client::new(Some(id), None).await?;
    /// # let initial_balance = Token::from_str("100")?; client.trigger_simulated_farming_payout(initial_balance).await?;
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
        &self,
        address: SequenceAddress,
        range: (SequenceIndex, SequenceIndex),
    ) -> Result<SequenceEntries, Error> {
        trace!(
            "Get range of entries from Sequence Data at {:?}",
            address.name()
        );

        let sequence = self.get_sequence(address).await?;
        // TODO: do we need to query with some specific PK?
        sequence
            .in_range(range.0, range.1, None)?
            .ok_or_else(|| Error::from(sn_data_types::Error::NoSuchEntry))
    }

    //----------------------
    // Ownership
    //---------------------

    /// Get the owner of a Sequence.
    ///
    /// # Examples
    /// ```no_run
    /// # extern crate tokio; use sn_client::Error; use std::str::FromStr;
    /// use sn_client::Client;
    /// use sn_data_types::{Keypair, PublicKey, Token, SequencePrivatePermissions};
    /// use std::collections::BTreeMap;
    /// use xor_name::XorName;
    /// use rand::rngs::OsRng;
    /// # #[tokio::main] async fn main() { let _: Result<(), Error> = futures::executor::block_on( async {
    /// // Let's use an existing client, with a pre-existing balance to be used for write payments.
    /// let id = std::sync::Keypair::new_ed25519(&mut OsRng);

    /// let mut client = Client::new(Some(id), None).await?;
    /// # let initial_balance = Token::from_str("100")?; client.trigger_simulated_farming_payout(initial_balance).await?;
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
    pub async fn get_sequence_owner(&self, address: SequenceAddress) -> Result<PublicKey, Error> {
        trace!("Get owner of the Sequence Data at {:?}", address.name());

        // TODO: perhaps we want to grab it directly from the network and update local replica
        let sequence = self.get_sequence(address).await?;

        let owner = if sequence.is_pub() {
            sequence.public_policy()?.owner
        } else {
            // TODO: do we need to query with some specific PK?
            sequence.private_policy(None)?.owner
        };

        Ok(owner)
    }

    /// Set the new owner of a Sequence Data
    /// Update sequence data owners
    ///
    /// # Examples
    /// ```no_run
    /// # extern crate tokio; use sn_client::Error; use std::str::FromStr;
    /// use sn_client::Client;
    /// use sn_data_types::{Keypair, PublicKey, Token, SequencePrivatePermissions};
    /// use std::collections::BTreeMap;
    /// use xor_name::XorName;
    /// use rand::rngs::OsRng;
    /// use threshold_crypto::SecretKey;
    /// # #[tokio::main] async fn main() { let _: Result<(), Error> = futures::executor::block_on( async {
    /// // Let's use an existing client, with a pre-existing balance to be used for write payments.
    /// let id = std::sync::Keypair::new_ed25519(&mut OsRng);

    /// let mut client = Client::new(Some(id), None).await?;
    /// # let initial_balance = Token::from_str("100")?; client.trigger_simulated_farming_payout(initial_balance).await?;
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
        &self,
        address: SequenceAddress,
        owner: PublicKey,
    ) -> Result<(), Error> {
        // First we fetch it either from local CRDT replica or from the network if not found
        let mut sequence = self.get_sequence(address).await?;

        let pk = self.public_key().await;

        // get current policy permissions
        let permissions = sequence.private_policy(Some(pk))?.permissions.clone();

        // set new owner against this
        let mut op = sequence.create_unsigned_private_policy_op(owner, permissions)?;
        let bytes = bincode::serialize(&op.crdt_op)?;
        let signature = self.keypair.sign(&bytes);
        op.signature = Some(signature);
        sequence.apply_private_policy_op(op.clone())?;

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
    /// # extern crate tokio; use sn_client::Error; use std::str::FromStr;
    /// use sn_client::Client;
    /// use sn_data_types::{Keypair, Token, SequenceUser,SequencePublicPermissions};
    /// use std::collections::BTreeMap;
    /// use xor_name::XorName;
    /// use rand::rngs::OsRng;
    /// # #[tokio::main] async fn main() { let _: Result<(), Error> = futures::executor::block_on( async {
    /// // Let's use an existing client, with a pre-existing balance to be used for write payments.
    /// let id = std::sync::Keypair::new_ed25519(&mut OsRng);

    /// let mut client = Client::new(Some(id), None).await?;
    /// # let initial_balance = Token::from_str("100")?; client.trigger_simulated_farming_payout(initial_balance).await?;
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
        &self,
        address: SequenceAddress,
        user: PublicKey,
    ) -> Result<SequencePublicPermissions, Error> {
        trace!(
            "Get permissions from Public Sequence Data at {:?}",
            address.name()
        );

        // TODO: perhaps we want to grab it directly from
        // the network and update local replica
        let sequence = self.get_sequence(address).await?;
        // TODO: do we need to query with some specific PK?
        let perms = match sequence
            .permissions(SequenceUser::Key(user), None)
            .map_err(Error::from)?
        {
            SequencePermissions::Public(perms) => perms,
            _ => return Err(Error::NotPublicPermissions),
        };

        Ok(perms)
    }

    /// Get the set of Permissions of a Private Sequence.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # extern crate tokio; use sn_client::Error; use std::str::FromStr;
    /// use sn_client::Client;
    /// use sn_data_types::{Keypair, PublicKey, Token, SequencePrivatePermissions};
    /// use std::collections::BTreeMap;
    /// use xor_name::XorName;
    /// use rand::rngs::OsRng;
    /// # #[tokio::main] async fn main() { let _: Result<(), Error> = futures::executor::block_on( async {
    /// // Let's use an existing client, with a pre-existing balance to be used for write payments.
    /// let id = std::sync::Keypair::new_ed25519(&mut OsRng);

    /// let mut client = Client::new(Some(id), None).await?;
    /// # let initial_balance = Token::from_str("100")?; client.trigger_simulated_farming_payout(initial_balance).await?;
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
        &self,
        address: SequenceAddress,
        user: PublicKey,
    ) -> Result<SequencePrivatePermissions, Error> {
        trace!(
            "Get permissions from Private Sequence Data at {:?}",
            address.name()
        );
        let sequence = self.get_sequence(address).await?;

        // TODO: do we need to query with some specific PK?
        let perms = match sequence
            .permissions(SequenceUser::Key(user), None)
            .map_err(Error::from)?
        {
            SequencePermissions::Private(perms) => perms,
            _ => return Err(Error::NotPrivatePermissions),
        };

        Ok(perms)
    }

    /// Get the set of Permissions for a specific user in a Sequence.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # extern crate tokio; use sn_client::Error; use std::str::FromStr;
    /// use sn_client::Client;
    /// use sn_data_types::{Keypair, PublicKey, Token, SequencePrivatePermissions};
    /// use std::collections::BTreeMap;
    /// use xor_name::XorName;
    /// use rand::rngs::OsRng;
    /// # #[tokio::main] async fn main() { let _: Result<(), Error> = futures::executor::block_on( async {
    /// // Let's use an existing client, with a pre-existing balance to be used for write payments.
    /// let id = std::sync::Keypair::new_ed25519(&mut OsRng);

    /// let mut client = Client::new(Some(id), None).await?;
    /// # let initial_balance = Token::from_str("100")?; client.trigger_simulated_farming_payout(initial_balance).await?;
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
        &self,
        address: SequenceAddress,
        user: SequenceUser,
    ) -> Result<SequencePermissions, Error> {
        trace!(
            "Get permissions for user {:?} from Sequence Data at {:?}",
            user,
            address.name()
        );

        // TODO: perhaps we want to grab it directly from
        // the network and update local replica
        let sequence = self.get_sequence(address).await?;
        // TODO: do we need to query with some specific PK?
        let perms = sequence.permissions(user, None).map_err(Error::from)?;

        Ok(perms)
    }

    /// Set permissions for a PublicKey on a Public Sequence
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # extern crate tokio; use sn_client::Error; use std::str::FromStr;
    /// use sn_client::Client;
    /// use sn_data_types::{Keypair, PublicKey, SequenceUser, Token, SequencePublicPermissions};
    /// use std::collections::BTreeMap;
    /// use xor_name::XorName;
    /// use rand::rngs::OsRng;
    /// use threshold_crypto::SecretKey;
    /// # #[tokio::main] async fn main() { let _: Result<(), Error> = futures::executor::block_on( async {
    /// // Let's use an existing client, with a pre-existing balance to be used for write payments.
    /// let id = std::sync::Keypair::new_ed25519(&mut OsRng);

    /// let mut client = Client::new(Some(id), None).await?;
    /// # let initial_balance = Token::from_str("100")?; client.trigger_simulated_farming_payout(initial_balance).await?;
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
        &self,
        address: SequenceAddress,
        permissions: BTreeMap<SequenceUser, SequencePublicPermissions>,
    ) -> Result<(), Error> {
        // First we fetch it either from local CRDT replica or from the network if not found
        let mut sequence = self.get_sequence(address).await?;

        // We can now set the new permissions to the Sequence
        let mut op =
            sequence.create_unsigned_public_policy_op(self.public_key().await, permissions)?;
        let bytes = bincode::serialize(&op.crdt_op)?;
        let signature = self.keypair.sign(&bytes);
        op.signature = Some(signature);
        sequence.apply_public_policy_op(op.clone())?;

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
    /// # extern crate tokio; use sn_client::Error; use std::str::FromStr;
    /// use sn_client::Client;
    /// use sn_data_types::{Keypair, PublicKey, Token, SequencePrivatePermissions};
    /// use std::collections::BTreeMap;
    /// use xor_name::XorName;
    /// use rand::rngs::OsRng;
    /// use threshold_crypto::SecretKey;
    /// # #[tokio::main] async fn main() { let _: Result<(), Error> = futures::executor::block_on( async {
    /// // Let's use an existing client, with a pre-existing balance to be used for write payments.
    /// let id = std::sync::Keypair::new_ed25519(&mut OsRng);

    /// let mut client = Client::new(Some(id), None).await?;
    /// # let initial_balance = Token::from_str("100")?; client.trigger_simulated_farming_payout(initial_balance).await?;
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
        &self,
        address: SequenceAddress,
        permissions: BTreeMap<PublicKey, SequencePrivatePermissions>,
    ) -> Result<(), Error> {
        // First we fetch it either from local CRDT replica or from the network if not found
        let mut sequence = self.get_sequence(address).await?;

        // We can now set the new permissions to the Sequence
        let mut op =
            sequence.create_unsigned_private_policy_op(self.public_key().await, permissions)?;
        let bytes = bincode::serialize(&op.crdt_op)?;
        let signature = self.keypair.sign(&bytes);
        op.signature = Some(signature);
        sequence.apply_private_policy_op(op.clone())?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::gen_ed_keypair;
    use sn_data_types::{SequenceAction, SequencePrivatePermissions, Token};
    use sn_messaging::Error as ErrorMessage;
    use std::str::FromStr;
    use tokio::time::{delay_for, Duration};
    use unwrap::unwrap;
    use xor_name::XorName;

    #[tokio::test]
    pub async fn sequence_deletions_should_cost_put_price() -> Result<(), Error> {
        let name = XorName(rand::random());
        let tag = 10;
        let client = Client::new(None, None).await?;
        let owner = client.public_key().await;
        let perms = BTreeMap::<PublicKey, SequencePrivatePermissions>::new();
        let sequence_address = client
            .store_private_sequence(None, name, tag, owner, perms)
            .await?;

        let mut balance_before_delete = client.get_balance().await?;

        while balance_before_delete == Token::from_str("0")?
            || balance_before_delete == Token::from_str("10")?
        {
            delay_for(Duration::from_millis(200)).await;
            balance_before_delete = client.get_balance().await?;
        }

        client.delete_sequence(sequence_address).await?;
        let mut new_balance = client.get_balance().await?;

        // now let's ensure we've paid _something_
        while new_balance == balance_before_delete {
            delay_for(Duration::from_millis(200)).await;
            new_balance = client.get_balance().await?;
        }

        Ok(())
    }

    /// Sequence data tests ///

    #[tokio::test]
    pub async fn sequence_basics_test() -> Result<(), Error> {
        let client = Client::new(None, None).await?;

        let name = XorName(rand::random());
        let tag = 15000;
        let owner = client.public_key().await;

        // store a Private Sequence
        let mut perms = BTreeMap::<PublicKey, SequencePrivatePermissions>::new();
        let _ = perms.insert(owner, SequencePrivatePermissions::new(true, true, true));
        let address = client
            .store_private_sequence(None, name, tag, owner, perms)
            .await?;

        let mut seq_res = client.get_sequence(address).await;

        while seq_res.is_err() {
            delay_for(Duration::from_millis(200)).await;
            seq_res = client.get_sequence(address).await;
        }

        let sequence = seq_res?;

        assert!(sequence.is_private());
        assert_eq!(*sequence.name(), name);
        assert_eq!(sequence.tag(), tag);
        assert_eq!(sequence.policy_version(None)?, Some(0));
        assert_eq!(sequence.policy_version(None)?, Some(0));
        assert_eq!(sequence.len(None)?, 0);

        // store a Public Sequence
        let mut perms = BTreeMap::<SequenceUser, SequencePublicPermissions>::new();
        let _ = perms.insert(
            SequenceUser::Anyone,
            SequencePublicPermissions::new(true, true),
        );
        let address = client
            .store_public_sequence(None, name, tag, owner, perms)
            .await?;

        let mut seq_res = client.get_sequence(address).await;

        while seq_res.is_err() {
            delay_for(Duration::from_millis(200)).await;
            seq_res = client.get_sequence(address).await;
        }

        let sequence = seq_res?;

        assert!(sequence.is_pub());
        assert_eq!(*sequence.name(), name);
        assert_eq!(sequence.tag(), tag);
        assert_eq!(sequence.policy_version(None)?, Some(0));
        assert_eq!(sequence.policy_version(None)?, Some(0));
        assert_eq!(sequence.len(None)?, 0);

        Ok(())
    }

    #[tokio::test]
    pub async fn sequence_private_permissions_test() -> Result<(), Error> {
        let client = Client::new(None, None).await?;
        let name = XorName(rand::random());
        let tag = 15000;
        let owner = client.public_key().await;
        let mut perms = BTreeMap::<PublicKey, SequencePrivatePermissions>::new();
        let _ = perms.insert(owner, SequencePrivatePermissions::new(true, true, true));
        let address = client
            .store_private_sequence(None, name, tag, owner, perms)
            .await?;

        let mut seq_res = client.get_sequence(address).await;

        while seq_res.is_err() {
            delay_for(Duration::from_millis(200)).await;
            seq_res = client.get_sequence(address).await;
        }

        let data = seq_res?;

        assert_eq!(data.len(None)?, 0);
        assert_eq!(data.policy_version(None)?, Some(0));

        let mut seq_res = client
            .get_sequence_private_permissions_for_user(address, owner)
            .await;

        while seq_res.is_err() {
            delay_for(Duration::from_millis(200)).await;
            seq_res = client
                .get_sequence_private_permissions_for_user(address, owner)
                .await;
        }

        let user_perms = seq_res?;

        assert!(user_perms.is_allowed(SequenceAction::Read));
        assert!(user_perms.is_allowed(SequenceAction::Append));
        assert!(user_perms.is_allowed(SequenceAction::Admin));

        let mut seq_res = client
            .get_sequence_permissions(address, SequenceUser::Key(owner))
            .await;
        while seq_res.is_err() {
            delay_for(Duration::from_millis(200)).await;
            seq_res = client
                .get_sequence_permissions(address, SequenceUser::Key(owner))
                .await;
        }

        match seq_res? {
            SequencePermissions::Private(user_perms) => {
                assert!(user_perms.is_allowed(SequenceAction::Read));
                assert!(user_perms.is_allowed(SequenceAction::Append));
                assert!(user_perms.is_allowed(SequenceAction::Admin));
            }
            SequencePermissions::Public(_) => return Err(Error::IncorrectPermissions),
        }

        let sim_client = gen_ed_keypair().public_key();
        let mut perms2 = BTreeMap::<PublicKey, SequencePrivatePermissions>::new();
        let _ = perms2.insert(
            sim_client,
            SequencePrivatePermissions::new(false, true, false),
        );
        client
            .sequence_set_private_permissions(address, perms2)
            .await?;

        let mut seq_res = client
            .get_sequence_private_permissions_for_user(address, sim_client)
            .await;

        while seq_res.is_err() {
            delay_for(Duration::from_millis(200)).await;
            seq_res = client
                .get_sequence_private_permissions_for_user(address, sim_client)
                .await;
        }

        let user_perms = seq_res?;

        assert!(!user_perms.is_allowed(SequenceAction::Read));
        assert!(user_perms.is_allowed(SequenceAction::Append));
        assert!(!user_perms.is_allowed(SequenceAction::Admin));

        let mut seq_res = client
            .get_sequence_permissions(address, SequenceUser::Key(sim_client))
            .await;
        while seq_res.is_err() {
            delay_for(Duration::from_millis(200)).await;
            seq_res = client
                .get_sequence_permissions(address, SequenceUser::Key(sim_client))
                .await;
        }

        match seq_res? {
            SequencePermissions::Private(user_perms) => {
                assert!(!user_perms.is_allowed(SequenceAction::Read));
                assert!(user_perms.is_allowed(SequenceAction::Append));
                assert!(!user_perms.is_allowed(SequenceAction::Admin));
                Ok(())
            }
            SequencePermissions::Public(_) => Err(Error::IncorrectPermissions),
        }
    }

    #[tokio::test]
    pub async fn sequence_pub_permissions_test() -> anyhow::Result<()> {
        let client = Client::new(None, None).await?;

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

        let mut seq_res = client.get_sequence(address).await;

        while seq_res.is_err() {
            delay_for(Duration::from_millis(200)).await;
            seq_res = client.get_sequence(address).await;
        }

        let data = seq_res?;

        assert_eq!(data.len(None)?, 0);
        assert_eq!(data.policy_version(None)?, Some(0));

        let mut seq_res = client
            .get_sequence_pub_permissions_for_user(address, owner)
            .await;

        while seq_res.is_err() {
            delay_for(Duration::from_millis(200)).await;
            seq_res = client
                .get_sequence_pub_permissions_for_user(address, owner)
                .await;
        }

        let user_perms = seq_res?;

        assert_eq!(Some(true), user_perms.is_allowed(SequenceAction::Read));
        assert_eq!(None, user_perms.is_allowed(SequenceAction::Append));
        assert_eq!(Some(true), user_perms.is_allowed(SequenceAction::Admin));

        let mut seq_res = client
            .get_sequence_permissions(address, SequenceUser::Key(owner))
            .await;
        while seq_res.is_err() {
            delay_for(Duration::from_millis(200)).await;
            seq_res = client
                .get_sequence_permissions(address, SequenceUser::Key(owner))
                .await;
        }

        match seq_res? {
            SequencePermissions::Public(user_perms) => {
                assert_eq!(Some(true), user_perms.is_allowed(SequenceAction::Read));
                assert_eq!(None, user_perms.is_allowed(SequenceAction::Append));
                assert_eq!(Some(true), user_perms.is_allowed(SequenceAction::Admin));
            }
            SequencePermissions::Private(_) => {
                return Err(anyhow::anyhow!(
                    "Unexpectedly obtained incorrect user permissions",
                ));
            }
        }

        let sim_client = gen_ed_keypair().public_key();
        let mut perms2 = BTreeMap::<SequenceUser, SequencePublicPermissions>::new();
        let _ = perms2.insert(
            SequenceUser::Key(sim_client),
            SequencePublicPermissions::new(false, false),
        );
        client
            .sequence_set_public_permissions(address, perms2)
            .await?;

        let mut seq_res = client
            .get_sequence_pub_permissions_for_user(address, sim_client)
            .await;

        while seq_res.is_err() {
            delay_for(Duration::from_millis(200)).await;
            seq_res = client
                .get_sequence_pub_permissions_for_user(address, sim_client)
                .await;
        }

        let user_perms = seq_res?;

        assert_eq!(Some(true), user_perms.is_allowed(SequenceAction::Read));
        assert_eq!(Some(false), user_perms.is_allowed(SequenceAction::Append));
        assert_eq!(Some(false), user_perms.is_allowed(SequenceAction::Admin));

        let mut seq_res = client
            .get_sequence_permissions(address, SequenceUser::Key(sim_client))
            .await;
        while seq_res.is_err() {
            delay_for(Duration::from_millis(200)).await;
            seq_res = client
                .get_sequence_permissions(address, SequenceUser::Key(sim_client))
                .await;
        }

        match seq_res? {
            SequencePermissions::Public(user_perms) => {
                assert_eq!(Some(true), user_perms.is_allowed(SequenceAction::Read));
                assert_eq!(Some(false), user_perms.is_allowed(SequenceAction::Append));
                assert_eq!(Some(false), user_perms.is_allowed(SequenceAction::Admin));
                Ok(())
            }
            SequencePermissions::Private(_) => Err(Error::IncorrectPermissions.into()),
        }
    }

    #[tokio::test]
    pub async fn append_to_sequence_test() -> anyhow::Result<()> {
        let name = XorName(rand::random());
        let tag = 10;
        let client = Client::new(None, None).await?;

        let owner = client.public_key().await;
        let mut perms = BTreeMap::<SequenceUser, SequencePublicPermissions>::new();
        let _ = perms.insert(
            SequenceUser::Key(owner),
            SequencePublicPermissions::new(true, true),
        );

        let address = client
            .store_public_sequence(None, name, tag, owner, perms)
            .await?;

        // append to the data the data
        let mut seq_res = client.append_to_sequence(address, b"VALUE1".to_vec()).await;

        while seq_res.is_err() {
            delay_for(Duration::from_millis(200)).await;
            seq_res = client.append_to_sequence(address, b"VALUE1".to_vec()).await;
        }

        // now check last entry
        let mut seq_res = client.get_sequence_last_entry(address).await;

        while seq_res.is_err() {
            delay_for(Duration::from_millis(200)).await;
            seq_res = client.get_sequence_last_entry(address).await;
        }

        let (index, data) = seq_res?;

        assert_eq!(0, index);
        assert_eq!(unwrap!(std::str::from_utf8(&data)), "VALUE1");

        // append to the data the data
        let mut seq_res = client.append_to_sequence(address, b"VALUE2".to_vec()).await;

        while seq_res.is_err() {
            delay_for(Duration::from_millis(200)).await;
            seq_res = client.append_to_sequence(address, b"VALUE2".to_vec()).await;
        }

        // and then lets check last entry
        let mut seq_res = client.get_sequence_last_entry(address).await;

        while seq_res.is_err() {
            delay_for(Duration::from_millis(200)).await;
            seq_res = client.get_sequence_last_entry(address).await;
        }

        let (mut index, mut data) = seq_res?;
        // we might still be getting old data here
        while index == 0 {
            delay_for(Duration::from_millis(200)).await;
            let (i, d) = client.get_sequence_last_entry(address).await?;
            index = i;
            data = d;
        }

        assert_eq!(1, index);
        assert_eq!(unwrap!(std::str::from_utf8(&data)), "VALUE2");

        let mut seq_res = client
            .get_sequence_range(
                address,
                (SequenceIndex::FromStart(0), SequenceIndex::FromEnd(0)),
            )
            .await;

        while seq_res.is_err() {
            delay_for(Duration::from_millis(200)).await;
            seq_res = client
                .get_sequence_range(
                    address,
                    (SequenceIndex::FromStart(0), SequenceIndex::FromEnd(0)),
                )
                .await;
        }

        let data = seq_res?;

        assert_eq!(unwrap!(std::str::from_utf8(&data[0])), "VALUE1");
        assert_eq!(unwrap!(std::str::from_utf8(&data[1])), "VALUE2");

        // get_sequence_entry

        let data0 = client.get_sequence_entry(address, 0).await?;
        assert_eq!(unwrap!(std::str::from_utf8(&data0)), "VALUE1");

        let data1 = client.get_sequence_entry(address, 1).await?;
        assert_eq!(unwrap!(std::str::from_utf8(&data1)), "VALUE2");

        // Requesting a version that's too high throws an error
        let res = client.get_sequence_entry(address, 2).await;
        match res {
            Err(_) => Ok(()),
            Ok(_data) => Err(anyhow::anyhow!(
                "Unexpectedly retrieved a sequence entry at index that's too high!",
            )),
        }
    }

    #[tokio::test]
    pub async fn sequence_owner_test() -> Result<(), Error> {
        let name = XorName(rand::random());
        let tag = 10;
        let client = Client::new(None, None).await?;

        let owner = client.public_key().await;
        let mut perms = BTreeMap::<PublicKey, SequencePrivatePermissions>::new();
        let _ = perms.insert(owner, SequencePrivatePermissions::new(true, true, true));
        let address = client
            .store_private_sequence(None, name, tag, owner, perms)
            .await?;

        // Assert that the data is stored.
        let mut res = client.get_sequence(address).await;
        while res.is_err() {
            delay_for(Duration::from_millis(200)).await;
            res = client.get_sequence(address).await;
        }

        client
            .append_to_sequence(address, b"VALUE1".to_vec())
            .await?;

        let mut data = client.get_sequence(address).await?;
        while data.len(None)? == 0 {
            delay_for(Duration::from_millis(200)).await;
            data = client.get_sequence(address).await?;
        }

        client
            .append_to_sequence(address, b"VALUE2".to_vec())
            .await?;

        let mut data = client.get_sequence(address).await?;
        while data.len(None)? == 1 {
            delay_for(Duration::from_millis(200)).await;
            data = client.get_sequence(address).await?;
        }

        assert_eq!(data.len(None)?, 2);
        assert_eq!(data.policy_version(None)?, Some(0));

        let current_owner = client.get_sequence_owner(address).await?;
        assert_eq!(owner, current_owner);

        let sim_client = gen_ed_keypair().public_key();
        client
            .set_private_sequence_owner(address, sim_client)
            .await?;

        let mut res = client.get_sequence_owner(address).await?;
        while res != sim_client {
            delay_for(Duration::from_millis(200)).await;
            res = client.get_sequence_owner(address).await?;
        }

        Ok(())
    }

    #[tokio::test]
    pub async fn sequence_can_delete_private_test() -> anyhow::Result<()> {
        let client = Client::new(None, None).await?;
        let name = XorName(rand::random());
        let tag = 15000;
        let owner = client.public_key().await;

        // store a Private Sequence
        let mut perms = BTreeMap::<PublicKey, SequencePrivatePermissions>::new();
        let _ = perms.insert(owner, SequencePrivatePermissions::new(true, true, true));
        let address = client
            .store_private_sequence(None, name, tag, owner, perms)
            .await?;

        let mut sequence = client.get_sequence(address).await;

        while sequence.is_err() {
            delay_for(Duration::from_millis(200)).await;
            sequence = client.get_sequence(address).await;
        }

        assert!(sequence?.is_private());

        client.delete_sequence(address).await?;

        let mut res = client.get_sequence(address).await;

        while res.is_ok() {
            delay_for(Duration::from_millis(200)).await;
            res = client.get_sequence(address).await;
        }

        match res {
            Err(Error::ErrorMessage(ErrorMessage::NoSuchData)) => Ok(()),
            Err(err) => Err(anyhow::anyhow!(
                "Unexpected error returned when deleting a nonexisting Private Sequence: {}",
                err
            )),
            Ok(_data) => Err(anyhow::anyhow!(
                "Unexpectedly retrieved a deleted Private Sequence!",
            )),
        }
    }

    #[tokio::test]
    pub async fn sequence_cannot_delete_public_test() -> anyhow::Result<()> {
        let client = Client::new(None, None).await?;

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

        let mut sequence = client.get_sequence(address).await;

        while sequence.is_err() {
            sequence = client.get_sequence(address).await;
        }

        assert!(sequence?.is_pub());

        client.delete_sequence(address).await?;

        // Check that our data still exists.
        match client.get_sequence(address).await {
            Err(Error::ErrorMessage(ErrorMessage::InvalidOperation)) => Ok(()),
            Err(err) => Err(anyhow::anyhow!(
                "Unexpected error returned when attempting to get a Public Sequence: {}",
                err
            )),
            Ok(_data) => Ok(()),
        }
    }
}
