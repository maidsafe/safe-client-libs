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
    Cmd, DataCmd, DataQuery, Map, MapAddress, MapEntries, MapEntryActions, MapPermissionSet,
    MapRead, MapSeqEntries, MapSeqEntryActions, MapSeqValue, MapUnseqEntryActions, MapValue,
    MapValues, PublicKey, Query, QueryResponse,
};

use sn_data_types::MapWrite;

use xor_name::XorName;

use std::collections::{BTreeMap, BTreeSet};

fn wrap_map_read(read: MapRead) -> Query {
    Query::Data(DataQuery::Map(read))
}

impl Client {
    //-------------------
    // Store
    // ------------------

    /// Store a new map
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # extern crate tokio; use sn_client::ClientError; use std::str::FromStr;
    /// use sn_client::Client;
    /// use sn_data_types::{ ClientFullId, Money, Map, MapAction, MapPermissionSet, UnseqMap};
    /// use rand::rngs::OsRng;
    /// use std::collections::BTreeMap;
    /// use xor_name::XorName;
    /// # #[tokio::main] async fn main() { let _: Result<(), ClientError> = futures::executor::block_on( async {
    /// // Let's use an existing client, with a pre-existing balance to be used for write payments.
    /// let id = ClientFullId::new_ed25519(&mut OsRng);
    /// let mut client = Client::new(Some(id)).await?;
    /// # let initial_balance = Money::from_str("100")?; client.trigger_simulated_farming_payout(initial_balance).await?;
    /// let name = XorName::random();
    /// let tag = 15001;
    /// let mut entries: BTreeMap<Vec<u8>, Vec<u8>> = Default::default();
    /// let mut permissions: BTreeMap<_, _> = Default::default();
    /// let permission_set = MapPermissionSet::new().allow(MapAction::Read);
    /// let _ = permissions.insert(client.public_key().await, permission_set);
    /// let _ = entries.insert(b"key".to_vec(), b"value".to_vec());
    /// let our_map = Map::Unseq(UnseqMap::new_with_data(
    ///     name,
    ///     tag,
    ///     entries.clone(),
    ///     permissions,
    ///     client.public_key().await,
    /// ));
    /// let _ = client.store_map(our_map.clone()).await?;
    ///
    /// # let balance_after_write = client.get_local_balance().await; assert_ne!(initial_balance, balance_after_write); Ok(()) } ); }
    /// ```
    pub async fn store_map(&mut self, data: Map) -> Result<(), ClientError> {
        let cmd = DataCmd::Map(MapWrite::New(data));

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

    /// Delete Map
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # extern crate tokio; use sn_client::ClientError; use std::str::FromStr;
    /// use sn_client::Client;
    /// use sn_data_types::{ ClientFullId, Money, Map, MapAction, MapPermissionSet, UnseqMap};
    /// use rand::rngs::OsRng;
    /// use std::collections::BTreeMap;
    /// use xor_name::XorName;
    /// # #[tokio::main] async fn main() { let _: Result<(), ClientError> = futures::executor::block_on( async {
    /// // Let's use an existing client, with a pre-existing balance to be used for write payments.
    /// let id = ClientFullId::new_ed25519(&mut OsRng);
    /// let mut client = Client::new(Some(id)).await?;
    /// # let initial_balance = Money::from_str("100")?; client.trigger_simulated_farming_payout(initial_balance).await?;
    /// let name = XorName::random();
    /// let tag = 15001;
    /// let mut entries: BTreeMap<Vec<u8>, Vec<u8>> = Default::default();
    /// let mut permissions: BTreeMap<_, _> = Default::default();
    /// let permission_set = MapPermissionSet::new().allow(MapAction::Read);
    /// let _ = permissions.insert(client.public_key().await, permission_set);
    /// let _ = entries.insert(b"key".to_vec(), b"value".to_vec());
    /// let our_map = Map::Unseq(UnseqMap::new_with_data(
    ///     name,
    ///     tag,
    ///     entries.clone(),
    ///     permissions,
    ///     client.public_key().await,
    /// ));
    /// let _ = client.store_map(our_map.clone()).await?;
    /// # let balance_after_first_write = client.get_local_balance().await; assert_ne!(initial_balance, balance_after_first_write);
    /// let _ = client.delete_map(*our_map.address()).await?;
    /// # let balance_after_second_write = client.get_local_balance().await; assert_ne!(balance_after_second_write, balance_after_first_write);
    /// # Ok(()) } ); }
    /// ```
    pub async fn delete_map(&mut self, address: MapAddress) -> Result<(), ClientError> {
        let cmd = DataCmd::Map(MapWrite::Delete(address));

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

    /// Delete map user permission
    pub async fn delete_map_user_perms(
        &mut self,
        address: MapAddress,
        user: PublicKey,
        version: u64,
    ) -> Result<(), ClientError> {
        let cmd = DataCmd::Map(MapWrite::DelUserPermissions {
            address,
            user,
            version,
        });

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

    /// Set map user permissions
    pub async fn set_map_user_perms(
        &mut self,
        address: MapAddress,
        user: PublicKey,
        permissions: MapPermissionSet,
        version: u64,
    ) -> Result<(), ClientError> {
        let cmd = DataCmd::Map(MapWrite::SetUserPermissions {
            address,
            user,
            permissions,
            version,
        });

        // Payment for PUT
        let payment_proof = self.create_write_payment_proof(&cmd).await?;

        // The _actual_ message
        let msg_contents = Cmd::Data {
            cmd,
            payment: payment_proof.clone(),
        };

        let message = Self::create_cmd_message(msg_contents);

        // TODO what will be the correct reponse here?... We have it validated, so registered?
        let _ = self
            .connection_manager
            .lock()
            .await
            .send_cmd(&message)
            .await?;

        self.apply_write_payment_to_local_actor(payment_proof).await
    }

    /// Mutate map user entries
    pub async fn edit_map_entries(
        &mut self,
        address: MapAddress,
        changes: MapEntryActions,
    ) -> Result<(), ClientError> {
        let cmd = DataCmd::Map(MapWrite::Edit { address, changes });

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

    //-------------------
    // Gets
    // ------------------

    /// Fetch map data from the network
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # extern crate tokio; use sn_client::ClientError; use std::str::FromStr;
    /// use sn_client::Client;
    /// use sn_data_types::{ ClientFullId, Money, Map, MapAction, MapPermissionSet, UnseqMap};
    /// use std::collections::BTreeMap;
    /// use xor_name::XorName;
    /// use rand::rngs::OsRng;
    /// # #[tokio::main] async fn main() { let _: Result<(), ClientError> = futures::executor::block_on( async {
    /// // Let's use an existing client, with a pre-existing balance to be used for write payments.
    /// let id = ClientFullId::new_ed25519(&mut OsRng);
    /// let mut client = Client::new(Some(id)).await?;
    /// # let initial_balance = Money::from_str("100")?; client.trigger_simulated_farming_payout(initial_balance).await?;
    /// let name = XorName::random();
    /// let tag = 15001;
    /// let mut entries: BTreeMap<Vec<u8>, Vec<u8>> = Default::default();
    /// let mut permissions: BTreeMap<_, _> = Default::default();
    /// let permission_set = MapPermissionSet::new().allow(MapAction::Read);
    /// let _ = permissions.insert(client.public_key().await, permission_set);
    /// let _ = entries.insert(b"key".to_vec(), b"value".to_vec());
    /// let our_map = Map::Unseq(UnseqMap::new_with_data(
    ///     name,
    ///     tag,
    ///     entries.clone(),
    ///     permissions,
    ///     client.public_key().await,
    /// ));
    /// let _ = client.store_map(our_map.clone()).await?;
    /// # let balance_after_first_write = client.get_local_balance().await; assert_ne!(initial_balance, balance_after_first_write);
    /// let _ = client.get_map(*our_map.address()).await?;
    /// # Ok(()) } ); }
    /// ```
    pub async fn get_map(&mut self, address: MapAddress) -> Result<Map, ClientError>
    where
        Self: Sized,
    {
        trace!("Fetch Sequenced Mutable Data");

        match self
            .send_query(wrap_map_read(MapRead::Get(address)))
            .await?
        {
            QueryResponse::GetMap(res) => res.map_err(ClientError::from),
            _ => Err(ClientError::ReceivedUnexpectedEvent),
        }
    }

    /// Fetch the value for a given key in a map
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # extern crate tokio; use sn_client::ClientError; use std::str::FromStr;
    /// use sn_client::Client;
    /// use sn_data_types::{ ClientFullId, Money, Map, MapAction, MapValue, MapPermissionSet, UnseqMap};
    /// use std::collections::BTreeMap;
    /// use xor_name::XorName;
    /// use rand::rngs::OsRng;
    /// # #[tokio::main] async fn main() { let _: Result<(), ClientError> = futures::executor::block_on( async {
    /// // Let's use an existing client, with a pre-existing balance to be used for write payments.
    /// let id = ClientFullId::new_ed25519(&mut OsRng);
    /// let mut client = Client::new(Some(id)).await?;
    /// # let initial_balance = Money::from_str("100")?; client.trigger_simulated_farming_payout(initial_balance).await?;
    /// let name = XorName::random();
    /// let tag = 15001;
    /// let mut entries: BTreeMap<Vec<u8>, Vec<u8>> = Default::default();
    /// let _ = entries.insert(b"beep".to_vec(), b"boop".to_vec() );
    /// let mut permissions: BTreeMap<_, _> = Default::default();
    /// let permission_set = MapPermissionSet::new().allow(MapAction::Read);
    /// let _ = permissions.insert(client.public_key().await, permission_set);
    /// let _ = entries.insert(b"key".to_vec(), b"value".to_vec());
    /// let our_map = Map::Unseq(UnseqMap::new_with_data(
    ///     name,
    ///     tag,
    ///     entries.clone(),
    ///     permissions,
    ///     client.public_key().await,
    /// ));
    /// let _ = client.store_map(our_map.clone()).await?;
    /// # let balance_after_first_write = client.get_local_balance().await; assert_ne!(initial_balance, balance_after_first_write);
    /// let received_value = match client.get_map_value(*our_map.address(), b"beep".to_vec()).await? {
    ///     MapValue::Unseq(value) => value,
    ///     _ => panic!("Exptected an unsequenced map")
    /// };
    /// assert_eq!(received_value, b"boop".to_vec());
    /// # Ok(()) } ); }
    /// ```
    pub async fn get_map_value(
        &mut self,
        address: MapAddress,
        key: Vec<u8>,
    ) -> Result<MapValue, ClientError>
    where
        Self: Sized,
    {
        trace!("Fetch MapValue for {:?}", address);

        match self
            .send_query(wrap_map_read(MapRead::GetValue { address, key }))
            .await?
        {
            QueryResponse::GetMapValue(res) => res.map_err(ClientError::from),
            _ => Err(ClientError::ReceivedUnexpectedEvent),
        }
    }

    /// Get a shell (bare bones) version of `Map` from the network.
    pub async fn get_map_shell(&mut self, address: MapAddress) -> Result<Map, ClientError>
    where
        Self: Sized,
    {
        trace!("GetMapShell for {:?}", address);

        match self
            .send_query(wrap_map_read(MapRead::GetShell(address)))
            .await?
        {
            QueryResponse::GetMapShell(res) => res.map_err(ClientError::from),
            _ => Err(ClientError::ReceivedUnexpectedEvent),
        }
    }

    /// Get a current version of `Map` from the network.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # extern crate tokio; use sn_client::ClientError; use std::str::FromStr;
    /// use sn_client::Client;
    /// use sn_data_types::{ ClientFullId, Money, Map, MapAction, MapPermissionSet, UnseqMap};
    /// use rand::rngs::OsRng;
    /// use std::collections::BTreeMap;
    /// use xor_name::XorName;
    /// # #[tokio::main] async fn main() { let _: Result<(), ClientError> = futures::executor::block_on( async {
    /// // Let's use an existing client, with a pre-existing balance to be used for write payments.
    /// let id = ClientFullId::new_ed25519(&mut OsRng);
    /// let mut client = Client::new(Some(id)).await?;
    /// # let initial_balance = Money::from_str("100")?; client.trigger_simulated_farming_payout(initial_balance).await?;
    /// let name = XorName::random();
    /// let tag = 15001;
    /// let mut entries: BTreeMap<Vec<u8>, Vec<u8>> = Default::default();
    /// let _ = entries.insert(b"beep".to_vec(), b"boop".to_vec() );
    /// let mut permissions: BTreeMap<_, _> = Default::default();
    /// let permission_set = MapPermissionSet::new().allow(MapAction::Read);
    /// let _ = permissions.insert(client.public_key().await, permission_set);
    /// let _ = entries.insert(b"key".to_vec(), b"value".to_vec());
    /// let our_map = Map::Unseq(UnseqMap::new_with_data(
    ///     name,
    ///     tag,
    ///     entries.clone(),
    ///     permissions,
    ///     client.public_key().await,
    /// ));
    /// let _ = client.store_map(our_map.clone()).await?;
    /// # let balance_after_first_write = client.get_local_balance().await; assert_ne!(initial_balance, balance_after_first_write);
    /// let version = client.get_map_version(*our_map.address()).await?;
    /// assert_eq!(version, 0);
    /// # Ok(()) } ); }
    /// ```
    pub async fn get_map_version(&mut self, address: MapAddress) -> Result<u64, ClientError>
    where
        Self: Sized,
    {
        trace!("GetMapVersion for {:?}", address);

        match self
            .send_query(wrap_map_read(MapRead::GetVersion(address)))
            .await?
        {
            QueryResponse::GetMapVersion(res) => res.map_err(ClientError::from),
            _ => Err(ClientError::ReceivedUnexpectedEvent),
        }
    }

    //----------
    // Entries
    //----------

    /// Mutates sequenced `Map` entries in bulk
    pub async fn mutate_seq_map_entries(
        &mut self,
        name: XorName,
        tag: u64,
        actions: MapSeqEntryActions,
    ) -> Result<(), ClientError>
    where
        Self: Sized,
    {
        trace!("Mutate Map for {:?}", name);

        let map_actions = MapEntryActions::Seq(actions);
        let address = MapAddress::Seq { name, tag };

        self.edit_map_entries(address, map_actions).await
    }

    /// Mutates unsequenced `Map` entries in bulk
    pub async fn mutate_unseq_map_entries(
        &mut self,
        name: XorName,
        tag: u64,
        actions: MapUnseqEntryActions,
    ) -> Result<(), ClientError>
    where
        Self: Sized,
    {
        trace!("Mutate Map for {:?}", name);

        let map_actions = MapEntryActions::Unseq(actions);
        let address = MapAddress::Unseq { name, tag };

        self.edit_map_entries(address, map_actions).await
    }

    /// Return a complete list of entries in `Map`.
    pub async fn list_unseq_map_entries(
        &mut self,
        name: XorName,
        tag: u64,
    ) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, ClientError>
    where
        Self: Sized,
    {
        trace!("ListMapEntries for {:?}", name);

        match self
            .send_query(wrap_map_read(MapRead::ListEntries(MapAddress::Unseq {
                name,
                tag,
            })))
            .await?
        {
            QueryResponse::ListMapEntries(res) => {
                res.map_err(ClientError::from)
                    .and_then(|entries| match entries {
                        MapEntries::Unseq(data) => Ok(data),
                        MapEntries::Seq(_) => Err(ClientError::ReceivedUnexpectedData),
                    })
            }
            _ => Err(ClientError::ReceivedUnexpectedEvent),
        }
    }

    /// Return a complete list of entries in `Map`.
    pub async fn list_seq_map_entries(
        &mut self,
        name: XorName,
        tag: u64,
    ) -> Result<MapSeqEntries, ClientError>
    where
        Self: Sized,
    {
        trace!("ListSeqMapEntries for {:?}", name);

        match self
            .send_query(wrap_map_read(MapRead::ListEntries(MapAddress::Seq {
                name,
                tag,
            })))
            .await?
        {
            QueryResponse::ListMapEntries(res) => {
                res.map_err(ClientError::from)
                    .and_then(|entries| match entries {
                        MapEntries::Seq(data) => Ok(data),
                        MapEntries::Unseq(_) => Err(ClientError::ReceivedUnexpectedData),
                    })
            }
            _ => Err(ClientError::ReceivedUnexpectedEvent),
        }
    }

    /// Return a list of keys in `Map` stored on the network.
    pub async fn list_map_keys(
        &mut self,
        address: MapAddress,
    ) -> Result<BTreeSet<Vec<u8>>, ClientError>
    where
        Self: Sized,
    {
        trace!("ListMapKeys for {:?}", address);

        let res = match self
            .send_query(wrap_map_read(MapRead::ListKeys(address)))
            .await?
        {
            QueryResponse::ListMapKeys(res) => res.map_err(ClientError::from),
            _ => Err(ClientError::ReceivedUnexpectedEvent),
        }?;

        Ok(res)
    }

    /// Return a list of values in a Sequenced Mutable Data
    pub async fn list_seq_map_values(
        &mut self,
        name: XorName,
        tag: u64,
    ) -> Result<Vec<MapSeqValue>, ClientError>
    where
        Self: Sized,
    {
        trace!("List MapValues for {:?}", name);

        match self
            .send_query(wrap_map_read(MapRead::ListValues(MapAddress::Seq {
                name,
                tag,
            })))
            .await?
        {
            QueryResponse::ListMapValues(res) => {
                res.map_err(ClientError::from)
                    .and_then(|values| match values {
                        MapValues::Seq(data) => Ok(data),
                        MapValues::Unseq(_) => Err(ClientError::ReceivedUnexpectedData),
                    })
            }
            _ => Err(ClientError::ReceivedUnexpectedEvent),
        }
    }

    /// Returns a list of values in an Unsequenced Mutable Data
    pub async fn list_unseq_map_values(
        &mut self,
        name: XorName,
        tag: u64,
    ) -> Result<Vec<Vec<u8>>, ClientError>
    where
        Self: Sized,
    {
        trace!("List MapValues for {:?}", name);

        match self
            .send_query(wrap_map_read(MapRead::ListValues(MapAddress::Unseq {
                name,
                tag,
            })))
            .await?
        {
            QueryResponse::ListMapValues(res) => {
                res.map_err(ClientError::from)
                    .and_then(|values| match values {
                        MapValues::Unseq(data) => Ok(data),
                        MapValues::Seq(_) => Err(ClientError::ReceivedUnexpectedData),
                    })
            }
            _ => Err(ClientError::ReceivedUnexpectedEvent),
        }
    }

    //-----------------
    // Permissions
    //-----------------

    /// Return the permissions set for a particular user
    pub async fn list_map_user_permissions(
        &mut self,
        address: MapAddress,
        user: PublicKey,
    ) -> Result<MapPermissionSet, ClientError>
    where
        Self: Sized,
    {
        trace!("GetMapUserPermissions for {:?}", address);

        match self
            .send_query(wrap_map_read(MapRead::ListUserPermissions {
                address,
                user,
            }))
            .await?
        {
            QueryResponse::ListMapUserPermissions(res) => res.map_err(ClientError::from),
            _ => Err(ClientError::ReceivedUnexpectedEvent),
        }
    }

    /// Return a list of permissions in `Map` stored on the network.
    pub async fn list_map_permissions(
        &mut self,
        address: MapAddress,
    ) -> Result<BTreeMap<PublicKey, MapPermissionSet>, ClientError>
    where
        Self: Sized,
    {
        trace!("List MapPermissions for {:?}", address);

        let res = match self
            .send_query(wrap_map_read(MapRead::ListPermissions(address)))
            .await?
        {
            QueryResponse::ListMapPermissions(res) => res.map_err(ClientError::from),
            _ => Err(ClientError::ReceivedUnexpectedEvent),
        }?;

        Ok(res)
    }

    /// Updates or inserts a permissions set for a user
    pub async fn set_map_user_permissions(
        &mut self,
        address: MapAddress,
        user: PublicKey,
        permissions: MapPermissionSet,
        version: u64,
    ) -> Result<(), ClientError>
    where
        Self: Sized,
    {
        trace!("SetMapUserPermissions for {:?}", address);

        self.set_map_user_perms(address, user, permissions, version)
            .await
    }

    /// Updates or inserts a permissions set for a user
    pub async fn del_map_user_permissions(
        &mut self,
        address: MapAddress,
        user: PublicKey,
        version: u64,
    ) -> Result<(), ClientError>
    where
        Self: Sized,
    {
        trace!("DelMapUserPermissions for {:?}", address);

        self.delete_map_user_perms(address, user, version).await
    }

    /// Sends an ownership transfer request.
    pub fn change_map_owner(
        &mut self,
        _name: XorName,
        _tag: u64,
        _new_owner: PublicKey,
        _version: u64,
    ) -> Result<(), ClientError> {
        unimplemented!();
    }
}

#[allow(missing_docs)]
#[cfg(any(test, feature = "simulated-payouts", feature = "testing"))]
pub mod exported_tests {
    use super::*;
    use crate::utils::test_utils::gen_bls_keypair;
    use sn_data_types::{Error as SndError, MapAction, MapKind, Money, SeqMap, UnseqMap};
    use std::str::FromStr;
    use xor_name::XorName;

    // 1. Create unseq. map with some entries and perms and put it on the network
    // 2. Fetch the shell version, entries, keys, values anv verify them
    // 3. Fetch the entire. data object and verify
    pub async fn unseq_map_test() -> Result<(), ClientError> {
        let mut client = Client::new(None).await?;

        let name = XorName(rand::random());
        let tag = 15001;
        let mut entries: BTreeMap<Vec<u8>, Vec<u8>> = Default::default();
        let mut permissions: BTreeMap<_, _> = Default::default();
        let permission_set = MapPermissionSet::new().allow(MapAction::Read);
        let _ = permissions.insert(client.public_key().await, permission_set);
        let _ = entries.insert(b"key".to_vec(), b"value".to_vec());
        let entries_keys = entries.keys().cloned().collect();
        let entries_values: Vec<Vec<u8>> = entries.values().cloned().collect();

        let data = Map::Unseq(UnseqMap::new_with_data(
            name,
            tag,
            entries.clone(),
            permissions,
            client.public_key().await,
        ));
        client.store_map(data.clone()).await?;
        println!("Put unseq. Map successfully");

        let version = client
            .get_map_version(MapAddress::Unseq { name, tag })
            .await?;
        assert_eq!(version, 0);
        let fetched_entries = client.list_unseq_map_entries(name, tag).await?;
        assert_eq!(fetched_entries, entries);
        let keys = client
            .list_map_keys(MapAddress::Unseq { name, tag })
            .await?;
        assert_eq!(keys, entries_keys);
        let values = client.list_unseq_map_values(name, tag).await?;
        assert_eq!(values, entries_values);
        let fetched_data = client.get_map(*data.address()).await?;
        assert_eq!(fetched_data.name(), data.name());
        assert_eq!(fetched_data.tag(), data.tag());
        Ok(())
    }

    // 1. Create an put seq. map on the network with some entries and permissions.
    // 2. Fetch the shell version, entries, keys, values anv verify them
    // 3. Fetch the entire. data object and verify
    pub async fn seq_map_test() -> Result<(), ClientError> {
        let mut client = Client::new(None).await?;

        let name = XorName(rand::random());
        let tag = 15001;
        let mut entries: MapSeqEntries = Default::default();
        let _ = entries.insert(
            b"key".to_vec(),
            MapSeqValue {
                data: b"value".to_vec(),
                version: 0,
            },
        );
        let entries_keys = entries.keys().cloned().collect();
        let entries_values: Vec<MapSeqValue> = entries.values().cloned().collect();
        let mut permissions: BTreeMap<_, _> = Default::default();
        let permission_set = MapPermissionSet::new().allow(MapAction::Read);
        let _ = permissions.insert(client.public_key().await, permission_set);
        let data = Map::Seq(SeqMap::new_with_data(
            name,
            tag,
            entries.clone(),
            permissions,
            client.public_key().await,
        ));

        let address = *data.clone().address();

        client.store_map(data.clone()).await?;
        println!("Put seq. Map successfully");

        let fetched_entries = client.list_seq_map_entries(name, tag).await?;
        assert_eq!(fetched_entries, entries);
        let map_shell = match client.get_map_shell(address).await? {
            Map::Seq(data) => data,
            _ => panic!("expected sequence map"),
        };
        assert_eq!(*map_shell.name(), name);
        assert_eq!(map_shell.tag(), tag);
        assert_eq!(map_shell.entries().len(), 0);
        let keys = client.list_map_keys(MapAddress::Seq { name, tag }).await?;
        assert_eq!(keys, entries_keys);
        let values = client.list_seq_map_values(name, tag).await?;
        assert_eq!(values, entries_values);
        let fetched_data = match client.get_map(address).await? {
            Map::Seq(data) => data,
            _ => panic!("Expected seq map"),
        };
        assert_eq!(fetched_data.name(), data.name());
        assert_eq!(fetched_data.tag(), data.tag());
        assert_eq!(fetched_data.entries().len(), 1);
        Ok(())
    }

    // 1. Put seq. map on the network and then delete it
    // 2. Try getting the data object. It should panic
    pub async fn del_seq_map_test() -> Result<(), ClientError> {
        let mut client = Client::new(None).await?;
        let name = XorName(rand::random());
        let tag = 15001;
        let mapref = MapAddress::Seq { name, tag };
        let data = Map::Seq(SeqMap::new_with_data(
            name,
            tag,
            Default::default(),
            Default::default(),
            client.public_key().await,
        ));

        client.store_map(data.clone()).await?;
        client.delete_map(mapref).await?;
        let res = client.get_map(*data.address()).await;
        match res {
            Err(ClientError::DataError(SndError::NoSuchData)) => (),
            _ => panic!("Unexpected success"),
        }
        Ok(())
    }

    // 1. Put unseq. map on the network and then delete it
    // 2. Try getting the data object. It should panic
    pub async fn del_unseq_map_test() -> Result<(), ClientError> {
        let mut client = Client::new(None).await?;
        let name = XorName(rand::random());
        let tag = 15001;
        let mapref = MapAddress::Unseq { name, tag };
        let data = Map::Unseq(UnseqMap::new_with_data(
            name,
            tag,
            Default::default(),
            Default::default(),
            client.public_key().await,
        ));

        client.store_map(data.clone()).await?;
        client.delete_map(mapref).await?;

        let res = client.get_map(*data.address()).await;
        match res {
            Err(ClientError::DataError(SndError::NoSuchData)) => (),
            _ => panic!("Unexpected success"),
        }

        Ok(())
    }

    // 1. Create a client that PUTs some map on the network
    // 2. Create a different client that tries to delete the data. It should panic.
    pub async fn del_unseq_map_permission_test() -> Result<(), ClientError> {
        let name = XorName(rand::random());
        let tag = 15001;
        let mapref = MapAddress::Unseq { name, tag };

        let mut client = Client::new(None).await?;
        let data = Map::Unseq(UnseqMap::new_with_data(
            name,
            tag,
            Default::default(),
            Default::default(),
            client.public_key().await,
        ));

        client.store_map(data).await?;

        let mut client = Client::new(None).await?;
        let res = client.delete_map(mapref).await;
        match res {
            Err(ClientError::DataError(SndError::AccessDenied)) => (),
            res => panic!("Unexpected result: {:?}", res),
        }

        Ok(())
    }

    pub async fn map_cannot_initially_put_data_with_another_owner_than_current_client(
    ) -> Result<(), ClientError> {
        let mut client = Client::new(None).await?;
        let mut permissions: BTreeMap<_, _> = Default::default();
        let permission_set = MapPermissionSet::new()
            .allow(MapAction::Read)
            .allow(MapAction::Insert)
            .allow(MapAction::ManagePermissions);
        let user = client.public_key().await;
        let random_user = gen_bls_keypair().public_key();
        let random_pk = gen_bls_keypair().public_key();

        let _ = permissions.insert(user, permission_set.clone());
        let _ = permissions.insert(random_user, permission_set);

        let test_data_name = XorName(rand::random());
        let test_data_with_different_owner_than_client = Map::Seq(SeqMap::new_with_data(
            test_data_name,
            15000,
            Default::default(),
            permissions,
            random_pk,
        ));

        client
            .store_map(test_data_with_different_owner_than_client.clone())
            .await?;
        let res = client
            .get_map_shell(*test_data_with_different_owner_than_client.address())
            .await;
        match res {
            Err(ClientError::DataError(SndError::NoSuchData)) => (),
            Ok(_) => panic!("Unexpected Success: Validating owners should fail"),
            Err(e) => panic!("Unexpected: {:?}", e),
        };

        // TODO: Refunds not yet in place.... Reenable this check when that's the case

        // Check money was not taken
        // let balance = client.get_balance().await?;
        // let expected_bal = calculate_new_balance(start_bal, Some(2), None);
        // assert_eq!(balance, expected_bal);

        Ok(())
    }

    // 1. Create a map with some permissions and store it on the network.
    // 2. Modify the permissions of a user in the permission set.
    // 3. Fetch the list of permissions and verify the edit.
    // 4. Delete a user's permissions from the permission set and verify the deletion.
    pub async fn map_can_modify_permissions_test() -> Result<(), ClientError> {
        let mut client = Client::new(None).await?;
        let name = XorName(rand::random());
        let tag = 15001;
        let mut permissions: BTreeMap<_, _> = Default::default();
        let permission_set = MapPermissionSet::new()
            .allow(MapAction::Read)
            .allow(MapAction::Insert)
            .allow(MapAction::ManagePermissions);
        let user = client.public_key().await;
        let random_user = gen_bls_keypair().public_key();

        let _ = permissions.insert(user, permission_set.clone());
        let _ = permissions.insert(random_user, permission_set);

        let data = Map::Seq(SeqMap::new_with_data(
            name,
            tag,
            Default::default(),
            permissions.clone(),
            client.public_key().await,
        ));

        client.store_map(data).await?;

        let new_perm_set = MapPermissionSet::new()
            .allow(MapAction::ManagePermissions)
            .allow(MapAction::Read);
        client
            .set_map_user_permissions(MapAddress::Seq { name, tag }, user, new_perm_set, 1)
            .await?;
        println!("Modified user permissions");

        let permissions = client
            .list_map_user_permissions(MapAddress::Seq { name, tag }, user)
            .await?;
        assert!(!permissions.is_allowed(MapAction::Insert));
        assert!(permissions.is_allowed(MapAction::Read));
        assert!(permissions.is_allowed(MapAction::ManagePermissions));
        println!("Verified new permissions");

        client
            .del_map_user_permissions(MapAddress::Seq { name, tag }, random_user, 2)
            .await?;
        println!("Deleted permissions");
        let permissions = client
            .list_map_permissions(MapAddress::Seq { name, tag })
            .await?;
        assert_eq!(permissions.len(), 1);
        println!("Permission set verified");

        Ok(())
    }

    // 1. Create a map and store it on the network
    // 2. Create some entry actions and mutate the data on the network.
    // 3. List the entries and verify that the mutation was applied.
    // 4. Fetch a value for a particular key and verify
    pub async fn map_mutations_test() -> Result<(), ClientError> {
        let mut client = Client::new(None).await?;

        let name = XorName(rand::random());
        let tag = 15001;
        let mut permissions: BTreeMap<_, _> = Default::default();
        let permission_set = MapPermissionSet::new()
            .allow(MapAction::Read)
            .allow(MapAction::Insert)
            .allow(MapAction::Update)
            .allow(MapAction::Delete);
        let user = client.public_key().await;
        let _ = permissions.insert(user, permission_set);
        let mut entries: MapSeqEntries = Default::default();
        let _ = entries.insert(
            b"key1".to_vec(),
            MapSeqValue {
                data: b"value".to_vec(),
                version: 0,
            },
        );
        let _ = entries.insert(
            b"key2".to_vec(),
            MapSeqValue {
                data: b"value".to_vec(),
                version: 0,
            },
        );
        let data = Map::Seq(SeqMap::new_with_data(
            name,
            tag,
            entries.clone(),
            permissions,
            client.public_key().await,
        ));

        let address = *data.clone().address();
        client.store_map(data).await?;

        let fetched_entries = client.list_seq_map_entries(name, tag).await?;

        assert_eq!(fetched_entries, entries);
        let entry_actions: MapSeqEntryActions = MapSeqEntryActions::new()
            .update(b"key1".to_vec(), b"newValue".to_vec(), 1)
            .del(b"key2".to_vec(), 1)
            .ins(b"key3".to_vec(), b"value".to_vec(), 0);

        client
            .mutate_seq_map_entries(name, tag, entry_actions)
            .await?;

        let fetched_entries = client.list_seq_map_entries(name, tag).await?;
        let mut expected_entries: BTreeMap<_, _> = Default::default();
        let _ = expected_entries.insert(
            b"key1".to_vec(),
            MapSeqValue {
                data: b"newValue".to_vec(),
                version: 1,
            },
        );
        let _ = expected_entries.insert(
            b"key3".to_vec(),
            MapSeqValue {
                data: b"value".to_vec(),
                version: 0,
            },
        );

        assert_eq!(fetched_entries, expected_entries);

        let fetched_value = match client.get_map_value(address, b"key3".to_vec()).await? {
            MapValue::Seq(value) => value,
            _ => panic!("unexpeced seq mutable data"),
        };

        assert_eq!(
            fetched_value,
            MapSeqValue {
                data: b"value".to_vec(),
                version: 0
            }
        );

        let res = client.get_map_value(address, b"wrongKey".to_vec()).await;
        match res {
            Ok(_) => panic!("Unexpected: Entry should not exist"),
            Err(ClientError::DataError(SndError::NoSuchEntry)) => (),
            Err(err) => panic!("Unexpected error: {:?}", err),
        };

        let mut client = Client::new(None).await?;
        let name = XorName(rand::random());
        let tag = 15001;
        let mut permissions: BTreeMap<_, _> = Default::default();
        let permission_set = MapPermissionSet::new()
            .allow(MapAction::Read)
            .allow(MapAction::Insert)
            .allow(MapAction::Update)
            .allow(MapAction::Delete);
        let user = client.public_key().await;
        let _ = permissions.insert(user, permission_set);
        let mut entries: BTreeMap<Vec<u8>, Vec<u8>> = Default::default();
        let _ = entries.insert(b"key1".to_vec(), b"value".to_vec());
        let _ = entries.insert(b"key2".to_vec(), b"value".to_vec());
        let data = Map::Unseq(UnseqMap::new_with_data(
            name,
            tag,
            entries.clone(),
            permissions,
            client.public_key().await,
        ));
        client.store_map(data).await?;
        println!("Put unseq. Map successfully");

        let fetched_entries = client.list_unseq_map_entries(name, tag).await?;
        assert_eq!(fetched_entries, entries);
        let entry_actions: MapUnseqEntryActions = MapUnseqEntryActions::new()
            .update(b"key1".to_vec(), b"newValue".to_vec())
            .del(b"key2".to_vec())
            .ins(b"key3".to_vec(), b"value".to_vec());

        client
            .mutate_unseq_map_entries(name, tag, entry_actions)
            .await?;
        let fetched_entries = client.list_unseq_map_entries(name, tag).await?;
        let mut expected_entries: BTreeMap<_, _> = Default::default();
        let _ = expected_entries.insert(b"key1".to_vec(), b"newValue".to_vec());
        let _ = expected_entries.insert(b"key3".to_vec(), b"value".to_vec());
        assert_eq!(fetched_entries, expected_entries);
        let fetched_value = match client.get_map_value(address, b"key1".to_vec()).await? {
            MapValue::Unseq(value) => value,
            _ => panic!("unexpeced seq mutable data"),
        };
        assert_eq!(fetched_value, b"newValue".to_vec());
        let res = client.get_map_value(address, b"wrongKey".to_vec()).await;
        match res {
            Ok(_) => panic!("Unexpected: Entry should not exist"),
            Err(ClientError::DataError(SndError::NoSuchEntry)) => Ok(()),
            Err(err) => panic!("Unexpected error: {:?}", err),
        }
    }

    pub async fn map_deletions_should_cost_put_price() -> Result<(), ClientError> {
        let name = XorName(rand::random());
        let tag = 10;
        let mut client = Client::new(None).await?;

        let map = Map::Unseq(UnseqMap::new(name, tag, client.public_key().await));
        client.store_map(map).await?;

        let map_address = MapAddress::from_kind(MapKind::Unseq, name, tag);

        let balance_before_delete = client.get_balance().await?;
        client.delete_map(map_address).await?;
        let new_balance = client.get_balance().await?;

        // make sure we have _some_ balance
        assert_ne!(balance_before_delete, Money::from_str("0")?);
        assert_ne!(balance_before_delete, new_balance);

        Ok(())
    }
}

#[allow(missing_docs)]
#[cfg(all(test, feature = "simulated-payouts"))]
mod tests {
    use super::exported_tests;
    use super::ClientError;

    #[tokio::test]
    pub async fn unseq_map_test() -> Result<(), ClientError> {
        exported_tests::unseq_map_test().await
    }

    #[tokio::test]
    pub async fn seq_map_test() -> Result<(), ClientError> {
        exported_tests::seq_map_test().await
    }

    #[tokio::test]
    pub async fn del_seq_map_test() -> Result<(), ClientError> {
        exported_tests::del_seq_map_test().await
    }

    #[tokio::test]
    pub async fn del_unseq_map_test() -> Result<(), ClientError> {
        exported_tests::del_unseq_map_test().await
    }

    #[tokio::test]
    pub async fn del_unseq_map_permission_test() -> Result<(), ClientError> {
        exported_tests::del_unseq_map_permission_test().await
    }

    #[tokio::test]
    pub async fn map_cannot_initially_put_data_with_another_owner_than_current_client(
    ) -> Result<(), ClientError> {
        exported_tests::map_cannot_initially_put_data_with_another_owner_than_current_client().await
    }

    #[tokio::test]
    pub async fn map_can_modify_permissions_test() -> Result<(), ClientError> {
        exported_tests::map_can_modify_permissions_test().await
    }

    #[tokio::test]
    pub async fn map_mutations_test() -> Result<(), ClientError> {
        exported_tests::map_mutations_test().await
    }

    #[tokio::test]
    pub async fn map_deletions_should_cost_put_price() -> Result<(), ClientError> {
        exported_tests::map_deletions_should_cost_put_price().await
    }
}
