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
    Cmd, DataCmd, DataQuery, DebitAgreementProof, Map, MapAddress, MapEntries, MapEntryActions,
    MapPermissionSet, MapRead, MapSeqEntries, MapSeqEntryActions, MapSeqValue,
    MapUnseqEntryActions, MapValue, MapValues, PublicKey, Query, QueryResponse, SeqMap, UnseqMap,
};

use safe_nd::MapWrite;

use xor_name::XorName;

use std::collections::{BTreeMap, BTreeSet};

fn wrap_map_read(read: MapRead) -> Query {
    Query::Data(DataQuery::Map(read))
}

fn wrap_map_write(write: MapWrite, payment: DebitAgreementProof) -> Cmd {
    Cmd::Data {
        cmd: DataCmd::Map(write),
        payment,
    }
}

impl Client {
    /// Fetch unpublished mutable data from the network
    async fn get_unseq_map(&mut self, name: XorName, tag: u64) -> Result<UnseqMap, CoreError>
    where
        Self: Sized,
    {
        trace!("Fetch Unsequenced Mutable Data");

        match self
            .send_query(wrap_map_read(MapRead::Get(MapAddress::Unseq { name, tag })))
            .await?
        {
            QueryResponse::GetMap(res) => res.map_err(CoreError::from).and_then(|map| match map {
                Map::Unseq(data) => Ok(data),
                Map::Seq(_) => Err(CoreError::ReceivedUnexpectedData),
            }),
            _ => Err(CoreError::ReceivedUnexpectedEvent),
        }
    }

    /// Fetch the value for a given key in a sequenced mutable data
    async fn get_seq_map_value(
        &mut self,
        name: XorName,
        tag: u64,
        key: Vec<u8>,
    ) -> Result<MapSeqValue, CoreError>
    where
        Self: Sized,
    {
        trace!("Fetch MapValue for {:?}", name);

        match self
            .send_query(wrap_map_read(MapRead::GetValue {
                address: MapAddress::Seq { name, tag },
                key,
            }))
            .await?
        {
            QueryResponse::GetMapValue(res) => {
                res.map_err(CoreError::from).and_then(|value| match value {
                    MapValue::Seq(val) => Ok(val),
                    MapValue::Unseq(_) => Err(CoreError::ReceivedUnexpectedData),
                })
            }
            _ => Err(CoreError::ReceivedUnexpectedEvent),
        }
    }

    /// Fetch the value for a given key in a sequenced mutable data
    async fn get_unseq_map_value(
        &mut self,
        name: XorName,
        tag: u64,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, CoreError>
    where
        Self: Sized,
    {
        trace!("Fetch MapValue for {:?}", name);

        match self
            .send_query(wrap_map_read(MapRead::GetValue {
                address: MapAddress::Unseq { name, tag },
                key,
            }))
            .await?
        {
            QueryResponse::GetMapValue(res) => {
                res.map_err(CoreError::from).and_then(|value| match value {
                    MapValue::Unseq(val) => Ok(val),
                    MapValue::Seq(_) => Err(CoreError::ReceivedUnexpectedData),
                })
            }
            _ => Err(CoreError::ReceivedUnexpectedEvent),
        }
    }

    /// Fetch sequenced mutable data from the network
    async fn get_seq_map(&mut self, name: XorName, tag: u64) -> Result<SeqMap, CoreError>
    where
        Self: Sized,
    {
        trace!("Fetch Sequenced Mutable Data");

        match self
            .send_query(wrap_map_read(MapRead::Get(MapAddress::Seq { name, tag })))
            .await?
        {
            QueryResponse::GetMap(res) => res.map_err(CoreError::from).and_then(|map| match map {
                Map::Seq(data) => Ok(data),
                Map::Unseq(_) => Err(CoreError::ReceivedUnexpectedData),
            }),
            _ => Err(CoreError::ReceivedUnexpectedEvent),
        }
    }

    /// Mutates sequenced `Map` entries in bulk
    async fn mutate_seq_map_entries(
        &mut self,
        name: XorName,
        tag: u64,
        actions: MapSeqEntryActions,
    ) -> Result<(), CoreError>
    where
        Self: Sized,
    {
        trace!("Mutate Map for {:?}", name);

        let map_actions = MapEntryActions::Seq(actions);
        let address = MapAddress::Seq { name, tag };

        self.edit_map_entries(address, map_actions).await
    }

    /// Mutates unsequenced `Map` entries in bulk
    async fn mutate_unseq_map_entries(
        &mut self,
        name: XorName,
        tag: u64,
        actions: MapUnseqEntryActions,
    ) -> Result<(), CoreError>
    where
        Self: Sized,
    {
        trace!("Mutate Map for {:?}", name);

        let map_actions = MapEntryActions::Unseq(actions);
        let address = MapAddress::Unseq { name, tag };

        self.edit_map_entries(address, map_actions).await
    }

    /// Get a shell (bare bones) version of `Map` from the network.
    async fn get_seq_map_shell(&mut self, name: XorName, tag: u64) -> Result<SeqMap, CoreError>
    where
        Self: Sized,
    {
        trace!("GetMapShell for {:?}", name);

        match self
            .send_query(wrap_map_read(MapRead::GetShell(MapAddress::Seq {
                name,
                tag,
            })))
            .await?
        {
            QueryResponse::GetMapShell(res) => {
                res.map_err(CoreError::from).and_then(|map| match map {
                    Map::Seq(data) => Ok(data),
                    _ => Err(CoreError::ReceivedUnexpectedData),
                })
            }
            _ => Err(CoreError::ReceivedUnexpectedEvent),
        }
    }

    /// Get a shell (bare bones) version of `Map` from the network.
    #[allow(dead_code)]
    async fn get_unseq_map_shell(&mut self, name: XorName, tag: u64) -> Result<UnseqMap, CoreError>
    where
        Self: Sized,
    {
        trace!("GetMapShell for {:?}", name);

        match self
            .send_query(wrap_map_read(MapRead::GetShell(MapAddress::Unseq {
                name,
                tag,
            })))
            .await?
        {
            QueryResponse::GetMapShell(res) => {
                res.map_err(CoreError::from).and_then(|map| match map {
                    Map::Unseq(data) => Ok(data),
                    _ => Err(CoreError::ReceivedUnexpectedData),
                })
            }
            _ => Err(CoreError::ReceivedUnexpectedEvent),
        }
    }

    /// Get a current version of `Map` from the network.
    async fn get_map_version(&mut self, address: MapAddress) -> Result<u64, CoreError>
    where
        Self: Sized,
    {
        trace!("GetMapVersion for {:?}", address);

        match self
            .send_query(wrap_map_read(MapRead::GetVersion(address)))
            .await?
        {
            QueryResponse::GetMapVersion(res) => res.map_err(CoreError::from),
            _ => Err(CoreError::ReceivedUnexpectedEvent),
        }
    }

    /// Return a complete list of entries in `Map`.
    async fn list_unseq_map_entries(
        &mut self,
        name: XorName,
        tag: u64,
    ) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, CoreError>
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
                res.map_err(CoreError::from)
                    .and_then(|entries| match entries {
                        MapEntries::Unseq(data) => Ok(data),
                        MapEntries::Seq(_) => Err(CoreError::ReceivedUnexpectedData),
                    })
            }
            _ => Err(CoreError::ReceivedUnexpectedEvent),
        }
    }

    /// Return a complete list of entries in `Map`.
    async fn list_seq_map_entries(
        &mut self,
        name: XorName,
        tag: u64,
    ) -> Result<MapSeqEntries, CoreError>
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
                res.map_err(CoreError::from)
                    .and_then(|entries| match entries {
                        MapEntries::Seq(data) => Ok(data),
                        MapEntries::Unseq(_) => Err(CoreError::ReceivedUnexpectedData),
                    })
            }
            _ => Err(CoreError::ReceivedUnexpectedEvent),
        }
    }

    /// Return a list of keys in `Map` stored on the network.
    async fn list_map_keys(&mut self, address: MapAddress) -> Result<BTreeSet<Vec<u8>>, CoreError>
    where
        Self: Sized,
    {
        trace!("ListMapKeys for {:?}", address);

        let res = match self
            .send_query(wrap_map_read(MapRead::ListKeys(address)))
            .await?
        {
            QueryResponse::ListMapKeys(res) => res.map_err(CoreError::from),
            _ => Err(CoreError::ReceivedUnexpectedEvent),
        }?;

        Ok(res)
    }

    /// Return a list of values in a Sequenced Mutable Data
    async fn list_seq_map_values(
        &mut self,
        name: XorName,
        tag: u64,
    ) -> Result<Vec<MapSeqValue>, CoreError>
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
                res.map_err(CoreError::from)
                    .and_then(|values| match values {
                        MapValues::Seq(data) => Ok(data),
                        MapValues::Unseq(_) => Err(CoreError::ReceivedUnexpectedData),
                    })
            }
            _ => Err(CoreError::ReceivedUnexpectedEvent),
        }
    }

    /// Return the permissions set for a particular user
    async fn list_map_user_permissions(
        &mut self,
        address: MapAddress,
        user: PublicKey,
    ) -> Result<MapPermissionSet, CoreError>
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
            QueryResponse::ListMapUserPermissions(res) => res.map_err(CoreError::from),
            _ => Err(CoreError::ReceivedUnexpectedEvent),
        }
    }

    /// Returns a list of values in an Unsequenced Mutable Data
    async fn list_unseq_map_values(
        &mut self,
        name: XorName,
        tag: u64,
    ) -> Result<Vec<Vec<u8>>, CoreError>
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
                res.map_err(CoreError::from)
                    .and_then(|values| match values {
                        MapValues::Unseq(data) => Ok(data),
                        MapValues::Seq(_) => Err(CoreError::ReceivedUnexpectedData),
                    })
            }
            _ => Err(CoreError::ReceivedUnexpectedEvent),
        }
    }

    /// Return a list of permissions in `Map` stored on the network.
    async fn list_map_permissions(
        &mut self,
        address: MapAddress,
    ) -> Result<BTreeMap<PublicKey, MapPermissionSet>, CoreError>
    where
        Self: Sized,
    {
        trace!("List MapPermissions for {:?}", address);

        let res = match self
            .send_query(wrap_map_read(MapRead::ListPermissions(address)))
            .await?
        {
            QueryResponse::ListMapPermissions(res) => res.map_err(CoreError::from),
            _ => Err(CoreError::ReceivedUnexpectedEvent),
        }?;

        Ok(res)
    }

    /// Updates or inserts a permissions set for a user
    async fn set_map_user_permissions(
        &mut self,
        address: MapAddress,
        user: PublicKey,
        permissions: MapPermissionSet,
        version: u64,
    ) -> Result<(), CoreError>
    where
        Self: Sized,
    {
        trace!("SetMapUserPermissions for {:?}", address);

        self.set_map_user_perms(address, user, permissions, version)
            .await
    }

    /// Updates or inserts a permissions set for a user
    async fn del_map_user_permissions(
        &mut self,
        address: MapAddress,
        user: PublicKey,
        version: u64,
    ) -> Result<(), CoreError>
    where
        Self: Sized,
    {
        trace!("DelMapUserPermissions for {:?}", address);

        self.delete_map_user_perms(address, user, version).await
    }

    /// Sends an ownership transfer request.
    #[allow(unused)]
    fn change_map_owner(
        &mut self,
        name: XorName,
        tag: u64,
        new_owner: PublicKey,
        version: u64,
    ) -> Result<(), CoreError> {
        unimplemented!();
    }

    /// Delete sequence
    pub async fn delete_map(&mut self, address: MapAddress) -> Result<(), CoreError> {
        // --------------------------
        // Payment for PUT
        // --------------------------
        let payment_proof = self.create_write_payment_proof().await?;

        //---------------------------------
        // The _actual_ message
        //---------------------------------
        let msg_contents = wrap_map_write(MapWrite::Delete(address), payment_proof.clone());
        let message = Self::create_cmd_message(msg_contents);
        let _ = self.connection_manager.send_cmd(&message).await?;

        self.apply_write_payment_to_local_actor(payment_proof).await
    }

    /// Delete mutable data user permission
    pub async fn delete_map_user_perms(
        &mut self,
        address: MapAddress,
        user: PublicKey,
        version: u64,
    ) -> Result<(), CoreError> {
        // --------------------------
        // Payment for PUT
        // --------------------------
        let payment_proof = self.create_write_payment_proof().await?;

        //---------------------------------
        // The _actual_ message
        //---------------------------------

        let msg_contents = wrap_map_write(
            MapWrite::DelUserPermissions {
                address,
                user,
                version,
            },
            payment_proof.clone(),
        );

        let message = Self::create_cmd_message(msg_contents);

        let _ = self.connection_manager.send_cmd(&message).await?;

        self.apply_write_payment_to_local_actor(payment_proof).await
    }

    /// Set mutable data user permissions
    pub async fn set_map_user_perms(
        &mut self,
        address: MapAddress,
        user: PublicKey,
        permissions: MapPermissionSet,
        version: u64,
    ) -> Result<(), CoreError> {
        // --------------------------
        // Payment for PUT
        // --------------------------
        let payment_proof = self.create_write_payment_proof().await?;

        //---------------------------------
        // The _actual_ message
        //---------------------------------

        let msg_contents = wrap_map_write(
            MapWrite::SetUserPermissions {
                address,
                user,
                permissions,
                version,
            },
            payment_proof.clone(),
        );

        let message = Self::create_cmd_message(msg_contents);

        // TODO what will be the correct reponse here?... We have it validated, so registered?
        let _ = self.connection_manager.send_cmd(&message).await?;

        self.apply_write_payment_to_local_actor(payment_proof).await
    }

    /// Mutate mutable data user entries
    pub async fn edit_map_entries(
        &mut self,
        address: MapAddress,
        changes: MapEntryActions,
    ) -> Result<(), CoreError> {
        // --------------------------
        // Payment for PUT
        // --------------------------
        let payment_proof = self.create_write_payment_proof().await?;

        //---------------------------------
        // The _actual_ message
        //---------------------------------

        let msg_contents =
            wrap_map_write(MapWrite::Edit { address, changes }, payment_proof.clone());

        let message = Self::create_cmd_message(msg_contents);
        let _ = self.connection_manager.send_cmd(&message).await?;

        self.apply_write_payment_to_local_actor(payment_proof).await
    }

    /// Store a new public mutable data object
    /// Wraps msg_contents for payment validation and mutation
    pub async fn new_map(&mut self, data: Map) -> Result<(), CoreError> {
        // --------------------------
        // Payment for PUT
        // --------------------------
        let payment_proof = self.create_write_payment_proof().await?;

        //---------------------------------
        // The _actual_ message
        //---------------------------------
        let msg_contents = wrap_map_write(MapWrite::New(data), payment_proof.clone());
        let message = Self::create_cmd_message(msg_contents);
        let _ = self.connection_manager.send_cmd(&message).await?;

        self.apply_write_payment_to_local_actor(payment_proof).await
    }
}

#[allow(missing_docs)]
#[cfg(any(test, feature = "simulated-payouts", feature = "testing"))]
pub mod exported_tests {
    use super::*;
    use crate::utils::test_utils::gen_bls_keypair;
    use safe_nd::{Error as SndError, MapAction, MapKind, Money};
    use std::str::FromStr;
    use xor_name::XorName;

    // 1. Create unseq. map with some entries and perms and put it on the network
    // 2. Fetch the shell version, entries, keys, values anv verify them
    // 3. Fetch the entire. data object and verify
    pub async fn unseq_map_test() -> Result<(), CoreError> {
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
        client.new_map(data.clone()).await?;
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
        let fetched_data = client.get_unseq_map(*data.name(), data.tag()).await?;
        assert_eq!(fetched_data.name(), data.name());
        assert_eq!(fetched_data.tag(), data.tag());
        Ok(())
    }

    // 1. Create an put seq. map on the network with some entries and permissions.
    // 2. Fetch the shell version, entries, keys, values anv verify them
    // 3. Fetch the entire. data object and verify
    pub async fn seq_map_test() -> Result<(), CoreError> {
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

        client.new_map(data.clone()).await?;
        println!("Put seq. Map successfully");

        let fetched_entries = client.list_seq_map_entries(name, tag).await?;
        assert_eq!(fetched_entries, entries);
        let map_shell = client.get_seq_map_shell(name, tag).await?;
        assert_eq!(*map_shell.name(), name);
        assert_eq!(map_shell.tag(), tag);
        assert_eq!(map_shell.entries().len(), 0);
        let keys = client.list_map_keys(MapAddress::Seq { name, tag }).await?;
        assert_eq!(keys, entries_keys);
        let values = client.list_seq_map_values(name, tag).await?;
        assert_eq!(values, entries_values);
        let fetched_data = client.get_seq_map(name, tag).await?;
        assert_eq!(fetched_data.name(), data.name());
        assert_eq!(fetched_data.tag(), data.tag());
        assert_eq!(fetched_data.entries().len(), 1);
        Ok(())
    }

    // 1. Put seq. map on the network and then delete it
    // 2. Try getting the data object. It should panic
    pub async fn del_seq_map_test() -> Result<(), CoreError> {
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

        client.new_map(data.clone()).await?;
        client.delete_map(mapref).await?;
        let res = client.get_unseq_map(*data.name(), data.tag()).await;
        match res {
            Err(CoreError::DataError(SndError::NoSuchData)) => (),
            _ => panic!("Unexpected success"),
        }
        Ok(())
    }

    // 1. Put unseq. map on the network and then delete it
    // 2. Try getting the data object. It should panic
    pub async fn del_unseq_map_test() -> Result<(), CoreError> {
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

        client.new_map(data.clone()).await?;
        client.delete_map(mapref).await?;

        let res = client.get_unseq_map(*data.name(), data.tag()).await;
        match res {
            Err(CoreError::DataError(SndError::NoSuchData)) => (),
            _ => panic!("Unexpected success"),
        }

        Ok(())
    }

    // 1. Create a client that PUTs some map on the network
    // 2. Create a different client that tries to delete the data. It should panic.
    pub async fn del_unseq_map_permission_test() -> Result<(), CoreError> {
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

        client.new_map(data).await?;

        let mut client = Client::new(None).await?;
        let res = client.delete_map(mapref).await;
        match res {
            Err(CoreError::DataError(SndError::AccessDenied)) => (),
            res => panic!("Unexpected result: {:?}", res),
        }

        Ok(())
    }

    pub async fn map_cannot_initially_put_data_with_another_owner_than_current_client(
    ) -> Result<(), CoreError> {
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
            test_data_name.clone(),
            15000,
            Default::default(),
            permissions,
            random_pk,
        ));

        client
            .new_map(test_data_with_different_owner_than_client.clone())
            .await?;
        let res = client.get_seq_map_shell(test_data_name, 1500).await;
        match res {
            Err(CoreError::DataError(SndError::NoSuchData)) => (),
            Ok(_) => panic!("Unexpected Success: Validating owners should fail"),
            Err(e) => panic!("Unexpected: {:?}", e),
        };

        // TODO: Refunds not yet in place.... Reenable this check when that's the case

        // Check money was not taken
        // let balance = client.get_balance(None).await?;
        // let expected_bal = calculate_new_balance(start_bal, Some(2), None);
        // assert_eq!(balance, expected_bal);

        Ok(())
    }

    // 1. Create a mutable data with some permissions and store it on the network.
    // 2. Modify the permissions of a user in the permission set.
    // 3. Fetch the list of permissions and verify the edit.
    // 4. Delete a user's permissions from the permission set and verify the deletion.
    pub async fn map_can_modify_permissions_test() -> Result<(), CoreError> {
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

        client.new_map(data).await?;

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

    // 1. Create a mutable data and store it on the network
    // 2. Create some entry actions and mutate the data on the network.
    // 3. List the entries and verify that the mutation was applied.
    // 4. Fetch a value for a particular key and verify
    pub async fn map_mutations_test() -> Result<(), CoreError> {
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
        client.new_map(data).await?;

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

        let fetched_value = client
            .get_seq_map_value(name, tag, b"key3".to_vec())
            .await?;

        assert_eq!(
            fetched_value,
            MapSeqValue {
                data: b"value".to_vec(),
                version: 0
            }
        );

        let res = client
            .get_seq_map_value(name, tag, b"wrongKey".to_vec())
            .await;
        match res {
            Ok(_) => panic!("Unexpected: Entry should not exist"),
            Err(CoreError::DataError(SndError::NoSuchEntry)) => (),
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
        client.new_map(data).await?;
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
        let fetched_value = client
            .get_unseq_map_value(name, tag, b"key1".to_vec())
            .await?;
        assert_eq!(fetched_value, b"newValue".to_vec());
        let res = client
            .get_unseq_map_value(name, tag, b"wrongKey".to_vec())
            .await;
        match res {
            Ok(_) => panic!("Unexpected: Entry should not exist"),
            Err(CoreError::DataError(SndError::NoSuchEntry)) => Ok(()),
            Err(err) => panic!("Unexpected error: {:?}", err),
        }
    }

    pub async fn map_deletions_should_cost_put_price() -> Result<(), CoreError> {
        let name = XorName(rand::random());
        let tag = 10;
        let mut client = Client::new(None).await?;

        let map = Map::Unseq(UnseqMap::new(name, tag, client.public_key().await));
        client.new_map(map).await?;

        let map_address = MapAddress::from_kind(MapKind::Unseq, name, tag);

        let balance_before_delete = client.get_balance(None).await?;
        client.delete_map(map_address).await?;
        let new_balance = client.get_balance(None).await?;

        // make sure we have _some_ balance
        assert_ne!(balance_before_delete, Money::from_str("0")?);
        assert_ne!(balance_before_delete, new_balance);

        Ok(())
    }
}

#[allow(missing_docs)]
#[cfg(any(test, feature = "simulated-payouts"))]
mod tests {
    use super::exported_tests;
    use super::CoreError;

    #[tokio::test]
    pub async fn unseq_map_test() -> Result<(), CoreError> {
        exported_tests::unseq_map_test().await
    }

    #[tokio::test]
    pub async fn seq_map_test() -> Result<(), CoreError> {
        exported_tests::seq_map_test().await
    }

    #[tokio::test]
    pub async fn del_seq_map_test() -> Result<(), CoreError> {
        exported_tests::del_seq_map_test().await
    }

    #[tokio::test]
    pub async fn del_unseq_map_test() -> Result<(), CoreError> {
        exported_tests::del_unseq_map_test().await
    }

    #[tokio::test]
    pub async fn del_unseq_map_permission_test() -> Result<(), CoreError> {
        exported_tests::del_unseq_map_permission_test().await
    }

    #[tokio::test]
    pub async fn map_cannot_initially_put_data_with_another_owner_than_current_client(
    ) -> Result<(), CoreError> {
        exported_tests::map_cannot_initially_put_data_with_another_owner_than_current_client().await
    }

    #[tokio::test]
    pub async fn map_can_modify_permissions_test() -> Result<(), CoreError> {
        exported_tests::map_can_modify_permissions_test().await
    }

    #[tokio::test]
    pub async fn map_mutations_test() -> Result<(), CoreError> {
        exported_tests::map_mutations_test().await
    }

    #[tokio::test]
    pub async fn map_deletions_should_cost_put_price() -> Result<(), CoreError> {
        exported_tests::map_deletions_should_cost_put_price().await
    }
}
