// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::Client;
use crate::Error;
use log::trace;

use sn_data_types::{
    Map, MapAddress, MapEntries, MapEntryActions, MapPermissionSet, MapSeqEntries,
    MapSeqEntryActions, MapSeqValue, MapUnseqEntries, MapUnseqEntryActions, MapValue, MapValues,
    PublicKey, SeqMap, UnseqMap,
};

use sn_messaging::client::{DataCmd, DataQuery, MapRead, MapWrite, Query, QueryResponse};

use xor_name::XorName;

use std::collections::{BTreeMap, BTreeSet};

fn wrap_map_read(read: MapRead) -> Query {
    Query::Data(DataQuery::Map(read))
}

impl Client {
    //-------------------
    // Store
    // ------------------

    /// Store a new sequenced Map
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # extern crate tokio; use anyhow::Result; use std::str::FromStr;
    /// # use sn_client::utils::test_utils::read_network_conn_info;
    /// use sn_client::Client;
    /// use sn_data_types::{ Keypair, Token, MapAction, MapPermissionSet, MapSeqValue, MapSeqEntries};
    /// use rand::rngs::OsRng;
    /// use std::collections::BTreeMap;
    /// use xor_name::XorName;
    /// # #[tokio::main] async fn main() { let _: Result<()> = futures::executor::block_on( async {
    /// // Let's use an existing client, with a pre-existing balance to be used for write payments.
    /// let id = Keypair::new_ed25519(&mut OsRng);

    /// # let bootstrap_contacts = Some(read_network_conn_info()?);
    /// let mut client = Client::new(Some(id), None, bootstrap_contacts).await?;
    /// # let initial_balance = Token::from_str("100")?; client.trigger_simulated_farming_payout(initial_balance).await?;
    /// let name = XorName::random();
    /// let tag = 15001;
    /// let mut entries = MapSeqEntries::default();
    /// let mut permissions = BTreeMap::default();
    /// let permission_set = MapPermissionSet::new().allow(MapAction::Read);
    /// let _ = permissions.insert(client.public_key().await, permission_set);
    /// let _ = entries.insert(b"key".to_vec(), MapSeqValue { data: b"value".to_vec(), version: 0 });
    /// let owner = client.public_key().await;
    /// let _ = client.store_seq_map(name, tag, owner, Some(entries), Some(permissions)).await?;
    ///
    /// # let balance_after_write = client.get_local_balance().await; assert_ne!(initial_balance, balance_after_write); Ok(()) } ); }
    /// ```
    pub async fn store_seq_map(
        &self,
        name: XorName,
        tag: u64,
        owner: PublicKey,
        entries: Option<MapSeqEntries>,
        permissions: Option<BTreeMap<PublicKey, MapPermissionSet>>,
    ) -> Result<MapAddress, Error> {
        let data = Map::Seq(SeqMap::new_with_data(
            name,
            tag,
            entries.unwrap_or_else(MapSeqEntries::default),
            permissions.unwrap_or_else(BTreeMap::default),
            owner,
        ));
        let address = *data.address();
        let cmd = DataCmd::Map(MapWrite::New(data));

        self.pay_and_send_data_command(cmd).await?;

        Ok(address)
    }

    /// Store a new unsequenced Map
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # extern crate tokio; use anyhow::Result; use std::str::FromStr;
    /// # use sn_client::utils::test_utils::read_network_conn_info;
    /// use sn_client::Client;
    /// use sn_data_types::{ Keypair, Token, MapAction, MapPermissionSet, MapUnseqEntries};
    /// use rand::rngs::OsRng;
    /// use std::collections::BTreeMap;
    /// use xor_name::XorName;
    /// # #[tokio::main] async fn main() { let _: Result<()> = futures::executor::block_on( async {
    /// // Let's use an existing client, with a pre-existing balance to be used for write payments.
    /// let id = Keypair::new_ed25519(&mut OsRng);

    /// # let bootstrap_contacts = Some(read_network_conn_info()?);
    /// let mut client = Client::new(Some(id), None, bootstrap_contacts).await?;
    /// # let initial_balance = Token::from_str("100")?; client.trigger_simulated_farming_payout(initial_balance).await?;
    /// let name = XorName::random();
    /// let tag = 15001;
    /// let mut entries = MapUnseqEntries::default();
    /// let mut permissions = BTreeMap::default();
    /// let permission_set = MapPermissionSet::new().allow(MapAction::Read);
    /// let _ = permissions.insert(client.public_key().await, permission_set);
    /// let _ = entries.insert(b"key".to_vec(), b"value".to_vec());
    /// let owner = client.public_key().await;
    /// let _ = client.store_unseq_map(name, tag, owner, Some(entries), Some(permissions)).await?;
    ///
    /// # let balance_after_write = client.get_local_balance().await; assert_ne!(initial_balance, balance_after_write); Ok(()) } ); }
    /// ```
    pub async fn store_unseq_map(
        &self,
        name: XorName,
        tag: u64,
        owner: PublicKey,
        entries: Option<MapUnseqEntries>,
        permissions: Option<BTreeMap<PublicKey, MapPermissionSet>>,
    ) -> Result<MapAddress, Error> {
        let data = Map::Unseq(UnseqMap::new_with_data(
            name,
            tag,
            entries.unwrap_or_else(MapUnseqEntries::default),
            permissions.unwrap_or_else(BTreeMap::default),
            owner,
        ));
        let address = *data.address();

        let cmd = DataCmd::Map(MapWrite::New(data));

        self.pay_and_send_data_command(cmd).await?;

        Ok(address)
    }

    /// Delete Map
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # extern crate tokio; use anyhow::Result; use std::str::FromStr;
    /// # use sn_client::utils::test_utils::read_network_conn_info;
    /// use sn_client::Client;
    /// use sn_data_types::{ Keypair, Token, MapAction, MapPermissionSet, MapUnseqEntries};
    /// use rand::rngs::OsRng;
    /// use std::collections::BTreeMap;
    /// use xor_name::XorName;
    /// # #[tokio::main] async fn main() { let _: Result<()> = futures::executor::block_on( async {
    /// // Let's use an existing client, with a pre-existing balance to be used for write payments.
    /// let id = Keypair::new_ed25519(&mut OsRng);

    /// # let bootstrap_contacts = Some(read_network_conn_info()?);
    /// let mut client = Client::new(Some(id), None, bootstrap_contacts).await?;
    /// # let initial_balance = Token::from_str("100")?; client.trigger_simulated_farming_payout(initial_balance).await?;
    /// let name = XorName::random();
    /// let tag = 15001;
    /// let mut entries = MapUnseqEntries::default();
    /// let mut permissions = BTreeMap::default();
    /// let permission_set = MapPermissionSet::new().allow(MapAction::Read);
    /// let _ = permissions.insert(client.public_key().await, permission_set);
    /// let _ = entries.insert(b"key".to_vec(), b"value".to_vec());
    /// let owner = client.public_key().await;
    /// let address = client.store_unseq_map(name, tag, owner, Some(entries.clone()), Some(permissions)).await?;
    /// # let balance_after_first_write = client.get_local_balance().await; assert_ne!(initial_balance, balance_after_first_write);
    /// let _ = client.delete_map(address).await?;
    /// # let balance_after_second_write = client.get_local_balance().await; assert_ne!(balance_after_second_write, balance_after_first_write);
    /// # Ok(()) } ); }
    /// ```
    pub async fn delete_map(&self, address: MapAddress) -> Result<(), Error> {
        let cmd = DataCmd::Map(MapWrite::Delete(address));

        self.pay_and_send_data_command(cmd).await
    }

    /// Delete map user permission
    pub async fn delete_map_user_perms(
        &self,
        address: MapAddress,
        user: PublicKey,
        version: u64,
    ) -> Result<(), Error> {
        let cmd = DataCmd::Map(MapWrite::DelUserPermissions {
            address,
            user,
            version,
        });

        self.pay_and_send_data_command(cmd).await
    }

    /// Set map user permissions
    pub async fn set_map_user_perms(
        &self,
        address: MapAddress,
        user: PublicKey,
        permissions: MapPermissionSet,
        version: u64,
    ) -> Result<(), Error> {
        let cmd = DataCmd::Map(MapWrite::SetUserPermissions {
            address,
            user,
            permissions,
            version,
        });

        self.pay_and_send_data_command(cmd).await
    }

    /// Mutate map user entries
    pub async fn edit_map_entries(
        &self,
        address: MapAddress,
        changes: MapEntryActions,
    ) -> Result<(), Error> {
        let cmd = DataCmd::Map(MapWrite::Edit { address, changes });

        self.pay_and_send_data_command(cmd).await
    }

    //-------------------
    // Gets
    // ------------------

    /// Fetch map data from the network
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # extern crate tokio; use anyhow::Result; use std::str::FromStr;
    /// # use sn_client::utils::test_utils::read_network_conn_info;
    /// use sn_client::Client;
    /// use sn_data_types::{ Keypair, Token, MapAction, MapPermissionSet, MapUnseqEntries};
    /// use std::collections::BTreeMap;
    /// use xor_name::XorName;
    /// use rand::rngs::OsRng;
    /// # #[tokio::main] async fn main() { let _: Result<()> = futures::executor::block_on( async {
    /// // Let's use an existing client, with a pre-existing balance to be used for write payments.
    /// let id = Keypair::new_ed25519(&mut OsRng);

    /// # let bootstrap_contacts = Some(read_network_conn_info()?);
    /// let mut client = Client::new(Some(id), None, bootstrap_contacts).await?;
    /// # let initial_balance = Token::from_str("100")?; client.trigger_simulated_farming_payout(initial_balance).await?;
    /// let name = XorName::random();
    /// let tag = 15001;
    /// let mut entries = MapUnseqEntries::default();
    /// let mut permissions = BTreeMap::default();
    /// let permission_set = MapPermissionSet::new().allow(MapAction::Read);
    /// let _ = permissions.insert(client.public_key().await, permission_set);
    /// let _ = entries.insert(b"key".to_vec(), b"value".to_vec());
    /// let owner = client.public_key().await;
    /// let address = client.store_unseq_map(name, tag, owner, Some(entries.clone()), Some(permissions)).await?;
    /// # let balance_after_first_write = client.get_local_balance().await; assert_ne!(initial_balance, balance_after_first_write);
    /// let _ = client.get_map(address).await?;
    /// # Ok(()) } ); }
    /// ```
    pub async fn get_map(&self, address: MapAddress) -> Result<Map, Error>
    where
        Self: Sized,
    {
        trace!("Fetch Sequenced Mutable Data");

        let query_result = self
            .send_query(wrap_map_read(MapRead::Get(address)))
            .await?;
        let msg_id = query_result.msg_id;
        match query_result.response {
            QueryResponse::GetMap(res) => res.map_err(|err| Error::from((err, msg_id))),
            _ => Err(Error::ReceivedUnexpectedEvent),
        }
    }

    /// Fetch the value for a given key in a map
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # extern crate tokio; use anyhow::Result; use std::str::FromStr;
    /// # use sn_client::utils::test_utils::read_network_conn_info;
    /// use sn_client::Client;
    /// use sn_data_types::{ Keypair, Token, MapAction, MapValue, MapPermissionSet, MapUnseqEntries};
    /// use std::collections::BTreeMap;
    /// use xor_name::XorName;
    /// use rand::rngs::OsRng;
    /// # #[tokio::main] async fn main() { let _: Result<()> = futures::executor::block_on( async {
    /// // Let's use an existing client, with a pre-existing balance to be used for write payments.
    /// let id = Keypair::new_ed25519(&mut OsRng);

    /// # let bootstrap_contacts = Some(read_network_conn_info()?);
    /// let mut client = Client::new(Some(id), None, bootstrap_contacts).await?;
    /// # let initial_balance = Token::from_str("100")?; client.trigger_simulated_farming_payout(initial_balance).await?;
    /// let name = XorName::random();
    /// let tag = 15001;
    /// let mut entries = MapUnseqEntries::default();
    /// let _ = entries.insert(b"beep".to_vec(), b"boop".to_vec() );
    /// let mut permissions = BTreeMap::default();
    /// let permission_set = MapPermissionSet::new().allow(MapAction::Read);
    /// let _ = permissions.insert(client.public_key().await, permission_set);
    /// let _ = entries.insert(b"key".to_vec(), b"value".to_vec());
    /// let owner = client.public_key().await;
    /// let address = client.store_unseq_map(name, tag, owner, Some(entries.clone()), Some(permissions)).await?;
    /// # let balance_after_first_write = client.get_local_balance().await; assert_ne!(initial_balance, balance_after_first_write);
    /// let received_value = match client.get_map_value(address, b"beep".to_vec()).await? {
    ///     MapValue::Unseq(value) => value,
    ///     _ => panic!("Exptected an unsequenced map")
    /// };
    /// assert_eq!(received_value, b"boop".to_vec());
    /// # Ok(()) } ); }
    /// ```
    pub async fn get_map_value(&self, address: MapAddress, key: Vec<u8>) -> Result<MapValue, Error>
    where
        Self: Sized,
    {
        trace!("Fetch MapValue for {:?}", address);

        let query_result = self
            .send_query(wrap_map_read(MapRead::GetValue { address, key }))
            .await?;
        let msg_id = query_result.msg_id;
        match query_result.response {
            QueryResponse::GetMapValue(res) => res.map_err(|err| Error::from((err, msg_id))),
            _ => Err(Error::ReceivedUnexpectedEvent),
        }
    }

    /// Get a shell (bare bones) version of `Map` from the network.
    pub async fn get_map_shell(&self, address: MapAddress) -> Result<Map, Error>
    where
        Self: Sized,
    {
        trace!("GetMapShell for {:?}", address);

        let query_result = self
            .send_query(wrap_map_read(MapRead::GetShell(address)))
            .await?;
        let msg_id = query_result.msg_id;
        match query_result.response {
            QueryResponse::GetMapShell(res) => res.map_err(|err| Error::from((err, msg_id))),
            _ => Err(Error::ReceivedUnexpectedEvent),
        }
    }

    /// Get a current version of `Map` from the network.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # extern crate tokio; use anyhow::Result; use std::str::FromStr;
    /// # use sn_client::utils::test_utils::read_network_conn_info;
    /// use sn_client::Client;
    /// use sn_data_types::{ Keypair, Token, MapAction, MapPermissionSet, MapUnseqEntries};
    /// use rand::rngs::OsRng;
    /// use std::collections::BTreeMap;
    /// use xor_name::XorName;
    /// # #[tokio::main] async fn main() { let _: Result<()> = futures::executor::block_on( async {
    /// // Let's use an existing client, with a pre-existing balance to be used for write payments.
    /// let id = Keypair::new_ed25519(&mut OsRng);

    /// # let bootstrap_contacts = Some(read_network_conn_info()?);
    /// let mut client = Client::new(Some(id), None, bootstrap_contacts).await?;
    /// # let initial_balance = Token::from_str("100")?; client.trigger_simulated_farming_payout(initial_balance).await?;
    /// let name = XorName::random();
    /// let tag = 15001;
    /// let mut entries = MapUnseqEntries::default();
    /// let _ = entries.insert(b"beep".to_vec(), b"boop".to_vec() );
    /// let mut permissions = BTreeMap::default();
    /// let permission_set = MapPermissionSet::new().allow(MapAction::Read);
    /// let _ = permissions.insert(client.public_key().await, permission_set);
    /// let _ = entries.insert(b"key".to_vec(), b"value".to_vec());
    /// let owner = client.public_key().await;
    /// let address = client.store_unseq_map(name, tag, owner, Some(entries.clone()), Some(permissions)).await?;
    /// # let balance_after_first_write = client.get_local_balance().await; assert_ne!(initial_balance, balance_after_first_write);
    /// let version = client.get_map_version(address).await?;
    /// assert_eq!(version, 0);
    /// # Ok(()) } ); }
    /// ```
    pub async fn get_map_version(&self, address: MapAddress) -> Result<u64, Error>
    where
        Self: Sized,
    {
        trace!("GetMapVersion for {:?}", address);

        let query_result = self
            .send_query(wrap_map_read(MapRead::GetVersion(address)))
            .await?;
        let msg_id = query_result.msg_id;
        match query_result.response {
            QueryResponse::GetMapVersion(res) => res.map_err(|err| Error::from((err, msg_id))),
            _ => Err(Error::ReceivedUnexpectedEvent),
        }
    }

    //----------
    // Entries
    //----------

    /// Mutates sequenced `Map` entries in bulk
    pub async fn mutate_seq_map_entries(
        &self,
        name: XorName,
        tag: u64,
        actions: MapSeqEntryActions,
    ) -> Result<(), Error>
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
        &self,
        name: XorName,
        tag: u64,
        actions: MapUnseqEntryActions,
    ) -> Result<(), Error>
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
        &self,
        name: XorName,
        tag: u64,
    ) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, Error>
    where
        Self: Sized,
    {
        trace!("ListMapEntries for {:?}", name);

        let query_result = self
            .send_query(wrap_map_read(MapRead::ListEntries(MapAddress::Unseq {
                name,
                tag,
            })))
            .await?;
        let msg_id = query_result.msg_id;
        match query_result.response {
            QueryResponse::ListMapEntries(res) => res
                .map_err(|err| Error::from((err, msg_id)))
                .and_then(|entries| match entries {
                    MapEntries::Unseq(data) => Ok(data),
                    MapEntries::Seq(_) => Err(Error::ReceivedUnexpectedData),
                }),
            _ => Err(Error::ReceivedUnexpectedEvent),
        }
    }

    /// Return a complete list of entries in `Map`.
    pub async fn list_seq_map_entries(
        &self,
        name: XorName,
        tag: u64,
    ) -> Result<MapSeqEntries, Error>
    where
        Self: Sized,
    {
        trace!("ListSeqMapEntries for {:?}", name);

        let query_result = self
            .send_query(wrap_map_read(MapRead::ListEntries(MapAddress::Seq {
                name,
                tag,
            })))
            .await?;
        let msg_id = query_result.msg_id;
        match query_result.response {
            QueryResponse::ListMapEntries(res) => res
                .map_err(|err| Error::from((err, msg_id)))
                .and_then(|entries| match entries {
                    MapEntries::Seq(data) => Ok(data),
                    MapEntries::Unseq(_) => Err(Error::ReceivedUnexpectedData),
                }),
            _ => Err(Error::ReceivedUnexpectedEvent),
        }
    }

    /// Return a list of keys in `Map` stored on the network.
    pub async fn list_map_keys(&self, address: MapAddress) -> Result<BTreeSet<Vec<u8>>, Error>
    where
        Self: Sized,
    {
        trace!("ListMapKeys for {:?}", address);

        let query_result = self
            .send_query(wrap_map_read(MapRead::ListKeys(address)))
            .await?;
        let msg_id = query_result.msg_id;
        match query_result.response {
            QueryResponse::ListMapKeys(res) => res.map_err(|err| Error::from((err, msg_id))),
            _ => Err(Error::ReceivedUnexpectedEvent),
        }
    }

    /// Return a list of values in a Sequenced Mutable Data
    pub async fn list_seq_map_values(
        &self,
        name: XorName,
        tag: u64,
    ) -> Result<Vec<MapSeqValue>, Error>
    where
        Self: Sized,
    {
        trace!("List MapValues for {:?}", name);

        let query_result = self
            .send_query(wrap_map_read(MapRead::ListValues(MapAddress::Seq {
                name,
                tag,
            })))
            .await?;
        let msg_id = query_result.msg_id;
        match query_result.response {
            QueryResponse::ListMapValues(res) => res
                .map_err(|err| Error::from((err, msg_id)))
                .and_then(|values| match values {
                    MapValues::Seq(data) => Ok(data),
                    MapValues::Unseq(_) => Err(Error::ReceivedUnexpectedData),
                }),
            _ => Err(Error::ReceivedUnexpectedEvent),
        }
    }

    /// Returns a list of values in an Unsequenced Mutable Data
    pub async fn list_unseq_map_values(
        &self,
        name: XorName,
        tag: u64,
    ) -> Result<Vec<Vec<u8>>, Error>
    where
        Self: Sized,
    {
        trace!("List MapValues for {:?}", name);

        let query_result = self
            .send_query(wrap_map_read(MapRead::ListValues(MapAddress::Unseq {
                name,
                tag,
            })))
            .await?;
        let msg_id = query_result.msg_id;
        match query_result.response {
            QueryResponse::ListMapValues(res) => res
                .map_err(|err| Error::from((err, msg_id)))
                .and_then(|values| match values {
                    MapValues::Unseq(data) => Ok(data),
                    MapValues::Seq(_) => Err(Error::ReceivedUnexpectedData),
                }),
            _ => Err(Error::ReceivedUnexpectedEvent),
        }
    }

    //-----------------
    // Permissions
    //-----------------

    /// Return the permissions set for a particular user
    pub async fn list_map_user_permissions(
        &self,
        address: MapAddress,
        user: PublicKey,
    ) -> Result<MapPermissionSet, Error>
    where
        Self: Sized,
    {
        trace!("GetMapUserPermissions for {:?}", address);

        let query_result = self
            .send_query(wrap_map_read(MapRead::ListUserPermissions {
                address,
                user,
            }))
            .await?;
        let msg_id = query_result.msg_id;
        match query_result.response {
            QueryResponse::ListMapUserPermissions(res) => {
                res.map_err(|err| Error::from((err, msg_id)))
            }
            _ => Err(Error::ReceivedUnexpectedEvent),
        }
    }

    /// Return a list of permissions in `Map` stored on the network.
    pub async fn list_map_permissions(
        &self,
        address: MapAddress,
    ) -> Result<BTreeMap<PublicKey, MapPermissionSet>, Error>
    where
        Self: Sized,
    {
        trace!("List MapPermissions for {:?}", address);

        let query_result = self
            .send_query(wrap_map_read(MapRead::ListPermissions(address)))
            .await?;
        let msg_id = query_result.msg_id;
        match query_result.response {
            QueryResponse::ListMapPermissions(res) => res.map_err(|err| Error::from((err, msg_id))),
            _ => Err(Error::ReceivedUnexpectedEvent),
        }
    }

    /// Updates or inserts a permissions set for a user
    pub async fn set_map_user_permissions(
        &self,
        address: MapAddress,
        user: PublicKey,
        permissions: MapPermissionSet,
        version: u64,
    ) -> Result<(), Error>
    where
        Self: Sized,
    {
        trace!("SetMapUserPermissions for {:?}", address);

        self.set_map_user_perms(address, user, permissions, version)
            .await
    }

    /// Updates or inserts a permissions set for a user
    pub async fn del_map_user_permissions(
        &self,
        address: MapAddress,
        user: PublicKey,
        version: u64,
    ) -> Result<(), Error>
    where
        Self: Sized,
    {
        trace!("DelMapUserPermissions for {:?}", address);

        self.delete_map_user_perms(address, user, version).await
    }

    /// Sends an ownership transfer request.
    pub fn change_map_owner(
        &self,
        _name: XorName,
        _tag: u64,
        _new_owner: PublicKey,
        _version: u64,
    ) -> Result<(), Error> {
        unimplemented!();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::{create_test_client, gen_ed_keypair};
    use anyhow::{anyhow, bail, Result};
    use sn_data_types::{MapAction, MapKind, Token};
    use sn_messaging::client::Error as ErrorMessage;
    use std::str::FromStr;
    use std::time::Duration;
    use tokio::time::sleep;
    use xor_name::XorName;

    // 1. Create unseq. map with some entries and perms and put it on the network
    // 2. Fetch the shell version, entries, keys, values anv verify them
    // 3. Fetch the entire. data object and verify
    #[tokio::test]
    pub async fn unseq_map_test() -> Result<()> {
        let client = create_test_client().await?;

        let name = XorName(rand::random());
        let tag = 15001;
        let mut entries: BTreeMap<Vec<u8>, Vec<u8>> = Default::default();
        let mut permissions: BTreeMap<_, _> = Default::default();
        let permission_set = MapPermissionSet::new().allow(MapAction::Read);
        let _ = permissions.insert(client.public_key().await, permission_set);
        let _ = entries.insert(b"key".to_vec(), b"value".to_vec());
        let entries_keys = entries.keys().cloned().collect();
        let entries_values: Vec<Vec<u8>> = entries.values().cloned().collect();
        let owner = client.public_key().await;
        let address = client
            .store_unseq_map(name, tag, owner, Some(entries.clone()), Some(permissions))
            .await?;

        let mut res: Result<u64> = Err(anyhow!("Timeout!".to_string()));
        while res.is_err() {
            sleep(Duration::from_millis(200)).await;
            res = match client
                .get_map_version(MapAddress::Unseq { name, tag })
                .await
            {
                Ok(res) => Ok(res),
                Err(error) => Err(error.into()), // into anyhow error
            };
        }

        let version = res?;

        assert_eq!(version, 0);
        let fetched_entries = client.list_unseq_map_entries(name, tag).await?;
        assert_eq!(fetched_entries, entries);
        let keys = client
            .list_map_keys(MapAddress::Unseq { name, tag })
            .await?;
        assert_eq!(keys, entries_keys);
        let values = client.list_unseq_map_values(name, tag).await?;
        assert_eq!(values, entries_values);
        let fetched_data = client.get_map(address).await?;
        assert_eq!(*fetched_data.name(), name);
        assert_eq!(fetched_data.tag(), tag);
        Ok(())
    }

    // 1. Create an put seq. map on the network with some entries and permissions.
    // 2. Fetch the shell version, entries, keys, values anv verify them
    // 3. Fetch the entire. data object and verify
    #[tokio::test]
    pub async fn seq_map_test() -> Result<()> {
        let client = create_test_client().await?;

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
        let owner = client.public_key().await;

        let address = client
            .store_seq_map(name, tag, owner, Some(entries.clone()), Some(permissions))
            .await?;

        let mut res: Result<MapSeqEntries> = Err(anyhow!("Timeout!".to_string()));
        while res.is_err() {
            sleep(Duration::from_millis(200)).await;
            res = match client.list_seq_map_entries(name, tag).await {
                Ok(res) => Ok(res),
                Err(error) => Err(error.into()), // into anyhow error
            };
        }
        let fetched_entries = res?;

        assert_eq!(fetched_entries, entries);
        let map_shell = match client.get_map_shell(address).await? {
            Map::Seq(data) => data,
            _ => bail!("expected sequence map"),
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
            _ => bail!("Expected seq map"),
        };
        assert_eq!(*fetched_data.name(), name);
        assert_eq!(fetched_data.tag(), tag);
        assert_eq!(fetched_data.entries().len(), 1);
        Ok(())
    }

    // 1. Put seq. map on the network and then delete it
    // 2. Try getting the data object. It should bail
    #[tokio::test]
    pub async fn del_seq_map_test() -> Result<()> {
        let client = create_test_client().await?;
        let name = XorName(rand::random());
        let tag = 15001;
        let mapref = MapAddress::Seq { name, tag };
        let owner = client.public_key().await;

        let address = client.store_seq_map(name, tag, owner, None, None).await?;

        client.delete_map(mapref).await?;

        let mut res = client.get_map(address).await;
        while res.is_ok() {
            sleep(Duration::from_millis(200)).await;
            // Keep trying until it fails
            res = client.get_map(address).await;
        }

        match res {
            Err(Error::ErrorMessage {
                source: ErrorMessage::DataNotFound(_),
                ..
            }) => (),
            _ => bail!("Unexpected success"),
        }
        Ok(())
    }

    // 1. Put unseq. map on the network and then delete it
    // 2. Try getting the data object. It should bail
    #[tokio::test]
    pub async fn del_unseq_map_test() -> Result<()> {
        let client = create_test_client().await?;
        let name = XorName(rand::random());
        let tag = 15001;
        let mapref = MapAddress::Unseq { name, tag };
        let owner = client.public_key().await;

        let address = client.store_unseq_map(name, tag, owner, None, None).await?;

        client.delete_map(mapref).await?;

        let mut res = client.get_map(address).await;
        while res.is_ok() {
            // Keep trying until it fails
            res = client.get_map(address).await;
        }

        match res {
            Err(Error::ErrorMessage {
                source: ErrorMessage::DataNotFound(_),
                ..
            }) => (),
            _ => bail!("Unexpected success"),
        }

        Ok(())
    }

    // 1. Create a client that PUTs some map on the network
    // 2. Create a different client that tries to delete the data. It should bail.
    #[tokio::test]
    pub async fn del_unseq_map_permission_test() -> Result<()> {
        let name = XorName(rand::random());
        let tag = 15001;
        let mapref = MapAddress::Unseq { name, tag };

        let client = create_test_client().await?;
        let owner = client.public_key().await;

        let _ = client.store_unseq_map(name, tag, owner, None, None).await?;

        let mut client = create_test_client().await?;

        client.delete_map(mapref).await?;

        match client.expect_cmd_error().await {
            Some(sn_messaging::client::CmdError::Data(
                sn_messaging::client::Error::AccessDenied(_),
            )) => Ok(()),
            _ => bail!("Unexpected: Deletion by non-owners should fail"),
        }
    }

    #[tokio::test]
    pub async fn map_cannot_initially_put_data_with_another_owner_than_current_client() -> Result<()>
    {
        let client = create_test_client().await?;
        let mut permissions: BTreeMap<_, _> = Default::default();
        let permission_set = MapPermissionSet::new()
            .allow(MapAction::Read)
            .allow(MapAction::Insert)
            .allow(MapAction::ManagePermissions);
        let user = client.public_key().await;
        let random_user = gen_ed_keypair().public_key();
        let random_pk = gen_ed_keypair().public_key();

        let _ = permissions.insert(user, permission_set.clone());
        let _ = permissions.insert(random_user, permission_set);

        let test_data_name = XorName(rand::random());
        let address = client
            .store_seq_map(test_data_name, 15000u64, random_pk, None, Some(permissions))
            .await?;
        let res = client.get_map_shell(address).await;
        match res {
            Err(Error::ErrorMessage {
                source: ErrorMessage::DataNotFound(_),
                ..
            }) => (),
            Ok(_) => bail!("Unexpected Success: Validating owners should fail"),
            Err(e) => bail!("Unexpected: {:?}", e),
        };

        // TODO: Refunds not yet in place.... Reenable this check when that's the case

        // Check token was not taken
        // let balance = client.get_balance().await?;
        // let expected_bal = calculate_new_balance(start_bal, Some(2), None);
        // assert_eq!(balance, expected_bal);

        Ok(())
    }

    // 1. Create a map with some permissions and store it on the network.
    // 2. Modify the permissions of a user in the permission set.
    // 3. Fetch the list of permissions and verify the edit.
    // 4. Delete a user's permissions from the permission set and verify the deletion.
    #[tokio::test]
    pub async fn map_can_modify_permissions_test() -> Result<()> {
        let client = create_test_client().await?;
        let name = XorName(rand::random());
        let tag = 15001;
        let mut permissions: BTreeMap<_, _> = Default::default();
        let permission_set = MapPermissionSet::new()
            .allow(MapAction::Read)
            .allow(MapAction::Insert)
            .allow(MapAction::ManagePermissions);
        let user = client.public_key().await;
        let random_user = gen_ed_keypair().public_key();

        let _ = permissions.insert(user, permission_set.clone());
        let _ = permissions.insert(random_user, permission_set);

        let owner = client.public_key().await;

        // Store the data
        let address = client
            .store_seq_map(name, tag, owner, None, Some(permissions))
            .await?;

        // Assert that the data is stored.
        let mut res = client.get_map(address).await;
        while res.is_err() {
            sleep(Duration::from_millis(200)).await;
            res = client.get_map(address).await;
        }

        let new_perm_set = MapPermissionSet::new()
            .allow(MapAction::ManagePermissions)
            .allow(MapAction::Read);

        // Set new perms to the data
        client
            .set_map_user_permissions(MapAddress::Seq { name, tag }, user, new_perm_set, 1)
            .await?;

        // Assert that the new perms are set.
        let mut permissions = client
            .list_map_user_permissions(MapAddress::Seq { name, tag }, user)
            .await?;
        while permissions.is_allowed(MapAction::Insert) {
            sleep(Duration::from_millis(200)).await;
            permissions = client
                .list_map_user_permissions(MapAddress::Seq { name, tag }, user)
                .await?;
        }
        assert!(!permissions.is_allowed(MapAction::Insert));
        assert!(permissions.is_allowed(MapAction::Read));
        assert!(permissions.is_allowed(MapAction::ManagePermissions));

        // Delete user perms
        client
            .del_map_user_permissions(MapAddress::Seq { name, tag }, random_user, 2)
            .await?;

        // Assert perms deletion.
        let mut permissions = client
            .list_map_permissions(MapAddress::Seq { name, tag })
            .await?;
        while permissions.len() != 1 {
            sleep(Duration::from_millis(200)).await;
            permissions = client
                .list_map_permissions(MapAddress::Seq { name, tag })
                .await?;
        }

        Ok(())
    }

    // 1. Create a map and store it on the network
    // 2. Create some entry actions and mutate the data on the network.
    // 3. List the entries and verify that the mutation was applied.
    // 4. Fetch a value for a particular key and verify
    #[tokio::test]
    pub async fn map_mutations_test() -> Result<()> {
        let client = create_test_client().await?;
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
        let owner = client.public_key().await;

        let address = client
            .store_seq_map(name, tag, owner, Some(entries.clone()), Some(permissions))
            .await?;

        // Assert that the data is stored.
        let mut res = client.get_map(address).await;

        while res.is_err() {
            sleep(Duration::from_millis(200)).await;
            res = client.get_map(address).await;
        }
        let fetched_entries = client.list_seq_map_entries(name, tag).await?;

        assert_eq!(fetched_entries, entries);
        let entry_actions: MapSeqEntryActions = MapSeqEntryActions::new()
            .update(b"key1".to_vec(), b"newValue".to_vec(), 1)
            .del(b"key2".to_vec(), 1)
            .ins(b"key3".to_vec(), b"value".to_vec(), 0);

        client
            .mutate_seq_map_entries(name, tag, entry_actions)
            .await?;

        let mut fetched_entries = client.list_seq_map_entries(name, tag).await?;
        while fetched_entries.contains_key(&b"key2".to_vec()) {
            fetched_entries = client.list_seq_map_entries(name, tag).await?;
        }

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
            _ => bail!("Unexpected seq mutable data"),
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
            Ok(_) => bail!("Unexpected: Entry should not exist"),
            Err(Error::ErrorMessage {
                source: ErrorMessage::NoSuchEntry,
                ..
            }) => (),
            Err(err) => bail!("Unexpected error: {:?}", err),
        };

        let client = create_test_client().await?;
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

        let owner = client.public_key().await;
        let address = client
            .store_unseq_map(name, tag, owner, Some(entries.clone()), Some(permissions))
            .await?;

        // Assert that the data is stored.
        let mut res = client.get_map(address).await;
        while res.is_err() {
            sleep(Duration::from_millis(200)).await;
            res = client.get_map(address).await;
        }

        let fetched_entries = client.list_unseq_map_entries(name, tag).await?;
        assert_eq!(fetched_entries, entries);
        let entry_actions: MapUnseqEntryActions = MapUnseqEntryActions::new()
            .update(b"key1".to_vec(), b"newValue".to_vec())
            .del(b"key2".to_vec())
            .ins(b"key3".to_vec(), b"value".to_vec());

        client
            .mutate_unseq_map_entries(name, tag, entry_actions)
            .await?;

        let mut fetched_entries = client.list_unseq_map_entries(name, tag).await?;
        while fetched_entries.contains_key(&b"key2".to_vec()) {
            fetched_entries = client.list_unseq_map_entries(name, tag).await?;
        }

        let mut expected_entries: BTreeMap<_, _> = Default::default();
        let _ = expected_entries.insert(b"key1".to_vec(), b"newValue".to_vec());
        let _ = expected_entries.insert(b"key3".to_vec(), b"value".to_vec());
        assert_eq!(fetched_entries, expected_entries);
        let fetched_value = match client.get_map_value(address, b"key1".to_vec()).await? {
            MapValue::Unseq(value) => value,
            _ => bail!("unexpeced seq mutable data"),
        };

        assert_eq!(fetched_value, b"newValue".to_vec());
        let res = client.get_map_value(address, b"wrongKey".to_vec()).await;
        match res {
            Ok(_) => bail!("Unexpected: Entry should not exist"),
            Err(Error::ErrorMessage {
                source: ErrorMessage::NoSuchEntry,
                ..
            }) => Ok(()),
            Err(err) => bail!("Unexpected error: {:?}", err),
        }
    }

    #[tokio::test]
    pub async fn map_deletions_should_cost_put_price() -> Result<()> {
        let name = XorName(rand::random());
        let tag = 10;
        let client = create_test_client().await?;
        let owner = client.public_key().await;

        let _ = client.store_unseq_map(name, tag, owner, None, None).await?;

        let map_address = MapAddress::from_kind(MapKind::Unseq, name, tag);

        let balance_before_delete = client.get_balance().await?;
        client.delete_map(map_address).await?;
        let new_balance = client.get_balance().await?;

        // make sure we have _some_ balance
        assert_ne!(balance_before_delete, Token::from_str("0")?);
        assert_ne!(balance_before_delete, new_balance);

        Ok(())
    }
}
