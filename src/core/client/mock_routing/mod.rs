// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net
// Commercial License, version 1.0 or later, or (2) The General Public License
// (GPL), version 3, depending on which licence you accepted on initial access
// to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project
// generally, you agree to be bound by the terms of the MaidSafe Contributor
// Agreement, version 1.0.
// This, along with the Licenses can be found in the root directory of this
// project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network
// Software distributed under the GPL Licence is distributed on an "AS IS"
// BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
//
// Please review the Licences for the specific language governing permissions
// and limitations relating to use of the SAFE Network Software.

#![allow(unused)] // <-- TODO: remove this

mod storage;
use maidsafe_utilities::thread;
use rand;
use routing::{Authority, ClientError, Data, EntryAction, Event, FullId, ImmutableData,
              InterfaceError, MessageId, MutableData, PermissionSet, Response, RoutingError, User,
              XorName};
// use routing::TYPE_TAG_SESSION_PACKET;
use rust_sodium::crypto::hash::sha256;
use rust_sodium::crypto::sign;
use self::storage::{Storage, StorageError};
use std;
use std::cell::Cell;
use std::collections::BTreeMap;
use std::sync::Mutex;
use std::sync::mpsc::Sender;
use std::time::Duration;

const CONNECT_THREAD_NAME: &'static str = "Mock routing connect";
const DELAY_THREAD_NAME: &'static str = "Mock routing delay";

const DEFAULT_DELAY_MS: u64 = 0;
const CONNECT_DELAY_MS: u64 = DEFAULT_DELAY_MS;

const GET_ACCOUNT_INFO_DELAY_MS: u64 = DEFAULT_DELAY_MS;
const PUT_IDATA_DELAY_MS: u64 = DEFAULT_DELAY_MS;
const GET_IDATA_DELAY_MS: u64 = DEFAULT_DELAY_MS;

const PUT_MDATA_DELAY_MS: u64 = DEFAULT_DELAY_MS;
const GET_MDATA_VERSION_DELAY_MS: u64 = DEFAULT_DELAY_MS;
const GET_MDATA_ENTRIES_DELAY_MS: u64 = DEFAULT_DELAY_MS;
const SET_MDATA_ENTRIES_DELAY_MS: u64 = DEFAULT_DELAY_MS;
const GET_MDATA_PERMISSIONS_DELAY_MS: u64 = DEFAULT_DELAY_MS;
const SET_MDATA_PERMISSIONS_DELAY_MS: u64 = DEFAULT_DELAY_MS;
const CHANGE_MDATA_OWNER_DELAY_MS: u64 = DEFAULT_DELAY_MS;

lazy_static! {
    static ref STORAGE: Mutex<Storage> = Mutex::new(Storage::new());
}

pub struct MockRouting {
    sender: Sender<Event>,
    client_auth: Authority,
    max_ops_countdown: Option<Cell<u64>>,
    timeout_simulation: bool,
}

impl MockRouting {
    pub fn new(sender: Sender<Event>, _id: Option<FullId>) -> Result<Self, RoutingError> {
        ::rust_sodium::init();

        let cloned_sender = sender.clone();
        let _ = thread::named(CONNECT_THREAD_NAME, move || {
            std::thread::sleep(Duration::from_millis(CONNECT_DELAY_MS));
            let _ = cloned_sender.send(Event::Connected);
        });

        let client_auth = Authority::Client {
            client_key: sign::gen_keypair().0,
            peer_id: rand::random(),
            proxy_node_name: rand::random(),
        };
        Ok(MockRouting {
            sender: sender,
            client_auth: client_auth,
            max_ops_countdown: None,
            timeout_simulation: false,
        })
    }

    /// Gets MAID account information.
    pub fn get_account_info(&mut self,
                            dst: Authority,
                            msg_id: MessageId)
                            -> Result<(), InterfaceError> {
        if self.timeout_simulation {
            return Ok(());
        }

        let res = if let Err(err) = self.verify_network_limits(msg_id, "get_account_info") {
            Err(err)
        } else {
            match unwrap!(STORAGE.lock()).get_account_info(&self.client_name()) {
                Some(account_info) => Ok(*account_info),
                None => Err(ClientError::NoSuchAccount),
            }
        };

        self.send_response(GET_ACCOUNT_INFO_DELAY_MS,
                           dst,
                           self.client_auth,
                           Response::GetAccountInfo {
                               res: res,
                               msg_id: msg_id,
                           });

        Ok(())
    }

    /// Puts ImmutableData to the network.
    pub fn put_idata(&mut self,
                     _dst: Authority,
                     data: ImmutableData,
                     msg_id: MessageId)
                     -> Result<(), InterfaceError> {
        if self.timeout_simulation {
            return Ok(());
        }

        let data_name = *data.name();

        let res = if let Err(err) = self.verify_network_limits(msg_id, "put_idata") {
            Err(err)
        } else {
            let mut storage = unwrap!(STORAGE.lock());
            match storage.get_data(data.name()) {
                // Immutable data is de-duplicated so always allowed
                Ok(Data::Immutable(_)) => Ok(()),
                Ok(_) => Err(ClientError::DataExists),
                Err(StorageError::NoSuchData) => {
                    storage.put_data(data_name, Data::Immutable(data))
                        .map_err(ClientError::from)
                }
                Err(err) => Err(ClientError::from(err)),
            }
        };

        if res.is_ok() {
            let mut storage = unwrap!(STORAGE.lock());
            update_account_info(&mut storage, &self.client_name());
            storage.sync();
        }

        let nae_auth = Authority::NaeManager(data_name);
        self.send_response(PUT_IDATA_DELAY_MS,
                           nae_auth,
                           self.client_auth,
                           Response::PutIData {
                               res: res,
                               msg_id: msg_id,
                           });
        Ok(())
    }

    /// Fetches ImmutableData from the network by the given name.
    pub fn get_idata(&mut self,
                     _dst: Authority,
                     name: XorName,
                     msg_id: MessageId)
                     -> Result<(), InterfaceError> {
        if self.timeout_simulation {
            return Ok(());
        }

        let res = if let Err(err) = self.verify_network_limits(msg_id, "get_idata") {
            Err(err)
        } else {
            match unwrap!(STORAGE.lock()).get_data(&name) {
                Ok(Data::Immutable(data)) => Ok(data),
                _ => Err(ClientError::NoSuchData),
            }
        };

        let nae_auth = Authority::NaeManager(name);
        self.send_response(GET_IDATA_DELAY_MS,
                           nae_auth,
                           self.client_auth,
                           Response::GetIData {
                               res: res,
                               msg_id: msg_id,
                           });
        Ok(())
    }

    /// Creates a new MutableData in the network.
    pub fn put_mdata(&mut self,
                     dst: Authority,
                     data: MutableData,
                     msg_id: MessageId,
                     requester: sign::PublicKey)
                     -> Result<(), InterfaceError> {
        if self.timeout_simulation {
            return Ok(());
        }

        let data_name = *data.name();

        let res = if let Err(err) = self.verify_network_limits(msg_id, "put_mdata") {
            Err(err)
        } else {
            let mut storage = unwrap!(STORAGE.lock());
            if storage.contains_data(data.name()) {
                Err(ClientError::DataExists)
            } else {
                storage.put_data(data_name, Data::Mutable(data))
                    .map_err(ClientError::from)
            }
        };

        if res.is_ok() {
            let mut storage = unwrap!(STORAGE.lock());
            update_account_info(&mut storage, &self.client_name());
            storage.sync();
        }

        let nae_auth = Authority::NaeManager(data_name);
        self.send_response(PUT_MDATA_DELAY_MS,
                           nae_auth,
                           self.client_auth,
                           Response::PutMData {
                               res: res,
                               msg_id: msg_id,
                           });
        Ok(())
    }

    /// Fetches a latest version number.
    pub fn get_mdata_version(&mut self,
                             dst: Authority,
                             name: XorName,
                             tag: u64,
                             msg_id: MessageId)
                             -> Result<(), InterfaceError> {
        self.read_mdata(name,
                        msg_id,
                        "get_mdata_version",
                        GET_MDATA_VERSION_DELAY_MS,
                        |data| Ok(data.version()),
                        |res| {
                            Response::GetMDataVersion {
                                res: res,
                                msg_id: msg_id,
                            }
                        })
    }

    /// Fetches a list of entries (keys + values).
    pub fn list_mdata_entries(&mut self,
                              dst: Authority,
                              name: XorName,
                              tag: u64,
                              msg_id: MessageId)
                              -> Result<(), InterfaceError> {
        self.read_mdata(name,
                        msg_id,
                        "list_mdata_entries",
                        GET_MDATA_ENTRIES_DELAY_MS,
                        |data| Ok(data.entries().clone()),
                        |res| {
                            Response::ListMDataEntries {
                                res: res,
                                msg_id: msg_id,
                            }
                        })
    }

    /// Fetches a list of keys in MutableData.
    pub fn list_mdata_keys(&mut self,
                           dst: Authority,
                           name: XorName,
                           tag: u64,
                           msg_id: MessageId)
                           -> Result<(), InterfaceError> {
        self.read_mdata(name,
                        msg_id,
                        "list_mdata_keys",
                        GET_MDATA_ENTRIES_DELAY_MS,
                        |data| {
                            let keys = data.keys().into_iter().cloned().collect();
                            Ok(keys)
                        },
                        |res| {
                            Response::ListMDataKeys {
                                res: res,
                                msg_id: msg_id,
                            }
                        })
    }

    /// Fetches a list of values in MutableData.
    pub fn list_mdata_values(&mut self,
                             dst: Authority,
                             name: XorName,
                             tag: u64,
                             msg_id: MessageId)
                             -> Result<(), InterfaceError> {
        self.read_mdata(name,
                        msg_id,
                        "list_mdata_values",
                        GET_MDATA_ENTRIES_DELAY_MS,
                        |data| {
                            let values = data.values().into_iter().cloned().collect();
                            Ok(values)
                        },
                        |res| {
                            Response::ListMDataValues {
                                res: res,
                                msg_id: msg_id,
                            }
                        })
    }

    /// Fetches a single value from MutableData
    pub fn get_mdata_value(&mut self,
                           dst: Authority,
                           name: XorName,
                           tag: u64,
                           key: Vec<u8>,
                           msg_id: MessageId)
                           -> Result<(), InterfaceError> {
        self.read_mdata(name,
                        msg_id,
                        "get_mdata_value",
                        GET_MDATA_ENTRIES_DELAY_MS,
                        |data| {
                            data.get(&key)
                                .cloned()
                                .ok_or(ClientError::NoSuchEntry)
                        },
                        |res| {
                            Response::GetMDataValue {
                                res: res,
                                msg_id: msg_id,
                            }
                        })
    }

    /// Updates MutableData entries in bulk.
    pub fn mutate_mdata_entries(&mut self,
                                dst: Authority,
                                name: XorName,
                                tag: u64,
                                actions: BTreeMap<Vec<u8>, EntryAction>,
                                msg_id: MessageId,
                                requester: sign::PublicKey)
                                -> Result<(), InterfaceError> {
        self.mutate_mdata(name,
                          msg_id,
                          "mutate_mdata_entries",
                          SET_MDATA_ENTRIES_DELAY_MS,
                          |data| data.mutate_entries(actions, requester),
                          |res| {
                              Response::MutateMDataEntries {
                                  res: res,
                                  msg_id: msg_id,
                              }
                          })
    }

    /// Fetches a complete list of permissions.
    pub fn list_mdata_permissions(&mut self,
                                  dst: Authority,
                                  name: XorName,
                                  tag: u64,
                                  msg_id: MessageId)
                                  -> Result<(), InterfaceError> {
        self.read_mdata(name,
                        msg_id,
                        "list_mdata_permissions",
                        GET_MDATA_PERMISSIONS_DELAY_MS,
                        |data| Ok(data.permissions().clone()),
                        |res| {
                            Response::ListMDataPermissions {
                                res: res,
                                msg_id: msg_id,
                            }
                        })
    }

    /// Fetches a list of permissions for a particular User.
    pub fn list_mdata_user_permissions(&mut self,
                                       dst: Authority,
                                       name: XorName,
                                       tag: u64,
                                       user: User,
                                       msg_id: MessageId)
                                       -> Result<(), InterfaceError> {
        self.read_mdata(name,
                        msg_id,
                        "list_mdata_user_permissions",
                        GET_MDATA_PERMISSIONS_DELAY_MS,
                        // TODO: data doesn't need to be mut here
                        |mut data| {
                            // TODO: better ClientError variant
                            data.user_permissions(&user)
                                .cloned()
                                .ok_or_else(|| ClientError::from("User not found"))
                        },
                        |res| {
                            Response::ListMDataUserPermissions {
                                res: res,
                                msg_id: msg_id,
                            }
                        })
    }

    /// Updates or inserts a list of permissions for a particular User in the given
    /// MutableData.
    pub fn set_mdata_user_permissions(&mut self,
                                      dst: Authority,
                                      name: XorName,
                                      tag: u64,
                                      user: User,
                                      permissions: PermissionSet,
                                      version: u64,
                                      msg_id: MessageId,
                                      requester: sign::PublicKey)
                                      -> Result<(), InterfaceError> {
        self.mutate_mdata(name,
                          msg_id,
                          "set_mdata_user_permissions",
                          SET_MDATA_PERMISSIONS_DELAY_MS,
                          |data| data.set_user_permissions(user, permissions, version, requester),
                          |res| {
                              Response::SetMDataUserPermissions {
                                  res: res,
                                  msg_id: msg_id,
                              }
                          })
    }

    /// Deletes a list of permissions for a particular User in the given MutableData.
    pub fn del_mdata_user_permissions(&mut self,
                                      dst: Authority,
                                      name: XorName,
                                      tag: u64,
                                      user: User,
                                      version: u64,
                                      msg_id: MessageId,
                                      requester: sign::PublicKey)
                                      -> Result<(), InterfaceError> {
        self.mutate_mdata(name,
                          msg_id,
                          "del_mdata_user_permissions",
                          SET_MDATA_PERMISSIONS_DELAY_MS,
                          |data| data.del_user_permissions(&user, version, requester),
                          |res| {
                              Response::DelMDataUserPermissions {
                                  res: res,
                                  msg_id: msg_id,
                              }
                          })
    }

    /// Changes an owner of the given MutableData. Only the current owner can perform this action.
    pub fn change_mdata_owner(&mut self,
                              dst: Authority,
                              name: XorName,
                              tag: u64,
                              new_owner: sign::PublicKey,
                              version: u64,
                              msg_id: MessageId,
                              requester: sign::PublicKey)
                              -> Result<(), InterfaceError> {
        self.mutate_mdata(name,
                          msg_id,
                          "change_mdata_owner",
                          CHANGE_MDATA_OWNER_DELAY_MS,
                          |data| data.change_owner(new_owner, version, requester),
                          |res| {
                              Response::ChangeMDataOwner {
                                  res: res,
                                  msg_id: msg_id,
                              }
                          })
    }

    fn send_response(&self, delay_ms: u64, src: Authority, dst: Authority, response: Response) {
        let event = Event::Response {
            response: response,
            src: src,
            dst: dst,
        };

        let sender = self.sender.clone();

        let _ = thread::named(DELAY_THREAD_NAME, move || {
            std::thread::sleep(Duration::from_millis(delay_ms));
            if let Err(err) = sender.send(event) {
                error!("mpsc-send failure: {:?}", err);
            }
        });
    }

    fn client_name(&self) -> XorName {
        match self.client_auth {
            Authority::Client { ref client_key, .. } => XorName(sha256::hash(&client_key[..]).0),
            _ => panic!("This authority must be Client"),
        }
    }

    fn read_mdata<F, G, R>(&self,
                           name: XorName,
                           msg_id: MessageId,
                           log_label: &str,
                           delay_ms: u64,
                           f: F,
                           g: G)
                           -> Result<(), InterfaceError>
        where F: FnOnce(MutableData) -> Result<R, ClientError>,
              G: FnOnce(Result<R, ClientError>) -> Response
    {
        self.with_mdata(name, msg_id, log_label, delay_ms, |data, _| f(data), g)
    }

    fn mutate_mdata<F, G, R>(&self,
                             name: XorName,
                             msg_id: MessageId,
                             log_label: &str,
                             delay_ms: u64,
                             f: F,
                             g: G)
                             -> Result<(), InterfaceError>
        where F: FnOnce(&mut MutableData) -> Result<R, ClientError>,
              G: FnOnce(Result<R, ClientError>) -> Response
    {
        let mutate = |mut data: MutableData, storage: &mut Storage| {
            f(&mut data).and_then(|r| {
                storage.put_data(name, Data::Mutable(data))
                    .map(|_| {
                        storage.sync();
                        r
                    })
                    .map_err(ClientError::from)
            })
        };

        self.with_mdata(name, msg_id, log_label, delay_ms, mutate, g)
    }

    fn with_mdata<F, G, R>(&self,
                           name: XorName,
                           msg_id: MessageId,
                           log_label: &str,
                           delay_ms: u64,
                           f: F,
                           g: G)
                           -> Result<(), InterfaceError>
        where F: FnOnce(MutableData, &mut Storage) -> Result<R, ClientError>,
              G: FnOnce(Result<R, ClientError>) -> Response
    {
        if self.timeout_simulation {
            return Ok(());
        }

        // TODO: permission verification

        let res = if let Err(err) = self.verify_network_limits(msg_id, log_label) {
            Err(err)
        } else {
            let mut storage = unwrap!(STORAGE.lock());
            match storage.get_data(&name) {
                Ok(Data::Mutable(data)) => f(data, &mut *storage),
                _ => Err(ClientError::NoSuchData),
            }
        };

        let nae_auth = Authority::NaeManager(name);
        self.send_response(delay_ms, nae_auth, self.client_auth, g(res));
        Ok(())
    }

    #[cfg(test)]
    pub fn set_network_limits(&mut self, max_ops_count: Option<u64>) {
        self.max_ops_countdown = max_ops_count.map(Cell::new)
    }

    #[cfg(test)]
    pub fn simulate_disconnect(&self) {
        let sender = self.sender.clone();
        let _ = std::thread::spawn(move || unwrap!(sender.send(Event::RestartRequired)));
    }

    #[cfg(test)]
    pub fn set_simulate_timeout(&mut self, enable: bool) {
        self.timeout_simulation = enable;
    }

    fn verify_network_limits(&self, msg_id: MessageId, op: &str) -> Result<(), ClientError> {
        let client_name = self.client_name();

        if self.network_limits_reached() {
            info!("Mock {}: {:?} {:?} [0]", op, client_name, msg_id);
            Err(ClientError::NetworkOther("Max operations exhausted".to_string()))
        } else {
            if let Some(count) = self.update_network_limits() {
                info!("Mock {}: {:?} {:?} [{}]", op, client_name, msg_id, count);
            }

            Ok(())
        }
    }

    fn network_limits_reached(&self) -> bool {
        self.max_ops_countdown.as_ref().map_or(false, |count| count.get() == 0)
    }

    fn update_network_limits(&self) -> Option<u64> {
        self.max_ops_countdown.as_ref().map(|count| {
            let ops = count.get();
            count.set(ops - 1);
            ops
        })
    }
}

impl Drop for MockRouting {
    fn drop(&mut self) {
        let _ = self.sender.send(Event::Terminate);
    }
}

fn update_account_info(storage: &mut Storage, client_name: &XorName) {
    let account = storage.get_or_create_account_info(client_name);
    account.data_stored += 1;
    account.space_available -= 1;
}

#[cfg(test)]
mod tests {
    use core::utility;
    use rand;
    use routing::{AccountInfo, Authority, ClientError, Event, FullId, ImmutableData, MessageId,
                  MutableData, Response};
    use std::sync::mpsc::{self, Receiver};
    use super::*;
    use super::storage::DEFAULT_CLIENT_ACCOUNT_SIZE;

    /*
    use maidsafe_utilities::serialisation::{deserialise, serialise};
    use routing::{AppendWrapper, AppendedData, Data, DataIdentifier, Filter,
                  PubAppendableData, StructuredData,
                  XOR_NAME_LEN, XorName};
    use rust_sodium::crypto::sign;
    use std::collections::HashMap;
    use std::iter;
    */

    // Helper macro to receive a routing event and assert it's a response
    // success.
    macro_rules! expect_success {
        ($rx:expr, $msg_id:expr, $res:path) => {
            match unwrap!($rx.recv()) {
                Event::Response {
                    response: $res { res, msg_id, }, ..
                } => {
                    assert_eq!(msg_id, $msg_id);

                    match res {
                        Ok(value) => value,
                        Err(err) => panic!("Unexpected error {:?}", err),
                    }
                }
                event => panic!("Unexpected event {:?}", event),
            }
        }
    }

    // Helper macro to receive a routing event and assert it's a response
    // failure.
    macro_rules! expect_failure {
        ($rx:expr, $msg_id:expr, $res:path, $err:pat) => {
            match unwrap!($rx.recv()) {
                Event::Response {
                    response: $res { res, msg_id, }, ..
                } => {
                    assert_eq!(msg_id, $msg_id);

                    match res {
                        Ok(_) => panic!("Unexpected success"),
                        Err($err) => (),
                        Err(err) => panic!("Unexpected error {:?}", err),
                    }
                }
                event => panic!("Unexpected event {:?}", event),
            }
        }
    }

    macro_rules! btree_set {
        ($($item:expr),*) => {{
            let mut set = ::std::collections::BTreeSet::new();
            $(
                let _ = set.insert($item);
            )*
            set
        }}
    }

    #[test]
    fn immutable_data_basics() {
        let (mut routing, routing_rx, _) = setup();

        // Construct ImmutableData
        let orig_data = ImmutableData::new(unwrap!(utility::generate_random_vector(100)));
        let nae_mgr = Authority::NaeManager(*orig_data.name());
        let client_mgr = Authority::ClientManager(*orig_data.name());

        // GetIData should fail
        let msg_id = MessageId::new();
        unwrap!(routing.get_idata(nae_mgr.clone(), *orig_data.name(), msg_id));
        expect_failure!(routing_rx,
                        msg_id,
                        Response::GetIData,
                        ClientError::NoSuchData);

        // First PutIData should succeed
        let msg_id = MessageId::new();
        unwrap!(routing.put_idata(client_mgr.clone(), orig_data.clone(), msg_id));
        expect_success!(routing_rx, msg_id, Response::PutIData);

        // Now GetIData should pass
        let msg_id = MessageId::new();
        unwrap!(routing.get_idata(nae_mgr.clone(), *orig_data.name(), msg_id));
        let got_data = expect_success!(routing_rx, msg_id, Response::GetIData);
        assert_eq!(got_data, orig_data);

        // GetAccountInfo should pass and show one chunk stored
        let account_info = do_get_account_info(&mut routing, &routing_rx, client_mgr);
        assert_eq!(account_info.data_stored, 1);
        assert_eq!(account_info.space_available,
                   DEFAULT_CLIENT_ACCOUNT_SIZE - 1);

        // Subsequent PutIData for same data should succeed - De-duplication
        let msg_id = MessageId::new();
        unwrap!(routing.put_idata(client_mgr.clone(), orig_data.clone(), msg_id));
        expect_success!(routing_rx, msg_id, Response::PutIData);

        // GetIData should succeed
        let msg_id = MessageId::new();
        unwrap!(routing.get_idata(nae_mgr.clone(), *orig_data.name(), msg_id));
        let got_data = expect_success!(routing_rx, msg_id, Response::GetIData);
        assert_eq!(got_data, orig_data);


        // GetAccountInfo should pass and show two chunks stored
        let account_info = do_get_account_info(&mut routing, &routing_rx, client_mgr);
        assert_eq!(account_info.data_stored, 2);
        assert_eq!(account_info.space_available,
                   DEFAULT_CLIENT_ACCOUNT_SIZE - 2);
    }

    /*
    #[test]
    fn mutable_data_basics() {
        let (mut routing, routing_rx, full_id) = setup();

        // Construct MutableData
        let name = rand::random();
        let tag = 1000u64;
        let owner_key = *full_id.public_id().signing_public_key();

        let data = unwrap!(MutableData::new(name,
                                            tag,
                                            Default::default(),
                                            Default::default(),
                                            btree_set!(owner_key)));
    }
    */

    fn setup() -> (MockRouting, Receiver<Event>, FullId) {
        let full_id = FullId::new();
        let (routing_tx, routing_rx) = mpsc::channel();
        let mut routing = unwrap!(MockRouting::new(routing_tx, Some(full_id.clone())));

        // Wait until connection is established.
        match unwrap!(routing_rx.recv()) {
            Event::Connected => (),
            e => panic!("Unexpected event {:?}", e),
        }

        (routing, routing_rx, full_id)
    }

    fn do_get_account_info(routing: &mut MockRouting,
                           routing_rx: &Receiver<Event>,
                           client_mgr: Authority)
                           -> AccountInfo {
        let msg_id = MessageId::new();
        unwrap!(routing.get_account_info(client_mgr, msg_id));
        expect_success!(routing_rx, msg_id, Response::GetAccountInfo)
    }
}
