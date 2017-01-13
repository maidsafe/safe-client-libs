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

use ipc::BootstrapConfig;
use maidsafe_utilities::thread;
use rand;
use routing::{Authority, ClientError, EntryAction, Event, FullId, ImmutableData, InterfaceError,
              MessageId, MutableData, PermissionSet, Response, RoutingError,
              TYPE_TAG_SESSION_PACKET, User, XorName};
use rust_sodium::crypto::hash::sha256;
use rust_sodium::crypto::sign;
use std;
use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;
use std::sync::mpsc::Sender;
use std::time::Duration;
use super::vault::{Data, Vault};

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

const LIST_AUTH_KEYS_AND_VERSION_DELAY_MS: u64 = DEFAULT_DELAY_MS;
const INS_AUTH_KEY_DELAY_MS: u64 = DEFAULT_DELAY_MS;
const DEL_AUTH_KEY_DELAY_MS: u64 = DEFAULT_DELAY_MS;

lazy_static! {
    static ref VAULT: Mutex<Vault> = Mutex::new(Vault::new());
}

pub struct Routing {
    sender: Sender<Event>,
    full_id: FullId,
    client_auth: Authority,
    max_ops_countdown: Option<Cell<u64>>,
    timeout_simulation: bool,
}

impl Routing {
    pub fn new(sender: Sender<Event>,
               id: Option<FullId>,
               _config: Option<BootstrapConfig>)
               -> Result<Self, RoutingError> {
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

        Ok(Routing {
            sender: sender,
            full_id: id.unwrap_or_else(FullId::new),
            client_auth: client_auth,
            max_ops_countdown: None,
            timeout_simulation: false,
        })
    }

    /// Gets MAID account information.
    pub fn get_account_info(&self,
                            dst: Authority,
                            msg_id: MessageId)
                            -> Result<(), InterfaceError> {
        if self.timeout_simulation {
            return Ok(());
        }

        let res = if let Err(err) = self.verify_network_limits(msg_id, "get_account_info") {
            Err(err)
        } else {
            let name = match dst {
                Authority::ClientManager(name) => name,
                x => panic!("Unexpected authority: {:?}", x),
            };

            let vault = unwrap!(VAULT.lock());
            match vault.get_account(&name) {
                Some(account) => Ok(*account.account_info()),
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
    pub fn put_idata(&self,
                     dst: Authority,
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
            self.authorise_mutation(&dst);

            let mut vault = unwrap!(VAULT.lock());
            match vault.get_data(data.name()) {
                // Immutable data is de-duplicated so always allowed
                Some(Data::Immutable(_)) => Ok(()),
                Some(_) => Err(ClientError::DataExists),
                None => {
                    vault.insert_data(data_name, Data::Immutable(data));
                    Ok(())
                }
            }
        };

        if res.is_ok() {
            self.commit_mutation(&dst);
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
    pub fn get_idata(&self,
                     dst: Authority,
                     name: XorName,
                     msg_id: MessageId)
                     -> Result<(), InterfaceError> {
        if self.timeout_simulation {
            return Ok(());
        }

        let res = if let Err(err) = self.verify_network_limits(msg_id, "get_idata") {
            Err(err)
        } else {
            self.authorise_read(&dst, &name);

            let vault = unwrap!(VAULT.lock());
            match vault.get_data(&name) {
                Some(Data::Immutable(data)) => Ok(data),
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
    pub fn put_mdata(&self,
                     dst: Authority,
                     data: MutableData,
                     msg_id: MessageId,
                     _requester: sign::PublicKey)
                     -> Result<(), InterfaceError> {
        if self.timeout_simulation {
            return Ok(());
        }

        let data_name = *data.name();

        let res = if let Err(err) = self.verify_network_limits(msg_id, "put_mdata") {
            Err(err)
        } else if data.tag() == TYPE_TAG_SESSION_PACKET {
            // Put Account.
            let dst_name = match dst {
                Authority::ClientManager(name) => name,
                x => panic!("Unexpected authority: {:?}", x),
            };

            let mut vault = unwrap!(VAULT.lock());
            if vault.contains_data(&data_name) {
                Err(ClientError::AccountExists)
            } else {
                vault.insert_account(dst_name);
                vault.insert_data(data_name, Data::Mutable(data));
                vault.sync();
                Ok(())
            }
        } else {
            // Put normal data.
            self.authorise_mutation(&dst);

            let res = if let Err(err) = self.verify_owner(&dst, data.owners()) {
                Err(err)
            } else {
                let mut vault = unwrap!(VAULT.lock());

                if vault.contains_data(&data_name) {
                    Err(ClientError::DataExists)
                } else {
                    vault.insert_data(data_name, Data::Mutable(data));
                    Ok(())
                }
            };

            if res.is_ok() {
                self.commit_mutation(&dst);
            }

            res
        };

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
    pub fn get_mdata_version(&self,
                             dst: Authority,
                             name: XorName,
                             tag: u64,
                             msg_id: MessageId)
                             -> Result<(), InterfaceError> {
        self.read_mdata(dst,
                        name,
                        tag,
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
    pub fn list_mdata_entries(&self,
                              dst: Authority,
                              name: XorName,
                              tag: u64,
                              msg_id: MessageId)
                              -> Result<(), InterfaceError> {
        self.read_mdata(dst,
                        name,
                        tag,
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
    pub fn list_mdata_keys(&self,
                           dst: Authority,
                           name: XorName,
                           tag: u64,
                           msg_id: MessageId)
                           -> Result<(), InterfaceError> {
        self.read_mdata(dst,
                        name,
                        tag,
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
    pub fn list_mdata_values(&self,
                             dst: Authority,
                             name: XorName,
                             tag: u64,
                             msg_id: MessageId)
                             -> Result<(), InterfaceError> {
        self.read_mdata(dst,
                        name,
                        tag,
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
    pub fn get_mdata_value(&self,
                           dst: Authority,
                           name: XorName,
                           tag: u64,
                           key: Vec<u8>,
                           msg_id: MessageId)
                           -> Result<(), InterfaceError> {
        self.read_mdata(dst,
                        name,
                        tag,
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
    pub fn mutate_mdata_entries(&self,
                                dst: Authority,
                                name: XorName,
                                tag: u64,
                                actions: BTreeMap<Vec<u8>, EntryAction>,
                                msg_id: MessageId,
                                requester: sign::PublicKey)
                                -> Result<(), InterfaceError> {
        self.mutate_mdata(dst,
                          name,
                          tag,
                          msg_id,
                          requester,
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
    pub fn list_mdata_permissions(&self,
                                  dst: Authority,
                                  name: XorName,
                                  tag: u64,
                                  msg_id: MessageId)
                                  -> Result<(), InterfaceError> {
        self.read_mdata(dst,
                        name,
                        tag,
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
    pub fn list_mdata_user_permissions(&self,
                                       dst: Authority,
                                       name: XorName,
                                       tag: u64,
                                       user: User,
                                       msg_id: MessageId)
                                       -> Result<(), InterfaceError> {
        self.read_mdata(dst,
                        name,
                        tag,
                        msg_id,
                        "list_mdata_user_permissions",
                        GET_MDATA_PERMISSIONS_DELAY_MS,
                        |data| data.user_permissions(&user).map(|p| *p),
                        |res| {
                            Response::ListMDataUserPermissions {
                                res: res,
                                msg_id: msg_id,
                            }
                        })
    }

    /// Updates or inserts a list of permissions for a particular User in the given
    /// MutableData.
    pub fn set_mdata_user_permissions(&self,
                                      dst: Authority,
                                      name: XorName,
                                      tag: u64,
                                      user: User,
                                      permissions: PermissionSet,
                                      version: u64,
                                      msg_id: MessageId,
                                      requester: sign::PublicKey)
                                      -> Result<(), InterfaceError> {
        self.mutate_mdata(dst,
                          name,
                          tag,
                          msg_id,
                          requester,
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
    pub fn del_mdata_user_permissions(&self,
                                      dst: Authority,
                                      name: XorName,
                                      tag: u64,
                                      user: User,
                                      version: u64,
                                      msg_id: MessageId,
                                      requester: sign::PublicKey)
                                      -> Result<(), InterfaceError> {
        self.mutate_mdata(dst,
                          name,
                          tag,
                          msg_id,
                          requester,
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
    pub fn change_mdata_owner(&self,
                              dst: Authority,
                              name: XorName,
                              tag: u64,
                              new_owner: sign::PublicKey,
                              version: u64,
                              msg_id: MessageId,
                              requester: sign::PublicKey)
                              -> Result<(), InterfaceError> {
        let sign_pk = *self.full_id.public_id().signing_public_key();

        self.mutate_mdata(dst,
                          name,
                          tag,
                          msg_id,
                          requester,
                          "change_mdata_owner",
                          CHANGE_MDATA_OWNER_DELAY_MS,
                          |data| data.change_owner(new_owner, version, sign_pk),
                          |res| {
                              Response::ChangeMDataOwner {
                                  res: res,
                                  msg_id: msg_id,
                              }
                          })
    }

    /// Fetches a list of authorised keys and version in MaidManager
    pub fn list_auth_keys_and_version(&self,
                                      dst: Authority,
                                      msg_id: MessageId)
                                      -> Result<(), InterfaceError> {
        if self.timeout_simulation {
            return Ok(());
        }

        let res = if let Err(err) =
            self.verify_network_limits(msg_id, "list_auth_keys_and_version") {
            Err(err)
        } else {
            let name = match dst {
                Authority::ClientManager(name) => name,
                x => panic!("Unexpected authority: {:?}", x),
            };

            let vault = unwrap!(VAULT.lock());
            if let Some(account) = vault.get_account(&name) {
                Ok((account.auth_keys().clone(), account.version()))
            } else {
                Err(ClientError::NoSuchAccount)
            }
        };

        self.send_response(LIST_AUTH_KEYS_AND_VERSION_DELAY_MS,
                           dst,
                           self.client_auth,
                           Response::ListAuthKeysAndVersion {
                               res: res,
                               msg_id: msg_id,
                           });
        Ok(())
    }

    /// Adds a new authorised key to MaidManager
    pub fn ins_auth_key(&self,
                        dst: Authority,
                        key: sign::PublicKey,
                        version: u64,
                        msg_id: MessageId)
                        -> Result<(), InterfaceError> {
        if self.timeout_simulation {
            return Ok(());
        }

        let res = if let Err(err) = self.verify_network_limits(msg_id, "ins_auth_key") {
            Err(err)
        } else {
            let name = match dst {
                Authority::ClientManager(name) => name,
                x => panic!("Unexpected authority: {:?}", x),
            };

            let mut vault = unwrap!(VAULT.lock());
            let res = if let Some(account) = vault.get_account_mut(&name) {
                account.ins_auth_key(key, version)
            } else {
                Err(ClientError::NoSuchAccount)
            };

            if res.is_ok() {
                vault.sync();
            }

            res
        };


        self.send_response(INS_AUTH_KEY_DELAY_MS,
                           dst,
                           self.client_auth,
                           Response::InsAuthKey {
                               res: res,
                               msg_id: msg_id,
                           });
        Ok(())
    }

    /// Removes an authorised key from MaidManager
    pub fn del_auth_key(&self,
                        dst: Authority,
                        key: sign::PublicKey,
                        version: u64,
                        msg_id: MessageId)
                        -> Result<(), InterfaceError> {
        if self.timeout_simulation {
            return Ok(());
        }

        let res = if let Err(err) = self.verify_network_limits(msg_id, "del_auth_key") {
            Err(err)
        } else {
            let name = match dst {
                Authority::ClientManager(name) => name,
                x => panic!("Unexpected authority: {:?}", x),
            };

            let mut vault = unwrap!(VAULT.lock());
            let res = if let Some(account) = vault.get_account_mut(&name) {
                account.del_auth_key(&key, version)
            } else {
                Err(ClientError::NoSuchAccount)
            };

            if res.is_ok() {
                vault.sync();
            }

            res
        };

        self.send_response(DEL_AUTH_KEY_DELAY_MS,
                           dst,
                           self.client_auth,
                           Response::DelAuthKey {
                               res: res,
                               msg_id: msg_id,
                           });
        Ok(())
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
                           dst: Authority,
                           name: XorName,
                           tag: u64,
                           msg_id: MessageId,
                           log_label: &str,
                           delay_ms: u64,
                           f: F,
                           g: G)
                           -> Result<(), InterfaceError>
        where F: FnOnce(MutableData) -> Result<R, ClientError>,
              G: FnOnce(Result<R, ClientError>) -> Response
    {
        self.authorise_read(&dst, &name);
        self.with_mdata(name,
                        tag,
                        msg_id,
                        None,
                        log_label,
                        delay_ms,
                        |data, _| f(data),
                        g)
    }

    fn mutate_mdata<F, G, R>(&self,
                             dst: Authority,
                             name: XorName,
                             tag: u64,
                             msg_id: MessageId,
                             requester: sign::PublicKey,
                             log_label: &str,
                             delay_ms: u64,
                             f: F,
                             g: G)
                             -> Result<(), InterfaceError>
        where F: FnOnce(&mut MutableData) -> Result<R, ClientError>,
              G: FnOnce(Result<R, ClientError>) -> Response
    {
        let mutate = |mut data: MutableData, vault: &mut Vault| {
            let output = f(&mut data)?;
            vault.insert_data(name, Data::Mutable(data));
            vault.sync();
            Ok(output)
        };

        self.authorise_mutation(&dst);
        self.with_mdata(name,
                        tag,
                        msg_id,
                        Some(requester),
                        log_label,
                        delay_ms,
                        mutate,
                        g)?;
        self.commit_mutation(&dst);
        Ok(())
    }

    fn with_mdata<F, G, R>(&self,
                           name: XorName,
                           tag: u64,
                           msg_id: MessageId,
                           requester: Option<sign::PublicKey>,
                           log_label: &str,
                           delay_ms: u64,
                           f: F,
                           g: G)
                           -> Result<(), InterfaceError>
        where F: FnOnce(MutableData, &mut Vault) -> Result<R, ClientError>,
              G: FnOnce(Result<R, ClientError>) -> Response
    {
        if self.timeout_simulation {
            return Ok(());
        }

        let res = if let Err(err) = self.verify_network_limits(msg_id, log_label) {
            Err(err)
        } else if let Err(err) = self.verify_requester(requester) {
            Err(err)
        } else {
            let mut vault = unwrap!(VAULT.lock());
            match vault.get_data(&name) {
                Some(Data::Mutable(data)) => f(data, &mut *vault),
                _ => {
                    if tag == TYPE_TAG_SESSION_PACKET {
                        Err(ClientError::NoSuchAccount)
                    } else {
                        Err(ClientError::NoSuchData)
                    }
                }
            }
        };

        let nae_auth = Authority::NaeManager(name);
        self.send_response(delay_ms, nae_auth, self.client_auth, g(res));
        Ok(())
    }

    fn authorise_read(&self, dst: &Authority, data_name: &XorName) {
        let vault = unwrap!(VAULT.lock());
        assert!(vault.authorise_read(dst, data_name));
    }

    fn authorise_mutation(&self, dst: &Authority) {
        let vault = unwrap!(VAULT.lock());
        assert!(vault.authorise_mutation(dst, self.full_id.public_id().signing_public_key()));
    }

    fn commit_mutation(&self, dst: &Authority) {
        let mut vault = unwrap!(VAULT.lock());

        {
            let account = unwrap!(vault.get_account_mut(dst.name()));
            account.increment_mutations_counter();
        }

        vault.sync();
    }

    fn verify_owner(&self,
                    dst: &Authority,
                    owner_keys: &BTreeSet<sign::PublicKey>)
                    -> Result<(), ClientError> {
        let dst_name = match *dst {
            Authority::ClientManager(name) => name,
            _ => return Err(ClientError::InvalidOwners),
        };

        let ok = owner_keys.iter().any(|owner_key| {
            let owner_name = XorName(sha256::hash(&owner_key.0).0);
            owner_name == dst_name
        });

        if ok {
            Ok(())
        } else {
            Err(ClientError::InvalidOwners)
        }
    }

    fn verify_requester(&self, requester: Option<sign::PublicKey>) -> Result<(), ClientError> {
        let requester = match requester {
            Some(key) => key,
            None => return Ok(()),
        };

        if *self.full_id.public_id().signing_public_key() == requester {
            Ok(())
        } else {
            Err(ClientError::from("Invalid requester"))
        }
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

    pub fn bootstrap_config(&self) -> BootstrapConfig {
        BootstrapConfig::default()
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

impl Drop for Routing {
    fn drop(&mut self) {
        let _ = self.sender.send(Event::Terminate);
    }
}
