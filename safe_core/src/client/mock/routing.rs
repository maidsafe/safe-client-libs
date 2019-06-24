// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::vault::{self, Data, Vault, VaultGuard};
use super::DataId;
use crate::config_handler::{get_config, Config};
use maidsafe_utilities::serialisation::serialise;
use maidsafe_utilities::thread;
use routing::{
    Authority, BootstrapConfig, ClientError, EntryAction, Event, FullId, InterfaceError,
    MutableData, PermissionSet, Request, Response, RoutingError, User, TYPE_TAG_SESSION_PACKET,
};
#[cfg(any(feature = "testing", test))]
use safe_nd::Coins;
use safe_nd::{
    AppFullId, ClientFullId, IDataKind, ImmutableData, Message, MessageId, PublicId, PublicKey,
    Signature, XorName,
};
use std;
use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use threshold_crypto::SecretKey as BlsSecretKey;

/// Function that is used to tap into routing requests and return preconditioned responses.
pub type RequestHookFn = FnMut(&Request) -> Option<Response> + 'static;

/// Function that is used to modify responses before they are sent.
pub type ResponseHookFn = FnMut(Response) -> Response + 'static;

const CONNECT_THREAD_NAME: &str = "Mock routing connect";
const DELAY_THREAD_NAME: &str = "Mock routing delay";

const DEFAULT_DELAY_MS: u64 = 0;
const CONNECT_DELAY_MS: u64 = DEFAULT_DELAY_MS;

const GET_ACCOUNT_INFO_DELAY_MS: u64 = DEFAULT_DELAY_MS;
const PUT_IDATA_DELAY_MS: u64 = DEFAULT_DELAY_MS;
const GET_IDATA_DELAY_MS: u64 = DEFAULT_DELAY_MS;

const PUT_MDATA_DELAY_MS: u64 = DEFAULT_DELAY_MS;
const GET_MDATA_VERSION_DELAY_MS: u64 = DEFAULT_DELAY_MS;
const GET_MDATA_SHELL_DELAY_MS: u64 = DEFAULT_DELAY_MS;
const GET_MDATA_DELAY_MS: u64 = DEFAULT_DELAY_MS;
const GET_MDATA_ENTRIES_DELAY_MS: u64 = DEFAULT_DELAY_MS;
const SET_MDATA_ENTRIES_DELAY_MS: u64 = DEFAULT_DELAY_MS;
const GET_MDATA_PERMISSIONS_DELAY_MS: u64 = DEFAULT_DELAY_MS;
const SET_MDATA_PERMISSIONS_DELAY_MS: u64 = DEFAULT_DELAY_MS;
const CHANGE_MDATA_OWNER_DELAY_MS: u64 = DEFAULT_DELAY_MS;

lazy_static! {
    static ref VAULT: Arc<Mutex<Vault>> = Arc::new(Mutex::new(Vault::new(get_config())));
}

/// Creates a thread-safe reference-counted pointer to the global vault.
pub fn clone_vault() -> Arc<Mutex<Vault>> {
    VAULT.clone()
}

pub fn unlimited_muts(config: &Config) -> bool {
    match env::var("SAFE_MOCK_UNLIMITED_MUTATIONS") {
        Ok(_) => true,
        Err(_) => match config.dev {
            Some(ref dev) => dev.mock_unlimited_mutations,
            None => false,
        },
    }
}

/// Mock routing implementation that mirrors the behaviour
/// of the real network but is not connected to it
pub struct Routing {
    vault: Arc<Mutex<Vault>>,
    sender: Sender<Event>,
    /// mock_routing::FullId for old types
    pub full_id: FullId,
    /// NewFullId for new types
    pub full_id_new: NewFullId,
    client_auth: Authority<XorName>,
    max_ops_countdown: Option<Cell<u64>>,
    timeout_simulation: bool,
    request_hook: Option<Box<RequestHookFn>>,
    response_hook: Option<Box<ResponseHookFn>>,
}

/// An enum representing the Full Id variants for a Client or App
pub enum NewFullId {
    /// Represents an application authorised by a client.
    App(AppFullId),
    /// Represents a network client.
    Client(ClientFullId),
}

impl NewFullId {
    /// Signs a given message using the App / Client full id as required
    pub fn sign(&self, msg: &[u8]) -> Signature {
        match self {
            NewFullId::App(app_full_id) => app_full_id.sign(msg),
            NewFullId::Client(client_full_id) => client_full_id.sign(msg),
        }
    }
}

impl Routing {
    /// Initialises mock routing.
    /// The function signature mirrors `routing::Client`.
    pub fn new(
        sender: Sender<Event>,
        id: Option<FullId>,
        full_id: Option<NewFullId>,
        _bootstrap_config: Option<BootstrapConfig>,
        _msg_expiry_dur: Duration,
    ) -> Result<Self, RoutingError> {
        let _ = ::rust_sodium::init();

        let cloned_sender = sender.clone();
        let _ = thread::named(CONNECT_THREAD_NAME, move || {
            std::thread::sleep(Duration::from_millis(CONNECT_DELAY_MS));
            let _ = cloned_sender.send(Event::Connected);
        });

        let client_auth = Authority::Client {
            client_id: *FullId::new().public_id(),
            proxy_node_name: new_rand::random(),
        };

        let bls_sk = id
            .as_ref()
            .map(|id| id.bls_key().clone())
            .unwrap_or_else(BlsSecretKey::random);

        Ok(Routing {
            vault: clone_vault(),
            sender,
            full_id: id.unwrap_or_else(FullId::new),
            full_id_new: full_id
                .unwrap_or_else(|| NewFullId::Client(ClientFullId::with_bls_key(bls_sk))),
            client_auth,
            max_ops_countdown: None,
            timeout_simulation: false,
            request_hook: None,
            response_hook: None,
        })
    }

    /// Send a routing message
    pub fn send(&mut self, dst: Authority<XorName>, payload: &[u8]) -> Result<(), InterfaceError> {
        let msg: Message = {
            let mut vault = self.lock_vault(true);
            let public_id = match &self.full_id_new {
                NewFullId::Client(full_id) => PublicId::Client(full_id.public_id().clone()),
                NewFullId::App(full_id) => PublicId::App(full_id.public_id().clone()),
            };
            unwrap!(vault.process_request(public_id, payload.to_vec()))
        };
        // Send response back to a client
        let (message_id, response) = if let Message::Response {
            message_id,
            response,
        } = msg
        {
            (message_id, response)
        } else {
            return Err(InterfaceError::InvalidState);
        };
        let response = Response::RpcResponse {
            res: Ok(unwrap!(serialise(&response))),
            msg_id: message_id,
        };
        self.send_response(DEFAULT_DELAY_MS, self.client_auth, dst, response);

        Ok(())
    }

    /// Sets the vault for this routing instance.
    pub fn set_vault(&mut self, vault: &Arc<Mutex<Vault>>) {
        self.vault = Arc::clone(vault);
    }

    /// Gets MAID account information.
    pub fn get_account_info(
        &mut self,
        dst: Authority<XorName>,
        msg_id: MessageId,
    ) -> Result<(), InterfaceError> {
        let client_auth = self.client_auth;

        let skip = self.intercept_request(GET_ACCOUNT_INFO_DELAY_MS, dst, client_auth, || {
            Request::GetAccountInfo(msg_id)
        });
        if skip {
            return Ok(());
        }

        let res = if let Err(err) = self.verify_network_limits(msg_id, "get_account_info") {
            Err(err)
        } else {
            let name = match dst {
                Authority::ClientManager(name) => name,
                x => panic!("Unexpected authority: {:?}", x),
            };

            let vault = self.lock_vault(false);
            match vault.get_account(&name) {
                Some(account) => Ok(*account.account_info()),
                None => Err(ClientError::NoSuchAccount),
            }
        };

        self.send_response(
            GET_ACCOUNT_INFO_DELAY_MS,
            dst,
            client_auth,
            Response::GetAccountInfo { res, msg_id },
        );

        Ok(())
    }

    /// Puts ImmutableData to the network.
    pub fn put_idata(
        &mut self,
        dst: Authority<XorName>,
        data: ImmutableData,
        msg_id: MessageId,
    ) -> Result<(), InterfaceError> {
        let data_name = *data.name();
        let client_auth = self.client_auth;
        let nae_auth = Authority::NaeManager(data_name);

        let skip = self.intercept_request(PUT_IDATA_DELAY_MS, nae_auth, client_auth, || {
            Request::PutIData {
                data: data.clone(),
                msg_id,
            }
        });
        if skip {
            return Ok(());
        }

        let res = {
            let mut vault = self.lock_vault(true);

            self.verify_network_limits(msg_id, "put_idata")
                .and_then(|_| vault.authorise_mutation(&dst, &self.client_key()))
                .and_then(|_| {
                    match vault.get_data(&DataId::immutable(*data.name(), true)) {
                        // Immutable data is de-duplicated so always allowed
                        Some(Data::Immutable(_)) => Ok(()),
                        Some(_) => Err(ClientError::DataExists),
                        None => {
                            vault.insert_data(
                                DataId::immutable(data_name, true),
                                Data::Immutable(data.into()),
                            );
                            Ok(())
                        }
                    }
                })
                .map(|_| vault.commit_mutation(&dst.name()))
        };

        self.send_response(
            PUT_IDATA_DELAY_MS,
            nae_auth,
            client_auth,
            Response::PutIData { res, msg_id },
        );
        Ok(())
    }

    /// Fetches ImmutableData from the network by the given name.
    pub fn get_idata(
        &mut self,
        dst: Authority<XorName>,
        name: XorName,
        msg_id: MessageId,
    ) -> Result<(), InterfaceError> {
        let client_auth = self.client_auth;
        let nae_auth = Authority::NaeManager(name);

        let skip = self.intercept_request(GET_IDATA_DELAY_MS, nae_auth, client_auth, || {
            Request::GetIData { name, msg_id }
        });
        if skip {
            return Ok(());
        }

        let res = {
            let vault = self.lock_vault(false);

            if let Err(err) = self.verify_network_limits(msg_id, "get_idata") {
                Err(err)
            } else if let Err(err) = vault.authorise_read(&dst, &name) {
                Err(err)
            } else {
                match vault.get_data(&DataId::immutable(name, true)) {
                    Some(Data::Immutable(IDataKind::Pub(data))) => Ok(data),
                    _ => Err(ClientError::NoSuchData),
                }
            }
        };

        self.send_response(
            GET_IDATA_DELAY_MS,
            nae_auth,
            client_auth,
            Response::GetIData { res, msg_id },
        );
        Ok(())
    }

    /// Creates a new MutableData in the network.
    pub fn put_mdata(
        &mut self,
        dst: Authority<XorName>,
        data: MutableData,
        msg_id: MessageId,
        requester: PublicKey,
    ) -> Result<(), InterfaceError> {
        let data_name = DataId::mutable(*data.name(), data.tag());
        let client_auth = self.client_auth;
        let nae_auth = Authority::NaeManager(*data_name.name());

        let skip = self.intercept_request(PUT_MDATA_DELAY_MS, nae_auth, client_auth, || {
            Request::PutMData {
                data: data.clone(),
                msg_id,
                requester,
            }
        });
        if skip {
            return Ok(());
        }

        let res = {
            let mut vault = self.lock_vault(true);

            if let Err(err) = self.verify_network_limits(msg_id, "put_mdata") {
                Err(err)
            } else if data.tag() == TYPE_TAG_SESSION_PACKET {
                // Put Account.
                let dst_name = match dst {
                    Authority::ClientManager(name) => name,
                    x => panic!("Unexpected authority: {:?}", x),
                };

                if vault.contains_data(&data_name) {
                    Err(ClientError::AccountExists)
                } else {
                    vault.insert_account(dst_name);
                    vault.insert_data(data_name, Data::OldMutable(data));
                    Ok(())
                }
            } else {
                // Put normal data.
                vault
                    .authorise_mutation(&dst, &self.client_key())
                    .and_then(|_| Self::verify_owner(&dst, data.owners()))
                    .and_then(|_| {
                        if vault.contains_data(&data_name) {
                            Err(ClientError::DataExists)
                        } else {
                            vault.insert_data(data_name, Data::OldMutable(data));
                            Ok(())
                        }
                    })
                    .map(|_| vault.commit_mutation(&dst.name()))
            }
        };

        self.send_response(
            PUT_MDATA_DELAY_MS,
            nae_auth,
            client_auth,
            Response::PutMData { res, msg_id },
        );
        Ok(())
    }

    /// Fetches a latest version number.
    pub fn get_mdata_version(
        &mut self,
        dst: Authority<XorName>,
        name: XorName,
        tag: u64,
        msg_id: MessageId,
    ) -> Result<(), InterfaceError> {
        self.read_mdata(
            dst,
            name,
            tag,
            Request::GetMDataVersion { name, tag, msg_id },
            "get_mdata_version",
            GET_MDATA_VERSION_DELAY_MS,
            |data| Ok(data.version()),
            |res| Response::GetMDataVersion { res, msg_id },
        )
    }

    /// Fetches a complete MutableData object.
    pub fn get_mdata(
        &mut self,
        dst: Authority<XorName>,
        name: XorName,
        tag: u64,
        msg_id: MessageId,
    ) -> Result<(), InterfaceError> {
        self.read_mdata(
            dst,
            name,
            tag,
            Request::GetMData { name, tag, msg_id },
            "get_mdata",
            GET_MDATA_DELAY_MS,
            Ok,
            |res| Response::GetMData { res, msg_id },
        )
    }

    /// Fetches a shell of given MutableData.
    pub fn get_mdata_shell(
        &mut self,
        dst: Authority<XorName>,
        name: XorName,
        tag: u64,
        msg_id: MessageId,
    ) -> Result<(), InterfaceError> {
        self.read_mdata(
            dst,
            name,
            tag,
            Request::GetMDataShell { name, tag, msg_id },
            "get_mdata_shell",
            GET_MDATA_SHELL_DELAY_MS,
            |data| Ok(data.shell()),
            |res| Response::GetMDataShell { res, msg_id },
        )
    }

    /// Fetches a list of entries (keys + values).
    pub fn list_mdata_entries(
        &mut self,
        dst: Authority<XorName>,
        name: XorName,
        tag: u64,
        msg_id: MessageId,
    ) -> Result<(), InterfaceError> {
        self.read_mdata(
            dst,
            name,
            tag,
            Request::ListMDataEntries { name, tag, msg_id },
            "list_mdata_entries",
            GET_MDATA_ENTRIES_DELAY_MS,
            |data| Ok(data.entries().clone()),
            |res| Response::ListMDataEntries { res, msg_id },
        )
    }

    /// Fetches a list of keys in MutableData.
    pub fn list_mdata_keys(
        &mut self,
        dst: Authority<XorName>,
        name: XorName,
        tag: u64,
        msg_id: MessageId,
    ) -> Result<(), InterfaceError> {
        self.read_mdata(
            dst,
            name,
            tag,
            Request::ListMDataKeys { name, tag, msg_id },
            "list_mdata_keys",
            GET_MDATA_ENTRIES_DELAY_MS,
            |data| {
                let keys = data.keys().into_iter().cloned().collect();
                Ok(keys)
            },
            |res| Response::ListMDataKeys { res, msg_id },
        )
    }

    /// Fetches a list of values in MutableData.
    pub fn list_mdata_values(
        &mut self,
        dst: Authority<XorName>,
        name: XorName,
        tag: u64,
        msg_id: MessageId,
    ) -> Result<(), InterfaceError> {
        self.read_mdata(
            dst,
            name,
            tag,
            Request::ListMDataValues { name, tag, msg_id },
            "list_mdata_values",
            GET_MDATA_ENTRIES_DELAY_MS,
            |data| {
                let values = data.values().into_iter().cloned().collect();
                Ok(values)
            },
            |res| Response::ListMDataValues { res, msg_id },
        )
    }

    /// Fetches a single value from MutableData
    pub fn get_mdata_value(
        &mut self,
        dst: Authority<XorName>,
        name: XorName,
        tag: u64,
        key: Vec<u8>,
        msg_id: MessageId,
    ) -> Result<(), InterfaceError> {
        self.read_mdata(
            dst,
            name,
            tag,
            Request::GetMDataValue {
                name,
                tag,
                key: key.clone(),
                msg_id,
            },
            "get_mdata_value",
            GET_MDATA_ENTRIES_DELAY_MS,
            |data| data.get(&key).cloned().ok_or(ClientError::NoSuchEntry),
            |res| Response::GetMDataValue { res, msg_id },
        )
    }

    /// Updates MutableData entries in bulk.
    pub fn mutate_mdata_entries(
        &mut self,
        dst: Authority<XorName>,
        name: XorName,
        tag: u64,
        actions: BTreeMap<Vec<u8>, EntryAction>,
        msg_id: MessageId,
        requester: PublicKey,
    ) -> Result<(), InterfaceError> {
        let actions2 = actions.clone();

        self.mutate_mdata(
            dst,
            name,
            tag,
            Request::MutateMDataEntries {
                name,
                tag,
                msg_id,
                actions,
                requester,
            },
            requester,
            "mutate_mdata_entries",
            SET_MDATA_ENTRIES_DELAY_MS,
            |data| data.mutate_entries(actions2, requester),
            |res| Response::MutateMDataEntries { res, msg_id },
        )
    }

    /// Fetches a complete list of permissions.
    pub fn list_mdata_permissions(
        &mut self,
        dst: Authority<XorName>,
        name: XorName,
        tag: u64,
        msg_id: MessageId,
    ) -> Result<(), InterfaceError> {
        self.read_mdata(
            dst,
            name,
            tag,
            Request::ListMDataPermissions { name, tag, msg_id },
            "list_mdata_permissions",
            GET_MDATA_PERMISSIONS_DELAY_MS,
            |data| Ok(data.permissions().clone()),
            |res| Response::ListMDataPermissions { res, msg_id },
        )
    }

    /// Fetches a list of permissions for a particular User.
    pub fn list_mdata_user_permissions(
        &mut self,
        dst: Authority<XorName>,
        name: XorName,
        tag: u64,
        user: User,
        msg_id: MessageId,
    ) -> Result<(), InterfaceError> {
        self.read_mdata(
            dst,
            name,
            tag,
            Request::ListMDataUserPermissions {
                name,
                tag,
                user,
                msg_id,
            },
            "list_mdata_user_permissions",
            GET_MDATA_PERMISSIONS_DELAY_MS,
            |data| data.user_permissions(&user).map(|p| *p),
            |res| Response::ListMDataUserPermissions { res, msg_id },
        )
    }

    /// Updates or inserts a list of permissions for a particular User in the given
    /// MutableData.
    pub fn set_mdata_user_permissions(
        &mut self,
        dst: Authority<XorName>,
        name: XorName,
        tag: u64,
        user: User,
        permissions: PermissionSet,
        version: u64,
        msg_id: MessageId,
        requester: PublicKey,
    ) -> Result<(), InterfaceError> {
        self.mutate_mdata(
            dst,
            name,
            tag,
            Request::SetMDataUserPermissions {
                name,
                tag,
                user,
                permissions,
                version,
                msg_id,
                requester,
            },
            requester,
            "set_mdata_user_permissions",
            SET_MDATA_PERMISSIONS_DELAY_MS,
            |data| data.set_user_permissions(user, permissions, version, requester),
            |res| Response::SetMDataUserPermissions { res, msg_id },
        )
    }

    /// Deletes a list of permissions for a particular User in the given MutableData.
    pub fn del_mdata_user_permissions(
        &mut self,
        dst: Authority<XorName>,
        name: XorName,
        tag: u64,
        user: User,
        version: u64,
        msg_id: MessageId,
        requester: PublicKey,
    ) -> Result<(), InterfaceError> {
        self.mutate_mdata(
            dst,
            name,
            tag,
            Request::DelMDataUserPermissions {
                name,
                tag,
                user,
                version,
                msg_id,
                requester,
            },
            requester,
            "del_mdata_user_permissions",
            SET_MDATA_PERMISSIONS_DELAY_MS,
            |data| data.del_user_permissions(&user, version, requester),
            |res| Response::DelMDataUserPermissions { res, msg_id },
        )
    }

    /// Changes an owner of the given MutableData. Only the current owner can perform this action.
    pub fn change_mdata_owner(
        &mut self,
        dst: Authority<XorName>,
        name: XorName,
        tag: u64,
        new_owners: BTreeSet<PublicKey>,
        version: u64,
        msg_id: MessageId,
    ) -> Result<(), InterfaceError> {
        let new_owners_len = new_owners.len();
        let new_owner = match new_owners.into_iter().next() {
            Some(ref owner) if new_owners_len == 1 => *owner,
            Some(_) | None => {
                // `new_owners` must have exactly 1 element.
                let client_auth = self.client_auth;
                self.send_response(
                    CHANGE_MDATA_OWNER_DELAY_MS,
                    dst,
                    client_auth,
                    Response::ChangeMDataOwner {
                        res: Err(ClientError::InvalidOwners),
                        msg_id,
                    },
                );
                return Ok(());
            }
        };

        let requester = self.client_key();
        let requester_name = XorName::from(requester);

        self.mutate_mdata(
            dst,
            name,
            tag,
            Request::ChangeMDataOwner {
                name,
                tag,
                new_owners: btree_set![new_owner],
                version,
                msg_id,
            },
            requester,
            "change_mdata_owner",
            CHANGE_MDATA_OWNER_DELAY_MS,
            |data| {
                let dst_name = match dst {
                    Authority::ClientManager(name) => name,
                    _ => return Err(ClientError::InvalidOwners),
                };

                // Only the current owner can change ownership for MD
                match Self::verify_owner(&dst, data.owners()) {
                    Err(ClientError::InvalidOwners) => return Err(ClientError::AccessDenied),
                    Err(e) => return Err(e),
                    Ok(_) => (),
                }

                if requester_name != dst_name {
                    Err(ClientError::AccessDenied)
                } else {
                    data.change_owner(new_owner, version)
                }
            },
            |res| Response::ChangeMDataOwner { res, msg_id },
        )
    }

    fn send_response(
        &mut self,
        delay_ms: u64,
        src: Authority<XorName>,
        dst: Authority<XorName>,
        mut response: Response,
    ) {
        if let Some(ref mut hook) = self.response_hook {
            response = hook(response);
        }

        let event = Event::Response { response, src, dst };

        self.send_event(delay_ms, event)
    }

    fn send_event(&self, delay_ms: u64, event: Event) {
        if delay_ms > 0 {
            let sender = self.sender.clone();
            let _ = thread::named(DELAY_THREAD_NAME, move || {
                std::thread::sleep(Duration::from_millis(delay_ms));
                if let Err(err) = sender.send(event) {
                    error!("mpsc-send failure: {:?}", err);
                }
            });
        } else if let Err(err) = self.sender.send(event) {
            error!("mpsc-send failure: {:?}", err);
        }
    }

    fn client_name(&self) -> XorName {
        match self.client_auth {
            Authority::Client { ref client_id, .. } => *client_id.name(),
            _ => panic!("This authority must be Client"),
        }
    }

    fn read_mdata<F, G, R>(
        &mut self,
        dst: Authority<XorName>,
        name: XorName,
        tag: u64,
        request: Request,
        log_label: &str,
        delay_ms: u64,
        f: F,
        g: G,
    ) -> Result<(), InterfaceError>
    where
        F: FnOnce(MutableData) -> Result<R, ClientError>,
        G: FnOnce(Result<R, ClientError>) -> Response,
    {
        self.with_mdata(
            name,
            tag,
            request,
            None,
            log_label,
            delay_ms,
            false,
            |data, vault| {
                vault.authorise_read(&dst, &name)?;
                f(data)
            },
            g,
        )
    }

    fn mutate_mdata<F, G, R>(
        &mut self,
        dst: Authority<XorName>,
        name: XorName,
        tag: u64,
        request: Request,
        requester: PublicKey,
        log_label: &str,
        delay_ms: u64,
        f: F,
        g: G,
    ) -> Result<(), InterfaceError>
    where
        F: FnOnce(&mut MutableData) -> Result<R, ClientError>,
        G: FnOnce(Result<R, ClientError>) -> Response,
    {
        let client_key = self.client_key();
        let mutate = |mut data: MutableData, vault: &mut Vault| {
            vault.authorise_mutation(&dst, &client_key)?;

            let output = f(&mut data)?;
            vault.insert_data(DataId::mutable(name, tag), Data::OldMutable(data));
            vault.commit_mutation(&dst.name());

            Ok(output)
        };

        self.with_mdata(
            name,
            tag,
            request,
            Some(requester),
            log_label,
            delay_ms,
            true,
            mutate,
            g,
        )
    }

    fn with_mdata<F, G, R>(
        &mut self,
        name: XorName,
        tag: u64,
        request: Request,
        requester: Option<PublicKey>,
        log_label: &str,
        delay_ms: u64,
        write: bool,
        f: F,
        g: G,
    ) -> Result<(), InterfaceError>
    where
        F: FnOnce(MutableData, &mut Vault) -> Result<R, ClientError>,
        G: FnOnce(Result<R, ClientError>) -> Response,
    {
        let client_auth = self.client_auth;
        let nae_auth = Authority::NaeManager(name);
        let msg_id = *request.message_id();

        if self.intercept_request(delay_ms, nae_auth, client_auth, move || request) {
            return Ok(());
        }

        let res = if let Err(err) = self.verify_network_limits(msg_id, log_label) {
            Err(err)
        } else if let Err(err) = self.verify_requester(requester) {
            Err(err)
        } else {
            let mut vault = self.lock_vault(write);
            match vault.get_data(&DataId::mutable(name, tag)) {
                Some(Data::OldMutable(data)) => f(data, &mut *vault),
                _ => {
                    if tag == TYPE_TAG_SESSION_PACKET {
                        Err(ClientError::NoSuchAccount)
                    } else {
                        Err(ClientError::NoSuchData)
                    }
                }
            }
        };

        self.send_response(delay_ms, nae_auth, client_auth, g(res));
        Ok(())
    }

    fn verify_owner(
        dst: &Authority<XorName>,
        owner_keys: &BTreeSet<PublicKey>,
    ) -> Result<(), ClientError> {
        let dst_name = match *dst {
            Authority::ClientManager(name) => name,
            _ => return Err(ClientError::InvalidOwners),
        };

        let ok = owner_keys
            .iter()
            .any(|owner_key| XorName::from(*owner_key) == dst_name);

        if ok {
            Ok(())
        } else {
            Err(ClientError::InvalidOwners)
        }
    }

    fn verify_requester(&self, requester: Option<PublicKey>) -> Result<(), ClientError> {
        let requester = match requester {
            Some(key) => key,
            None => return Ok(()),
        };

        if self.client_key() == requester {
            Ok(())
        } else {
            Err(ClientError::from("Invalid requester"))
        }
    }

    fn lock_vault(&self, write: bool) -> VaultGuard {
        vault::lock(&self.vault, write)
    }

    /// Returns the default boostrap config.
    pub fn bootstrap_config() -> Result<BootstrapConfig, InterfaceError> {
        Ok(BootstrapConfig::default())
    }

    /// Returns the config settings.
    pub fn config(&self) -> Config {
        let vault = self.lock_vault(false);
        vault.config()
    }

    fn verify_network_limits(&self, msg_id: MessageId, op: &str) -> Result<(), ClientError> {
        let client_name = self.client_name();

        if self.network_limits_reached() {
            info!("Mock {}: {:?} {:?} [0]", op, client_name, msg_id);
            Err(ClientError::NetworkOther(
                "Max operations exhausted".to_string(),
            ))
        } else {
            if let Some(count) = self.update_network_limits() {
                info!("Mock {}: {:?} {:?} [{}]", op, client_name, msg_id, count);
            }

            Ok(())
        }
    }

    fn network_limits_reached(&self) -> bool {
        self.max_ops_countdown
            .as_ref()
            .map_or(false, |count| count.get() == 0)
    }

    fn update_network_limits(&self) -> Option<u64> {
        self.max_ops_countdown.as_ref().map(|count| {
            let ops = count.get();
            count.set(ops - 1);
            ops
        })
    }

    fn intercept_request<F>(
        &mut self,
        delay_ms: u64,
        src: Authority<XorName>,
        dst: Authority<XorName>,
        request: F,
    ) -> bool
    where
        F: FnOnce() -> Request,
    {
        let response = if let Some(ref mut hook) = self.request_hook {
            hook(&request())
        } else {
            None
        };

        if let Some(response) = response {
            self.send_response(delay_ms, src, dst, response);
            return true;
        }

        if self.timeout_simulation {
            return true;
        }

        false
    }

    fn client_key(&self) -> PublicKey {
        PublicKey::Bls(self.full_id.bls_key().public_key())
    }
}

#[cfg(any(feature = "testing", test))]
impl Routing {
    /// Set hook function to override response before request is processed, for test purposes.
    pub fn set_request_hook<F>(&mut self, hook: F)
    where
        F: FnMut(&Request) -> Option<Response> + 'static,
    {
        let hook: Box<RequestHookFn> = Box::new(hook);
        self.request_hook = Some(hook);
    }

    /// Set hook function to override response after request is processed, for test purposes.
    pub fn set_response_hook<F>(&mut self, hook: F)
    where
        F: FnMut(Response) -> Response + 'static,
    {
        let hook: Box<ResponseHookFn> = Box::new(hook);
        self.response_hook = Some(hook);
    }

    /// Removes hook function to override response results
    pub fn remove_request_hook(&mut self) {
        self.request_hook = None;
    }

    /// Sets a maximum number of operations
    pub fn set_network_limits(&mut self, max_ops_count: Option<u64>) {
        self.max_ops_countdown = max_ops_count.map(Cell::new)
    }

    /// Simulates network disconnect
    pub fn simulate_disconnect(&self) {
        let sender = self.sender.clone();
        let _ = std::thread::spawn(move || unwrap!(sender.send(Event::Terminate)));
    }

    /// Simulates network timeouts
    pub fn set_simulate_timeout(&mut self, enable: bool) {
        self.timeout_simulation = enable;
    }

    /// Create coin balance in the mock network arbitrarily.
    pub fn create_coin_balance(
        &self,
        coin_balance_name: &XorName,
        amount: Coins,
        owner: threshold_crypto::PublicKey,
    ) {
        let mut vault = self.lock_vault(true);
        vault.mock_create_balance(coin_balance_name, amount, owner);
    }
}

impl Drop for Routing {
    fn drop(&mut self) {
        let _ = self.sender.send(Event::Terminate);
    }
}
