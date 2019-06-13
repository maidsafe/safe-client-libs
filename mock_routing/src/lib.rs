// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use maidsafe_utilities::serialisation;
use rand::{Rand, Rng};
use rust_sodium::crypto::{box_, sign};
use safe_nd::{ImmutableData, MessageId as MsgId, PublicKey};
pub use safe_nd::{XorName, XOR_NAME_LEN};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::{
    btree_map::{BTreeMap, Entry},
    BTreeSet,
};
use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};
use std::mem;
use tiny_keccak::sha3_256;

#[allow(clippy::large_enum_variant)]
#[derive(Serialize, Copy, Deserialize, Debug, PartialEq, PartialOrd, Eq, Ord, Clone, Hash)]
pub enum Authority<N: Clone + Copy + Debug> {
    /// Manager of a Client.  XorName is the hash of the Client's `client_key`.
    ClientManager(N),
    /// Manager of a network-addressable element, i.e. the group matching this name.
    /// `XorName` is the name of the element in question.
    NaeManager(N),
    /// A Client.
    Client {
        /// The Public ID of the client.
        client_id: PublicId,
        /// The name of the single ManagedNode which the Client connects to and proxies all messages
        /// through.
        proxy_node_name: N,
    },
}

impl<N: Clone + Copy + Debug> Authority<N> {
    /// Returns the name of authority.
    pub fn name(&self) -> N {
        match *self {
            Authority::ClientManager(ref name) | Authority::NaeManager(ref name) => *name,
            Authority::Client {
                ref proxy_node_name,
                ..
            } => *proxy_node_name,
        }
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum Event {
    /// Received a request message.
    Request {
        /// The request message.
        request: Request,
        /// The source authority that sent the request.
        src: Authority<XorName>,
        /// The destination authority that receives the request.
        dst: Authority<XorName>,
    },
    /// Received a response message.
    Response {
        /// The response message.
        response: Response,
        /// The source authority that sent the response.
        src: Authority<XorName>,
        /// The destination authority that receives the response.
        dst: Authority<XorName>,
    },
    /// The client has successfully connected to a proxy node on the network.
    Connected,
    /// Startup failed - terminate.
    Terminate,
}

/// Maximum allowed size for `MutableData` (1 MiB)
pub const MAX_MUTABLE_DATA_SIZE_IN_BYTES: u64 = 1024 * 1024;

/// Maximum allowed entries in `MutableData`
pub const MAX_MUTABLE_DATA_ENTRIES: u64 = 1000;

/// Errors in operations involving Core and Vaults
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub enum ClientError {
    /// Access is denied for a given requester
    AccessDenied,
    /// SAFE Account does not exist for client
    NoSuchAccount,
    /// Attempt to take an account network name that already exists
    AccountExists,
    /// Requested data not found
    NoSuchData,
    /// Attempt to create a mutable data when data with such a name already exists
    DataExists,
    /// Attempt to create/post a data exceeds size limit
    DataTooLarge,
    /// Requested entry not found
    NoSuchEntry,
    /// Exceeded a limit on a number of entries
    TooManyEntries,
    /// Some entry actions are not valid.
    InvalidEntryActions(BTreeMap<Vec<u8>, EntryError>),
    /// Key does not exist
    NoSuchKey,
    /// The list of owner keys is invalid
    InvalidOwners,
    /// Invalid version for performing a given mutating operation. Contains the
    /// current data version.
    InvalidSuccessor(u64),
    /// Invalid Operation such as a POST on ImmutableData
    InvalidOperation,
    /// Wrong invitation token specified by the client
    InvalidInvitation,
    /// Invitation token already used
    InvitationAlreadyClaimed,
    /// Insufficient balance for performing a given mutating operation
    LowBalance,
    /// The loss of sacrificial copies indicates the network as a whole is no longer having
    /// enough space to accept further put request so have to wait for more nodes to join
    NetworkFull,
    /// Network error occurring at Vault level which has no bearing on clients, e.g. serialisation
    /// failure or database failure
    NetworkOther(String),
}

impl<T: Into<String>> From<T> for ClientError {
    fn from(err: T) -> Self {
        ClientError::NetworkOther(err.into())
    }
}

impl Display for ClientError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match *self {
            ClientError::AccessDenied => write!(f, "Access denied"),
            ClientError::NoSuchAccount => write!(f, "Account does not exist for client"),
            ClientError::AccountExists => write!(f, "Account already exists for client"),
            ClientError::NoSuchData => write!(f, "Requested data not found"),
            ClientError::DataExists => write!(f, "Data given already exists"),
            ClientError::DataTooLarge => write!(f, "Data given is too large"),
            ClientError::NoSuchEntry => write!(f, "Requested entry not found"),
            ClientError::TooManyEntries => write!(f, "Exceeded a limit on a number of entries"),
            ClientError::InvalidEntryActions(ref errors) => {
                write!(f, "Entry actions are invalid: {:?}", errors)
            }
            ClientError::NoSuchKey => write!(f, "Key does not exists"),
            ClientError::InvalidOwners => write!(f, "The list of owner keys is invalid"),
            ClientError::InvalidOperation => write!(f, "Requested operation is not allowed"),
            ClientError::InvalidInvitation => write!(f, "Invitation token not found"),
            ClientError::InvitationAlreadyClaimed => {
                write!(f, "Invitation token has already been used")
            }
            ClientError::InvalidSuccessor(_) => {
                write!(f, "Data given is not a valid successor of stored data")
            }
            ClientError::LowBalance => write!(f, "Insufficient account balance for this operation"),
            ClientError::NetworkFull => write!(f, "Network cannot store any further data"),
            ClientError::NetworkOther(ref error) => write!(f, "Error on Vault network: {}", error),
        }
    }
}

impl Error for ClientError {
    fn description(&self) -> &str {
        match *self {
            ClientError::AccessDenied => "Access denied",
            ClientError::NoSuchAccount => "No such account",
            ClientError::AccountExists => "Account exists",
            ClientError::NoSuchData => "No such data",
            ClientError::DataExists => "Data exists",
            ClientError::DataTooLarge => "Data is too large",
            ClientError::NoSuchEntry => "No such entry",
            ClientError::TooManyEntries => "Too many entries",
            ClientError::InvalidEntryActions(_) => "Invalid entry actions",
            ClientError::NoSuchKey => "No such key",
            ClientError::InvalidOwners => "Invalid owners",
            ClientError::InvalidSuccessor(_) => "Invalid data successor",
            ClientError::InvalidOperation => "Invalid operation",
            ClientError::InvalidInvitation => "Invalid invitation token",
            ClientError::InvitationAlreadyClaimed => "Invitation token already claimed",
            ClientError::LowBalance => "Low account balance",
            ClientError::NetworkFull => "Network full",
            ClientError::NetworkOther(ref error) => error,
        }
    }
}

/// Entry error for `ClientError::InvalidEntryActions`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub enum EntryError {
    /// Entry does not exists.
    NoSuchEntry,
    /// Entry already exists. Contains the current entry version.
    EntryExists(u64),
    /// Invalid version when updating an entry. Contains the current entry version.
    InvalidSuccessor(u64),
}

/// Mutable data.
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
pub struct MutableData {
    /// Network address
    name: XorName,
    /// Type tag
    tag: u64,
    // ---- owner and vault access only ----
    /// Maps an arbitrary key to a (version, data) tuple value
    data: BTreeMap<Vec<u8>, Value>,
    /// Maps an application key to a list of allowed or forbidden actions
    permissions: BTreeMap<User, PermissionSet>,
    /// Version should be increased for every change in MutableData fields
    /// except for data
    version: u64,
    /// Contains a set of owners which are allowed to mutate permissions.
    /// Currently limited to one owner to disallow multisig.
    owners: BTreeSet<PublicKey>,
}

/// A value in `MutableData`
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize, Debug)]
pub struct Value {
    /// Content of the entry.
    pub content: Vec<u8>,
    /// Version of the entry.
    pub entry_version: u64,
}

/// Subject of permissions
#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum User {
    /// Permissions apply to anyone.
    Anyone,
    /// Permissions apply to a single public key.
    Key(PublicKey),
}

/// Action a permission applies to
#[derive(Debug, Hash, Eq, PartialEq, PartialOrd, Ord, Copy, Clone, Serialize, Deserialize)]
pub enum Action {
    /// Permission to insert new entries.
    Insert,
    /// Permission to update existing entries.
    Update,
    /// Permission to delete existing entries.
    Delete,
    /// Permission to modify permissions for other users.
    ManagePermissions,
}

/// Set of user permissions.
#[derive(
    Clone, Copy, Debug, Eq, Hash, PartialEq, PartialOrd, Ord, Serialize, Deserialize, Default,
)]
pub struct PermissionSet {
    insert: Option<bool>,
    update: Option<bool>,
    delete: Option<bool>,
    manage_permissions: Option<bool>,
}

impl PermissionSet {
    /// Construct new permission set.
    pub fn new() -> PermissionSet {
        PermissionSet {
            insert: None,
            update: None,
            delete: None,
            manage_permissions: None,
        }
    }

    /// Allow the given action.
    pub fn allow(mut self, action: Action) -> Self {
        match action {
            Action::Insert => self.insert = Some(true),
            Action::Update => self.update = Some(true),
            Action::Delete => self.delete = Some(true),
            Action::ManagePermissions => self.manage_permissions = Some(true),
        }
        self
    }

    /// Deny the given action.
    pub fn deny(mut self, action: Action) -> Self {
        match action {
            Action::Insert => self.insert = Some(false),
            Action::Update => self.update = Some(false),
            Action::Delete => self.delete = Some(false),
            Action::ManagePermissions => self.manage_permissions = Some(false),
        }
        self
    }

    /// Clear the permission for the given action.
    pub fn clear(mut self, action: Action) -> Self {
        match action {
            Action::Insert => self.insert = None,
            Action::Update => self.update = None,
            Action::Delete => self.delete = None,
            Action::ManagePermissions => self.manage_permissions = None,
        }
        self
    }

    /// Is the given action allowed according to this permission set?
    pub fn is_allowed(self, action: Action) -> Option<bool> {
        match action {
            Action::Insert => self.insert,
            Action::Update => self.update,
            Action::Delete => self.delete,
            Action::ManagePermissions => self.manage_permissions,
        }
    }
}

impl Rand for PermissionSet {
    fn rand<R: Rng>(rng: &mut R) -> PermissionSet {
        PermissionSet {
            insert: Rand::rand(rng),
            update: Rand::rand(rng),
            delete: Rand::rand(rng),
            manage_permissions: Rand::rand(rng),
        }
    }
}

/// Action performed on a single entry: insert, update or delete.
#[derive(Hash, Debug, Eq, PartialEq, Clone, PartialOrd, Ord, Serialize, Deserialize)]
pub enum EntryAction {
    /// Inserts a new entry
    Ins(Value),
    /// Updates an entry with a new value and version
    Update(Value),
    /// Deletes an entry by emptying its contents. Contains the version number
    Del(u64),
}

/// Helper struct to build entry actions on `MutableData`
#[derive(Debug, Default, Clone)]
pub struct EntryActions {
    actions: BTreeMap<Vec<u8>, EntryAction>,
}

impl EntryActions {
    /// Create a helper to simplify construction of `MutableData` actions
    pub fn new() -> Self {
        Default::default()
    }

    /// Insert a new key-value pair
    pub fn ins(mut self, key: Vec<u8>, content: Vec<u8>, version: u64) -> Self {
        let _ = self.actions.insert(
            key,
            EntryAction::Ins(Value {
                entry_version: version,
                content,
            }),
        );
        self
    }

    /// Update existing key-value pair
    pub fn update(mut self, key: Vec<u8>, content: Vec<u8>, version: u64) -> Self {
        let _ = self.actions.insert(
            key,
            EntryAction::Update(Value {
                entry_version: version,
                content,
            }),
        );
        self
    }

    /// Delete existing key
    pub fn del(mut self, key: Vec<u8>, version: u64) -> Self {
        let _ = self.actions.insert(key, EntryAction::Del(version));
        self
    }
}

impl Into<BTreeMap<Vec<u8>, EntryAction>> for EntryActions {
    fn into(self) -> BTreeMap<Vec<u8>, EntryAction> {
        self.actions
    }
}

impl MutableData {
    /// Creates a new MutableData
    #[allow(clippy::new_ret_no_self)]
    pub fn new(
        name: XorName,
        tag: u64,
        permissions: BTreeMap<User, PermissionSet>,
        data: BTreeMap<Vec<u8>, Value>,
        owners: BTreeSet<PublicKey>,
    ) -> Result<MutableData, ClientError> {
        let md = MutableData {
            name,
            tag,
            data,
            permissions,
            version: 0,
            owners,
        };

        md.validate()?;
        Ok(md)
    }

    /// Validate this data.
    pub fn validate(&self) -> Result<(), ClientError> {
        if self.owners.len() > 1 {
            return Err(ClientError::InvalidOwners);
        }
        if self.data.len() >= (MAX_MUTABLE_DATA_ENTRIES + 1) as usize {
            return Err(ClientError::TooManyEntries);
        }

        if self.serialised_size() > MAX_MUTABLE_DATA_SIZE_IN_BYTES {
            return Err(ClientError::DataTooLarge);
        }

        Ok(())
    }

    /// Returns the shell of this data. Shell contains the same fields as the data itself,
    /// except the entries.
    pub fn shell(&self) -> MutableData {
        MutableData {
            name: self.name,
            tag: self.tag,
            data: BTreeMap::new(),
            permissions: self.permissions.clone(),
            version: self.version,
            owners: self.owners.clone(),
        }
    }

    /// Returns the name.
    pub fn name(&self) -> &XorName {
        &self.name
    }

    /// Returns the type tag of this MutableData
    pub fn tag(&self) -> u64 {
        self.tag
    }

    /// Returns the current version of this MutableData
    pub fn version(&self) -> u64 {
        self.version
    }

    /// Returns the owner keys
    pub fn owners(&self) -> &BTreeSet<PublicKey> {
        &self.owners
    }

    /// Returns a value by the given key
    pub fn get(&self, key: &[u8]) -> Option<&Value> {
        self.data.get(key)
    }

    /// Returns keys of all entries
    pub fn keys(&self) -> BTreeSet<&Vec<u8>> {
        self.data.keys().collect()
    }

    /// Returns values of all entries
    pub fn values(&self) -> Vec<&Value> {
        self.data.values().collect()
    }

    /// Returns all entries
    pub fn entries(&self) -> &BTreeMap<Vec<u8>, Value> {
        &self.data
    }

    /// Removes and returns all entries
    pub fn take_entries(&mut self) -> BTreeMap<Vec<u8>, Value> {
        mem::replace(&mut self.data, BTreeMap::new())
    }

    /// Mutates entries (key + value pairs) in bulk
    pub fn mutate_entries(
        &mut self,
        actions: BTreeMap<Vec<u8>, EntryAction>,
        requester: PublicKey,
    ) -> Result<(), ClientError> {
        // Deconstruct actions into inserts, updates, and deletes
        let (insert, update, delete) = actions.into_iter().fold(
            (BTreeMap::new(), BTreeMap::new(), BTreeMap::new()),
            |(mut insert, mut update, mut delete), (key, item)| {
                match item {
                    EntryAction::Ins(value) => {
                        let _ = insert.insert(key, value);
                    }
                    EntryAction::Update(value) => {
                        let _ = update.insert(key, value);
                    }
                    EntryAction::Del(version) => {
                        let _ = delete.insert(key, version);
                    }
                };
                (insert, update, delete)
            },
        );

        if (!insert.is_empty() && !self.is_action_allowed(requester, Action::Insert))
            || (!update.is_empty() && !self.is_action_allowed(requester, Action::Update))
            || (!delete.is_empty() && !self.is_action_allowed(requester, Action::Delete))
        {
            return Err(ClientError::AccessDenied);
        }

        let mut new_data = self.data.clone();
        let mut errors = BTreeMap::new();

        for (key, val) in insert {
            match new_data.entry(key) {
                Entry::Occupied(entry) => {
                    let _ = errors.insert(
                        entry.key().clone(),
                        EntryError::EntryExists(entry.get().entry_version),
                    );
                }
                Entry::Vacant(entry) => {
                    let _ = entry.insert(val);
                }
            }
        }

        for (key, val) in update {
            match new_data.entry(key) {
                Entry::Occupied(mut entry) => {
                    let current_version = entry.get().entry_version;
                    if val.entry_version == current_version + 1 {
                        let _ = entry.insert(val);
                    } else {
                        let _ = errors.insert(
                            entry.key().clone(),
                            EntryError::InvalidSuccessor(current_version),
                        );
                    }
                }
                Entry::Vacant(entry) => {
                    let _ = errors.insert(entry.key().clone(), EntryError::NoSuchEntry);
                }
            }
        }

        for (key, version) in delete {
            // TODO(nbaksalyar): find a way to decrease a number of entries after deletion.
            // In the current implementation if a number of entries exceeds the limit
            // there's no way for an owner to delete unneeded entries.
            match new_data.entry(key) {
                Entry::Occupied(mut entry) => {
                    let current_version = entry.get().entry_version;
                    if version == current_version + 1 {
                        let _ = entry.insert(Value {
                            content: Vec::new(),
                            entry_version: version,
                        });
                    } else {
                        let _ = errors.insert(
                            entry.key().clone(),
                            EntryError::InvalidSuccessor(current_version),
                        );
                    }
                }
                Entry::Vacant(entry) => {
                    let _ = errors.insert(entry.key().clone(), EntryError::NoSuchEntry);
                }
            }
        }

        if !errors.is_empty() {
            return Err(ClientError::InvalidEntryActions(errors));
        }

        if new_data.len() > MAX_MUTABLE_DATA_ENTRIES as usize {
            return Err(ClientError::TooManyEntries);
        }

        let old_data = mem::replace(&mut self.data, new_data);

        if !self.validate_size() {
            self.data = old_data;
            return Err(ClientError::DataTooLarge);
        }

        Ok(())
    }

    /// Mutates entries without performing any validation.
    ///
    /// For updates and deletes, the mutation is performed only if he entry version
    /// of the action is higher than the current version of the entry.
    pub fn mutate_entries_without_validation(&mut self, actions: BTreeMap<Vec<u8>, EntryAction>) {
        for (key, action) in actions {
            match action {
                EntryAction::Ins(new_value) => {
                    let _ = self.data.insert(key, new_value);
                }
                EntryAction::Update(new_value) => match self.data.entry(key) {
                    Entry::Occupied(mut entry) => {
                        if new_value.entry_version > entry.get().entry_version {
                            let _ = entry.insert(new_value);
                        }
                    }
                    Entry::Vacant(entry) => {
                        let _ = entry.insert(new_value);
                    }
                },
                EntryAction::Del(new_version) => {
                    if let Entry::Occupied(mut entry) = self.data.entry(key) {
                        if new_version > entry.get().entry_version {
                            let _ = entry.insert(Value {
                                content: Vec::new(),
                                entry_version: new_version,
                            });
                        }
                    }
                }
            }
        }
    }

    /// Mutates single entry without performing any validations, except the version
    /// check (new version must be higher than the existing one).
    /// If the entry doesn't exist yet, inserts it, otherwise, updates it.
    /// Returns true if the version check passed and the entry was mutated,
    /// false otherwise.
    pub fn mutate_entry_without_validation(&mut self, key: Vec<u8>, value: Value) -> bool {
        match self.data.entry(key) {
            Entry::Occupied(mut entry) => {
                if value.entry_version > entry.get().entry_version {
                    let _ = entry.insert(value);
                    true
                } else {
                    false
                }
            }
            Entry::Vacant(entry) => {
                let _ = entry.insert(value);
                true
            }
        }
    }

    /// Gets a complete list of permissions
    pub fn permissions(&self) -> &BTreeMap<User, PermissionSet> {
        &self.permissions
    }

    /// Gets a list of permissions for the provided user.
    pub fn user_permissions(&self, user: &User) -> Result<&PermissionSet, ClientError> {
        self.permissions.get(user).ok_or(ClientError::NoSuchKey)
    }

    /// Insert or update permissions for the provided user.
    pub fn set_user_permissions(
        &mut self,
        user: User,
        permissions: PermissionSet,
        version: u64,
        requester: PublicKey,
    ) -> Result<(), ClientError> {
        if !self.is_action_allowed(requester, Action::ManagePermissions) {
            return Err(ClientError::AccessDenied);
        }
        if version != self.version + 1 {
            return Err(ClientError::InvalidSuccessor(self.version));
        }
        let prev = self.permissions.insert(user, permissions);
        if !self.validate_size() {
            // Serialised data size limit is exceeded
            let _ = match prev {
                None => self.permissions.remove(&user),
                Some(perms) => self.permissions.insert(user, perms),
            };
            return Err(ClientError::DataTooLarge);
        }
        self.version = version;
        Ok(())
    }

    /// Set user permission without performing any validation.
    pub fn set_user_permissions_without_validation(
        &mut self,
        user: User,
        permissions: PermissionSet,
        version: u64,
    ) -> bool {
        if version <= self.version {
            return false;
        }

        let _ = self.permissions.insert(user, permissions);
        self.version = version;
        true
    }

    /// Delete permissions for the provided user.
    pub fn del_user_permissions(
        &mut self,
        user: &User,
        version: u64,
        requester: PublicKey,
    ) -> Result<(), ClientError> {
        if !self.is_action_allowed(requester, Action::ManagePermissions) {
            return Err(ClientError::AccessDenied);
        }
        if version != self.version + 1 {
            return Err(ClientError::InvalidSuccessor(self.version));
        }
        if !self.permissions.contains_key(user) {
            return Err(ClientError::NoSuchKey);
        }
        let _ = self.permissions.remove(user);
        self.version = version;
        Ok(())
    }

    /// Delete user permissions without performing any validation.
    pub fn del_user_permissions_without_validation(&mut self, user: &User, version: u64) -> bool {
        if version <= self.version {
            return false;
        }

        let _ = self.permissions.remove(user);
        self.version = version;
        true
    }

    /// Change owner of the mutable data.
    pub fn change_owner(&mut self, new_owner: PublicKey, version: u64) -> Result<(), ClientError> {
        if version != self.version + 1 {
            return Err(ClientError::InvalidSuccessor(self.version));
        }
        self.owners.clear();
        let _ = self.owners.insert(new_owner);
        self.version = version;
        Ok(())
    }

    /// Change the owner without performing any validation.
    pub fn change_owner_without_validation(&mut self, new_owner: PublicKey, version: u64) -> bool {
        if version <= self.version {
            return false;
        }

        self.owners.clear();
        let _ = self.owners.insert(new_owner);
        self.version = version;
        true
    }

    /// Return the size of this data after serialisation.
    pub fn serialised_size(&self) -> u64 {
        serialisation::serialised_size(self)
    }

    /// Return true if the size is valid
    pub fn validate_size(&self) -> bool {
        self.serialised_size() <= MAX_MUTABLE_DATA_SIZE_IN_BYTES
    }

    fn check_anyone_permissions(&self, action: Action) -> bool {
        match self.permissions.get(&User::Anyone) {
            None => false,
            Some(perms) => perms.is_allowed(action).unwrap_or(false),
        }
    }

    fn is_action_allowed(&self, requester: PublicKey, action: Action) -> bool {
        if self.owners.contains(&requester) {
            return true;
        }
        match self.permissions.get(&User::Key(requester)) {
            Some(perms) => perms
                .is_allowed(action)
                .unwrap_or_else(|| self.check_anyone_permissions(action)),
            None => self.check_anyone_permissions(action),
        }
    }
}

impl Debug for MutableData {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        // TODO(nbaksalyar): write all other fields
        write!(
            formatter,
            "MutableData {{ name: {}, tag: {}, version: {}, owners: {:?} }}",
            self.name(),
            self.tag,
            self.version,
            self.owners
        )
    }
}

/// Request message types
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum Request {
    /// Represents a refresh message sent between vaults. Vec<u8> is the message content.
    Refresh(Vec<u8>, MsgId),
    /// Gets MAID account information.
    GetAccountInfo(MsgId),

    // --- ImmutableData ---
    // ==========================
    /// Puts ImmutableData to the network.
    PutIData {
        /// ImmutableData to be stored
        data: ImmutableData,
        /// Unique message identifier
        msg_id: MsgId,
    },
    /// Fetches ImmutableData from the network by the given name.
    GetIData {
        /// Network identifier of ImmutableData
        name: XorName,
        /// Unique message identifier
        msg_id: MsgId,
    },

    // --- MutableData ---
    /// Fetches whole MutableData from the network.
    /// Note: responses to this request are unlikely to accumulate during churn.
    GetMData {
        /// Network identifier of MutableData
        name: XorName,
        /// Type tag
        tag: u64,
        /// Unique message identifier
        msg_id: MsgId,
    },
    // ==========================
    /// Creates a new MutableData in the network.
    PutMData {
        /// MutableData to be stored
        data: MutableData,
        /// Unique message identifier
        msg_id: MsgId,
        /// Requester public key
        requester: PublicKey,
    },
    /// Fetches a latest version number.
    GetMDataVersion {
        /// Network identifier of MutableData
        name: XorName,
        /// Type tag
        tag: u64,
        /// Unique message identifier
        msg_id: MsgId,
    },
    /// Fetches the shell (everthing except the entries).
    GetMDataShell {
        /// Network identifier of MutableData
        name: XorName,
        /// Type tag
        tag: u64,
        /// Unique message identifier
        msg_id: MsgId,
    },

    // Data Actions
    /// Fetches a list of entries (keys + values).
    /// Note: responses to this request are unlikely to accumulate during churn.
    ListMDataEntries {
        /// Network identifier of MutableData
        name: XorName,
        /// Type tag
        tag: u64,
        /// Unique message identifier
        msg_id: MsgId,
    },
    /// Fetches a list of keys in MutableData.
    /// Note: responses to this request are unlikely to accumulate during churn.
    ListMDataKeys {
        /// Network identifier of MutableData
        name: XorName,
        /// Type tag
        tag: u64,
        /// Unique message identifier
        msg_id: MsgId,
    },
    /// Fetches a list of values in MutableData.
    /// Note: responses to this request are unlikely to accumulate during churn.
    ListMDataValues {
        /// Network identifier of MutableData
        name: XorName,
        /// Type tag
        tag: u64,
        /// Unique message identifier
        msg_id: MsgId,
    },
    /// Fetches a single value from MutableData
    GetMDataValue {
        /// Network identifier of MutableData
        name: XorName,
        /// Type tag
        tag: u64,
        /// Key of an entry to be fetched
        key: Vec<u8>,
        /// Unique message identifier
        msg_id: MsgId,
    },
    /// Updates MutableData entries in bulk.
    MutateMDataEntries {
        /// Network identifier of MutableData
        name: XorName,
        /// Type tag
        tag: u64,
        /// A list of mutations (inserts, updates, or deletes) to be performed
        /// on MutableData in bulk.
        actions: BTreeMap<Vec<u8>, EntryAction>,
        /// Unique message identifier
        msg_id: MsgId,
        /// Requester public key
        requester: PublicKey,
    },

    // Permission Actions
    /// Fetches a complete list of permissions.
    ListMDataPermissions {
        /// Network identifier of MutableData
        name: XorName,
        /// Type tag
        tag: u64,
        /// Unique message identifier
        msg_id: MsgId,
    },
    /// Fetches a list of permissions for a particular User.
    ListMDataUserPermissions {
        /// Network identifier of MutableData
        name: XorName,
        /// Type tag
        tag: u64,
        /// A user identifier used to fetch permissions
        user: User,
        /// Unique message identifier
        msg_id: MsgId,
    },
    /// Updates or inserts a list of permissions for a particular User in the given MutableData.
    SetMDataUserPermissions {
        /// Network identifier of MutableData
        name: XorName,
        /// Type tag
        tag: u64,
        /// A user identifier used to set permissions
        user: User,
        /// Permissions to be set for a user
        permissions: PermissionSet,
        /// Incremented version of MutableData
        version: u64,
        /// Unique message identifier
        msg_id: MsgId,
        /// Requester public key
        requester: PublicKey,
    },
    /// Deletes a list of permissions for a particular User in the given MutableData.
    DelMDataUserPermissions {
        /// Network identifier of MutableData
        name: XorName,
        /// Type tag
        tag: u64,
        /// A user identifier used to delete permissions
        user: User,
        /// Incremented version of MutableData
        version: u64,
        /// Unique message identifier
        msg_id: MsgId,
        /// Requester public key
        requester: PublicKey,
    },

    // Ownership Actions
    /// Changes an owner of the given MutableData. Only the current owner can perform this action.
    ChangeMDataOwner {
        /// Network identifier of MutableData
        name: XorName,
        /// Type tag
        tag: u64,
        /// A list of new owners
        new_owners: BTreeSet<PublicKey>,
        /// Incremented version of MutableData
        version: u64,
        /// Unique message identifier
        msg_id: MsgId,
    },
}

impl Request {
    /// Message ID getter.
    pub fn message_id(&self) -> &MsgId {
        use Request::*;
        match *self {
            Refresh(_, ref msg_id)
            | GetAccountInfo(ref msg_id)
            | PutIData { ref msg_id, .. }
            | GetIData { ref msg_id, .. }
            | GetMData { ref msg_id, .. }
            | PutMData { ref msg_id, .. }
            | GetMDataVersion { ref msg_id, .. }
            | GetMDataShell { ref msg_id, .. }
            | ListMDataEntries { ref msg_id, .. }
            | ListMDataKeys { ref msg_id, .. }
            | ListMDataValues { ref msg_id, .. }
            | GetMDataValue { ref msg_id, .. }
            | MutateMDataEntries { ref msg_id, .. }
            | ListMDataPermissions { ref msg_id, .. }
            | ListMDataUserPermissions { ref msg_id, .. }
            | SetMDataUserPermissions { ref msg_id, .. }
            | DelMDataUserPermissions { ref msg_id, .. }
            | ChangeMDataOwner { ref msg_id, .. } => msg_id,
        }
    }

    /// Is the response corresponding to this request cacheable?
    pub fn is_cacheable(&self) -> bool {
        if let Request::GetIData { .. } = *self {
            true
        } else {
            false
        }
    }
}

/// Response message types
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum Response {
    /// Returns a success or failure status of account information retrieval.
    GetAccountInfo {
        /// Result of fetching account info from the network.
        res: Result<AccountInfo, ClientError>,
        /// Unique message identifier
        msg_id: MsgId,
    },

    // --- ImmutableData ---
    // ==========================
    /// Returns a success or failure status of putting ImmutableData to the network.
    PutIData {
        /// Result of putting ImmutableData to the network.
        res: Result<(), ClientError>,
        /// Unique message identifier
        msg_id: MsgId,
    },
    /// Returns a result of fetching ImmutableData from the network.
    GetIData {
        /// Result of fetching ImmutableData from the network.
        res: Result<ImmutableData, ClientError>,
        /// Unique message identifier
        msg_id: MsgId,
    },

    // --- MutableData ---
    // ==========================
    /// Returns a success or failure status of putting MutableData to the network.
    PutMData {
        /// Result of putting MutableData to the network.
        res: Result<(), ClientError>,
        /// Unique message identifier
        msg_id: MsgId,
    },
    /// Returns a result of fetching MutableData from the network.
    GetMData {
        /// Result of fetching MutableData from the network.
        res: Result<MutableData, ClientError>,
        /// Unique message identifier
        msg_id: MsgId,
    },
    /// Returns a current version of MutableData stored in the network.
    GetMDataVersion {
        /// Result of getting a version of MutableData
        res: Result<u64, ClientError>,
        /// Unique message identifier
        msg_id: MsgId,
    },
    /// Returns the shell of MutableData (everything except the entries).
    GetMDataShell {
        /// Result of getting the shell of MutableData.
        res: Result<MutableData, ClientError>,
        /// Unique message identifier
        msg_id: MsgId,
    },

    // Data Actions
    /// Returns a complete list of entries in MutableData or an error in case of failure.
    ListMDataEntries {
        /// Result of getting a list of entries in MutableData
        res: Result<BTreeMap<Vec<u8>, Value>, ClientError>,
        /// Unique message identifier
        msg_id: MsgId,
    },
    /// Returns a list of keys in MutableData or an error in case of failure.
    ListMDataKeys {
        /// Result of getting a list of keys in MutableData
        res: Result<BTreeSet<Vec<u8>>, ClientError>,
        /// Unique message identifier
        msg_id: MsgId,
    },
    /// Returns a list of values in MutableData or an error in case of failure.
    ListMDataValues {
        /// Result of getting a list of values in MutableData
        res: Result<Vec<Value>, ClientError>,
        /// Unique message identifier
        msg_id: MsgId,
    },
    /// Returns a single entry from MutableData or an error in case of failure.
    GetMDataValue {
        /// Result of getting a value from MutableData
        res: Result<Value, ClientError>,
        /// Unique message identifier
        msg_id: MsgId,
    },
    /// Returns a success or failure status of mutating MutableData in the network.
    MutateMDataEntries {
        /// Result of mutating an entry in MutableData
        res: Result<(), ClientError>,
        /// Unique message identifier
        msg_id: MsgId,
    },

    // Permission Actions
    /// Returns a complete list of MutableData permissions stored on the network
    /// or an error in case of failure.
    ListMDataPermissions {
        /// Result of getting a list of permissions in MutableData
        res: Result<BTreeMap<User, PermissionSet>, ClientError>,
        /// Unique message identifier
        msg_id: MsgId,
    },
    /// Returns a list of permissions for a particular User in MutableData or an
    /// error in case of failure.
    ListMDataUserPermissions {
        /// Result of getting a list of user permissions in MutableData
        res: Result<PermissionSet, ClientError>,
        /// Unique message identifier
        msg_id: MsgId,
    },
    /// Returns a success or failure status of setting permissions for a particular
    /// User in MutableData.
    SetMDataUserPermissions {
        /// Result of setting a list of user permissions in MutableData
        res: Result<(), ClientError>,
        /// Unique message identifier
        msg_id: MsgId,
    },
    /// Returns a success or failure status of deleting permissions for a particular
    /// User in MutableData.
    DelMDataUserPermissions {
        /// Result of deleting a list of user permissions in MutableData
        res: Result<(), ClientError>,
        /// Unique message identifier
        msg_id: MsgId,
    },

    // Ownership Actions
    /// Returns a success or failure status of chaning an owner of MutableData.
    ChangeMDataOwner {
        /// Result of chaning an owner of MutableData
        res: Result<(), ClientError>,
        /// Unique message identifier
        msg_id: MsgId,
    },

    /// RpcResponse from Vaults - should be in safe-nd crate
    RpcResponse {
        /// Reponse payload
        res: Result<Vec<u8>, ClientError>,
        /// Unique message ID
        msg_id: MsgId,
    },
}

impl Response {
    /// The priority Crust should send this message with.
    pub fn priority(&self) -> u8 {
        match *self {
            Response::GetIData { res: Ok(_), .. } => 5,
            Response::GetMDataValue { res: Ok(_), .. }
            | Response::GetMDataShell { res: Ok(_), .. } => 4,
            _ => 3,
        }
    }

    /// Message ID getter.
    pub fn message_id(&self) -> &MsgId {
        use Response::*;
        match *self {
            GetAccountInfo { ref msg_id, .. }
            | PutIData { ref msg_id, .. }
            | GetIData { ref msg_id, .. }
            | PutMData { ref msg_id, .. }
            | GetMData { ref msg_id, .. }
            | GetMDataVersion { ref msg_id, .. }
            | GetMDataShell { ref msg_id, .. }
            | ListMDataEntries { ref msg_id, .. }
            | ListMDataKeys { ref msg_id, .. }
            | ListMDataValues { ref msg_id, .. }
            | GetMDataValue { ref msg_id, .. }
            | MutateMDataEntries { ref msg_id, .. }
            | ListMDataPermissions { ref msg_id, .. }
            | ListMDataUserPermissions { ref msg_id, .. }
            | SetMDataUserPermissions { ref msg_id, .. }
            | DelMDataUserPermissions { ref msg_id, .. }
            | ChangeMDataOwner { ref msg_id, .. }
            | RpcResponse { ref msg_id, .. } => msg_id,
        }
    }

    /// Is this response cacheable?
    pub fn is_cacheable(&self) -> bool {
        if let Response::GetIData { .. } = *self {
            true
        } else {
            false
        }
    }
}

/// Account information
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, Debug)]
pub struct AccountInfo {
    /// Number of mutate operations performed by the account.
    pub mutations_done: u64,
    /// Number of mutate operations remaining for the account.
    pub mutations_available: u64,
}

/// Structured Data Tag for Session Packet Type
pub const TYPE_TAG_SESSION_PACKET: u64 = 0;
/// Structured Data Tag for DNS Packet Type
pub const TYPE_TAG_DNS_PACKET: u64 = 5;

pub type BootstrapConfig = u64;

/// Key of an account data in the account packet
pub const ACC_LOGIN_ENTRY_KEY: &[u8] = b"Login";

/// Account packet that is used to provide an invitation code for registration.
/// After successful registration it should be replaced with `AccountPacket::AccPkt`
/// with the contents of `account_ciphertext` as soon as possible to prevent an
/// invitation code leak.
#[derive(Serialize, Deserialize)]
pub enum AccountPacket {
    /// Account data with an invitation code that is used for registration.
    WithInvitation {
        /// Invitation code.
        invitation_string: String,
        /// Encrypted account data.
        acc_pkt: Vec<u8>,
    },
    /// Encrypted account data.
    AccPkt(Vec<u8>),
}

/// The type of errors that can occur if routing is unable to handle a send request.
#[derive(Debug)]
// FIXME - See https://maidsafe.atlassian.net/browse/MAID-2026 for info on removing this exclusion.
#[allow(clippy::large_enum_variant)]
pub enum InterfaceError {
    /// We are not connected to the network.
    NotConnected,
    /// We are not in a state to handle the action.
    InvalidState,
    /// Error while trying to receive a message from a channel
    ChannelRxError(()),
    /// Error while trying to transmit an event via a channel
    EventSenderError(()),
}

/// The type of errors that can occur during handling of routing events.
#[derive(Debug)]
// FIXME - See https://maidsafe.atlassian.net/browse/MAID-2026 for info on removing this exclusion.
#[allow(clippy::large_enum_variant)]
pub enum RoutingError {
    /// The node/client has not bootstrapped yet
    NotBootstrapped,
    /// Invalid State
    Terminated,
    /// Invalid requester or handler authorities
    BadAuthority,
    /// Failure to connect to an already connected node
    AlreadyConnected,
    /// Failure to connect to a group in handling a joining request
    AlreadyHandlingJoinRequest,
    /// Received message having unknown type
    UnknownMessageType,
    /// Failed signature check
    FailedSignature,
    /// Not Enough signatures
    NotEnoughSignatures,
    /// Duplicate signatures
    DuplicateSignatures,
    /// The list of owner keys is invalid
    InvalidOwners,
    /// Duplicate request received
    FilterCheckFailed,
    /// Failure to bootstrap off the provided endpoints
    FailedToBootstrap,
    /// Node's new name doesn't fall within the specified target address range.
    InvalidRelocationTargetRange,
    /// A client with `client_restriction == true` tried to send a message restricted to nodes.
    RejectedClientMessage,
    /// Routing Table error
    RoutingTable(()),
    /// String errors
    Utf8(::std::str::Utf8Error),
    /// Interface error
    Interface(InterfaceError),
    /// i/o error
    Io(::std::io::Error),
    /// Crust error
    Crust(()),
    /// Channel sending error
    SendEventError(()),
    /// Current state is invalid for the operation
    InvalidStateForOperation,
    /// Serialisation Error
    SerialisationError(()),
    /// Asymmetric Decryption Failure
    AsymmetricDecryptionFailure,
    /// Unknown Connection
    UnknownConnection(PublicId),
    /// Invalid Destination
    InvalidDestination,
    /// Connection to proxy node does not exist in proxy map
    ProxyConnectionNotFound,
    /// Connection to client does not exist in client map
    ClientConnectionNotFound,
    /// Invalid Source
    InvalidSource,
    /// Attempted to use a node as a tunnel that is not directly connected
    CannotTunnelThroughTunnel,
    /// Decoded a user message with an unexpected hash.
    HashMismatch,
    /// Version check has failed
    InvalidSuccessor,
    /// Candidate is unknown
    UnknownCandidate,
    /// Operation timed out
    TimedOut,
    /// Failed validation of resource proof
    FailedResourceProofValidation,
    /// Candidate is connected via a tunnel
    CandidateIsTunnelling,
    /// Content of a received message is inconsistent.
    InvalidMessage,
    /// Invalid Peer
    InvalidPeer,
    /// The client's message indicated by the included hash digest has been rejected by the
    /// rate-limiter.
    ExceedsRateLimit(()),
    /// Invalid configuration
    ConfigError(()),
}

pub mod messaging {
    use std::error::Error as StdError;
    use std::fmt::{self, Display, Formatter};
    /// Error types relating to MPID messaging.
    #[derive(Debug)]
    pub enum Error {
        /// Used where the length of a [header's `metadata`](struct.MpidHeader.html#method.new) exceeds
        /// [`MAX_HEADER_METADATA_SIZE`](constant.MAX_HEADER_METADATA_SIZE.html).
        MetadataTooLarge,
        /// Used where the length of a [message's `body`](struct.MpidMessage.html#method.new) exceeds
        /// [`MAX_BODY_SIZE`](constant.MAX_BODY_SIZE.html).
        BodyTooLarge,
        /// Serialisation error.
        Serialisation(()),
    }

    impl Display for Error {
        fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
            match *self {
                Error::MetadataTooLarge => write!(formatter, "Message header too large"),
                Error::BodyTooLarge => write!(formatter, "Message body too large"),
                Error::Serialisation(()) => write!(formatter, "Serialisation error"),
            }
        }
    }

    impl StdError for Error {
        fn description(&self) -> &str {
            match *self {
                Error::MetadataTooLarge => "Header too large",
                Error::BodyTooLarge => "Body too large",
                Error::Serialisation(()) => "Serialisation error",
            }
        }

        fn cause(&self) -> Option<&StdError> {
            None
        }
    }
}

/// Network identity component containing name, and public and private keys.
#[derive(Clone)]
pub struct FullId {
    public_id: PublicId,
    private_encrypt_key: box_::SecretKey,
    private_sign_key: sign::SecretKey,
    private_bls_key: threshold_crypto::SecretKey,
}

impl FullId {
    /// Construct a `FullId` with newly generated keys.
    pub fn new() -> FullId {
        let encrypt_keys = box_::gen_keypair();
        let sign_keys = sign::gen_keypair();
        let private_bls_key = threshold_crypto::SecretKey::random();
        FullId {
            public_id: PublicId::new(encrypt_keys.0, sign_keys.0, private_bls_key.public_key()),
            private_encrypt_key: encrypt_keys.1,
            private_sign_key: sign_keys.1,
            private_bls_key,
        }
    }

    /// Construct with given keys (client requirement).
    pub fn with_keys(
        encrypt_keys: (box_::PublicKey, box_::SecretKey),
        sign_keys: (sign::PublicKey, sign::SecretKey),
        private_bls_key: threshold_crypto::SecretKey,
    ) -> FullId {
        // TODO Verify that pub/priv key pairs match
        FullId {
            public_id: PublicId::new(encrypt_keys.0, sign_keys.0, private_bls_key.public_key()),
            private_encrypt_key: encrypt_keys.1,
            private_sign_key: sign_keys.1,
            private_bls_key,
        }
    }

    /// Construct a `FullId` whose name is in the interval [start, end] (both endpoints inclusive).
    /// FIXME(Fraser) - time limit this function? Document behaviour
    pub fn within_range(start: &XorName, end: &XorName) -> FullId {
        let mut sign_keys = sign::gen_keypair();
        loop {
            let name = PublicId::name_from_key(&sign_keys.0);
            if name >= *start && name <= *end {
                let encrypt_keys = box_::gen_keypair();
                let private_bls_key = threshold_crypto::SecretKey::random();
                let full_id = FullId::with_keys(encrypt_keys, sign_keys, private_bls_key);
                return full_id;
            }
            sign_keys = sign::gen_keypair();
        }
    }

    /// Returns public ID reference.
    pub fn public_id(&self) -> &PublicId {
        &self.public_id
    }

    /// Returns mutable reference to public ID.
    pub fn public_id_mut(&mut self) -> &mut PublicId {
        &mut self.public_id
    }

    /// Secret signing key.
    pub fn signing_private_key(&self) -> &sign::SecretKey {
        &self.private_sign_key
    }

    /// Private encryption key.
    pub fn encrypting_private_key(&self) -> &box_::SecretKey {
        &self.private_encrypt_key
    }

    /// Private BLS key
    pub fn bls_key(&self) -> &threshold_crypto::SecretKey {
        &self.private_bls_key
    }
}

impl Default for FullId {
    fn default() -> FullId {
        FullId::new()
    }
}

/// Network identity component containing name and public keys.
///
/// Note that the `name` member is omitted when serialising `PublicId` and is calculated from the
/// `public_sign_key` when deserialising.
#[derive(Hash, PartialEq, Eq, PartialOrd, Ord, Copy, Clone)]
pub struct PublicId {
    name: XorName,
    public_sign_key: sign::PublicKey,
    public_encrypt_key: box_::PublicKey,
    public_bls_key: threshold_crypto::PublicKey,
}

impl Debug for PublicId {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "PublicId(name: {})", self.name)
    }
}

impl Display for PublicId {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl Serialize for PublicId {
    fn serialize<S: Serializer>(&self, serialiser: S) -> Result<S::Ok, S::Error> {
        (
            &self.public_encrypt_key,
            &self.public_sign_key,
            &self.public_bls_key,
        )
            .serialize(serialiser)
    }
}

impl<'de> Deserialize<'de> for PublicId {
    fn deserialize<D: Deserializer<'de>>(deserialiser: D) -> Result<Self, D::Error> {
        let (public_encrypt_key, public_sign_key, public_bls_key): (
            box_::PublicKey,
            sign::PublicKey,
            threshold_crypto::PublicKey,
        ) = Deserialize::deserialize(deserialiser)?;
        Ok(PublicId::new(
            public_encrypt_key,
            public_sign_key,
            public_bls_key,
        ))
    }
}

impl PublicId {
    /// Return initial/relocated name.
    pub fn name(&self) -> &XorName {
        &self.name
    }

    /// Return public signing key.
    pub fn encrypting_public_key(&self) -> &box_::PublicKey {
        &self.public_encrypt_key
    }

    /// Return public signing key.
    pub fn signing_public_key(&self) -> &sign::PublicKey {
        &self.public_sign_key
    }

    /// Return public BLS key.
    pub fn bls_public_key(&self) -> &threshold_crypto::PublicKey {
        &self.public_bls_key
    }

    fn new(
        public_encrypt_key: box_::PublicKey,
        public_sign_key: sign::PublicKey,
        public_bls_key: threshold_crypto::PublicKey,
    ) -> PublicId {
        PublicId {
            public_encrypt_key,
            public_sign_key,
            public_bls_key,
            name: Self::name_from_key(&public_sign_key),
        }
    }

    fn name_from_key(public_sign_key: &sign::PublicKey) -> XorName {
        XorName(sha3_256(&public_sign_key[..]))
    }
}
