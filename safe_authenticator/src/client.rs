// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

#[cfg(not(feature = "mock-network"))]
use routing::Client as Routing;
#[cfg(feature = "mock-network")]
use safe_core::client::NewFullId;
#[cfg(feature = "mock-network")]
use safe_core::MockRouting as Routing;

use crate::errors::AuthError;
use crate::AuthFuture;
use crate::AuthMsgTx;
use futures::Future;
use lru_cache::LruCache;
use maidsafe_utilities::serialisation::{deserialise, serialise};
use routing::{
    AccountPacket, Authority, BootstrapConfig, EntryAction, Event, FullId, MutableData, Response,
    Value, XorName, ACC_LOGIN_ENTRY_KEY, TYPE_TAG_SESSION_PACKET,
};
use rust_sodium::crypto::sign::Seed;
use rust_sodium::crypto::{box_, sign};
use safe_core::client::account::Account;
use safe_core::client::{
    setup_routing, spawn_routing_thread, ClientInner, IMMUT_DATA_CACHE_SIZE, REQUEST_TIMEOUT_SECS,
};
use safe_core::crypto::{shared_box, shared_secretbox, shared_sign};
#[cfg(any(test, feature = "testing"))]
use safe_core::utils::seed::{divide_seed, SEED_SUBPARTS};
use safe_core::{utils, Client, ClientKeys, CoreError, FutureExt, MDataInfo, NetworkTx};
use safe_nd::{Message, MessageId, PublicKey, Request, Signature};
use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::rc::Rc;
use std::time::Duration;
use tiny_keccak::sha3_256;
use tokio_core::reactor::Handle;

/// Client object used by safe_authenticator.
pub struct AuthClient {
    inner: Rc<RefCell<ClientInner<AuthClient, ()>>>,
    auth_inner: Rc<RefCell<AuthInner>>,
}

impl AuthClient {
    /// This is a Gateway function to the Maidsafe network. This will help
    /// create a fresh acc for the user in the SAFE-network.
    pub(crate) fn registered(
        acc_locator: &str,
        acc_password: &str,
        invitation: &str,
        el_handle: Handle,
        core_tx: AuthMsgTx,
        net_tx: NetworkTx,
    ) -> Result<Self, AuthError> {
        Self::registered_impl(
            acc_locator.as_bytes(),
            acc_password.as_bytes(),
            invitation,
            el_handle,
            core_tx,
            net_tx,
            None,
            |routing| routing,
        )
    }

    /// This is one of the Gateway functions to the Maidsafe network, the others being `registered`,
    /// and `login`. This will help create an account given a seed. Everything including both
    /// account secrets and all MAID keys will be deterministically derived from the supplied seed,
    /// so this seed needs to be strong. For ordinary users, it's recommended to use the normal
    /// `registered` function where the secrets can be what's easy to remember for the user while
    /// also being strong.
    #[cfg(any(test, feature = "testing"))]
    pub(crate) fn registered_with_seed(
        seed: &str,
        el_handle: Handle,
        core_tx: AuthMsgTx,
        net_tx: NetworkTx,
    ) -> Result<Self, AuthError>
where {
        let arr = divide_seed(seed)?;

        let id_seed = Seed(sha3_256(arr[SEED_SUBPARTS - 2]));

        Self::registered_impl(
            arr[0],
            arr[1],
            "",
            el_handle,
            core_tx,
            net_tx,
            Some(&id_seed),
            |routing| routing,
        )
    }

    #[cfg(all(feature = "mock-network", any(test, feature = "testing")))]
    /// Allows customising the mock Routing client before registering a new account
    pub fn registered_with_hook<F>(
        acc_locator: &str,
        acc_password: &str,
        invitation: &str,
        el_handle: Handle,
        core_tx: AuthMsgTx,
        net_tx: NetworkTx,
        routing_wrapper_fn: F,
    ) -> Result<Self, AuthError>
    where
        F: Fn(Routing) -> Routing,
    {
        Self::registered_impl(
            acc_locator.as_bytes(),
            acc_password.as_bytes(),
            invitation,
            el_handle,
            core_tx,
            net_tx,
            None,
            routing_wrapper_fn,
        )
    }

    // This is a Gateway function to the Maidsafe network. This will help create a fresh acc for the
    // user in the SAFE-network.
    fn registered_impl<F>(
        acc_locator: &[u8],
        acc_password: &[u8],
        invitation: &str,
        el_handle: Handle,
        core_tx: AuthMsgTx,
        net_tx: NetworkTx,
        id_seed: Option<&Seed>,
        routing_wrapper_fn: F,
    ) -> Result<Self, AuthError>
    where
        F: Fn(Routing) -> Routing,
    {
        trace!("Creating an account.");

        let (password, keyword, pin) = utils::derive_secrets(acc_locator, acc_password);

        let acc_loc = Account::generate_network_id(&keyword, &pin)?;
        let user_cred = UserCred::new(password, pin);

        let maid_keys = ClientKeys::new(id_seed);
        let pub_key = PublicKey::from(maid_keys.bls_pk);
        let full_id = Some(maid_keys.clone().into());

        let (mut routing, routing_rx) = setup_routing(
            full_id,
            Some(NewFullId::Client(maid_keys.clone().into())),
            None,
        )?;
        routing = routing_wrapper_fn(routing);

        let acc = Account::new(maid_keys)?;

        let acc_ciphertext = acc.encrypt(&user_cred.password, &user_cred.pin)?;
        let acc_data = btree_map![
            ACC_LOGIN_ENTRY_KEY.to_owned() => Value {
                content: serialise(&if !invitation.is_empty() {
                    AccountPacket::WithInvitation {
                        invitation_string: invitation.to_owned(),
                        acc_pkt: acc_ciphertext
                    }
                } else {
                    AccountPacket::AccPkt(acc_ciphertext)
                })?,
                entry_version: 0,
            }
        ];

        let acc_md = MutableData::new(
            acc_loc,
            TYPE_TAG_SESSION_PACKET,
            BTreeMap::new(),
            acc_data,
            btree_set![pub_key],
        )
        .map_err(CoreError::from)?;

        let cm_addr = Authority::ClientManager(XorName::from(pub_key));

        let msg_id = MessageId::new();
        routing
            .put_mdata(cm_addr, acc_md.clone(), msg_id, pub_key)
            .map_err(CoreError::from)
            .and_then(|_| wait_for_response!(routing_rx, Response::PutMData, msg_id))
            .map_err(AuthError::from)
            .map_err(|e| {
                warn!("Could not put account to the Network: {:?}", e);
                e
            })?;

        // Create the client
        let joiner = spawn_routing_thread(routing_rx, core_tx.clone(), net_tx.clone());

        Ok(AuthClient {
            inner: Rc::new(RefCell::new(ClientInner::new(
                el_handle,
                routing,
                HashMap::with_capacity(10),
                LruCache::new(IMMUT_DATA_CACHE_SIZE),
                Duration::from_secs(REQUEST_TIMEOUT_SECS),
                joiner,
                core_tx,
                net_tx,
            ))),
            auth_inner: Rc::new(RefCell::new(AuthInner {
                acc,
                acc_loc,
                user_cred,
                cm_addr,
                session_packet_version: 0,
            })),
        })
    }

    /// This is a Gateway function to the Maidsafe network. This will help login to an already
    /// existing account of the user in the SAFE-network.
    pub(crate) fn login(
        acc_locator: &str,
        acc_password: &str,
        el_handle: Handle,
        core_tx: AuthMsgTx,
        net_tx: NetworkTx,
    ) -> Result<Self, AuthError> {
        Self::login_impl(
            acc_locator.as_bytes(),
            acc_password.as_bytes(),
            el_handle,
            core_tx,
            net_tx,
            |routing| routing,
        )
    }

    /// Login using seeded account.
    #[cfg(any(test, feature = "testing"))]
    pub(crate) fn login_with_seed(
        seed: &str,
        el_handle: Handle,
        core_tx: AuthMsgTx,
        net_tx: NetworkTx,
    ) -> Result<Self, AuthError> {
        let arr = divide_seed(seed)?;
        Self::login_impl(arr[0], arr[1], el_handle, core_tx, net_tx, |routing| {
            routing
        })
    }

    #[cfg(all(feature = "mock-network", any(test, feature = "testing")))]
    /// Allows customising the mock Routing client before logging into the network.
    pub fn login_with_hook<F>(
        acc_locator: &str,
        acc_password: &str,
        el_handle: Handle,
        core_tx: AuthMsgTx,
        net_tx: NetworkTx,
        routing_wrapper_fn: F,
    ) -> Result<Self, AuthError>
    where
        F: Fn(Routing) -> Routing,
    {
        Self::login_impl(
            acc_locator.as_bytes(),
            acc_password.as_bytes(),
            el_handle,
            core_tx,
            net_tx,
            routing_wrapper_fn,
        )
    }

    fn login_impl<F>(
        acc_locator: &[u8],
        acc_password: &[u8],
        el_handle: Handle,
        core_tx: AuthMsgTx,
        net_tx: NetworkTx,
        routing_wrapper_fn: F,
    ) -> Result<Self, AuthError>
    where
        F: Fn(Routing) -> Routing,
    {
        trace!("Attempting to log into an acc.");

        let (password, keyword, pin) = utils::derive_secrets(acc_locator, acc_password);

        let acc_loc = Account::generate_network_id(&keyword, &pin)?;
        let user_cred = UserCred::new(password, pin);

        let dst = Authority::NaeManager(acc_loc);

        let (acc_content, acc_version) = {
            trace!("Creating throw-away routing getter for account packet.");
            let (mut routing, routing_rx) = setup_routing(None, None, None)?;
            routing = routing_wrapper_fn(routing);

            let msg_id = MessageId::new();
            let val = routing
                .get_mdata_value(
                    dst,
                    acc_loc,
                    TYPE_TAG_SESSION_PACKET,
                    ACC_LOGIN_ENTRY_KEY.to_owned(),
                    msg_id,
                )
                .map_err(CoreError::from)
                .and_then(|_| wait_for_response!(routing_rx, Response::GetMDataValue, msg_id))
                .map_err(AuthError::from)
                .map_err(|e| {
                    warn!("Could not fetch account from the Network: {:?}", e);
                    e
                })?;
            (val.content, val.entry_version)
        };

        let acc = match deserialise::<AccountPacket>(&acc_content)? {
            AccountPacket::AccPkt(acc_content)
            | AccountPacket::WithInvitation {
                acc_pkt: acc_content,
                ..
            } => Account::decrypt(&acc_content, &user_cred.password, &user_cred.pin)?,
        };

        let id_packet = acc.maid_keys.clone().into();

        let pub_key = PublicKey::from(acc.maid_keys.bls_pk);
        let cm_addr = Authority::ClientManager(XorName::from(pub_key));

        trace!("Creating an actual routing...");
        let (mut routing, routing_rx) = setup_routing(
            Some(id_packet),
            Some(NewFullId::Client(acc.maid_keys.clone().into())),
            None,
        )?;
        routing = routing_wrapper_fn(routing);

        let joiner = spawn_routing_thread(routing_rx, core_tx.clone(), net_tx.clone());

        Ok(AuthClient {
            inner: Rc::new(RefCell::new(ClientInner::new(
                el_handle,
                routing,
                HashMap::with_capacity(10),
                LruCache::new(IMMUT_DATA_CACHE_SIZE),
                Duration::from_secs(REQUEST_TIMEOUT_SECS),
                joiner,
                core_tx,
                net_tx,
            ))),
            auth_inner: Rc::new(RefCell::new(AuthInner {
                acc,
                acc_loc,
                user_cred,
                cm_addr,
                session_packet_version: acc_version,
            })),
        })
    }

    /// Get Maidsafe specific configuration's Root Directory ID if available in
    /// account packet used for current login.
    pub fn config_root_dir(&self) -> MDataInfo {
        let auth_inner = self.auth_inner.borrow();
        auth_inner.acc.config_root.clone()
    }

    /// Replaces the config root reference in the account packet.
    /// Returns `false` if it wasn't updated.
    /// Doesn't actually modify the session packet - you should call
    /// `update_account_packet` afterwards to actually update it on the
    /// network.
    pub fn set_config_root_dir(&self, dir: MDataInfo) -> bool {
        trace!("Setting configuration root Dir ID.");

        let mut auth_inner = self.auth_inner.borrow_mut();
        let acc = &mut auth_inner.acc;

        if acc.config_root != dir {
            acc.config_root = dir;
            true
        } else {
            false
        }
    }

    /// Get User's Access Container if available in account packet used for
    /// current login
    pub fn access_container(&self) -> MDataInfo {
        let auth_inner = self.auth_inner.borrow();
        auth_inner.acc.access_container.clone()
    }

    /// Replaces the config root reference in the account packet.
    /// Returns `false` if it wasn't updated.
    /// Doesn't actually modify the session packet - you should call
    /// `update_account_packet` afterwards to actually update it on the
    /// network.
    pub fn set_access_container(&self, dir: MDataInfo) -> bool {
        trace!("Setting user root Dir ID.");

        let mut auth_inner = self.auth_inner.borrow_mut();
        let account = &mut auth_inner.acc;

        if account.access_container != dir {
            account.access_container = dir;
            true
        } else {
            false
        }
    }

    fn prepare_account_packet_update(
        account: &Account,
        keys: &UserCred,
        entry_version: u64,
    ) -> Result<BTreeMap<Vec<u8>, EntryAction>, AuthError> {
        let encrypted_account = account.encrypt(&keys.password, &keys.pin)?;
        let content = serialise(&AccountPacket::AccPkt(encrypted_account))?;
        Ok(btree_map![
            ACC_LOGIN_ENTRY_KEY.to_owned() => EntryAction::Update(Value {
                content,
                entry_version,
            })
        ])
    }

    /// Updates user's account packet.
    pub fn update_account_packet(&self) -> Box<AuthFuture<()>> {
        trace!("Updating account packet.");

        let entry_version = {
            let mut auth_inner = self.auth_inner.borrow_mut();
            auth_inner.session_packet_version += 1;
            auth_inner.session_packet_version
        };

        let auth_inner = self.auth_inner.borrow();
        let update = {
            let account = &auth_inner.acc;
            let keys = &auth_inner.user_cred;

            fry!(Self::prepare_account_packet_update(
                account,
                keys,
                entry_version,
            ))
        };

        let data_name = auth_inner.acc_loc;

        self.mutate_mdata_entries(data_name, TYPE_TAG_SESSION_PACKET, update)
            .map_err(AuthError::from)
            .into_box()
    }

    /// Returns the current status of std/root dirs creation.
    pub fn std_dirs_created(&self) -> bool {
        let auth_inner = self.auth_inner.borrow();
        auth_inner.acc.root_dirs_created
    }

    /// Sets the current status of std/root dirs creation.
    pub fn set_std_dirs_created(&self, val: bool) {
        let mut auth_inner = self.auth_inner.borrow_mut();
        let account = &mut auth_inner.acc;
        account.root_dirs_created = val;
    }
}

impl Client for AuthClient {
    type MsgType = ();

    fn full_id(&self) -> Option<FullId> {
        let auth_inner = self.auth_inner.borrow();
        Some(auth_inner.acc.maid_keys.clone().into())
    }

    fn full_id_new(&self) -> Option<NewFullId> {
        let auth_inner = self.auth_inner.borrow();
        Some(NewFullId::Client(ClientKeys::into(
            auth_inner.acc.maid_keys.clone(),
        )))
    }

    fn config(&self) -> Option<BootstrapConfig> {
        None
    }

    fn cm_addr(&self) -> Option<Authority<XorName>> {
        let auth_inner = self.auth_inner.borrow();
        Some(auth_inner.cm_addr)
    }

    fn inner(&self) -> Rc<RefCell<ClientInner<Self, Self::MsgType>>> {
        self.inner.clone()
    }

    fn public_encryption_key(&self) -> Option<box_::PublicKey> {
        let auth_inner = self.auth_inner.borrow();
        Some(auth_inner.acc.maid_keys.enc_pk)
    }

    fn secret_encryption_key(&self) -> Option<shared_box::SecretKey> {
        let auth_inner = self.auth_inner.borrow();
        Some(auth_inner.acc.maid_keys.enc_sk.clone())
    }

    fn public_signing_key(&self) -> Option<sign::PublicKey> {
        let auth_inner = self.auth_inner.borrow();
        Some(auth_inner.acc.maid_keys.sign_pk)
    }

    fn secret_signing_key(&self) -> Option<shared_sign::SecretKey> {
        let auth_inner = self.auth_inner.borrow();
        Some(auth_inner.acc.maid_keys.sign_sk.clone())
    }

    fn secret_symmetric_key(&self) -> Option<shared_secretbox::Key> {
        let auth_inner = self.auth_inner.borrow();
        Some(auth_inner.acc.maid_keys.enc_key.clone())
    }

    fn public_bls_key(&self) -> Option<threshold_crypto::PublicKey> {
        let auth_inner = self.auth_inner.borrow();
        Some(auth_inner.acc.maid_keys.bls_pk)
    }

    fn secret_bls_key(&self) -> Option<threshold_crypto::SecretKey> {
        let auth_inner = self.auth_inner.borrow();
        Some(auth_inner.acc.maid_keys.bls_sk.clone())
    }

    fn owner_key(&self) -> Option<PublicKey> {
        let auth_inner = self.auth_inner.borrow();
        Some(PublicKey::from(auth_inner.acc.maid_keys.bls_pk))
    }

    fn compose_message(&self, request: Request) -> Message {
        let auth_inner = self.auth_inner.borrow();
        let message_id = MessageId::new();

        let sig = auth_inner
            .acc
            .maid_keys
            .bls_sk
            .sign(&unwrap!(bincode::serialize(&(&request, message_id))));

        Message::Request {
            request,
            message_id,
            signature: Some(Signature::from(sig)),
        }
    }
}

impl fmt::Debug for AuthClient {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Safe Authenticator Client")
    }
}

impl Clone for AuthClient {
    fn clone(&self) -> Self {
        AuthClient {
            inner: Rc::clone(&self.inner),
            auth_inner: Rc::clone(&self.auth_inner),
        }
    }
}

struct AuthInner {
    acc: Account,
    acc_loc: XorName,
    user_cred: UserCred,
    cm_addr: Authority<XorName>,
    session_packet_version: u64,
}

// ------------------------------------------------------------
// Helper Struct
// ------------------------------------------------------------

#[derive(Clone)]
struct UserCred {
    pin: Vec<u8>,
    password: Vec<u8>,
}

impl UserCred {
    fn new(password: Vec<u8>, pin: Vec<u8>) -> UserCred {
        UserCred { pin, password }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::sync::mpsc;
    use routing::ClientError;
    use safe_core::utils::test_utils::{finish, setup_client};
    use safe_core::{utils, CoreError, DIR_TAG};
    use tokio_core::reactor::Core;
    use AuthMsgTx;

    // Test account creation.
    // It should succeed the first time and fail the second time with the same secrets.
    #[test]
    fn registered_client() {
        let el = unwrap!(Core::new());
        let (core_tx, _): (AuthMsgTx, _) = mpsc::unbounded();
        let (net_tx, _) = mpsc::unbounded();

        let sec_0 = unwrap!(utils::generate_random_string(10));
        let sec_1 = unwrap!(utils::generate_random_string(10));
        let inv = unwrap!(utils::generate_random_string(10));

        // Account creation for the 1st time - should succeed
        let _ = unwrap!(AuthClient::registered(
            &sec_0,
            &sec_1,
            &inv,
            el.handle(),
            core_tx.clone(),
            net_tx.clone(),
        ));

        // Account creation - same secrets - should fail
        match AuthClient::registered(&sec_0, &sec_1, &inv, el.handle(), core_tx, net_tx) {
            Ok(_) => panic!("Account name hijacking should fail"),
            Err(AuthError::CoreError(CoreError::RoutingClientError(
                ClientError::AccountExists,
            ))) => (),
            Err(err) => panic!("{:?}", err),
        }
    }

    // Test creating and logging in to an account on the network.
    #[test]
    fn login() {
        let sec_0 = unwrap!(utils::generate_random_string(10));
        let sec_1 = unwrap!(utils::generate_random_string(10));
        let inv = unwrap!(utils::generate_random_string(10));

        setup_client(
            &(),
            |el_h, core_tx, net_tx| {
                match AuthClient::login(
                    &sec_0,
                    &sec_1,
                    el_h.clone(),
                    core_tx.clone(),
                    net_tx.clone(),
                ) {
                    Err(AuthError::CoreError(CoreError::RoutingClientError(
                        ClientError::NoSuchAccount,
                    ))) => (),
                    x => panic!("Unexpected Login outcome: {:?}", x),
                }
                AuthClient::registered(&sec_0, &sec_1, &inv, el_h, core_tx, net_tx)
            },
            |_| finish(),
        );

        setup_client(
            &(),
            |el_h, core_tx, net_tx| AuthClient::login(&sec_0, &sec_1, el_h, core_tx, net_tx),
            |_| finish(),
        );
    }

    // Test logging in using a seeded account.
    #[test]
    fn seeded_login() {
        let invalid_seed = String::from("123");
        {
            let el = unwrap!(Core::new());
            let (core_tx, _): (AuthMsgTx, _) = mpsc::unbounded();
            let (net_tx, _) = mpsc::unbounded();

            match AuthClient::registered_with_seed(&invalid_seed, el.handle(), core_tx, net_tx) {
                Err(AuthError::CoreError(CoreError::Unexpected(_))) => (),
                _ => panic!("Expected a failure"),
            }
        }
        {
            let el = unwrap!(Core::new());
            let (core_tx, _): (AuthMsgTx, _) = mpsc::unbounded();
            let (net_tx, _) = mpsc::unbounded();

            match AuthClient::login_with_seed(&invalid_seed, el.handle(), core_tx, net_tx) {
                Err(AuthError::CoreError(CoreError::Unexpected(_))) => (),
                _ => panic!("Expected a failure"),
            }
        }

        let seed = unwrap!(utils::generate_random_string(30));

        setup_client(
            &(),
            |el_h, core_tx, net_tx| {
                match AuthClient::login_with_seed(
                    &seed,
                    el_h.clone(),
                    core_tx.clone(),
                    net_tx.clone(),
                ) {
                    Err(AuthError::CoreError(CoreError::RoutingClientError(
                        ClientError::NoSuchAccount,
                    ))) => (),
                    x => panic!("Unexpected Login outcome: {:?}", x),
                }
                AuthClient::registered_with_seed(&seed, el_h, core_tx, net_tx)
            },
            |_| finish(),
        );

        setup_client(
            &(),
            |el_h, core_tx, net_tx| AuthClient::login_with_seed(&seed, el_h, core_tx, net_tx),
            |_| finish(),
        );
    }

    // Test creation of an access container.
    #[test]
    fn access_container_creation() {
        let sec_0 = unwrap!(utils::generate_random_string(10));
        let sec_1 = unwrap!(utils::generate_random_string(10));
        let inv = unwrap!(utils::generate_random_string(10));

        let dir = unwrap!(MDataInfo::random_private(DIR_TAG));
        let dir_clone = dir.clone();

        setup_client(
            &(),
            |el_h, core_tx, net_tx| {
                AuthClient::registered(&sec_0, &sec_1, &inv, el_h, core_tx, net_tx)
            },
            move |client| {
                assert!(client.set_access_container(dir));
                client.update_account_packet()
            },
        );

        setup_client(
            &(),
            |el_h, core_tx, net_tx| AuthClient::login(&sec_0, &sec_1, el_h, core_tx, net_tx),
            move |client| {
                let got_dir = client.access_container();
                assert_eq!(got_dir, dir_clone);
                finish()
            },
        );
    }

    // Test setting the configuration root directory.
    #[test]
    fn config_root_dir_creation() {
        let sec_0 = unwrap!(utils::generate_random_string(10));
        let sec_1 = unwrap!(utils::generate_random_string(10));
        let inv = unwrap!(utils::generate_random_string(10));

        let dir = unwrap!(MDataInfo::random_private(DIR_TAG));
        let dir_clone = dir.clone();

        setup_client(
            &(),
            |el_h, core_tx, net_tx| {
                AuthClient::registered(&sec_0, &sec_1, &inv, el_h, core_tx, net_tx)
            },
            move |client| {
                assert!(client.set_config_root_dir(dir));
                client.update_account_packet()
            },
        );

        setup_client(
            &(),
            |el_h, core_tx, net_tx| AuthClient::login(&sec_0, &sec_1, el_h, core_tx, net_tx),
            move |client| {
                let got_dir = client.config_root_dir();
                assert_eq!(got_dir, dir_clone);
                finish()
            },
        );
    }

    // Test restarting routing after a network disconnect.
    #[cfg(feature = "mock-network")]
    #[test]
    fn restart_routing() {
        use crate::test_utils::random_client_with_net_obs;
        use futures;
        use maidsafe_utilities::thread;
        use safe_core::NetworkEvent;
        use std::sync::mpsc;

        let (tx, rx) = mpsc::channel();
        let (hook, keep_alive) = futures::oneshot();

        let _joiner = thread::named("Network Observer", move || {
            match unwrap!(rx.recv()) {
                NetworkEvent::Disconnected => (),
                x => panic!("Unexpected network event: {:?}", x),
            }
            match unwrap!(rx.recv()) {
                NetworkEvent::Connected => (),
                x => panic!("Unexpected network event: {:?}", x),
            }
            let _ = hook.send(());
        });

        random_client_with_net_obs(
            move |net_event| unwrap!(tx.send(net_event)),
            move |client| {
                client.simulate_network_disconnect();
                unwrap!(client.restart_routing());
                keep_alive
            },
        );
    }

    // Test that a `RequestTimeout` error is returned on network timeout.
    #[cfg(feature = "mock-network")]
    #[test]
    fn timeout() {
        use crate::test_utils::random_client;
        use safe_nd::ImmutableData;
        use std::time::Duration;

        // Get
        random_client(|client| {
            let client2 = client.clone();

            client.set_simulate_timeout(true);
            client.set_timeout(Duration::from_millis(250));

            client
                .get_idata(new_rand::random())
                .then(|result| match result {
                    Ok(_) => panic!("Unexpected success"),
                    Err(CoreError::RequestTimeout) => Ok::<_, CoreError>(()),
                    Err(err) => panic!("Unexpected {:?}", err),
                })
                .then(move |result| {
                    unwrap!(result);

                    let data = unwrap!(utils::generate_random_vector(4));
                    let data = ImmutableData::new(data);

                    client2.put_idata(data)
                })
                .then(|result| match result {
                    Ok(_) => panic!("Unexpected success"),
                    Err(CoreError::RequestTimeout) => Ok::<_, CoreError>(()),
                    Err(err) => panic!("Unexpected {:?}", err),
                })
        })
    }
}
