// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::errors::AuthError;
#[cfg(any(test, feature = "testing"))]
use crate::test_utils::divide_seed;
use crate::AuthFuture;
use crate::AuthMsgTx;
use futures::future;
use futures::Future;
use log::trace;
use lru_cache::LruCache;
use rand::rngs::StdRng;
use rand::{thread_rng, CryptoRng, Rng, SeedableRng};
use safe_core::client::account::Account;
use safe_core::client::{
    attempt_bootstrap, req, AuthActions, Inner, SafeKey, IMMUT_DATA_CACHE_SIZE,
};
use safe_core::config_handler::Config;
use safe_core::crypto::{shared_box, shared_secretbox};
use safe_core::fry;
use safe_core::ipc::BootstrapConfig;
use safe_core::{utils, Client, ClientKeys, ConnectionManager, CoreError, MDataInfo, NetworkTx};
use safe_nd::{
    ClientFullId, LoginPacket, Message, MessageId, PublicId, PublicKey, Request, Response, XorName,
};
use std::cell::RefCell;
use std::fmt;
use std::rc::Rc;
use std::time::Duration;
use tiny_keccak::sha3_256;
use tokio::runtime::current_thread::{block_on_all, Handle};
use unwrap::unwrap;

/// Client object used by `safe_authenticator`.
pub struct AuthClient {
    inner: Rc<RefCell<Inner<AuthClient, ()>>>,
    auth_inner: Rc<RefCell<AuthInner>>,
}

impl AuthClient {
    /// This is a Gateway function to the Maidsafe network. This will help
    /// create a fresh acc for the user in the SAFE-network.
    pub(crate) fn registered(
        acc_locator: &str,
        acc_password: &str,
        client_id: ClientFullId,
        el_handle: Handle,
        core_tx: AuthMsgTx,
        net_tx: NetworkTx,
    ) -> Result<Self, AuthError> {
        Self::registered_impl(
            acc_locator.as_bytes(),
            acc_password.as_bytes(),
            client_id,
            el_handle,
            core_tx,
            net_tx,
            None::<&mut StdRng>,
            |cm| cm,
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
        client_id: ClientFullId,
        el_handle: Handle,
        core_tx: AuthMsgTx,
        net_tx: NetworkTx,
    ) -> Result<Self, AuthError> {
        let arr = divide_seed(seed)?;

        let seed = sha3_256(seed.as_bytes());
        let mut rng = StdRng::from_seed(seed);

        Self::registered_impl(
            arr[0],
            arr[1],
            client_id,
            el_handle,
            core_tx,
            net_tx,
            Some(&mut rng),
            |cm| cm,
        )
    }

    #[cfg(all(feature = "mock-network", any(test, feature = "testing")))]
    /// Allows customising the mock client before registering a new account.
    pub fn registered_with_hook<F>(
        acc_locator: &str,
        acc_password: &str,
        client_id: ClientFullId,
        el_handle: Handle,
        core_tx: AuthMsgTx,
        net_tx: NetworkTx,
        connection_manager_wrapper_fn: F,
    ) -> Result<Self, AuthError>
    where
        F: Fn(ConnectionManager) -> ConnectionManager,
    {
        Self::registered_impl(
            acc_locator.as_bytes(),
            acc_password.as_bytes(),
            client_id,
            el_handle,
            core_tx,
            net_tx,
            None::<&mut StdRng>,
            connection_manager_wrapper_fn,
        )
    }

    // This is a Gateway function to the Maidsafe network. This will help create a fresh acc for the
    // user in the SAFE-network.
    #[allow(clippy::too_many_arguments)]
    fn registered_impl<F, R>(
        acc_locator: &[u8],
        acc_password: &[u8],
        client_id: ClientFullId,
        el_handle: Handle,
        core_tx: AuthMsgTx,
        net_tx: NetworkTx,
        seed: Option<&mut R>,
        connection_manager_wrapper_fn: F,
    ) -> Result<Self, AuthError>
    where
        R: CryptoRng + SeedableRng + Rng,
        F: Fn(ConnectionManager) -> ConnectionManager,
    {
        trace!("Creating an account.");

        let (password, keyword, pin) = utils::derive_secrets(acc_locator, acc_password);

        let acc_locator = Account::generate_network_id(&keyword, &pin)?;
        let user_cred = UserCred::new(password, pin);
        let mut maid_keys = match seed {
            Some(seed) => ClientKeys::new(seed),
            None => ClientKeys::new(&mut thread_rng()),
        };
        maid_keys.client_id = client_id;

        let client_safe_key = maid_keys.client_safe_key();

        let acc = Account::new(maid_keys)?;
        let acc_ciphertext = acc.encrypt(&user_cred.password, &user_cred.pin)?;

        let transient_id = create_client_id(&acc_locator.0);

        let sig = transient_id.sign(&acc_ciphertext);
        let transient_pk = transient_id.public_id().public_key();
        let new_login_packet = LoginPacket::new(acc_locator, *transient_pk, acc_ciphertext, sig)?;

        // Create the connection manager
        let mut connection_manager =
            attempt_bootstrap(&Config::new().quic_p2p, &net_tx, client_safe_key.clone())?;

        connection_manager = connection_manager_wrapper_fn(connection_manager);

        let response = req(
            &mut connection_manager,
            Request::CreateLoginPacket(new_login_packet),
            &client_safe_key,
        )?;

        match response {
            Response::Mutation(res) => res?,
            _ => return Err(AuthError::from("Unexpected response")),
        };

        Ok(Self {
            inner: Rc::new(RefCell::new(Inner::new(
                el_handle,
                connection_manager,
                LruCache::new(IMMUT_DATA_CACHE_SIZE),
                Duration::from_secs(180), // FIXME //(REQUEST_TIMEOUT_SECS),
                core_tx,
                net_tx,
            ))),
            auth_inner: Rc::new(RefCell::new(AuthInner {
                acc,
                acc_loc: acc_locator,
                user_cred,
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
    /// Allows customising the mock connection manager before logging into the network.
    pub fn login_with_hook<F>(
        acc_locator: &str,
        acc_password: &str,
        el_handle: Handle,
        core_tx: AuthMsgTx,
        net_tx: NetworkTx,
        connection_manager_wrapper_fn: F,
    ) -> Result<Self, AuthError>
    where
        F: Fn(ConnectionManager) -> ConnectionManager,
    {
        Self::login_impl(
            acc_locator.as_bytes(),
            acc_password.as_bytes(),
            el_handle,
            core_tx,
            net_tx,
            connection_manager_wrapper_fn,
        )
    }

    fn login_impl<F>(
        acc_locator: &[u8],
        acc_password: &[u8],
        el_handle: Handle,
        core_tx: AuthMsgTx,
        net_tx: NetworkTx,
        connection_manager_wrapper_fn: F,
    ) -> Result<Self, AuthError>
    where
        F: Fn(ConnectionManager) -> ConnectionManager,
    {
        trace!("Attempting to log into an acc.");

        let (password, keyword, pin) = utils::derive_secrets(acc_locator, acc_password);

        let acc_locator = Account::generate_network_id(&keyword, &pin)?;

        let client_full_id = create_client_id(&acc_locator.0);
        let client_pk = *client_full_id.public_id().public_key();
        let client_full_id = SafeKey::client(client_full_id);

        let user_cred = UserCred::new(password, pin);

        // Create the connection manager
        let mut connection_manager =
            attempt_bootstrap(&Config::new().quic_p2p, &net_tx, client_full_id.clone())?;
        connection_manager = connection_manager_wrapper_fn(connection_manager);

        let (account_buffer, signature) = {
            trace!("Using throw-away connection group to get a login packet.");

            let response = req(
                &mut connection_manager,
                Request::GetLoginPacket(acc_locator),
                &client_full_id,
            )?;

            block_on_all(connection_manager.disconnect(&client_full_id.public_id()))?;

            match response {
                Response::GetLoginPacket(res) => res?,
                _ => return Err(AuthError::from("Unexpected response")),
            }
        };

        client_pk.verify(&signature, account_buffer.as_slice())?;
        let acc = Account::decrypt(
            account_buffer.as_slice(),
            &user_cred.password,
            &user_cred.pin,
        )?;

        let id_packet = acc.maid_keys.client_safe_key();

        trace!("Creating an actual client...");

        block_on_all(connection_manager.bootstrap(id_packet))?;

        Ok(Self {
            inner: Rc::new(RefCell::new(Inner::new(
                el_handle,
                connection_manager,
                LruCache::new(IMMUT_DATA_CACHE_SIZE),
                Duration::from_secs(180), // REQUEST_TIMEOUT_SECS), //FIXME
                core_tx,
                net_tx,
            ))),
            auth_inner: Rc::new(RefCell::new(AuthInner {
                acc,
                acc_loc: acc_locator,
                user_cred,
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

        if acc.config_root == dir {
            false
        } else {
            acc.config_root = dir;
            true
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

        if account.access_container == dir {
            false
        } else {
            account.access_container = dir;
            true
        }
    }

    fn prepare_account_packet_update(
        acc_loc: XorName,
        account: &Account,
        keys: &UserCred,
        full_id: &SafeKey,
    ) -> Result<LoginPacket, AuthError> {
        let encrypted_account = account.encrypt(&keys.password, &keys.pin)?;

        let sig = full_id.sign(&encrypted_account);
        let client_pk = match full_id.public_id() {
            PublicId::Client(id) => *id.public_key(),
            // FIXME
            x => panic!("Unexpected ID type {:?}", x),
        };
        LoginPacket::new(acc_loc, client_pk, encrypted_account, sig).map_err(AuthError::from)
    }

    /// Updates user's account packet.
    pub fn update_account_packet(&self) -> Box<AuthFuture<()>> {
        trace!("Updating account packet.");

        let auth_inner = self.auth_inner.borrow();
        let account = &auth_inner.acc;
        let keys = &auth_inner.user_cred;
        let acc_loc = &auth_inner.acc_loc;
        let account_packet_id = SafeKey::client(create_client_id(&acc_loc.0));
        let account_pub_id = account_packet_id.public_id();
        let updated_packet = r#try!(Self::prepare_account_packet_update(
            *acc_loc,
            account,
            keys,
            &account_packet_id
        ));

        let mut client_inner = self.inner.borrow_mut();

        let mut cm = client_inner.cm().clone();
        let mut cm2 = cm.clone();
        let mut cm4 = cm.clone();

        let message_id = MessageId::new();
        let request = Request::UpdateLoginPacket(updated_packet);
        let signature =
            account_packet_id.sign(&unwrap!(bincode::serialize(&(&request, message_id))));

        let account_pub_id2 = account_pub_id.clone();

        Box::new(
            future::lazy(move || cm.bootstrap(account_packet_id))
                .and_then(move |_| {
                    cm2.send(
                        &account_pub_id,
                        &Message::Request {
                            request,
                            message_id,
                            signature: Some(signature),
                        },
                    )
                })
                .and_then(move |resp| match resp {
                    Response::Mutation(res) => res.map_err(CoreError::from),
                    _ => Err(CoreError::from("Unexpected response")),
                })
                .and_then(move |_resp| cm4.disconnect(&account_pub_id2))
                .map_err(AuthError::from),
        )
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

fn create_client_id(seeder: &[u8]) -> ClientFullId {
    let seed = sha3_256(&seeder);
    let mut rng = StdRng::from_seed(seed);
    ClientFullId::new_bls(&mut rng)
}

impl AuthActions for AuthClient {}

impl Client for AuthClient {
    type Context = ();

    fn full_id(&self) -> SafeKey {
        let auth_inner = self.auth_inner.borrow();
        auth_inner.acc.maid_keys.client_safe_key()
    }

    fn owner_key(&self) -> PublicKey {
        self.public_key()
    }

    fn config(&self) -> Option<BootstrapConfig> {
        None
    }

    fn inner(&self) -> Rc<RefCell<Inner<Self, Self::Context>>> {
        self.inner.clone()
    }

    fn public_encryption_key(&self) -> threshold_crypto::PublicKey {
        let auth_inner = self.auth_inner.borrow();
        auth_inner.acc.maid_keys.enc_public_key
    }

    fn secret_encryption_key(&self) -> shared_box::SecretKey {
        let auth_inner = self.auth_inner.borrow();
        auth_inner.acc.maid_keys.enc_secret_key.clone()
    }

    fn secret_symmetric_key(&self) -> shared_secretbox::Key {
        let auth_inner = self.auth_inner.borrow();
        auth_inner.acc.maid_keys.enc_key.clone()
    }
}

impl fmt::Debug for AuthClient {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Safe Authenticator Client")
    }
}

impl Clone for AuthClient {
    fn clone(&self) -> Self {
        Self {
            inner: Rc::clone(&self.inner),
            auth_inner: Rc::clone(&self.auth_inner),
        }
    }
}

struct AuthInner {
    acc: Account,
    acc_loc: XorName,
    user_cred: UserCred,
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
    fn new(password: Vec<u8>, pin: Vec<u8>) -> Self {
        Self { pin, password }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::channel::mpsc;
    use futures::Future;
    use safe_core::client::test_create_balance;
    use safe_core::ok;
    use safe_core::utils::test_utils::{
        calculate_new_balance, finish, gen_client_id, random_client, setup_client,
    };
    use safe_core::{utils, CoreError, DIR_TAG};
    use safe_nd::{Coins, Error as SndError, MDataKind};
    use std::str::FromStr;
    use tokio::runtime::current_thread::Runtime;
    use AuthMsgTx;

    // Test account creation.
    // It should succeed the first time and fail the second time with the same secrets.
    #[test]
    fn registered_client() {
        let el = unwrap!(Runtime::new());
        let (core_tx, _): (AuthMsgTx, _) = mpsc::unbounded();
        let (net_tx, _) = mpsc::unbounded();

        let sec_0 = unwrap!(utils::generate_random_string(10));
        let sec_1 = unwrap!(utils::generate_random_string(10));
        let client_id = gen_client_id();
        unwrap!(test_create_balance(
            &client_id,
            unwrap!(Coins::from_str("10"))
        ));

        // Account creation for the 1st time - should succeed
        let _ = unwrap!(AuthClient::registered(
            &sec_0,
            &sec_1,
            client_id.clone(),
            el.handle(),
            core_tx.clone(),
            net_tx.clone(),
        ));

        // Account creation - same secrets - should fail
        match AuthClient::registered(&sec_0, &sec_1, client_id, el.handle(), core_tx, net_tx) {
            Ok(_) => panic!("Account name hijacking should fail"),
            Err(AuthError::SndError(SndError::LoginPacketExists)) => (),
            Err(err) => panic!("{:?}", err),
        }
    }

    // Test creating and logging in to an account on the network.
    #[test]
    fn login() {
        let sec_0 = unwrap!(utils::generate_random_string(10));
        let sec_1 = unwrap!(utils::generate_random_string(10));
        let client_id = gen_client_id();

        unwrap!(test_create_balance(
            &client_id,
            unwrap!(Coins::from_str("10"))
        ));

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
                    Err(AuthError::SndError(SndError::NoSuchLoginPacket)) => (),
                    x => panic!("Unexpected Login outcome: {:?}", x),
                }
                AuthClient::registered(&sec_0, &sec_1, client_id, el_h, core_tx, net_tx)
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
            let el = unwrap!(Runtime::new());
            let (core_tx, _): (AuthMsgTx, _) = mpsc::unbounded();
            let (net_tx, _) = mpsc::unbounded();
            let client_id = gen_client_id();

            match AuthClient::registered_with_seed(
                &invalid_seed,
                client_id,
                el.handle(),
                core_tx,
                net_tx,
            ) {
                Err(AuthError::Unexpected(_)) => (),
                _ => panic!("Expected a failure"),
            }
        }
        {
            let el = unwrap!(Runtime::new());
            let (core_tx, _): (AuthMsgTx, _) = mpsc::unbounded();
            let (net_tx, _) = mpsc::unbounded();

            match AuthClient::login_with_seed(&invalid_seed, el.handle(), core_tx, net_tx) {
                Err(AuthError::Unexpected(_)) => (),
                _ => panic!("Expected a failure"),
            }
        }

        let seed = unwrap!(utils::generate_random_string(30));
        let client_id = gen_client_id();

        unwrap!(test_create_balance(
            &client_id,
            unwrap!(Coins::from_str("10"))
        ));

        setup_client(
            &(),
            |el_h, core_tx, net_tx| {
                match AuthClient::login_with_seed(
                    &seed,
                    el_h.clone(),
                    core_tx.clone(),
                    net_tx.clone(),
                ) {
                    Err(AuthError::SndError(SndError::NoSuchLoginPacket)) => (),
                    x => panic!("Unexpected Login outcome: {:?}", x),
                }
                AuthClient::registered_with_seed(&seed, client_id, el_h, core_tx, net_tx)
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
        let client_id = gen_client_id();

        unwrap!(test_create_balance(
            &client_id,
            unwrap!(Coins::from_str("10"))
        ));

        let dir = unwrap!(MDataInfo::random_private(MDataKind::Seq, DIR_TAG));
        let dir_clone = dir.clone();

        setup_client(
            &(),
            |el_h, core_tx, net_tx| {
                AuthClient::registered(&sec_0, &sec_1, client_id, el_h, core_tx, net_tx)
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
        let client_id = gen_client_id();

        unwrap!(test_create_balance(
            &client_id,
            unwrap!(Coins::from_str("10"))
        ));

        let dir = unwrap!(MDataInfo::random_private(MDataKind::Seq, DIR_TAG));
        let dir_clone = dir.clone();

        setup_client(
            &(),
            |el_h, core_tx, net_tx| {
                AuthClient::registered(&sec_0, &sec_1, client_id, el_h, core_tx, net_tx)
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
    #[ignore] // FIXME: ignoring this temporarily until we figure out the disconnection semantics
    #[test]
    fn restart_network() {
        use crate::test_utils::random_client_with_net_obs;
        use futures;
        use safe_core::NetworkEvent;
        use std::sync::mpsc;
        use std::thread;

        let (tx, rx) = mpsc::channel();
        let (hook, keep_alive) = futures::oneshot();

        let _joiner = unwrap!(thread::Builder::new()
            .name(String::from("Network Observer"))
            .spawn(move || {
                match unwrap!(rx.recv()) {
                    NetworkEvent::Disconnected => (),
                    x => panic!("Unexpected network event: {:?}", x),
                }
                match unwrap!(rx.recv()) {
                    NetworkEvent::Connected => (),
                    x => panic!("Unexpected network event: {:?}", x),
                }
                let _ = hook.send(());
            }));

        random_client_with_net_obs(
            move |net_event| unwrap!(tx.send(net_event)),
            move |client| {
                client.simulate_network_disconnect();
                unwrap!(client.restart_network());
                keep_alive
            },
        );
    }

    // Test that a `RequestTimeout` error is returned on network timeout.
    #[cfg(feature = "mock-network")]
    #[ignore]
    #[test]
    fn timeout() {
        use crate::test_utils::random_client;
        use safe_nd::{IDataAddress, PubImmutableData};
        use std::time::Duration;

        // Get
        random_client(|client| {
            let client2 = client.clone();

            client.set_simulate_timeout(true);
            client.set_timeout(Duration::from_millis(250));

            client
                .get_idata(IDataAddress::Pub(rand::random()))
                .then(|result| match result {
                    Ok(_) => panic!("Unexpected success"),
                    Err(CoreError::RequestTimeout) => Ok::<_, CoreError>(()),
                    Err(err) => panic!("Unexpected {:?}", err),
                })
                .then(move |result| {
                    unwrap!(result);

                    let data = unwrap!(utils::generate_random_vector(4));
                    let data = PubImmutableData::new(data);

                    client2.put_idata(data)
                })
                .then(|result| match result {
                    Ok(_) => panic!("Unexpected success"),
                    Err(CoreError::RequestTimeout) => Ok::<_, CoreError>(()),
                    Err(err) => panic!("Unexpected {:?}", err),
                })
        })
    }

    // Create a login packet using some credentials and pass the login packet to a client who stores
    // it on the network and creates a wallet for it. Now calling login using the same credentials
    // should succeed and we must be able to fetch the balance.
    #[test]
    fn create_login_packet_for() {
        let sec_0 = unwrap!(utils::generate_random_string(10));
        let sec_1 = unwrap!(utils::generate_random_string(10));

        let acc_locator: &[u8] = sec_0.as_bytes();
        let acc_password: &[u8] = sec_1.as_bytes();

        let (password, keyword, pin) = utils::derive_secrets(acc_locator, acc_password);

        let acc_loc = unwrap!(Account::generate_network_id(&keyword, &pin));

        let maid_keys = ClientKeys::new(&mut thread_rng());
        let acc = unwrap!(Account::new(maid_keys.clone()));

        let acc_ciphertext = unwrap!(acc.encrypt(&password, &pin));

        let client_full_id = create_client_id(&acc_loc.0);

        let sig = client_full_id.sign(&acc_ciphertext);
        let client_pk = *client_full_id.public_id().public_key();
        let new_login_packet = unwrap!(LoginPacket::new(acc_loc, client_pk, acc_ciphertext, sig));
        let new_login_packet2 = new_login_packet.clone();
        let five_coins = unwrap!(Coins::from_str("5"));
        let client_id = gen_client_id();
        let random_pk = *client_id.public_id().public_key();

        // The `random_client()` initializes the client with 10 coins.
        let start_bal = unwrap!(Coins::from_str("10"));
        // Create a client which has a pre-loaded balance and use it to store the login packet on
        // the network.
        random_client(move |client| {
            let c1 = client.clone();
            let c2 = client.clone();
            let c3 = client.clone();
            let c4 = client.clone();
            client
                .insert_login_packet_for(
                    None,
                    maid_keys.public_key(),
                    five_coins,
                    None,
                    new_login_packet.clone(),
                )
                // Make sure no error occurred.
                .then(move |result| match result {
                    Ok(_transaction) => Ok::<_, CoreError>(()),
                    res => panic!("Unexpected {:?}", res),
                })
                .and_then(move |_| {
                    c1.insert_login_packet_for(
                        None,
                        maid_keys.public_key(),
                        unwrap!(Coins::from_str("3")),
                        None,
                        new_login_packet,
                    )
                })
                // Re-insert to check for refunds for a failed insert_login_packet_for operation
                // The balance is created first, so `BalanceExists` is returned.
                .then(move |result| match result {
                    Err(CoreError::DataError(SndError::BalanceExists)) => Ok::<_, CoreError>(()),
                    res => panic!("Unexpected {:?}", res),
                })
                // For a different balance and an existing login packet
                // `LoginPacketExists` should be returned.
                .and_then(move |_| {
                    c3.insert_login_packet_for(
                        None,
                        random_pk,
                        unwrap!(Coins::from_str("3")),
                        None,
                        new_login_packet2,
                    )
                })
                .then(move |result| match result {
                    Err(CoreError::DataError(SndError::LoginPacketExists)) => {
                        c4.get_balance(Some(&client_id))
                    }
                    res => panic!("Unexpected {:?}", res),
                })
                // The new balance should exist
                .and_then(move |balance| {
                    assert_eq!(balance, unwrap!(Coins::from_str("3")));
                    c2.get_balance(None)
                })
                .and_then(move |balance| {
                    let expected = calculate_new_balance(
                        start_bal,
                        Some(3),
                        Some(unwrap!(Coins::from_str("8"))),
                    );
                    assert_eq!(balance, expected);
                    Ok(())
                })
        });

        setup_client(
            &(),
            |el_h, core_tx, net_tx| AuthClient::login(&sec_0, &sec_1, el_h, core_tx, net_tx),
            move |client| {
                client.get_balance(None).and_then(move |balance| {
                    assert_eq!(balance, five_coins);
                    Ok(())
                })
            },
        );
    }
}
