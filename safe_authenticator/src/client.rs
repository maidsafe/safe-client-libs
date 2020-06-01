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

use async_trait::async_trait;
use futures::lock::Mutex;
use log::trace;
use lru_cache::LruCache;
use rand::{rngs::StdRng, thread_rng, CryptoRng, Rng, SeedableRng};
use safe_core::client::{
    account::Account, attempt_bootstrap, req, AuthActions, Inner, SafeKey, IMMUT_DATA_CACHE_SIZE,
};
use safe_core::{
    config_handler::Config,
    crypto::{shared_box, shared_secretbox},
    ipc::BootstrapConfig,
    utils, Client, ClientKeys, ConnectionManager, CoreError, MDataInfo, NetworkTx,
};
use safe_nd::{
    ClientFullId, LoginPacket, LoginPacketRequest, Message, MessageId, PublicId, PublicKey,
    Request, Response, XorName,
};
use std::{fmt, sync::Arc, time::Duration};
use tiny_keccak::sha3_256;
use unwrap::unwrap;

/// Client object used by `safe_authenticator`.
pub struct AuthClient {
    inner: Arc<Mutex<Inner>>,
    auth_inner: Arc<Mutex<AuthInner>>,
}

impl AuthClient {
    /// This is a Gateway function to the Maidsafe network. This will help
    /// create a fresh acc for the user in the SAFE-network.
    pub(crate) async fn registered(
        acc_locator: &str,
        acc_password: &str,
        client_id: ClientFullId,
        net_tx: NetworkTx,
    ) -> Result<Self, AuthError> {
        Self::registered_impl(
            acc_locator.as_bytes(),
            acc_password.as_bytes(),
            client_id,
            net_tx,
            None::<&mut StdRng>,
            |cm| cm,
        )
        .await
    }

    /// This is one of the Gateway functions to the Maidsafe network, the others being `registered`,
    /// and `login`. This will help create an account given a seed. Everything including both
    /// account secrets and all MAID keys will be deterministically derived from the supplied seed,
    /// so this seed needs to be strong. For ordinary users, it's recommended to use the normal
    /// `registered` function where the secrets can be what's easy to remember for the user while
    /// also being strong.
    #[cfg(any(test, feature = "testing"))]
    pub(crate) async fn registered_with_seed(
        seed: &str,
        client_id: ClientFullId,
        net_tx: NetworkTx,
    ) -> Result<Self, AuthError> {
        let arr = divide_seed(seed)?;

        let seed = sha3_256(seed.as_bytes());
        let mut rng = StdRng::from_seed(seed);

        Self::registered_impl(arr[0], arr[1], client_id, net_tx, Some(&mut rng), |cm| cm).await
    }

    #[cfg(all(feature = "mock-network", any(test, feature = "testing")))]
    /// Allows customising the mock client before registering a new account.
    pub async fn registered_with_hook<F>(
        acc_locator: &str,
        acc_password: &str,
        client_id: ClientFullId,
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
            net_tx,
            None::<&mut StdRng>,
            connection_manager_wrapper_fn,
        )
        .await
    }

    // This is a Gateway function to the Maidsafe network. This will help create a fresh acc for the
    // user in the SAFE-network.
    #[allow(clippy::too_many_arguments)]
    async fn registered_impl<F, R>(
        acc_locator: &[u8],
        acc_password: &[u8],
        client_id: ClientFullId,
        net_tx: NetworkTx,
        seed: Option<&mut R>,
        connection_manager_wrapper_fn: F,
    ) -> Result<Self, AuthError>
    where
        R: CryptoRng + SeedableRng + Rng,
        F: Fn(ConnectionManager) -> ConnectionManager,
    {
        trace!("Creating an account...");

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
            attempt_bootstrap(&Config::new().quic_p2p, &net_tx, client_safe_key.clone()).await?;

        connection_manager = connection_manager_wrapper_fn(connection_manager);

        let response = req(
            &mut connection_manager,
            Request::LoginPacket(LoginPacketRequest::Create(new_login_packet)),
            &client_safe_key,
        )
        .await?;

        match response {
            Response::Mutation(res) => res?,
            _ => return Err(AuthError::from("Unexpected response")),
        };

        Ok(Self {
            inner: Arc::new(Mutex::new(Inner::new(
                connection_manager,
                LruCache::new(IMMUT_DATA_CACHE_SIZE),
                Duration::from_secs(180), // FIXME //(REQUEST_TIMEOUT_SECS),
                net_tx,
            ))),
            auth_inner: Arc::new(Mutex::new(AuthInner {
                acc,
                acc_loc: acc_locator,
                user_cred,
            })),
        })
    }

    /// This is a Gateway function to the Maidsafe network. This will help login to an already
    /// existing account of the user in the SAFE-network.
    pub(crate) async fn login(
        acc_locator: &str,
        acc_password: &str,
        net_tx: NetworkTx,
    ) -> Result<Self, AuthError> {
        Self::auth_client_login_impl(
            acc_locator.as_bytes(),
            acc_password.as_bytes(),
            net_tx,
            |routing| routing,
        )
        .await
    }

    /// Login using seeded account.
    #[cfg(any(test, feature = "testing"))]
    pub(crate) async fn login_with_seed(seed: &str, net_tx: NetworkTx) -> Result<Self, AuthError> {
        let arr = divide_seed(seed)?;
        Self::auth_client_login_impl(arr[0], arr[1], net_tx, |routing| routing).await
    }

    #[cfg(all(feature = "mock-network", any(test, feature = "testing")))]
    /// Allows customising the mock connection manager before logging into the network.
    pub async fn login_with_hook<F>(
        acc_locator: &str,
        acc_password: &str,
        net_tx: NetworkTx,
        connection_manager_wrapper_fn: F,
    ) -> Result<Self, AuthError>
    where
        F: Fn(ConnectionManager) -> ConnectionManager,
    {
        Self::auth_client_login_impl(
            acc_locator.as_bytes(),
            acc_password.as_bytes(),
            net_tx,
            connection_manager_wrapper_fn,
        )
        .await
    }

    async fn auth_client_login_impl<F>(
        acc_locator: &[u8],
        acc_password: &[u8],
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
            attempt_bootstrap(&Config::new().quic_p2p, &net_tx, client_full_id.clone()).await?;
        connection_manager = connection_manager_wrapper_fn(connection_manager);

        let (account_buffer, signature) = {
            trace!("Using throw-away connection group to get a login packet.");

            let response = req(
                &mut connection_manager,
                Request::LoginPacket(LoginPacketRequest::Get(acc_locator)),
                &client_full_id,
            )
            .await?;

            connection_manager
                .disconnect(&client_full_id.public_id())
                .await?;

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

        connection_manager.bootstrap(id_packet).await?;

        Ok(Self {
            inner: Arc::new(Mutex::new(Inner::new(
                connection_manager,
                LruCache::new(IMMUT_DATA_CACHE_SIZE),
                Duration::from_secs(180), // REQUEST_TIMEOUT_SECS), //FIXME
                net_tx,
            ))),
            auth_inner: Arc::new(Mutex::new(AuthInner {
                acc,
                acc_loc: acc_locator,
                user_cred,
            })),
        })
    }

    /// Get Maidsafe specific configuration's Root Directory ID if available in
    /// account packet used for current login.
    pub async fn config_root_dir(&self) -> MDataInfo {
        let auth_inner = self.auth_inner.lock().await;
        auth_inner.acc.config_root.clone()
    }

    /// Replaces the config root reference in the account packet.
    /// Returns `false` if it wasn't updated.
    /// Doesn't actually modify the session packet - you should call
    /// `update_account_packet` afterwards to actually update it on the
    /// network.
    pub async fn set_config_root_dir(&self, dir: MDataInfo) -> bool {
        trace!("Setting configuration root Dir ID.");

        let mut auth_inner = self.auth_inner.lock().await;
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
    pub async fn access_container(&self) -> MDataInfo {
        let auth_inner = self.auth_inner.lock().await;
        auth_inner.acc.access_container.clone()
    }

    /// Replaces the config root reference in the account packet.
    /// Returns `false` if it wasn't updated.
    /// Doesn't actually modify the session packet - you should call
    /// `update_account_packet` afterwards to actually update it on the
    /// network.
    pub async fn set_access_container(&self, dir: MDataInfo) -> bool {
        trace!("Setting user root Dir ID.");

        let mut auth_inner = self.auth_inner.lock().await;
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
    pub async fn update_account_packet(&self) -> Result<(), AuthError> {
        trace!("Updating account packet.");

        let auth_inner = self.auth_inner.lock().await;
        let account = &auth_inner.acc;
        let keys = &auth_inner.user_cred;
        let acc_loc = &auth_inner.acc_loc;
        let account_packet_id = SafeKey::client(create_client_id(&acc_loc.0));
        let account_pub_id = account_packet_id.public_id();
        let updated_packet =
            Self::prepare_account_packet_update(*acc_loc, account, keys, &account_packet_id)?;

        let mut client_inner = self.inner.lock().await;

        let mut cm = client_inner.cm().clone();
        let mut cm2 = cm.clone();
        let mut cm4 = cm.clone();

        let message_id = MessageId::new();
        let request = Request::LoginPacket(LoginPacketRequest::Update(updated_packet));
        let signature =
            account_packet_id.sign(&unwrap!(bincode::serialize(&(&request, message_id))));

        let account_pub_id2 = account_pub_id.clone();

        futures::executor::block_on(cm.bootstrap(account_packet_id))?;

        let resp = futures::executor::block_on(cm2.send(
            &account_pub_id,
            &Message::Request {
                request,
                message_id,
                signature: Some(signature),
            },
        ))?;

        let _resp = match resp {
            Response::Mutation(res) => res.map_err(CoreError::from),
            _ => return Err(AuthError::from(CoreError::from("Unexpected response"))),
        };

        cm4.disconnect(&account_pub_id2).await?;

        Ok(())
    }

    /// Returns the current status of std/root dirs creation.
    pub async fn std_dirs_created(&self) -> bool {
        let auth_inner = self.auth_inner.lock().await;
        auth_inner.acc.root_dirs_created
    }

    /// Sets the current status of std/root dirs creation.
    pub async fn set_std_dirs_created(&self, val: bool) {
        let mut auth_inner = self.auth_inner.lock().await;
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

#[async_trait]
impl Client for AuthClient {
    type Context = ();

    async fn full_id(&self) -> SafeKey {
        let auth_inner = self.auth_inner.lock().await;
        auth_inner.acc.maid_keys.client_safe_key()
    }

    async fn owner_key(&self) -> PublicKey {
        self.public_key().await
    }

    async fn config(&self) -> Option<BootstrapConfig> {
        None
    }

    fn inner(&self) -> Arc<Mutex<Inner>> {
        self.inner.clone()
    }

    async fn public_encryption_key(&self) -> threshold_crypto::PublicKey {
        let auth_inner = self.auth_inner.lock().await;
        auth_inner.acc.maid_keys.enc_public_key
    }

    async fn secret_encryption_key(&self) -> shared_box::SecretKey {
        let auth_inner = self.auth_inner.lock().await;
        auth_inner.acc.maid_keys.enc_secret_key.clone()
    }

    async fn secret_symmetric_key(&self) -> shared_secretbox::Key {
        let auth_inner = self.auth_inner.lock().await;
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
            inner: Arc::clone(&self.inner),
            auth_inner: Arc::clone(&self.auth_inner),
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
    use safe_core::client::test_create_balance;
    use safe_core::utils::test_utils::{
        calculate_new_balance, gen_client_id, random_client, setup_client,
    };
    use safe_core::{utils, CoreError, DIR_TAG};
    use safe_nd::{Error as SndError, MDataKind, Money};
    use std::str::FromStr;

    // Test account creation.
    // It should succeed the first time and fail the second time with the same secrets.
    #[tokio::test]
    async fn registered_client() -> Result<(), AuthError> {
        let (net_tx, _) = mpsc::unbounded();

        let sec_0 = utils::generate_random_string(10)?;
        let sec_1 = utils::generate_random_string(10)?;
        let client_id = gen_client_id();
        test_create_balance(&client_id, unwrap!(Money::from_str("10"))).await?;

        // Account creation for the 1st time - should succeed
        let _ = AuthClient::registered(&sec_0, &sec_1, client_id.clone(), net_tx.clone()).await?;

        // Account creation - same secrets - should fail
        match AuthClient::registered(&sec_0, &sec_1, client_id, net_tx).await {
            Ok(_) => panic!("Account name hijacking should fail"),
            Err(AuthError::SndError(SndError::LoginPacketExists)) => (),
            Err(err) => panic!("{:?}", err),
        }
        Ok(())
    }

    // Test creating and logging in to an account on the network.
    #[tokio::test]
    async fn login() -> Result<(), AuthError> {
        let sec_0 = utils::generate_random_string(10)?;
        let sec_1 = utils::generate_random_string(10)?;
        let client_id = gen_client_id();

        test_create_balance(&client_id, Money::from_str("10")?).await?;

        let _ = setup_client(&(), |net_tx| {
            match futures::executor::block_on(AuthClient::login(&sec_0, &sec_1, net_tx.clone())) {
                Err(AuthError::SndError(SndError::NoSuchLoginPacket)) => (),
                x => panic!("Unexpected Login outcome: {:?}", x),
            }
            futures::executor::block_on(AuthClient::registered(&sec_0, &sec_1, client_id, net_tx))
        })?;

        let _ = setup_client(&(), |net_tx| {
            futures::executor::block_on(AuthClient::login(&sec_0, &sec_1, net_tx))
        })?;
        Ok(())
    }

    // Test logging in using a seeded account.
    #[tokio::test]
    async fn seeded_login() -> Result<(), AuthError> {
        let invalid_seed = String::from("123");
        {
            let (net_tx, _) = mpsc::unbounded();
            let client_id = gen_client_id();

            match AuthClient::registered_with_seed(&invalid_seed, client_id, net_tx).await {
                Err(AuthError::Unexpected(_)) => (),
                _ => panic!("Expected a failure"),
            }
        }
        {
            let (net_tx, _) = mpsc::unbounded();
            match AuthClient::login_with_seed(&invalid_seed, net_tx).await {
                Err(AuthError::Unexpected(_)) => (),
                _ => panic!("Expected a failure"),
            }
        }

        let seed = utils::generate_random_string(30)?;
        let client_id = gen_client_id();
        test_create_balance(&client_id, unwrap!(Money::from_str("10"))).await?;

        let _ = setup_client(&(), |net_tx| {
            match futures::executor::block_on(AuthClient::login_with_seed(&seed, net_tx.clone())) {
                Err(AuthError::SndError(SndError::NoSuchLoginPacket)) => (),
                x => panic!("Unexpected Login outcome: {:?}", x),
            }
            futures::executor::block_on(AuthClient::registered_with_seed(&seed, client_id, net_tx))
        })?;

        let _ = setup_client(&(), |net_tx| {
            futures::executor::block_on(AuthClient::login_with_seed(&seed, net_tx))
        })?;
        Ok(())
    }

    // Test creation of an access container.
    #[tokio::test]
    async fn access_container_creation() -> Result<(), AuthError> {
        let sec_0 = utils::generate_random_string(10)?;
        let sec_1 = utils::generate_random_string(10)?;
        let client_id = gen_client_id();

        test_create_balance(&client_id, unwrap!(Money::from_str("10"))).await?;

        let dir = MDataInfo::random_private(MDataKind::Seq, DIR_TAG)?;
        let dir_clone = dir.clone();

        let client = setup_client(&(), |net_tx| {
            futures::executor::block_on(AuthClient::registered(&sec_0, &sec_1, client_id, net_tx))
        })?;

        assert!(client.set_access_container(dir).await);
        client.update_account_packet().await?;

        let client = setup_client(&(), |net_tx| {
            futures::executor::block_on(AuthClient::login(&sec_0, &sec_1, net_tx))
        })?;

        let got_dir = client.access_container().await;
        assert_eq!(got_dir, dir_clone);
        Ok(())
    }

    // Test setting the configuration root directory.
    #[tokio::test]
    async fn config_root_dir_creation() -> Result<(), AuthError> {
        let sec_0 = utils::generate_random_string(10)?;
        let sec_1 = utils::generate_random_string(10)?;
        let client_id = gen_client_id();

        test_create_balance(&client_id, unwrap!(Money::from_str("10"))).await?;

        let dir = unwrap!(MDataInfo::random_private(MDataKind::Seq, DIR_TAG));
        let dir_clone = dir.clone();

        let client = setup_client(&(), |net_tx| {
            futures::executor::block_on(AuthClient::registered(&sec_0, &sec_1, client_id, net_tx))
        })?;
        assert!(client.set_config_root_dir(dir).await);
        client.update_account_packet().await?;

        let client = setup_client(&(), |net_tx| {
            futures::executor::block_on(AuthClient::login(&sec_0, &sec_1, net_tx))
        })?;
        let got_dir = client.config_root_dir().await;
        assert_eq!(got_dir, dir_clone);
        Ok(())
    }

    // Test restarting routing after a network disconnect.
    #[cfg(feature = "mock-network")]
    #[ignore] // FIXME: ignoring this temporarily until we figure out the disconnection semantics
    #[tokio::test]
    async fn restart_network() -> Result<(), AuthError> {
        use crate::test_utils::random_client_with_net_obs;
        use safe_core::NetworkEvent;
        use tokio::{
            sync::{mpsc, oneshot},
            task::LocalSet,
        };

        let (mut tx, mut rx) = mpsc::channel(2);
        let (hook, _keep_alive) = oneshot::channel();
        let local = LocalSet::new();
        let _joiner = local.spawn_local(async move {
            // Network Observer
            match unwrap!(rx.recv().await) {
                NetworkEvent::Disconnected => (),
                x => panic!("Unexpected network event: {:?}", x),
            }
            match unwrap!(rx.recv().await) {
                NetworkEvent::Connected => (),
                x => panic!("Unexpected network event: {:?}", x),
            }
            let _ = hook.send(());
        });

        let _client = random_client_with_net_obs(move |net_event| {
            let _ = futures::executor::block_on(tx.send(net_event));
        })?;

        //client.simulate_network_disconnect();
        //client.restart_network().await;
        //keep_alive;

        Ok(())
    }

    // Test that a `RequestTimeout` error is returned on network timeout.
    #[cfg(feature = "mock-network")]
    #[ignore]
    #[tokio::test]
    async fn timeout() -> Result<(), AuthError> {
        use safe_core::utils::test_utils::random_client;
        use safe_nd::{IDataAddress, PubImmutableData};
        use std::time::Duration;

        let client = random_client()?;
        client.set_simulate_timeout(true).await;
        client.set_timeout(Duration::from_millis(250)).await;

        match client.get_idata(IDataAddress::Pub(rand::random())).await {
            Ok(_) => panic!("Unexpected success"),
            Err(CoreError::RequestTimeout) => {}
            Err(err) => panic!("Unexpected {:?}", err),
        }

        let data = utils::generate_random_vector(4)?;
        let data = PubImmutableData::new(data);

        match client.put_idata(data).await {
            Ok(_) => panic!("Unexpected success"),
            Err(CoreError::RequestTimeout) => {}
            Err(err) => panic!("Unexpected {:?}", err),
        }

        Ok(())
    }

    // Create a login packet using some credentials and pass the login packet to a client who stores
    // it on the network and creates a wallet for it. Now calling login using the same credentials
    // should succeed and we must be able to fetch the balance.
    #[tokio::test]
    async fn create_login_packet_for() -> Result<(), AuthError> {
        let sec_0 = utils::generate_random_string(10)?;
        let sec_1 = utils::generate_random_string(10)?;

        let acc_locator: &[u8] = sec_0.as_bytes();
        let acc_password: &[u8] = sec_1.as_bytes();

        let (password, keyword, pin) = utils::derive_secrets(acc_locator, acc_password);

        let acc_loc = Account::generate_network_id(&keyword, &pin)?;

        let maid_keys = ClientKeys::new(&mut thread_rng());
        let acc = Account::new(maid_keys.clone())?;

        let acc_ciphertext = acc.encrypt(&password, &pin)?;

        let client_full_id = create_client_id(&acc_loc.0);

        let sig = client_full_id.sign(&acc_ciphertext);
        let client_pk = *client_full_id.public_id().public_key();
        let new_login_packet = unwrap!(LoginPacket::new(acc_loc, client_pk, acc_ciphertext, sig));
        let new_login_packet2 = new_login_packet.clone();
        let five_coins = unwrap!(Money::from_str("5"));
        let client_id = gen_client_id();
        let random_pk = *client_id.public_id().public_key();

        // The `random_client()` initializes the client with 10 coins.
        let start_bal = Money::from_str("10")?;
        // Create a client which has a pre-loaded balance and use it to store the login packet on
        // the network.
        let client = random_client()?;
        let c1 = client.clone();
        let c2 = client.clone();
        let c3 = client.clone();
        let c4 = client.clone();

        // Make sure no error occurred.
        let _ = client
            .insert_login_packet_for(
                None,
                maid_keys.public_key(),
                five_coins,
                None,
                new_login_packet.clone(),
            )
            .await?;

        // Re-insert to check for refunds for a failed insert_login_packet_for operation
        // The balance is created first, so `BalanceExists` is returned.
        match c1
            .insert_login_packet_for(
                None,
                maid_keys.public_key(),
                unwrap!(Money::from_str("3")),
                None,
                new_login_packet,
            )
            .await
        {
            Err(CoreError::DataError(SndError::BalanceExists)) => {}
            res => panic!("Unexpected {:?}", res),
        }

        // For a different balance and an existing login packet
        // `LoginPacketExists` should be returned.
        let balance = match c3
            .insert_login_packet_for(
                None,
                random_pk,
                unwrap!(Money::from_str("3")),
                None,
                new_login_packet2,
            )
            .await
        {
            Err(CoreError::DataError(SndError::LoginPacketExists)) => {
                c4.get_balance(Some(&client_id)).await?
            }
            res => panic!("Unexpected {:?}", res),
        };

        // The new balance should exist
        assert_eq!(balance, Money::from_str("3")?);

        let balance = c2.get_balance(None).await?;
        let expected = calculate_new_balance(start_bal, Some(3), Some(Money::from_str("8")?));
        assert_eq!(balance, expected);

        let client = setup_client(&(), |net_tx| {
            futures::executor::block_on(AuthClient::login(&sec_0, &sec_1, net_tx))
        })?;

        let balance = client.get_balance(None).await?;
        assert_eq!(balance, five_coins);
        Ok(())
    }
}
