// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::client::account::{Account as ClientAccount, ClientKeys};
#[cfg(feature = "mock-network")]
use crate::client::mock::Routing;
use crate::client::{
    setup_routing, spawn_routing_thread, AuthActions, Client, ClientInner, IMMUT_DATA_CACHE_SIZE,
    REQUEST_TIMEOUT_SECS,
};
use crate::crypto::{shared_box, shared_secretbox, shared_sign};
use crate::errors::CoreError;
use crate::event::NetworkTx;
use crate::event_loop::CoreMsgTx;
use crate::utils;
use lru_cache::LruCache;
#[cfg(not(feature = "mock-network"))]
use routing::Client as Routing;
use routing::{
    Authority, BootstrapConfig, FullId,
};
use rust_sodium::crypto::sign::Seed;
use rust_sodium::crypto::{box_, sign};
use safe_nd::{
    ClientPublicId, Message, MessageId, PublicId, PublicKey, Request, Signature, XorName, ClientFullId, Coins, LoginPacket, Response as RpcResponse
};
use new_rand::rngs::StdRng;
use new_rand::SeedableRng;
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::time::Duration;
use std::str::FromStr;
use threshold_crypto::SecretKey as BlsSecretKey;
use tiny_keccak::sha3_256;
use tokio_core::reactor::Handle;

/// Wait for a response from the `$rx` receiver with path `$res` and message ID `$msg_id`.
#[macro_export]
macro_rules! wait_for_response {
    ($rx:expr, $res:path, $msg_id:expr) => {
        match $rx.recv_timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS)) {
            Ok(Event::Response {
                response:
                    $res {
                        res,
                        msg_id: res_msg_id,
                    },
                ..
            }) => {
                if res_msg_id == $msg_id {
                    res.map_err(CoreError::RoutingClientError)
                } else {
                    warn!("Received response with unexpected message id");
                    Err(CoreError::OperationAborted)
                }
            }
            Ok(x) => {
                warn!("Received unexpected response: {:?}", x);
                Err(CoreError::OperationAborted)
            }
            Err(err) => {
                warn!("Failed to receive response: {:?}", err);
                Err(CoreError::OperationAborted)
            }
        }
    };
}

/// Barebones Client object used for testing purposes.
pub struct CoreClient {
    inner: Rc<RefCell<ClientInner<CoreClient, ()>>>,
    cm_addr: Authority<XorName>,
    keys: ClientKeys,
}

impl CoreClient {
    /// This will create a basic Client object which is sufficient only for testing purposes.
    pub fn new(
        acc_locator: &str,
        acc_password: &str,
        // invitation: &str,
        el_handle: Handle,
        core_tx: CoreMsgTx<Self, ()>,
        net_tx: NetworkTx,
    ) -> Result<Self, CoreError> {
        Self::new_impl(
            acc_locator.as_bytes(),
            acc_password.as_bytes(),
            // invitation,
            el_handle,
            core_tx,
            net_tx,
            None,
            |routing| routing,
        )
    }

    fn new_impl<F>(
        acc_locator: &[u8],
        acc_password: &[u8],
        // balance_sk: BlsSecretKey,
        el_handle: Handle,
        core_tx: CoreMsgTx<Self, ()>,
        net_tx: NetworkTx,
        id_seed: Option<&Seed>,
        routing_wrapper_fn: F,
    ) -> Result<Self, CoreError>
    where
        F: Fn(Routing) -> Routing,
    {
        trace!("Creating an account.");

        let (password, keyword, pin) = utils::derive_secrets(acc_locator, acc_password);

        let acc_loc = ClientAccount::generate_network_id(&keyword, &pin)?;

        let maid_keys = ClientKeys::new(id_seed);
        let pub_key = PublicKey::Bls(maid_keys.bls_pk);
        let full_id = Some(maid_keys.clone().into());
        let balance_sk = BlsSecretKey::random();

        let acc = ClientAccount::new(maid_keys.clone())?;

        let acc_ciphertext = acc.encrypt(&password, &pin)?;

        let mut seeder: Vec<u8> = Vec::with_capacity(acc_locator.len() + acc_password.len());
        seeder.extend_from_slice(acc_locator);
        seeder.extend_from_slice(acc_password);

        let seed = sha3_256(&seeder);
        let mut rng = StdRng::from_seed(seed);
        let client_full_id = ClientFullId::new_bls(&mut rng);

        let sig = client_full_id.sign(&acc_ciphertext);
        let client_pk = client_full_id.public_id().public_key();
        let new_account_data = LoginPacket::new(acc_loc, *client_pk, acc_ciphertext, sig)?;
        let balance_client_id = ClientFullId::with_bls_key(balance_sk);

        {
            let (mut routing, routing_rx) = setup_routing(
                full_id.clone(),
                PublicId::Client(balance_client_id.public_id().clone()),
                None,
            )?;

            routing.create_balance(*balance_client_id.public_id().public_key(), unwrap!(Coins::from_str("10")));

            let rpc_response = routing.req_as_client(
                &routing_rx,
                Request::CreateLoginPacketFor {
                    new_owner: pub_key,
                    amount: unwrap!(Coins::from_str("1")),
                    transaction_id: new_rand::random(),
                    new_login_packet: new_account_data,
                },
                &balance_client_id,
            );
            match rpc_response {
                RpcResponse::Mutation(res) => res?,
                _ => return Err(CoreError::from("Unexpected response")),
            };
        }

        let (mut routing, routing_rx) = setup_routing(
            full_id,
            PublicId::Client(ClientPublicId::new(pub_key.into(), pub_key)),
            None,
        )?;
        routing = routing_wrapper_fn(routing);

        let cm_addr = Authority::ClientManager(XorName::from(pub_key));

        // Create the client
        let joiner = spawn_routing_thread(routing_rx, core_tx.clone(), net_tx.clone());

        Ok(Self {
            inner: Rc::new(RefCell::new(ClientInner {
                el_handle,
                routing,
                hooks: HashMap::with_capacity(10),
                cache: LruCache::new(IMMUT_DATA_CACHE_SIZE),
                timeout: Duration::from_secs(REQUEST_TIMEOUT_SECS),
                joiner,
                net_tx,
                core_tx,
            })),
            cm_addr,
            keys: maid_keys,
        })
    }
}

impl Client for CoreClient {
    type MsgType = ();

    fn full_id(&self) -> Option<FullId> {
        Some(ClientKeys::into(self.keys.clone()))
    }

    fn public_id(&self) -> PublicId {
        let client_pk = PublicKey::from(self.keys.bls_pk);
        PublicId::Client(ClientPublicId::new(client_pk.into(), client_pk))
    }

    fn config(&self) -> Option<BootstrapConfig> {
        None
    }

    fn cm_addr(&self) -> Option<Authority<XorName>> {
        Some(self.cm_addr)
    }

    fn inner(&self) -> Rc<RefCell<ClientInner<Self, Self::MsgType>>> {
        self.inner.clone()
    }

    fn public_encryption_key(&self) -> Option<box_::PublicKey> {
        Some(self.keys.enc_pk)
    }

    fn secret_encryption_key(&self) -> Option<shared_box::SecretKey> {
        Some(self.keys.enc_sk.clone())
    }

    fn public_signing_key(&self) -> Option<sign::PublicKey> {
        Some(self.keys.sign_pk)
    }

    fn secret_signing_key(&self) -> Option<shared_sign::SecretKey> {
        Some(self.keys.sign_sk.clone())
    }

    fn secret_symmetric_key(&self) -> Option<shared_secretbox::Key> {
        Some(self.keys.enc_key.clone())
    }

    fn public_bls_key(&self) -> Option<threshold_crypto::PublicKey> {
        Some(self.keys.bls_pk)
    }

    fn secret_bls_key(&self) -> Option<threshold_crypto::SecretKey> {
        Some(self.keys.bls_sk.clone())
    }

    fn owner_key(&self) -> Option<PublicKey> {
        Some(PublicKey::from(self.keys.bls_pk))
    }

    fn compose_message(&self, request: Request) -> Message {
        let message_id = MessageId::new();

        let signature = Some(Signature::from(
            self.keys
                .bls_sk
                .sign(&unwrap!(bincode::serialize(&(&request, message_id)))),
        ));

        Message::Request {
            request,
            message_id,
            signature,
        }
    }
}

impl AuthActions for CoreClient {}

impl Clone for CoreClient {
    fn clone(&self) -> Self {
        CoreClient {
            inner: Rc::clone(&self.inner),
            cm_addr: self.cm_addr,
            keys: self.keys.clone(),
        }
    }
}
