// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

#[cfg(feature = "mock-network")]
use crate::client::mock::Routing;
#[cfg(not(feature = "mock-network"))]
use routing::Client as Routing;

use crate::client::account::{Account as ClientAccount, ClientKeys};
use crate::client::{
    setup_routing, spawn_routing_thread, Client, ClientInner, IMMUT_DATA_CACHE_SIZE,
    REQUEST_TIMEOUT_SECS,
};
use crate::crypto::{shared_box, shared_secretbox, shared_sign};
use crate::errors::CoreError;
use crate::event::NetworkTx;
use crate::event_loop::CoreMsgTx;
use crate::utils;
use lru_cache::LruCache;
use maidsafe_utilities::serialisation::serialise;
use routing::XorName;
use routing::{
    AccountPacket, Authority, BootstrapConfig, Event, FullId, MessageId, MutableData, Response,
    Value, ACC_LOGIN_ENTRY_KEY, TYPE_TAG_SESSION_PACKET,
};
use rust_sodium::crypto::sign::Seed;
use rust_sodium::crypto::{box_, sign};
use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};
use std::rc::Rc;
use std::time::Duration;
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
        invitation: &str,
        el_handle: Handle,
        core_tx: CoreMsgTx<Self, ()>,
        net_tx: NetworkTx,
    ) -> Result<Self, CoreError> {
        Self::new_impl(
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

    fn new_impl<F>(
        acc_locator: &[u8],
        acc_password: &[u8],
        invitation: &str,
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
        let pub_key = maid_keys.sign_pk;
        let full_id = Some(maid_keys.clone().into());

        let (mut routing, routing_rx) = setup_routing(full_id, None)?;
        routing = routing_wrapper_fn(routing);

        let acc = ClientAccount::new(maid_keys.clone())?;

        let acc_ciphertext = acc.encrypt(&password, &pin)?;
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
        )?;

        let digest = sha3_256(&pub_key.0);
        let cm_addr = Authority::ClientManager(XorName(digest));

        let msg_id = MessageId::new();
        routing
            .put_mdata(cm_addr, acc_md.clone(), msg_id, pub_key)
            .map_err(CoreError::from)
            .and_then(|_| wait_for_response!(routing_rx, Response::PutMData, msg_id))
            .map_err(|e| {
                warn!("Could not put account to the Network: {:?}", e);
                e
            })?;

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

    fn owner_key(&self) -> Option<sign::PublicKey> {
        Some(self.keys.sign_pk)
    }
}

impl Clone for CoreClient {
    fn clone(&self) -> Self {
        CoreClient {
            inner: Rc::clone(&self.inner),
            cm_addr: self.cm_addr,
            keys: self.keys.clone(),
        }
    }
}
