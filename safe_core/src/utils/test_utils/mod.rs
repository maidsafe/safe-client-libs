// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

#[cfg(feature = "use-mock-routing")]
mod sync;

#[cfg(feature = "use-mock-routing")]
pub use self::sync::Synchronizer;
use client::core_client::CoreClient;
use client::Client;
use event::{NetworkEvent, NetworkTx};
use event_loop::{self, CoreMsg, CoreMsgTx};
use futures::stream::Stream;
use futures::sync::mpsc;
use futures::{Future, IntoFuture};
use safe_crypto::{
    self, PublicSignKey, SecretSignKey, PUBLIC_SIGN_KEY_BYTES, SECRET_SIGN_KEY_BYTES,
};
use std::fmt::Debug;
use std::sync::mpsc as std_mpsc;
use std::{iter, u8};
use tokio_core::reactor::{Core, Handle};
use utils::{self, FutureExt};

/// Generates random public keys
pub fn generate_public_keys(len: usize) -> Vec<PublicSignKey> {
    (0..len)
        .map(|_| safe_crypto::gen_sign_keypair().0)
        .collect()
}

/// Generates random secret keys
pub fn generate_secret_keys(len: usize) -> Vec<SecretSignKey> {
    (0..len)
        .map(|_| safe_crypto::gen_sign_keypair().1)
        .collect()
}

/// Generates public keys of maximum size
pub fn get_max_sized_public_keys(len: usize) -> Vec<PublicSignKey> {
    iter::repeat(PublicSignKey::from_bytes([u8::MAX; PUBLIC_SIGN_KEY_BYTES]))
        .take(len)
        .collect()
}

/// Generates secret keys of maximum size
pub fn get_max_sized_secret_keys(len: usize) -> Vec<SecretSignKey> {
    iter::repeat(SecretSignKey::from_bytes([u8::MAX; SECRET_SIGN_KEY_BYTES]))
        .take(len)
        .collect()
}

/// Convenience for creating a blank runner.
pub fn finish() -> Result<(), ()> {
    Ok(())
}

/// Create random registered client and run it inside an event loop. Use this to
/// create a `CoreClient` automatically and randomly.
pub fn random_client<Run, I, T, E>(r: Run) -> T
where
    Run: FnOnce(&CoreClient) -> I + Send + 'static,
    I: IntoFuture<Item = T, Error = E> + 'static,
    T: Send + 'static,
    E: Debug,
{
    let n = |net_event| panic!("Unexpected NetworkEvent occurred: {:?}", net_event);
    let c = |el_h, core_tx, net_tx| {
        let acc_locator = unwrap!(utils::generate_random_string(10));
        let acc_password = unwrap!(utils::generate_random_string(10));
        let invitation = unwrap!(utils::generate_random_string(10));
        CoreClient::new(
            &acc_locator,
            &acc_password,
            &invitation,
            el_h,
            core_tx,
            net_tx,
        )
    };
    setup_client_with_net_obs(&(), c, n, r)
}

/// Helper to create a client and run it in an event loop. Useful when we need
/// to supply credentials explicitly or when Client is to be constructed as
/// unregistered or as a result of successful login. Use this to create Client
/// manually.
pub fn setup_client<Create, Run, A, C, I, T, E, F>(context: &A, c: Create, r: Run) -> T
where
    Create: FnOnce(Handle, CoreMsgTx<C, A>, NetworkTx) -> Result<C, F>,
    Run: FnOnce(&C) -> I + Send + 'static,
    A: 'static,
    C: Client,
    I: IntoFuture<Item = T, Error = E> + 'static,
    T: Send + 'static,
    E: Debug,
    F: Debug,
{
    let n = |net_event| panic!("Unexpected NetworkEvent occurred: {:?}", net_event);
    setup_client_with_net_obs(context, c, n, r)
}

/// Helper to create a client and run it in an event loop. Useful when we need
/// to supply credentials explicitly or when Client is to be constructed as
/// unregistered or as a result of successful login. Use this to create Client
/// manually.
pub fn setup_client_with_net_obs<Create, NetObs, Run, A, C, I, T, E, F>(
    context: &A,
    c: Create,
    mut n: NetObs,
    r: Run,
) -> T
where
    Create: FnOnce(Handle, CoreMsgTx<C, A>, NetworkTx) -> Result<C, F>,
    NetObs: FnMut(NetworkEvent) + 'static,
    Run: FnOnce(&C) -> I + Send + 'static,
    A: 'static,
    C: Client,
    I: IntoFuture<Item = T, Error = E> + 'static,
    T: Send + 'static,
    E: Debug,
    F: Debug,
{
    let el = unwrap!(Core::new());
    let el_h = el.handle();

    let (core_tx, core_rx) = mpsc::unbounded();
    let (net_tx, net_rx) = mpsc::unbounded();
    let client = unwrap!(c(el_h.clone(), core_tx.clone(), net_tx));

    let net_fut = net_rx
        .for_each(move |net_event| {
            n(net_event);
            Ok(())
        }).map_err(|e| panic!("Network event stream error: {:?}", e));
    el_h.spawn(net_fut);

    let core_tx_clone = core_tx.clone();
    let (result_tx, result_rx) = std_mpsc::channel();

    unwrap!(
        core_tx.unbounded_send(CoreMsg::new(move |client, _context| {
            let fut = r(client)
                .into_future()
                .map_err(|e| panic!("{:?}", e))
                .map(move |value| {
                    unwrap!(result_tx.send(value));
                    unwrap!(core_tx_clone.unbounded_send(CoreMsg::build_terminator()));
                }).into_box();

            Some(fut)
        }))
    );

    event_loop::run(el, &client, context, core_rx);

    unwrap!(result_rx.recv())
}
