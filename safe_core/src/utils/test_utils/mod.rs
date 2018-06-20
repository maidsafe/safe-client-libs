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
use client;
use errors::CoreError;
use event::{NetworkEvent, NetworkTx};
use event_loop::{self, CoreMsg, CoreMsgTx};
use futures::stream::Stream;
use futures::sync::mpsc;
use futures::{Future, IntoFuture};
use rust_sodium::crypto::sign;
use std::fmt::Debug;
use std::sync::mpsc as std_mpsc;
use std::{iter, u8};
use tokio_core::reactor::{Core, Handle};
use utils::{self, FutureExt};
use Client;

/// Generates random public keys
pub fn generate_public_keys(len: usize) -> Vec<sign::PublicKey> {
    (0..len).map(|_| sign::gen_keypair().0).collect()
}

/// Generates random secret keys
pub fn generate_secret_keys(len: usize) -> Vec<sign::SecretKey> {
    (0..len).map(|_| sign::gen_keypair().1).collect()
}

/// Generates public keys of maximum size
pub fn get_max_sized_public_keys(len: usize) -> Vec<sign::PublicKey> {
    iter::repeat(sign::PublicKey([u8::MAX; sign::PUBLICKEYBYTES]))
        .take(len)
        .collect()
}

/// Generates secret keys of maximum size
pub fn get_max_sized_secret_keys(len: usize) -> Vec<sign::SecretKey> {
    iter::repeat(sign::SecretKey([u8::MAX; sign::SECRETKEYBYTES]))
        .take(len)
        .collect()
}

/// Create random registered client and run it inside an event loop. Use this to
/// create Client automatically and randomly,
pub fn random_client<Run, I, T, E>(r: Run) -> T
where
    Run: FnOnce(&Client<()>) -> I + Send + 'static,
    I: IntoFuture<Item = T, Error = E> + 'static,
    T: Send + 'static,
    E: Debug,
{
    let n = |net_event| panic!("Unexpected NetworkEvent occurred: {:?}", net_event);
    random_client_with_net_obs(n, r)
}

/// Create random registered client and run it inside an event loop. Use this to
/// create Client automatically and randomly,
pub fn random_client_with_net_obs<NetObs, Run, I, T, E>(n: NetObs, r: Run) -> T
where
    NetObs: FnMut(NetworkEvent) + 'static,
    Run: FnOnce(&Client<()>) -> I + Send + 'static,
    I: IntoFuture<Item = T, Error = E> + 'static,
    T: Send + 'static,
    E: Debug,
{
    let c = |el_h, core_tx, net_tx| {
        let acc_locator = unwrap!(utils::generate_random_string(10));
        let acc_password = unwrap!(utils::generate_random_string(10));
        let invitation = unwrap!(utils::generate_random_string(10));
        client::registered(
            &acc_locator,
            &acc_password,
            &invitation,
            el_h,
            core_tx,
            net_tx,
        )
    };
    setup_client_with_net_obs(c, n, r)
}

/// Helper to create a client and run it in an event loop. Useful when we need
/// to supply credentials explicitly or when Client is to be constructed as
/// unregistered or as a result of successful login. Use this to create Client
/// manually,
pub fn setup_client<Create, Run, I, T, E>(c: Create, r: Run) -> T
where
    Create: FnOnce(Handle, CoreMsgTx<()>, NetworkTx) -> Result<Client<()>, CoreError>,
    Run: FnOnce(&Client<()>) -> I + Send + 'static,
    I: IntoFuture<Item = T, Error = E> + 'static,
    T: Send + 'static,
    E: Debug,
{
    let n = |net_event| panic!("Unexpected NetworkEvent occurred: {:?}", net_event);
    setup_client_with_net_obs(c, n, r)
}

/// Helper to create a client and run it in an event loop. Useful when we need
/// to supply credentials explicitly or when Client is to be constructed as
/// unregistered or as a result of successful login. Use this to create Client
/// manually,
pub fn setup_client_with_net_obs<Create, NetObs, Run, I, T, E>(
    c: Create,
    mut n: NetObs,
    r: Run,
) -> T
where
    Create: FnOnce(Handle, CoreMsgTx<()>, NetworkTx) -> Result<Client<()>, CoreError>,
    NetObs: FnMut(NetworkEvent) + 'static,
    Run: FnOnce(&Client<()>) -> I + Send + 'static,
    I: IntoFuture<Item = T, Error = E> + 'static,
    T: Send + 'static,
    E: Debug,
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
        })
        .map_err(|e| panic!("Network event stream error: {:?}", e));
    el_h.spawn(net_fut);

    let core_tx_clone = core_tx.clone();
    let (result_tx, result_rx) = std_mpsc::channel();

    unwrap!(core_tx.unbounded_send(CoreMsg::new(move |client, &()| {
        let fut = r(client)
            .into_future()
            .map_err(|e| panic!("{:?}", e))
            .map(move |value| {
                unwrap!(result_tx.send(value));
                unwrap!(core_tx_clone.unbounded_send(CoreMsg::build_terminator()));
            })
            .into_box();

        Some(fut)
    })));

    event_loop::run(el, &client, &(), core_rx);

    unwrap!(result_rx.recv())
}

/// Convenience for creating a blank runner.
pub fn finish() -> Result<(), ()> {
    Ok(())
}
