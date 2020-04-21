// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

#[cfg(feature = "mock-network")]
mod sync;

#[cfg(feature = "mock-network")]
pub use self::sync::Synchronizer;

use crate::client::core_client::CoreClient;
use crate::client::{Client, COST_OF_PUT};
use crate::event_loop::{self, CoreMsg, CoreMsgTx};
use crate::network_event::{NetworkEvent, NetworkTx};
use crate::utils::{self, FutureExt};
use futures::stream::Stream;
use futures::channel::mpsc;
use futures::{Future, future::IntoFuture};
use log::trace;
use rand;
use safe_nd::{AppFullId, ClientFullId, ClientPublicId, Coins, Keypair};
use std::fmt::Debug;
use std::sync::mpsc as std_mpsc;
use tokio::runtime::current_thread::{Handle, Runtime};
use unwrap::unwrap;

/// Generates a random BLS secret and public keypair.
pub fn gen_bls_keypair() -> Keypair {
    let mut rng = rand::thread_rng();
    Keypair::new_bls(&mut rng)
}

/// Generates a random client full ID.
pub fn gen_client_id() -> ClientFullId {
    let mut rng = rand::thread_rng();
    ClientFullId::new_bls(&mut rng)
}

/// Generates a random app full ID.
pub fn gen_app_id(client_public_id: ClientPublicId) -> AppFullId {
    let mut rng = rand::thread_rng();
    AppFullId::new_bls(&mut rng, client_public_id)
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
    I: Future<Output=Result<T, E>> + 'static,
    T: Send + 'static,
    E: Debug,
{
    // FIXME: in stage 1 disconnection is a natural event, so instead of panicking we
    // just print it out.
    let n = |net_event| trace!("Unexpected NetworkEvent occurred: {:?}", net_event);
    let c = |el_h, core_tx, net_tx| {
        let acc_locator = unwrap!(utils::generate_random_string(10));
        let acc_password = unwrap!(utils::generate_random_string(10));
        CoreClient::new(&acc_locator, &acc_password, el_h, core_tx, net_tx)
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
    I: Future<Output=Result<T, E>> + 'static,
    T: Send + 'static,
    E: Debug,
    F: Debug,
{
    // FIXME: in stage 1 disconnection is a natural event, so instead of panicking we
    // just print it out.
    let n = |net_event| trace!("Unexpected NetworkEvent occurred: {:?}", net_event);
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
    I: Future<Output=Result<T, E>> + 'static,
    T: Send + 'static,
    E: Debug,
    F: Debug,
{
    let mut el = unwrap!(Runtime::new());
    let el_h = el.handle();

    let (core_tx, core_rx) = mpsc::unbounded();
    let (net_tx, net_rx) = mpsc::unbounded();
    let client = unwrap!(c(el_h, core_tx.clone(), net_tx));

    let net_fut = net_rx
        .for_each(move |net_event| {
            n(net_event);
            Ok(())
        })
        .map_err(|e| panic!("Network event stream error: {:?}", e));
    let _ = el.spawn(net_fut);

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
                })
                .into_box();

            Some(fut)
        }))
    );

    event_loop::run(el, &client, context, core_rx);

    unwrap!(result_rx.recv())
}

/// Helper function to calculate the total cost of expenditure by adding number of mutations and
/// amount of transferred coins if any.
pub fn calculate_new_balance(
    mut balance: Coins,
    mutation_count: Option<u64>,
    transferred_coins: Option<Coins>,
) -> Coins {
    if let Some(x) = mutation_count {
        balance = unwrap!(balance.checked_sub(Coins::from_nano(x * COST_OF_PUT.as_nano())));
    }
    if let Some(coins) = transferred_coins {
        balance = unwrap!(balance.checked_sub(coins));
    }
    balance
}

/// Initialises `env_logger` with custom settings.
pub fn init_log() {
    use std::io::Write;
    let do_format = move |formatter: &mut env_logger::fmt::Formatter, record: &log::Record<'_>| {
        let now = formatter.timestamp();
        writeln!(
            formatter,
            "{} {} [{}:{}] {}",
            formatter.default_styled_level(record.level()),
            now,
            record.file().unwrap_or_default(),
            record.line().unwrap_or_default(),
            record.args()
        )
    };
    let _ = env_logger::Builder::from_default_env()
        .format(do_format)
        .is_test(true)
        .try_init();
}
