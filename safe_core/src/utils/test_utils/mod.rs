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
use crate::network_event::{NetworkEvent, NetworkTx};
use crate::utils::{self};
use crate::CoreError;
use futures::{channel::mpsc, future::Future};
use log::trace;
use rand;
use safe_nd::{AppFullId, ClientFullId, ClientPublicId, Coins, Keypair};
use std::fmt::Debug;
use tokio::stream::StreamExt;
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

/// Create random registered client. Use this to
/// create a `CoreClient` automatically and randomly.
pub fn random_client() -> Result<CoreClient, CoreError>
where
{
    // FIXME: in stage 1 disconnection is a natural event, so instead of panicking we
    // just print it out.
    let on_network_event = |net_event| trace!("Unexpected NetworkEvent occurred: {:?}", net_event);
    let client_creator = |net_tx| {
        let acc_locator = unwrap!(utils::generate_random_string(10));
        let acc_password = unwrap!(utils::generate_random_string(10));

        // blocking on the thread here as part of tests. Core client construction is async
        futures::executor::block_on(CoreClient::new(&acc_locator, &acc_password, net_tx))
    };
    match setup_client_with_net_obs(&(), client_creator, on_network_event) {
        Ok((_receiver, client)) => Ok(client),
        Err(error) => Err(error),
    }
}

/// Helper to create a client
/// Useful when we need  to supply credentials explicitly or when Client is to be constructed as
/// unregistered or as a result of successful login. Use this to create Client
/// manually.
pub fn setup_client<Create, A, C, F>(context: &A, c: Create) -> Result<C, CoreError>
where
    Create: FnOnce(NetworkTx) -> Result<C, F>,
    A: 'static,
    C: Client,
    F: Debug,
{
    // FIXME: in stage 1 disconnection is a natural event, so instead of panicking we
    // just print it out.
    let n = |net_event| trace!("Unexpected NetworkEvent occurred: {:?}", net_event);
    match setup_client_with_net_obs(context, c, n) {
        Ok((_receiver, client)) => Ok(client),
        Err(error) => Err(error),
    }
}

/// Helper to create a client and setup network event listener.
/// Useful when we need
/// to supply credentials explicitly or when Client is to be constructed as
/// unregistered or as a result of successful login. Use this to create Client
/// manually.
pub fn setup_client_with_net_obs<Create, NetObs, A, C, F>(
    _context: &A,
    client_creator: Create,
    mut n: NetObs,
) -> Result<(Box<dyn Future<Output = ()> + 'static + Send>, C), CoreError>
where
    Create: FnOnce(NetworkTx) -> Result<C, F>,
    NetObs: FnMut(NetworkEvent) + 'static + Send,
    A: 'static,
    C: Client,

    F: Debug,
{
    let (net_tx, mut net_rx) = mpsc::unbounded();
    let client = unwrap!(client_creator(net_tx));

    let net_fut = async move {
        while let Some(msg) = net_rx.next().await {
            n(msg);
        }
    };

    // net fut returned in order to keep it alive.
    Ok((Box::new(net_fut), client))
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
