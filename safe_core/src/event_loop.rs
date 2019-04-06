// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::client::Client;
use crate::errors::CoreError;
use futures::stream::Stream;
use futures::sync::mpsc;
use futures::Future;
use tokio_core::reactor::Core;

/// Transmitter of messages to be run in the core event loop.
pub type CoreMsgTx<C, T> = mpsc::UnboundedSender<CoreMsg<C, T>>;
/// Receiver of messages to be run in the core event loop.
pub type CoreMsgRx<C, T> = mpsc::UnboundedReceiver<CoreMsg<C, T>>;

/// The final future which the event loop will run.
pub type TailFuture = Box<Future<Item = (), Error = ()>>;
type TailFutureFn<C, T> = FnMut(&C, &T) -> Option<TailFuture> + Send + 'static;

/// The message format that core event loop understands.
pub struct CoreMsg<C: Client, T>(Option<Box<TailFutureFn<C, T>>>);

/// Future trait returned from core operations.
pub type CoreFuture<T> = Future<Item = T, Error = CoreError>;

impl<C: Client, T> CoreMsg<C, T> {
    /// Construct a new message to ask core event loop to do something. If the
    /// return value of the given closure is optionally a future, it will be
    /// registered in the event loop.
    pub fn new<F>(f: F) -> Self
    where
        F: FnOnce(&C, &T) -> Option<TailFuture> + Send + 'static,
    {
        let mut f = Some(f);
        CoreMsg(Some(Box::new(
            move |client, context| -> Option<TailFuture> {
                let f = unwrap!(f.take());
                f(client, context)
            },
        )))
    }

    /// Construct a new message which when processed by the event loop will
    /// terminate the event loop. This will be the graceful exit condition.
    pub fn build_terminator() -> Self {
        CoreMsg(None)
    }
}

/// Run the core event loop. This will block until the event loop is alive.
/// Hence must typically be called inside a spawned thread.
pub fn run<C: Client, T>(mut el: Core, client: &C, context: &T, el_rx: CoreMsgRx<C, T>) {
    let el_h = el.handle();

    let keep_alive = el_rx.for_each(|core_msg| {
        if let Some(mut f) = core_msg.0 {
            if let Some(tail) = f(client, context) {
                el_h.spawn(tail);
            }
            Ok(())
        } else {
            // Err(io::Error::new(ErrorKind::Other, "Graceful Termination"))
            Err(())
        }
    });

    let _ = el.run(keep_alive);
    debug!("Exiting Core Event Loop");
}
