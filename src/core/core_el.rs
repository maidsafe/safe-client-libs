// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use core::CPtr;
use futures::Future;
use futures::stream::Stream;
use std::io::{self, ErrorKind};
use tokio_core::channel;
use tokio_core::reactor::Core;

/// Transmitter of messages to be run in the core event loop.
pub type CoreMsgTx = channel::Sender<CoreMsg>;
/// Receiver of messages to be run in the core event loop.
pub type CoreMsgRx = channel::Receiver<CoreMsg>;

/// The final future which the event loop will run.
pub type TailFuture = Box<Future<Item = (), Error = ()>>;
/// The message format that core event loop understands.
pub struct CoreMsg(Option<Box<FnMut(&CPtr) -> Option<TailFuture> + Send + 'static>>);
impl CoreMsg {
    /// Construct a new message to ask core event loop to do something. If the return value of the
    /// given closure is optionally a future, it will be registered in the event loop.
    pub fn new<F>(f: F) -> Self
        where F: FnOnce(&CPtr) -> Option<TailFuture> + Send + 'static
    {
        let mut f = Some(f);
        CoreMsg(Some(Box::new(move |cptr| -> Option<TailFuture> {
            let f = f.take().unwrap();
            f(cptr)
        })))
    }

    /// Construct a new message which when processed by the event loop will terminate the event
    /// loop. This will be the graceful exit condition.
    pub fn build_terminator() -> Self {
        CoreMsg(None)
    }
}

/// Run the core event loop. This will block until the event loop is alive. Hence must typically be
/// called inside a spawned thread.
pub fn run(mut el: Core, cptr: CPtr, el_rx: CoreMsgRx) {
    let el_h = el.handle();

    let keep_alive = el_rx.for_each(|core_msg| {
        if let Some(mut f) = core_msg.0 {
            if let Some(tail) = f(&cptr) {
                el_h.spawn(tail);
            }
            Ok(())
        } else {
            Err(io::Error::new(ErrorKind::Other, "Graceful Termination"))
        }
    });

    let _ = el.run(keep_alive);
    debug!("Exiting Core Event Loop");
}
