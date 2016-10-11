// Copyright 2015 MaidSafe.net limited.
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

use core::core_el::{self, CoreMsg, CoreMsgRx, CoreMsgTx};
use core::client::{Client, CPtr};
use core::errors::CoreError;
use core::futures::FutureExt;
use core::utility;
use futures::Future;
use rust_sodium::crypto::sign;
use std::cell::RefCell;
use std::rc::Rc;
use tokio_core::reactor::Core;
use tokio_core::channel;

/// Generates a random mock client for testing
pub fn get_client(core_tx: CoreMsgTx) -> Result<Client, CoreError> {
    let acc_locator = try!(utility::generate_random_string(10));
    let acc_password = try!(utility::generate_random_string(10));
    Client::registered(&acc_locator, &acc_password, core_tx)
}

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
    ::std::iter::repeat(sign::PublicKey([::std::u8::MAX; sign::PUBLICKEYBYTES])).take(len).collect()
}

/// Generates secret keys of maximum size
pub fn get_max_sized_secret_keys(len: usize) -> Vec<sign::SecretKey> {
    ::std::iter::repeat(sign::SecretKey([::std::u8::MAX; sign::SECRETKEYBYTES])).take(len).collect()
}

// Helper to create a client and run it inside an event loop.
pub fn setup_client<F>(f: F) -> Env where F: FnOnce(CoreMsgTx) -> Client {
    let core = unwrap!(Core::new());
    let (tx, rx) = unwrap!(channel::channel(&core.handle()));

    Env {
        client: f(tx.clone()),
        core: core,
        tx: tx,
        rx: rx,
    }
}

pub struct Env {
    client: Client,
    core: Core,
    tx: CoreMsgTx,
    rx: CoreMsgRx,
}

impl Env {
    // Spin up an event loop and execute the given closure on it. The closure
    // must return a future which will then be driven to completion.
    pub fn run<F, R>(self, f: F)
        where F: FnOnce(&CPtr) -> R + Send + 'static,
              R: Future + 'static
    {
        let client = Rc::new(RefCell::new(self.client));
        let tx = self.tx.clone();

        unwrap!(self.tx.send(CoreMsg::new(move |cptr| {
            let future = f(cptr).then(move |_| {
                // When the future completes, send terminator to the event loop
                // to stop it.
                unwrap!(tx.send(CoreMsg::build_terminator()));
                Ok(())
            }).into_box();

            Some(future)
        })));

        core_el::run(self.core, client.clone(), self.rx);
    }

    // Return the client stored in this Env.
    pub fn unwrap(self) -> Client {
        self.client
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use tokio_core::channel;
    use tokio_core::reactor::Core;

    #[test]
    fn random_client() {
        let core = unwrap!(Core::new());
        let (core_tx, _) = unwrap!(channel::channel(&core.handle()));

        let client_0 = unwrap!(get_client(core_tx.clone()));
        let client_1 = unwrap!(get_client(core_tx));

        let sign_key_0 = unwrap!(client_0.public_signing_key());
        let sign_key_1 = unwrap!(client_1.public_signing_key());
        let pub_key_0 = unwrap!(client_0.public_encryption_key());
        let pub_key_1 = unwrap!(client_1.public_encryption_key());

        assert!(sign_key_0 != sign_key_1);
        assert!(pub_key_0 != pub_key_1);
    }
}
