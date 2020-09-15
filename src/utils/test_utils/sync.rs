// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

// FIXME
#![allow(unused)]

use crate::ConnectionManager;
use rand::seq::SliceRandom;
use rand::Rng;
use sn_data_types::{QueryResponse, Request};
use std::rc::Rc;
use std::sync::{Arc, Condvar, Mutex};
use unwrap::unwrap;

/// Helper for running multiple clients in parallel while keeping the runs
/// deterministic.
#[derive(Clone)]
pub struct Synchronizer<T: Rng> {
    inner: Arc<Inner<T>>,
}

impl<T: Clone + Rng> Synchronizer<T> {
    /// Create new instance of `Synchronizer` using the given random number
    /// generator. The generator can be initialized with a seed to guarantee
    /// repeatable, deterministic runs.
    pub fn new(rng: &mut T) -> Self {
        Self {
            inner: Arc::new(Inner {
                state: Mutex::new(State::new(rng)),
                condvar: Condvar::new(),
            }),
        }
    }

    /// Install necessary hooks on the given sn_routing instance.
    pub fn hook(&self, mut cm: ConnectionManager) -> ConnectionManager {
        // let req_hook = Arc::new(Hook::new(Arc::clone(&self.inner)));
        // let res_hook = Arc::clone(&req_hook);

        // FIXME:
        // sn_routing.set_request_hook(move |req| req_hook.request(req));
        // sn_routing.set_response_hook(move |res| res_hook.response(res));
        cm
    }
}

struct Hook<T: Clone + Rng> {
    id: usize,
    inner: Arc<Inner<T>>,
}

impl<T: Clone + Rng> Hook<T> {
    fn new(inner: Arc<Inner<T>>) -> Self {
        let id = inner.register_id();
        Self { id, inner }
    }

    // Invoke request hook.
    fn request(&self, _req: &Request) -> Option<QueryResponse> {
        self.inner.wait(self.id);
        None
    }

    // Invoke response hook.
    fn response(&self, res: QueryResponse) -> QueryResponse {
        self.inner.sleep();
        res
    }
}

impl<T: Clone + Rng> Drop for Hook<T> {
    fn drop(&mut self) {
        self.inner.unregister_id(self.id);
    }
}

struct Inner<T> {
    state: Mutex<State<T>>,
    condvar: Condvar,
}

impl<T: Clone + Rng> Inner<T> {
    fn register_id(&self) -> usize {
        let mut state = unwrap!(self.state.lock());
        state.register_id()
    }

    fn unregister_id(&self, id: usize) {
        let mut state = unwrap!(self.state.lock());
        state.unregister_id(id);
        self.condvar.notify_all();
    }

    fn wait(&self, id: usize) {
        let mut state = unwrap!(self.state.lock());
        while state.awake != id {
            state = unwrap!(self.condvar.wait(state));
        }
    }

    fn sleep(&self) {
        let mut state = unwrap!(self.state.lock());
        state.wake_next();
        self.condvar.notify_all();
    }
}

struct State<T> {
    rng: T,
    all: Vec<usize>,
    next: usize,
    awake: usize,
}

impl<T: Clone + Rng> State<T> {
    fn new(rng: &mut T) -> Self {
        Self {
            rng: rng.clone(),
            all: Vec::new(),
            next: 0,
            awake: 0,
        }
    }

    fn register_id(&mut self) -> usize {
        let id = self.next;
        self.next += 1;

        self.all.push(id);
        self.awake = id;

        id
    }

    fn unregister_id(&mut self, id: usize) {
        if let Some(index) = self.all.iter().position(|other| *other == id) {
            let _ = self.all.remove(index);
        }

        if self.awake == id {
            self.wake_next();
        }
    }

    fn wake_next(&mut self) {
        if !self.all.is_empty() {
            self.awake = *unwrap!(self.all.choose(&mut self.rng));
        }
    }
}
