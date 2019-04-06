// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::client::MockRouting;
use maidsafe_utilities::SeededRng;
use rand::Rng;
use routing::{Request, Response};
use std::rc::Rc;
use std::sync::{Arc, Condvar, Mutex};

/// Helper for running multiple clients in parallel while keeping the runs
/// deterministic.
#[derive(Clone)]
pub struct Synchronizer {
    inner: Arc<Inner>,
}

impl Synchronizer {
    /// Create new instance of `Synchronizer` using the given random number
    /// generator. The generator can be initialized with a seed to guarantee
    /// repeatable, deterministic runs.
    pub fn new(rng: SeededRng) -> Self {
        Synchronizer {
            inner: Arc::new(Inner {
                state: Mutex::new(State::new(rng)),
                condvar: Condvar::new(),
            }),
        }
    }

    /// Install necessary hooks on the given routing instance.
    pub fn hook(&self, mut routing: MockRouting) -> MockRouting {
        let req_hook = Rc::new(Hook::new(Arc::clone(&self.inner)));
        let res_hook = Rc::clone(&req_hook);

        routing.set_request_hook(move |req| req_hook.request(req));
        routing.set_response_hook(move |res| res_hook.response(res));
        routing
    }
}

struct Hook {
    id: usize,
    inner: Arc<Inner>,
}

impl Hook {
    fn new(inner: Arc<Inner>) -> Self {
        let id = inner.register_id();
        Hook { id, inner }
    }

    // Invoke request hook.
    fn request(&self, _req: &Request) -> Option<Response> {
        self.inner.wait(self.id);
        None
    }

    // Invoke response hook.
    fn response(&self, res: Response) -> Response {
        self.inner.sleep();
        res
    }
}

impl Drop for Hook {
    fn drop(&mut self) {
        self.inner.unregister_id(self.id);
    }
}

struct Inner {
    state: Mutex<State>,
    condvar: Condvar,
}

impl Inner {
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

struct State {
    rng: SeededRng,
    all: Vec<usize>,
    next: usize,
    awake: usize,
}

impl State {
    fn new(rng: SeededRng) -> Self {
        State {
            rng,
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
            self.awake = *unwrap!(self.rng.choose(&self.all));
        }
    }
}
