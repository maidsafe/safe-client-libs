// Copyright 2015 MaidSafe.net limited.
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
// relating to use of the SAFE Network Software.                                                                 */

#![allow(unused_variables)]

use routing;

use std::sync::{Mutex, Arc, Condvar};
use lru_time_cache::LruCache;

use routing::error::ResponseError;
use routing::types::{MessageId};


pub struct RoutingInterface {
  my_cvar : Arc<(Mutex<bool>, Condvar)>,
  my_cache : LruCache<u32, Result<Vec<u8>, ResponseError>>
}

impl routing::client_interface::Interface for RoutingInterface {
  // fn handle_get(&mut self, type_id: u64, our_authority: Authority, from_authority: Authority,
  //               from_address: NameType, data: Vec<u8>)->Result<Action, ResponseError> {
  //   Err(ResponseError::InvalidRequest)
  // }

  // fn handle_put(&mut self, our_authority: Authority, from_authority: Authority,
  //               from_address: NameType, dest_address: DestinationAddress, data: Vec<u8>)->Result<Action, ResponseError> {
  //   ;
  //   Err(ResponseError::InvalidRequest)
  // }

  // fn handle_post(&mut self, our_authority: Authority, from_authority: Authority, from_address: NameType, data: Vec<u8>)->Result<Action, ResponseError> {
  //   ;
  //   Err(ResponseError::InvalidRequest)
  // }

  fn handle_get_response(&mut self, message_id: MessageId, response: Result<Vec<u8>, ResponseError>) {
    self.my_cache.add(message_id, response);
    let &(ref lock, ref cvar) = &*self.my_cvar;
    let mut fetched = lock.lock().unwrap();
    *fetched = true;
    cvar.notify_one();
  }

  fn handle_put_response(&mut self, message: MessageId, response: Result<Vec<u8>, ResponseError>) {
    ;
  }

  // fn handle_post_response(&mut self, from_authority: Authority, from_address: NameType, response: Result<Vec<u8>, ResponseError>) {
  //   ;
  // }

  // fn add_node(&mut self, node: NameType) { unimplemented!() }

  // fn drop_node(&mut self, node: NameType) { unimplemented!() }
}

impl RoutingInterface {
  pub fn new(cvar: Arc<(Mutex<bool>, Condvar)>) -> RoutingInterface {
    RoutingInterface { my_cvar: cvar, my_cache: LruCache::with_capacity(10000) }
  }

  pub fn get_response(&mut self, message_id : u32) -> Result<Vec<u8>, ResponseError> {
    let result = self.my_cache.remove(&message_id).unwrap();
    result
  }
}
