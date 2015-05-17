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
// relating to use of the SAFE Network Software.

#![crate_name = "maidsafe_client"]
#![crate_type = "lib"]
#![doc(html_logo_url = "http://maidsafe.net/img/Resources/branding/maidsafe_logo.fab2.png",
       html_favicon_url = "http://maidsafe.net/img/favicon.ico",
              html_root_url = "http://dirvine.github.io/dirvine/maidsafe_client/")]

extern crate cbor;
extern crate lru_time_cache;
extern crate crypto;
extern crate maidsafe_types;
extern crate routing;
extern crate rustc_serialize;
extern crate sodiumoxide;

pub mod account;
mod client;

use std::sync::{Mutex, Arc, Condvar};
use std::io::Error as IoError;
use std::net::{SocketAddr};
use std::str::FromStr;

use cbor::{Decoder};

use maidsafe_types::{ImmutableData, StructuredData};
use routing::routing_client::Endpoint;
use routing::routing_client::RoutingClient;
use routing::sendable::Sendable;
use routing::test_utils::Random;
use routing::NameType;
use client::RoutingInterface;
use account::Account;


pub enum CryptoError {
    SymmetricCryptoError(crypto::symmetriccipher::SymmetricCipherError),
    BadBuffer
}

impl From<crypto::symmetriccipher::SymmetricCipherError> for CryptoError {
    fn from(error : crypto::symmetriccipher::SymmetricCipherError) -> CryptoError {
        return CryptoError::SymmetricCryptoError(error);
    }
}


pub enum MaidsafeError {
    CryptoError(CryptoError),
    EncodingError(cbor::CborError),
}

impl From<CryptoError> for MaidsafeError {
    fn from(error : CryptoError) -> MaidsafeError {
        return MaidsafeError::CryptoError(error);
    }
}

impl From<cbor::CborError> for MaidsafeError {
    fn from(error : cbor::CborError) -> MaidsafeError {
        return MaidsafeError::EncodingError(error);
    }
}

impl From<crypto::symmetriccipher::SymmetricCipherError> for MaidsafeError {
    fn from(error : crypto::symmetriccipher::SymmetricCipherError) -> MaidsafeError {
        return MaidsafeError::CryptoError(CryptoError::SymmetricCryptoError(error));
    }
}



pub struct Client {
  my_routing : RoutingClient<RoutingInterface>,
  my_account : Account,
  my_facade : Arc<Mutex<RoutingInterface>>,
  my_cvar : Arc<(Mutex<bool>, Condvar)>
}

impl<'a> Client {
  pub fn new(username : &String, password : &[u8], pin : u32) -> Client {
    let account = Account::create_account(username, password, pin).ok().unwrap();
    let cvar = Arc::new((Mutex::new(false), Condvar::new()));
    let facade = Arc::new(Mutex::new(RoutingInterface::new(cvar.clone())));
    // FIX ME: Krishna - below RoutingClient must use the interface object from facade
    let mut client = Client { my_routing: RoutingClient::new(RoutingInterface::new(cvar.clone()), account.get_account().clone()),
                              my_account: account, my_facade: facade, my_cvar: cvar };
    let encrypted_account = ImmutableData::new(client.my_account.encrypt(&password, pin).ok().unwrap());
    // encrypted account data will be stored as ImmutableData across the network
    let _ = client.my_routing.put(encrypted_account.clone());
    // ownership will be reflected as in an SDV so account can be receovered later on during login
    let network_id = Account::generate_network_id(&username, pin);
    let ownership = StructuredData::new(network_id, client.my_account.get_account().get_name(),
                                        vec![vec![encrypted_account.name()]]);
    let _ = client.my_routing.put(ownership);
    client
  }

  pub fn log_in(username : &String, password : &[u8], pin : u32) -> Client {
    let mut fetched_encrypted : Vec<u8>;
    {
      let network_id = Account::generate_network_id(username, pin);
      let temp_account = Account::new();
      let temp_cvar = Arc::new((Mutex::new(false), Condvar::new()));
      let temp_facade = Arc::new(Mutex::new(RoutingInterface::new(temp_cvar.clone())));
      // FIX ME: Krishna
      let mut temp_routing = RoutingClient::new(RoutingInterface::new(temp_cvar.clone()), temp_account.get_account().clone());
      let mut get_queue = temp_routing.get(102u64, NameType::new(network_id.0));
      let &(ref lock, ref cvar) = &*temp_cvar;
      let mut fetched = lock.lock().unwrap();
      while !*fetched {
          fetched = cvar.wait(fetched).unwrap();
      }
      {
        let &ref facade_lock = &*temp_facade;
        let mut facade = facade_lock.lock().unwrap();
        let fetched_ownership = facade.get_response(get_queue.ok().unwrap()).ok().unwrap();
        // fetched_ownership is serialised SDV, the encrypted account shall be the root of of it
        let mut d = Decoder::from_bytes(fetched_ownership);
        let ownership: StructuredData = d.decode().next().unwrap().unwrap();
        *fetched = false;
        get_queue = temp_routing.get(101u64, ownership.get_value()[0][0].clone());
      }
      while !*fetched {
          fetched = cvar.wait(fetched).unwrap();
      }
      {
        let &ref facade_lock = &*temp_facade;
        let mut facade = facade_lock.lock().unwrap();
        fetched_encrypted = facade.get_response(get_queue.ok().unwrap()).ok().unwrap();
      }
    }
    let existing_account = Account::decrypt(&fetched_encrypted[..], &password, pin).ok().unwrap();
    let cvar = Arc::new((Mutex::new(false), Condvar::new()));
    let facade = Arc::new(Mutex::new(RoutingInterface::new(cvar.clone())));
    // FIX ME: Krishna
    Client { my_routing: RoutingClient::new(RoutingInterface::new(cvar.clone()), existing_account.get_account().clone()),
             my_account: existing_account, my_facade: facade, my_cvar: cvar }
  }

  pub fn put(&mut self, data: Vec<u8>) {
    // data will be stored as ImmutableData
    // TODO: shall the input data to be checked and sliced into chunks here to fit the restriction of 1MB size each chunk?
    let _ =  self.my_routing.put(ImmutableData::new(data));
  }

  pub fn get(&mut self, data_name: NameType) -> Result<Vec<u8>, IoError> {
    let get_queue = self.my_routing.get(0u64, data_name);
    let &(ref lock, ref cvar) = &*self.my_cvar;
    let mut fetched = lock.lock().unwrap();
    while !*fetched {
        fetched = cvar.wait(fetched).unwrap();
    }
    let &ref facade_lock = &*self.my_facade;
    let mut facade = facade_lock.lock().unwrap();
    let result = facade.get_response(get_queue.ok().unwrap());
    *fetched = false;
    Ok(result.ok().unwrap())
  }

}
