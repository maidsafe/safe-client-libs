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

#![allow(unsafe_code)]

use cbor;
use rand::Rng;
use crypto::buffer::ReadBuffer;
use crypto::buffer::WriteBuffer;

use routing;
use maidsafe_types;
use maidsafe_types::{Payload, PayloadTypeTag, TypeTag};
use routing::sendable::Sendable;

mod user_account;
mod response_getter;
mod callback_interface;

#[cfg(not(feature = "USE_ACTUAL_ROUTING"))]
mod non_networking_test_framework;
#[cfg(not(feature = "USE_ACTUAL_ROUTING"))]
type RoutingClient = ::std::sync::Arc<::std::sync::Mutex<non_networking_test_framework::RoutingClientMock>>;
#[cfg(not(feature = "USE_ACTUAL_ROUTING"))]
fn get_new_routing_client(cb_interface: ::std::sync::Arc<::std::sync::Mutex<callback_interface::CallbackInterface>>, id_packet: routing::types::Id) -> RoutingClient {
    ::std::sync::Arc::new(::std::sync::Mutex::new(non_networking_test_framework::RoutingClientMock::new(cb_interface, id_packet)))
}

#[cfg(feature = "USE_ACTUAL_ROUTING")]
type RoutingClient = ::std::sync::Arc<::std::sync::Mutex<routing::routing_client::RoutingClient<callback_interface::CallbackInterface>>>;
#[cfg(feature = "USE_ACTUAL_ROUTING")]
fn get_new_routing_client(cb_interface: ::std::sync::Arc<::std::sync::Mutex<callback_interface::CallbackInterface>>, id_packet: routing::types::Id) -> RoutingClient {
    ::std::sync::Arc::new(::std::sync::Mutex::new(routing::routing_client::RoutingClient::new(cb_interface, id_packet)))
}

mod misc {
    pub type ResponseNotifier = ::std::sync::Arc<(::std::sync::Mutex<::routing::types::MessageId>, ::std::sync::Condvar)>;
}

/// The main self-authentication client instance that will interface all the request from high
/// level API's to the actual routing layer and manage all interactions with it. This is
/// essentially a non-blocking Client with upper layers having an option to either block and wait
/// on the returned ResponseGetter for receiving network response or spawn a new thread. The Client
/// itself is however well equipped for parallel and non-blocking PUTs and GETS.
pub struct Client {
    account:             user_account::Account,
    session_packet_id:   ::routing::NameType,
    session_packet_keys: SessionPacketEncryptionKeys,
    routing:             RoutingClient,
    response_notifier:   misc::ResponseNotifier,
    callback_interface:  ::std::sync::Arc<::std::sync::Mutex<callback_interface::CallbackInterface>>,
    routing_stop_flag:   ::std::sync::Arc<::std::sync::Mutex<bool>>,
    routing_join_handle: Option<::std::thread::JoinHandle<()>>,
}

impl Client {
    /// This is one of the two Gateway functions to the Maidsafe network, the other being the
    /// log_in. This will help create a fresh account for the user in the SAFE-network.
    pub fn create_account(keyword: &String, pin: u32, password_str: &String) -> Result<Client, ::IoError> {
        let password = password_str.as_bytes();

        let notifier = ::std::sync::Arc::new((::std::sync::Mutex::new(0), ::std::sync::Condvar::new()));
        let account_packet = user_account::Account::new(None);
        let callback_interface = ::std::sync::Arc::new(::std::sync::Mutex::new(callback_interface::CallbackInterface::new(notifier.clone())));
        let id_packet = routing::types::Id::with_keys(account_packet.get_maid().public_keys().clone(),
                                                      account_packet.get_maid().secret_keys().clone());

        let routing_client = get_new_routing_client(callback_interface.clone(), id_packet);
        let cloned_routing_client = routing_client.clone();
        let routing_stop_flag = ::std::sync::Arc::new(::std::sync::Mutex::new(false));
        let routing_stop_flag_clone = routing_stop_flag.clone();

        let client = Client {
            account: account_packet,
            session_packet_id: user_account::Account::generate_network_id(keyword, pin),
            session_packet_keys: SessionPacketEncryptionKeys::new(password, pin),
            routing: routing_client,
            callback_interface: callback_interface,
            response_notifier: notifier,
            routing_stop_flag: routing_stop_flag,
            routing_join_handle: Some(::std::thread::spawn(move || {
                let _ = cloned_routing_client.lock().unwrap().bootstrap(None, None);
                while !*routing_stop_flag_clone.lock().unwrap() {
                    ::std::thread::sleep_ms(1);
                    cloned_routing_client.lock().unwrap().run();
                }
            })),
        };

        {
            let destination = client.account.get_public_maid().name();
            let public_maid = client.account.get_public_maid().clone();
            let payload = Payload::new(PayloadTypeTag::PublicMaid, &public_maid);
            let _ = client.routing.lock().unwrap().unauthorised_put(destination, Box::new(payload));
        }

        let encrypted_account = maidsafe_types::ImmutableData::new(client.account.encrypt(password, pin).ok().unwrap());
        let payload = Payload::new(PayloadTypeTag::ImmutableData, &encrypted_account);
        let put_res = client.routing.lock().unwrap().put(payload);
        match put_res {
            Ok(_) => {
                // Vault network does not guarantee to give a put response, the waiting for that shall not be blocking
                // a put response will only be given when MaidManager reject the put request because of low allownance
                let account_versions = maidsafe_types::StructuredData::new(client.session_packet_id.clone(),
                                                                           client.account.get_public_maid().name(),
                                                                           vec![encrypted_account.name()]);
                let payload = Payload::new(PayloadTypeTag::StructuredData, &account_versions);
                let put_res = client.routing.lock().unwrap().put(payload);
                match put_res {
                    Ok(_) => Ok(client),
                    Err(io_error) => Err(io_error),
                }

                // let mut response_getter = response_getter::ResponseGetter::new(client.response_notifier.clone(), client.callback_interface.clone(), Some(id), None);
                // match response_getter.get() {
                //     Ok(_) => {
                //         let account_versions = maidsafe_types::StructuredData::new(client.session_packet_id.clone(),
                //                                                                    client.account.get_public_maid().name(),
                //                                                                    vec![encrypted_account.name()]);

                //         let put_res = client.routing.lock().unwrap().put(account_versions);

                //         match put_res {
                //             Ok(id) => {
                //                 let mut response_getter = response_getter::ResponseGetter::new(client.response_notifier.clone(), client.callback_interface.clone(), Some(id), None);
                //                 match response_getter.get() {
                //                     Ok(_) => Ok(client),
                //                     Err(_) => Err(::IoError::new(::std::io::ErrorKind::Other, "Version-Packet PUT-Response Failure !!")),
                //                 }
                //             },
                //             Err(io_error) => Err(io_error),
                //         }
                //     },
                //     Err(_) => Err(::IoError::new(::std::io::ErrorKind::Other, "Session-Packet PUT-Response Failure !!")),
                // }
            },
            Err(io_error) => Err(io_error),
        }
    }

    /// This is one of the two Gateway functions to the Maidsafe network, the other being the
    /// create_account. This will help log into an already created account for the user in the
    /// SAFE-network.
    pub fn log_in(keyword: &String, pin: u32, password_str: &String) -> Result<Client, ::IoError> {
        let password = password_str.as_bytes();

        let notifier = ::std::sync::Arc::new((::std::sync::Mutex::new(0), ::std::sync::Condvar::new()));
        let user_network_id = user_account::Account::generate_network_id(keyword, pin);
        let fake_account_packet = user_account::Account::new(None);
        let callback_interface = ::std::sync::Arc::new(::std::sync::Mutex::new(callback_interface::CallbackInterface::new(notifier.clone())));
        let fake_id_packet = routing::types::Id::with_keys(fake_account_packet.get_maid().public_keys().clone(),
                                                           fake_account_packet.get_maid().secret_keys().clone());

        let fake_routing_client = get_new_routing_client(callback_interface.clone(), fake_id_packet);
        let cloned_fake_routing_client = fake_routing_client.clone();
        let fake_routing_stop_flag = ::std::sync::Arc::new(::std::sync::Mutex::new(false));
        let fake_routing_stop_flag_clone = fake_routing_stop_flag.clone();

        struct RAIIThreadExit {
            routing_stop_flag: ::std::sync::Arc<::std::sync::Mutex<bool>>,
            join_handle: Option<::std::thread::JoinHandle<()>>,
        }

        impl Drop for RAIIThreadExit {
            fn drop(&mut self) {
                *self.routing_stop_flag.lock().unwrap() = true;
                self.join_handle.take().unwrap().join().unwrap();
            }
        }

        let _managed_thread = RAIIThreadExit {
            routing_stop_flag: fake_routing_stop_flag,
            join_handle: Some(::std::thread::spawn(move || {
                let _ = cloned_fake_routing_client.lock().unwrap().bootstrap(None, None);
                while !*fake_routing_stop_flag_clone.lock().unwrap() {
                    ::std::thread::sleep_ms(1);
                    cloned_fake_routing_client.lock().unwrap().run();
                }
            })),
        };
        ::std::thread::sleep_ms(10000);
        let structured_data_type_id = maidsafe_types::data::StructuredDataTypeTag;
        let get_result = fake_routing_client.lock().unwrap().get(structured_data_type_id.type_tag(), user_network_id);

        match get_result {
            Ok(id) => {
                let mut response_getter = response_getter::ResponseGetter::new(notifier.clone(), callback_interface.clone(), Some(id), None);
                match response_getter.get() {
                    Ok(raw_data) => {
                        let mut decoder = cbor::Decoder::from_bytes(raw_data);
                        let payload: Payload = decoder.decode().next().unwrap().unwrap();
                        let account_versions: maidsafe_types::StructuredData = payload.get_data();
                        match account_versions.value().pop() {
                            Some(latest_version) => {
                                let immutable_data_type_id = maidsafe_types::data::ImmutableDataTypeTag;
                                let get_result = fake_routing_client.lock().unwrap().get(immutable_data_type_id.type_tag(), latest_version);
                                match get_result {
                                    Ok(id) => {
                                        let mut response_getter = response_getter::ResponseGetter::new(notifier.clone(), callback_interface.clone(), Some(id), None);
                                        match response_getter.get() {
                                            Ok(raw_data) => {
                                                let mut decoder = cbor::Decoder::from_bytes(raw_data);
                                                let payload: Payload = decoder.decode().next().unwrap().unwrap();
                                                let encrypted_account_packet: maidsafe_types::ImmutableData = payload.get_data();
                                                let decryption_result = user_account::Account::decrypt(&encrypted_account_packet.value()[..], password, pin);
                                                if decryption_result.is_err() {
                                                    return Err(::IoError::new(::std::io::ErrorKind::Other, "Could Not Decrypt Session Packet !! (Probably Wrong Password)"));
                                                }
                                                let account_packet = decryption_result.ok().unwrap();

                                                let id_packet = routing::types::Id::with_keys(account_packet.get_maid().public_keys().clone(),
                                                                                              account_packet.get_maid().secret_keys().clone());

                                                let routing_client = get_new_routing_client(callback_interface.clone(), id_packet);
                                                let cloned_routing_client = routing_client.clone();
                                                let routing_stop_flag = ::std::sync::Arc::new(::std::sync::Mutex::new(false));
                                                let routing_stop_flag_clone = routing_stop_flag.clone();
                                                println!("\n returning");
                                                let client = Client {
                                                    account: account_packet,
                                                    session_packet_id: user_account::Account::generate_network_id(keyword, pin),
                                                    session_packet_keys: SessionPacketEncryptionKeys::new(password, pin),
                                                    routing: routing_client,
                                                    callback_interface: callback_interface,
                                                    response_notifier: notifier,
                                                    routing_stop_flag: routing_stop_flag,
                                                    routing_join_handle: Some(::std::thread::spawn(move || {
                                                        let _ = cloned_routing_client.lock().unwrap().bootstrap(None, None);
                                                        while !*routing_stop_flag_clone.lock().unwrap() {
                                                            ::std::thread::sleep_ms(10);
                                                            cloned_routing_client.lock().unwrap().run();
                                                        }
                                                    })),
                                                };

                                                Ok(client)
                                            },
                                            Err(_) => Err(::IoError::new(::std::io::ErrorKind::Other, "Session Packet (ImmutableData) GET-Response Failure !!")),
                                        }
                                    },
                                    Err(io_error) => Err(io_error),
                                }
                            },
                            None => Err(::IoError::new(::std::io::ErrorKind::Other, "No Session Packet information in retrieved StructuredData !!")),
                        }
                    },
                    Err(_) => Err(::IoError::new(::std::io::ErrorKind::Other, "StructuredData GET-Response Failure !! (Probably Invalid User-ID)")),
                }
            },
            Err(io_error) => Err(io_error),
        }
    }

    /// Create an entry for the Root Directory ID for the user into the session packet, encrypt and
    /// store it. It will be retireved when the user logs into his account. Root directory ID is
    /// necessary to fetch all of user's data as all further data is encoded as meta-information
    /// into the Root Directory or one of its subdirectories.
    pub fn set_root_directory_id(&mut self, root_dir_id: routing::NameType) -> Result<(), ::IoError> {
        if self.account.set_root_dir_id(root_dir_id.clone()) {
            let encrypted_account = maidsafe_types::ImmutableData::new(self.account.encrypt(self.session_packet_keys.get_password(), self.session_packet_keys.get_pin()).ok().unwrap());
            let put_res = self.routing.lock().unwrap().put(encrypted_account.clone());
            match put_res {
                Ok(id) => {
                    let mut response_getter = response_getter::ResponseGetter::new(self.response_notifier.clone(), self.callback_interface.clone(), Some(id), None);
                    match response_getter.get() {
                        Ok(_) => {},
                        Err(_) => return Err(::IoError::new(::std::io::ErrorKind::Other, "Session-Packet PUT-Response Failure !!")),
                    }

                    let structured_data_type_id = maidsafe_types::data::StructuredDataTypeTag;
                    let get_result = self.routing.lock().unwrap().get(structured_data_type_id.type_tag(), self.session_packet_id.clone());

                    match get_result {
                        Ok(id) => {
                            let mut response_getter = response_getter::ResponseGetter::new(self.response_notifier.clone(), self.callback_interface.clone(), Some(id), None);
                            match response_getter.get() {
                                Ok(raw_data) => {
                                    let mut decoder = cbor::Decoder::from_bytes(raw_data);
                                    let account_versions: maidsafe_types::StructuredData = decoder.decode().next().unwrap().unwrap();
                                    let mut vec_accounts = account_versions.value();
                                    vec_accounts.push(encrypted_account.name());

                                    let new_account_versions = maidsafe_types::StructuredData::new(self.session_packet_id.clone(),
                                                                                                   self.account.get_public_maid().name(),
                                                                                                   vec_accounts);

                                    let put_res = self.routing.lock().unwrap().put(new_account_versions);

                                    match put_res {
                                        Ok(id) => {
                                            let mut response_getter = response_getter::ResponseGetter::new(self.response_notifier.clone(), self.callback_interface.clone(), Some(id), None);
                                            match response_getter.get() {
                                                Ok(_) => Ok(()),
                                                Err(_) => Err(::IoError::new(::std::io::ErrorKind::Other, "Version-Packet PUT-Response Failure !!")),
                                            }
                                        },
                                        Err(io_error) => Err(io_error),
                                    }
                                },
                                Err(_) => Err(::IoError::new(::std::io::ErrorKind::Other, "SD-GET-Resp Failure - Could Not Retrieve Existing Account Versions !!")),
                            }
                        },
                        Err(io_error) => Err(io_error),
                    }
                },
                Err(io_error) => Err(io_error),
            }
        } else {
            Err(::IoError::new(::std::io::ErrorKind::Other, "Root Directory Id Set-Failure (Possibly already Exists - Do a get) !!"))
        }
    }

    /// Get Root Directory ID if available in session packet used for current login
    pub fn get_root_directory_id(&self) -> Option<&routing::NameType> {
        self.account.get_root_dir_id()
    }

    /// Combined Asymmectric and Symmetric encryption. The data is encrypted using random Key and
    /// IV with AES-symmetric encryption. Random IV ensures that same plain text produces different
    /// cipher-texts for each fresh symmetric encryption. The Key and IV are then asymmetrically
    /// enrypted using Public-MAID and the whole thing is then serialised into a single Vec<u8>.
    pub fn hybrid_encrypt(&self,
                          data_to_encrypt: &[u8],
                          nonce_opt: Option<::sodiumoxide::crypto::box_::Nonce>) -> Result<Vec<u8>, ::crypto::symmetriccipher::SymmetricCipherError> {
        let nonce = match nonce_opt {
            Some(nonce) => nonce,
            None => {
                let digest = ::sodiumoxide::crypto::hash::sha256::hash(&self.account.get_public_maid().name().0);
                let mut nonce = ::sodiumoxide::crypto::box_::Nonce([0u8; ::sodiumoxide::crypto::box_::NONCEBYTES]);
                let min_length = ::std::cmp::min(::sodiumoxide::crypto::box_::NONCEBYTES, digest.0.len());
                for it in digest.0.iter().take(min_length).enumerate() {
                    nonce.0[it.0] = *it.1;
                }
                nonce
            },
        };

        let mut key = [0u8; 32];
        let mut iv  = [0u8; 16];

        let mut rand_generator = ::rand::OsRng::new().ok().unwrap();
        rand_generator.fill_bytes(&mut key);
        rand_generator.fill_bytes(&mut iv);

        let mut combined_key_iv: [u8; 48] = unsafe { ::std::mem::uninitialized() };

        for it in key.iter().enumerate() {
            combined_key_iv[it.0] = *it.1;
        }
        for it in iv.iter().enumerate() {
            combined_key_iv[it.0 + 32] = *it.1;
        }

        let mut encryptor = ::crypto::aes::cbc_encryptor(::crypto::aes::KeySize::KeySize256, &key, &iv, ::crypto::blockmodes::PkcsPadding);

        let mut symm_encryption_result = Vec::<u8>::with_capacity(data_to_encrypt.len());

        let mut read_buffer = ::crypto::buffer::RefReadBuffer::new(data_to_encrypt);
        let mut buffer = [0u8; 4096];
        let mut write_buffer = ::crypto::buffer::RefWriteBuffer::new(&mut buffer);

        loop {
            let result = try!(encryptor.encrypt(&mut read_buffer, &mut write_buffer, true));
            symm_encryption_result.extend(write_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));

            match result {
                ::crypto::buffer::BufferResult::BufferUnderflow => break,
                ::crypto::buffer::BufferResult::BufferOverflow  => {},
            }
        }

        let asymm_encryption_result = ::sodiumoxide::crypto::box_::seal(&combined_key_iv,
                                                                                 &nonce,
                                                                                 &self.account.get_public_maid().public_keys().1,
                                                                                 &self.account.get_maid().secret_keys().1);

        let mut encoder = ::cbor::Encoder::from_memory();
        encoder.encode(&[(asymm_encryption_result, symm_encryption_result)]).unwrap();

        Ok(encoder.into_bytes())
    }

    /// Reverse of hybrid_encrypt. Refer hybrid_encrypt.
    pub fn hybrid_decrypt(&self,
                          data_to_decrypt: &[u8],
                          nonce_opt: Option<::sodiumoxide::crypto::box_::Nonce>) -> Option<Vec<u8>> {
        let mut decoder = ::cbor::Decoder::from_bytes(data_to_decrypt);
        let (asymm_encryption_result, symm_encryption_result): (Vec<u8>, Vec<u8>) = decoder.decode().next().unwrap().unwrap();

        let nonce = match nonce_opt {
            Some(nonce) => nonce,
            None => {
                let digest = ::sodiumoxide::crypto::hash::sha256::hash(&self.account.get_public_maid().name().0);
                let mut nonce = ::sodiumoxide::crypto::box_::Nonce([0u8; ::sodiumoxide::crypto::box_::NONCEBYTES]);
                let min_length = ::std::cmp::min(::sodiumoxide::crypto::box_::NONCEBYTES, digest.0.len());
                for it in digest.0.iter().take(min_length).enumerate() {
                    nonce.0[it.0] = *it.1;
                }
                nonce
            },
        };

        match ::sodiumoxide::crypto::box_::open(&asymm_encryption_result[..],
                                                         &nonce,
                                                         &self.account.get_public_maid().public_keys().1,
                                                         &self.account.get_maid().secret_keys().1) {
            Some(asymm_decryption_result) => {
                if asymm_decryption_result.len() == 48 {
                    let mut key: [u8; 32] = unsafe { ::std::mem::uninitialized() };
                    let mut iv : [u8; 16] = unsafe { ::std::mem::uninitialized() };

                    for it in asymm_decryption_result.iter().take(32).enumerate() {
                        key[it.0] = *it.1;
                    }
                    for it in asymm_decryption_result.iter().skip(32).enumerate() {
                        iv[it.0] = *it.1;
                    }

                    let mut decryptor = ::crypto::aes::cbc_decryptor(::crypto::aes::KeySize::KeySize256, &key, &iv, ::crypto::blockmodes::PkcsPadding);

                    let mut symm_decryption_result = Vec::<u8>::with_capacity(symm_encryption_result.len());
                    let mut read_buffer = ::crypto::buffer::RefReadBuffer::new(&symm_encryption_result[..]);
                    let mut buffer = [0u8; 4096];
                    let mut write_buffer = ::crypto::buffer::RefWriteBuffer::new(&mut buffer);

                    loop {
                        match decryptor.decrypt(&mut read_buffer, &mut write_buffer, true) {
                            Ok(result) => {
                                symm_decryption_result.extend(write_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));
                                match result {
                                    ::crypto::buffer::BufferResult::BufferUnderflow => break,
                                    ::crypto::buffer::BufferResult::BufferOverflow  => {},
                                }
                            },
                            Err(_) => return None,
                        }
                    }

                    Some(symm_decryption_result)
                } else {
                    None
                }
            },
            None => None,
        }
    }

    /// Owner of this client is the name of Public-MAID
    pub fn get_owner(&self) -> routing::NameType {
        self.account.get_public_maid().name()
    }

    /// Put data onto the network. This is non-blocking.
    pub fn put<T>(&mut self, sendable: T) -> Result<response_getter::ResponseGetter, ::IoError> where T: Sendable {
        match self.routing.lock().unwrap().put(sendable) {
            Ok(id)      => Ok(response_getter::ResponseGetter::new(self.response_notifier.clone(), self.callback_interface.clone(), Some(id), None)),
            Err(io_err) => Err(io_err),
        }
    }

    /// Get data from the network. This is non-blocking. Additionally this incorporates a mechanism
    /// of local caching. So if data already exists in the local cache, it is immediately returned
    /// via ResponseGetter and no networking penatly is payed. The functionality is abstracted to
    /// the user and is baked entirely into ResponseGetter.
    pub fn get(&mut self, tag_id: u64, name: routing::NameType) -> Result<response_getter::ResponseGetter, ::IoError> {
        let immutable_data_tag = maidsafe_types::data::ImmutableDataTypeTag;
        if tag_id == immutable_data_tag.type_tag() {
            let mut cb_interface = self.callback_interface.lock().unwrap();
            if cb_interface.cache_check(&name) {
                return Ok(response_getter::ResponseGetter::new(self.response_notifier.clone(), self.callback_interface.clone(), None, Some(name)))
            }
        }

        let mut data_name: Option<routing::NameType> = None;
        if tag_id == immutable_data_tag.type_tag() {
            data_name = Some(name.clone());
        }

        match self.routing.lock().unwrap().get(tag_id, name) {
            Ok(id) => Ok(response_getter::ResponseGetter::new(
                    self.response_notifier.clone(), self.callback_interface.clone(), Some(id), data_name)),
            Err(io_err) => Err(io_err),
        }
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        *self.routing_stop_flag.lock().unwrap() = true;
        self.routing_join_handle.take().unwrap().join().unwrap();
    }
}

/////////////////////////////////////////////////////////////////
/// Helper Struct
/////////////////////////////////////////////////////////////////

struct SessionPacketEncryptionKeys {
    password: Vec<u8>,
    pin: u32,
}

impl SessionPacketEncryptionKeys {
    fn new(password: &[u8], pin: u32) -> SessionPacketEncryptionKeys {
        let vec: Vec<u8> = password.iter().map(|a| *a).collect();
        SessionPacketEncryptionKeys {
            password: vec,
            pin: pin,
        }
    }

    fn get_password(&self) -> &[u8] {
        &self.password[..]
    }

    fn get_pin(&self) -> u32 {
        self.pin
    }
}

/////////////////////////////////////////////////////////////////

#[cfg(test)]
mod test {
    use super::*;
    use std::error::Error;

    #[test]
    fn account_creation() {
        let keyword = ::utility::generate_random_string(10);
        let password = ::utility::generate_random_string(10);
        let pin = ::utility::generate_random_pin();
        let result = Client::create_account(&keyword, pin, &password);
        assert!(result.is_ok());
    }

    #[test]
    fn account_login() {
        let keyword = ::utility::generate_random_string(10);
        let password = ::utility::generate_random_string(10);
        let pin = ::utility::generate_random_pin();

        // Without Creation Login Should Fail
        let mut result = Client::log_in(&keyword, pin, &password);
        assert!(result.is_err());

        // Creation should pass
        result = Client::create_account(&keyword, pin, &password);
        assert!(result.is_ok());

        // Wrong Credentials (Password) - Login should Fail
        let wrong_password = "Spandan".to_string();
        assert!(password != wrong_password);
        result = Client::log_in(&keyword, pin, &wrong_password);
        assert!(result.is_err());

        // Wrong Credentials (Keyword) - Login should Fail
        let wrong_keyword = "Spandan".to_string();
        assert!(keyword != wrong_keyword);
        result = Client::log_in(&wrong_keyword, pin, &password);
        assert!(result.is_err());

        // Wrong Credentials (Pin) - Login should Fail
        let wrong_pin = if pin == 0 {
            pin + 1
        } else {
            pin - 1
        };
        result = Client::log_in(&keyword, wrong_pin, &password);
        assert!(result.is_err());

        // Correct Credentials - Login Should Pass
        result = Client::log_in(&keyword, pin, &password);
        assert!(result.is_ok());
    }

    #[test]
    fn root_dir_id_creation() {
        // Construct Client
        let keyword = ::utility::generate_random_string(10);
        let password = ::utility::generate_random_string(10);
        let pin = ::utility::generate_random_pin();

        let result = Client::create_account(&keyword, pin, &password);
        assert!(result.is_ok());
        let mut client = result.ok().unwrap();

        assert!(client.get_root_directory_id().is_none());

        let root_dir_id = ::routing::NameType::new([99u8; 64]);
        match client.set_root_directory_id(root_dir_id.clone()) {
            Ok(_) => {
                // Correct Credentials - Login Should Pass
                let result = Client::log_in(&keyword, pin, &password);
                assert!(result.is_ok());

                let client = result.ok().unwrap();

                assert!(client.get_root_directory_id().is_some());

                assert_eq!(*client.get_root_directory_id().unwrap(), root_dir_id);
            },
            Err(io_err) => panic!("{:?}", io_err.description()),
        }
    }

    #[test]
    fn hybrid_encryption_decryption() {
        // Construct Client
        let keyword = ::utility::generate_random_string(10);
        let password = ::utility::generate_random_string(10);
        let pin = ::utility::generate_random_pin();

        let result = Client::create_account(&keyword, pin, &password);
        assert!(result.is_ok());
        let client = result.ok().unwrap();

        // Identical Plain Texts
        let plain_text_0 = vec![123u8; 1000];
        let plain_text_1 = plain_text_0.clone();

        // Encrypt passing Nonce
        let nonce = ::sodiumoxide::crypto::box_::gen_nonce();
        let hybrid_encrypt_0 = client.hybrid_encrypt(&plain_text_0[..], Some(nonce));
        let hybrid_encrypt_1 = client.hybrid_encrypt(&plain_text_1[..], Some(nonce));

        // Encrypt without passing Nonce
        let hybrid_encrypt_2 = client.hybrid_encrypt(&plain_text_0[..], None);
        let hybrid_encrypt_3 = client.hybrid_encrypt(&plain_text_1[..], None);

        assert!(hybrid_encrypt_0.is_ok());
        assert!(hybrid_encrypt_1.is_ok());
        assert!(hybrid_encrypt_2.is_ok());
        assert!(hybrid_encrypt_3.is_ok());

        // Same Plain Texts
        assert_eq!(plain_text_0, plain_text_1);

        // Different Results because of random "iv"
        assert!(hybrid_encrypt_0.clone().ok().unwrap() != hybrid_encrypt_1.clone().ok().unwrap());
        assert!(hybrid_encrypt_0.clone().ok().unwrap() != hybrid_encrypt_2.clone().ok().unwrap());
        assert!(hybrid_encrypt_0.clone().ok().unwrap() != hybrid_encrypt_3.clone().ok().unwrap());
        assert!(hybrid_encrypt_2.clone().ok().unwrap() != hybrid_encrypt_1.clone().ok().unwrap());
        assert!(hybrid_encrypt_2.clone().ok().unwrap() != hybrid_encrypt_3.clone().ok().unwrap());

        // Decrypt with Nonce
        let hybrid_decrypt_0 = client.hybrid_decrypt(&hybrid_encrypt_0.clone().ok().unwrap()[..], Some(nonce));
        let hybrid_decrypt_1 = client.hybrid_decrypt(&hybrid_encrypt_1.ok().unwrap()[..], Some(nonce));

        // Decrypt without Nonce
        let hybrid_decrypt_2 = client.hybrid_decrypt(&hybrid_encrypt_2.ok().unwrap()[..], None);
        let hybrid_decrypt_3 = client.hybrid_decrypt(&hybrid_encrypt_3.clone().ok().unwrap()[..], None);

        // Decryption without passing Nonce for something encrypted with passing Nonce - Should Fail
        let hybrid_decrypt_4 = client.hybrid_decrypt(&hybrid_encrypt_0.ok().unwrap()[..], None);
        // Decryption passing Nonce for something encrypted without passing Nonce - Should Fail
        let hybrid_decrypt_5 = client.hybrid_decrypt(&hybrid_encrypt_3.ok().unwrap()[..], Some(nonce));

        assert!(hybrid_decrypt_0.is_some());
        assert!(hybrid_decrypt_1.is_some());
        assert!(hybrid_decrypt_2.is_some());
        assert!(hybrid_decrypt_3.is_some());

        // Should fail
        assert!(hybrid_decrypt_4.is_none());
        assert!(hybrid_decrypt_5.is_none());

        // Should have decrypted to the same Plain Texts
        assert_eq!(plain_text_0, hybrid_decrypt_0.unwrap());
        assert_eq!(plain_text_1, hybrid_decrypt_1.unwrap());
        assert_eq!(plain_text_0, hybrid_decrypt_2.unwrap());
        assert_eq!(plain_text_1, hybrid_decrypt_3.unwrap());
    }
}
