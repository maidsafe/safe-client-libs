// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net
// Commercial License, version 1.0 or later, or (2) The General Public License
// (GPL), version 3, depending on which licence you accepted on initial access
// to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project
// generally, you agree to be bound by the terms of the MaidSafe Contributor
// Agreement, version 1.0.
// This, along with the Licenses can be found in the root directory of this
// project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network
// Software distributed under the GPL Licence is distributed on an "AS IS"
// BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
//
// Please review the Licences for the specific language governing permissions
// and limitations relating to use of the SAFE Network Software.

mod storage;
// use maidsafe_utilities::serialisation::serialise;

use maidsafe_utilities::thread;
use rand;
// use routing::{DataIdentifier, Request};
use routing::{Authority, ClientError, Data, EntryAction, Event, FullId, ImmutableData,
              InterfaceError, MessageId, MutableData, PermissionSet, Response, RoutingError, User,
              XorName};
// use routing::TYPE_TAG_SESSION_PACKET;
use rust_sodium::crypto::hash::sha256;
use rust_sodium::crypto::sign;
// use rustc_serialize::Encodable;
use self::storage::{Storage, StorageError};
use std;
use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;
use std::sync::mpsc::Sender;
use std::time::Duration;

const CONNECT_THREAD_NAME: &'static str = "Mock routing connect";
const DELAY_THREAD_NAME: &'static str = "Mock routing delay";
const DEFAULT_DELAY_MS: u64 = 0;
const CONNECT_DELAY_MS: u64 = DEFAULT_DELAY_MS;
const GET_ACCOUNT_INFO_DELAY_MS: u64 = DEFAULT_DELAY_MS;
const PUT_IDATA_DELAY_MS: u64 = DEFAULT_DELAY_MS;
const GET_IDATA_DELAY_MS: u64 = DEFAULT_DELAY_MS;

lazy_static! {
    static ref STORAGE: Mutex<Storage> = Mutex::new(Storage::new());
}

pub struct MockRouting {
    sender: Sender<Event>,
    client_auth: Authority,
    max_ops_countdown: Option<Cell<u64>>,
    timeout_simulation: bool,
}

impl MockRouting {
    pub fn new(sender: Sender<Event>, _id: Option<FullId>) -> Result<Self, RoutingError> {
        ::rust_sodium::init();

        let cloned_sender = sender.clone();
        let _ = thread::named(CONNECT_THREAD_NAME, move || {
            std::thread::sleep(Duration::from_millis(CONNECT_DELAY_MS));
            let _ = cloned_sender.send(Event::Connected);
        });

        let client_auth = Authority::Client {
            client_key: sign::gen_keypair().0,
            peer_id: rand::random(),
            proxy_node_name: rand::random(),
        };
        Ok(MockRouting {
            sender: sender,
            client_auth: client_auth,
            max_ops_countdown: None,
            timeout_simulation: false,
        })
    }

    /// Gets MAID account information.
    pub fn get_account_info(&mut self,
                            dst: Authority,
                            msg_id: MessageId)
                            -> Result<(), InterfaceError> {
        if self.timeout_simulation {
            return Ok(());
        }

        let client_name = self.client_name();
        let client_auth = self.client_auth.clone();

        if let Err(err) = self.verify_network_limits(msg_id, "get_account_info") {
            self.send_response(GET_ACCOUNT_INFO_DELAY_MS,
                               dst,
                               client_auth,
                               Response::GetAccountInfo {
                                   res: Err(err),
                                   msg_id: msg_id,
                               });
            return Ok(());
        }


        match unwrap!(STORAGE.lock()).get_account_info(&client_name) {
            Some(account_info) => {
                self.send_response(GET_ACCOUNT_INFO_DELAY_MS,
                                   dst,
                                   client_auth,
                                   Response::GetAccountInfo {
                                       res: Ok(*account_info),
                                       msg_id: msg_id,
                                   })
            }
            None => {
                self.send_response(GET_ACCOUNT_INFO_DELAY_MS,
                                   dst,
                                   client_auth,
                                   Response::GetAccountInfo {
                                       res: Err(ClientError::NoSuchAccount),
                                       msg_id: msg_id,
                                   })
            }
        }

        Ok(())
    }

    /// Puts ImmutableData to the network.
    pub fn put_idata(&mut self,
                     _dst: Authority,
                     data: ImmutableData,
                     msg_id: MessageId)
                     -> Result<(), InterfaceError> {
        if self.timeout_simulation {
            return Ok(());
        }

        let nae_auth = Authority::NaeManager(*data.name());

        if let Err(err) = self.verify_network_limits(msg_id, "put_idata") {
            self.send_response(PUT_IDATA_DELAY_MS,
                               nae_auth,
                               self.client_auth.clone(),
                               Response::GetAccountInfo {
                                   res: Err(err),
                                   msg_id: msg_id,
                               });
            return Ok(());
        }

        let mut storage = unwrap!(STORAGE.lock());
        let res = match storage.get_data(data.name()) {
            // Immutable data is de-duplicated so always allowed
            Ok(Data::Immutable(_)) => Ok(()),
            Ok(_) => Err(ClientError::DataExists),
            Err(StorageError::NoSuchData) => {
                storage.put_data(*data.name(), Data::Immutable(data))
                    .map_err(ClientError::from)
            }
            Err(err) => Err(ClientError::from(err)),
        };

        if let Ok(_) = res {
            {
                let account = storage.get_or_create_account_info(&self.client_name());
                account.data_stored += 1;
                account.space_available -= 1;
            }

            storage.sync();
        }

        self.send_response(PUT_IDATA_DELAY_MS,
                           nae_auth,
                           self.client_auth.clone(),
                           Response::PutIData {
                               res: res,
                               msg_id: msg_id,
                           });
        Ok(())
    }

    /// Fetches ImmutableData from the network by the given name.
    pub fn get_idata(&mut self,
                     _dst: Authority,
                     name: XorName,
                     msg_id: MessageId)
                     -> Result<(), InterfaceError> {
        if self.timeout_simulation {
            return Ok(());
        }

        let nae_auth = Authority::NaeManager(name);

        if let Err(err) = self.verify_network_limits(msg_id, "get_idata") {
            self.send_response(GET_IDATA_DELAY_MS,
                               nae_auth,
                               self.client_auth.clone(),
                               Response::GetIData {
                                   res: Err(err),
                                   msg_id: msg_id,
                               });
            return Ok(());
        }

        let res = match unwrap!(STORAGE.lock()).get_data(&name) {
            Ok(Data::Immutable(data)) => Ok(data),
            _ => Err(ClientError::NoSuchData),
        };

        self.send_response(GET_IDATA_DELAY_MS,
                           nae_auth,
                           self.client_auth.clone(),
                           Response::GetIData {
                               res: res,
                               msg_id: msg_id,
                           });
        Ok(())
    }

    /// Creates a new MutableData in the network.
    pub fn put_mdata(&mut self,
                     dst: Authority,
                     data: MutableData,
                     msg_id: MessageId,
                     requester: sign::PublicKey)
                     -> Result<(), InterfaceError> {
        unimplemented!()
    }

    /// Fetches a latest version number.
    pub fn get_mdata_version(&mut self,
                             dst: Authority,
                             name: XorName,
                             tag: u64,
                             msg_id: MessageId)
                             -> Result<(), InterfaceError> {
        unimplemented!()
    }

    /// Fetches a list of entries (keys + values).
    pub fn list_mdata_entries(&mut self,
                              dst: Authority,
                              name: XorName,
                              tag: u64,
                              msg_id: MessageId)
                              -> Result<(), InterfaceError> {
        unimplemented!()
    }

    /// Fetches a list of keys in MutableData.
    pub fn list_mdata_keys(&mut self,
                           dst: Authority,
                           name: XorName,
                           tag: u64,
                           msg_id: MessageId)
                           -> Result<(), InterfaceError> {
        unimplemented!()
    }

    /// Fetches a list of values in MutableData.
    pub fn list_mdata_values(&mut self,
                             dst: Authority,
                             name: XorName,
                             tag: u64,
                             msg_id: MessageId)
                             -> Result<(), InterfaceError> {
        unimplemented!()
    }

    /// Fetches a single value from MutableData
    pub fn get_mdata_value(&mut self,
                           dst: Authority,
                           name: XorName,
                           tag: u64,
                           key: Vec<u8>,
                           msg_id: MessageId)
                           -> Result<(), InterfaceError> {
        unimplemented!()
    }

    /// Updates MutableData entries in bulk.
    pub fn mutate_mdata_entries(&mut self,
                                dst: Authority,
                                name: XorName,
                                tag: u64,
                                actions: BTreeMap<Vec<u8>, EntryAction>,
                                msg_id: MessageId,
                                requester: sign::PublicKey)
                                -> Result<(), InterfaceError> {
        unimplemented!()
    }

    /// Fetches a complete list of permissions.
    pub fn list_mdata_permissions(&mut self,
                                  dst: Authority,
                                  name: XorName,
                                  tag: u64,
                                  msg_id: MessageId)
                                  -> Result<(), InterfaceError> {
        unimplemented!()
    }

    /// Fetches a list of permissions for a particular User.
    pub fn list_mdata_user_permissions(&mut self,
                                       dst: Authority,
                                       name: XorName,
                                       tag: u64,
                                       user: User,
                                       msg_id: MessageId)
                                       -> Result<(), InterfaceError> {
        unimplemented!()
    }

    /// Updates or inserts a list of permissions for a particular User in the given
    /// MutableData.
    pub fn set_mdata_user_permissions(&mut self,
                                      dst: Authority,
                                      name: XorName,
                                      tag: u64,
                                      user: User,
                                      permissions: PermissionSet,
                                      version: u64,
                                      msg_id: MessageId,
                                      requester: sign::PublicKey)
                                      -> Result<(), InterfaceError> {
        unimplemented!()
    }

    /// Deletes a list of permissions for a particular User in the given MutableData.
    pub fn del_mdata_user_permissions(&mut self,
                                      dst: Authority,
                                      name: XorName,
                                      tag: u64,
                                      user: User,
                                      version: u64,
                                      msg_id: MessageId,
                                      requester: sign::PublicKey)
                                      -> Result<(), InterfaceError> {
        unimplemented!()
    }

    /// Changes an owner of the given MutableData. Only the current owner can perform this action.
    pub fn change_mdata_owner(&mut self,
                              dst: Authority,
                              name: XorName,
                              tag: u64,
                              new_owners: BTreeSet<sign::PublicKey>,
                              version: u64,
                              msg_id: MessageId)
                              -> Result<(), InterfaceError> {
        unimplemented!()
    }

    fn send_response(&self, delay_ms: u64, src: Authority, dst: Authority, response: Response) {
        let event = Event::Response {
            response: response,
            src: src,
            dst: dst,
        };

        let sender = self.sender.clone();

        let _ = thread::named(DELAY_THREAD_NAME, move || {
            std::thread::sleep(Duration::from_millis(delay_ms));
            if let Err(err) = sender.send(event) {
                error!("mpsc-send failure: {:?}", err);
            }
        });
    }

    fn client_name(&self) -> XorName {
        match self.client_auth {
            Authority::Client { ref client_key, .. } => XorName(sha256::hash(&client_key[..]).0),
            _ => panic!("This authority must be Client"),
        }
    }

    #[cfg(test)]
    pub fn set_network_limits(&mut self, max_ops_count: Option<u64>) {
        self.max_ops_countdown = max_ops_count.map(Cell::new)
    }

    #[cfg(test)]
    pub fn simulate_disconnect(&self) {
        let sender = self.sender.clone();
        let _ = std::thread::spawn(move || unwrap!(sender.send(Event::RestartRequired)));
    }

    #[cfg(test)]
    pub fn set_simulate_timeout(&mut self, enable: bool) {
        self.timeout_simulation = enable;
    }

    fn verify_network_limits(&self, msg_id: MessageId, op: &str) -> Result<(), ClientError> {
        let client_name = self.client_name();

        if self.network_limits_reached() {
            info!("Mock {}: {:?} {:?} [0]", op, client_name, msg_id);
            Err(ClientError::NetworkOther("Max operations exhausted".to_string()))
        } else {
            if let Some(count) = self.update_network_limits() {
                info!("Mock {}: {:?} {:?} [{}]", op, client_name, msg_id, count);
            }

            Ok(())
        }
    }

    fn network_limits_reached(&self) -> bool {
        self.max_ops_countdown.as_ref().map_or(false, |count| count.get() == 0)
    }

    fn update_network_limits(&self) -> Option<u64> {
        self.max_ops_countdown.as_ref().map(|count| {
            let ops = count.get();
            count.set(ops - 1);
            ops
        })
    }
}

impl Drop for MockRouting {
    fn drop(&mut self) {
        let _ = self.sender.send(Event::Terminate);
    }
}

#[cfg(test)]
mod tests {
    use core::client::account::Account;
    use core::errors::CoreError;
    use core::utility;
    use routing::{AccountInfo, Authority, ClientError, Event, FullId, ImmutableData, MessageId,
                  Response};
    use std::sync::mpsc::{self, Receiver};
    use super::*;
    use super::storage::DEFAULT_CLIENT_ACCOUNT_SIZE;

    /*
    use maidsafe_utilities::serialisation::{deserialise, serialise};
    use rand;
    use routing::{AppendWrapper, AppendedData, Data, DataIdentifier, Filter,
                  PubAppendableData, StructuredData,
                  XOR_NAME_LEN, XorName};
    use rust_sodium::crypto::sign;
    use std::collections::HashMap;
    use std::iter;
    */

    // Helper macro to receive a routing event and assert it's a response
    // success.
    macro_rules! expect_success {
        ($rx:expr, $msg_id:expr, $res:path) => {
            match unwrap!($rx.recv()) {
                Event::Response {
                    response: $res { res, msg_id, }, ..
                } => {
                    assert_eq!(msg_id, $msg_id);

                    match res {
                        Ok(value) => value,
                        Err(err) => panic!("Unexpected error {:?}", err),
                    }
                }
                event => panic!("Unexpected event {:?}", event),
            }
        }
    }

    // Helper macro to receive a routing event and assert it's a response
    // failure.
    macro_rules! expect_failure {
        ($rx:expr, $msg_id:expr, $res:path, $err:pat) => {
            match unwrap!($rx.recv()) {
                Event::Response {
                    response: $res { res, msg_id, }, ..
                } => {
                    assert_eq!(msg_id, $msg_id);

                    match res {
                        Ok(_) => panic!("Unexpected success"),
                        Err($err) => (),
                        Err(err) => panic!("Unexpected error {:?}", err),
                    }
                }
                event => panic!("Unexpected event {:?}", event),
            }
        }
    }

    #[test]
    fn immutable_data_basics() {
        let (mut routing, routing_rx) = setup();

        // Construct ImmutableData
        let orig_data = ImmutableData::new(unwrap!(utility::generate_random_vector(100)));
        let nae_mgr = Authority::NaeManager(*orig_data.name());
        let client_mgr = Authority::ClientManager(*orig_data.name());

        // GetIData should fail
        let msg_id = MessageId::new();
        unwrap!(routing.get_idata(nae_mgr.clone(), *orig_data.name(), msg_id));
        expect_failure!(routing_rx,
                        msg_id,
                        Response::GetIData,
                        ClientError::NoSuchData);

        // First PutIData should succeed
        let msg_id = MessageId::new();
        unwrap!(routing.put_idata(client_mgr.clone(), orig_data.clone(), msg_id));
        expect_success!(routing_rx, msg_id, Response::PutIData);

        // Now GetIData should pass
        let msg_id = MessageId::new();
        unwrap!(routing.get_idata(nae_mgr.clone(), *orig_data.name(), msg_id));
        let got_data = expect_success!(routing_rx, msg_id, Response::GetIData);
        assert_eq!(got_data, orig_data);

        // GetAccountInfo should pass and show one chunk stored
        let account_info = do_get_account_info(&mut routing, &routing_rx, client_mgr.clone());
        assert_eq!(account_info.data_stored, 1);
        assert_eq!(account_info.space_available,
                   DEFAULT_CLIENT_ACCOUNT_SIZE - 1);

        // Subsequent PutIData for same data should succeed - De-duplication
        let msg_id = MessageId::new();
        unwrap!(routing.put_idata(client_mgr.clone(), orig_data.clone(), msg_id));
        expect_success!(routing_rx, msg_id, Response::PutIData);

        // GetIData should succeed
        let msg_id = MessageId::new();
        unwrap!(routing.get_idata(nae_mgr.clone(), *orig_data.name(), msg_id));
        let got_data = expect_success!(routing_rx, msg_id, Response::GetIData);
        assert_eq!(got_data, orig_data);


        // GetAccountInfo should pass and show two chunks stored
        let account_info = do_get_account_info(&mut routing, &routing_rx, client_mgr.clone());
        assert_eq!(account_info.data_stored, 2);
        assert_eq!(account_info.space_available,
                   DEFAULT_CLIENT_ACCOUNT_SIZE - 2);
    }

    fn setup() -> (MockRouting, Receiver<Event>) {
        let (_, full_id) = create_account_and_full_id();
        let (routing_tx, routing_rx) = mpsc::channel();
        let mut routing = unwrap!(MockRouting::new(routing_tx, Some(full_id)));

        // Wait until connection is established.
        match unwrap!(routing_rx.recv()) {
            Event::Connected => (),
            e => panic!("Unexpected event {:?}", e),
        }

        (routing, routing_rx)
    }

    fn create_account_and_full_id() -> (Account, FullId) {
        let account = Account::new();
        let id = FullId::with_keys((account.get_maid().public_keys().1,
                                    account.get_maid().secret_keys().1.clone()),
                                   (account.get_maid().public_keys().0,
                                    account.get_maid().secret_keys().0.clone()));

        (account, id)
    }

    fn do_get_account_info(routing: &mut MockRouting,
                           routing_rx: &Receiver<Event>,
                           client_mgr: Authority)
                           -> AccountInfo {
        let msg_id = MessageId::new();
        unwrap!(routing.get_account_info(client_mgr, msg_id));
        expect_success!(routing_rx, msg_id, Response::GetAccountInfo)
    }

    /*

    #[test]
    fn check_put_post_get_delete_for_structured_data() {
        let (account_packet, id_packet) = create_account_and_full_id();
        let (routing_sender, routing_receiver) = mpsc::channel();
        let mut mock_routing = unwrap!(MockRouting::new(routing_sender, Some(id_packet)));
        wait_for_connection(&routing_receiver);

        let owner_key = account_packet.get_public_maid().public_keys().0.clone();
        let sign_key = &account_packet.get_maid().secret_keys().0;

        // Construct ImmutableData
        let orig_immutable_data = generate_random_immutable_data();
        let orig_data = Data::Immutable(orig_immutable_data);

        const TYPE_TAG: u64 = 999;

        // Construct StructuredData, 1st version, for this ImmutableData
        let keyword = unwrap!(utility::generate_random_string(10));
        let pin = unwrap!(utility::generate_random_string(10));
        let user_id = unwrap!(Account::generate_network_id(keyword.as_bytes(),
                                                           pin.to_string().as_bytes()));
        let account_ver_res = StructuredData::new(TYPE_TAG,
                                                  user_id,
                                                  0,
                                                  unwrap!(serialise(&vec![orig_data.name()])),
                                                  vec![owner_key.clone()],
                                                  Vec::new(),
                                                  Some(sign_key));
        let mut account_version = unwrap!(account_ver_res);
        let mut data_account_version = Data::Structured(account_version);


        let location_nae_mgr_immut = Authority::NaeManager(*orig_data.name());
        let location_nae_mgr_struct = Authority::NaeManager(*data_account_version.name());

        let location_client_mgr_immut = Authority::ClientManager(*orig_data.name());
        let location_client_mgr_struct = Authority::ClientManager(*data_account_version.name());

        // First PUT of StructuredData should succeed
        unwrap!(do_put(&mut mock_routing,
                       &routing_receiver,
                       location_client_mgr_struct.clone(),
                       data_account_version.clone()));

        // PUT for ImmutableData should succeed
        unwrap!(do_put(&mut mock_routing,
                       &routing_receiver,
                       location_client_mgr_immut.clone(),
                       orig_data.clone()));

        let mut received_structured_data: StructuredData;

        // GET StructuredData should pass
        {
            let struct_data_id = DataIdentifier::Structured(user_id, TYPE_TAG);
            let data = unwrap!(do_get(&mut mock_routing,
                                      &routing_receiver,
                                      location_client_mgr_struct.clone(),
                                      struct_data_id));

            assert_eq!(data, data_account_version);
            match data {
                Data::Structured(struct_data) => received_structured_data = struct_data,
                _ => unreachable!("Unexpected! {:?}", data),
            }
        }

        // GetAccountInfo should pass and show two chunks stored
        assert_eq!(unwrap!(do_get_account_info(&mut mock_routing,
                                               &routing_receiver,
                                               location_client_mgr_struct.clone())),

                   (2, DEFAULT_CLIENT_ACCOUNT_SIZE - 2));

        // GET ImmutableData from latest version of StructuredData should pass
        {
            let mut location_vec =
                unwrap!(deserialise::<Vec<XorName>>(received_structured_data.get_data()));
            let immut_data_id = DataIdentifier::Immutable(unwrap!(location_vec.pop(),
                                                                  "Value must exist !"));

            assert_eq!(unwrap!(do_get(&mut mock_routing,
                                      &routing_receiver,
                                      location_client_mgr_immut.clone(),
                                      immut_data_id)),
                       orig_data);
        }

        // Construct ImmutableData
        let new_immutable_data = generate_random_immutable_data();
        let new_data = Data::Immutable(new_immutable_data);

        // PUT for new ImmutableData should succeed
        unwrap!(do_put(&mut mock_routing,
                       &routing_receiver,
                       location_client_mgr_struct.clone(),
                       new_data.clone()));

        // Construct StructuredData, 2nd version, for this ImmutableData - INVALID
        // Versioning
        let invalid_version_account_version = unwrap!(StructuredData::new(TYPE_TAG,
                                                                          user_id,
                                                                          0,
                                                                          Vec::new(),
                                                                          vec![owner_key.clone()],
                                                                          Vec::new(),
                                                                          Some(sign_key)));
        let invalid_version_data_account_version =
            Data::Structured(invalid_version_account_version);

        // Construct StructuredData, 2nd version, for this ImmutableData - INVALID
        // Signature
        let invalid_signature_account_version = unwrap!(StructuredData::new(TYPE_TAG,
                                        user_id,
                                        1,
                                        Vec::new(),
                                        vec![owner_key.clone()],
                                        Vec::new(),
                                        Some(&account_packet.get_mpid().secret_keys().0)));
        let invalid_signature_data_account_version =
            Data::Structured(invalid_signature_account_version);

        let data_for_version_2 = unwrap!(serialise(&vec![orig_data.name(), new_data.name()]));
        // Construct StructuredData, 2nd version, for this ImmutableData - Valid
        account_version = unwrap!(StructuredData::new(TYPE_TAG,
                                                      user_id,
                                                      1,
                                                      data_for_version_2,
                                                      vec![owner_key.clone()],
                                                      Vec::new(),
                                                      Some(sign_key)));
        data_account_version = Data::Structured(account_version);

        // Subsequent PUTs for same StructuredData should fail
        {
            let result = do_put(&mut mock_routing,
                                &routing_receiver,
                                location_client_mgr_struct.clone(),
                                data_account_version.clone());

            match result {
                Ok(_) => panic!("Expected Put Failure!"),
                Err(CoreError::MutationFailure { reason: MutationError::DataExists, .. }) => (),
                Err(err) => panic!("Unexpected: {:?}", err),
            }
        }

        // Subsequent POSTSs for same StructuredData should fail if versioning is
        // invalid
        {
            let result = do_post(&mut mock_routing,
                                 &routing_receiver,
                                 location_nae_mgr_struct.clone(),
                                 invalid_version_data_account_version);

            match result {
                Ok(_) => panic!("Expected Post Failure!"),
                Err(CoreError::MutationFailure { reason: MutationError::InvalidSuccessor, .. }) => {
                    ()
                }
                Err(err) => panic!("Unexpected: {:?}", err),
            }
        }

        // Subsequent POSTSs for same StructuredData should fail if signature is invalid
        {
            let result = do_post(&mut mock_routing,
                                 &routing_receiver,
                                 location_client_mgr_struct.clone(),
                                 invalid_signature_data_account_version);

            match result {
                Ok(_) => panic!("Expected Post Failure!"),
                Err(CoreError::MutationFailure { reason: MutationError::InvalidSuccessor, .. }) => {
                    ()
                }
                Err(err) => panic!("Unexpected: {:?}", err),
            }
        }

        // Subsequent POSTSs for existing StructuredData version should pass for valid
        // update
        unwrap!(do_post(&mut mock_routing,
                        &routing_receiver,
                        location_nae_mgr_struct.clone(),
                        data_account_version.clone()));

        // GET for new StructuredData version should pass
        {
            let struct_data_id = DataIdentifier::Structured(user_id, TYPE_TAG);
            let data = unwrap!(do_get(&mut mock_routing,
                                      &routing_receiver,
                                      location_nae_mgr_struct.clone(),
                                      struct_data_id));

            assert_eq!(data, data_account_version);
            match data {
                Data::Structured(struct_data) => received_structured_data = struct_data,
                _ => unreachable!("Unexpected! {:?}", data),
            }
        }

        let location_vec =
            unwrap!(deserialise::<Vec<XorName>>(received_structured_data.get_data()));
        assert_eq!(location_vec.len(), 2);

        // GET new ImmutableData should pass
        {
            let immut_data_id = DataIdentifier::Immutable(location_vec[1]);
            assert_eq!(unwrap!(do_get(&mut mock_routing,
                                      &routing_receiver,
                                      location_nae_mgr_immut.clone(),
                                      immut_data_id)),
                       new_data);
        }

        // GET original ImmutableData should pass
        {
            let immut_data_id = DataIdentifier::Immutable(location_vec[0]);
            assert_eq!(unwrap!(do_get(&mut mock_routing,
                                      &routing_receiver,
                                      location_client_mgr_immut.clone(),
                                      immut_data_id)),
                       orig_data);
        }

        // DELETE of Structured Data without version bump should fail
        {
            let result = do_delete(&mut mock_routing,
                                   &routing_receiver,
                                   location_client_mgr_struct.clone(),
                                   data_account_version.clone());

            match result {
                Ok(_) => panic!("Expected Delete Failure!"),
                Err(CoreError::MutationFailure { reason: MutationError::InvalidSuccessor, .. }) => {
                    ()
                }
                Err(err) => panic!("Unexpected: {:?}", err),
            }
        }

        // GET for StructuredData version should still pass
        {
            let struct_data_id = DataIdentifier::Structured(user_id, TYPE_TAG);
            assert_eq!(unwrap!(do_get(&mut mock_routing,
                                      &routing_receiver,
                                      location_client_mgr_struct.clone(),
                                      struct_data_id)),
                       data_account_version);
        }

        // Construct StructuredData, 3rd version, for DELETE - Valid
        account_version = unwrap!(StructuredData::new(TYPE_TAG,
                                                      user_id,
                                                      2,
                                                      vec![],
                                                      vec![owner_key.clone()],
                                                      vec![],
                                                      Some(sign_key)));
        data_account_version = Data::Structured(account_version);

        // DELETE of Structured Data with version bump should pass
        unwrap!(do_delete(&mut mock_routing,
                          &routing_receiver,
                          location_client_mgr_struct.clone(),
                          data_account_version));

        // GET for deleted StructuredData version should return empty data
        {
            let struct_data_id = DataIdentifier::Structured(user_id, TYPE_TAG);
            let data = unwrap!(do_get(&mut mock_routing,
                                      &routing_receiver,
                                      location_nae_mgr_struct.clone(),
                                      struct_data_id));

            let data = match data {
                Data::Structured(data) => data,
                _ => panic!("Unexpected data type"),
            };

            assert!(data.get_data().is_empty());
            assert!(data.get_owner_keys().is_empty());
        }

        // PUT after DELETE without version bump fails
        account_version = unwrap!(StructuredData::new(TYPE_TAG,
                                                      user_id,
                                                      0,
                                                      vec![],
                                                      vec![owner_key.clone()],
                                                      vec![],
                                                      Some(sign_key)));
        data_account_version = Data::Structured(account_version);

        let result = do_put(&mut mock_routing,
                            &routing_receiver,
                            location_client_mgr_struct.clone(),
                            data_account_version);

        match result {
            Ok(_) => panic!("Expected PUT Failure!"),
            Err(CoreError::MutationFailure { reason: MutationError::InvalidSuccessor, .. }) => (),
            Err(err) => panic!("Unexpected: {:?}", err),
        }

        // Repeated DELETE fails
        account_version = unwrap!(StructuredData::new(TYPE_TAG,
                                                      user_id,
                                                      3,
                                                      vec![],
                                                      vec![owner_key.clone()],
                                                      vec![],
                                                      Some(sign_key)));
        data_account_version = Data::Structured(account_version);

        let result = do_delete(&mut mock_routing,
                               &routing_receiver,
                               location_client_mgr_struct.clone(),
                               data_account_version);

        match result {
            Ok(_) => panic!("Expected DELETE Failure!"),
            Err(CoreError::MutationFailure { reason: MutationError::InvalidOperation, .. }) => (),
            Err(err) => panic!("Unexpected: {:?}", err),
        }

        // PUT after DELETE with version bump restores data
        account_version = unwrap!(StructuredData::new(TYPE_TAG,
                                                      user_id,
                                                      3,
                                                      vec![],
                                                      vec![owner_key.clone()],
                                                      vec![],
                                                      Some(sign_key)));
        data_account_version = Data::Structured(account_version);

        unwrap!(do_put(&mut mock_routing,
                       &routing_receiver,
                       location_client_mgr_struct.clone(),
                       data_account_version.clone()));

        let data_id = DataIdentifier::Structured(user_id, TYPE_TAG);
        let data = unwrap!(do_get(&mut mock_routing,
                                  &routing_receiver,
                                  location_nae_mgr_struct.clone(),
                                  data_id));

        assert_eq!(data, data_account_version);

        // GetAccountInfo should pass and show four chunks stored
        assert_eq!(unwrap!(do_get_account_info(&mut mock_routing,
                                               &routing_receiver,
                                               location_client_mgr_immut)),
                   (4, DEFAULT_CLIENT_ACCOUNT_SIZE - 4));
    }

    #[test]
    fn check_put_post_get_append_delete_for_pub_appendable_data() {
        let (account_packet, id_packet) = create_account_and_full_id();
        let (routing_sender, routing_receiver) = mpsc::channel();
        let mut mock_routing = unwrap!(MockRouting::new(routing_sender, Some(id_packet)));
        wait_for_connection(&routing_receiver);

        let owner_key = account_packet.get_public_maid().public_keys().0.clone();
        let sign_sk = account_packet.get_maid().secret_keys().0.clone();

        // Construct some immutable data to be later appended to an appendable data.
        let immut_data_0 = Data::Immutable(generate_random_immutable_data());
        let immut_data_0_nae_mgr = Authority::NaeManager(*immut_data_0.name());

        unwrap!(do_put(&mut mock_routing,
                       &routing_receiver,
                       immut_data_0_nae_mgr,
                       immut_data_0.clone()));

        let immut_data_1 = Data::Immutable(generate_random_immutable_data());
        let immut_data_1_nae_mgr = Authority::NaeManager(*immut_data_1.name());

        unwrap!(do_put(&mut mock_routing,
                       &routing_receiver,
                       immut_data_1_nae_mgr,
                       immut_data_1.clone()));

        // Construct appendable data
        let appendable_data_name = rand::random();
        let appendable_data_nae_mgr = Authority::NaeManager(appendable_data_name);

        let appendable_data = unwrap!(PubAppendableData::new(appendable_data_name,
                                                             0,
                                                             vec![owner_key],
                                                             vec![],
                                                             Default::default(),
                                                             Filter::black_list(iter::empty()),
                                                             Some(&sign_sk)));

        let appendable_data_id = appendable_data.identifier();

        // PUT it to the network
        unwrap!(do_put(&mut mock_routing,
                       &routing_receiver,
                       appendable_data_nae_mgr.clone(),
                       Data::PubAppendable(appendable_data)));

        // APPEND data
        {
            let appended_data =
                unwrap!(AppendedData::new(immut_data_0.identifier(), owner_key, &sign_sk));
            let append_wrapper = AppendWrapper::new_pub(appendable_data_name, appended_data, 0);

            unwrap!(do_append(&mut mock_routing,
                              &routing_receiver,
                              appendable_data_nae_mgr.clone(),
                              append_wrapper));
        }

        // GET the appendable data back from the network and verify it has the
        // previously appended data.
        let appendable_data = unwrap!(do_get(&mut mock_routing,
                                             &routing_receiver,
                                             appendable_data_nae_mgr.clone(),
                                             appendable_data_id));

        let appendable_data = match appendable_data {
            Data::PubAppendable(data) => data,
            _ => panic!("Unexpected data type"),
        };

        assert_eq!(appendable_data.name, appendable_data_name);
        assert_eq!(appendable_data.data.len(), 1);

        let appended_data = unwrap!(appendable_data.data.iter().next());
        assert_eq!(appended_data.pointer, immut_data_0.identifier());

        // APPEND more data
        {
            let appended_data =
                unwrap!(AppendedData::new(immut_data_1.identifier(), owner_key, &sign_sk));
            let append_wrapper = AppendWrapper::new_pub(appendable_data_name,
                                                        appended_data,
                                                        appendable_data.version);

            unwrap!(do_append(&mut mock_routing,
                              &routing_receiver,
                              appendable_data_nae_mgr.clone(),
                              append_wrapper));
        }

        // GET the appendable data back from the network and verify it has all the
        // previously appended data.
        let appendable_data = unwrap!(do_get(&mut mock_routing,
                                             &routing_receiver,
                                             appendable_data_nae_mgr.clone(),
                                             appendable_data_id));

        let appendable_data = match appendable_data {
            Data::PubAppendable(data) => data,
            _ => panic!("Unexpected data type"),
        };

        assert_eq!(appendable_data.version, 0);
        assert_eq!(appendable_data.name, appendable_data_name);
        assert_eq!(appendable_data.data.len(), 2);

        // POST without version bump should fail
        let result = do_post(&mut mock_routing,
                             &routing_receiver,
                             appendable_data_nae_mgr.clone(),
                             Data::PubAppendable(appendable_data.clone()));

        match result {
            Ok(_) => panic!("Expected POST failure"),
            Err(CoreError::MutationFailure { reason: MutationError::InvalidSuccessor, .. }) => (),
            Err(error) => panic!("Unexpected: {:?}", error),
        }

        // POST with modified filter.
        let (blacklisted_pk, blacklisted_sk) = sign::gen_keypair();
        let filter = Filter::black_list(iter::once(blacklisted_pk));
        let appendable_data = unwrap!(PubAppendableData::new(appendable_data.name,
                                                             appendable_data.version + 1,
                                                             appendable_data.current_owner_keys
                                                                 .clone(),
                                                             appendable_data.previous_owner_keys
                                                                 .clone(),
                                                             appendable_data.deleted_data.clone(),
                                                             filter,
                                                             Some(&sign_sk)));

        unwrap!(do_post(&mut mock_routing,
                        &routing_receiver,
                        appendable_data_nae_mgr.clone(),
                        Data::PubAppendable(appendable_data)));

        // GET it back and verify the filter and version are modified.
        let appendable_data = unwrap!(do_get(&mut mock_routing,
                                             &routing_receiver,
                                             appendable_data_nae_mgr.clone(),
                                             appendable_data_id));

        let appendable_data = match appendable_data {
            Data::PubAppendable(data) => data,
            _ => panic!("Unexpected data type"),
        };

        assert_eq!(appendable_data.version, 1);

        match appendable_data.filter {
            Filter::BlackList(ref list) => {
                assert_eq!(list.len(), 1);
                assert!(list.contains(&blacklisted_pk));
            }
            _ => panic!("Unexpected filter type"),
        }

        // APPEND by a blacklisted user should fail.
        {
            let immut_data_name = rand::random();
            let immut_data_id = DataIdentifier::Immutable(immut_data_name);

            let appended_data =
                unwrap!(AppendedData::new(immut_data_id, blacklisted_pk, &blacklisted_sk));
            let append_wrapper = AppendWrapper::new_pub(appendable_data_name,
                                                        appended_data,
                                                        appendable_data.version);

            let result = do_append(&mut mock_routing,
                                   &routing_receiver,
                                   appendable_data_nae_mgr.clone(),
                                   append_wrapper);

            match result {
                Ok(_) => panic!("Expected APPEND failure"),
                Err(CoreError::MutationFailure { reason: MutationError::InvalidSuccessor, .. }) => {
                    ()
                }
                Err(error) => panic!("Unexpected {:?}", error),
            }
        }

        // TODO: test also whitelist

        // PUT with data already appended.
        let appendable_data_name = rand::random();
        let appendable_data_nae_mgr = Authority::NaeManager(appendable_data_name);

        let mut appendable_data = unwrap!(PubAppendableData::new(appendable_data_name,
                                                                 0,
                                                                 vec![owner_key],
                                                                 vec![],
                                                                 Default::default(),
                                                                 Filter::black_list(iter::empty()),
                                                                 Some(&sign_sk)));

        let appendable_data_id = appendable_data.identifier();

        let appended_data =
            unwrap!(AppendedData::new(immut_data_0.identifier(), owner_key, &sign_sk));
        assert!(appendable_data.append(appended_data));

        unwrap!(do_put(&mut mock_routing,
                       &routing_receiver,
                       appendable_data_nae_mgr.clone(),
                       Data::PubAppendable(appendable_data)));

        // GET it back and verify the appended data is there.
        let appendable_data = unwrap!(do_get(&mut mock_routing,
                                             &routing_receiver,
                                             appendable_data_nae_mgr.clone(),
                                             appendable_data_id));

        let appendable_data = match appendable_data {
            Data::PubAppendable(data) => data,
            _ => panic!("Unexpected data type"),
        };

        assert_eq!(appendable_data.data.len(), 1);

        let appended_data = unwrap!(appendable_data.data.iter().next());
        assert_eq!(appended_data.pointer, immut_data_0.identifier());

        // TODO: test POST with appended data too
        // TODO: test simultaneous POSTs with different appended data - verify
        // the appendable data contains data items from both POSTs afterwards.
    }

    // Do a GET request and wait for the response.
    fn do_get(routing: &mut MockRouting,
              routing_rx: &Receiver<Event>,
              dst: Authority,
              data_id: DataIdentifier)
              -> Result<Data, CoreError> {
        let message_id = MessageId::new();
        unwrap!(routing.send_get_request(dst, data_id, message_id));

        match unwrap!(routing_rx.recv()) {
            Event::Response { response: Response::GetSuccess(data, id), .. } => {
                assert_eq!(id, message_id);
                Ok(data)
            }
            Event::Response { response: Response::GetFailure { id,
                                                     data_id,
                                                     external_error_indicator },
                              .. } => {
                assert_eq!(id, message_id);
                let reason = unwrap!(deserialise(&external_error_indicator));

                Err(CoreError::GetFailure {
                    data_id: data_id,
                    reason: reason,
                })
            }
            event => panic!("Unexpected routing event: {:?}", event),
        }
    }

    // Do a PUT request and wait for the response.
    fn do_put(routing: &mut MockRouting,
              routing_rx: &Receiver<Event>,
              dst: Authority,
              data: Data)
              -> Result<(), CoreError> {
        let message_id = MessageId::new();
        unwrap!(routing.send_put_request(dst, data, message_id));

        match unwrap!(routing_rx.recv()) {
            Event::Response { response: Response::PutSuccess(_, id), .. } => {
                assert_eq!(id, message_id);
                Ok(())
            }
            Event::Response { response: Response::PutFailure { id,
                                                     data_id,
                                                     external_error_indicator },
                              .. } => {
                assert_eq!(id, message_id);
                let reason = unwrap!(deserialise(&external_error_indicator));

                Err(CoreError::MutationFailure {
                    data_id: data_id,
                    reason: reason,
                })
            }
            event => panic!("Unexpected routing event: {:?}", event),
        }
    }

    // Do a POST request and wait for the response.
    fn do_post(routing: &mut MockRouting,
               routing_rx: &Receiver<Event>,
               dst: Authority,
               data: Data)
               -> Result<(), CoreError> {
        let message_id = MessageId::new();
        unwrap!(routing.send_post_request(dst, data, message_id));

        match unwrap!(routing_rx.recv()) {
            Event::Response { response: Response::PostSuccess(_, id), .. } => {
                assert_eq!(id, message_id);
                Ok(())
            }
            Event::Response { response: Response::PostFailure { id,
                                                      data_id,
                                                      external_error_indicator },
                              .. } => {
                assert_eq!(id, message_id);
                let reason = unwrap!(deserialise(&external_error_indicator));

                Err(CoreError::MutationFailure {
                    data_id: data_id,
                    reason: reason,
                })
            }
            event => panic!("Unexpected routing event: {:?}", event),
        }
    }

    // Do a DELETE request and wait for the response.
    fn do_delete(routing: &mut MockRouting,
                 routing_rx: &Receiver<Event>,
                 dst: Authority,
                 data: Data)
                 -> Result<(), CoreError> {
        let message_id = MessageId::new();
        unwrap!(routing.send_delete_request(dst, data, message_id));

        match unwrap!(routing_rx.recv()) {
            Event::Response { response: Response::DeleteSuccess(_, id), .. } => {
                assert_eq!(id, message_id);
                Ok(())
            }
            Event::Response { response: Response::DeleteFailure { id,
                                                        data_id,
                                                        external_error_indicator },
                              .. } => {
                assert_eq!(id, message_id);
                let reason = unwrap!(deserialise(&external_error_indicator));

                Err(CoreError::MutationFailure {
                    data_id: data_id,
                    reason: reason,
                })
            }
            event => panic!("Unexpected routing event: {:?}", event),
        }
    }

    // Do an APPEND request and wait for the response.
    fn do_append(routing: &mut MockRouting,
                 routing_rx: &Receiver<Event>,
                 dst: Authority,
                 append_wrapper: AppendWrapper)
                 -> Result<(), CoreError> {
        let message_id = MessageId::new();
        unwrap!(routing.send_append_request(dst, append_wrapper, message_id));

        match unwrap!(routing_rx.recv()) {
            Event::Response { response: Response::AppendSuccess(_, id), .. } => {
                assert_eq!(id, message_id);
                Ok(())
            }
            Event::Response { response: Response::AppendFailure { id,
                                                        data_id,
                                                        external_error_indicator },
                              .. } => {
                assert_eq!(id, message_id);
                let reason = unwrap!(deserialise(&external_error_indicator));

                Err(CoreError::MutationFailure {
                    data_id: data_id,
                    reason: reason,
                })
            }
            event => panic!("Unexpected routing event: {:?}", event),
        }
    }

    // Do a GetAccountInfo request and wait for the response.
    fn do_get_account_info(routing: &mut MockRouting,
                           routing_rx: &Receiver<Event>,
                           dst: Authority)
                           -> Result<(u64, u64), CoreError> {
        let message_id = MessageId::new();
        unwrap!(routing.send_get_account_info_request(dst, message_id));

        match unwrap!(routing_rx.recv()) {
            Event::Response { response: Response::GetAccountInfoSuccess { id,
                                                                data_stored,
                                                                space_available },
                              .. } => {
                assert_eq!(id, message_id);
                Ok((data_stored, space_available))
            }
            Event::Response {
                response: Response::GetAccountInfoFailure { id, external_error_indicator }, ..
            } => {
                assert_eq!(id, message_id);
                let reason = unwrap!(deserialise(&external_error_indicator));

                Err(CoreError::GetAccountInfoFailure { reason: reason })
            }
            event => panic!("Unexpected routing event: {:?}", event),
        }
    }
    */
}
