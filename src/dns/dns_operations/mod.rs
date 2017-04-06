// Copyright 2015 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement.  This, along with the Licenses can be
// found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use core::client::Client;
use core::errors::CoreError;
use core::structured_data_operations::unversioned;
use dns::errors::DnsError;
use maidsafe_utilities::serialisation::{deserialise, serialise};
use nfs::metadata::directory_key::DirectoryKey;
use routing::{Data, DataIdentifier, StructuredData, XorName};
use routing::TYPE_TAG_DNS_PACKET;
use routing::client_errors::{GetError, MutationError};
use rust_sodium::crypto::{box_, sign};
use rust_sodium::crypto::hash::sha256;
use std::collections::BTreeSet;
use std::convert::From;
use std::sync::{Arc, Mutex};

pub mod dns_configuration;

/// This is a representational structure for all safe-dns operations
pub struct DnsOperations {
    client: Arc<Mutex<Client>>,
}

impl DnsOperations {
    /// Create a new instance of DnsOperations. It is intended that only one of this be created as
    /// it operates on global data such as files.
    pub fn new(client: Arc<Mutex<Client>>) -> Result<DnsOperations, DnsError> {
        dns_configuration::initialise_dns_configuaration(client.clone())?;

        Ok(DnsOperations { client: client })
    }

    /// Create a new instance of DnsOperations. This is used for an unregistered client and will
    /// have very limited set of functionalities - mostly reads. This is ideal for browsers etc.,
    /// which only want to fetch from the Network, not mutate it.
    /// It is intended that only one of this be created as it operates on global data such as
    /// files.
    pub fn new_unregistered(unregistered_client: Arc<Mutex<Client>>) -> DnsOperations {
        DnsOperations { client: unregistered_client }
    }

    /// Register one's own Dns - eg., pepsico.com, spandansharma.com, krishnakumar.in etc
    #[cfg_attr(feature="cargo-clippy", allow(too_many_arguments))]
    pub fn register_dns(&self,
                        long_name: String,
                        public_messaging_encryption_key: &box_::PublicKey,
                        secret_messaging_encryption_key: &box_::SecretKey,
                        services: &[(String, DirectoryKey)],
                        owners: BTreeSet<sign::PublicKey>,
                        private_signing_key: &sign::SecretKey,
                        data_encryption_keys: Option<(&box_::PublicKey,
                                                      &box_::SecretKey,
                                                      &box_::Nonce)>)
                        -> Result<(), DnsError> {
        trace!("Registering dns with name: {}", long_name);

        let mut saved_configs = dns_configuration::get_dns_configuration_data(self.client.clone())?;
        if saved_configs
               .iter()
               .any(|config| config.long_name == long_name) {
            Err(DnsError::DnsNameAlreadyRegistered)
        } else {
            let identifier = XorName(sha256::hash(long_name.as_bytes()).0);

            let dns_record = Dns {
                long_name: long_name.clone(),
                services: services.iter().cloned().collect(),
                encryption_key: *public_messaging_encryption_key,
            };

            let mut struct_data = unversioned::create(self.client.clone(),
                                                      TYPE_TAG_DNS_PACKET,
                                                      identifier,
                                                      0,
                                                      serialise(&dns_record)?,
                                                      owners.clone(),
                                                      data_encryption_keys)?;
            let _ = struct_data
                .add_signature(&(*owners
                                      .iter()
                                      .nth(0)
                                      .ok_or_else(|| CoreError::ReceivedUnexpectedData)?,
                                 private_signing_key.clone()))
                .map_err(CoreError::from)?;

            match Client::put_recover(self.client.clone(), Data::Structured(struct_data), None) {
                Ok(()) => (),
                Err(CoreError::MutationFailure { reason: MutationError::DataExists, .. }) => {
                    return Err(DnsError::DnsNameAlreadyRegistered)
                }
                Err(err) => return Err(From::from(err)),
            }

            trace!("Adding encryption key pair to the retrieved saved dns configuration.");
            saved_configs.push(dns_configuration::DnsConfiguration {
                                   long_name: long_name,
                                   encryption_keypair: (*public_messaging_encryption_key,
                                                        secret_messaging_encryption_key.clone()),
                               });
            dns_configuration::write_dns_configuration_data(self.client.clone(), &saved_configs)?;

            Ok(())
        }
    }

    /// Delete the Dns-Record
    pub fn delete_dns(&self,
                      long_name: &str,
                      private_signing_key: &sign::SecretKey)
                      -> Result<(), DnsError> {
        trace!("Deleting dns with name: {}", long_name);

        let mut saved_configs = dns_configuration::get_dns_configuration_data(self.client.clone())?;
        let pos = saved_configs
            .iter()
            .position(|config| config.long_name == *long_name)
            .ok_or(DnsError::DnsRecordNotFound)?;

        match self.get_housing_structured_data(long_name) {
            Ok(prev_struct_data) => {
                let mut struct_data = unversioned::create(self.client.clone(),
                                                          TYPE_TAG_DNS_PACKET,
                                                          *prev_struct_data.name(),
                                                          prev_struct_data.get_version() + 1,
                                                          vec![],
                                                          prev_struct_data.get_owners().clone(),
                                                          None)?;
                let owner_key = *unwrap!(self.client.lock()).get_public_signing_key()?;
                let _ = struct_data
                    .add_signature(&(owner_key, private_signing_key.clone()))
                    .map_err(CoreError::from)?;
                Client::delete_recover(self.client.clone(), Data::Structured(struct_data), None)?;
            }
            Err(DnsError::CoreError(CoreError::GetFailure {
                                        reason: GetError::NoSuchData, ..
                                    })) => (),
            Err(e) => return Err(e),
        };

        trace!("Removing dns entry from the retrieved saved config.");
        let _ = saved_configs.remove(pos);
        dns_configuration::write_dns_configuration_data(self.client.clone(), &saved_configs)?;

        Ok(())
    }

    /// Get all the Dns-names registered by the user so far in the network.
    pub fn get_all_registered_names(&self) -> Result<Vec<String>, DnsError> {
        trace!("Get all dns long names that we own.");

        dns_configuration::get_dns_configuration_data(self.client.clone())
            .map(|v| v.iter().map(|a| a.long_name.clone()).collect())
    }

    /// Get the messaging encryption keys that the user has associated with one's particular
    /// Dns-name.
    pub fn get_messaging_encryption_keys
        (&self,
         long_name: &str)
         -> Result<(box_::PublicKey, box_::SecretKey), DnsError> {
        trace!("Get messaging encryption keys for owned dns with name: {}",
               long_name);

        let dns_config_record = self.find_dns_record(long_name)?;
        Ok(dns_config_record.encryption_keypair.clone())
    }

    /// Get all the services (www, blog, micro-blog etc) that user has associated with this
    /// Dns-name
    pub fn get_all_services(&self,
                            long_name: &str,
                            data_decryption_keys: Option<(&box_::PublicKey,
                                                          &box_::SecretKey,
                                                          &box_::Nonce)>)
                            -> Result<Vec<String>, DnsError> {
        trace!("Get all services for the dns with name: {}", long_name);

        let (_, dns_record) =
            self.get_housing_structured_data_and_dns_record(long_name, data_decryption_keys)?;
        Ok(dns_record.services.keys().cloned().collect())
    }

    /// Get the home directory (eg., homepage containing HOME.html, INDEX.html) for the given
    /// service.
    pub fn get_service_home_directory_key(&self,
                                          long_name: &str,
                                          service_name: &str,
                                          data_decryption_keys: Option<(&box_::PublicKey,
                                                                        &box_::SecretKey,
                                                                        &box_::Nonce)>)
                                          -> Result<DirectoryKey, DnsError> {
        trace!("Get service home directory key (to locate the home directory on SAFE Network) \
                for \"//{}.{}\".",
               service_name,
               long_name);

        let (_, dns_record) =
            self.get_housing_structured_data_and_dns_record(long_name, data_decryption_keys)?;
        dns_record
            .services
            .get(service_name)
            .cloned()
            .ok_or(DnsError::ServiceNotFound)
    }

    /// Add a new service for the given Dns-name.
    pub fn add_service(&self,
                       long_name: &str,
                       new_service: (String, DirectoryKey),
                       private_signing_key: &sign::SecretKey,
                       data_encryption_decryption_keys: Option<(&box_::PublicKey,
                                                                &box_::SecretKey,
                                                                &box_::Nonce)>)
                       -> Result<(), DnsError> {
        trace!("Add service {:?} to dns with name: {}",
               new_service,
               long_name);

        self.add_remove_service_impl(long_name,
                                     (new_service.0, Some(new_service.1)),
                                     private_signing_key,
                                     data_encryption_decryption_keys)
    }

    /// Remove a service from the given Dns-name.
    pub fn remove_service(&self,
                          long_name: &str,
                          service_to_remove: String,
                          private_signing_key: &sign::SecretKey,
                          data_encryption_decryption_keys: Option<(&box_::PublicKey,
                                                                   &box_::SecretKey,
                                                                   &box_::Nonce)>)
                          -> Result<(), DnsError> {
        trace!("Remove service {:?} from dns with name: {}",
               service_to_remove,
               long_name);

        self.add_remove_service_impl(long_name,
                                     (service_to_remove, None),
                                     private_signing_key,
                                     data_encryption_decryption_keys)
    }

    fn find_dns_record(&self,
                       long_name: &str)
                       -> Result<dns_configuration::DnsConfiguration, DnsError> {
        let config_vec = dns_configuration::get_dns_configuration_data(self.client.clone())?;
        config_vec
            .iter()
            .find(|config| config.long_name == *long_name)
            .cloned()
            .ok_or(DnsError::DnsRecordNotFound)
    }

    fn add_remove_service_impl(&self,
                               long_name: &str,
                               service: (String, Option<DirectoryKey>),
                               private_signing_key: &sign::SecretKey,
                               data_encryption_decryption_keys: Option<(&box_::PublicKey,
                                                                        &box_::SecretKey,
                                                                        &box_::Nonce)>)
                               -> Result<(), DnsError> {
        let _ = self.find_dns_record(long_name)?;

        let is_add_service = service.1.is_some();
        let (prev_struct_data, mut dns_record) =
            self.get_housing_structured_data_and_dns_record(long_name,
                                                            data_encryption_decryption_keys)?;

        if !is_add_service && !dns_record.services.contains_key(&service.0) {
            Err(DnsError::ServiceNotFound)
        } else if is_add_service && dns_record.services.contains_key(&service.0) {
            Err(DnsError::ServiceAlreadyExists)
        } else {
            if is_add_service {
                debug!("Inserting service ...");
                let _ =
                    dns_record.services
                        .insert(service.0,
                                service.1.ok_or_else(
                                    || DnsError::from("Programming Error - Investigate !!"))?);
            } else {
                debug!("Removing service ...");
                let _ = dns_record.services.remove(&service.0);
            }

            let mut struct_data = unversioned::create(self.client.clone(),
                                                      TYPE_TAG_DNS_PACKET,
                                                      *prev_struct_data.name(),
                                                      prev_struct_data.get_version() + 1,
                                                      serialise(&dns_record)?,
                                                      prev_struct_data.get_owners().clone(),
                                                      data_encryption_decryption_keys)?;
            let owner_key = *unwrap!(prev_struct_data.get_owners().iter().nth(0),
                                     "Logic error: SD doesn't have any owners");
            let _ = struct_data
                .add_signature(&(owner_key, private_signing_key.clone()))
                .map_err(CoreError::from)?;

            let resp_getter = unwrap!(self.client.lock())
                .post(Data::Structured(struct_data), None)?;
            resp_getter.get()?;

            Ok(())
        }
    }

    fn get_housing_structured_data_and_dns_record(&self,
                                                  long_name: &str,
                                                  data_decryption_keys: Option<(&box_::PublicKey,
                                                                                &box_::SecretKey,
                                                                                &box_::Nonce)>)
-> Result<(StructuredData, Dns), DnsError>{
        let struct_data = self.get_housing_structured_data(long_name)?;
        let dns_record = deserialise(&unversioned::get_data(self.client.clone(),
                                                            &struct_data,
                                                            data_decryption_keys)?)?;
        Ok((struct_data, dns_record))
    }

    fn get_housing_structured_data(&self, long_name: &str) -> Result<StructuredData, DnsError> {
        trace!("Fetch capsule from network for dns with name: {}",
               long_name);

        let identifier = XorName(sha256::hash(long_name.as_bytes()).0);
        let request = DataIdentifier::Structured(identifier, TYPE_TAG_DNS_PACKET);
        let response_getter = unwrap!(self.client.lock()).get(request, None)?;
        if let Data::Structured(struct_data) = response_getter.get()? {
            Ok(struct_data)
        } else {
            Err(DnsError::from(CoreError::ReceivedUnexpectedData))
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct Dns {
    long_name: String,
    services: ::std::collections::HashMap<String, DirectoryKey>,
    encryption_key: box_::PublicKey,
}

#[cfg(test)]
mod test {
    use super::*;
    use core::client::Client;
    use core::utility::{generate_random_string, test_utils};
    use dns::errors::DnsError;
    use nfs::AccessLevel;
    use nfs::metadata::directory_key::DirectoryKey;
    use routing::{XOR_NAME_LEN, XorName};
    use rust_sodium::crypto::box_;
    use std::collections::BTreeSet;
    use std::sync::{Arc, Mutex};

    #[test]
    fn register_and_delete_dns() {
        let client = Arc::new(Mutex::new(unwrap!(test_utils::get_client())));
        let dns_operations = unwrap!(DnsOperations::new(client.clone()));

        let dns_name = unwrap!(generate_random_string(10));
        let messaging_keypair = box_::gen_keypair();
        let mut owners = BTreeSet::new();
        owners.insert(*unwrap!(unwrap!(client.lock()).get_public_signing_key()));

        let secret_signing_key = unwrap!(unwrap!(client.lock()).get_secret_signing_key()).clone();

        // Trying to delete before we've registered should give the right error.
        match dns_operations.delete_dns(&dns_name, &secret_signing_key) {
            Ok(x) => {
                panic!("Deleting before we registered should have been an error.
                             \
                        Instead we got: {:?}",
                       x)
            }
            Err(DnsError::DnsRecordNotFound) => (),
            Err(e) => panic!("Got the wrong error: {:?}", e),
        };

        // Trying to delete when it's in our config but not on the network should succeed.
        let config_data =
            dns_configuration::get_dns_configuration_data(dns_operations.client.clone());
        let mut saved_configs = unwrap!(config_data);
        saved_configs.push(dns_configuration::DnsConfiguration {
                               long_name: dns_name.clone(),
                               encryption_keypair: (messaging_keypair.0,
                                                    messaging_keypair.1.clone()),
                           });
        unwrap!(dns_configuration::write_dns_configuration_data(dns_operations.client.clone(),
                                                                &saved_configs));
        unwrap!(dns_operations.delete_dns(&dns_name, &secret_signing_key));

        // Trying to delete a second time should error again.
        match dns_operations.delete_dns(&dns_name, &secret_signing_key) {
            Ok(x) => {
                panic!("Deleting before we registered should have been an error.
                             \
                        Instead we got: {:?}",
                       x)
            }
            Err(DnsError::DnsRecordNotFound) => (),
            Err(e) => panic!("Got the wrong error: {:?}", e),
        };

        // Register
        unwrap!(dns_operations.register_dns(dns_name.clone(),
                                            &messaging_keypair.0,
                                            &messaging_keypair.1,
                                            &[],
                                            owners.clone(),
                                            &secret_signing_key,
                                            None));

        // Get Services
        let services = unwrap!(dns_operations.get_all_services(&dns_name, None));
        assert_eq!(services.len(), 0);

        // Re-registering by the same client is not allowed
        match dns_operations.register_dns(dns_name.clone(),
                                          &messaging_keypair.0,
                                          &messaging_keypair.1,
                                          &[],
                                          owners.clone(),
                                          &secret_signing_key,
                                          None) {
            Ok(_) => panic!("Should have been an error"),
            Err(DnsError::DnsNameAlreadyRegistered) => (),
            Err(error) => panic!("{:?}", error),
        }

        // Pretend that the last registration failed at our end. Re-registering should succeed.
        unwrap!(dns_configuration::write_dns_configuration_data(dns_operations.client.clone(),
                                                                &[]));
        unwrap!(dns_operations.register_dns(dns_name.clone(),
                                            &messaging_keypair.0,
                                            &messaging_keypair.1,
                                            &[],
                                            owners.clone(),
                                            &secret_signing_key,
                                            None));


        // Re-registering by the same client is not allowed again (check that we're back in a sane
        // state).
        match dns_operations.register_dns(dns_name.clone(),
                                          &messaging_keypair.0,
                                          &messaging_keypair.1,
                                          &[],
                                          owners,
                                          &secret_signing_key,
                                          None) {
            Ok(_) => panic!("Should have been an error"),
            Err(DnsError::DnsNameAlreadyRegistered) => (),
            Err(error) => panic!("{:?}", error),
        }

        // Re-registering by a different new_client is not allowed
        {
            let new_client = Arc::new(Mutex::new(unwrap!(test_utils::get_client())));
            let dns_operations = unwrap!(DnsOperations::new(new_client.clone()));

            let messaging_keypair = box_::gen_keypair();
            let mut owners = BTreeSet::new();
            owners.insert(*unwrap!(unwrap!(new_client.lock()).get_public_signing_key()));

            let secret_signing_key = unwrap!(unwrap!(new_client.lock()).get_secret_signing_key())
                .clone();
            match dns_operations.register_dns(dns_name.clone(),
                                              &messaging_keypair.0,
                                              &messaging_keypair.1,
                                              &[],
                                              owners,
                                              &secret_signing_key,
                                              None) {
                Ok(_) => panic!("Should have been an error"),
                Err(DnsError::DnsNameAlreadyRegistered) => (),
                Err(error) => panic!("{:?}", error),
            }
        }

        // Delete
        unwrap!(dns_operations.delete_dns(&dns_name, &secret_signing_key));

        // TODO Since Delete no longer deletes it actually, PUT with version 0 will fail - we need a
        // version check.
        // Registering again should be allowed
        // unwrap!(dns_operations.register_dns(dns_name,
        //                                     &messaging_keypair.0,
        //                                     &messaging_keypair.1,
        //                                     &[],
        //                                     owners,
        //                                     &secret_signing_key,
        //                                     None));
    }

    #[test]
    fn manipulate_services() {
        let client = Arc::new(Mutex::new(unwrap!(test_utils::get_client())));
        let dns_operations = unwrap!(DnsOperations::new(client.clone()));

        let dns_name = unwrap!(generate_random_string(10));
        let messaging_keypair = box_::gen_keypair();

        let mut services = vec![("www".to_string(),
                                 DirectoryKey::new(XorName([123; XOR_NAME_LEN]),
                                                   15000,
                                                   false,
                                                   AccessLevel::Public)),
                                ("blog".to_string(),
                                 DirectoryKey::new(XorName([123; XOR_NAME_LEN]),
                                                   15000,
                                                   false,
                                                   AccessLevel::Public)),
                                ("bad-ass".to_string(),
                                 DirectoryKey::new(XorName([123; XOR_NAME_LEN]),
                                                   15000,
                                                   false,
                                                   AccessLevel::Public))];

        let mut owners = BTreeSet::new();
        owners.insert(*unwrap!(unwrap!(client.lock()).get_public_signing_key()));

        let secret_signing_key = unwrap!(unwrap!(client.lock()).get_secret_signing_key()).clone();

        // Register
        unwrap!(dns_operations.register_dns(dns_name.clone(),
                                            &messaging_keypair.0,
                                            &messaging_keypair.1,
                                            &services,
                                            owners,
                                            &secret_signing_key,
                                            None));

        // Get all dns-names
        let dns_records_vec = unwrap!(dns_operations.get_all_registered_names());
        assert_eq!(dns_records_vec.len(), 1);

        // Gets should be possible with unregistered clients
        let unregistered_client =
            Arc::new(Mutex::new(unwrap!(Client::create_unregistered_client())));
        let dns_operations_unregistered = DnsOperations::new_unregistered(unregistered_client);

        // Get all services for a dns-name
        let services_vec = unwrap!(dns_operations_unregistered.get_all_services(&dns_name, None));
        assert_eq!(services.len(), services_vec.len());
        assert!(services
                    .iter()
                    .all(|&(ref a, _)| services_vec.iter().any(|b| *a == **b)));
        assert!(dns_operations
                    .get_service_home_directory_key(&"bogus".to_string(),
                                                    &services[0].0,
                                                    None)
                    .is_err());

        // Get information about a service - the home-directory and its type
        let home_dir_key_result =
            dns_operations_unregistered.get_service_home_directory_key(&dns_name,
                                                                       &services[1].0,
                                                                       None);
        let home_dir_key = unwrap!(home_dir_key_result);
        assert_eq!(home_dir_key, services[1].1);

        // Remove a service
        let removed_service = services.remove(1);
        unwrap!(dns_operations.remove_service(&dns_name,
                                              removed_service.0.clone(),
                                              &secret_signing_key,
                                              None));
        ::std::thread::sleep(::std::time::Duration::from_secs(1));

        // Get all services
        let services_vec = unwrap!(dns_operations_unregistered.get_all_services(&dns_name, None));
        assert_eq!(services.len(), services_vec.len());
        assert!(services
                    .iter()
                    .all(|&(ref a, _)| services_vec.iter().any(|b| *a == **b)));

        // Try to enquire about a deleted service
        match dns_operations_unregistered.get_service_home_directory_key(&dns_name,
                                                                         &removed_service.0,
                                                                         None) {
            Ok(_) => panic!("Should have been an error"),
            Err(DnsError::ServiceNotFound) => (),
            Err(error) => panic!("{:?}", error),
        }

        // Add a service
        services.push(("added-service".to_string(),
                       DirectoryKey::new(XorName([126; XOR_NAME_LEN]),
                                         15000,
                                         false,
                                         AccessLevel::Public)));
        let services_size = services.len();
        unwrap!(dns_operations.add_service(&dns_name,
                                           services[services_size - 1].clone(),
                                           &secret_signing_key,
                                           None));

        // Get all services
        let services_vec = unwrap!(dns_operations_unregistered.get_all_services(&dns_name, None));
        assert_eq!(services.len(), services_vec.len());
        assert!(services
                    .iter()
                    .all(|&(ref a, _)| services_vec.iter().any(|b| *a == **b)));
    }

    #[test]
    #[cfg(feature = "use-mock-routing")]
    fn register_and_delete_dns_internal_error_recovery() {
        use core::errors::CoreError;
        use nfs::errors::NfsError;
        use routing::client_errors::GetError;
        use maidsafe_utilities;

        unwrap!(maidsafe_utilities::log::init(true));

        let client = Arc::new(Mutex::new(unwrap!(test_utils::get_client())));
        let dns_operations = unwrap!(DnsOperations::new(client.clone()));
        let dns_name = unwrap!(generate_random_string(10));
        let messaging_keypair = box_::gen_keypair();
        let mut owners = BTreeSet::new();
        owners.insert(*unwrap!(unwrap!(client.lock()).get_public_signing_key()));
        let secret_signing_key = unwrap!(unwrap!(client.lock()).get_secret_signing_key()).clone();

        // Limit of `Some(2)` would prevent the mutation to happen. We want one
        // `Mutation` exactly at this point
        unwrap!(client.lock()).set_network_limits(Some(3));

        info!("Fail to register the name");
        match dns_operations.register_dns(dns_name.clone(),
                                          &messaging_keypair.0,
                                          &messaging_keypair.1,
                                          &[],
                                          owners.clone(),
                                          &secret_signing_key,
                                          None) {
            Err(DnsError::NfsError(NfsError::CoreError(CoreError::GetFailure {
                                                           reason: GetError::NetworkOther(ref s), ..
                                                       }))) if s == "Max operations exhausted" => {
                ()
            }
            Ok(()) => panic!("Operation unexpectedly had succeed"),
            Err(e) => panic!("Unexpected error {:?}", e),
        }

        // Remove artificial network failure
        unwrap!(client.lock()).set_network_limits(None);

        info!("Now try and delete. It should fail because the registration failed.");
        match dns_operations.delete_dns(&dns_name, &secret_signing_key) {
            Err(DnsError::DnsRecordNotFound) => (),
            Ok(()) => panic!("Operation unexpectedly had succeed"),
            Err(e) => panic!("Unexpected error {:?}", e),
        }

        info!("List of registered names should be empty");
        let names = unwrap!(dns_operations.get_all_registered_names());
        assert!(names.is_empty());

        info!("Register for real this time.");
        unwrap!(dns_operations.register_dns(dns_name.clone(),
                                            &messaging_keypair.0,
                                            &messaging_keypair.1,
                                            &[],
                                            owners.clone(),
                                            &secret_signing_key,
                                            None));

        info!("Delete with simulated failure");
        unwrap!(client.lock()).set_network_limits(Some(5));
        match dns_operations.delete_dns(&dns_name, &secret_signing_key) {
            Err(DnsError::NfsError(NfsError::CoreError(CoreError::GetFailure {
                                                           reason: GetError::NetworkOther(ref s), ..
                                                       }))) if s == "Max operations exhausted" => {
                ()
            }
            Ok(()) => panic!("Operation unexpectedly had succeed"),
            Err(e) => panic!("Unexpected error {:?}", e),
        }

        // Remove artificial network failure
        unwrap!(client.lock()).set_network_limits(None);

        info!("Fail to register because it's already registered");
        match dns_operations.register_dns(dns_name.clone(),
                                          &messaging_keypair.0,
                                          &messaging_keypair.1,
                                          &[],
                                          owners.clone(),
                                          &secret_signing_key,
                                          None) {
            Err(DnsError::DnsNameAlreadyRegistered) => (),
            Ok(()) => panic!("Operation unexpectedly had succeed"),
            Err(e) => panic!("Unexpected error {:?}", e),
        }

        info!("List of registered names should contain record");
        let names = unwrap!(dns_operations.get_all_registered_names());
        assert_eq!(&names[..], &[&dns_name[..]]);

        info!("Delete should succeed");
        unwrap!(dns_operations.delete_dns(&dns_name, &secret_signing_key));

        info!("List of registered names should be empty");
        let names = unwrap!(dns_operations.get_all_registered_names());
        assert!(names.is_empty());

        // TODO Since Delete no longer deletes it actually, PUT with version 0 will fail - we need a
        // version check.
        // info!("Register for real again.");
        // unwrap!(dns_operations.register_dns(dns_name.clone(),
        //                                     &messaging_keypair.0,
        //                                     &messaging_keypair.1,
        //                                     &[],
        //                                     owners.clone(),
        //                                     &secret_signing_key,
        //                                     None));

    }
}
