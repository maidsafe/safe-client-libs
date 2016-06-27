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

use std::convert::From;
use std::sync::{Arc, Mutex};

use routing::{Data, DataIdentifier, StructuredData, XorName};
use maidsafe_utilities::serialisation::{serialise, deserialise};
use core::client::Client;
use dns::errors::DnsError;
use nfs::errors::NfsError;
use nfs::metadata::directory_key::DirectoryKey;
use core::errors::CoreError;
use core::structured_data_operations::unversioned;
use sodiumoxide::crypto::{sign, box_};
use sodiumoxide::crypto::hash::sha256;
use safe_network_common::TYPE_TAG_DNS_PACKET;
use safe_network_common::client_errors::MutationError;

mod dns_configuration;

/// This is a representational structure for all safe-dns operations
pub struct DnsOperations {
    client: Arc<Mutex<Client>>,
}

impl DnsOperations {
    /// Create a new instance of DnsOperations. It is intended that only one of this be created as
    /// it operates on global data such as files.
    pub fn new(client: Arc<Mutex<Client>>) -> Result<DnsOperations, DnsError> {
        try!(dns_configuration::initialise_dns_configuaration(client.clone()));

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
    pub fn register_dns(&self,
                        long_name: String,
                        public_messaging_encryption_key: &box_::PublicKey,
                        secret_messaging_encryption_key: &box_::SecretKey,
                        services: &Vec<(String, DirectoryKey)>,
                        owners: Vec<sign::PublicKey>,
                        private_signing_key: &sign::SecretKey,
                        data_encryption_keys: Option<(&box_::PublicKey,
                                                      &box_::SecretKey,
                                                      &box_::Nonce)>)
                        -> Result<(), DnsError> {
        debug!("Registering {:?} dns ...", long_name);
        let mut saved_configs = try!(dns_configuration::get_dns_configuration_data(self.client
                                                                                        .clone()));
        if saved_configs.iter().any(|config| config.long_name == long_name) {
            Err(DnsError::DnsNameAlreadyRegistered)
        } else {
            let identifier = XorName(sha256::hash(long_name.as_bytes()).0);

            let dns_record = Dns {
                long_name: long_name.clone(),
                services: services.iter().map(|a| a.clone()).collect(),
                encryption_key: public_messaging_encryption_key.clone(),
            };

            let struct_data = try!(unversioned::create(self.client.clone(),
                                                       TYPE_TAG_DNS_PACKET,
                                                       identifier,
                                                       0,
                                                       try!(serialise(&dns_record)),
                                                       owners,
                                                       vec![],
                                                       private_signing_key,
                                                       data_encryption_keys));
            match unwrap_result!(self.client.lock())
                            .put_recover(Data::Structured(struct_data), None)
            {
                Ok(()) => (),
                Err(CoreError::MutationFailure { reason: MutationError::DataExists, .. }) => {
                    return Err(DnsError::DnsNameAlreadyRegistered)
                }
                Err(err) => return Err(From::from(err)),
            }

            debug!("Adding encryption key pair to saved dns configuration ...");
            saved_configs.push(dns_configuration::DnsConfiguration {
                long_name: long_name,
                encryption_keypair: (public_messaging_encryption_key.clone(),
                                     secret_messaging_encryption_key.clone()),
            });
            try!(dns_configuration::write_dns_configuration_data(self.client.clone(),
                                                                 &saved_configs));

            Ok(())
        }
    }

    /// Delete the Dns-Record
    pub fn delete_dns(&self,
                      long_name: &String,
                      private_signing_key: &sign::SecretKey)
                      -> Result<(), DnsError> {
        let mut saved_configs = try!(dns_configuration::get_dns_configuration_data(self.client
                                                                                        .clone()));
        let pos = try!(saved_configs.iter()
                                    .position(|config| config.long_name == *long_name)
                                    .ok_or(DnsError::DnsRecordNotFound));

        let prev_struct_data = try!(self.get_housing_structured_data(long_name));

        let struct_data = try!(unversioned::create(self.client.clone(),
                                                   TYPE_TAG_DNS_PACKET,
                                                   prev_struct_data.get_identifier().clone(),
                                                   prev_struct_data.get_version() + 1,
                                                   vec![],
                                                   prev_struct_data.get_owner_keys().clone(),
                                                   prev_struct_data.get_previous_owner_keys()
                                                                   .clone(),
                                                   private_signing_key,
                                                   None));
        try!(try!(unwrap_result!(self.client.lock()).delete(Data::Structured(struct_data), None))
                 .get());

        debug!("Removing dns saved configs at {:?} position ...", pos);
        let _ = saved_configs.remove(pos);
        try!(dns_configuration::write_dns_configuration_data(self.client.clone(), &saved_configs));

        Ok(())
    }

    /// Get all the Dns-names registered by the user so far in the network.
    pub fn get_all_registered_names(&self) -> Result<Vec<String>, DnsError> {
        dns_configuration::get_dns_configuration_data(self.client.clone())
            .map(|v| v.iter().map(|a| a.long_name.clone()).collect())
    }

    /// Get the messaging encryption keys that the user has associated with one's particular
    /// Dns-name.
    pub fn get_messaging_encryption_keys
        (&self,
         long_name: &String)
         -> Result<(box_::PublicKey, box_::SecretKey), DnsError> {
        let dns_config_record = try!(self.find_dns_record(long_name));
        Ok(dns_config_record.encryption_keypair.clone())
    }

    /// Get all the services (www, blog, micro-blog etc) that user has associated with this
    /// Dns-name
    pub fn get_all_services(&self,
                            long_name: &String,
                            data_decryption_keys: Option<(&box_::PublicKey,
                                                          &box_::SecretKey,
                                                          &box_::Nonce)>)
                            -> Result<Vec<String>, DnsError> {
        // Allow unregistered clients to access this function
        match self.find_dns_record(long_name) {
            Ok(_) => (),
            Err(DnsError::CoreError(CoreError::OperationForbiddenForClient)) => (),
            Err(DnsError::NfsError(NfsError::CoreError(
                CoreError::OperationForbiddenForClient))) => (),
            Err(error) => return Err(error),
        };

        let (_, dns_record) =
            try!(self.get_housing_structured_data_and_dns_record(long_name, data_decryption_keys));
        Ok(dns_record.services.keys().map(|a| a.clone()).collect())
    }

    /// Get the home directory (eg., homepage containing HOME.html, INDEX.html) for the given
    /// service.
    pub fn get_service_home_directory_key(&self,
                                          long_name: &String,
                                          service_name: &String,
                                          data_decryption_keys: Option<(&box_::PublicKey,
                                                                        &box_::SecretKey,
                                                                        &box_::Nonce)>)
                                          -> Result<DirectoryKey, DnsError> {
        // Allow unregistered clients to access this function
        match self.find_dns_record(long_name) {
            Ok(_) => (),
            Err(DnsError::CoreError(CoreError::OperationForbiddenForClient)) => (),
            Err(DnsError::NfsError(NfsError::CoreError(
                CoreError::OperationForbiddenForClient))) => (),
            Err(DnsError::DnsRecordNotFound) => (),
            Err(error) => return Err(error),
        };
        let (_, dns_record) =
            try!(self.get_housing_structured_data_and_dns_record(long_name, data_decryption_keys));
        dns_record.services
                  .get(service_name)
                  .map(|v| v.clone())
                  .ok_or(DnsError::ServiceNotFound)
    }

    /// Add a new service for the given Dns-name.
    pub fn add_service(&self,
                       long_name: &String,
                       new_service: (String, DirectoryKey),
                       private_signing_key: &sign::SecretKey,
                       data_encryption_decryption_keys: Option<(&box_::PublicKey,
                                                                &box_::SecretKey,
                                                                &box_::Nonce)>)
                       -> Result<(), DnsError> {
        self.add_remove_service_impl(long_name,
                                     (new_service.0, Some(new_service.1)),
                                     private_signing_key,
                                     data_encryption_decryption_keys)
    }

    /// Remove a service from the given Dns-name.
    pub fn remove_service(&self,
                          long_name: &String,
                          service_to_remove: String,
                          private_signing_key: &sign::SecretKey,
                          data_encryption_decryption_keys: Option<(&box_::PublicKey,
                                                                   &box_::SecretKey,
                                                                   &box_::Nonce)>)
                          -> Result<(), DnsError> {
        self.add_remove_service_impl(long_name,
                                     (service_to_remove, None),
                                     private_signing_key,
                                     data_encryption_decryption_keys)
    }

    fn find_dns_record(&self,
                       long_name: &String)
                       -> Result<dns_configuration::DnsConfiguration, DnsError> {
        let config_vec = try!(dns_configuration::get_dns_configuration_data(self.client.clone()));
        config_vec.iter()
                  .find(|config| config.long_name == *long_name)
                  .map(|v| v.clone())
                  .ok_or(DnsError::DnsRecordNotFound)
    }

    fn add_remove_service_impl(&self,
                               long_name: &String,
                               service: (String, Option<DirectoryKey>),
                               private_signing_key: &sign::SecretKey,
                               data_encryption_decryption_keys: Option<(&box_::PublicKey,
                                                                        &box_::SecretKey,
                                                                        &box_::Nonce)>)
                               -> Result<(), DnsError> {
        let _ = try!(self.find_dns_record(long_name));

        let is_add_service = service.1.is_some();
        let (prev_struct_data, mut dns_record) =
            try!(self.get_housing_structured_data_and_dns_record(long_name,
                                                                 data_encryption_decryption_keys));

        if !is_add_service && !dns_record.services.contains_key(&service.0) {
            Err(DnsError::ServiceNotFound)
        } else if is_add_service && dns_record.services.contains_key(&service.0) {
            Err(DnsError::ServiceAlreadyExists)
        } else {
            if is_add_service {
                debug!("Inserting service ...");
                let _ = dns_record.services
                                  .insert(service.0,
                                          try!(service.1
                                                      .ok_or(DnsError::from("Programming \
                                                                             Error - Investiga\
                                                                             te !!"))));
            } else {
                debug!("Removing service ...");
                let _ = dns_record.services.remove(&service.0);
            }

            let struct_data = try!(unversioned::create(self.client.clone(),
                                                       TYPE_TAG_DNS_PACKET,
                                                       prev_struct_data.get_identifier().clone(),
                                                       prev_struct_data.get_version() + 1,
                                                       try!(serialise(&dns_record)),
                                                       prev_struct_data.get_owner_keys().clone(),
                                                       prev_struct_data.get_previous_owner_keys()
                                                                       .clone(),
                                                       private_signing_key,
                                                       data_encryption_decryption_keys));
            try!(try!(unwrap_result!(self.client.lock())
                          .post(Data::Structured(struct_data), None))
                     .get());

            Ok(())
        }
    }

    fn get_housing_structured_data_and_dns_record(&self,
                                                  long_name: &String,
                                                  data_decryption_keys: Option<(&box_::PublicKey,
                                                                                &box_::SecretKey,
                                                                                &box_::Nonce)>)
                                                  -> Result<(StructuredData, Dns), DnsError> {
        let struct_data = try!(self.get_housing_structured_data(long_name));
        let dns_record = try!(deserialise(&try!(unversioned::get_data(self.client.clone(),
                                                                      &struct_data,
                                                                      data_decryption_keys))));
        Ok((struct_data, dns_record))
    }

    fn get_housing_structured_data(&self, long_name: &String) -> Result<StructuredData, DnsError> {
        let identifier = XorName(sha256::hash(long_name.as_bytes()).0);
        let request = DataIdentifier::Structured(identifier, TYPE_TAG_DNS_PACKET);
        debug!("Retrieving structured data from network for {:?} dns ...",
               long_name);
        let response_getter = try!(unwrap_result!(self.client.lock()).get(request, None));
        if let Data::Structured(struct_data) = try!(response_getter.get()) {
            Ok(struct_data)
        } else {
            Err(DnsError::from(CoreError::ReceivedUnexpectedData))
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, RustcEncodable, RustcDecodable)]
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
    use routing::{XorName, XOR_NAME_LEN};
    use sodiumoxide::crypto::box_;
    use std::sync::{Arc, Mutex};

    #[test]
    fn register_and_delete_dns() {
        let client = Arc::new(Mutex::new(unwrap_result!(test_utils::get_client())));
        let dns_operations = unwrap_result!(DnsOperations::new(client.clone()));

        let dns_name = unwrap_result!(generate_random_string(10));
        let messaging_keypair = box_::gen_keypair();
        let owners = vec![unwrap_result!(unwrap_result!(client.lock()).get_public_signing_key())
                              .clone()];

        let secret_signing_key = unwrap_result!(unwrap_result!(client.lock())
                                                    .get_secret_signing_key())
                                     .clone();

        // Register
        unwrap_result!(dns_operations.register_dns(dns_name.clone(),
                                                   &messaging_keypair.0,
                                                   &messaging_keypair.1,
                                                   &vec![],
                                                   owners.clone(),
                                                   &secret_signing_key,
                                                   None));

        // Get Services
        let services = unwrap_result!(dns_operations.get_all_services(&dns_name, None));
        assert_eq!(services.len(), 0);

        // Re-registering by the same client is not allowed
        match dns_operations.register_dns(dns_name.clone(),
                                          &messaging_keypair.0,
                                          &messaging_keypair.1,
                                          &vec![],
                                          owners.clone(),
                                          &secret_signing_key,
                                          None) {
            Ok(_) => panic!("Should have been an error"),
            Err(DnsError::DnsNameAlreadyRegistered) => (),
            Err(error) => panic!("{:?}", error),
        }

        // Re-registering by a different new_client is not allowed
        {
            let new_client = Arc::new(Mutex::new(unwrap_result!(test_utils::get_client())));
            let dns_operations = unwrap_result!(DnsOperations::new(new_client.clone()));

            let messaging_keypair = box_::gen_keypair();
            let owners = vec![unwrap_result!(unwrap_result!(new_client.lock())
                                                 .get_public_signing_key())
                                  .clone()];

            let secret_signing_key = unwrap_result!(unwrap_result!(new_client.lock())
                                                        .get_secret_signing_key())
                                         .clone();
            match dns_operations.register_dns(dns_name.clone(),
                                              &messaging_keypair.0,
                                              &messaging_keypair.1,
                                              &vec![],
                                              owners.clone(),
                                              &secret_signing_key,
                                              None) {
                Ok(_) => panic!("Should have been an error"),
                Err(DnsError::DnsNameAlreadyRegistered) => (),
                Err(error) => panic!("{:?}", error),
            }
        }

        // Delete
        unwrap_result!(dns_operations.delete_dns(&dns_name, &secret_signing_key));

        // Registering again should be allowed
        unwrap_result!(dns_operations.register_dns(dns_name,
                                                   &messaging_keypair.0,
                                                   &messaging_keypair.1,
                                                   &vec![],
                                                   owners,
                                                   &secret_signing_key,
                                                   None));
    }

    #[test]
    fn manipulate_services() {
        let client = Arc::new(Mutex::new(unwrap_result!(test_utils::get_client())));
        let dns_operations = unwrap_result!(DnsOperations::new(client.clone()));

        let dns_name = unwrap_result!(generate_random_string(10));
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

        let owners = vec![unwrap_result!(unwrap_result!(client.lock()).get_public_signing_key())
                              .clone()];

        let secret_signing_key = unwrap_result!(unwrap_result!(client.lock())
                                                    .get_secret_signing_key())
                                     .clone();

        // Register
        unwrap_result!(dns_operations.register_dns(dns_name.clone(),
                                                   &messaging_keypair.0,
                                                   &messaging_keypair.1,
                                                   &services,
                                                   owners.clone(),
                                                   &secret_signing_key,
                                                   None));

        // Get all dns-names
        let dns_records_vec = unwrap_result!(dns_operations.get_all_registered_names());
        assert_eq!(dns_records_vec.len(), 1);

        // Gets should be possible with unregistered clients
        let unregistered_client =
            Arc::new(Mutex::new(unwrap_result!(Client::create_unregistered_client())));
        let dns_operations_unregistered = DnsOperations::new_unregistered(unregistered_client);

        // Get all services for a dns-name
        let services_vec = unwrap_result!(dns_operations_unregistered.get_all_services(&dns_name,
                                                                                       None));
        assert_eq!(services.len(), services_vec.len());
        assert!(services.iter()
                        .all(|&(ref a, _)| services_vec.iter().find(|b| *a == **b).is_some()));

        assert!(dns_operations.get_service_home_directory_key(&"bogus".to_string(),
                                                              &services[0].0,
                                                              None)
                              .is_err());

        // Get information about a service - the home-directory and its type
        let home_dir_key_result =
            dns_operations_unregistered.get_service_home_directory_key(&dns_name,
                                                                       &services[1].0,
                                                                       None);
        let home_dir_key = unwrap_result!(home_dir_key_result);
        assert_eq!(home_dir_key, services[1].1);

        // Remove a service
        let removed_service = services.remove(1);
        unwrap_result!(dns_operations.remove_service(&dns_name,
                                                     removed_service.0.clone(),
                                                     &secret_signing_key,
                                                     None));
        ::std::thread::sleep(::std::time::Duration::from_secs(1));

        // Get all services
        let services_vec = unwrap_result!(dns_operations_unregistered.get_all_services(&dns_name,
                                                                                       None));
        assert_eq!(services.len(), services_vec.len());
        assert!(services.iter()
                        .all(|&(ref a, _)| services_vec.iter().find(|b| *a == **b).is_some()));

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
        unwrap_result!(dns_operations.add_service(&dns_name,
                                                  services[services_size - 1].clone(),
                                                  &secret_signing_key,
                                                  None));

        // Get all services
        let services_vec = unwrap_result!(dns_operations_unregistered.get_all_services(&dns_name,
                                                                                       None));
        assert_eq!(services.len(), services_vec.len());
        assert!(services.iter()
                        .all(|&(ref a, _)| services_vec.iter().find(|b| *a == **b).is_some()));
    }
}
