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

//! DNS operations.

use core::{Client, CoreError};
use core::futures::FutureExt;
use core::structured_data::{self, unversioned};
use futures::Future;
use maidsafe_utilities::serialisation::{deserialise, serialise};
use nfs::DirId;
use routing::{Data, StructuredData, TYPE_TAG_DNS_PACKET, XorName};
use routing::client_errors::{GetError, MutationError};
use rust_sodium::crypto::{box_, secretbox, sign};
use rust_sodium::crypto::hash::sha256;
use std::collections::HashMap;
use super::{DnsError, DnsFuture};
use super::config::{self, DnsConfig};

/// Register one's own Dns - eg., pepsico.com, spandansharma.com,
/// krishnakumar.in etc
pub fn register_dns<S>(client: &Client,
                       long_name: S,
                       public_messaging_encryption_key: box_::PublicKey,
                       secret_messaging_encryption_key: box_::SecretKey,
                       services: &[(String, DirId)],
                       owners: Vec<sign::PublicKey>,
                       sign_sk: sign::SecretKey,
                       encryption_key: Option<secretbox::Key>)
                       -> Box<DnsFuture<()>>
    where S: Into<String>
{
    let long_name = long_name.into();

    trace!("Registering dns with name: {}", long_name);

    let client2 = client.clone();
    let client3 = client.clone();
    let client4 = client.clone();

    let services = services.iter().cloned().collect();
    let public_messaging_encryption_key2 = public_messaging_encryption_key.clone();

    let sign_sk2 = sign_sk.clone();

    config::read(client)
        .and_then(move |saved_configs| {
            if saved_configs.iter().any(|config| config.long_name == long_name) {
                Err(DnsError::DnsNameAlreadyRegistered)
            } else {
                let dns_record = Dns {
                    long_name: long_name.clone(),
                    services: services,
                    encryption_key: public_messaging_encryption_key2,
                };
                let encoded_dns_record = serialise(&dns_record)?;

                Ok((encoded_dns_record, saved_configs, long_name))
            }
        })
        .and_then(move |(encoded_dns_record, saved_configs, long_name)| {
            let identifier = XorName(sha256::hash(long_name.as_bytes()).0);
            unversioned::create(&client2,
                                TYPE_TAG_DNS_PACKET,
                                identifier,
                                0,
                                encoded_dns_record,
                                owners,
                                vec![],
                                sign_sk,
                                encryption_key)
                .map(move |struct_data| (struct_data, saved_configs, long_name))
                .map_err(DnsError::from)
        })
        .and_then(move |(struct_data, saved_configs, long_name)| {
            client3.put_recover(Data::Structured(struct_data), None, sign_sk2)
                .map(move |_| (saved_configs, long_name))
                .map_err(|err| match err {
                    CoreError::MutationFailure { reason: MutationError::DataExists, .. } => {
                        DnsError::DnsNameAlreadyRegistered
                    }
                    err => DnsError::from(err),
                })
        })
        .and_then(move |(mut saved_configs, long_name)| {
            trace!("Adding encryption key pair to the retrieved saved dns configuration.");
            saved_configs.push(DnsConfig {
                long_name: long_name,
                encryption_keypair: (public_messaging_encryption_key,
                                     secret_messaging_encryption_key),
            });

            config::write(&client4, saved_configs)
        })
        .into_box()
}


/// Delete the Dns-Record
pub fn delete_dns<S>(client: &Client, long_name: S, sign_sk: sign::SecretKey) -> Box<DnsFuture<()>>
    where S: Into<String>
{
    let long_name = long_name.into();

    trace!("Deleting dns with name: {}", long_name);

    let client2 = client.clone();
    let client3 = client.clone();

    config::read(client)
        .and_then(move |saved_configs| {
            saved_configs.iter()
                .position(|config| config.long_name == long_name)
                .ok_or(DnsError::DnsRecordNotFound)
                .map(move |pos| (saved_configs, pos, long_name))
        })
        .and_then(move |(saved_configs, pos, long_name)| {
            get_housing_structured_data(&client2, &long_name)
                .and_then(move |struct_data| {
                    structured_data::delete_recover(&client2, struct_data, &sign_sk)
                        .map_err(DnsError::from)
                })
                .or_else(|err| match err {
                    DnsError::CoreError(CoreError::GetFailure {
                        reason: GetError::NoSuchData, ..
                    }) => Ok(()),
                    err => Err(err),
                })
                .map(move |_| (saved_configs, pos))
        })
        .and_then(move |(mut saved_configs, pos)| {
            trace!("Removing dns entry from the retrieved saved config.");
            let _ = saved_configs.remove(pos);
            config::write(&client3, saved_configs)
        })
        .into_box()
}

/// Get all the Dns-names registered by the user so far in the network.
pub fn get_all_registered_names(client: &Client) -> Box<DnsFuture<Vec<String>>> {
    trace!("Get all dns long names that we own.");
    config::read(client)
        .map(|configs| configs.iter().map(|c| c.long_name.clone()).collect())
        .into_box()
}

/// Get the messaging encryption keys that the user has associated with one's
/// particular Dns-name.
pub fn get_messaging_encryption_keys(client: &Client,
                                     long_name: String)
                                     -> Box<DnsFuture<(box_::PublicKey, box_::SecretKey)>> {
    trace!("Get messaging encryption keys for owned dns with name: {}",
           long_name);

    find_dns_record(client, long_name)
        .map(|record| record.encryption_keypair)
        .into_box()
}

/// Get all the services (www, blog, micro-blog etc) that user has associated
/// with this Dns-name
pub fn get_all_services<L>(client: &Client,
                           long_name: L,
                           decryption_key: Option<secretbox::Key>)
                           -> Box<DnsFuture<Vec<String>>>
    where L: AsRef<str>
{
    let long_name = long_name.as_ref();

    trace!("Get all services for the dns with name: {}", long_name);

    get_housing_structured_data_and_dns_record(client, long_name, decryption_key)
        .map(|(_, dns_record)| dns_record.services.keys().cloned().collect())
        .into_box()
}

/// Add a new service for the given Dns-name.
pub fn add_service(client: &Client,
                   long_name: String,
                   new_service: (String, DirId),
                   sign_sk: sign::SecretKey,
                   encryption_key: Option<secretbox::Key>)
                   -> Box<DnsFuture<()>> {
    trace!("Add service {:?} to dns with name: {}",
           new_service,
           long_name);

    let client2 = client.clone();

    let future1 =
        get_housing_structured_data_and_dns_record(client, &long_name, encryption_key.clone());
    let future2 = find_dns_record(client, long_name);

    future1.join(future2)
        .and_then(move |((prev_data, mut dns_record), _)| {
            if dns_record.services.contains_key(&new_service.0) {
                Err(DnsError::ServiceAlreadyExists)
            } else {
                let _ = dns_record.services.insert(new_service.0, new_service.1);
                let encoded_dns_record = serialise(&dns_record)?;
                Ok((prev_data, encoded_dns_record))
            }
        })
        .and_then(move |(prev_data, encoded_dns_record)| {
            unversioned::update(&client2,
                                prev_data,
                                encoded_dns_record,
                                sign_sk,
                                encryption_key)
                .map_err(DnsError::from)
        })
        .into_box()
}

/// Remove a service from the given Dns-name.
pub fn remove_service<L, S>(client: &Client,
                            long_name: L,
                            service_name: S,
                            sign_sk: sign::SecretKey,
                            encryption_key: Option<secretbox::Key>)
                            -> Box<DnsFuture<()>>
    where L: Into<String>,
          S: Into<String>
{
    let long_name = long_name.into();
    let service_name = service_name.into();

    trace!("Remove service {:?} from dns with name: {}",
           service_name,
           long_name);

    let client2 = client.clone();

    let future1 =
        get_housing_structured_data_and_dns_record(client, &long_name, encryption_key.clone());
    let future2 = find_dns_record(client, long_name);

    future1.join(future2)
        .and_then(move |((prev_data, mut dns_record), _)| {
            if !dns_record.services.contains_key(&service_name) {
                Err(DnsError::ServiceNotFound)
            } else {
                let _ = dns_record.services.remove(&service_name);
                let encoded_dns_record = serialise(&dns_record)?;
                Ok((prev_data, encoded_dns_record))
            }
        })
        .and_then(move |(prev_data, encoded_dns_record)| {
            unversioned::update(&client2,
                                prev_data,
                                encoded_dns_record,
                                sign_sk,
                                encryption_key)
                .map_err(DnsError::from)
        })
        .into_box()
}

/// Get the home directory (eg., homepage containing HOME.html, INDEX.html) for
/// the given service.
pub fn get_service_home_dir_id<L, S>(client: &Client,
                                     long_name: L,
                                     service_name: S,
                                     decryption_key: Option<secretbox::Key>)
                                     -> Box<DnsFuture<DirId>>
    where L: AsRef<str>,
          S: Into<String>
{
    let service_name = service_name.into();
    let long_name = long_name.as_ref();

    trace!("Get service home directory key (to locate the home directory on SAFE Network) \
            for \"//{}.{}\".",
           service_name,
           long_name);

    get_housing_structured_data_and_dns_record(client, long_name, decryption_key)
        .and_then(move |(_, dns_record)| {
            dns_record.services
                .get(&service_name)
                .cloned()
                .ok_or(DnsError::ServiceNotFound)
        })
        .into_box()
}

fn get_housing_structured_data(client: &Client, long_name: &str) -> Box<DnsFuture<StructuredData>> {
    trace!("Fetch capsule from network for dns with name: {}",
           long_name);

    let identifier = XorName(sha256::hash(long_name.as_bytes()).0);

    structured_data::get(client, TYPE_TAG_DNS_PACKET, &identifier)
        .map_err(DnsError::from)
        .into_box()
}

fn get_housing_structured_data_and_dns_record(client: &Client,
                                              long_name: &str,
                                              decryption_key: Option<secretbox::Key>)
                                              -> Box<DnsFuture<(StructuredData, Dns)>> {
    let client2 = client.clone();

    get_housing_structured_data(client, long_name)
        .and_then(move |struct_data| {
            unversioned::extract_value(&client2, &struct_data, decryption_key)
                .map(move |encoded| (struct_data, encoded))
                .map_err(DnsError::from)
        })
        .and_then(|(struct_data, encoded)| {
            let dns_record = deserialise(&encoded)?;
            Ok((struct_data, dns_record))
        })
        .into_box()
}

fn find_dns_record(client: &Client, long_name: String) -> Box<DnsFuture<DnsConfig>> {
    config::read(client)
        .and_then(move |configs| {
            configs.iter()
                .find(|config| config.long_name == *long_name)
                .cloned()
                .ok_or(DnsError::DnsRecordNotFound)
        })
        .into_box()
}

#[derive(Clone, Debug, Eq, PartialEq, RustcEncodable, RustcDecodable)]
struct Dns {
    long_name: String,
    services: HashMap<String, DirId>,
    encryption_key: box_::PublicKey,
}

#[cfg(test)]
mod tests {
    use core::{Client, utility};
    use core::utility::test_utils::{finish, random_client, setup_client};
    use dns::errors::DnsError;
    use futures::Future;
    use nfs::DirId;
    use rand;
    use routing::DataIdentifier;
    use rust_sodium::crypto::box_;
    use std::collections::HashSet;
    use super::*;

    #[test]
    fn register_basics() {
        random_client(move |client| {
            let client2 = client.clone();
            let client3 = client.clone();

            let dns_name = unwrap!(utility::generate_random_string(10));
            let dns_name2 = dns_name.clone();

            let messaging_keypair = box_::gen_keypair();
            let owners = vec![unwrap!(client.public_signing_key()).clone()];
            let signing_key = unwrap!(client.secret_signing_key()).clone();

            get_all_registered_names(client)
                .then(move |res| {
                    let names = unwrap!(res);
                    assert!(names.is_empty());

                    register_dns(&client2,
                                 dns_name,
                                 messaging_keypair.0,
                                 messaging_keypair.1,
                                 &[],
                                 owners,
                                 signing_key,
                                 None)
                })
                .then(move |res| {
                    unwrap!(res);
                    get_all_registered_names(&client3)
                })
                .map(move |names| {
                    assert_eq!(names.len(), 1);
                    assert_eq!(names[0], dns_name2);
                })
        })
    }

    #[test]
    fn register_with_services() {
        let dns_name = unwrap!(utility::generate_random_string(10));
        let dns_name2 = dns_name.clone();
        let dns_name3 = dns_name.clone();

        let services = vec![gen_service("blog"), gen_service("chat")];
        let service_names = services.iter().map(|s| s.0.clone()).collect::<HashSet<_>>();
        let service_names2 = service_names.clone();

        random_client(move |client| {
            let client2 = client.clone();

            let messaging_keypair = box_::gen_keypair();
            let owners = vec![unwrap!(client.public_signing_key()).clone()];
            let signing_key = unwrap!(client.secret_signing_key()).clone();

            register_dns(client,
                         dns_name,
                         messaging_keypair.0,
                         messaging_keypair.1,
                         &services,
                         owners,
                         signing_key,
                         None)
                .then(move |res| {
                    unwrap!(res);
                    get_all_services(&client2, &dns_name2, None)
                })
                .map(move |names| {
                    // Convert to HashSet to ignore order.
                    let names = names.into_iter().collect::<HashSet<_>>();
                    assert_eq!(names, service_names);
                })
        });

        // Gets should be possible with unregistered clients
        setup_client(|el_h, core_tx, net_tx| Client::unregistered(el_h, core_tx, net_tx),
                     move |client| {
            get_all_services(client, &dns_name3, None).map(move |names| {
                // Convert to HashSet to ignore order.
                let names = names.into_iter().collect::<HashSet<_>>();
                assert_eq!(names, service_names2);
            })
        })
    }

    #[test]
    fn register_existing_name_using_the_same_client_fails() {
        random_client(move |client| {
            let client2 = client.clone();

            let dns_name = unwrap!(utility::generate_random_string(10));
            let dns_name2 = dns_name.clone();

            let messaging_keypair = box_::gen_keypair();
            let messaging_keypair2 = messaging_keypair.clone();

            let owners = vec![unwrap!(client.public_signing_key()).clone()];
            let owners2 = owners.clone();

            let signing_key = unwrap!(client.secret_signing_key()).clone();
            let signing_key2 = signing_key.clone();

            register_dns(client,
                         dns_name,
                         messaging_keypair.0,
                         messaging_keypair.1,
                         &[],
                         owners,
                         signing_key,
                         None)
                .then(move |res| {
                    unwrap!(res);
                    register_dns(&client2,
                                 dns_name2,
                                 messaging_keypair2.0,
                                 messaging_keypair2.1,
                                 &[],
                                 owners2,
                                 signing_key2,
                                 None)
                })
                .then(|res| {
                    match res {
                        Ok(_) => panic!("Should fail"),
                        Err(DnsError::DnsNameAlreadyRegistered) => (),
                        Err(err) => panic!("{:?}", err),
                    }
                    finish()
                })
        })
    }

    #[test]
    fn register_existing_name_using_different_client_fails() {
        let dns_name = unwrap!(utility::generate_random_string(10));
        let dns_name2 = dns_name.clone();

        // Client 1
        random_client(move |client| {
            let messaging_keypair = box_::gen_keypair();
            let owners = vec![unwrap!(client.public_signing_key()).clone()];
            let signing_key = unwrap!(client.secret_signing_key()).clone();

            register_dns(client,
                         dns_name,
                         messaging_keypair.0,
                         messaging_keypair.1,
                         &[],
                         owners,
                         signing_key,
                         None)
        });

        // Client 2
        random_client(move |client| {
            let messaging_keypair = box_::gen_keypair();
            let owners = vec![unwrap!(client.public_signing_key()).clone()];
            let signing_key = unwrap!(client.secret_signing_key()).clone();

            register_dns(client,
                         dns_name2,
                         messaging_keypair.0,
                         messaging_keypair.1,
                         &[],
                         owners,
                         signing_key,
                         None)
                .then(|res| {
                    match res {
                        Ok(_) => panic!("Should fail"),
                        Err(DnsError::DnsNameAlreadyRegistered) => (),
                        Err(err) => panic!("{:?}", err),
                    }
                    finish()
                })
        })
    }

    #[test]
    fn register_delete_and_reregister() {
        random_client(move |client| {
            let client2 = client.clone();
            let client3 = client.clone();
            let client4 = client.clone();

            let dns_name = unwrap!(utility::generate_random_string(10));
            let dns_name2 = dns_name.clone();
            let dns_name3 = dns_name.clone();
            let dns_name4 = dns_name.clone();

            let messaging_keypair = box_::gen_keypair();
            let messaging_keypair2 = messaging_keypair.clone();

            let owners = vec![unwrap!(client.public_signing_key()).clone()];
            let owners2 = owners.clone();

            let signing_key = unwrap!(client.secret_signing_key()).clone();
            let signing_key2 = signing_key.clone();
            let signing_key3 = signing_key.clone();

            register_dns(client,
                         dns_name,
                         messaging_keypair.0,
                         messaging_keypair.1,
                         &[],
                         owners,
                         signing_key,
                         None)
                .then(move |res| {
                    unwrap!(res);
                    delete_dns(&client2, dns_name2, signing_key2)
                })
                .then(move |res| {
                    unwrap!(res);
                    get_all_registered_names(&client3)
                })
                .then(move |res| -> Result<_, DnsError> {
                    let names = unwrap!(res);
                    assert!(!names.contains(&dns_name3));
                    Ok(())
                })
                .then(move |_| {
                    register_dns(&client4,
                                 dns_name4,
                                 messaging_keypair2.0,
                                 messaging_keypair2.1,
                                 &[],
                                 owners2,
                                 signing_key3,
                                 None)
                })
        })
    }

    #[test]
    fn delete_non_existing_name_fails() {
        random_client(move |client| {
            let dns_name = unwrap!(utility::generate_random_string(10));
            let signing_key = unwrap!(client.secret_signing_key()).clone();

            delete_dns(client, dns_name, signing_key).then(|res| {
                match res {
                    Ok(_) => panic!("Should fail"),
                    Err(DnsError::DnsRecordNotFound) => (),
                    Err(err) => panic!("{:?}", err),
                }
                finish()
            })
        })
    }

    #[test]
    fn delete_deleted_name_fails() {
        random_client(move |client| {
            let client2 = client.clone();
            let client3 = client.clone();

            let dns_name = unwrap!(utility::generate_random_string(10));
            let dns_name2 = dns_name.clone();
            let dns_name3 = dns_name.clone();

            let messaging_keypair = box_::gen_keypair();
            let owners = vec![unwrap!(client.public_signing_key()).clone()];

            let signing_key = unwrap!(client.secret_signing_key()).clone();
            let signing_key2 = signing_key.clone();
            let signing_key3 = signing_key.clone();

            register_dns(client,
                         dns_name,
                         messaging_keypair.0,
                         messaging_keypair.1,
                         &[],
                         owners,
                         signing_key,
                         None)
                .then(move |res| {
                    unwrap!(res);
                    delete_dns(&client2, dns_name2, signing_key2)
                })
                .then(move |res| {
                    unwrap!(res);
                    delete_dns(&client3, dns_name3, signing_key3)
                })
                .then(|res| {
                    match res {
                        Ok(_) => panic!("Should fail"),
                        Err(DnsError::DnsRecordNotFound) => (),
                        Err(err) => panic!("{:?}", err),
                    }
                    finish()
                })
        })
    }

    #[test]
    fn add_service_basics() {
        random_client(|client| {
            let client2 = client.clone();
            let client3 = client.clone();
            let client4 = client.clone();

            let dns_name = unwrap!(utility::generate_random_string(10));
            let dns_name2 = dns_name.clone();
            let dns_name3 = dns_name.clone();
            let dns_name4 = dns_name.clone();

            let service = gen_service("www");
            let service_name = service.0.clone();

            let messaging_keypair = box_::gen_keypair();
            let owners = vec![unwrap!(client.public_signing_key()).clone()];

            let signing_key = unwrap!(client.secret_signing_key()).clone();
            let signing_key2 = signing_key.clone();

            register_dns(client,
                         dns_name,
                         messaging_keypair.0,
                         messaging_keypair.1,
                         &[],
                         owners,
                         signing_key,
                         None)
                .then(move |res| {
                    unwrap!(res);
                    get_all_services(&client2, &dns_name2, None)
                })
                .then(move |res| {
                    let names = unwrap!(res);
                    assert!(names.is_empty());

                    add_service(&client3, dns_name3, service, signing_key2, None)
                })
                .then(move |res| {
                    unwrap!(res);
                    get_all_services(&client4, &dns_name4, None)
                })
                .map(move |names| {
                    assert_eq!(&names, &[service_name]);
                })
        })
    }

    #[test]
    fn remove_service_basics() {
        random_client(|client| {
            let client2 = client.clone();
            let client3 = client.clone();
            let client4 = client.clone();

            let dns_name = unwrap!(utility::generate_random_string(10));
            let dns_name2 = dns_name.clone();
            let dns_name3 = dns_name.clone();
            let dns_name4 = dns_name.clone();

            let service = gen_service("www");

            let messaging_keypair = box_::gen_keypair();
            let owners = vec![unwrap!(client.public_signing_key()).clone()];

            let signing_key = unwrap!(client.secret_signing_key()).clone();
            let signing_key2 = unwrap!(client.secret_signing_key()).clone();

            register_dns(client,
                         dns_name,
                         messaging_keypair.0,
                         messaging_keypair.1,
                         &[service.clone()],
                         owners,
                         signing_key,
                         None)
                .then(move |res| {
                    unwrap!(res);
                    get_all_services(&client2, &dns_name2, None)
                })
                .then(move |res| {
                    let names = unwrap!(res);
                    assert_eq!(names, [service.0.clone()]);

                    remove_service(&client3, dns_name3, service.0.clone(), signing_key2, None)
                })
                .then(move |res| {
                    unwrap!(res);
                    get_all_services(&client4, &dns_name4, None)
                })
                .map(|names| assert!(names.is_empty()))
        })
    }

    #[test]
    fn service_home_dir() {
        let dns_name = unwrap!(utility::generate_random_string(10));
        let dns_name2 = dns_name.clone();
        let dns_name3 = dns_name.clone();

        let service = gen_service("www");

        let service_name = service.0.clone();
        let service_name2 = service.0.clone();

        let service_dir_id = service.1.clone();
        let service_dir_id2 = service.1.clone();

        random_client(move |client| {
            let client2 = client.clone();

            let messaging_keypair = box_::gen_keypair();
            let owners = vec![unwrap!(client.public_signing_key()).clone()];
            let signing_key = unwrap!(client.secret_signing_key()).clone();

            register_dns(client,
                         dns_name,
                         messaging_keypair.0,
                         messaging_keypair.1,
                         &[service],
                         owners,
                         signing_key,
                         None)
                .then(move |res| {
                    unwrap!(res);
                    get_service_home_dir_id(&client2, &dns_name2, service_name, None)
                })
                .map(move |dir_id| {
                    assert_eq!(dir_id, service_dir_id);
                })
        });

        // unregistered clients can get the home dir too
        setup_client(|el_h, core_tx, net_tx| Client::unregistered(el_h, core_tx, net_tx),
                     move |client| {
                         get_service_home_dir_id(client, &dns_name3, service_name2, None)
                             .map(move |dir_id| {
                                 assert_eq!(dir_id, service_dir_id2);
                             })
                     })
    }

    fn gen_service(name: &str) -> (String, DirId) {
        use ::UNVERSIONED_STRUCT_DATA_TYPE_TAG as TAG;
        let id = DataIdentifier::Structured(rand::random(), TAG);
        (name.to_string(), (id, None))
    }
}
