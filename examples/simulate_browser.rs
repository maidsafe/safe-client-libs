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

//! Simulate browser example.

// For explanation of lint checks, run `rustc -W help` or see
// https://github.com/maidsafe/QA/blob/master/Documentation/Rust%20Lint%20Checks.md
#![forbid(bad_style, exceeding_bitshifts, mutable_transmutes, no_mangle_const_items,
          unknown_crate_types, warnings)]
#![deny(deprecated, improper_ctypes, missing_docs,
        non_shorthand_field_patterns, overflowing_literals, plugin_as_library,
        private_no_mangle_fns, private_no_mangle_statics, stable_features, unconditional_recursion,
        unknown_lints, unsafe_code, unused, unused_allocation, unused_attributes,
        unused_comparisons, unused_features, unused_parens, while_true)]
#![warn(trivial_casts, trivial_numeric_casts, unused_extern_crates, unused_import_braces,
        unused_qualifications, unused_results)]
#![allow(box_pointers, fat_ptr_transmutes, missing_copy_implementations,
         missing_debug_implementations, variant_size_differences)]

#![cfg_attr(feature="clippy", feature(plugin))]
#![cfg_attr(feature="clippy", plugin(clippy))]
#![cfg_attr(feature="clippy", deny(clippy, clippy_pedantic))]
#![cfg_attr(feature="clippy", allow(use_debug, print_stdout))]

#![allow(unused_extern_crates)]#[macro_use]
extern crate maidsafe_utilities;
extern crate regex;
extern crate routing;
extern crate safe_core;
extern crate rust_sodium;
#[macro_use]
extern crate unwrap;


use regex::Regex;

use safe_core::core::client::Client;
use safe_core::dns::dns_operations::DnsOperations;

use safe_core::dns::errors::DnsError;
use safe_core::nfs::AccessLevel;
use safe_core::nfs::helper::directory_helper::DirectoryHelper;

use safe_core::nfs::helper::file_helper::FileHelper;
use std::sync::{Arc, Mutex};

const DEFAULT_SERVICE: &'static str = "www";
const HOME_PAGE_FILE_NAME: &'static str = "index.html";

fn handle_login() -> Arc<Mutex<Client>> {
    let mut secret_0 = String::new();
    let mut secret_1 = String::new();

    println!("\n\tAccount Creation");
    println!("\t================");

    println!("\n------------ Enter account-locator ---------------");
    let _ = std::io::stdin().read_line(&mut secret_0);
    secret_0 = secret_0.trim().to_string();
    println!("\n------------ Enter password ---------------");
    let _ = std::io::stdin().read_line(&mut secret_1);
    secret_1 = secret_1.trim().to_string();

    // Account Creation
    {
        println!("\nTrying to create an account ...");
        let _ = unwrap!(Client::create_account(&secret_0, &secret_1));
        println!("Account Creation Successful !!");
    }

    println!("\n\n\tAuto Account Login");
    println!("\t==================");

    // Log into the created account
    println!("\nTrying to log into the created account using supplied credentials ...");
    Arc::new(Mutex::new(unwrap!(Client::log_in(&secret_0, &secret_1))))
}

fn create_dns_record(client: Arc<Mutex<Client>>,
                     dns_operations: &DnsOperations)
                     -> Result<(), DnsError> {
    println!("\n\n    Create Dns Record");
    println!("    =================");
    println!("\nEnter Dns Name (eg., pepsico.com [Note: more than one \".\"s are not allowed in \
              this simple example]):");
    let mut long_name = String::new();
    let _ = std::io::stdin().read_line(&mut long_name);
    long_name = long_name.trim().to_string();

    println!("\nGenerating messaging ecryption keys for you...");
    let (public_messaging_encryption_key, secret_messaging_encryption_key) =
        rust_sodium::crypto::box_::gen_keypair();

    println!("Registering Dns...");

    let owners = vec![try!(unwrap!(client.lock()).get_public_signing_key()).clone()];
    let secret_signing_key = try!(unwrap!(client.lock()).get_secret_signing_key()).clone();
    dns_operations.register_dns(long_name,
                                &public_messaging_encryption_key,
                                &secret_messaging_encryption_key,
                                &[],
                                owners,
                                &secret_signing_key,
                                None)
}

fn delete_dns_record(client: Arc<Mutex<Client>>,
                     dns_operations: &DnsOperations)
                     -> Result<(), DnsError> {
    println!("\n\n    Delete Dns Record");
    println!("    =================");
    println!("\nEnter Dns Name (eg., pepsico.com):");
    let mut long_name = String::new();
    let _ = std::io::stdin().read_line(&mut long_name);
    long_name = long_name.trim().to_string();

    let secret_signing_key = try!(unwrap!(client.lock()).get_secret_signing_key()).clone();

    println!("Deleting Dns...");

    dns_operations.delete_dns(&long_name, &secret_signing_key)
}

fn display_dns_records(dns_operations: &DnsOperations) -> Result<(), DnsError> {
    println!("\n\n    Display Dns Records");
    println!("    ===================");
    println!("\nRegistered Dns Names (fetching...):");
    let record_names = try!(dns_operations.get_all_registered_names());
    for it in record_names.iter().enumerate() {
        println!("<{:?}> {}", it.0 + 1, it.1);
    }
    Ok(())
}

fn add_service(client: Arc<Mutex<Client>>, dns_operations: &DnsOperations) -> Result<(), DnsError> {
    println!("\n\n    Add Service");
    println!("    ===========");
    println!("\nEnter Dns Name (eg., pepsico.com):");
    let mut long_name = String::new();
    let _ = std::io::stdin().read_line(&mut long_name);
    long_name = long_name.trim().to_string();

    println!("\nEnter Service Name (eg., www):");
    let mut service_name = String::new();
    let _ = std::io::stdin().read_line(&mut service_name);
    service_name = service_name.trim().to_string();

    println!("Creating Home Directory for the Service...");

    let mut service_home_dir_name = service_name.clone();
    service_home_dir_name.push_str("_home_dir");

    let dir_helper = DirectoryHelper::new(client.clone());
    let (dir_listing, _) = try!(dir_helper.create(service_home_dir_name,
                                                  vec![],
                                                  false,
                                                  AccessLevel::Public,
                                                  None));

    let mut file_helper = FileHelper::new(client.clone());
    let mut writer = try!(file_helper.create(HOME_PAGE_FILE_NAME.to_string(), vec![], dir_listing));

    println!("\nEnter text that you want to display on the Home-Page:");
    let mut text = String::new();
    let _ = std::io::stdin().read_line(&mut text);
    text = text.trim().to_string();

    println!("Creating Home Page for the Service...");

    try!(writer.write(text.as_bytes()));
    let (updated_parent_dir_listing, _) = try!(writer.close());
    let dir_key = updated_parent_dir_listing.get_key();

    let secret_signing_key = try!(unwrap!(client.lock()).get_secret_signing_key()).clone();

    dns_operations.add_service(&long_name,
                               (service_name, dir_key.clone()),
                               &secret_signing_key,
                               None)
}

fn remove_service(client: Arc<Mutex<Client>>,
                  dns_operations: &DnsOperations)
                  -> Result<(), DnsError> {
    println!("\n\n    Remove Service");
    println!("    ==============");
    println!("\nEnter Dns Name (eg., pepsico.com):");
    let mut long_name = String::new();
    let _ = std::io::stdin().read_line(&mut long_name);
    long_name = long_name.trim().to_string();

    println!("\nEnter Service Name (eg., www):");
    let mut service_name = String::new();
    let _ = std::io::stdin().read_line(&mut service_name);
    service_name = service_name.trim().to_string();

    println!("Removing Service...");

    let secret_signing_key = try!(unwrap!(client.lock()).get_secret_signing_key()).clone();
    dns_operations.remove_service(&long_name, service_name, &secret_signing_key, None)
}

fn display_services(dns_operations: &DnsOperations) -> Result<(), DnsError> {
    println!("\n\n    Display Services");
    println!("    ================");
    println!("\nEnter Dns Name (eg., pepsico.com):");
    let mut long_name = String::new();
    let _ = std::io::stdin().read_line(&mut long_name);
    long_name = long_name.trim().to_string();

    println!("\nServices For Dns {:?} (fetching...):", long_name);
    let service_names = try!(dns_operations.get_all_services(&long_name, None));
    for it in service_names.iter().enumerate() {
        println!("<{:?}> {}", it.0 + 1, it.1);
    }
    Ok(())
}

fn parse_url_and_get_home_page(client: Arc<Mutex<Client>>,
                               dns_operations: &DnsOperations)
                               -> Result<(), DnsError> {
    println!("\n\n    Parse URL");
    println!("    =========");
    println!("\nEnter SAFE-Url (eg., safe:lays.pepsico.com ie., \
              \"safe:[<service-name>.]<dns-name>\"):");
    let mut url = String::new();
    let _ = std::io::stdin().read_line(&mut url);
    url = url.trim().to_string();

    let re_with_service = try!(Regex::new(r"safe:([^.]+?)\.([^.]+?\.[^.]+)$")
        .map_err(|_| DnsError::Unexpected("Failed to form Regular-Expression !!".to_string())));
    let re_without_service = try!(Regex::new(r"safe:([^.]+?\.[^.]+)$")
        .map_err(|_| DnsError::Unexpected("Failed to form Regular-Expression !!".to_string())));

    let long_name;
    let service_name;

    if re_with_service.is_match(&url) {
        let captures = try!(re_with_service.captures(&url)
            .ok_or(DnsError::Unexpected("Could not capture items in Url !!".to_string())));
        let caps_0 = try!(captures.at(1)
            .ok_or(DnsError::Unexpected("Could not access a capture !!".to_string())));
        let caps_1 = try!(captures.at(2)
            .ok_or(DnsError::Unexpected("Could not access a capture !!".to_string())));

        long_name = caps_1.to_string();
        service_name = caps_0.to_string();
    } else if re_without_service.is_match(&url) {
        let captures = try!(re_without_service.captures(&url)
            .ok_or(DnsError::Unexpected("Could not capture items in Url !!".to_string())));
        let caps_0 = try!(captures.at(1)
            .ok_or(DnsError::Unexpected("Could not access a capture !!".to_string())));

        long_name = caps_0.to_string();
        service_name = DEFAULT_SERVICE.to_string();
    } else {
        return Err(DnsError::Unexpected("Malformed Url !!".to_string()));
    }

    println!("Fetching data...");

    let dir_key =
        try!(dns_operations.get_service_home_directory_key(&long_name, &service_name, None));
    let directory_helper = DirectoryHelper::new(client.clone());
    let dir_listing = try!(directory_helper.get(&dir_key));

    let file = try!(dir_listing.get_files()
        .iter()
        .find(|a| *a.get_name() == HOME_PAGE_FILE_NAME.to_string())
        .ok_or(DnsError::Unexpected("Could not find homepage !!".to_string())));
    let mut file_helper = FileHelper::new(client.clone());
    let mut reader = try!(file_helper.read(file));
    let size = reader.size();
    let content = try!(reader.read(0, size));

    println!("\n-----------------------------------------------------");
    println!("                 Home Page Contents");
    println!("-----------------------------------------------------\n");
    println!("{}",
             try!(String::from_utf8(content).map_err(|_| {
                 DnsError::Unexpected("Cannot convert contents to displayable string !!"
                     .to_string())
             })));

    Ok(())
}

fn main() {
    let client = handle_login();
    let unregistered_client = Arc::new(Mutex::new(unwrap!(Client::create_unregistered_client())));
    println!("Account Login Successful !!");

    println!("Initialising Dns...");
    let dns_operations = unwrap!(DnsOperations::new(client.clone()));
    let dns_operations_unregistered = DnsOperations::new_unregistered(unregistered_client.clone());

    let mut user_option = String::new();

    loop {
        println!("\n\n     ------\n    | MENU |\n     ------");
        println!("\n<1> Register Your Dns");
        println!("\n<2> Delete Dns Record");
        println!("\n<3> List Dns Records");
        println!("\n<4> Add Service");
        println!("\n<5> Remove Service");
        println!("\n<6> List Services");
        println!("\n<7> Parse URL (Simulate Browser)");
        println!("\n<8> Exit");

        println!("\nEnter Option [1-8]:");
        let _ = std::io::stdin().read_line(&mut user_option);

        if let Ok(option) = user_option.trim().parse::<u8>() {
            let mut error = None;

            match option {
                1 => {
                    if let Err(err) = create_dns_record(client.clone(), &dns_operations) {
                        error = Some(err);
                    }
                }
                2 => {
                    if let Err(err) = delete_dns_record(client.clone(), &dns_operations) {
                        error = Some(err);
                    }
                }
                3 => {
                    if let Err(err) = display_dns_records(&dns_operations) {
                        error = Some(err);
                    }
                }
                4 => {
                    if let Err(err) = add_service(client.clone(), &dns_operations) {
                        error = Some(err);
                    }
                }
                5 => {
                    if let Err(err) = remove_service(client.clone(), &dns_operations) {
                        error = Some(err);
                    }
                }
                6 => {
                    if let Err(err) = display_services(&dns_operations_unregistered) {
                        error = Some(err);
                    }
                }
                7 => {
                    if let Err(err) = parse_url_and_get_home_page(unregistered_client.clone(),
                                                                  &dns_operations_unregistered) {
                        error = Some(err);
                    }
                }
                8 => break,
                _ => println!("\nUnrecognised option !!"),
            }

            println!("\n ----------------------------------------------");
            if let Some(err) = error {
                println!("|  ERROR !! {:?}", err);
            } else {
                println!("|  Operation Completed Successfully !");
            }
            println!(" ----------------------------------------------");
        } else {
            println!("\nUnrecognised option !!");
        }

        println!("Hit Enter to continue...");
        let _ = std::io::stdin().read_line(&mut user_option);
        user_option.clear();
    }
}
