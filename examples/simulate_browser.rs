// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net
// Commercial License, version 1.0 or later, or (2) The General Public License
// (GPL), version 3, depending on which licence you accepted on initial access
// to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project
// generally, you agree to be bound by the terms of the MaidSafe Contributor
// Agreement, version 1.0. This, along with the Licenses can be found in the
// root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network
// Software distributed under the GPL Licence is distributed on an "AS IS"
// BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
//
// Please review the Licences for the specific language governing permissions
// and limitations relating to use of the SAFE Network Software.

//! Simulate browser example.

// For explanation of lint checks, run `rustc -W help` or see
// https://github.
// com/maidsafe/QA/blob/master/Documentation/Rust%20Lint%20Checks.md
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

/*

#![allow(unused_extern_crates)]
extern crate futures;
#[macro_use]
extern crate maidsafe_utilities;
extern crate regex;
extern crate routing;
extern crate safe_core;
extern crate rust_sodium;
extern crate tokio_core;
#[macro_use]
extern crate unwrap;

use futures::Future;
use maidsafe_utilities::thread;
use regex::Regex;
use safe_core::core::{self, Client, CoreMsg, CoreMsgTx, FutureExt, NetworkTx};
use safe_core::dns::{DnsError, DnsFuture};
use safe_core::dns::operations as dns;
use safe_core::nfs::helper::{dir_helper, file_helper};
use std::sync::mpsc;
use tokio_core::channel;
use tokio_core::reactor::{Core, Handle};

macro_rules! fry {
    ($res:expr) => {
        match $res {
            Ok(elt) => elt,
            Err(e) => {
                return futures::done(Err(From::from(e))).into_box()
            }
        }
    }
}

const DEFAULT_SERVICE: &'static str = "www";
const HOME_PAGE_FILE_NAME: &'static str = "index.html";

fn handle_login<T: 'static>(el_h: Handle, core_tx: CoreMsgTx<T>, net_tx: NetworkTx) -> Client {
    let mut secret_0 = String::new();
    let mut secret_1 = String::new();

    println!("\nDo you already have an account created (enter Y for yes) ?");

    let mut user_option = String::new();
    let _ = std::io::stdin().read_line(&mut user_option);
    user_option = user_option.trim().to_string();

    if user_option != "Y" && user_option != "y" {
        println!("\n\tAccount Creation");
        println!("\t================");
    } else {
        println!("\n\n\tAccount Login");
        println!("\t====================");
    }

    println!("\n------------ Enter account-locator ---------------");
    let _ = std::io::stdin().read_line(&mut secret_0);
    secret_0 = secret_0.trim().to_string();
    println!("\n------------ Enter password ---------------");
    let _ = std::io::stdin().read_line(&mut secret_1);
    secret_1 = secret_1.trim().to_string();

    // Account Creation
    if user_option != "Y" && user_option != "y" {
        println!("\nTrying to create an account ...");
        unwrap!(Client::registered::<T>(&secret_0,
                                        &secret_1,
                                        el_h,
                                        core_tx.clone(),
                                        net_tx.clone()))
    } else {
        println!("\nTrying to log into the created account using supplied credentials ...");
        unwrap!(Client::login::<T>(&secret_0, &secret_1, el_h, core_tx.clone(), net_tx.clone()))
    }
}

fn create_dns_record(client: &Client) -> Box<DnsFuture<()>> {
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

    let owners = vec![fry!(client.public_signing_key())];
    let secret_signing_key = fry!(client.secret_signing_key());

    dns::register_dns(client,
                      long_name,
                      public_messaging_encryption_key,
                      secret_messaging_encryption_key,
                      &[],
                      owners,
                      secret_signing_key,
                      None)
}

fn delete_dns_record(client: &Client) -> Box<DnsFuture<()>> {
    println!("\n\n    Delete Dns Record");
    println!("    =================");
    println!("\nEnter Dns Name (eg., pepsico.com):");
    let mut long_name = String::new();
    let _ = std::io::stdin().read_line(&mut long_name);
    long_name = long_name.trim().to_string();

    let secret_signing_key = fry!(client.secret_signing_key());

    println!("Deleting Dns...");

    dns::delete_dns(client, long_name, secret_signing_key)
}

fn display_dns_records(client: &Client) -> Box<DnsFuture<()>> {
    println!("\n\n    Display Dns Records");
    println!("    ===================");
    println!("\nRegistered Dns Names (fetching...):");

    dns::get_all_registered_names(client)
        .map(move |record_names| {
            for it in record_names.iter().enumerate() {
                println!("<{:?}> {}", it.0 + 1, it.1);
            }
        })
        .into_box()
}

fn add_service(client: &Client) -> Box<DnsFuture<()>> {
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

    println!("\nEnter text that you want to display on the Home-Page:");
    let mut text = String::new();
    let _ = std::io::stdin().read_line(&mut text);
    text = text.trim().to_string();

    println!("Creating Home Page for the Service...");

    let c2 = client.clone();
    let c3 = client.clone();
    let c4 = client.clone();
    let secret_signing_key = fry!(client.secret_signing_key());

    dir_helper::user_root_dir(client.clone())
        .map_err(DnsError::from)
        .and_then(move |(parent, parent_id)| {
            dir_helper::create_sub_dir(c2, service_home_dir_name, None, vec![], &parent, &parent_id)
                .map_err(DnsError::from)
        })
        .and_then(move |(_, dir_listing, dir_meta)| {
            file_helper::create(c3,
                                HOME_PAGE_FILE_NAME.to_string(),
                                vec![],
                                dir_meta.id(),
                                dir_listing,
                                false)
                .and_then(move |writer| {
                    writer.write(text.as_bytes())
                        .and_then(move |_| writer.close())
                })
                .map(move |_| dir_meta)
                .map_err(DnsError::from)
        })
        .and_then(move |dir_meta| {
            dns::add_service(&c4,
                             long_name,
                             (service_name, dir_meta.id()),
                             secret_signing_key,
                             None)
        })
        .into_box()
}

fn remove_service(client: &Client) -> Box<DnsFuture<()>> {
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

    let secret_signing_key = fry!(client.secret_signing_key());
    dns::remove_service(client, long_name, service_name, secret_signing_key, None)
}

fn display_services(client: &Client) -> Box<DnsFuture<()>> {
    println!("\n\n    Display Services");
    println!("    ================");
    println!("\nEnter Dns Name (eg., pepsico.com):");
    let mut long_name = String::new();
    let _ = std::io::stdin().read_line(&mut long_name);
    long_name = long_name.trim().to_string();

    println!("\nServices For Dns {:?} (fetching...):", long_name);
    dns::get_all_services(client, &long_name, None)
        .map(move |service_names| {
            for it in service_names.iter().enumerate() {
                println!("<{:?}> {}", it.0 + 1, it.1);
            }
        })
        .into_box()
}

fn parse_url_and_get_home_page(client: &Client) -> Box<DnsFuture<()>> {
    println!("\n\n    Parse URL");
    println!("    =========");
    println!("\nEnter SAFE-Url (eg., safe:lays.pepsico.com ie., \
              \"safe:[<service-name>.]<dns-name>\"):");
    let mut url = String::new();
    let _ = std::io::stdin().read_line(&mut url);
    url = url.trim().to_string();

    let re_with_service = fry!(Regex::new(r"safe:([^.]+?)\.([^.]+?\.[^.]+)$")
        .map_err(|_| DnsError::Unexpected("Failed to form Regular-Expression !!".to_string())));
    let re_without_service = fry!(Regex::new(r"safe:([^.]+?\.[^.]+)$")
        .map_err(|_| DnsError::Unexpected("Failed to form Regular-Expression !!".to_string())));

    let long_name;
    let service_name;

    if re_with_service.is_match(&url) {
        let captures = fry!(re_with_service.captures(&url)
            .ok_or(DnsError::Unexpected("Could not capture items in Url !!".to_string())));
        let caps_0 = fry!(captures.at(1)
            .ok_or(DnsError::Unexpected("Could not access a capture !!".to_string())));
        let caps_1 = fry!(captures.at(2)
            .ok_or(DnsError::Unexpected("Could not access a capture !!".to_string())));

        long_name = caps_1.to_string();
        service_name = caps_0.to_string();
    } else if re_without_service.is_match(&url) {
        let captures = fry!(re_without_service.captures(&url)
            .ok_or(DnsError::Unexpected("Could not capture items in Url !!".to_string())));
        let caps_0 = fry!(captures.at(1)
            .ok_or(DnsError::Unexpected("Could not access a capture !!".to_string())));

        long_name = caps_0.to_string();
        service_name = DEFAULT_SERVICE.to_string();
    } else {
        return futures::failed(DnsError::Unexpected("Malformed Url !!".to_string())).into_box();
    }

    println!("Fetching data...");

    let c2 = client.clone();
    let c3 = client.clone();

    dns::get_service_home_dir_id(&client, long_name, service_name, None)
        .map_err(DnsError::from)
        .and_then(move |dir_key| dir_helper::get(c2, &dir_key).map_err(DnsError::from))
        .and_then(move |dir_listing| {
            let file = fry!(dir_listing.files()
                .iter()
                .find(|a| *a.name() == HOME_PAGE_FILE_NAME.to_string())
                .ok_or(DnsError::Unexpected("Could not find homepage !!".to_string())));

            let reader = fry!(file_helper::read(c3, file.metadata()).map_err(DnsError::from));

            let size = reader.size();

            reader.read(0, size)
                .map_err(DnsError::from)
                .into_box()
        })
        .and_then(move |content| {
            println!("\n-----------------------------------------------------");
            println!("                 Home Page Contents");
            println!("-----------------------------------------------------\n");
            println!("{}",
                     try!(String::from_utf8(content).map_err(|_| {
                         DnsError::Unexpected("Cannot convert contents to displayable string !!"
                             .to_string())
                     })));
            Ok(())
        })
        .into_box()
}

fn main() {
    let (tx, rx) = mpsc::channel::<CoreMsgTx<()>>();

    let _joiner = thread::named("Core Event Loop", move || {
        let el = unwrap!(Core::new());
        let el_h = el.handle();

        let (core_tx, core_rx) = unwrap!(channel::channel(&el_h));
        let (net_tx, _net_rx) = unwrap!(channel::channel(&el_h));

        let client = handle_login(el_h, core_tx.clone(), net_tx);
        let _ = unwrap!(tx.send(core_tx.clone()));

        core::run(el, client, (), core_rx);
    });

    let core_tx = unwrap!(rx.recv());

    println!("Account Login Successful!");

    loop {
        let mut user_option = String::new();

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

        let (tx, rx) = mpsc::channel::<bool>();

        let _ = std::io::stdin().read_line(&mut user_option);
        let core_tx_clone = core_tx.clone();

        unwrap!(core_tx.send(CoreMsg::new(move |client, _| {
            let client = client.clone();

            let fut = if let Ok(option) = user_option.trim().parse::<u8>() {
                let fut = match option {
                    1 => create_dns_record(&client),
                    2 => delete_dns_record(&client),
                    3 => display_dns_records(&client),
                    4 => add_service(&client),
                    5 => remove_service(&client),
                    6 => display_services(&client),
                    7 => parse_url_and_get_home_page(&client),
                    8 => {
                        unwrap!(core_tx_clone.send(CoreMsg::build_terminator()));
                        let _ = unwrap!(tx.send(false));
                        return futures::failed(()).into_box().into();
                    }
                    _ => {
                        println!("\nUnrecognised option !!");
                        futures::finished(()).into_box()
                    }
                };

                println!("\n ----------------------------------------------");

                fut.then(move |res| {
                        match res {
                            Err(err) => println!("|  ERROR !! {:?}", err),
                            Ok(_) => println!("|  Operation Completed Successfully!"),
                        }
                        Ok(())
                    })
                    .into_box()
            } else {
                println!("\nUnrecognised option !!");
                futures::finished(()).into_box()
            };

            fut.map(move |_| {
                    let _ = unwrap!(tx.send(true));
                })
                .into_box()
                .into()
        })));

        let continue_loop = unwrap!(rx.recv());

        if !continue_loop {
            break;
        } else {
            let mut user_option = String::new();
            println!("Hit Enter to continue...");
            let _ = std::io::stdin().read_line(&mut user_option);
            user_option.clear();
        }
    }
}

*/

fn main() {}
