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

//! REST API example.

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
#![cfg_attr(feature="clippy", deny(clippy))]
#![cfg_attr(feature="clippy", allow(use_debug, print_stdout))]

/*

#![allow(unused_extern_crates)]
extern crate futures;
#[macro_use]
extern crate maidsafe_utilities;
extern crate time;
extern crate routing;
extern crate rust_sodium;
extern crate safe_core;
extern crate tokio_core;
#[macro_use]
extern crate unwrap;



use futures::Future;
use maidsafe_utilities::thread;
use rust_sodium::crypto::secretbox;
use safe_core::core::{self, Client, CoreMsg, CoreMsgTx, FutureExt, NetworkTx};
use safe_core::nfs::{Dir, DirId, DirMetadata, File, NfsError};
use safe_core::nfs::helper::{dir_helper, file_helper};
use safe_core::nfs::helper::writer::Mode;
use std::sync::mpsc;
use tokio_core::channel;
use tokio_core::reactor::{Core, Handle};

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

    if user_option != "Y" && user_option != "y" {
        println!("\nTrying to create an account ...");
        unwrap!(Client::registered(&secret_0, &secret_1, el_h, core_tx, net_tx))
    } else {
        println!("\nTrying to log in ...");
        unwrap!(Client::login(&secret_0, &secret_1, el_h, core_tx, net_tx))
    }
}

fn get_user_string(placeholder: &str) -> String {
    let mut txt = String::new();
    println!("------Enter {}--------", placeholder);
    let _ = std::io::stdin().read_line(&mut txt);
    while txt.is_empty() {
        println!("{} can not be empty", placeholder);
        println!("------Enter Directory name--------");
        let _ = std::io::stdin().read_line(&mut txt);
    }
    txt
}

fn get_child_directory(client: Client,
                       dir: &mut Dir)
                       -> Box<Future<Item = (Dir, DirMetadata), Error = NfsError>> {
    let directory_name = &get_user_string("Directory name");

    let dir_metadata = match dir.find_sub_dir(directory_name)
        .cloned()
        .ok_or(NfsError::DirectoryNotFound) {
        Ok(r) => r,
        Err(e) => return futures::failed(e).into_box(),
    };

    dir_helper::get(client, &dir_metadata.id())
        .map(move |dir| (dir, dir_metadata))
        .into_box()
}

fn directory_operation(option: u32,
                       client: &Client,
                       mut dir: &mut Dir,
                       dir_id: DirId)
                       -> Box<Future<Item = (), Error = NfsError>> {
    match option {
        1 => {
            // Create directory
            println!("----------Select the Directory type-----------");
            println!("1. Private Directory");
            println!("2. Public Directory");
            match get_user_string("number corresponding to the type").trim().parse::<usize>() {
                Ok(index) => {
                    if index > 2 {
                        println!("Invalid input");
                        return futures::finished(()).into_box();
                    }
                    let name = get_user_string("Directory name");
                    let sk = match index {
                        1 => Some(secretbox::gen_key()),
                        _ => None,
                    };

                    if name.is_empty() {
                        return futures::failed(NfsError::ParameterIsNotValid).into_box();
                    }

                    dir_helper::create_sub_dir(client.clone(),
                                               name.clone(),
                                               sk,
                                               vec![],
                                               &dir,
                                               &dir_id)
                        .map(move |_| {
                            println!("Created Directory - {}", name);
                        })
                        .into_box()
                }
                Err(_) => {
                    println!("Invalid input");
                    futures::finished(()).into_box()
                }
            }
        }
        2 => {
            // List directories
            let directory_metadata = dir.sub_dirs();

            if directory_metadata.is_empty() {
                println!("No directories found");
            } else {
                println!("List of directories");
                println!("\t        Created On                  Name ");
                println!("\t =========================       ==========");
                for metadata in directory_metadata {
                    println!("\t {:?} \t {}",
                             unwrap!(time::strftime("%d-%m-%Y %H:%M UTC",
                                                    &metadata.created_time())),
                             metadata.name());
                }
            }
            futures::finished(()).into_box()
        }
        3 => {
            // Delete directory
            dir_helper::delete(client.clone(),
                               dir,
                               &dir_id,
                               &get_user_string("Directory name"))
                .map(move |_| {
                    println!("Directory deleted");
                })
                .into_box()
        }
        _ => futures::finished(()).into_box(),
    }
}

fn file_operation(option: u32,
                  client: Client,
                  dir: &mut Dir)
                  -> Box<Future<Item = (), Error = NfsError>> {
    match option {
        4 => {
            // List files
            get_child_directory(client, dir)
                .map(move |(child, metadata)| {
                    let files = child.files();
                    if files.is_empty() {
                        println!("No Files found in Directory - {}", metadata.name());
                    } else {
                        println!("List of Files");
                        println!("\t        Modified On                Name ");
                        println!("\t =========================      ===========");
                        for file in files {
                            println!("\t {:?} \t {}",
                                     unwrap!(time::strftime("%d-%m-%Y %H:%M UTC",
                                                            &file.metadata().modified_time())),
                                     file.name());
                        }
                    }
                })
                .into_box()
        }
        5 => {
            let c2 = client.clone();

            // Create file
            get_child_directory(client.clone(), dir)
                .and_then(move |(child, metadata)| {
                    file_helper::create(c2,
                                        get_user_string("File name"),
                                        vec![],
                                        metadata.id(),
                                        child,
                                        true)
                })
                .and_then(move |writer| {
                    let data = get_user_string("text to be saved as a file").into_bytes();

                    writer.write(&data[..])
                        .and_then(move |_| writer.close())
                })
                .map(move |_| {
                    println!("File created");
                })
                .into_box()
        }
        6 => {
            let c2 = client.clone();

            // Update file
            get_child_directory(client.clone(), dir)
                .and_then(move |(child, meta)| {
                    let file = if let Some(file) = child.find_file(&get_user_string("File name"))
                        .cloned() {
                        file
                    } else {
                        return futures::failed(NfsError::FileNotFound).into_box();
                    };
                    file_helper::update_content(c2, file.clone(), Mode::Overwrite, meta.id(), child)
                })
                .and_then(move |writer| {
                    let data = get_user_string("text to be saved as a file").into_bytes();
                    writer.write(&data[..])
                        .and_then(move |_| writer.close())
                })
                .map(move |_| {
                    println!("File Updated");
                })
                .into_box()
        }
        7 => {
            // Read file
            let c2 = client.clone();

            get_child_directory(client.clone(), dir)
                .and_then(move |(child, _)| {
                    let file = if let Some(file) = child.find_file(&get_user_string("File name")) {
                        file
                    } else {
                        return futures::failed(NfsError::FileNotFound).into_box();
                    };

                    let reader = match file_helper::read(c2, file.metadata()) {
                        Ok(r) => r,
                        Err(e) => return futures::failed(e).into_box(),
                    };
                    reader.read(0, file.metadata().size())
                })
                .map(move |data_read| {
                    match String::from_utf8(data_read) {
                        Ok(data) => {
                            println!("Content Read: ");
                            println!("{}\n", data);
                        }
                        Err(msg) => println!("Failed: {:?}", msg),
                    }
                })
                .into_box()

        }
        8 => {
            let c2 = client.clone();
            let c3 = client.clone();

            // Read file by version
            get_child_directory(client.clone(), dir)
                .and_then(move |(child, meta)| {
                    let file_name = get_user_string("File name");
                    let file = match child.find_file(&file_name).ok_or(NfsError::FileNotFound) {
                        Ok(file) => file,
                        Err(e) => return futures::failed(e).into_box(),
                    };
                    match *file {
                        File::Versioned { ref ptr_versions, ref latest_version, .. } => {
                            let latest_version = latest_version.clone();

                            file_helper::get_versions(&c2,
                                                      ptr_versions,
                                                      meta.encrypt_key().cloned())
                                .map(move |mut versions| {
                                    versions.push(latest_version);
                                    versions
                                })
                                .into_box()
                        }
                        File::Unversioned(_) => {
                            futures::failed(NfsError::from("File is not versioned")).into_box()
                        }
                    }
                })
                .and_then(move |versions| {
                    let file_version;
                    if versions.len() == 1 {
                        file_version = unwrap!(versions.get(0));
                    } else {
                        println!("Available Versions::");
                        for (i, version) in versions.iter().enumerate() {
                            println!("\t{} Modified at {:?}",
                                     i + 1,
                                     unwrap!(time::strftime("%d-%m-%Y %H:%M UTC",
                                                            &version.modified_time())))
                        }
                        match get_user_string("Number corresponding to the version")
                            .trim()
                            .parse::<usize>() {
                            Ok(index) => {
                                if let Some(version) = versions.get(index - 1) {
                                    file_version = version;
                                } else {
                                    println!("Invalid version : Fetching latest version");
                                    file_version = unwrap!(versions.get(0));
                                }
                            }
                            Err(e) => {
                                println!("Invalid input ({}): Fetching latest version", e);
                                file_version = unwrap!(versions.get(0));
                            }
                        }
                    }

                    let reader = match file_helper::read(c3, file_version) {
                        Ok(r) => r,
                        Err(e) => return futures::failed(e).into_box(),
                    };
                    reader.read(0, file_version.size())
                })
                .map(move |data_read| {
                    match String::from_utf8(data_read) {
                        Ok(data) => {
                            println!("Content Read: ");
                            println!("{}\n", data);
                        }
                        Err(msg) => println!("Failed: {:?}", msg),
                    }
                })
                .into_box()
        }
        9 => {
            // Delete file
            let c2 = client.clone();

            get_child_directory(client.clone(), dir)
                .and_then(move |(mut child, meta)| {
                    file_helper::delete(c2, &get_user_string("File name"), &meta.id(), &mut child)
                })
                .map(|_| {
                    println!("File deleted");
                })
                .into_box()
        }
        10 => {
            // Copy file
            let c2 = client.clone();
            let mut dir = dir.clone();

            get_child_directory(client.clone(), &mut dir)
                .and_then(move |(from_dir, meta)| {
                    let to_dir_name = get_user_string("Select the Directory to copy file to \
                                                       (Destination Directory)");
                    if dir.sub_dirs().len() <= 1 {
                        println!("No directories found");
                        return futures::finished(()).into_box();
                    } else {
                        match dir.find_sub_dir(&to_dir_name) {
                            Some(to_dir) => {
                                if meta.id() == to_dir.id() {
                                    return futures::failed(NfsError::DestinationAndSourceAreSame)
                                        .into_box();
                                }
                                let file_name = &get_user_string("File name");
                                let file = match from_dir.find_file(file_name)
                                    .cloned()
                                    .ok_or(NfsError::FileNotFound) {
                                    Ok(file) => file,
                                    Err(e) => return futures::failed(e).into_box(),
                                };

                                let to_id = to_dir.id();
                                dir_helper::get(c2.clone(), &to_id)
                                    .and_then(move |mut dst| {
                                        let _ = match dst.add_file(file) {
                                            Err(e) => return futures::failed(e).into_box(),
                                            _ => {}
                                        };
                                        dir_helper::update(c2, &to_id, &dst)
                                    })
                                    .map(move |_| println!("File copied"))
                                    .into_box()

                            }
                            None => {
                                println!("Destination Directory not found");
                                futures::finished(()).into_box()
                            }
                        }
                    }
                })
                .into_box()
        }
        _ => futures::finished(()).into_box(),
    }
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

    println!("\n\n------  (Tip) Start by creating a directory and then store file, modify \
              file within the directory --------------------");

    loop {
        println!("\n----------Choose an Operation----------------");
        println!("1. Create Directory");
        println!("2. List Directories");
        println!("3. Delete Directory");
        println!("4. List Files from directory");
        println!("5. Create File");
        println!("6. Update File");
        println!("7. Get file content");
        println!("8. Get file content by version");
        println!("9. Delete file");
        println!("10. Copy file");
        println!("11. Exit");
        println!("------ Enter a number --------------------");

        let (tx, rx) = mpsc::channel::<bool>();
        let core_tx_clone = core_tx.clone();

        unwrap!(core_tx.send(CoreMsg::new(move |client, _| {
            let mut option = String::new();
            let _ = std::io::stdin().read_line(&mut option);
            println!("\n");

            let fut = match option.trim().parse::<u32>() {
                Ok(selection) => {
                    match selection {
                        1...3 => {
                            let c2 = client.clone();

                            dir_helper::user_root_dir(client.clone())
                                .and_then(move |(mut root_dir, dir_id)| {
                                    directory_operation(selection, &c2, &mut root_dir, dir_id)
                                })
                                .into_box()
                        }
                        4...10 => {
                            let c2 = client.clone();

                            dir_helper::user_root_dir(client.clone())
                                .and_then(move |(mut root_dir, _)| {
                                    file_operation(selection, c2, &mut root_dir)
                                })
                                .into_box()
                        }
                        11 => {
                            unwrap!(core_tx_clone.send(CoreMsg::build_terminator()));
                            let _ = unwrap!(tx.send(false));
                            return futures::failed(()).into_box().into();
                        }
                        _ => {
                            println!("Invalid option");
                            futures::finished(()).into_box()
                        }
                    }
                }
                Err(_) => {
                    println!("Enter a valid number");
                    futures::finished(()).into_box()
                }
            };

            fut.then(move |res| {
                    match res {
                        Err(e) => println!("Error: {:?}", e),
                        _ => {}
                    }
                    let _ = unwrap!(tx.send(true));
                    Ok(())
                })
                .into_box()
                .into()
        })));

        let continue_loop = unwrap!(rx.recv());
        if !continue_loop {
            break;
        }
    }
}

*/

fn main() {}
