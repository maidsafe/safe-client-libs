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

extern crate maidsafe_client;
extern crate time;

use maidsafe_client::nfs;


fn validate_pin_is_4_digits(mut pin: u32) -> bool {
    for _ in 0..3 {
        pin /= 10;
        if pin == 0 {
            return false;
        }
    }

    pin /= 10;

    if pin != 0 {
        false
    } else {
        true
    }
}

#[allow(unused_must_use)]
fn create_account() -> Result<maidsafe_client::client::Client, String> {
    let mut keyword = String::new();
    let mut password = String::new();
    let mut pin_str = String::new();
    let mut pin: u32;

    println!("\n\tAccount Creation");
    println!("\t================");

    println!("\n------------ Enter Keyword ---------------");
    std::io::stdin().read_line(&mut keyword);

    println!("\n\n------------ Enter Password --------------");
    std::io::stdin().read_line(&mut password);

    loop {
        println!("\n\n--------- Enter PIN (4 Digits) -----------");
        std::io::stdin().read_line(&mut pin_str);
        let result = pin_str.trim().parse::<u32>();
        if result.is_ok() {
            pin = result.ok().unwrap();
            if validate_pin_is_4_digits(pin) {
                break;
            }
        }
        println!("ERROR: PIN is not 4 Digits !!");
        pin_str.clear();
    }

    //TODO Not to be used if not using non_networking_test_framework.
    let data_store = maidsafe_client::client::non_networking_test_framework::get_new_data_store();

    // Account Creation
    println!("\nTrying to create an account ...");

    match maidsafe_client::client::Client::create_account(&keyword, pin, &password.as_bytes(), data_store.clone()) {
        Ok(_) => {
            println!("Account Created Successfully !!");
        },
        Err(_) => panic!("Account Created failed"),
    }

    println!("\n\n\tAuto Account Login");
    println!("\t==================");

    // Log into the created account
    println!("\nTrying to log into the created account using supplied credentials ...");
    match maidsafe_client::client::Client::log_in(&keyword, pin, &password.as_bytes(), data_store.clone()) {
        Ok(client) => {
            println!("Account Login Successful !!");
            Ok(client)
        },
        Err(_)  => Err("Account Login Failed !!".to_string()),
    }
}

#[allow(unused_must_use)]
fn get_user_string(placeholder: &str) -> String {
    let mut txt = String::new();
    println!("------Enter {}--------", placeholder);
    std::io::stdin().read_line(&mut txt);
    while txt.is_empty() {
        println!("{} can not be empty", placeholder);
        println!("------Enter Container name--------");
        std::io::stdin().read_line(&mut txt);
    }
    txt
}

fn format_version_id(version_id: &[u8; 64]) -> String {
    let mut version = String::new();
    for j in 0..4 {
        version.push((version_id[j] + 48) as char)
    }
    version.push('.');
    version.push('.');
    for j in 60..64 {
        version.push((version_id[j] + 48) as char)
    }
    version
}

fn container_operation(option: u32, container: &mut nfs::rest::Container) {
    match option {
        1 => {// Create container
            let name = get_user_string("Container name");
            match container.create(name.clone()) {
                Ok(_) => println!("Created Container - {}", name),
                Err(msg) => println!("Failed :: {}", msg)
            }
        },
        2 => { // List containers
            let containers = container.get_containers();
            if containers.is_empty() {
                println!("No containers found");
            } else {
                println!("List of containers");
                println!("\t        Created On                  Name ");
                println!("\t =========================       ==========");
                for container_info in containers {
                    println!("\t {:?} \t {}", time::strftime("%d-%m-%Y %H:%M UTC", &container_info.get_created_time()).unwrap(), container_info.get_name());
                }
            }
        }
        3 => { // List versions
            match container.get_versions() {
                Ok(versions) => {
                    if versions.is_empty() {
                        println!("No container versions found");
                    } else {
                        println!("List of container versions");
                        println!("\t No. \t Version Id");
                        println!("\t === \t ==========");
                        for i in 0..versions.len() {
                            println!("\t {} \t {:?}", i+1, format_version_id(&versions[i]));
                        }
                    }
                },
                Err(msg) => println!("Failed :: {}", msg)
            }
        },
        4 => { // Delete container
            match container.delete_container(get_user_string("Container name")) {
                Ok(_) => {
                    println!("Container deleted");
                },
                Err(msg) => println!("Failed :: {}", msg)
            };
        }
        _ => {}
    }
}

fn blob_operation(option: u32, container: &mut nfs::rest::Container) {
    match option {
        5 => { // List blobs
            match container.get_container(get_user_string("Container name"), None) {
                Ok(container) => {
                    let blobs: Vec<nfs::rest::Blob> = container.get_blobs();
                    if blobs.is_empty() {
                        println!("No blobs found in Container - {}", container.get_name());
                    } else {
                        println!("List of Blobs");
                        println!("\t        Modified On                Name ");
                        println!("\t =========================      ===========");
                        for blob in blobs {
                            println!("\t {:?} \t {}", time::strftime("%d-%m-%Y %H:%M UTC", &blob.get_modified_time()).unwrap(), blob.get_name());
                        }
                    }
                },
                Err(msg) => println!("Failed :: {}", msg)
            }
        },
        6 => { // Create blob
            match container.get_container(get_user_string("Container name"), None) {
                Ok(mut container) => {
                    let data = get_user_string("text to be saved as a file").into_bytes();
                    match container.create_blob(get_user_string("Blob name"), None) {
                        Ok(mut writer) => {
                            writer.write(&data[..], 0);
                            match writer.close() {
                                Ok(_) => {
                                    println!("Blob created");
                                },
                                Err(msg) => println!("Failed :: {}", msg)
                            }
                        },
                        Err(msg) => println!("Failed :: {}", msg)
                    }
                },
                Err(msg) => println!("Failed :: {}", msg)
            }
        },
        7 => { // Update blob
            match container.get_container(get_user_string("Container name"), None) {
                Ok(mut container) => {
                    match container.get_blob(get_user_string("Blob name"), None) {
                        Ok(blob) => {
                            let data = get_user_string("text to be saved as a file").into_bytes();
                            match container.get_blob_writer(&blob) {
                                Ok(mut writer) => {
                                    writer.write(&data[..], 0);
                                    match writer.close() {
                                        Ok(_) => {
                                            println!("Blob Updated");
                                        },
                                        Err(msg) => println!("Failed :: {}", msg)
                                    }
                                },
                                Err(msg) => println!("Failed :: {}", msg)
                            }
                        },
                        Err(msg) => println!("Failed :: {}", msg)
                    }
                },
                Err(msg) => println!("Failed :: {}", msg)
            }
        },
        8 => { // Read blob
            match container.get_container(get_user_string("Container name"), None) {
                Ok(mut container) => {
                    match container.get_blob(get_user_string("Blob name"), None) {
                        Ok(blob) => {
                            match container.get_blob_reader(&blob) {
                                Ok(mut reader) => {
                                    match reader.read(0, blob.get_size()) {
                                        Ok(data) => {
                                            println!("Content Read: ");
                                            println!("{}\n", String::from_utf8(data).unwrap());
                                        },
                                        Err(msg) => println!("Failed :: {}", msg)
                                    }
                                },
                                Err(msg) => println!("Failed :: {}", msg)
                            }
                        },
                        Err(msg) => println!("Failed :: {}", msg)
                    }
                },
                Err(msg) => println!("Failed :: {}", msg)
            }
        },
        9 => { // Read blob by version
            match container.get_container(get_user_string("Container name"), None) {
                Ok(mut container) => {
                    let blob_name = get_user_string("Blob name");
                    match container.get_blob_versions(blob_name.clone()) {
                        Ok(versions) => {
                            let mut version_id;
                            if versions.len() == 1 {
                                version_id = versions[0];
                            } else{
                                println!("Available Versions::");
                                for i in 0..versions.len() {
                                    println!("\t{} {:?}", i+1, format_version_id(&versions[i]))
                                }
                                match get_user_string("Number corresponding to the version").trim().parse::<usize>() {
                                    Ok(index) => version_id = versions[index - 1],
                                    Err(_) =>  {
                                        println!("Invalid input : Fetching latest version");
                                        version_id = versions[0];

                                    }
                                }
                            }
                            match container.get_blob(blob_name, Some(version_id)) {
                                Ok(blob) => {
                                    match container.get_blob_reader(&blob) {
                                        Ok(mut reader) => {
                                            match reader.read(0, blob.get_size()) {
                                                Ok(data) => {
                                                    println!("Content Read: ");
                                                    println!("{}\n", String::from_utf8(data).unwrap());
                                                },
                                                Err(msg) => println!("Failed :: {}", msg)
                                            }
                                        },
                                        Err(msg) => println!("Failed :: {}", msg)
                                    }
                                },
                                Err(msg) => println!("Failed :: {}", msg)
                            }
                        },
                        Err(msg) => println!("{}", msg)
                    }
                },
                Err(msg) => println!("Failed :: {}", msg)
            }
        },
        10 => { // Delete blob
            match container.get_container(get_user_string("Container name"), None) {
                Ok(mut container) => {
                    match container.delete_blob(get_user_string("Blob name")) {
                        Ok(_) => println!("Blob deleted"),
                        Err(msg) => println!("Failed :: {}", msg)
                    }
                },
                Err(msg) => println!("Failed :: {}", msg)
            }
        },
        11 => { // Copy blob
            match container.get_container(get_user_string("Container name to copy blob from (Source Container)"), None) {
                Ok(mut from_container) => {
                    let to_dir_name = get_user_string("Select the Container to copy blob to (Destination Container)");
                    let containers = container.get_containers();
                    if containers.is_empty() || containers.len() == 1 {
                        println!("No containers found");
                        return;
                    } else {
                        match containers.iter().find(|dir| *dir.get_name() == to_dir_name) {
                            Some(info) => {
                                match from_container.copy_blob(get_user_string("Blob name"), info.get_id()) {
                                    Ok(_) => println!("Blob copied"),
                                    Err(msg) => println!("Failed :: {}", msg)
                                }
                            },
                            None => println!("Destination Container not found")
                        }
                    }
                },
                Err(msg) => println!("Failed :: {}", msg)
            }
        },
        _ => {}
    }
}

fn get_root_container(client: &::std::sync::Arc<::std::sync::Mutex<maidsafe_client::client::Client>>) -> nfs::rest::Container {
    let mut root_container;
    match nfs::rest::Container::authorise(client.clone(), None) {
        Ok(container) => root_container = container,
        Err(msg) => panic!(msg)
    };
    root_container
}
#[allow(unused_must_use)]
fn main() {
    let mut client;
    match create_account() {
        Ok(authorised_client) => client = ::std::sync::Arc::new(::std::sync::Mutex::new(authorised_client)),
        Err(msg) => panic!(msg)
    }
    println!("\n\t-- Preparing storage ----\n");
    let mut root_container = get_root_container(&client);
    println!("\n\n------  (Tip) Start by creating a container and then store blob, modify blob within the container --------------------");
    loop {
        let mut option = String::new();
        {
            println!("\n----------Choose an Operation----------------");
            println!("1. Create Container");
            println!("2. List Containers");
            println!("3. Get Container Versions");
            println!("4. Delete Container");
            println!("5. List Blobs from container");
            println!("6. Create Blob");
            println!("7. Update Blob");
            println!("8. Get blob content");
            println!("9. Get blob content by version");
            println!("10. Delete blob");
            println!("11. Copy blob");
            println!("------ Enter a number --------------------");
            std::io::stdin().read_line(&mut option);
            println!("\n");
            match option.trim().parse::<u32>() {
                Ok(selection) => {
                    match selection {
                        1...4 => container_operation(selection, &mut root_container),
                        5...11 => blob_operation(selection, &mut root_container),
                        _ => println!("Invalid option"),
                    }
                },
                Err(_) => println!("Enter a valid number")
            }
        }
    }
}
