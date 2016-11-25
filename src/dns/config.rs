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

//! DNS configuration.

use core::Client;
use core::futures::FutureExt;
use futures::Future;
use maidsafe_utilities::serialisation::{deserialise, serialise};
use nfs::errors::NfsError;
use nfs::helper::{dir_helper, file_helper};
use nfs::helper::writer::Mode;
use rust_sodium::crypto::box_;
use super::{DnsError, DnsFuture};

const DNS_CONFIG_DIR_NAME: &'static str = "DnsReservedDirectory";
const DNS_CONFIG_FILE_NAME: &'static str = "DnsConfigurationFile";

/// Dns configuration. For internal use by the `dns` module.
#[derive(Clone, Debug, Eq, PartialEq, RustcEncodable, RustcDecodable)]
pub struct DnsConfig {
    /// Dns long name
    pub long_name: String,
    /// Encryption keys
    pub encryption_keypair: (box_::PublicKey, box_::SecretKey),
}

/// Read DNS configuration data.
pub fn read(client: &Client) -> Box<DnsFuture<Vec<DnsConfig>>> {
    let client2 = client.clone();

    dir_helper::configuration_dir(client.clone(), DNS_CONFIG_DIR_NAME.to_owned())
        .and_then(move |(dir, _)| {
            if let Some(file) = dir.find_file(DNS_CONFIG_FILE_NAME) {
                let reader = file_helper::read(client2, file.metadata())?;
                if reader.size() == 0 {
                    Err(NfsError::FileNotFound)
                } else {
                    Ok(reader)
                }
            } else {
                Err(NfsError::FileNotFound)
            }
        })
        .and_then(|reader| {
            let size = reader.size();
            reader.read(0, size)
        })
        .and_then(|encoded| Ok(deserialise(&encoded)?))
        .or_else(|err| match err {
            NfsError::FileNotFound => Ok(vec![]),
            err => Err(DnsError::from(err)),
        })
        .into_box()
}

/// Write DNS configuration data.
pub fn write(client: &Client, config: Vec<DnsConfig>) -> Box<DnsFuture<()>> {
    let client2 = client.clone();
    let encoded_config = fry!(serialise(&config));

    dir_helper::configuration_dir(client.clone(), DNS_CONFIG_DIR_NAME.to_owned())
        .and_then(|(dir, dir_metadata)| {
            if let Some(file) = dir.find_file(DNS_CONFIG_FILE_NAME).cloned() {
                file_helper::update_content(client2, file, Mode::Overwrite, dir_metadata.id(), dir)
            } else {
                file_helper::create(client2,
                                    DNS_CONFIG_FILE_NAME.to_string(),
                                    vec![],
                                    dir_metadata.id(),
                                    dir,
                                    false)
            }
        })
        .and_then(move |writer| writer.write(&encoded_config).map(move |_| writer))
        .and_then(|writer| writer.close())
        .map(|_| ())
        .map_err(DnsError::from)
        .into_box()
}

#[cfg(test)]
mod tests {
    use core::utility;
    use core::utility::test_utils::random_client;
    use futures::Future;
    use rust_sodium::crypto::box_;
    use super::*;

    #[test]
    fn read_write_dns_config_file() {
        let config_0 = DnsConfig {
            long_name: unwrap!(utility::generate_random_string(10)),
            encryption_keypair: box_::gen_keypair(),
        };
        let config_0_2 = config_0.clone();

        let config_1 = DnsConfig {
            long_name: unwrap!(utility::generate_random_string(10)),
            encryption_keypair: box_::gen_keypair(),
        };
        let config_1_2 = config_1.clone();

        random_client(move |client| {
            let client2 = client.clone();
            let client3 = client.clone();
            let client4 = client.clone();
            let client5 = client.clone();
            let client6 = client.clone();
            let client7 = client.clone();

            // Get the Stored Configurations
            read(client)
                .then(move |result| {
                    let mut config_vec = unwrap!(result);
                    assert!(config_vec.is_empty());

                    // Put in the 1st record
                    config_vec.push(config_0);
                    write(&client2, config_vec)
                })
                .then(move |result| {
                    unwrap!(result);
                    read(&client3)
                })
                .then(move |result| {
                    let mut config_vec = unwrap!(result);
                    assert_eq!(config_vec.len(), 1);
                    assert_eq!(config_vec[0], config_0_2);

                    // Modify the content
                    config_vec[0] = config_1;
                    write(&client4, config_vec)
                })
                .then(move |result| {
                    unwrap!(result);
                    read(&client5)
                })
                .then(move |result| {
                    let mut config_vec = unwrap!(result);
                    assert_eq!(config_vec.len(), 1);
                    assert_eq!(config_vec[0], config_1_2);

                    // Delete Record
                    config_vec.clear();
                    write(&client6, config_vec)
                })
                .then(move |result| {
                    unwrap!(result);
                    read(&client7)
                })
                .map(|config_vec| {
                    assert!(config_vec.is_empty());
                })
        })
    }
}
