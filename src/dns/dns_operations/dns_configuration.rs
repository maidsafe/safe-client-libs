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

//! Dns operations. Implementation for some of the `dns` module


use core::client::Client;
use dns::errors::DnsError;
use maidsafe_utilities::serialisation::{deserialise, serialise};
use nfs::errors::NfsError;
use nfs::helper::directory_helper::DirectoryHelper;
use nfs::helper::file_helper::FileHelper;
use nfs::helper::writer::Mode;
use rust_sodium::crypto::box_;
use std::sync::{Arc, Mutex};

const DNS_CONFIG_DIR_NAME: &'static str = "DnsReservedDirectory";
const DNS_CONFIG_FILE_NAME: &'static str = "DnsConfigurationFile";

/// Dns configuration. For internal use by the `dns` module.
#[derive(Clone, Debug, Eq, PartialEq, RustcEncodable, RustcDecodable)]
pub struct DnsConfiguration {
    /// Dns long name
    pub long_name: String,
    /// Encryption keys
    pub encryption_keypair: (box_::PublicKey, box_::SecretKey),
}

/// Initialise dns configuration.
pub fn initialise_dns_configuaration(client: Arc<Mutex<Client>>) -> Result<(), DnsError> {
    trace!("Initialise dns configuration if not already done.");

    let dir_helper = DirectoryHelper::new(client.clone());
    let dir_listing =
        dir_helper.get_configuration_directory_listing(DNS_CONFIG_DIR_NAME.to_string())?;
    let mut file_helper = FileHelper::new(client.clone());
    match file_helper.create(DNS_CONFIG_FILE_NAME.to_string(), vec![], dir_listing) {
        Ok(writer) => {
            trace!("Dns configuration not found - initialising.");

            let _ = writer.close()?;
            Ok(())
        }
        Err(NfsError::FileAlreadyExistsWithSameName) => {
            trace!("Dns configuration is already initialised.");
            Ok(())
        }
        Err(error) => Err(DnsError::from(error)),
    }
}

/// Get dns configuration data.
pub fn get_dns_configuration_data(client: Arc<Mutex<Client>>)
                                  -> Result<Vec<DnsConfiguration>, DnsError> {
    trace!("Retrieve dns configuration data from a previously initialised dns configuration.");

    let dir_helper = DirectoryHelper::new(client.clone());
    let dir_listing =
        dir_helper.get_configuration_directory_listing(DNS_CONFIG_DIR_NAME.to_string())?;
    let file = dir_listing.get_files()
        .iter()
        .find(|file| file.get_name() == DNS_CONFIG_FILE_NAME)
        .ok_or(DnsError::DnsConfigFileNotFoundOrCorrupted)?;
    let mut file_helper = FileHelper::new(client.clone());
    let mut reader = file_helper.read(file)?;
    let size = reader.size();
    if size == 0 {
        Ok(vec![])
    } else {
        Ok(deserialise(&reader.read(0, size)?)?)
    }
}

/// Write dns configuration data.
pub fn write_dns_configuration_data(client: Arc<Mutex<Client>>,
                                    config: &[DnsConfiguration])
                                    -> Result<(), DnsError> {
    trace!("Write new dns configuration data to the previously initialised dns configuration.");

    let dir_helper = DirectoryHelper::new(client.clone());
    let dir_listing =
        dir_helper.get_configuration_directory_listing(DNS_CONFIG_DIR_NAME.to_string())?;
    let file = dir_listing
        .get_files()
        .iter()
        .find(|file| file.get_name() == DNS_CONFIG_FILE_NAME)
        .ok_or(DnsError::DnsConfigFileNotFoundOrCorrupted)?
        .clone();
    let mut file_helper = FileHelper::new(client.clone());
    let mut writer = file_helper.update_content(file, Mode::Overwrite, dir_listing)?;
    writer.write(&serialise(&config)?)?;
    let _ = writer.close()?;
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use core::utility;
    use core::utility::test_utils;
    use rust_sodium::crypto::box_;
    use std::sync::{Arc, Mutex};

    #[test]
    fn read_write_dns_configuration_file() {
        let client = Arc::new(Mutex::new(unwrap!(test_utils::get_client())));

        // Initialise Dns Configuration File
        unwrap!(initialise_dns_configuaration(client.clone()));

        // Get the Stored Configurations
        let mut config_vec = unwrap!(get_dns_configuration_data(client.clone()));
        assert_eq!(config_vec.len(), 0);

        let long_name = unwrap!(utility::generate_random_string(10));

        // Put in the 1st record
        let mut keypair = box_::gen_keypair();
        let config_0 = DnsConfiguration {
            long_name: long_name.clone(),
            encryption_keypair: (keypair.0, keypair.1),
        };

        config_vec.push(config_0.clone());
        unwrap!(write_dns_configuration_data(client.clone(), &config_vec));

        // Get the Stored Configurations
        config_vec = unwrap!(get_dns_configuration_data(client.clone()));
        assert_eq!(config_vec.len(), 1);

        assert_eq!(config_vec[0], config_0);

        // Modify the content
        keypair = box_::gen_keypair();
        let config_1 = DnsConfiguration {
            long_name: long_name,
            encryption_keypair: (keypair.0, keypair.1),
        };

        config_vec[0] = config_1.clone();
        unwrap!(write_dns_configuration_data(client.clone(), &config_vec));

        // Get the Stored Configurations
        config_vec = unwrap!(get_dns_configuration_data(client.clone()));
        assert_eq!(config_vec.len(), 1);

        assert!(config_vec[0] != config_0);
        assert_eq!(config_vec[0], config_1);

        // Delete Record
        config_vec.clear();
        unwrap!(write_dns_configuration_data(client.clone(), &config_vec));

        // Get the Stored Configurations
        config_vec = unwrap!(get_dns_configuration_data(client.clone()));
        assert_eq!(config_vec.len(), 0);
    }
}
