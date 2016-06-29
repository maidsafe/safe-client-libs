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

use std::sync::{Arc, Mutex};

use core::client::Client;
use ffi::config::{LAUNCHER_GLOBAL_CONFIG_FILE_NAME, LAUNCHER_GLOBAL_DIRECTORY_NAME};
use ffi::errors::FfiError;
use maidsafe_utilities::serialisation::{deserialise, serialise};
use nfs::directory_listing::DirectoryListing;
use nfs::{AccessLevel, UNVERSIONED_DIRECTORY_LISTING_TAG};
use nfs::helper::directory_helper::DirectoryHelper;
use nfs::helper::file_helper::FileHelper;
use nfs::helper::writer::Mode::Overwrite;
use nfs::metadata::directory_key::DirectoryKey;
use routing::XorName;
use sodiumoxide::crypto::hash::sha256;

#[derive(RustcEncodable, RustcDecodable, Debug)]
pub struct LauncherConfiguration {
    pub app_id: XorName,
    pub app_root_dir_key: DirectoryKey,
}

pub struct ConfigHandler {
    client: Arc<Mutex<Client>>,
}

impl ConfigHandler {
    pub fn new(client: Arc<Mutex<Client>>) -> ConfigHandler {
        ConfigHandler { client: client }
    }

    pub fn get_app_dir_key(&self,
                           app_name: String,
                           app_key: String,
                           vendor: String)
                           -> Result<DirectoryKey, FfiError> {
        let app_id = self.get_app_id(&app_key, &vendor);

        let (configs, _) = try!(self.get_launcher_global_config_and_dir());
        let app_dir_key = match configs.into_iter()
            .find(|config| config.app_id == app_id)
            .map(|config| config) {
            Some(config) => config.app_root_dir_key.clone(),
            None => {
                let dir_helper = DirectoryHelper::new(self.client.clone());
                let mut root_dir_listing = try!(dir_helper.get_user_root_directory_listing());
                let app_dir_name = self.get_app_dir_name(&app_name, &root_dir_listing);
                let dir_key = try!(dir_helper.create(app_dir_name,
                                                     UNVERSIONED_DIRECTORY_LISTING_TAG,
                                                     Vec::new(),
                                                     false,
                                                     AccessLevel::Private,
                                                     Some(&mut root_dir_listing)))
                    .0
                    .get_key()
                    .clone();
                let app_config = LauncherConfiguration {
                    app_id: app_id,
                    app_root_dir_key: dir_key.clone(),
                };
                try!(self.upsert_to_launcher_global_config(app_config));
                dir_key
            }
        };

        Ok(app_dir_key)
    }

    fn get_app_id(&self, app_key: &str, vendor: &str) -> XorName {
        let mut id_str = String::new();
        id_str.push_str(app_key);
        id_str.push_str(vendor);
        XorName(sha256::hash(id_str.as_bytes()).0)
    }

    fn get_app_dir_name(&self, app_name: &str, directory_listing: &DirectoryListing) -> String {
        let mut dir_name = format!("{}-Root-Dir", &app_name);
        if directory_listing.find_sub_directory(&dir_name).is_some() {
            let mut index = 1u8;
            loop {
                dir_name = format!("{}-{}-Root-Dir", &app_name, index);
                if directory_listing.find_sub_directory(&dir_name).is_some() {
                    index += 1;
                } else {
                    break;
                }
            }
        }

        dir_name
    }

    fn upsert_to_launcher_global_config(&self,
                                        config: LauncherConfiguration)
                                        -> Result<(), FfiError> {
        let (mut global_configs, dir_listing) = try!(self.get_launcher_global_config_and_dir());

        // (Spandan)
        // Unable to use `if let Some() .. else` logic to upsert to a vector due to a language bug.
        // Once the bug is resolved
        // - https://github.com/rust-lang/rust/issues/28449
        // then modify the following to use it.
        if let Some(pos) = global_configs.iter()
            .position(|existing_config| existing_config.app_id == config.app_id) {
            let existing_config = unwrap!(global_configs.get_mut(pos));
            *existing_config = config;
        } else {
            global_configs.push(config);
        }

        let file = unwrap!(dir_listing.get_files()
                               .iter()
                               .find(|file| file.get_name() == LAUNCHER_GLOBAL_CONFIG_FILE_NAME),
                           "Logic Error - Launcher start-up should ensure the file must be \
                            present at this stage - Report bug.")
            .clone();

        let mut file_helper = FileHelper::new(self.client.clone());
        let mut writer = try!(file_helper.update_content(file, Overwrite, dir_listing));
        try!(writer.write(&try!(serialise(&global_configs)), 0));
        let _ = try!(writer.close());

        Ok(())
    }

    fn get_launcher_global_config_and_dir
        (&self)
         -> Result<(Vec<LauncherConfiguration>, DirectoryListing), FfiError> {
        let dir_helper = DirectoryHelper::new(self.client.clone());
        let mut dir_listing = try!(dir_helper.get_configuration_directory_listing(
            LAUNCHER_GLOBAL_DIRECTORY_NAME.to_string()));

        let global_configs = {
            let mut file_helper = FileHelper::new(self.client.clone());
            let file = match dir_listing.get_files()
                .iter()
                .find(|file| file.get_name() == LAUNCHER_GLOBAL_CONFIG_FILE_NAME)
                .cloned() {
                Some(file) => file,
                None => {
                    dir_listing =
                        try!(try!(file_helper.create(LAUNCHER_GLOBAL_CONFIG_FILE_NAME.to_string(),
                                            Vec::new(),
                                            dir_listing))
                                .close())
                            .0;
                    unwrap!(dir_listing.get_files()
                            .iter()
                            .find(|file| file.get_name() == LAUNCHER_GLOBAL_CONFIG_FILE_NAME)
                            .cloned())
                        .clone()
                }
            };
            let mut reader = try!(file_helper.read(&file));

            let size = reader.size();

            if size == 0 {
                Vec::new()
            } else {
                try!(deserialise(&try!(reader.read(0, size))))
            }
        };

        Ok((global_configs, dir_listing))
    }
}
