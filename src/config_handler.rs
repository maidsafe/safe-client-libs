// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::Error;
use lazy_static::lazy_static;
use log::{info, trace};
use qp2p::Config as QuicP2pConfig;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
#[cfg(test)]
use std::fs;
use std::{
    collections::HashSet,
    ffi::OsStr,
    fs::File,
    io::{self, BufReader},
    net::SocketAddr,
    path::PathBuf,
    sync::Mutex,
};
use unwrap::unwrap;

const HOME_DIR_SAFE: &str = ".safe";
const CONFIG_DIR_APPLICATION: &str = "client";
const CONFIG_FILE: &str = "sn_client.config";

const NODE_CONFIG_DIR_APPLICATION: &str = "node";
const NODE_CONNECTION_INFO_FILE: &str = "node_connection_info.config";

lazy_static! {
    static ref CONFIG_DIR_PATH: Mutex<Option<PathBuf>> = Mutex::new(None);
}

/// Set a custom path for the config files.
// `OsStr` is platform-native.
pub fn set_config_dir_path<P: AsRef<OsStr> + ?Sized>(path: &P) {
    *unwrap!(CONFIG_DIR_PATH.lock()) = Some(From::from(path));
}

/// Configuration for sn_client.
#[derive(Clone, Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
pub struct Config {
    /// QuicP2p options.
    pub qp2p: QuicP2pConfig,
}

impl Config {
    /// Returns a new `Config` instance. Tries to read quic-p2p config from file.
    pub fn new() -> Self {
        let qp2p = Self::read_qp2p_from_file().unwrap_or_default();
        Self { qp2p }
    }

    fn read_qp2p_from_file() -> Result<QuicP2pConfig, Error> {
        // First we read the default configuration file, and use a slightly modified default config
        // if there is none.
        let mut config: QuicP2pConfig = {
            match read_config_file(dirs()?, CONFIG_FILE) {
                Err(Error::IoError(ref err)) if err.kind() == io::ErrorKind::NotFound => {
                    let custom_dir =
                        if let Some(custom_path) = unwrap!(CONFIG_DIR_PATH.lock()).clone() {
                            Some(
                                custom_path
                                    .into_os_string()
                                    .into_string()
                                    .map_err(|_| Error::InvalidConfigPath)?,
                            )
                        } else {
                            None
                        };
                    // If there is no config file, assume we are a client
                    QuicP2pConfig {
                        bootstrap_cache_dir: custom_dir,
                        ..Default::default()
                    }
                }
                result => result?,
            }
        };

        // Then if there is a locally running Node we add it to the list of know contacts.
        if let Ok(contacts) =
            read_config_file::<HashSet<SocketAddr>>(node_dirs()?, NODE_CONNECTION_INFO_FILE)
        {
            contacts.iter().for_each(|node_info| {
                if config.hard_coded_contacts.insert(*node_info) {
                    trace!(
                        "New contact added to the hard-coded contacts list: {}",
                        node_info
                    );
                } else {
                    trace!(
                        "Contact is already in the hard-coded contacts list: {}",
                        node_info
                    );
                }
            })
        }
        Ok(config)
    }
}

/// Return the Project directory
pub fn dirs() -> Result<PathBuf, Error> {
    let project_dirs = if let Some(custom_path) = unwrap!(CONFIG_DIR_PATH.lock()).clone() {
        let mut path = PathBuf::new();
        path.push(custom_path);
        path
    } else {
        let mut path = dirs_next::home_dir().ok_or(Error::NoHomeDir)?;
        path.push(HOME_DIR_SAFE);
        path.push(CONFIG_DIR_APPLICATION);
        path
    };
    Ok(project_dirs)
}

fn node_dirs() -> Result<PathBuf, Error> {
    let project_dirs = if let Some(custom_path) = unwrap!(CONFIG_DIR_PATH.lock()).clone() {
        let mut path = PathBuf::new();
        path.push(custom_path);
        path
    } else {
        let mut path = dirs_next::home_dir().ok_or(Error::NoHomeDir)?;
        path.push(HOME_DIR_SAFE);
        path.push(NODE_CONFIG_DIR_APPLICATION);
        path
    };
    Ok(project_dirs)
}

fn read_config_file<T>(dirs: PathBuf, file: &str) -> Result<T, Error>
where
    T: DeserializeOwned,
{
    let path = dirs.join(file);
    let file = match File::open(&path) {
        Ok(file) => {
            trace!("Reading: {}", path.display());
            file
        }
        Err(error) => {
            trace!("Not available: {}", path.display());
            return Err(error.into());
        }
    };
    let reader = BufReader::new(file);
    serde_json::from_reader(reader).map_err(|err| {
        info!("Could not parse: {} ({:?})", err, err);
        err.into()
    })
}

/// Writes a `sn_client` config file **for use by tests and examples**.
///
/// N.B. This method should only be used as a utility for test and examples.  In normal use cases,
/// the config file should be created by the Node's installer.
#[cfg(test)]
pub fn write_config_file(config: &Config) -> Result<PathBuf, Error> {
    let dir = dirs()?;
    fs::create_dir_all(dir.clone())?;

    let path = dir.join(CONFIG_FILE);
    let mut file = File::create(&path)?;
    serde_json::to_writer_pretty(&mut file, config)?;
    file.sync_all()?;

    Ok(path)
}

#[cfg(test)]
mod test {
    use super::*;
    use std::env::temp_dir;

    // 1. Write the default config file to temp directory.
    // 2. Set the temp directory as the custom config directory path.
    // 3. Assert that `Config::new()` reads the default config written to disk.
    // 4. Verify that `Config::new()` generates the correct default config.
    //    The default config will have the custom config path in the
    //    `boostrap_cache_dir` field
    #[test]
    fn custom_config_path() {
        let path = temp_dir();
        let temp_dir_path = path.clone();
        set_config_dir_path(&path);
        let config: Config = Default::default();
        unwrap!(write_config_file(&config));

        let read_cfg = Config::new();
        assert_eq!(config, read_cfg);

        let mut path = PathBuf::new();
        path.push(temp_dir_path.clone());

        path.push(CONFIG_FILE);
        unwrap!(std::fs::remove_file(path));

        // In the absence of a config file, the config handler
        // should initialize bootstrap_cache_dir only
        let config = Config::new();
        let expected_config = Config {
            qp2p: QuicP2pConfig {
                bootstrap_cache_dir: Some(unwrap!(temp_dir_path.into_os_string().into_string())),
                ..Default::default()
            },
        };
        assert_eq!(config, expected_config);
    }
}
