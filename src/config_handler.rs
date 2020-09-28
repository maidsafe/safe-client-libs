// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::ClientError;
use directories::ProjectDirs;
use lazy_static::lazy_static;
use log::{info, trace};
use qp2p::Config as QuicP2pConfig;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
#[cfg(test)]
use std::fs;
use std::{
    ffi::OsStr,
    fs::File,
    io::{self, BufReader},
    path::PathBuf,
    sync::Mutex,
};
use unwrap::unwrap;

const CONFIG_DIR_QUALIFIER: &str = "net";
const CONFIG_DIR_ORGANISATION: &str = "MaidSafe";
const CONFIG_DIR_APPLICATION: &str = "sn_client";
const CONFIG_FILE: &str = "sn_client.config";

const NODE_CONFIG_DIR_APPLICATION: &str = "sn_node";
const NODE_CONNECTION_INFO_FILE: &str = "node_connection_info.config";

lazy_static! {
    static ref CONFIG_DIR_PATH: Mutex<Option<PathBuf>> = Mutex::new(None);
    static ref DEFAULT_SN_CLIENT_PROJECT_DIRS: Option<ProjectDirs> = ProjectDirs::from(
        CONFIG_DIR_QUALIFIER,
        CONFIG_DIR_ORGANISATION,
        CONFIG_DIR_APPLICATION,
    );
    static ref DEFAULT_NODE_PROJECT_DIRS: Option<ProjectDirs> = ProjectDirs::from(
        CONFIG_DIR_QUALIFIER,
        CONFIG_DIR_ORGANISATION,
        NODE_CONFIG_DIR_APPLICATION,
    );
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
    /// Developer options.
    pub dev: Option<DevConfig>,
}

#[cfg(any(target_os = "android", target_os = "androideabi", target_os = "ios"))]
fn check_config_path_set() -> Result<(), ClientError> {
    if unwrap!(CONFIG_DIR_PATH.lock()).is_none() {
        Err(ClientError::QuicP2p(qp2p::QuicP2pError::Configuration {
            e: "Boostrap cache directory not set".to_string(),
        }))
    } else {
        Ok(())
    }
}

impl Config {
    /// Returns a new `Config` instance. Tries to read quic-p2p config from file.
    pub fn new() -> Self {
        let qp2p = Self::read_qp2p_from_file().unwrap_or_default();
        Self { qp2p, dev: None }
    }

    fn read_qp2p_from_file() -> Result<QuicP2pConfig, ClientError> {
        // First we read the default configuration file, and use a slightly modified default config
        // if there is none.
        let mut config: QuicP2pConfig = {
            match read_config_file(dirs()?, CONFIG_FILE) {
                Err(ClientError::IoError(ref err)) if err.kind() == io::ErrorKind::NotFound => {
                    // Bootstrap cache dir must be set on mobile platforms
                    // using set_config_dir_path
                    #[cfg(any(
                        target_os = "android",
                        target_os = "androideabi",
                        target_os = "ios"
                    ))]
                    check_config_path_set()?;

                    let custom_dir =
                        if let Some(custom_path) = unwrap!(CONFIG_DIR_PATH.lock()).clone() {
                            Some(custom_path.into_os_string().into_string().map_err(|_| {
                                ClientError::from("Config path is not a valid UTF-8 string")
                            })?)
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
        if let Ok(node_info) = read_config_file(node_dirs()?, NODE_CONNECTION_INFO_FILE) {
            let _ = config.hard_coded_contacts.insert(node_info);
        }
        Ok(config)
    }
}

/// Extra configuration options intended for developers.
#[derive(Clone, Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
pub struct DevConfig {
    /// Switch off mutations limit in mock-node.
    pub mock_unlimited_money: bool,
    /// Use memory store instead of file store in mock-node.
    pub mock_in_memory_storage: bool,
    /// Set the mock-node path if using file store (`mock_in_memory_storage` is `false`).
    pub mock_node_path: Option<String>,
}

/// Reads the `sn_client` config file and returns it or a default if this fails.
pub fn get_config() -> Config {
    Config::new()
}

/// Returns the directory from which the config files are read
pub fn config_dir() -> Result<PathBuf, ClientError> {
    Ok(dirs()?.config_dir().to_path_buf())
}

fn dirs() -> Result<ProjectDirs, ClientError> {
    let project_dirs = if let Some(custom_path) = unwrap!(CONFIG_DIR_PATH.lock()).clone() {
        ProjectDirs::from_path(custom_path)
    } else {
        DEFAULT_SN_CLIENT_PROJECT_DIRS.clone()
    };
    project_dirs.ok_or_else(|| ClientError::from("Cannot determine project directory paths"))
}

fn node_dirs() -> Result<ProjectDirs, ClientError> {
    let project_dirs = if let Some(custom_path) = unwrap!(CONFIG_DIR_PATH.lock()).clone() {
        ProjectDirs::from_path(custom_path)
    } else {
        DEFAULT_NODE_PROJECT_DIRS.clone()
    };
    project_dirs.ok_or_else(|| ClientError::from("Cannot determine node directory paths"))
}

fn read_config_file<T>(dirs: ProjectDirs, file: &str) -> Result<T, ClientError>
where
    T: DeserializeOwned,
{
    let path = dirs.config_dir().join(file);
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
pub fn write_config_file(config: &Config) -> Result<PathBuf, ClientError> {
    let dir = config_dir()?;
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
        let mut path = unwrap!(ProjectDirs::from_path(temp_dir_path.clone()))
            .config_dir()
            .to_path_buf();
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
            ..Default::default()
        };
        assert_eq!(config, expected_config);
    }
}
