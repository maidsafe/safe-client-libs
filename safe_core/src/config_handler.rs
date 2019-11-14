// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::CoreError;
use directories::ProjectDirs;
use quic_p2p::Config as QuicP2pConfig;
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

const CONFIG_DIR_QUALIFIER: &str = "net";
const CONFIG_DIR_ORGANISATION: &str = "MaidSafe";
const CONFIG_DIR_APPLICATION: &str = "safe_core";
const CONFIG_FILE: &str = "safe_core.config";

const VAULT_CONFIG_DIR_APPLICATION: &str = "safe_vault";
const VAULT_CONNECTION_INFO_FILE: &str = "vault_connection_info.config";

lazy_static! {
    static ref CONFIG_DIR_PATH: Mutex<Option<PathBuf>> = Mutex::new(None);
    static ref DEFAULT_SAFE_CORE_PROJECT_DIRS: Option<ProjectDirs> = ProjectDirs::from(
        CONFIG_DIR_QUALIFIER,
        CONFIG_DIR_ORGANISATION,
        CONFIG_DIR_APPLICATION,
    );
    static ref DEFAULT_VAULT_PROJECT_DIRS: Option<ProjectDirs> = ProjectDirs::from(
        CONFIG_DIR_QUALIFIER,
        CONFIG_DIR_ORGANISATION,
        VAULT_CONFIG_DIR_APPLICATION,
    );
}

/// Set a custom path for the config files.
// `OsStr` is platform-native.
pub fn set_config_dir_path<P: AsRef<OsStr> + ?Sized>(path: &P) {
    *unwrap!(CONFIG_DIR_PATH.lock()) = Some(From::from(path));
}

/// Configuration for safe-core.
#[derive(Clone, Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
pub struct Config {
    /// QuicP2p options.
    pub quic_p2p: QuicP2pConfig,
    /// Developer options.
    pub dev: Option<DevConfig>,
}

#[cfg(any(target_os = "android", target_os = "androideabi", target_os = "ios"))]
fn check_config_path_set() -> Result<(), CoreError> {
    if unwrap!(CONFIG_DIR_PATH.lock()).is_none() {
        Err(CoreError::QuicP2p(quic_p2p::Error::Configuration(
            "Boostrap cache directory not set".to_string(),
        )))
    } else {
        Ok(())
    }
}

impl Config {
    /// Returns a new `Config` instance. Tries to read quic-p2p config from file.
    pub fn new() -> Self {
        let quic_p2p = Self::read_qp2p_from_file().unwrap_or_default();
        Self {
            quic_p2p,
            dev: None,
        }
    }

    fn read_qp2p_from_file() -> Result<QuicP2pConfig, CoreError> {
        // Firs we read the default configuration file, and use a slightly modified default config
        // if there is none.
        let mut config: QuicP2pConfig = {
            match read_config_file(dirs()?, CONFIG_FILE) {
                Err(CoreError::IoError(ref err)) if err.kind() == io::ErrorKind::NotFound => {
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
                                CoreError::from("Config path is not a valid UTF-8 string")
                            })?)
                        } else {
                            None
                        };
                    // If there is no config file, assume we are a client
                    QuicP2pConfig {
                        our_type: quic_p2p::OurType::Client,
                        bootstrap_cache_dir: custom_dir,
                        ..Default::default()
                    }
                }
                result => result?,
            }
        };
        // Then if there is a locally running Vault we add it to the list of know contacts.
        if let Ok(node_info) = read_config_file(vault_dirs()?, VAULT_CONNECTION_INFO_FILE) {
            let _ = config.hard_coded_contacts.insert(node_info);
        }
        Ok(config)
    }
}

/// Extra configuration options intended for developers.
#[derive(Clone, Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
pub struct DevConfig {
    /// Switch off mutations limit in mock-vault.
    pub mock_unlimited_coins: bool,
    /// Use memory store instead of file store in mock-vault.
    pub mock_in_memory_storage: bool,
    /// Set the mock-vault path if using file store (`mock_in_memory_storage` is `false`).
    pub mock_vault_path: Option<String>,
}

/// Reads the `safe_core` config file and returns it or a default if this fails.
pub fn get_config() -> Config {
    Config::new()
}

/// Returns the directory from which the config files are read
pub fn config_dir() -> Result<PathBuf, CoreError> {
    Ok(dirs()?.config_dir().to_path_buf())
}

fn dirs() -> Result<ProjectDirs, CoreError> {
    let project_dirs = if let Some(custom_path) = unwrap!(CONFIG_DIR_PATH.lock()).clone() {
        ProjectDirs::from_path(custom_path)
    } else {
        DEFAULT_SAFE_CORE_PROJECT_DIRS.clone()
    };
    project_dirs.ok_or_else(|| CoreError::from("Cannot determine project directory paths"))
}

fn vault_dirs() -> Result<ProjectDirs, CoreError> {
    let project_dirs = if let Some(custom_path) = unwrap!(CONFIG_DIR_PATH.lock()).clone() {
        ProjectDirs::from_path(custom_path)
    } else {
        DEFAULT_VAULT_PROJECT_DIRS.clone()
    };
    project_dirs.ok_or_else(|| CoreError::from("Cannot determine vault directory paths"))
}

fn read_config_file<T>(dirs: ProjectDirs, file: &str) -> Result<T, CoreError>
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

/// Writes a `safe_core` config file **for use by tests and examples**.
///
/// N.B. This method should only be used as a utility for test and examples.  In normal use cases,
/// the config file should be created by the Vault's installer.
#[cfg(test)]
pub fn write_config_file(config: &Config) -> Result<PathBuf, CoreError> {
    let dir = config_dir()?;
    fs::create_dir_all(dir.clone())?;

    let path = dir.join(CONFIG_FILE);
    dbg!(&path);
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
    //    `boostrap_cache_dir` field and `our_type` will be set to `Client`
    #[test]
    fn custom_config_path() {
        let path = temp_dir();
        let temp_dir_path = path.clone();
        set_config_dir_path(&path);
        // In the default config, `our_type` will be set to Node.
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
        // should initialize the `our_type` field to Client.
        let config = Config::new();
        let expected_config = Config {
            quic_p2p: QuicP2pConfig {
                our_type: quic_p2p::OurType::Client,
                bootstrap_cache_dir: Some(unwrap!(temp_dir_path.into_os_string().into_string())),
                ..Default::default()
            },
            ..Default::default()
        };
        assert_eq!(config, expected_config);
    }
}
