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
use std::{fs, path::PathBuf};
use std::{
    fs::File,
    io::{self, BufReader},
};

const CONFIG_DIR_QUALIFIER: &str = "net";
const CONFIG_DIR_ORGANISATION: &str = "MaidSafe";
const CONFIG_DIR_APPLICATION: &str = "safe_core";
const CONFIG_FILE: &str = "safe_core.config";

const VAULT_CONFIG_DIR_APPLICATION: &str = "safe_vault";
const VAULT_CONNECTION_INFO_FILE: &str = "vault_connection_info.config";

/// Configuration for safe-core.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Config {
    /// QuicP2p options.
    pub quic_p2p: QuicP2pConfig,
    /// Developer options.
    pub dev: Option<DevConfig>,
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
        let mut config: QuicP2pConfig = read_config_file(dirs()?, CONFIG_FILE)?;
        if let Ok(node_info) = read_config_file(vault_dirs()?, VAULT_CONNECTION_INFO_FILE) {
            let _ = config.hard_coded_contacts.insert(node_info);
        }
        Ok(config)
    }
}

/// Extra configuration options intended for developers.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct DevConfig {
    /// Switch off mutations limit in mock-vault.
    pub mock_unlimited_mutations: bool,
    /// Use memory store instead of file store in mock-vault.
    pub mock_in_memory_storage: bool,
    /// Set the mock-vault path if using file store (`mock_in_memory_storage` is `false`).
    pub mock_vault_path: Option<String>,
}

/// Reads the `safe_core` config file and returns it or a default if this fails.
pub fn get_config() -> Config {
    Config::new()
}

fn dirs() -> Result<ProjectDirs, CoreError> {
    ProjectDirs::from(
        CONFIG_DIR_QUALIFIER,
        CONFIG_DIR_ORGANISATION,
        CONFIG_DIR_APPLICATION,
    )
    .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Home directory not found").into())
}

fn vault_dirs() -> Result<ProjectDirs, CoreError> {
    ProjectDirs::from(
        CONFIG_DIR_QUALIFIER,
        CONFIG_DIR_ORGANISATION,
        VAULT_CONFIG_DIR_APPLICATION,
    )
    .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Home directory not found").into())
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
/// The file is written to the `current_bin_dir()` with the appropriate file name.
///
/// N.B. This method should only be used as a utility for test and examples.  In normal use cases,
/// the config file should be created by the Vault's installer.
#[cfg(test)]
#[allow(unused)]
pub fn write_config_file(config: &Config) -> Result<PathBuf, CoreError> {
    let dirs = dirs()?;
    let dir = dirs.config_dir();
    fs::create_dir_all(dir)?;

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

    // Write a default config file for use as reference. This will overwrite any existing
    // configurations so use with care.
    #[test]
    #[ignore]
    fn write_default_config_file() {
        let config = Config::default();
        unwrap!(write_config_file(&config));
    }
}
