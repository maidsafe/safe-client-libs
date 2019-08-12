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
use std::path::PathBuf;
use std::{
    ffi::OsString,
    fs::File,
    io::{self, BufReader},
};

// TODO: Currently the quic-p2p and dev config are handled through different mechanisms. We need to
// unify and streamline, in the process getting rid of config_file_handler.

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
/// The file is written to the [`current_bin_dir()`](file_handler/fn.current_bin_dir.html)
/// with the appropriate file name.
#[cfg(test)]
pub fn write_config_file(config: &Config) -> Result<PathBuf, CoreError> {
    let mut config_path = PathBuf::new();
    config_path.push(get_file_name()?);
    Ok(config_path)
    // use std::io::Write;

    // let mut config_path = config_file_handler::current_bin_dir()?;
    // config_path.push(get_file_name()?);
    // let mut file = ::std::fs::File::create(&config_path)?;
    // write!(
    //     &mut file,
    //     "{}",
    //     unwrap!(serde_json::to_string_pretty(config))
    // )?;
    // file.sync_all()?;
    // Ok(config_path)
}

fn get_file_name() -> Result<OsString, CoreError> {
    let mut name = config_file_handler::exe_file_stem()?;
    name.push(".safe_core.config");
    Ok(name)
}

#[cfg(test)]
mod test {
    use super::*;
    use serde_json;
    use std::fs::File;
    use std::io::Read;
    use std::path::Path;

    #[test]
    fn parse_sample_config_file_memory() {
        let path = Path::new("sample_config/sample_memory.safe_core.config").to_path_buf();
        let mut file = unwrap!(File::open(&path), "Error opening {}:", path.display());
        let mut encoded_contents = String::new();
        let _ = unwrap!(
            file.read_to_string(&mut encoded_contents),
            "Error reading {}:",
            path.display()
        );
        let config: Config = unwrap!(
            serde_json::from_str(&encoded_contents),
            "Error parsing {} as JSON:",
            path.display()
        );

        let dev_config = unwrap!(config.dev, "{} is missing `dev` field.", path.display());
        assert_eq!(dev_config.mock_unlimited_mutations, true);
        assert_eq!(dev_config.mock_in_memory_storage, true);
    }

    #[test]
    fn parse_sample_config_file_disk() {
        let path = Path::new("sample_config/sample_disk.safe_core.config").to_path_buf();
        let mut file = unwrap!(File::open(&path), "Error opening {}:", path.display());
        let mut encoded_contents = String::new();
        let _ = unwrap!(
            file.read_to_string(&mut encoded_contents),
            "Error reading {}:",
            path.display()
        );
        let config: Config = unwrap!(
            serde_json::from_str(&encoded_contents),
            "Error parsing {} as JSON:",
            path.display()
        );

        let dev_config = unwrap!(config.dev, "{} is missing `dev` field.", path.display());
        assert_eq!(dev_config.mock_unlimited_mutations, false);
        assert_eq!(dev_config.mock_in_memory_storage, false);
        assert_eq!(dev_config.mock_vault_path, Some(String::from("./tmp")));
    }
}
