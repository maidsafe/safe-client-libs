// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::Error;
use log::{debug, warn};
use qp2p::Config as QuicP2pConfig;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    fs::File,
    io::{self, BufReader},
    net::SocketAddr,
    path::Path,
};

/// Configuration for sn_client.
#[derive(Clone, Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
pub struct Config {
    /// QuicP2p options.
    pub qp2p: QuicP2pConfig,
}

impl Config {
    /// Returns a new `Config` instance. Tries to read quic-p2p config from file.
    pub fn new(
        config_file_path: Option<&Path>,
        bootstrap_config: Option<HashSet<SocketAddr>>,
    ) -> Self {
        // If a config file path was provided we try to read it,
        // otherwise we use default qp2p config.
        let mut qp2p = match &config_file_path {
            None => QuicP2pConfig::default(),
            Some(path) => match read_config_file(path) {
                Err(Error::IoError(ref err)) if err.kind() == io::ErrorKind::NotFound => {
                    QuicP2pConfig {
                        bootstrap_cache_dir: path.parent().map(|p| p.display().to_string()),
                        ..Default::default()
                    }
                }
                result => result.unwrap_or_default(),
            },
        };

        if let Some(contacts) = bootstrap_config {
            debug!("Bootstrapping contacts overriden with: {:?}", contacts);
            qp2p.hard_coded_contacts = contacts;
        }

        Self { qp2p }
    }
}

fn read_config_file(filepath: &Path) -> Result<QuicP2pConfig, Error> {
    match File::open(filepath) {
        Ok(file) => {
            debug!("Reading config file '{}' ...", filepath.display());
            let reader = BufReader::new(file);
            serde_json::from_reader(reader).map_err(|err| {
                warn!(
                    "Could not parse content of config file '{}': {}",
                    filepath.display(),
                    err
                );
                err.into()
            })
        }
        Err(err) => {
            warn!(
                "Failed to open config file from '{}': {}",
                filepath.display(),
                err
            );
            Err(err.into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::init_logger;
    use anyhow::Result;
    use rand::{distributions::Alphanumeric, thread_rng, Rng};
    use std::{env::temp_dir, fs::create_dir_all};

    // 1. Verify that `Config::new()` generates the correct default config
    //    when the file is not found. The default config shall have the provided
    //    config path in the `boostrap_cache_dir` field.
    // 2. Write the default config file to temp directory.
    // 3. Assert that `Config::new()` reads the default config written to disk.
    // 4. Verify that `Config::new()` returns the correct default config when no path is provided.
    #[test]
    fn custom_config_path() -> Result<()> {
        init_logger();

        let path = temp_dir();
        let random_filename: String = thread_rng().sample_iter(&Alphanumeric).take(15).collect();
        let config_filepath = path.join(random_filename);

        // In the absence of a config file, the config handler
        // should initialize bootstrap_cache_dir only
        let config = Config::new(Some(&config_filepath), None);
        // convert to string for assert
        let mut str_path = path
            .to_str()
            .ok_or(anyhow::anyhow!("No path for to_str".to_string()))?
            .to_string();
        // normalise for mac
        if str_path.ends_with('/') {
            let _ = str_path.pop();
        }

        let expected_config = Config {
            qp2p: QuicP2pConfig {
                bootstrap_cache_dir: Some(str_path),
                ..Default::default()
            },
        };
        assert_eq!(config, expected_config);

        create_dir_all(path)?;
        let mut file = File::create(&config_filepath)?;

        let config_on_disk = Config::default();
        serde_json::to_writer_pretty(&mut file, &config_on_disk)?;
        file.sync_all()?;

        let read_cfg = Config::new(Some(&config_filepath), None);
        assert_eq!(config_on_disk, read_cfg);

        let default_cfg = Config::new(None, None);
        assert_eq!(Config::default(), default_cfg);

        Ok(())
    }
}
