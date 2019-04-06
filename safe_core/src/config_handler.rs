// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use config_file_handler;
use std::ffi::OsString;
#[cfg(test)]
use std::path::PathBuf;
use crate::CoreError;

/// Configuration for safe-core.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Config {
    /// Developer options.
    pub dev: Option<DevConfig>,
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
    read_config_file().unwrap_or_else(|error| {
        warn!("Failed to parse safe_core config file: {:?}", error);
        Config::default()
    })
}

fn read_config_file() -> Result<Config, CoreError> {
    // If the config file is not present, a default one will be generated.
    let file_handler = config_file_handler::FileHandler::new(&get_file_name()?, false)?;
    Ok(file_handler.read_file()?)
}

/// Writes a `safe_core` config file **for use by tests and examples**.
///
/// The file is written to the [`current_bin_dir()`](file_handler/fn.current_bin_dir.html)
/// with the appropriate file name.
#[cfg(test)]
pub fn write_config_file(config: &Config) -> Result<PathBuf, CoreError> {
    use serde_json;
    use std::io::Write;

    let mut config_path = config_file_handler::current_bin_dir()?;
    config_path.push(get_file_name()?);
    let mut file = ::std::fs::File::create(&config_path)?;
    write!(
        &mut file,
        "{}",
        unwrap!(serde_json::to_string_pretty(config))
    )?;
    file.sync_all()?;
    Ok(config_path)
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
