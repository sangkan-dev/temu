use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::TemuError;

/// Application-wide configuration loaded from a TOML file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    /// Maximum HTTP requests per second.
    pub rate_limit: u32,
    /// Per-request timeout in seconds.
    pub timeout_secs: u64,
    /// Maximum number of concurrent async tasks.
    pub concurrency: usize,
    /// User-Agent header sent with every HTTP request.
    pub user_agent: String,
    /// Directory where scan results are written.
    pub output_dir: PathBuf,
    /// Directory containing YAML detection rule files.
    pub rules_dir: PathBuf,
    /// Directory containing wordlist files.
    pub dictionaries_dir: PathBuf,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            rate_limit: 50,
            timeout_secs: 10,
            concurrency: 100,
            user_agent: "Temu/0.1.0".to_string(),
            output_dir: PathBuf::from("./results"),
            rules_dir: PathBuf::from("./rules"),
            dictionaries_dir: PathBuf::from("./dictionaries"),
        }
    }
}

impl AppConfig {
    /// Loads configuration from a TOML file at `path`.
    /// Falls back to `AppConfig::default()` for any missing fields.
    pub fn load(path: &Path) -> Result<Self, TemuError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| TemuError::Config(format!("Cannot read config file {:?}: {}", path, e)))?;

        let config: AppConfig = toml::from_str(&content)
            .map_err(|e| TemuError::Config(format!("Invalid TOML in {:?}: {}", path, e)))?;

        Ok(config)
    }

    /// Loads configuration from `path` if it exists, otherwise returns `AppConfig::default()`.
    pub fn load_or_default(path: &Path) -> Self {
        Self::load(path).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_default_values() {
        let config = AppConfig::default();
        assert_eq!(config.rate_limit, 50);
        assert_eq!(config.timeout_secs, 10);
        assert_eq!(config.concurrency, 100);
        assert_eq!(config.user_agent, "Temu/0.1.0");
        assert_eq!(config.output_dir, PathBuf::from("./results"));
        assert_eq!(config.rules_dir, PathBuf::from("./rules"));
        assert_eq!(config.dictionaries_dir, PathBuf::from("./dictionaries"));
    }

    #[test]
    fn test_load_from_toml() {
        let toml_content = r#"
rate_limit = 100
timeout_secs = 20
concurrency = 200
user_agent = "Temu/0.2.0"
output_dir = "/tmp/results"
rules_dir = "/tmp/rules"
dictionaries_dir = "/tmp/dicts"
"#;
        let mut tmp = tempfile::NamedTempFile::new().expect("failed to create temp file");
        tmp.write_all(toml_content.as_bytes()).unwrap();

        let config = AppConfig::load(tmp.path()).expect("load failed");
        assert_eq!(config.rate_limit, 100);
        assert_eq!(config.timeout_secs, 20);
        assert_eq!(config.concurrency, 200);
        assert_eq!(config.user_agent, "Temu/0.2.0");
    }

    #[test]
    fn test_load_nonexistent_falls_back_to_default() {
        let config = AppConfig::load_or_default(Path::new("/nonexistent/path/config.toml"));
        assert_eq!(config.rate_limit, 50);
    }

    #[test]
    fn test_load_invalid_toml_returns_error() {
        let mut tmp = tempfile::NamedTempFile::new().expect("failed to create temp file");
        tmp.write_all(b"this is not valid toml :::").unwrap();
        let result = AppConfig::load(tmp.path());
        assert!(result.is_err());
    }
}
