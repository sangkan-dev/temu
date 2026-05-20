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
    /// Maximum recursive path fuzzing depth.
    #[serde(default = "default_max_recursion_depth")]
    pub max_recursion_depth: usize,
    /// Optional override path to a custom wordlist file. When set, this
    /// takes precedence over the size-based preset from `dictionaries_dir`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wordlist_override: Option<PathBuf>,
    /// Allows rules marked as intrusive, destructive, DoS-prone, or requiring
    /// explicit confirmation to execute.
    #[serde(default)]
    pub allow_risky_rules: bool,
}

fn default_max_recursion_depth() -> usize {
    2
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            rate_limit: 50,
            timeout_secs: 10,
            concurrency: 100,
            user_agent: "Temu/1.1.1".to_string(),
            output_dir: PathBuf::from("./results"),
            rules_dir: PathBuf::from("./rules"),
            dictionaries_dir: PathBuf::from("./dictionaries"),
            max_recursion_depth: default_max_recursion_depth(),
            wordlist_override: None,
            allow_risky_rules: false,
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

    /// Applies `TEMU_*` environment variable overrides to this config in-place.
    ///
    /// Each field has a corresponding env var with the `TEMU_` prefix:
    /// `TEMU_RATE_LIMIT`, `TEMU_TIMEOUT_SECS`, `TEMU_CONCURRENCY`,
    /// `TEMU_USER_AGENT`, `TEMU_OUTPUT_DIR`, `TEMU_RULES_DIR`, `TEMU_DICTIONARIES_DIR`,
    /// `TEMU_MAX_RECURSION_DEPTH`, `TEMU_ALLOW_RISKY_RULES`.
    /// Invalid values are silently ignored.
    pub fn apply_env_overrides(&mut self) {
        if let Ok(v) = std::env::var("TEMU_RATE_LIMIT")
            && let Ok(n) = v.parse()
        {
            self.rate_limit = n;
        }
        if let Ok(v) = std::env::var("TEMU_TIMEOUT_SECS")
            && let Ok(n) = v.parse()
        {
            self.timeout_secs = n;
        }
        if let Ok(v) = std::env::var("TEMU_CONCURRENCY")
            && let Ok(n) = v.parse()
        {
            self.concurrency = n;
        }
        if let Ok(v) = std::env::var("TEMU_USER_AGENT") {
            self.user_agent = v;
        }
        if let Ok(v) = std::env::var("TEMU_OUTPUT_DIR") {
            self.output_dir = PathBuf::from(v);
        }
        if let Ok(v) = std::env::var("TEMU_RULES_DIR") {
            self.rules_dir = PathBuf::from(v);
        }
        if let Ok(v) = std::env::var("TEMU_DICTIONARIES_DIR") {
            self.dictionaries_dir = PathBuf::from(v);
        }
        if let Ok(v) = std::env::var("TEMU_MAX_RECURSION_DEPTH")
            && let Ok(n) = v.parse()
        {
            self.max_recursion_depth = n;
        }
        if let Ok(v) = std::env::var("TEMU_ALLOW_RISKY_RULES") {
            self.allow_risky_rules = matches!(
                v.to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "y" | "on"
            );
        }
    }

    /// Loads configuration from `path` and applies `TEMU_*` env var overrides.
    pub fn load_with_env(path: &Path) -> Result<Self, TemuError> {
        let mut config = Self::load(path)?;
        config.apply_env_overrides();
        Ok(config)
    }

    /// Loads configuration from `path` (or default) and applies `TEMU_*` env var overrides.
    pub fn load_or_default_with_env(path: &Path) -> Self {
        let mut config = Self::load_or_default(path);
        config.apply_env_overrides();
        config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::Mutex;

    static ENV_MUTEX: Mutex<()> = Mutex::new(());

    #[test]
    fn test_default_values() {
        let config = AppConfig::default();
        assert_eq!(config.rate_limit, 50);
        assert_eq!(config.timeout_secs, 10);
        assert_eq!(config.concurrency, 100);
        assert_eq!(config.user_agent, "Temu/1.1.1");
        assert_eq!(config.output_dir, PathBuf::from("./results"));
        assert_eq!(config.rules_dir, PathBuf::from("./rules"));
        assert_eq!(config.dictionaries_dir, PathBuf::from("./dictionaries"));
        assert_eq!(config.max_recursion_depth, 2);
        assert!(!config.allow_risky_rules);
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
max_recursion_depth = 3
allow_risky_rules = true
"#;
        let mut tmp = tempfile::NamedTempFile::new().expect("failed to create temp file");
        tmp.write_all(toml_content.as_bytes()).unwrap();

        let config = AppConfig::load(tmp.path()).expect("load failed");
        assert_eq!(config.rate_limit, 100);
        assert_eq!(config.timeout_secs, 20);
        assert_eq!(config.concurrency, 200);
        assert_eq!(config.user_agent, "Temu/0.2.0");
        assert_eq!(config.max_recursion_depth, 3);
        assert!(config.allow_risky_rules);
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

    #[test]
    fn test_apply_env_overrides_rate_limit() {
        let _guard = ENV_MUTEX.lock().unwrap();
        unsafe { std::env::set_var("TEMU_RATE_LIMIT", "999") };
        let mut config = AppConfig::default();
        config.apply_env_overrides();
        unsafe { std::env::remove_var("TEMU_RATE_LIMIT") };
        assert_eq!(config.rate_limit, 999);
    }

    #[test]
    fn test_apply_env_overrides_user_agent() {
        let _guard = ENV_MUTEX.lock().unwrap();
        unsafe { std::env::set_var("TEMU_USER_AGENT", "TestAgent/1.0") };
        let mut config = AppConfig::default();
        config.apply_env_overrides();
        unsafe { std::env::remove_var("TEMU_USER_AGENT") };
        assert_eq!(config.user_agent, "TestAgent/1.0");
    }

    #[test]
    fn test_apply_env_overrides_invalid_value_ignored() {
        let _guard = ENV_MUTEX.lock().unwrap();
        unsafe { std::env::set_var("TEMU_RATE_LIMIT", "not_a_number") };
        let mut config = AppConfig::default();
        config.apply_env_overrides();
        unsafe { std::env::remove_var("TEMU_RATE_LIMIT") };
        assert_eq!(config.rate_limit, 50);
    }

    #[test]
    fn test_apply_env_overrides_output_dir() {
        let _guard = ENV_MUTEX.lock().unwrap();
        unsafe { std::env::set_var("TEMU_OUTPUT_DIR", "/tmp/temu_results") };
        let mut config = AppConfig::default();
        config.apply_env_overrides();
        unsafe { std::env::remove_var("TEMU_OUTPUT_DIR") };
        assert_eq!(config.output_dir, PathBuf::from("/tmp/temu_results"));
    }

    #[test]
    fn test_apply_env_overrides_max_recursion_depth() {
        let _guard = ENV_MUTEX.lock().unwrap();
        unsafe { std::env::set_var("TEMU_MAX_RECURSION_DEPTH", "4") };
        let mut config = AppConfig::default();
        config.apply_env_overrides();
        unsafe { std::env::remove_var("TEMU_MAX_RECURSION_DEPTH") };
        assert_eq!(config.max_recursion_depth, 4);
    }
}
