use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::TemuError;
use crate::session::SessionProfile;

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
    /// Enables browser-aware crawling of HTML and JavaScript routes.
    #[serde(default = "default_browser_crawl_enabled")]
    pub browser_crawl_enabled: bool,
    /// Maximum number of in-scope pages visited by the browser-aware crawler.
    #[serde(default = "default_browser_crawl_max_pages")]
    pub browser_crawl_max_pages: usize,
    /// Maximum crawl depth for links discovered by the browser-aware crawler.
    #[serde(default = "default_browser_crawl_max_depth")]
    pub browser_crawl_max_depth: usize,
    /// Uses a local Chromium/Chrome binary to render JavaScript before route extraction.
    #[serde(default)]
    pub browser_crawl_render_js: bool,
    /// Optional path to a Chromium/Chrome-compatible browser binary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub browser_crawl_browser_path: Option<PathBuf>,
    /// Optional authenticated session profile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_profile: Option<SessionProfile>,
    /// Optional OAST/collaborator callback base URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oast_callback_url: Option<String>,
    /// Optional OAST correlation identifier used in callback placeholders.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oast_correlation_id: Option<String>,
    /// Optional SQLite database path used to read collaborator evidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oast_database_path: Option<PathBuf>,
    /// Seconds to wait for callback evidence after OAST-aware probes.
    #[serde(default)]
    pub oast_wait_secs: u64,
}

fn default_max_recursion_depth() -> usize {
    2
}

fn default_browser_crawl_enabled() -> bool {
    true
}

fn default_browser_crawl_max_pages() -> usize {
    25
}

fn default_browser_crawl_max_depth() -> usize {
    2
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            rate_limit: 50,
            timeout_secs: 10,
            concurrency: 100,
            user_agent: "Temu/1.4.0".to_string(),
            output_dir: PathBuf::from("./results"),
            rules_dir: PathBuf::from("./rules"),
            dictionaries_dir: PathBuf::from("./dictionaries"),
            max_recursion_depth: default_max_recursion_depth(),
            wordlist_override: None,
            allow_risky_rules: false,
            browser_crawl_enabled: default_browser_crawl_enabled(),
            browser_crawl_max_pages: default_browser_crawl_max_pages(),
            browser_crawl_max_depth: default_browser_crawl_max_depth(),
            browser_crawl_render_js: false,
            browser_crawl_browser_path: None,
            session_profile: None,
            oast_callback_url: None,
            oast_correlation_id: None,
            oast_database_path: None,
            oast_wait_secs: 0,
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
    /// `TEMU_MAX_RECURSION_DEPTH`, `TEMU_ALLOW_RISKY_RULES`,
    /// `TEMU_BROWSER_CRAWL_ENABLED`, `TEMU_BROWSER_CRAWL_MAX_PAGES`,
    /// `TEMU_BROWSER_CRAWL_MAX_DEPTH`, `TEMU_BROWSER_CRAWL_RENDER_JS`,
    /// `TEMU_BROWSER_CRAWL_BROWSER_PATH`, `TEMU_SESSION_PROFILE`,
    /// `TEMU_SESSION_BEARER_TOKEN`, `TEMU_SESSION_COOKIE`,
    /// `TEMU_SESSION_BASE_URL`, `TEMU_SESSION_VALIDATE_URL`,
    /// `TEMU_OAST_CALLBACK_URL`, `TEMU_OAST_CORRELATION_ID`,
    /// `TEMU_OAST_DATABASE_PATH`, and `TEMU_OAST_WAIT_SECS`.
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
        if let Ok(v) = std::env::var("TEMU_BROWSER_CRAWL_ENABLED") {
            self.browser_crawl_enabled = matches!(
                v.to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "y" | "on"
            );
        }
        if let Ok(v) = std::env::var("TEMU_BROWSER_CRAWL_MAX_PAGES")
            && let Ok(n) = v.parse()
        {
            self.browser_crawl_max_pages = n;
        }
        if let Ok(v) = std::env::var("TEMU_BROWSER_CRAWL_MAX_DEPTH")
            && let Ok(n) = v.parse()
        {
            self.browser_crawl_max_depth = n;
        }
        if let Ok(v) = std::env::var("TEMU_BROWSER_CRAWL_RENDER_JS") {
            self.browser_crawl_render_js = matches!(
                v.to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "y" | "on"
            );
        }
        if let Ok(v) = std::env::var("TEMU_BROWSER_CRAWL_BROWSER_PATH") {
            self.browser_crawl_browser_path = Some(PathBuf::from(v));
        }
        if let Ok(v) = std::env::var("TEMU_OAST_CALLBACK_URL") {
            self.oast_callback_url = Some(v);
        }
        if let Ok(v) = std::env::var("TEMU_OAST_CORRELATION_ID") {
            self.oast_correlation_id = Some(v);
        }
        if let Ok(v) = std::env::var("TEMU_OAST_DATABASE_PATH") {
            self.oast_database_path = Some(PathBuf::from(v));
        }
        if let Ok(v) = std::env::var("TEMU_OAST_WAIT_SECS")
            && let Ok(n) = v.parse()
        {
            self.oast_wait_secs = n;
        }
        if let Ok(v) = std::env::var("TEMU_SESSION_PROFILE") {
            match SessionProfile::load(Path::new(&v)) {
                Ok(profile) => self.session_profile = Some(profile),
                Err(e) => tracing::warn!("Ignoring invalid TEMU_SESSION_PROFILE {v:?}: {e}"),
            }
        }
        if let Some(profile) = &mut self.session_profile {
            profile.apply_env_overrides();
        } else if std::env::var("TEMU_SESSION_BEARER_TOKEN").is_ok()
            || std::env::var("TEMU_SESSION_COOKIE").is_ok()
            || std::env::var("TEMU_SESSION_BASE_URL").is_ok()
            || std::env::var("TEMU_SESSION_VALIDATE_URL").is_ok()
        {
            let mut profile = SessionProfile::default();
            profile.apply_env_overrides();
            self.session_profile = Some(profile);
        }
    }

    /// Loads and attaches a session profile from `path`.
    pub fn with_session_profile(mut self, path: &Path) -> Result<Self, TemuError> {
        let mut profile = SessionProfile::load(path)?;
        profile.apply_env_overrides();
        self.session_profile = Some(profile);
        Ok(self)
    }

    /// Selects a named role from the current session profile.
    pub fn select_session_role(&mut self, role: &str) -> Result<(), TemuError> {
        let profile = self
            .session_profile
            .as_ref()
            .ok_or_else(|| TemuError::Config("No session profile loaded".to_string()))?
            .select_role(role)
            .ok_or_else(|| TemuError::Config(format!("Session role not found: {role}")))?;
        self.session_profile = Some(profile);
        Ok(())
    }

    /// Returns authentication headers that should be applied to `url`.
    pub fn session_headers_for_url(&self, url: &str) -> Vec<(String, String)> {
        self.session_profile
            .as_ref()
            .map(|profile| profile.headers_for_url(url))
            .unwrap_or_default()
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
        assert_eq!(config.user_agent, "Temu/1.4.0");
        assert_eq!(config.output_dir, PathBuf::from("./results"));
        assert_eq!(config.rules_dir, PathBuf::from("./rules"));
        assert_eq!(config.dictionaries_dir, PathBuf::from("./dictionaries"));
        assert_eq!(config.max_recursion_depth, 2);
        assert!(!config.allow_risky_rules);
        assert!(config.browser_crawl_enabled);
        assert_eq!(config.browser_crawl_max_pages, 25);
        assert_eq!(config.browser_crawl_max_depth, 2);
        assert!(!config.browser_crawl_render_js);
        assert!(config.browser_crawl_browser_path.is_none());
        assert!(config.session_profile.is_none());
        assert!(config.oast_callback_url.is_none());
        assert!(config.oast_correlation_id.is_none());
        assert!(config.oast_database_path.is_none());
        assert_eq!(config.oast_wait_secs, 0);
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
browser_crawl_enabled = false
browser_crawl_max_pages = 10
browser_crawl_max_depth = 1
browser_crawl_render_js = true
browser_crawl_browser_path = "/usr/bin/chromium"
oast_callback_url = "http://127.0.0.1:8788/cb"
oast_correlation_id = "temu-test"
oast_database_path = "/tmp/oast.sqlite"
oast_wait_secs = 2
[session_profile]
base_url_scope = "https://example.com"
bearer_token = "inline-token"
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
        assert!(!config.browser_crawl_enabled);
        assert_eq!(config.browser_crawl_max_pages, 10);
        assert_eq!(config.browser_crawl_max_depth, 1);
        assert!(config.browser_crawl_render_js);
        assert_eq!(
            config.browser_crawl_browser_path,
            Some(PathBuf::from("/usr/bin/chromium"))
        );
        assert_eq!(
            config.oast_callback_url.as_deref(),
            Some("http://127.0.0.1:8788/cb")
        );
        assert_eq!(config.oast_correlation_id.as_deref(), Some("temu-test"));
        assert_eq!(
            config.oast_database_path,
            Some(PathBuf::from("/tmp/oast.sqlite"))
        );
        assert_eq!(config.oast_wait_secs, 2);
        assert_eq!(
            config
                .session_profile
                .as_ref()
                .and_then(|profile| profile.bearer_token.as_deref()),
            Some("inline-token")
        );
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

    #[test]
    fn test_apply_env_overrides_browser_crawl() {
        let _guard = ENV_MUTEX.lock().unwrap();
        unsafe { std::env::set_var("TEMU_BROWSER_CRAWL_ENABLED", "false") };
        unsafe { std::env::set_var("TEMU_BROWSER_CRAWL_MAX_PAGES", "7") };
        unsafe { std::env::set_var("TEMU_BROWSER_CRAWL_MAX_DEPTH", "3") };
        unsafe { std::env::set_var("TEMU_BROWSER_CRAWL_RENDER_JS", "true") };
        unsafe { std::env::set_var("TEMU_BROWSER_CRAWL_BROWSER_PATH", "/opt/chrome") };
        let mut config = AppConfig::default();
        config.apply_env_overrides();
        unsafe { std::env::remove_var("TEMU_BROWSER_CRAWL_ENABLED") };
        unsafe { std::env::remove_var("TEMU_BROWSER_CRAWL_MAX_PAGES") };
        unsafe { std::env::remove_var("TEMU_BROWSER_CRAWL_MAX_DEPTH") };
        unsafe { std::env::remove_var("TEMU_BROWSER_CRAWL_RENDER_JS") };
        unsafe { std::env::remove_var("TEMU_BROWSER_CRAWL_BROWSER_PATH") };
        assert!(!config.browser_crawl_enabled);
        assert_eq!(config.browser_crawl_max_pages, 7);
        assert_eq!(config.browser_crawl_max_depth, 3);
        assert!(config.browser_crawl_render_js);
        assert_eq!(
            config.browser_crawl_browser_path,
            Some(PathBuf::from("/opt/chrome"))
        );
    }

    #[test]
    fn test_apply_env_overrides_session_profile() {
        let _guard = ENV_MUTEX.lock().unwrap();
        unsafe { std::env::set_var("TEMU_SESSION_BEARER_TOKEN", "env-token") };
        unsafe { std::env::set_var("TEMU_SESSION_BASE_URL", "https://example.com") };
        let mut config = AppConfig::default();
        config.apply_env_overrides();
        unsafe { std::env::remove_var("TEMU_SESSION_BEARER_TOKEN") };
        unsafe { std::env::remove_var("TEMU_SESSION_BASE_URL") };

        let headers = config.session_headers_for_url("https://example.com/admin");
        assert!(
            headers
                .iter()
                .any(|(name, value)| { name == "Authorization" && value == "Bearer env-token" })
        );
        assert!(
            config
                .session_headers_for_url("https://other.example/admin")
                .is_empty()
        );
    }

    #[test]
    fn test_apply_env_overrides_oast() {
        let _guard = ENV_MUTEX.lock().unwrap();
        unsafe {
            std::env::set_var("TEMU_OAST_CALLBACK_URL", "https://cb.example/c");
            std::env::set_var("TEMU_OAST_CORRELATION_ID", "cid-1");
            std::env::set_var("TEMU_OAST_DATABASE_PATH", "/tmp/callbacks.sqlite");
            std::env::set_var("TEMU_OAST_WAIT_SECS", "3");
        }

        let mut config = AppConfig::default();
        config.apply_env_overrides();

        unsafe {
            std::env::remove_var("TEMU_OAST_CALLBACK_URL");
            std::env::remove_var("TEMU_OAST_CORRELATION_ID");
            std::env::remove_var("TEMU_OAST_DATABASE_PATH");
            std::env::remove_var("TEMU_OAST_WAIT_SECS");
        }
        assert_eq!(
            config.oast_callback_url.as_deref(),
            Some("https://cb.example/c")
        );
        assert_eq!(config.oast_correlation_id.as_deref(), Some("cid-1"));
        assert_eq!(
            config.oast_database_path,
            Some(PathBuf::from("/tmp/callbacks.sqlite"))
        );
        assert_eq!(config.oast_wait_secs, 3);
    }
}
