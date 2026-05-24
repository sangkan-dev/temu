use std::collections::HashMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::TemuError;

/// Authentication/session data applied to in-scope HTTP requests.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SessionProfile {
    /// Optional base URL prefix where this session is allowed to be sent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_url_scope: Option<String>,
    /// Extra HTTP headers to apply to in-scope requests.
    #[serde(default)]
    pub headers: HashMap<String, String>,
    /// Cookie name/value pairs to apply to in-scope requests.
    #[serde(default)]
    pub cookies: HashMap<String, String>,
    /// Raw Cookie header for users that already have one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cookie_header: Option<String>,
    /// Bearer token applied as `Authorization: Bearer <token>`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bearer_token: Option<String>,
    /// Optional URL used by the CLI to validate whether the session is alive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validate_url: Option<String>,
    /// Optional command whose stdout returns a refreshed bearer token.
    #[serde(default)]
    pub refresh_command: Vec<String>,
    /// Named role profiles that can override the base profile.
    #[serde(default)]
    pub roles: HashMap<String, SessionProfile>,
}

impl SessionProfile {
    /// Loads a session profile from TOML, JSON, or YAML.
    pub fn load(path: &Path) -> Result<Self, TemuError> {
        let content = std::fs::read_to_string(path).map_err(|e| {
            TemuError::Config(format!("Cannot read session profile {:?}: {e}", path))
        })?;

        let mut profile: Self = match path.extension().and_then(|ext| ext.to_str()) {
            Some("json") => serde_json::from_str(&content).map_err(|e| {
                TemuError::Config(format!("Invalid JSON session profile {:?}: {e}", path))
            })?,
            Some("yaml") | Some("yml") => serde_yaml::from_str(&content).map_err(|e| {
                TemuError::Config(format!("Invalid YAML session profile {:?}: {e}", path))
            })?,
            _ => toml::from_str(&content).map_err(|e| {
                TemuError::Config(format!("Invalid TOML session profile {:?}: {e}", path))
            })?,
        };
        profile.resolve_env_placeholders();
        Ok(profile)
    }

    /// Selects a named role and merges it over the base profile.
    pub fn select_role(&self, role: &str) -> Option<Self> {
        let role_profile = self.roles.get(role)?;
        let mut selected = self.clone();
        selected.roles.clear();
        if role_profile.base_url_scope.is_some() {
            selected.base_url_scope = role_profile.base_url_scope.clone();
        }
        selected.headers.extend(role_profile.headers.clone());
        selected.cookies.extend(role_profile.cookies.clone());
        if role_profile.cookie_header.is_some() {
            selected.cookie_header = role_profile.cookie_header.clone();
        }
        if role_profile.bearer_token.is_some() {
            selected.bearer_token = role_profile.bearer_token.clone();
        }
        if role_profile.validate_url.is_some() {
            selected.validate_url = role_profile.validate_url.clone();
        }
        if !role_profile.refresh_command.is_empty() {
            selected.refresh_command = role_profile.refresh_command.clone();
        }
        selected.resolve_env_placeholders();
        Some(selected)
    }

    /// Returns whether this profile can be applied to `url`.
    pub fn applies_to(&self, url: &str) -> bool {
        self.base_url_scope
            .as_deref()
            .is_none_or(|scope| url.starts_with(scope))
    }

    /// Returns headers that should be applied to an in-scope request.
    pub fn headers_for_url(&self, url: &str) -> Vec<(String, String)> {
        if !self.applies_to(url) {
            return Vec::new();
        }

        let mut headers: Vec<(String, String)> = self
            .headers
            .iter()
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect();
        if let Some(token) = &self.bearer_token {
            headers.push(("Authorization".to_string(), format!("Bearer {token}")));
        }
        if let Some(cookie_header) = self.cookie_header_for_url(url) {
            headers.push(("Cookie".to_string(), cookie_header));
        }
        headers
    }

    /// Builds the Cookie header for `url`.
    pub fn cookie_header_for_url(&self, url: &str) -> Option<String> {
        if !self.applies_to(url) {
            return None;
        }
        if let Some(cookie_header) = &self.cookie_header {
            return Some(cookie_header.clone());
        }
        if self.cookies.is_empty() {
            return None;
        }

        let mut cookies: Vec<_> = self.cookies.iter().collect();
        cookies.sort_by(|a, b| a.0.cmp(b.0));
        Some(
            cookies
                .into_iter()
                .map(|(name, value)| format!("{name}={value}"))
                .collect::<Vec<_>>()
                .join("; "),
        )
    }

    /// Merges environment-provided secrets into this profile.
    pub fn apply_env_overrides(&mut self) {
        if let Ok(v) = std::env::var("TEMU_SESSION_BASE_URL") {
            self.base_url_scope = Some(v);
        }
        if let Ok(v) = std::env::var("TEMU_SESSION_VALIDATE_URL") {
            self.validate_url = Some(v);
        }
        if let Ok(v) = std::env::var("TEMU_SESSION_BEARER_TOKEN") {
            self.bearer_token = Some(v);
        }
        if let Ok(v) = std::env::var("TEMU_SESSION_COOKIE") {
            self.cookie_header = Some(v);
        }
        self.resolve_env_placeholders();
    }

    fn resolve_env_placeholders(&mut self) {
        for value in self.headers.values_mut() {
            *value = resolve_secret_value(value);
        }
        for value in self.cookies.values_mut() {
            *value = resolve_secret_value(value);
        }
        if let Some(value) = &mut self.cookie_header {
            *value = resolve_secret_value(value);
        }
        if let Some(value) = &mut self.bearer_token {
            *value = resolve_secret_value(value);
        }
    }
}

fn resolve_secret_value(value: &str) -> String {
    if let Some(name) = value.strip_prefix("env:") {
        return std::env::var(name).unwrap_or_default();
    }
    if let Some(name) = value.strip_prefix("${").and_then(|v| v.strip_suffix('}')) {
        return std::env::var(name).unwrap_or_default();
    }
    value.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::Mutex;

    static ENV_MUTEX: Mutex<()> = Mutex::new(());

    #[test]
    fn test_session_profile_headers_for_scope() {
        let mut profile = SessionProfile {
            base_url_scope: Some("https://example.com/app".to_string()),
            bearer_token: Some("token".to_string()),
            ..SessionProfile::default()
        };
        profile.cookies.insert("sid".to_string(), "abc".to_string());

        let headers = profile.headers_for_url("https://example.com/app/admin");
        assert!(
            headers
                .iter()
                .any(|(name, value)| { name == "Authorization" && value == "Bearer token" })
        );
        assert!(
            headers
                .iter()
                .any(|(name, value)| { name == "Cookie" && value == "sid=abc" })
        );
        assert!(
            profile
                .headers_for_url("https://example.com/other")
                .is_empty()
        );
    }

    #[test]
    fn test_session_profile_loads_toml_and_resolves_env() {
        let _guard = ENV_MUTEX.lock().unwrap();
        unsafe { std::env::set_var("TEMU_TEST_TOKEN", "secret-token") };
        let mut tmp = tempfile::NamedTempFile::new().expect("temp file");
        tmp.write_all(
            br#"
base_url_scope = "https://example.com"
bearer_token = "env:TEMU_TEST_TOKEN"
[headers]
X-Test = "ok"
"#,
        )
        .unwrap();

        let profile = SessionProfile::load(tmp.path()).expect("profile should load");

        unsafe { std::env::remove_var("TEMU_TEST_TOKEN") };
        assert_eq!(profile.bearer_token.as_deref(), Some("secret-token"));
        assert_eq!(
            profile.headers.get("X-Test").map(String::as_str),
            Some("ok")
        );
    }

    #[test]
    fn test_select_role_merges_role_over_base_profile() {
        let mut base = SessionProfile {
            base_url_scope: Some("https://example.com".to_string()),
            bearer_token: Some("base-token".to_string()),
            ..SessionProfile::default()
        };
        let role = SessionProfile {
            bearer_token: Some("admin-token".to_string()),
            ..SessionProfile::default()
        };
        base.roles.insert("admin".to_string(), role);

        let selected = base.select_role("admin").expect("role exists");

        assert_eq!(
            selected.base_url_scope.as_deref(),
            Some("https://example.com")
        );
        assert_eq!(selected.bearer_token.as_deref(), Some("admin-token"));
        assert!(selected.roles.is_empty());
    }
}
