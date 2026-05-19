use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};

const DEFAULT_RULES_REPO_URL: &str =
    "https://raw.githubusercontent.com/sangkan-dev/temu-rules/main";
const MANIFEST_NAME: &str = "rules-manifest.json";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RemoteRulesManifest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    #[serde(default)]
    pub vulnerability: Vec<String>,
    #[serde(default)]
    pub network: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RulesUpdateSummary {
    pub repo_url: String,
    pub written_files: Vec<PathBuf>,
}

/// Returns the default raw rules repository URL.
pub fn default_rules_repo_url() -> &'static str {
    DEFAULT_RULES_REPO_URL
}

/// Parses a remote rules manifest.
pub fn parse_manifest(content: &str) -> anyhow::Result<RemoteRulesManifest> {
    serde_json::from_str(content).with_context(|| "Invalid remote rules manifest JSON")
}

/// Builds a remote rule URL from a base URL and manifest path.
pub fn remote_rule_url(base_url: &str, rule_path: &str) -> anyhow::Result<String> {
    let path = rule_path.trim_start_matches('/');
    if path.is_empty() || path.contains("..") {
        bail!("Invalid remote rule path: {rule_path}");
    }
    Ok(format!("{}/{}", base_url.trim_end_matches('/'), path))
}

/// Returns a safe local filename for a remote rule path.
pub fn local_rule_filename(rule_path: &str) -> anyhow::Result<&str> {
    Path::new(rule_path)
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty() && !name.contains(std::path::MAIN_SEPARATOR))
        .with_context(|| format!("Invalid rule file name in manifest path: {rule_path}"))
}

/// Downloads rules listed in `rules-manifest.json` into the local rules directory.
pub async fn update_rules_from_repo(
    repo_url: &str,
    rules_dir: &Path,
) -> anyhow::Result<RulesUpdateSummary> {
    let client = reqwest::Client::builder()
        .user_agent("Temu/1.0.0 rules-updater")
        .build()
        .with_context(|| "Failed to build rules update HTTP client")?;

    let manifest_url = remote_rule_url(repo_url, MANIFEST_NAME)?;
    let manifest_text = client
        .get(&manifest_url)
        .send()
        .await
        .with_context(|| format!("Failed to download {manifest_url}"))?
        .error_for_status()
        .with_context(|| format!("Rules manifest returned an error: {manifest_url}"))?
        .text()
        .await
        .with_context(|| "Failed to read rules manifest body")?;
    let manifest = parse_manifest(&manifest_text)?;

    tokio::fs::create_dir_all(rules_dir)
        .await
        .with_context(|| format!("Failed to create rules directory {rules_dir:?}"))?;

    let mut written_files = Vec::new();
    if let Some(fingerprint_path) = manifest.fingerprint.as_deref() {
        let destination = rules_dir.join("fingerprint_rules.yaml");
        download_rule(&client, repo_url, fingerprint_path, &destination).await?;
        written_files.push(destination);
    }

    for rule_path in manifest.vulnerability.iter().chain(manifest.network.iter()) {
        let destination = rules_dir.join(local_rule_filename(rule_path)?);
        download_rule(&client, repo_url, rule_path, &destination).await?;
        written_files.push(destination);
    }

    Ok(RulesUpdateSummary {
        repo_url: repo_url.to_string(),
        written_files,
    })
}

async fn download_rule(
    client: &reqwest::Client,
    repo_url: &str,
    rule_path: &str,
    destination: &Path,
) -> anyhow::Result<()> {
    let url = remote_rule_url(repo_url, rule_path)?;
    let content = client
        .get(&url)
        .send()
        .await
        .with_context(|| format!("Failed to download {url}"))?
        .error_for_status()
        .with_context(|| format!("Rule file returned an error: {url}"))?
        .bytes()
        .await
        .with_context(|| format!("Failed to read rule file body: {url}"))?;
    tokio::fs::write(destination, content)
        .await
        .with_context(|| format!("Failed to write rule file {destination:?}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_manifest_accepts_general_rule_types() {
        let manifest = parse_manifest(
            r#"{
                "fingerprint": "fingerprint/technologies.yaml",
                "vulnerability": ["vulnerability/sql-injection.yaml"],
                "network": ["network/ssh.yaml", "network/tls.yaml"]
            }"#,
        )
        .expect("manifest must parse");

        assert_eq!(
            manifest.fingerprint,
            Some("fingerprint/technologies.yaml".to_string())
        );
        assert_eq!(manifest.vulnerability.len(), 1);
        assert_eq!(manifest.network.len(), 2);
    }

    #[test]
    fn test_remote_rule_url_rejects_parent_segments() {
        let result = remote_rule_url("https://example.test/rules", "../secret.yaml");
        assert!(result.is_err());
    }

    #[test]
    fn test_local_rule_filename_uses_basename() {
        let filename =
            local_rule_filename("vulnerability/cve/2026.yaml").expect("basename must be extracted");
        assert_eq!(filename, "2026.yaml");
    }
}
