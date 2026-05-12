use std::path::{Path, PathBuf};

use temu_core::TemuError;
use tracing::info;

use crate::types::ScanResult;

/// Serializes `result` to a pretty-printed JSON file in `output_dir`.
///
/// Filename pattern: `{YYYY-MM-DD}_{sanitized_domain}.json`
/// The output directory is created automatically if it does not exist.
/// Returns the path to the written file.
pub fn generate_json(result: &ScanResult, output_dir: &Path) -> Result<PathBuf, TemuError> {
    std::fs::create_dir_all(output_dir).map_err(|e| {
        TemuError::Io(std::io::Error::new(
            e.kind(),
            format!("Failed to create output directory {:?}: {e}", output_dir),
        ))
    })?;

    let date = result.scan_started_at.format("%Y-%m-%d").to_string();
    let sanitized = result
        .target
        .replace("https://", "")
        .replace("http://", "")
        .replace(['/', ':', '.'], "_")
        .trim_matches('_')
        .to_string();
    let filename = format!("{date}_{sanitized}.json");
    let path = output_dir.join(&filename);

    let json = serde_json::to_string_pretty(result).map_err(|e| {
        TemuError::Parse(format!("Failed to serialize ScanResult: {e}"))
    })?;

    std::fs::write(&path, json).map_err(|e| {
        TemuError::Io(std::io::Error::new(
            e.kind(),
            format!("Failed to write {:?}: {e}", path),
        ))
    })?;

    info!("Report written to {:?}", path);

    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ScanResult, ScanStats};
    use chrono::Utc;
    use std::collections::HashMap;

    fn make_result(target: &str) -> ScanResult {
        ScanResult {
            target: target.to_string(),
            assets: vec![],
            tech_stacks: HashMap::new(),
            vulnerabilities: vec![],
            scan_started_at: Utc::now(),
            scan_finished_at: Utc::now(),
            stats: ScanStats {
                subdomains_found: 0,
                paths_found: 0,
                vulns_found: 0,
                duration_secs: 0.0,
            },
        }
    }

    #[test]
    fn test_generate_json_creates_file() {
        let tmp = tempfile::tempdir().unwrap();
        let result = make_result("https://example.com");

        let path = generate_json(&result, tmp.path()).unwrap();

        assert!(path.exists(), "JSON file should exist");
        assert!(path.extension().and_then(|e| e.to_str()) == Some("json"));
    }

    #[test]
    fn test_generate_json_is_valid_json() {
        let tmp = tempfile::tempdir().unwrap();
        let result = make_result("https://staging.company.com");

        let path = generate_json(&result, tmp.path()).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();

        assert_eq!(
            parsed["target"].as_str().unwrap(),
            "https://staging.company.com"
        );
        assert!(parsed["stats"].is_object());
        assert!(parsed["assets"].is_array());
        assert!(parsed["vulnerabilities"].is_array());
    }

    #[test]
    fn test_generate_json_creates_output_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let nested = tmp.path().join("a").join("b").join("results");

        let result = make_result("example.com");
        let path = generate_json(&result, &nested).unwrap();

        assert!(nested.exists(), "Nested output dir should be created");
        assert!(path.exists());
    }

    #[test]
    fn test_filename_sanitization() {
        let tmp = tempfile::tempdir().unwrap();
        let result = make_result("https://target.example.com/path");

        let path = generate_json(&result, tmp.path()).unwrap();
        let name = path.file_name().unwrap().to_str().unwrap();

        assert!(!name.contains("://"), "Filename should not contain ://");
        assert!(!name.contains('/'), "Filename should not contain /");
    }
}
