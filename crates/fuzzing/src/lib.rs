// Fuzzing crate — path and parameter fuzzing

pub mod fuzzer;
pub mod types;

pub use fuzzer::fuzz_paths;
pub use types::FuzzResult;

use temu_core::{AppConfig, Asset, AssetType, TemuError};
use tracing::info;

/// Loads the path wordlist and runs path fuzzing against `base_url`.
///
/// Returns discovered paths as `Asset` values with type `AssetType::Path`.
pub async fn run_fuzzing(base_url: &str, config: &AppConfig) -> Result<Vec<Asset>, TemuError> {
    let wordlist_path = config.dictionaries_dir.join("paths-small.txt");

    let raw = std::fs::read_to_string(&wordlist_path).map_err(|e| {
        TemuError::Io(std::io::Error::new(
            e.kind(),
            format!("Failed to read {:?}: {e}", wordlist_path),
        ))
    })?;

    let wordlist: Vec<String> = raw
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(String::from)
        .collect();

    info!("Path fuzzing {} with {} paths", base_url, wordlist.len());

    let results = fuzz_paths(base_url, &wordlist, config).await;

    info!("Fuzzing complete: {} paths found", results.len());

    let assets = results
        .into_iter()
        .map(|r| Asset::new(r.url, AssetType::Path, "fuzzing::path"))
        .collect();

    Ok(assets)
}
