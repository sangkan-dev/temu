// Fuzzing crate — path and parameter fuzzing

pub mod fuzzer;
pub mod types;

pub use fuzzer::{fuzz_parameters, fuzz_paths, fuzz_paths_recursive};
pub use types::FuzzResult;

use temu_core::{AppConfig, Asset, AssetType, TemuError};
use tracing::info;

fn load_dictionary(path: &std::path::Path) -> Result<Vec<String>, TemuError> {
    let raw = std::fs::read_to_string(path).map_err(|e| {
        TemuError::Io(std::io::Error::new(
            e.kind(),
            format!("Failed to read {:?}: {e}", path),
        ))
    })?;

    Ok(raw
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(String::from)
        .collect())
}

/// Loads path and parameter wordlists and runs fuzzing against `base_url`.
///
/// Returns discovered paths as `AssetType::Path` and hidden parameters as
/// `AssetType::Parameter`.
pub async fn run_fuzzing(base_url: &str, config: &AppConfig) -> Result<Vec<Asset>, TemuError> {
    let wordlist_path = config.dictionaries_dir.join("paths-small.txt");
    let parameter_wordlist_path = config.dictionaries_dir.join("parameters-small.txt");

    let wordlist = load_dictionary(&wordlist_path)?;
    let parameter_wordlist = load_dictionary(&parameter_wordlist_path)?;

    info!("Path fuzzing {} with {} paths", base_url, wordlist.len());

    let path_results = fuzz_paths_recursive(base_url, &wordlist, config).await;

    info!(
        "Parameter fuzzing {} with {} parameters",
        base_url,
        parameter_wordlist.len()
    );
    let parameter_results = fuzz_parameters(base_url, &parameter_wordlist, config).await;

    info!(
        "Fuzzing complete: {} paths, {} parameters found",
        path_results.len(),
        parameter_results.len()
    );

    let mut assets: Vec<Asset> = path_results
        .into_iter()
        .map(|r| Asset::new(r.url, AssetType::Path, "fuzzing::path"))
        .collect();

    assets.extend(
        parameter_results
            .into_iter()
            .map(|r| Asset::new(r.url, AssetType::Parameter, "fuzzing::parameter")),
    );

    Ok(assets)
}
