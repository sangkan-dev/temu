use serde::{Deserialize, Serialize};

/// Result from fuzzing a single path against a target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzResult {
    pub url: String,
    pub path: String,
    pub status_code: u16,
    pub content_length: u64,
    pub content_type: Option<String>,
    pub redirect_url: Option<String>,
}
