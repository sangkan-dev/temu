// Reporter crate — JSON, HTML, PDF output generation

pub mod json;
pub mod types;

pub use json::generate_json;
pub use types::{ScanResult, ScanStats};
