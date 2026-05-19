// Reporter crate — JSON, HTML, PDF output generation

pub mod html;
pub mod json;
pub mod types;

pub use html::generate_html;
pub use json::generate_json;
pub use types::{ScanResult, ScanStats};
