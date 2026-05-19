// Reporter crate — JSON, HTML, PDF output generation

pub mod html;
pub mod json;
pub mod pdf;
pub mod types;

pub use html::generate_html;
pub use json::generate_json;
pub use pdf::generate_pdf;
pub use types::{ScanResult, ScanStats};
