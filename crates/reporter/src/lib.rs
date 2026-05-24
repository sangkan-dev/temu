// Reporter crate — JSON, HTML, PDF output generation

pub mod enterprise;
pub mod graph;
pub mod html;
pub mod json;
pub mod pdf;
pub mod redaction;
pub mod types;

pub use enterprise::{
    compare_reports, generate_diff_json, generate_markdown, generate_sarif, generate_trend_json,
    load_suppressions, record_scan_history,
};
pub use graph::{generate_graph_cache, generate_graph_json};
pub use html::generate_html;
pub use json::{generate_audit_json, generate_json};
pub use pdf::generate_pdf;
pub use types::{ScanResult, ScanStats};
