use serde::{Deserialize, Serialize};

/// Broad category of a detected technology.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TechCategory {
    WebServer,
    Framework,
    Language,
    CMS,
    CDN,
    WAF,
    OS,
    Database,
    Library,
    Other,
}

/// A single detected technology with confidence score.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TechStack {
    pub name: String,
    pub version: Option<String>,
    /// Confidence score between 0.0 and 1.0.
    pub confidence: f32,
    pub category: TechCategory,
}

impl TechStack {
    pub fn new(
        name: impl Into<String>,
        version: Option<String>,
        confidence: f32,
        category: TechCategory,
    ) -> Self {
        Self {
            name: name.into(),
            version,
            confidence,
            category,
        }
    }
}
