use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Broad category of a detected technology.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

/// A single Wappalyzer-style fingerprint rule loaded from YAML.
#[derive(Debug, Clone, Deserialize)]
pub struct FingerprintRule {
    /// Technology name (e.g. "nginx", "WordPress").
    pub name: String,
    /// Technology category.
    pub category: TechCategory,
    /// Base confidence score (0.0–1.0) when this rule matches.
    pub confidence: f32,
    /// HTTP response header patterns: header name → regex (capture group 1 = version).
    #[serde(default)]
    pub headers: HashMap<String, String>,
    /// Body substring or regex patterns (ANY match is sufficient).
    #[serde(default)]
    pub body: Vec<String>,
    /// HTML `<meta name="...">` patterns: meta name attr → regex on content attr.
    #[serde(default)]
    pub meta: HashMap<String, String>,
    /// Cookie name patterns: cookie name → regex on value.
    #[serde(default)]
    pub cookies: HashMap<String, String>,
    /// Version template referencing a capture group (e.g. `"\\1"`) from any matched pattern.
    #[serde(default)]
    pub version: Option<String>,
    /// Technology names to automatically add when this rule matches.
    #[serde(default)]
    pub implies: Vec<String>,
}
