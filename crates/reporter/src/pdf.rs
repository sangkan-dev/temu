use std::collections::BTreeMap;
use std::fs::File;
use std::io::BufWriter;
use std::path::{Path, PathBuf};

use printpdf::{
    BuiltinFont, Color, IndirectFontRef, Mm, PdfDocument, PdfDocumentReference, PdfLayerReference,
    Rgb,
};
use temu_core::{Asset, Severity, TemuError, Vulnerability};
use tracing::info;

use crate::types::ScanResult;

const PAGE_WIDTH_MM: f32 = 210.0;
const PAGE_HEIGHT_MM: f32 = 297.0;
const MARGIN_LEFT_MM: f32 = 18.0;
const CONTENT_TOP_MM: f32 = 255.0;
const FOOTER_Y_MM: f32 = 14.0;

/// Renders an executive PDF report for `result` into `output_dir`.
///
/// Filename pattern: `{YYYY-MM-DD}_{sanitized_domain}.pdf`.
pub fn generate_pdf(result: &ScanResult, output_dir: &Path) -> Result<PathBuf, TemuError> {
    std::fs::create_dir_all(output_dir).map_err(|e| {
        TemuError::Io(std::io::Error::new(
            e.kind(),
            format!("Failed to create output directory {:?}: {e}", output_dir),
        ))
    })?;

    let date = result.scan_started_at.format("%Y-%m-%d").to_string();
    let path = output_dir.join(format!("{date}_{}.pdf", sanitize_target(&result.target)));

    let (doc, page, layer) = PdfDocument::new(
        "Temu Security Report",
        Mm(PAGE_WIDTH_MM),
        Mm(PAGE_HEIGHT_MM),
        "Cover",
    );
    let regular = doc
        .add_builtin_font(BuiltinFont::Helvetica)
        .map_err(|e| TemuError::Parse(format!("Failed to load PDF font: {e:?}")))?;
    let bold = doc
        .add_builtin_font(BuiltinFont::HelveticaBold)
        .map_err(|e| TemuError::Parse(format!("Failed to load PDF font: {e:?}")))?;

    let mut report = PdfReport {
        doc,
        regular,
        bold,
        page_number: 1,
    };

    let cover = report.doc.get_page(page).get_layer(layer);
    report.render_cover_page(&cover, result);

    let risk = report.add_page("Risk Overview");
    report.render_risk_overview(&risk, result);

    if result.vulnerabilities.is_empty() {
        let layer = report.add_page("Vulnerability Details");
        report.render_empty_vulnerabilities(&layer);
    } else {
        for vulnerability in &result.vulnerabilities {
            let layer = report.add_page("Vulnerability Details");
            report.render_vulnerability(&layer, vulnerability);
        }
    }

    if !result.callback_events.is_empty() {
        let callbacks = report.add_page("OAST Callback Timeline");
        report.render_callback_events(&callbacks, result);
    }

    let assets = report.add_page("Assets and Recommendations");
    report.render_assets_and_recommendations(&assets, result);

    let file = File::create(&path).map_err(|e| {
        TemuError::Io(std::io::Error::new(
            e.kind(),
            format!("Failed to create {:?}: {e}", path),
        ))
    })?;
    report
        .doc
        .save(&mut BufWriter::new(file))
        .map_err(|e| TemuError::Parse(format!("Failed to write PDF report: {e:?}")))?;

    info!("PDF report written to {:?}", path);
    Ok(path)
}

struct PdfReport {
    doc: PdfDocumentReference,
    regular: IndirectFontRef,
    bold: IndirectFontRef,
    page_number: usize,
}

impl PdfReport {
    fn add_page(&mut self, title: &str) -> PdfLayerReference {
        self.page_number += 1;
        let (page, layer) = self.doc.add_page(
            Mm(PAGE_WIDTH_MM),
            Mm(PAGE_HEIGHT_MM),
            sanitize_pdf_text(title),
        );
        self.doc.get_page(page).get_layer(layer)
    }

    fn render_cover_page(&self, layer: &PdfLayerReference, result: &ScanResult) {
        self.header(layer, "Executive Report");
        self.text(layer, "Temu Security Report", 28.0, 28.0, 246.0, true);
        self.colored_text(
            layer,
            "Automated cybersecurity scanner",
            11.0,
            (29.0, 237.0),
            Color::Rgb(Rgb::new(0.20, 0.24, 0.31, None)),
            false,
        );

        self.section_title(layer, "Target", 206.0);
        self.wrapped_text(layer, &result.target, 12.0, (29.0, 196.0), 86, false);

        self.section_title(layer, "Executive Summary", 172.0);
        let risk = risk_rating(&result.vulnerabilities);
        let summary = format!(
            "Overall risk is {risk}. Temu scanned {} assets and identified {} vulnerabilities in {:.1} seconds.",
            result.assets.len(),
            result.vulnerabilities.len(),
            result.stats.duration_secs
        );
        self.wrapped_text(layer, &summary, 11.0, (29.0, 162.0), 88, false);

        self.metric(layer, "Subdomains", result.stats.subdomains_found, 122.0);
        self.metric(layer, "Paths", result.stats.paths_found, 108.0);
        self.metric(layer, "Parameters", result.stats.parameters_found, 94.0);
        self.metric(layer, "Vulnerabilities", result.stats.vulns_found, 80.0);
        self.metric(
            layer,
            "OAST callbacks",
            result.callback_events.len() as u32,
            66.0,
        );

        self.section_title(layer, "Scan Window", 48.0);
        self.text(
            layer,
            &format!("Started: {}", result.scan_started_at.to_rfc3339()),
            10.0,
            29.0,
            38.0,
            false,
        );
        self.text(
            layer,
            &format!("Finished: {}", result.scan_finished_at.to_rfc3339()),
            10.0,
            29.0,
            28.0,
            false,
        );
        self.footer(layer, 1);
    }

    fn render_risk_overview(&self, layer: &PdfLayerReference, result: &ScanResult) {
        self.header(layer, "Risk Overview");
        self.text(
            layer,
            "Risk Overview",
            22.0,
            MARGIN_LEFT_MM,
            CONTENT_TOP_MM,
            true,
        );
        self.text(
            layer,
            &format!("Overall Risk: {}", risk_rating(&result.vulnerabilities)),
            13.0,
            MARGIN_LEFT_MM,
            240.0,
            true,
        );

        let counts = severity_counts(&result.vulnerabilities);
        let rows = [
            Severity::Critical,
            Severity::High,
            Severity::Medium,
            Severity::Low,
            Severity::Info,
        ];
        let mut y = 218.0;
        self.text(layer, "Severity", 11.0, 24.0, y, true);
        self.text(layer, "Findings", 11.0, 82.0, y, true);
        y -= 12.0;
        for severity in rows {
            let count = counts
                .get(&severity.to_string())
                .copied()
                .unwrap_or_default();
            self.colored_text(
                layer,
                &severity.to_string(),
                11.0,
                (24.0, y),
                severity_color(&severity),
                true,
            );
            self.text(layer, &count.to_string(), 11.0, 86.0, y, false);
            y -= 11.0;
        }

        self.section_title(layer, "Scope Statistics", 136.0);
        self.text(
            layer,
            &format!("Assets discovered: {}", result.assets.len()),
            10.5,
            24.0,
            124.0,
            false,
        );
        self.text(
            layer,
            &format!(
                "Technologies identified: {}",
                result.tech_stacks.values().map(Vec::len).sum::<usize>()
            ),
            10.5,
            24.0,
            113.0,
            false,
        );
        self.text(
            layer,
            &format!("Parameters found: {}", result.stats.parameters_found),
            10.5,
            24.0,
            102.0,
            false,
        );

        if !result.target_summaries.is_empty() {
            self.section_title(layer, "Target Summary", 82.0);
            let mut target_y = 70.0;
            for summary in result.target_summaries.iter().take(5) {
                let severity = summary
                    .highest_severity
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or_else(|| "None".to_string());
                let line = format!(
                    "{} | assets: {} | vulns: {} | highest: {}",
                    summary.target, summary.assets_total, summary.vulnerabilities_total, severity
                );
                target_y = self.wrapped_text(layer, &line, 8.5, (24.0, target_y), 110, false);
            }
            self.footer(layer, self.page_number);
            return;
        }

        self.section_title(layer, "Recommended Priority", 76.0);
        for (line, y) in recommendation_lines(result)
            .iter()
            .zip([64.0, 53.0, 42.0, 31.0])
        {
            self.wrapped_text(layer, line, 10.0, (24.0, y), 92, false);
        }
        self.footer(layer, self.page_number);
    }

    fn render_empty_vulnerabilities(&self, layer: &PdfLayerReference) {
        self.header(layer, "Vulnerability Details");
        self.text(
            layer,
            "Vulnerability Details",
            22.0,
            MARGIN_LEFT_MM,
            CONTENT_TOP_MM,
            true,
        );
        self.wrapped_text(
            layer,
            "No vulnerabilities were recorded in this scan result.",
            11.0,
            (MARGIN_LEFT_MM, 236.0),
            90,
            false,
        );
        self.footer(layer, self.page_number);
    }

    fn render_vulnerability(&self, layer: &PdfLayerReference, vulnerability: &Vulnerability) {
        self.header(layer, "Vulnerability Details");
        self.colored_text(
            layer,
            &vulnerability.severity.to_string(),
            12.0,
            (MARGIN_LEFT_MM, CONTENT_TOP_MM),
            severity_color(&vulnerability.severity),
            true,
        );
        self.wrapped_text(
            layer,
            &vulnerability.name,
            18.0,
            (MARGIN_LEFT_MM, 242.0),
            62,
            true,
        );

        let mut y = 216.0;
        for (label, value) in [
            ("Rule ID", vulnerability.id.as_str()),
            ("URL", vulnerability.url.as_str()),
            (
                "Parameter",
                vulnerability.parameter.as_deref().unwrap_or("-"),
            ),
            (
                "Verified",
                if vulnerability.verified { "yes" } else { "no" },
            ),
        ] {
            self.text(layer, label, 10.0, MARGIN_LEFT_MM, y, true);
            y = self.wrapped_text(layer, value, 10.0, (52.0, y), 88, false) - 5.0;
        }

        self.text(
            layer,
            &format!("CVSS: {:.1}", vulnerability.cvss_score),
            10.0,
            MARGIN_LEFT_MM,
            y,
            true,
        );
        y -= 18.0;

        self.section_title(layer, "Evidence", y);
        y -= 10.0;
        y = self.wrapped_text(
            layer,
            &crate::redaction::redact_sensitive_text(&vulnerability.proof),
            9.5,
            (MARGIN_LEFT_MM, y),
            96,
            false,
        );

        y -= 14.0;
        self.section_title(layer, "Remediation", y);
        y -= 10.0;
        let remediation = vulnerability
            .remediation
            .as_deref()
            .unwrap_or("Review and patch the affected component.");
        self.wrapped_text(layer, remediation, 9.5, (MARGIN_LEFT_MM, y), 96, false);
        self.footer(layer, self.page_number);
    }

    fn render_callback_events(&self, layer: &PdfLayerReference, result: &ScanResult) {
        self.header(layer, "OAST Callback Timeline");
        self.text(
            layer,
            "OAST Callback Timeline",
            22.0,
            MARGIN_LEFT_MM,
            CONTENT_TOP_MM,
            true,
        );
        let mut y = 236.0;
        for event in result.callback_events.iter().take(14) {
            let line = format!(
                "{} | {} | {} {} | {} | ua={}",
                event.received_at.to_rfc3339(),
                event.correlation_id,
                event.method,
                event.path,
                event.remote_addr,
                event.user_agent.as_deref().unwrap_or("-")
            );
            y = self.wrapped_text(layer, &line, 8.5, (MARGIN_LEFT_MM, y), 116, false) - 4.0;
        }
        if result.callback_events.len() > 14 {
            self.text(
                layer,
                &format!(
                    "... {} more callback events in JSON/HTML reports",
                    result.callback_events.len() - 14
                ),
                9.0,
                MARGIN_LEFT_MM,
                y,
                false,
            );
        }
        self.footer(layer, self.page_number);
    }

    fn render_assets_and_recommendations(&self, layer: &PdfLayerReference, result: &ScanResult) {
        self.header(layer, "Assets and Recommendations");
        self.text(
            layer,
            "Assets and Recommendations",
            22.0,
            MARGIN_LEFT_MM,
            CONTENT_TOP_MM,
            true,
        );

        self.section_title(layer, "Discovered Assets", 235.0);
        let mut y = 224.0;
        if result.assets.is_empty() {
            self.text(layer, "No assets recorded.", 10.0, MARGIN_LEFT_MM, y, false);
            y -= 12.0;
        } else {
            for asset in result.assets.iter().take(16) {
                y = self.asset_line(layer, asset, y);
            }
            if result.assets.len() > 16 {
                self.text(
                    layer,
                    &format!(
                        "... {} more assets in JSON/HTML reports",
                        result.assets.len() - 16
                    ),
                    9.0,
                    MARGIN_LEFT_MM,
                    y,
                    false,
                );
                y -= 12.0;
            }
        }

        let recommendation_y = y.min(100.0) - 8.0;
        self.section_title(layer, "General Recommendations", recommendation_y);
        let mut next_y = recommendation_y - 12.0;
        for line in recommendation_lines(result) {
            next_y = self.wrapped_text(
                layer,
                &format!("- {line}"),
                9.5,
                (MARGIN_LEFT_MM, next_y),
                96,
                false,
            ) - 4.0;
        }
        self.footer(layer, self.page_number);
    }

    fn asset_line(&self, layer: &PdfLayerReference, asset: &Asset, y: f32) -> f32 {
        self.text(
            layer,
            &asset.asset_type.to_string(),
            9.0,
            MARGIN_LEFT_MM,
            y,
            true,
        );
        self.wrapped_text(layer, &asset.url, 9.0, (48.0, y), 96, false) - 4.0
    }

    fn header(&self, layer: &PdfLayerReference, title: &str) {
        self.colored_text(
            layer,
            "Temu",
            10.0,
            (MARGIN_LEFT_MM, 282.0),
            Color::Rgb(Rgb::new(0.12, 0.17, 0.25, None)),
            true,
        );
        self.text(layer, title, 9.0, 163.0, 282.0, false);
    }

    fn footer(&self, layer: &PdfLayerReference, page_number: usize) {
        self.text(
            layer,
            &format!("Generated by Temu | Page {page_number}"),
            8.0,
            MARGIN_LEFT_MM,
            FOOTER_Y_MM,
            false,
        );
    }

    fn section_title(&self, layer: &PdfLayerReference, text: &str, y: f32) {
        self.colored_text(
            layer,
            text,
            12.0,
            (MARGIN_LEFT_MM, y),
            Color::Rgb(Rgb::new(0.12, 0.17, 0.25, None)),
            true,
        );
    }

    fn metric(&self, layer: &PdfLayerReference, label: &str, value: u32, y: f32) {
        self.text(layer, label, 10.0, 29.0, y, true);
        self.text(layer, &value.to_string(), 10.0, 76.0, y, false);
    }

    fn wrapped_text(
        &self,
        layer: &PdfLayerReference,
        text: &str,
        font_size: f32,
        position: (f32, f32),
        max_chars: usize,
        bold: bool,
    ) -> f32 {
        let (x, y) = position;
        let mut next_y = y;
        for line in wrap_text(&sanitize_pdf_text(text), max_chars) {
            self.text(layer, &line, font_size, x, next_y, bold);
            next_y -= font_size * 0.48;
        }
        next_y
    }

    fn text(
        &self,
        layer: &PdfLayerReference,
        text: &str,
        font_size: f32,
        x: f32,
        y: f32,
        bold: bool,
    ) {
        let font = if bold { &self.bold } else { &self.regular };
        layer.set_fill_color(Color::Rgb(Rgb::new(0.10, 0.10, 0.10, None)));
        layer.use_text(sanitize_pdf_text(text), font_size, Mm(x), Mm(y), font);
    }

    fn colored_text(
        &self,
        layer: &PdfLayerReference,
        text: &str,
        font_size: f32,
        position: (f32, f32),
        color: Color,
        bold: bool,
    ) {
        let (x, y) = position;
        let font = if bold { &self.bold } else { &self.regular };
        layer.set_fill_color(color);
        layer.use_text(sanitize_pdf_text(text), font_size, Mm(x), Mm(y), font);
    }
}

fn sanitize_target(target: &str) -> String {
    target
        .replace("https://", "")
        .replace("http://", "")
        .replace(['/', ':', '.'], "_")
        .trim_matches('_')
        .to_string()
}

fn sanitize_pdf_text(text: &str) -> String {
    text.chars()
        .map(|ch| {
            if ch.is_ascii() && !ch.is_control() {
                ch
            } else if ch.is_whitespace() {
                ' '
            } else {
                '?'
            }
        })
        .collect()
}

fn wrap_text(text: &str, max_chars: usize) -> Vec<String> {
    if text.len() <= max_chars {
        return vec![text.to_string()];
    }

    let mut lines = Vec::new();
    let mut current = String::new();
    for word in text.split_whitespace() {
        let next_len = if current.is_empty() {
            word.len()
        } else {
            current.len() + 1 + word.len()
        };
        if next_len > max_chars && !current.is_empty() {
            lines.push(current);
            current = word.to_string();
        } else if current.is_empty() {
            current = word.to_string();
        } else {
            current.push(' ');
            current.push_str(word);
        }
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}

fn severity_counts(vulnerabilities: &[Vulnerability]) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::from([
        ("Critical".to_string(), 0),
        ("High".to_string(), 0),
        ("Medium".to_string(), 0),
        ("Low".to_string(), 0),
        ("Info".to_string(), 0),
    ]);
    for vulnerability in vulnerabilities {
        *counts
            .entry(vulnerability.severity.to_string())
            .or_insert(0) += 1;
    }
    counts
}

fn risk_rating(vulnerabilities: &[Vulnerability]) -> &'static str {
    if vulnerabilities
        .iter()
        .any(|v| v.severity == Severity::Critical)
    {
        "Critical"
    } else if vulnerabilities.iter().any(|v| v.severity == Severity::High) {
        "High"
    } else if vulnerabilities
        .iter()
        .any(|v| v.severity == Severity::Medium)
    {
        "Medium"
    } else if vulnerabilities.iter().any(|v| v.severity == Severity::Low) {
        "Low"
    } else {
        "Informational"
    }
}

fn severity_color(severity: &Severity) -> Color {
    match severity {
        Severity::Critical => Color::Rgb(Rgb::new(0.70, 0.08, 0.10, None)),
        Severity::High => Color::Rgb(Rgb::new(0.86, 0.32, 0.08, None)),
        Severity::Medium => Color::Rgb(Rgb::new(0.72, 0.48, 0.03, None)),
        Severity::Low => Color::Rgb(Rgb::new(0.12, 0.50, 0.24, None)),
        Severity::Info => Color::Rgb(Rgb::new(0.25, 0.34, 0.45, None)),
    }
}

fn recommendation_lines(result: &ScanResult) -> Vec<String> {
    if result.vulnerabilities.is_empty() {
        return vec![
            "Maintain periodic scans and compare future reports for drift.".to_string(),
            "Keep exposed services, frameworks, and dependencies patched.".to_string(),
            "Review newly discovered assets before they enter production scope.".to_string(),
        ];
    }

    let mut lines = vec![
        "Prioritize verified Critical and High findings before lower severity work.".to_string(),
        "Patch vulnerable components and retest affected URLs after remediation.".to_string(),
        "Use the JSON report as the source of truth for automation and ticket creation."
            .to_string(),
    ];
    if result.vulnerabilities.iter().any(|v| !v.verified) {
        lines.push(
            "Manually validate unverified findings before assigning production fixes.".to_string(),
        );
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use fingerprint::{TechCategory, TechStack};
    use std::collections::HashMap;
    use temu_core::{Asset, AssetType};

    fn make_result() -> ScanResult {
        let mut tech_stacks = HashMap::new();
        tech_stacks.insert(
            "https://example.com".to_string(),
            vec![TechStack::new(
                "nginx",
                Some("1.18.0".to_string()),
                0.95,
                TechCategory::WebServer,
            )],
        );

        let mut vulnerability = Vulnerability::new(
            "SENSITIVE-FILES-ENV",
            "Exposed .env file",
            Severity::High,
            7.5,
            "status=200 body contains DB_PASSWORD",
            "https://example.com/.env",
        );
        vulnerability.parameter = Some("file".to_string());
        vulnerability.verified = true;
        vulnerability.remediation =
            Some("Block access to dotfiles at the web server layer.".to_string());

        ScanResult {
            target: "https://example.com".to_string(),
            assets: vec![Asset::new(
                "https://example.com/.env",
                AssetType::Path,
                "test",
            )],
            tech_stacks,
            vulnerabilities: vec![vulnerability],
            target_summaries: vec![],
            callback_events: vec![],
            scan_started_at: Utc::now(),
            scan_finished_at: Utc::now(),
            stats: crate::types::ScanStats {
                subdomains_found: 0,
                paths_found: 1,
                parameters_found: 1,
                vulns_found: 1,
                duration_secs: 1.2,
            },
        }
    }

    #[test]
    fn test_generate_pdf_creates_valid_file() {
        let tmp = tempfile::tempdir().unwrap();
        let path = generate_pdf(&make_result(), tmp.path()).unwrap();

        assert!(path.exists());
        assert_eq!(path.extension().and_then(|e| e.to_str()), Some("pdf"));

        let content = std::fs::read(path).unwrap();
        assert!(content.starts_with(b"%PDF"));
        assert!(content.len() > 1_000);
    }

    #[test]
    fn test_wrap_text_splits_long_text() {
        let lines = wrap_text("alpha beta gamma delta", 10);

        assert!(lines.len() > 1);
        assert!(lines.iter().all(|line| !line.is_empty()));
    }
}
