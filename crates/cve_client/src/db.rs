use std::path::Path;

use chrono::{DateTime, Utc};
use rusqlite::{Connection, params};
use temu_core::{Severity, TemuError};

use crate::types::{CveEntry, Exploitability};

/// Opens or creates a CVE SQLite database and ensures the schema exists.
pub fn init_database(path: &Path) -> Result<Connection, TemuError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let conn = Connection::open(path).map_err(|e| TemuError::Parse(e.to_string()))?;
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS cve_entries (
            cve_id TEXT PRIMARY KEY,
            description TEXT NOT NULL,
            severity TEXT NOT NULL,
            cvss_score REAL NOT NULL,
            cpe_match TEXT NOT NULL,
            published_date TEXT,
            last_modified TEXT,
            exploitability TEXT NOT NULL,
            epss_score REAL,
            source TEXT NOT NULL,
            cached_at TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_cpe ON cve_entries(cpe_match);
        CREATE INDEX IF NOT EXISTS idx_severity ON cve_entries(severity);
        "#,
    )
    .map_err(|e| TemuError::Parse(e.to_string()))?;
    if !has_column(&conn, "cve_entries", "epss_score")? {
        conn.execute("ALTER TABLE cve_entries ADD COLUMN epss_score REAL", [])
            .map_err(|e| TemuError::Parse(e.to_string()))?;
    }

    Ok(conn)
}

/// Inserts or updates CVE entries in the cache.
pub fn cache_cve_entries(conn: &Connection, entries: &[CveEntry]) -> Result<(), TemuError> {
    for entry in entries {
        let cpe_json =
            serde_json::to_string(&entry.cpe_match).map_err(|e| TemuError::Parse(e.to_string()))?;
        conn.execute(
            r#"
            INSERT INTO cve_entries (
                cve_id, description, severity, cvss_score, cpe_match,
                published_date, last_modified, exploitability, epss_score, source, cached_at
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
            ON CONFLICT(cve_id) DO UPDATE SET
                description = excluded.description,
                severity = excluded.severity,
                cvss_score = excluded.cvss_score,
                cpe_match = excluded.cpe_match,
                published_date = excluded.published_date,
                last_modified = excluded.last_modified,
                exploitability = CASE
                    WHEN cve_entries.exploitability = 'known_exploited' THEN cve_entries.exploitability
                    ELSE excluded.exploitability
                END,
                epss_score = excluded.epss_score,
                source = CASE
                    WHEN cve_entries.exploitability = 'known_exploited'
                         AND excluded.source NOT LIKE '%cisa_kev%'
                    THEN excluded.source || ',cisa_kev'
                    ELSE excluded.source
                END,
                cached_at = excluded.cached_at
            "#,
            params![
                entry.cve_id,
                entry.description,
                entry.severity.to_string(),
                entry.cvss_score,
                cpe_json,
                entry.published_date,
                entry.last_modified,
                entry.exploitability.as_str(),
                entry.epss_score,
                entry.source,
                entry.cached_at.to_rfc3339(),
            ],
        )
        .map_err(|e| TemuError::Parse(e.to_string()))?;
    }

    Ok(())
}

/// Seeds CISA KEV metadata without overwriting CPE-backed NVD records.
pub fn cache_kev_entries(conn: &Connection, entries: &[CveEntry]) -> Result<(), TemuError> {
    for entry in entries {
        let cpe_json =
            serde_json::to_string(&entry.cpe_match).map_err(|e| TemuError::Parse(e.to_string()))?;
        conn.execute(
            r#"
            INSERT OR IGNORE INTO cve_entries (
                cve_id, description, severity, cvss_score, cpe_match,
                published_date, last_modified, exploitability, epss_score, source, cached_at
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
            "#,
            params![
                entry.cve_id,
                entry.description,
                entry.severity.to_string(),
                entry.cvss_score,
                cpe_json,
                entry.published_date,
                entry.last_modified,
                entry.exploitability.as_str(),
                entry.epss_score,
                entry.source,
                entry.cached_at.to_rfc3339(),
            ],
        )
        .map_err(|e| TemuError::Parse(e.to_string()))?;
    }
    Ok(())
}

/// Queries cached CVEs whose CPE match list contains `cpe`.
pub fn query_cves_by_cpe(conn: &Connection, cpe: &str) -> Result<Vec<CveEntry>, TemuError> {
    let mut stmt = conn
        .prepare(
            r#"
            SELECT cve_id, description, severity, cvss_score, cpe_match,
                   published_date, last_modified, exploitability, epss_score, source, cached_at
            FROM cve_entries
            WHERE cpe_match LIKE ?1
            "#,
        )
        .map_err(|e| TemuError::Parse(e.to_string()))?;

    let rows = stmt
        .query_map([format!("%{cpe}%")], row_to_cve)
        .map_err(|e| TemuError::Parse(e.to_string()))?;

    let mut entries = Vec::new();
    for row in rows {
        entries.push(row.map_err(|e| TemuError::Parse(e.to_string()))?);
    }

    Ok(entries)
}

/// Marks cached CVEs that appear in the CISA KEV catalog as known exploited.
pub fn mark_known_exploited(conn: &Connection, cve_ids: &[String]) -> Result<usize, TemuError> {
    let mut updated = 0usize;
    for cve_id in cve_ids {
        updated += conn
            .execute(
                r#"
                UPDATE cve_entries
                SET exploitability = ?1,
                    severity = CASE severity
                        WHEN 'Info' THEN 'Low'
                        WHEN 'Low' THEN 'Medium'
                        WHEN 'Medium' THEN 'High'
                        WHEN 'High' THEN 'Critical'
                        ELSE severity
                    END,
                    source = CASE
                        WHEN source = 'nvd' THEN 'nvd,cisa_kev'
                        ELSE source
                    END
                WHERE cve_id = ?2
                "#,
                params![Exploitability::KnownExploited.as_str(), cve_id],
            )
            .map_err(|e| TemuError::Parse(e.to_string()))?;
    }

    Ok(updated)
}

fn row_to_cve(row: &rusqlite::Row<'_>) -> rusqlite::Result<CveEntry> {
    let severity: String = row.get(2)?;
    let cpe_json: String = row.get(4)?;
    let exploitability: String = row.get(7)?;
    let cached_at: String = row.get(10)?;

    Ok(CveEntry {
        cve_id: row.get(0)?,
        description: row.get(1)?,
        severity: parse_severity(&severity),
        cvss_score: row.get::<_, f64>(3)? as f32,
        cpe_match: serde_json::from_str(&cpe_json).unwrap_or_default(),
        published_date: row.get(5)?,
        last_modified: row.get(6)?,
        exploitability: Exploitability::from_str(&exploitability),
        epss_score: row.get(8)?,
        source: row.get(9)?,
        cached_at: DateTime::parse_from_rfc3339(&cached_at)
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now()),
    })
}

fn has_column(conn: &Connection, table: &str, column: &str) -> Result<bool, TemuError> {
    let mut stmt = conn
        .prepare(&format!("PRAGMA table_info({table})"))
        .map_err(|e| TemuError::Parse(e.to_string()))?;
    let names = stmt
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(|e| TemuError::Parse(e.to_string()))?;
    for name in names {
        if name.map_err(|e| TemuError::Parse(e.to_string()))? == column {
            return Ok(true);
        }
    }
    Ok(false)
}

fn parse_severity(value: &str) -> Severity {
    match value {
        "Critical" => Severity::Critical,
        "High" => Severity::High,
        "Medium" => Severity::Medium,
        "Low" => Severity::Low,
        _ => Severity::Info,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_insert_query_database() {
        let tmp = tempfile::tempdir().unwrap();
        let db_path = tmp.path().join("cve.sqlite");
        let conn = init_database(&db_path).unwrap();
        let cpe = "cpe:2.3:a:php:php:8.1:*:*:*:*:*:*:*";
        let entry = CveEntry {
            cve_id: "CVE-2024-1234".to_string(),
            description: "Example PHP vulnerability".to_string(),
            severity: Severity::High,
            cvss_score: 8.1,
            cpe_match: vec![cpe.to_string()],
            published_date: Some("2024-01-01T00:00:00.000".to_string()),
            last_modified: None,
            exploitability: Exploitability::Theoretical,
            epss_score: Some(0.31),
            source: "nvd".to_string(),
            cached_at: Utc::now(),
        };

        cache_cve_entries(&conn, &[entry]).unwrap();
        let results = query_cves_by_cpe(&conn, cpe).unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].cve_id, "CVE-2024-1234");
        assert_eq!(results[0].severity, Severity::High);
        assert_eq!(results[0].epss_score, Some(0.31));
    }

    #[test]
    fn test_mark_known_exploited_updates_existing_entry() {
        let tmp = tempfile::tempdir().unwrap();
        let conn = init_database(&tmp.path().join("cve.sqlite")).unwrap();
        let cpe = "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*";
        cache_cve_entries(
            &conn,
            &[CveEntry {
                cve_id: "CVE-2024-5678".to_string(),
                description: "Example nginx vulnerability".to_string(),
                severity: Severity::High,
                cvss_score: 8.1,
                cpe_match: vec![cpe.to_string()],
                published_date: None,
                last_modified: None,
                exploitability: Exploitability::Theoretical,
                epss_score: None,
                source: "nvd".to_string(),
                cached_at: Utc::now(),
            }],
        )
        .unwrap();

        let updated = mark_known_exploited(&conn, &["CVE-2024-5678".to_string()]).unwrap();
        let entries = query_cves_by_cpe(&conn, cpe).unwrap();

        assert_eq!(updated, 1);
        assert_eq!(entries[0].exploitability, Exploitability::KnownExploited);
        assert_eq!(entries[0].severity, Severity::Critical);
        assert_eq!(entries[0].source, "nvd,cisa_kev");
    }

    #[test]
    fn test_nvd_refresh_preserves_known_exploited_classification() {
        let tmp = tempfile::tempdir().unwrap();
        let conn = init_database(&tmp.path().join("cve.sqlite")).unwrap();
        let kev = CveEntry {
            cve_id: "CVE-2024-7777".to_string(),
            description: "KEV seed".to_string(),
            severity: Severity::High,
            cvss_score: 8.0,
            cpe_match: Vec::new(),
            published_date: None,
            last_modified: None,
            exploitability: Exploitability::KnownExploited,
            epss_score: None,
            source: "cisa_kev".to_string(),
            cached_at: Utc::now(),
        };
        cache_kev_entries(&conn, &[kev]).unwrap();
        cache_cve_entries(
            &conn,
            &[CveEntry {
                cve_id: "CVE-2024-7777".to_string(),
                description: "NVD details".to_string(),
                severity: Severity::Critical,
                cvss_score: 9.8,
                cpe_match: vec!["cpe:2.3:a:php:php:8.1:*:*:*:*:*:*:*".to_string()],
                published_date: None,
                last_modified: None,
                exploitability: Exploitability::Theoretical,
                epss_score: Some(0.9),
                source: "nvd".to_string(),
                cached_at: Utc::now(),
            }],
        )
        .unwrap();

        let entries = query_cves_by_cpe(&conn, "cpe:2.3:a:php:php:8.1:*:*:*:*:*:*:*").unwrap();
        assert_eq!(entries[0].exploitability, Exploitability::KnownExploited);
        assert_eq!(entries[0].source, "nvd,cisa_kev");
    }
}
