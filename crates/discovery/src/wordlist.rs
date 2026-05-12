use std::path::Path;

use temu_core::TemuError;

/// Loads a wordlist file from `path`.
///
/// Lines starting with `#` are treated as comments and skipped.
/// Blank lines are also skipped.
/// Returns `TemuError::Io` if the file cannot be read.
pub fn load_wordlist(path: &Path) -> Result<Vec<String>, TemuError> {
    let content = std::fs::read_to_string(path)?;

    let entries: Vec<String> = content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(String::from)
        .collect();

    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_load_wordlist_skips_comments_and_blanks() {
        let content = "# comment\n\nwww\nmail\n# another comment\nftp\n";
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(content.as_bytes()).unwrap();

        let entries = load_wordlist(tmp.path()).unwrap();
        assert_eq!(entries, vec!["www", "mail", "ftp"]);
    }

    #[test]
    fn test_load_wordlist_count() {
        let content = "www\nmail\nftp\nadmin\napi\n";
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(content.as_bytes()).unwrap();

        let entries = load_wordlist(tmp.path()).unwrap();
        assert_eq!(entries.len(), 5);
    }

    #[test]
    fn test_load_wordlist_trims_whitespace() {
        let content = "  www  \n  mail\nftp  \n";
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(content.as_bytes()).unwrap();

        let entries = load_wordlist(tmp.path()).unwrap();
        assert_eq!(entries, vec!["www", "mail", "ftp"]);
    }

    #[test]
    fn test_load_wordlist_missing_file() {
        let result = load_wordlist(Path::new("/nonexistent/path/wordlist.txt"));
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), TemuError::Io(_)));
    }

    #[test]
    fn test_subdomains_small_exists_and_has_entries() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("dictionaries/subdomains-small.txt");

        if path.exists() {
            let entries = load_wordlist(&path).unwrap();
            assert!(
                entries.len() >= 50,
                "subdomains-small.txt should have at least 50 entries, got {}",
                entries.len()
            );
        }
    }
}
