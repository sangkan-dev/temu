use thiserror::Error;

/// Top-level error type for the Temu scanner.
///
/// Library crates should define their own fine-grained error types and convert
/// them into `TemuError` at the boundary (e.g. using `From` impls or `map_err`).
/// The `cli` crate may additionally use `anyhow` for convenience.
#[derive(Debug, Error)]
pub enum TemuError {
    /// Configuration file could not be read or parsed.
    #[error("Configuration error: {0}")]
    Config(String),

    /// A network-level error occurred (HTTP, TCP).
    /// Stores the error message as a string so that `core` does not need to
    /// depend on `reqwest` directly; individual crates convert their own
    /// network errors via `TemuError::from_network`.
    #[error("Network error: {0}")]
    Network(String),

    /// DNS resolution failed.
    #[error("DNS error: {0}")]
    Dns(String),

    /// I/O error (file system, sockets, etc.).
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Parsing error (YAML, JSON, regex, etc.).
    #[error("Parse error: {0}")]
    Parse(String),

    /// A detection rule file could not be loaded.
    #[error("Rule load error: {0}")]
    RuleLoad(String),

    /// An operation exceeded its configured timeout.
    #[error("Operation timed out")]
    Timeout,
}

impl TemuError {
    /// Convenience constructor for `TemuError::Network` from any `Display` type.
    pub fn from_network(e: impl std::fmt::Display) -> Self {
        TemuError::Network(e.to_string())
    }

    /// Returns `true` if this error represents a transient failure that may
    /// succeed on retry (network timeout, temporary I/O errors).
    pub fn is_retryable(&self) -> bool {
        matches!(self, TemuError::Timeout | TemuError::Network(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    #[test]
    fn test_io_error_conversion() {
        let io_err = io::Error::new(io::ErrorKind::NotFound, "file not found");
        let temu_err = TemuError::from(io_err);
        assert!(matches!(temu_err, TemuError::Io(_)));
        assert!(temu_err.to_string().contains("file not found"));
    }

    #[test]
    fn test_config_error_display() {
        let err = TemuError::Config("missing field rate_limit".to_string());
        assert_eq!(err.to_string(), "Configuration error: missing field rate_limit");
    }

    #[test]
    fn test_timeout_display() {
        let err = TemuError::Timeout;
        assert_eq!(err.to_string(), "Operation timed out");
    }

    #[test]
    fn test_is_retryable() {
        assert!(TemuError::Timeout.is_retryable());
        assert!(TemuError::Network("connection reset".to_string()).is_retryable());
        assert!(!TemuError::Config("bad config".to_string()).is_retryable());
        assert!(!TemuError::RuleLoad("missing file".to_string()).is_retryable());
    }

    #[test]
    fn test_from_network_helper() {
        let err = TemuError::from_network("connection refused");
        assert!(matches!(err, TemuError::Network(_)));
        assert!(err.to_string().contains("connection refused"));
    }
}
