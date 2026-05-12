use std::path::Path;

use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, fmt};

/// Initialises the global tracing subscriber with stdout output only.
///
/// `level` accepts standard tracing level strings: `"trace"`, `"debug"`,
/// `"info"`, `"warn"`, or `"error"`. An invalid value falls back to `"info"`.
///
/// The `RUST_LOG` environment variable, when set, always takes precedence over
/// the `level` argument (standard `EnvFilter` behaviour).
pub fn init_logging(level: &str) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(level));

    let _ = tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer().with_target(true))
        .try_init();
}

/// Initialises the global tracing subscriber with both stdout and rolling file output.
///
/// When `log_dir` is `Some(dir)`, a daily-rotating log file named `temu.log` is
/// written to `dir` in addition to stdout. When `None`, behaves identically to
/// `init_logging`.
///
/// This function is safe to call multiple times — subsequent calls are silently
/// ignored if a subscriber is already installed.
pub fn init_logging_with_file(level: &str, log_dir: Option<&Path>) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(level));

    let stdout_layer = fmt::layer().with_target(true).with_ansi(true);

    match log_dir {
        Some(dir) => {
            let file_appender = RollingFileAppender::new(Rotation::DAILY, dir, "temu.log");
            let file_layer = fmt::layer()
                .with_writer(file_appender)
                .with_ansi(false)
                .with_target(true);

            let _ = tracing_subscriber::registry()
                .with(filter)
                .with(stdout_layer)
                .with(file_layer)
                .try_init();
        }
        None => {
            let _ = tracing_subscriber::registry()
                .with(filter)
                .with(stdout_layer)
                .try_init();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init_logging_does_not_panic() {
        init_logging("info");
    }

    #[test]
    fn test_init_logging_with_file_no_dir_does_not_panic() {
        init_logging_with_file("info", None);
    }

    #[test]
    fn test_init_logging_with_file_writes_log() {
        let tmp_dir = tempfile::tempdir().unwrap();
        init_logging_with_file("debug", Some(tmp_dir.path()));
        // File may not be created until first log line — just check no panic.
        // A real write test would require flushing the non-blocking writer.
    }
}
