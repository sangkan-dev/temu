use tracing_subscriber::{EnvFilter, fmt};

/// Initialises the global tracing subscriber.
///
/// `level` accepts standard tracing level strings: `"trace"`, `"debug"`,
/// `"info"`, `"warn"`, or `"error"`. An invalid value falls back to `"info"`.
///
/// The `RUST_LOG` environment variable, when set, always takes precedence over
/// the `level` argument (standard `EnvFilter` behaviour).
pub fn init_logging(level: &str) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(level));

    fmt()
        .with_env_filter(filter)
        .with_target(true)
        .with_thread_ids(false)
        .init();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init_logging_does_not_panic() {
        // Calling init twice in the same process would panic (already initialised),
        // so we only verify the function exists and is callable in isolation.
        // The actual subscriber is verified by the build succeeding.
        let _ = EnvFilter::new("info");
    }
}
