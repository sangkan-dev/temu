/// Logs a message at the `INFO` level with the `temu` target.
///
/// Accepts the same arguments as `tracing::info!`.
#[macro_export]
macro_rules! temu_info {
    ($($arg:tt)*) => {
        tracing::info!(target: "temu", $($arg)*)
    };
}

/// Logs a message at the `WARN` level with the `temu` target.
///
/// Accepts the same arguments as `tracing::warn!`.
#[macro_export]
macro_rules! temu_warn {
    ($($arg:tt)*) => {
        tracing::warn!(target: "temu", $($arg)*)
    };
}

/// Logs a message at the `ERROR` level with the `temu` target.
///
/// Accepts the same arguments as `tracing::error!`.
#[macro_export]
macro_rules! temu_error {
    ($($arg:tt)*) => {
        tracing::error!(target: "temu", $($arg)*)
    };
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_macros_compile() {
        temu_info!("info message: {}", 42);
        temu_warn!("warn message");
        temu_error!("error message: key={}", "value");
    }
}
