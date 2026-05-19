use clap::{Parser, Subcommand, ValueEnum};

#[derive(Debug, Parser)]
#[command(
    name = "temu",
    version = "0.1.0",
    author = "Temu Security",
    about = "Automated cybersecurity scanner"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,

    /// Enable verbose (debug) logging
    #[arg(long, global = true)]
    pub verbose: bool,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run a vulnerability scan
    Scan {
        #[command(subcommand)]
        mode: ScanCommand,
    },
    /// Run a distributed scan worker
    Worker {
        /// Redis connection URL
        #[arg(long)]
        redis: String,

        /// TCP ports to scan, e.g. 80,443,8080 or 1-1024
        #[arg(long)]
        ports: Option<String>,

        /// Process one task and exit
        #[arg(long)]
        once: bool,
    },
    /// Coordinate a distributed scan
    Coordinator {
        /// Redis connection URL
        #[arg(long)]
        redis: String,

        /// Path to file containing target URLs (one per line)
        #[arg(long)]
        list: std::path::PathBuf,
    },
    /// Generate a report from a previous scan result
    Report {
        #[command(subcommand)]
        mode: ReportCommand,
    },
    /// Update CVE database cache
    Cve {
        #[command(subcommand)]
        mode: CveCommand,
    },
}

#[derive(Debug, Subcommand)]
pub enum ScanCommand {
    /// Scan a single URL
    Single {
        /// Target URL (e.g. https://example.com)
        #[arg(long)]
        url: String,

        /// Discovery mode
        #[arg(long, default_value = "hybrid")]
        mode: DiscoveryModeArg,

        /// Max requests per second
        #[arg(long)]
        rate: Option<u32>,

        /// Request timeout in seconds
        #[arg(long)]
        timeout: Option<u64>,

        /// Output directory for reports
        #[arg(long)]
        output: Option<std::path::PathBuf>,

        /// Path to config file
        #[arg(long)]
        config: Option<std::path::PathBuf>,

        /// Wordlist size preset for subdomain bruteforce
        #[arg(long, default_value = "small")]
        wordlist_size: WordlistSize,

        /// Custom wordlist file path (overrides --wordlist-size)
        #[arg(long)]
        wordlist: Option<std::path::PathBuf>,

        /// TCP ports to scan, e.g. 80,443,8080 or 1-1024
        #[arg(long)]
        ports: Option<String>,
    },
    /// Scan a list of targets from a file
    File {
        /// Path to file containing target URLs (one per line)
        #[arg(long)]
        list: std::path::PathBuf,
    },
    /// Scan an entire network CIDR
    Network {
        /// Network CIDR (e.g. 192.168.1.0/24)
        #[arg(long)]
        cidr: String,

        /// TCP ports to scan, e.g. 80,443,8080 or 1-1024
        #[arg(long)]
        ports: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
pub enum ReportCommand {
    /// Generate a report from a scan result file
    Generate {
        /// Output format
        #[arg(long, default_value = "json")]
        format: ReportFormat,

        /// Path to input scan result JSON
        #[arg(long)]
        input: std::path::PathBuf,
    },
}

#[derive(Debug, Subcommand)]
pub enum CveCommand {
    /// Update CVE database cache
    Update {
        /// CPE name to refresh from NVD. Can be passed multiple times.
        #[arg(long)]
        cpe: Vec<String>,
    },
}

#[derive(Debug, Clone, ValueEnum)]
pub enum DiscoveryModeArg {
    Bruteforce,
    Heuristic,
    Passive,
    Hybrid,
}

#[derive(Debug, Clone, ValueEnum)]
pub enum ReportFormat {
    Json,
    Html,
    Pdf,
}

#[derive(Debug, Clone, ValueEnum, Default)]
pub enum WordlistSize {
    #[default]
    Small,
    Medium,
    Large,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn test_scan_single_minimal() {
        let cli = Cli::try_parse_from(["temu", "scan", "single", "--url", "https://example.com"])
            .expect("minimal scan single must parse");
        match cli.command {
            Command::Scan {
                mode:
                    ScanCommand::Single {
                        url,
                        rate,
                        timeout,
                        output,
                        ..
                    },
            } => {
                assert_eq!(url, "https://example.com");
                assert!(rate.is_none());
                assert!(timeout.is_none());
                assert!(output.is_none());
            }
            _ => panic!("expected Scan::Single"),
        }
    }

    #[test]
    fn test_scan_single_all_options() {
        let cli = Cli::try_parse_from([
            "temu",
            "scan",
            "single",
            "--url",
            "https://target.com",
            "--ports",
            "80,443,8080",
            "--mode",
            "passive",
            "--rate",
            "30",
            "--timeout",
            "15",
            "--output",
            "/tmp/results",
            "--verbose",
        ])
        .expect("full options must parse");

        assert!(cli.verbose);
        match cli.command {
            Command::Scan {
                mode:
                    ScanCommand::Single {
                        url,
                        mode,
                        rate,
                        timeout,
                        output,
                        ports,
                        ..
                    },
            } => {
                assert_eq!(url, "https://target.com");
                assert!(matches!(mode, DiscoveryModeArg::Passive));
                assert_eq!(rate, Some(30));
                assert_eq!(timeout, Some(15));
                assert_eq!(output, Some(std::path::PathBuf::from("/tmp/results")));
                assert_eq!(ports, Some("80,443,8080".to_string()));
            }
            _ => panic!("expected Scan::Single"),
        }
    }

    #[test]
    fn test_default_discovery_mode_is_hybrid() {
        let cli = Cli::try_parse_from(["temu", "scan", "single", "--url", "https://example.com"])
            .unwrap();
        match cli.command {
            Command::Scan {
                mode: ScanCommand::Single { mode, .. },
            } => {
                assert!(matches!(mode, DiscoveryModeArg::Hybrid));
            }
            _ => panic!("expected Scan::Single"),
        }
    }

    #[test]
    fn test_all_discovery_modes_parse() {
        for (arg, expected) in [
            ("bruteforce", "bruteforce"),
            ("heuristic", "heuristic"),
            ("passive", "passive"),
            ("hybrid", "hybrid"),
        ] {
            let cli = Cli::try_parse_from([
                "temu",
                "scan",
                "single",
                "--url",
                "https://x.com",
                "--mode",
                arg,
            ])
            .unwrap_or_else(|e| panic!("mode '{arg}' failed: {e}"));
            match cli.command {
                Command::Scan {
                    mode: ScanCommand::Single { mode, .. },
                } => {
                    assert_eq!(format!("{mode:?}").to_lowercase(), expected);
                }
                _ => panic!("expected Scan::Single"),
            }
        }
    }

    #[test]
    fn test_scan_single_missing_url_fails() {
        let result = Cli::try_parse_from(["temu", "scan", "single"]);
        assert!(result.is_err(), "missing --url must fail");
    }

    #[test]
    fn test_invalid_mode_fails() {
        let result = Cli::try_parse_from([
            "temu",
            "scan",
            "single",
            "--url",
            "https://x.com",
            "--mode",
            "invalid",
        ]);
        assert!(result.is_err(), "invalid mode must fail");
    }

    #[test]
    fn test_scan_file_parses() {
        let cli = Cli::try_parse_from(["temu", "scan", "file", "--list", "/tmp/targets.txt"])
            .expect("scan file must parse");
        match cli.command {
            Command::Scan {
                mode: ScanCommand::File { list },
            } => {
                assert_eq!(list, std::path::PathBuf::from("/tmp/targets.txt"));
            }
            _ => panic!("expected Scan::File"),
        }
    }

    #[test]
    fn test_scan_network_parses() {
        let cli = Cli::try_parse_from([
            "temu",
            "scan",
            "network",
            "--cidr",
            "10.0.0.0/24",
            "--ports",
            "22,80-81",
        ])
        .expect("scan network must parse");
        match cli.command {
            Command::Scan {
                mode: ScanCommand::Network { cidr, ports },
            } => {
                assert_eq!(cidr, "10.0.0.0/24");
                assert_eq!(ports, Some("22,80-81".to_string()));
            }
            _ => panic!("expected Scan::Network"),
        }
    }

    #[test]
    fn test_report_generate_parses() {
        let cli =
            Cli::try_parse_from(["temu", "report", "generate", "--input", "/tmp/result.json"])
                .expect("report generate must parse");
        match cli.command {
            Command::Report {
                mode: ReportCommand::Generate { format, input },
            } => {
                assert!(matches!(format, ReportFormat::Json));
                assert_eq!(input, std::path::PathBuf::from("/tmp/result.json"));
            }
            _ => panic!("expected Report::Generate"),
        }
    }

    #[test]
    fn test_report_generate_html_parses() {
        let cli = Cli::try_parse_from([
            "temu",
            "report",
            "generate",
            "--format",
            "html",
            "--input",
            "/tmp/result.json",
        ])
        .expect("report generate html must parse");
        match cli.command {
            Command::Report {
                mode: ReportCommand::Generate { format, input },
            } => {
                assert!(matches!(format, ReportFormat::Html));
                assert_eq!(input, std::path::PathBuf::from("/tmp/result.json"));
            }
            _ => panic!("expected Report::Generate"),
        }
    }

    #[test]
    fn test_report_generate_pdf_parses() {
        let cli = Cli::try_parse_from([
            "temu",
            "report",
            "generate",
            "--format",
            "pdf",
            "--input",
            "/tmp/result.json",
        ])
        .expect("report generate pdf must parse");
        match cli.command {
            Command::Report {
                mode: ReportCommand::Generate { format, input },
            } => {
                assert!(matches!(format, ReportFormat::Pdf));
                assert_eq!(input, std::path::PathBuf::from("/tmp/result.json"));
            }
            _ => panic!("expected Report::Generate"),
        }
    }

    #[test]
    fn test_cve_update_parses() {
        let cli = Cli::try_parse_from(["temu", "cve", "update"]).expect("cve update must parse");
        assert!(matches!(
            cli.command,
            Command::Cve {
                mode: CveCommand::Update { .. }
            }
        ));
    }

    #[test]
    fn test_cve_update_with_cpe_parses() {
        let cli = Cli::try_parse_from([
            "temu",
            "cve",
            "update",
            "--cpe",
            "cpe:2.3:a:php:php:8.1:*:*:*:*:*:*:*",
        ])
        .expect("cve update --cpe must parse");
        match cli.command {
            Command::Cve {
                mode: CveCommand::Update { cpe },
            } => {
                assert_eq!(cpe, vec!["cpe:2.3:a:php:php:8.1:*:*:*:*:*:*:*"]);
            }
            _ => panic!("expected Cve::Update"),
        }
    }

    #[test]
    fn test_verbose_is_global_flag() {
        let cli = Cli::try_parse_from([
            "temu",
            "--verbose",
            "scan",
            "single",
            "--url",
            "https://x.com",
        ])
        .expect("--verbose before subcommand must work");
        assert!(cli.verbose);
    }

    #[test]
    fn test_wordlist_size_flag() {
        let cli = Cli::try_parse_from([
            "temu",
            "scan",
            "single",
            "--url",
            "https://example.com",
            "--wordlist-size",
            "medium",
        ])
        .expect("--wordlist-size medium must parse");
        match cli.command {
            Command::Scan {
                mode:
                    ScanCommand::Single {
                        wordlist_size,
                        wordlist,
                        ..
                    },
            } => {
                assert!(matches!(wordlist_size, WordlistSize::Medium));
                assert!(wordlist.is_none());
            }
            _ => panic!("expected Scan::Single"),
        }
    }

    #[test]
    fn test_custom_wordlist_flag() {
        let cli = Cli::try_parse_from([
            "temu",
            "scan",
            "single",
            "--url",
            "https://example.com",
            "--wordlist",
            "/tmp/custom-words.txt",
        ])
        .expect("--wordlist custom path must parse");
        match cli.command {
            Command::Scan {
                mode:
                    ScanCommand::Single {
                        wordlist,
                        wordlist_size,
                        ..
                    },
            } => {
                assert_eq!(
                    wordlist,
                    Some(std::path::PathBuf::from("/tmp/custom-words.txt"))
                );
                assert!(matches!(wordlist_size, WordlistSize::Small)); // default unchanged
            }
            _ => panic!("expected Scan::Single"),
        }
    }

    #[test]
    fn test_worker_parses() {
        let cli = Cli::try_parse_from([
            "temu",
            "worker",
            "--redis",
            "redis://localhost:6379",
            "--ports",
            "80",
            "--once",
        ])
        .expect("worker must parse");
        match cli.command {
            Command::Worker { redis, ports, once } => {
                assert_eq!(redis, "redis://localhost:6379");
                assert_eq!(ports, Some("80".to_string()));
                assert!(once);
            }
            _ => panic!("expected Worker"),
        }
    }

    #[test]
    fn test_coordinator_parses() {
        let cli = Cli::try_parse_from([
            "temu",
            "coordinator",
            "--redis",
            "redis://localhost:6379",
            "--list",
            "targets.txt",
        ])
        .expect("coordinator must parse");
        match cli.command {
            Command::Coordinator { redis, list } => {
                assert_eq!(redis, "redis://localhost:6379");
                assert_eq!(list, std::path::PathBuf::from("targets.txt"));
            }
            _ => panic!("expected Coordinator"),
        }
    }
}
