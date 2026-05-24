use clap::{Parser, Subcommand, ValueEnum};

#[derive(Debug, Parser)]
#[command(
    name = "temu",
    version = "1.3.0",
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
#[allow(clippy::large_enum_variant)]
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
    /// Update detection rules from a remote rules repository
    Rules {
        #[command(subcommand)]
        mode: RulesCommand,
    },
    /// Run the realtime WebSocket dashboard server
    Serve {
        /// Bind address, defaults to localhost only.
        #[arg(long, default_value = "127.0.0.1:8787")]
        bind: std::net::SocketAddr,

        /// WebSocket auth token. Required for non-localhost binds.
        #[arg(long)]
        token: Option<String>,
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

        /// Path to authenticated session profile (TOML/JSON/YAML).
        #[arg(long)]
        session_profile: Option<std::path::PathBuf>,

        /// Named role from the session profile to use.
        #[arg(long)]
        session_role: Option<String>,

        /// Wordlist size preset for subdomain bruteforce
        #[arg(long, default_value = "small")]
        wordlist_size: WordlistSize,

        /// Custom wordlist file path (overrides --wordlist-size)
        #[arg(long)]
        wordlist: Option<std::path::PathBuf>,

        /// TCP ports to scan, e.g. 80,443,8080 or 1-1024
        #[arg(long)]
        ports: Option<String>,

        /// Disable browser-aware HTML/JavaScript route crawling.
        #[arg(long)]
        no_browser_crawl: bool,

        /// Maximum pages visited by browser-aware crawling.
        #[arg(long)]
        crawl_max_pages: Option<usize>,

        /// Maximum link depth for browser-aware crawling.
        #[arg(long)]
        crawl_max_depth: Option<usize>,

        /// Render pages with a local Chromium/Chrome binary before crawling.
        #[arg(long)]
        browser_render_js: bool,

        /// Path to Chromium/Chrome binary used by --browser-render-js.
        #[arg(long)]
        browser_path: Option<std::path::PathBuf>,

        /// Execute rules marked intrusive/destructive/DoS-prone.
        #[arg(long)]
        allow_risky_rules: bool,
    },
    /// Scan a list of targets from a file
    File {
        /// Path to file containing target URLs (one per line)
        #[arg(long)]
        list: std::path::PathBuf,

        /// Path to authenticated session profile (TOML/JSON/YAML).
        #[arg(long)]
        session_profile: Option<std::path::PathBuf>,

        /// Named role from the session profile to use.
        #[arg(long)]
        session_role: Option<String>,

        /// Execute rules marked intrusive/destructive/DoS-prone.
        #[arg(long)]
        allow_risky_rules: bool,
    },
    /// Scan an entire network CIDR
    Network {
        /// Network CIDR (e.g. 192.168.1.0/24)
        #[arg(long)]
        cidr: String,

        /// TCP ports to scan, e.g. 80,443,8080 or 1-1024
        #[arg(long)]
        ports: Option<String>,

        /// Path to authenticated session profile (TOML/JSON/YAML).
        #[arg(long)]
        session_profile: Option<std::path::PathBuf>,

        /// Named role from the session profile to use.
        #[arg(long)]
        session_role: Option<String>,

        /// Execute rules marked intrusive/destructive/DoS-prone.
        #[arg(long)]
        allow_risky_rules: bool,
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

#[derive(Debug, Subcommand)]
pub enum RulesCommand {
    /// Download fingerprint, vulnerability, network rules, and dictionaries into local directories
    Update {
        /// Raw GitHub-compatible repository base URL.
        #[arg(long)]
        repo_url: Option<String>,
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
            "--session-profile",
            "/tmp/session.toml",
            "--session-role",
            "admin",
            "--no-browser-crawl",
            "--crawl-max-pages",
            "9",
            "--crawl-max-depth",
            "3",
            "--browser-render-js",
            "--browser-path",
            "/usr/bin/chromium",
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
                        session_profile,
                        session_role,
                        ports,
                        no_browser_crawl,
                        crawl_max_pages,
                        crawl_max_depth,
                        browser_render_js,
                        browser_path,
                        ..
                    },
            } => {
                assert_eq!(url, "https://target.com");
                assert!(matches!(mode, DiscoveryModeArg::Passive));
                assert_eq!(rate, Some(30));
                assert_eq!(timeout, Some(15));
                assert_eq!(output, Some(std::path::PathBuf::from("/tmp/results")));
                assert_eq!(
                    session_profile,
                    Some(std::path::PathBuf::from("/tmp/session.toml"))
                );
                assert_eq!(session_role.as_deref(), Some("admin"));
                assert_eq!(ports, Some("80,443,8080".to_string()));
                assert!(no_browser_crawl);
                assert_eq!(crawl_max_pages, Some(9));
                assert_eq!(crawl_max_depth, Some(3));
                assert!(browser_render_js);
                assert_eq!(
                    browser_path,
                    Some(std::path::PathBuf::from("/usr/bin/chromium"))
                );
            }
            _ => panic!("expected Scan::Single"),
        }
    }

    #[test]
    fn test_serve_parses() {
        let cli = Cli::try_parse_from(["temu", "serve", "--bind", "127.0.0.1:9000"])
            .expect("serve must parse");
        match cli.command {
            Command::Serve { bind, token } => {
                assert_eq!(bind.to_string(), "127.0.0.1:9000");
                assert!(token.is_none());
            }
            _ => panic!("expected Serve"),
        }
    }

    #[test]
    fn test_scan_single_allow_risky_rules_parses() {
        let cli = Cli::try_parse_from([
            "temu",
            "scan",
            "single",
            "--url",
            "https://target.com",
            "--allow-risky-rules",
        ])
        .expect("allow risky rules flag must parse");

        match cli.command {
            Command::Scan {
                mode:
                    ScanCommand::Single {
                        allow_risky_rules, ..
                    },
            } => {
                assert!(allow_risky_rules);
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
                mode: ScanCommand::File { list, .. },
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
                mode: ScanCommand::Network { cidr, ports, .. },
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
    fn test_rules_update_parses() {
        let cli = Cli::try_parse_from([
            "temu",
            "rules",
            "update",
            "--repo-url",
            "https://raw.githubusercontent.com/sangkan-dev/temu-rules/main",
        ])
        .expect("rules update must parse");
        match cli.command {
            Command::Rules {
                mode: RulesCommand::Update { repo_url },
            } => {
                assert_eq!(
                    repo_url,
                    Some(
                        "https://raw.githubusercontent.com/sangkan-dev/temu-rules/main".to_string()
                    )
                );
            }
            _ => panic!("expected Rules::Update"),
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
