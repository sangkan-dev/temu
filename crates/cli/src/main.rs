// CLI crate — entrypoint, argument parsing, scan orchestration

mod args;
use cli::orchestrator;

use std::path::PathBuf;

use anyhow::Context;
use args::{Cli, Command, DiscoveryModeArg, ReportFormat, ScanCommand, WordlistSize};
use clap::Parser;
use discovery::{DiscoveryMode, default_top_ports, parse_ports};
use reporter::{generate_html, generate_json, generate_pdf};
use temu_core::init_logging;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let log_level = if cli.verbose { "debug" } else { "info" };
    init_logging(log_level);

    match cli.command {
        Command::Scan { mode: scan_cmd } => match scan_cmd {
            ScanCommand::Single {
                url,
                mode,
                rate,
                timeout,
                output,
                config: config_path,
                wordlist_size,
                wordlist,
                ports,
            } => {
                // Validate URL early
                reqwest::Url::parse(&url).with_context(|| format!("Invalid URL: {url}"))?;

                // Load config (from file if given, else default.toml, else hardcoded defaults)
                let default_config_path = std::path::PathBuf::from("config/default.toml");
                let mut config = if let Some(path) = config_path {
                    temu_core::AppConfig::load(&path)
                        .with_context(|| format!("Failed to load config from {path:?}"))?
                } else {
                    temu_core::AppConfig::load_or_default_with_env(&default_config_path)
                };

                // CLI overrides
                if let Some(r) = rate {
                    config.rate_limit = r;
                }
                if let Some(t) = timeout {
                    config.timeout_secs = t;
                }
                let output_dir = output.unwrap_or_else(|| config.output_dir.clone());

                // Wordlist override: explicit path wins, otherwise resolve from size preset
                config.wordlist_override = if let Some(custom) = wordlist {
                    Some(custom)
                } else {
                    let filename = match wordlist_size {
                        WordlistSize::Small => "subdomains-small.txt",
                        WordlistSize::Medium => "subdomains-medium.txt",
                        WordlistSize::Large => "subdomains-large.txt",
                    };
                    let preset = config.dictionaries_dir.join(filename);
                    if preset.exists() { Some(preset) } else { None }
                };

                let discovery_mode = match mode {
                    DiscoveryModeArg::Bruteforce => DiscoveryMode::ActiveBruteforce,
                    DiscoveryModeArg::Heuristic => DiscoveryMode::SmartHeuristic,
                    DiscoveryModeArg::Passive => DiscoveryMode::PassiveOnly,
                    DiscoveryModeArg::Hybrid => DiscoveryMode::Hybrid,
                };
                let selected_ports = match ports {
                    Some(ports) => parse_ports(&ports)
                        .map_err(|e| anyhow::anyhow!("Invalid --ports value: {e}"))?,
                    None => default_top_ports(),
                };

                let result = tokio::select! {
                    res = orchestrator::run_scan_with_ports(&url, &config, discovery_mode, &selected_ports) => {
                        res?
                    }
                    _ = tokio::signal::ctrl_c() => {
                        eprintln!("\n[!] Interrupted — scan aborted by user (Ctrl+C)");
                        return Ok(());
                    }
                };

                let report_path = generate_json(&result, &output_dir)
                    .with_context(|| "Failed to write JSON report")?;
                let html_path = generate_html(&result, &output_dir)
                    .with_context(|| "Failed to write HTML report")?;
                let pdf_path = generate_pdf(&result, &output_dir)
                    .with_context(|| "Failed to write PDF report")?;

                println!("{}", report_path.display());
                println!("{}", html_path.display());
                println!("{}", pdf_path.display());
            }
            ScanCommand::File { list } => {
                eprintln!("[!] scan file --list {list:?} — not yet implemented");
            }
            ScanCommand::Network { cidr, ports } => {
                let default_config_path = std::path::PathBuf::from("config/default.toml");
                let config = temu_core::AppConfig::load_or_default_with_env(&default_config_path);
                let selected_ports = match ports {
                    Some(ports) => parse_ports(&ports)
                        .map_err(|e| anyhow::anyhow!("Invalid --ports value: {e}"))?,
                    None => default_top_ports(),
                };
                let result = orchestrator::run_network_scan(&cidr, &config, &selected_ports)
                    .await
                    .with_context(|| "Network scan failed")?;
                let json_path = generate_json(&result, &config.output_dir)
                    .with_context(|| "Failed to write JSON report")?;
                let html_path = generate_html(&result, &config.output_dir)
                    .with_context(|| "Failed to write HTML report")?;
                let pdf_path = generate_pdf(&result, &config.output_dir)
                    .with_context(|| "Failed to write PDF report")?;
                println!("{}", json_path.display());
                println!("{}", html_path.display());
                println!("{}", pdf_path.display());
            }
        },

        Command::Report { mode: report_cmd } => {
            use args::ReportCommand;
            match report_cmd {
                ReportCommand::Generate { format, input } => {
                    let content = std::fs::read_to_string(&input)
                        .with_context(|| format!("Cannot read {input:?}"))?;
                    let result: reporter::ScanResult = serde_json::from_str(&content)
                        .with_context(|| "Failed to parse input as ScanResult JSON")?;
                    let dir = input.parent().unwrap_or(&PathBuf::from(".")).to_path_buf();
                    let path = match format {
                        ReportFormat::Json => generate_json(&result, &dir)
                            .with_context(|| "Failed to write JSON report")?,
                        ReportFormat::Html => generate_html(&result, &dir)
                            .with_context(|| "Failed to write HTML report")?,
                        ReportFormat::Pdf => generate_pdf(&result, &dir)
                            .with_context(|| "Failed to write PDF report")?,
                    };
                    println!("{}", path.display());
                }
            }
        }

        Command::Cve { mode: cve_cmd } => {
            use args::CveCommand;
            match cve_cmd {
                CveCommand::Update { cpe } => {
                    let default_config_path = std::path::PathBuf::from("config/default.toml");
                    let config =
                        temu_core::AppConfig::load_or_default_with_env(&default_config_path);
                    eprintln!("[*] Updating CVE database...");
                    let count = cve_client::update_cve_cache_for_cpes(&config, &cpe)
                        .await
                        .with_context(|| "Failed to update CVE cache")?;
                    println!("CVE database updated: {count} entries cached");
                }
            }
        }
    }

    Ok(())
}
