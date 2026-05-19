// CLI crate — entrypoint, argument parsing, scan orchestration

mod args;
use cli::distributed;
use cli::orchestrator;

use std::path::PathBuf;

use anyhow::Context;
use args::{Cli, Command, DiscoveryModeArg, ReportFormat, RulesCommand, ScanCommand, WordlistSize};
use clap::Parser;
use cli::rules_update;
use discovery::{DiscoveryMode, default_top_ports, parse_ports};
use reporter::{ScanResult, generate_html, generate_json, generate_pdf};
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

                print_report_paths(&write_report_set(&result, &output_dir)?);
            }
            ScanCommand::File { list } => {
                let default_config_path = std::path::PathBuf::from("config/default.toml");
                let config = temu_core::AppConfig::load_or_default_with_env(&default_config_path);
                let selected_ports = default_top_ports();
                let result = orchestrator::run_file_scan(
                    &list,
                    &config,
                    DiscoveryMode::Hybrid,
                    &selected_ports,
                )
                .await
                .with_context(|| "File list scan failed")?;
                write_multi_target_reports(&result, &config.output_dir)?;
            }
            ScanCommand::Network { cidr, ports } => {
                let default_config_path = std::path::PathBuf::from("config/default.toml");
                let config = temu_core::AppConfig::load_or_default_with_env(&default_config_path);
                let selected_ports = match ports {
                    Some(ports) => parse_ports(&ports)
                        .map_err(|e| anyhow::anyhow!("Invalid --ports value: {e}"))?,
                    None => default_top_ports(),
                };
                let result = orchestrator::run_network_scan_multi(&cidr, &config, &selected_ports)
                    .await
                    .with_context(|| "Network scan failed")?;
                write_multi_target_reports(&result, &config.output_dir)?;
            }
        },

        Command::Worker { redis, ports, once } => {
            let default_config_path = std::path::PathBuf::from("config/default.toml");
            let config = temu_core::AppConfig::load_or_default_with_env(&default_config_path);
            let selected_ports = match ports {
                Some(ports) => parse_ports(&ports)
                    .map_err(|e| anyhow::anyhow!("Invalid --ports value: {e}"))?,
                None => default_top_ports(),
            };
            distributed::run_worker_with_ports(&redis, &config, once, &selected_ports)
                .await
                .with_context(|| "Distributed worker failed")?;
        }

        Command::Coordinator { redis, list } => {
            let result = distributed::run_coordinator_default(&redis, &list)
                .await
                .with_context(|| "Distributed coordinator failed")?;
            let default_config_path = std::path::PathBuf::from("config/default.toml");
            let config = temu_core::AppConfig::load_or_default_with_env(&default_config_path);
            write_multi_target_reports(&result, &config.output_dir)?;
        }

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

        Command::Rules { mode: rules_cmd } => match rules_cmd {
            RulesCommand::Update { repo_url } => {
                let default_config_path = std::path::PathBuf::from("config/default.toml");
                let config = temu_core::AppConfig::load_or_default_with_env(&default_config_path);
                let repo_url = repo_url
                    .or_else(|| std::env::var("TEMU_RULES_REPO_URL").ok())
                    .unwrap_or_else(|| rules_update::default_rules_repo_url().to_string());
                eprintln!("[*] Updating detection rules from {repo_url}");
                let summary = rules_update::update_rules_from_repo(&repo_url, &config.rules_dir)
                    .await
                    .with_context(|| "Failed to update detection rules")?;
                for path in summary.written_files {
                    println!("{}", path.display());
                }
            }
        },
    }

    Ok(())
}

fn write_multi_target_reports(
    result: &orchestrator::MultiTargetScanResult,
    output_dir: &std::path::Path,
) -> anyhow::Result<()> {
    for target in &result.targets {
        print_report_paths(&write_report_set(target, output_dir)?);
    }
    print_report_paths(&write_report_set(&result.aggregate, output_dir)?);
    Ok(())
}

fn write_report_set(
    result: &ScanResult,
    output_dir: &std::path::Path,
) -> anyhow::Result<Vec<std::path::PathBuf>> {
    let json_path =
        generate_json(result, output_dir).with_context(|| "Failed to write JSON report")?;
    let html_path =
        generate_html(result, output_dir).with_context(|| "Failed to write HTML report")?;
    let pdf_path =
        generate_pdf(result, output_dir).with_context(|| "Failed to write PDF report")?;
    Ok(vec![json_path, html_path, pdf_path])
}

fn print_report_paths(paths: &[std::path::PathBuf]) {
    for path in paths {
        println!("{}", path.display());
    }
}
