// CLI crate — entrypoint, argument parsing, scan orchestration

mod args;
use cli::distributed;
use cli::orchestrator;
use cli::realtime::{RealtimeServerConfig, run_realtime_server};

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
                session_profile,
                session_role,
                wordlist_size,
                wordlist,
                ports,
                no_browser_crawl,
                crawl_max_pages,
                crawl_max_depth,
                browser_render_js,
                browser_path,
                allow_risky_rules,
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
                if no_browser_crawl {
                    config.browser_crawl_enabled = false;
                }
                if let Some(max_pages) = crawl_max_pages {
                    config.browser_crawl_max_pages = max_pages;
                }
                if let Some(max_depth) = crawl_max_depth {
                    config.browser_crawl_max_depth = max_depth;
                }
                if browser_render_js {
                    config.browser_crawl_render_js = true;
                }
                if let Some(path) = browser_path {
                    config.browser_crawl_browser_path = Some(path);
                }
                if let Some(path) = session_profile {
                    config = config
                        .with_session_profile(&path)
                        .with_context(|| format!("Failed to load session profile from {path:?}"))?;
                }
                if let Some(role) = session_role {
                    config
                        .select_session_role(&role)
                        .with_context(|| format!("Failed to select session role {role:?}"))?;
                }
                prepare_session_profile(&mut config).await?;
                if allow_risky_rules {
                    eprintln!(
                        "[!] Risky rules enabled: Temu may execute intrusive, destructive, or DoS-prone probes at your own risk."
                    );
                    config.allow_risky_rules = true;
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
            ScanCommand::File {
                list,
                session_profile,
                session_role,
                allow_risky_rules,
            } => {
                let default_config_path = std::path::PathBuf::from("config/default.toml");
                let mut config =
                    temu_core::AppConfig::load_or_default_with_env(&default_config_path);
                if let Some(path) = session_profile {
                    config = config
                        .with_session_profile(&path)
                        .with_context(|| format!("Failed to load session profile from {path:?}"))?;
                }
                if let Some(role) = session_role {
                    config
                        .select_session_role(&role)
                        .with_context(|| format!("Failed to select session role {role:?}"))?;
                }
                prepare_session_profile(&mut config).await?;
                if allow_risky_rules {
                    eprintln!(
                        "[!] Risky rules enabled: Temu may execute intrusive, destructive, or DoS-prone probes at your own risk."
                    );
                    config.allow_risky_rules = true;
                }
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
            ScanCommand::Network {
                cidr,
                ports,
                session_profile,
                session_role,
                allow_risky_rules,
            } => {
                let default_config_path = std::path::PathBuf::from("config/default.toml");
                let mut config =
                    temu_core::AppConfig::load_or_default_with_env(&default_config_path);
                if let Some(path) = session_profile {
                    config = config
                        .with_session_profile(&path)
                        .with_context(|| format!("Failed to load session profile from {path:?}"))?;
                }
                if let Some(role) = session_role {
                    config
                        .select_session_role(&role)
                        .with_context(|| format!("Failed to select session role {role:?}"))?;
                }
                prepare_session_profile(&mut config).await?;
                if allow_risky_rules {
                    eprintln!(
                        "[!] Risky rules enabled: Temu may execute intrusive, destructive, or DoS-prone probes at your own risk."
                    );
                    config.allow_risky_rules = true;
                }
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
                let summary = rules_update::update_rules_from_repo(
                    &repo_url,
                    &config.rules_dir,
                    &config.dictionaries_dir,
                )
                .await
                .with_context(|| "Failed to update detection rules")?;
                for path in summary.written_rule_files {
                    println!("{}", path.display());
                }
                for path in summary.written_dictionary_files {
                    println!("{}", path.display());
                }
            }
            RulesCommand::Validate { rules_dir } => {
                let results = vulnerability::validate_rules_dir(&rules_dir)
                    .with_context(|| format!("Failed to validate rules in {rules_dir:?}"))?;
                let failed = results.iter().filter(|result| !result.valid).count();
                println!("{}", serde_json::to_string_pretty(&results)?);
                if failed > 0 {
                    anyhow::bail!("{failed} rule file(s) failed validation");
                }
                eprintln!("[+] Validated {} rule file(s)", results.len());
            }
            RulesCommand::Simulate {
                target_fixture,
                rules_dir,
                allow_risky_rules,
            } => {
                reqwest::Url::parse(&target_fixture)
                    .with_context(|| format!("Invalid fixture URL: {target_fixture}"))?;
                let results = vulnerability::validate_rules_dir(&rules_dir)
                    .with_context(|| format!("Failed to validate rules in {rules_dir:?}"))?;
                let failed = results.iter().filter(|result| !result.valid).count();
                if failed > 0 {
                    anyhow::bail!("{failed} rule file(s) failed validation; simulation aborted");
                }
                let default_config_path = std::path::PathBuf::from("config/default.toml");
                let mut config =
                    temu_core::AppConfig::load_or_default_with_env(&default_config_path);
                config.rules_dir = rules_dir;
                config.allow_risky_rules = allow_risky_rules;
                let findings = simulate_rules(&target_fixture, &config).await?;
                println!("{}", serde_json::to_string_pretty(&findings)?);
                eprintln!(
                    "[+] Rule simulation completed: {} finding(s)",
                    findings.len()
                );
            }
        },

        Command::Serve { bind, token } => {
            let default_config_path = std::path::PathBuf::from("config/default.toml");
            let config = temu_core::AppConfig::load_or_default_with_env(&default_config_path);
            let token = token.or_else(|| std::env::var("TEMU_SERVER_TOKEN").ok());
            run_realtime_server(RealtimeServerConfig {
                bind,
                token,
                app_config: config,
            })
            .await
            .with_context(|| "Realtime server failed")?;
        }
    }

    Ok(())
}

async fn simulate_rules(
    fixture_url: &str,
    config: &temu_core::AppConfig,
) -> anyhow::Result<Vec<temu_core::Vulnerability>> {
    let rules = vulnerability::load_rules(&config.rules_dir)
        .with_context(|| format!("Failed to load rules from {:?}", config.rules_dir))?;
    let mut findings = Vec::new();
    for rule in rules {
        if !config.allow_risky_rules && vulnerability::requires_risky_rule_ack(&rule) {
            eprintln!("[!] Skipping risky rule '{}' during simulation", rule.id);
            continue;
        }
        if let Some(finding) = vulnerability::execute_rule(&rule, fixture_url, None, config).await {
            findings.push(finding);
        }
    }
    Ok(findings)
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

async fn prepare_session_profile(config: &mut temu_core::AppConfig) -> anyhow::Result<()> {
    refresh_session_from_command(config).await?;
    validate_session_profile(config).await
}

async fn refresh_session_from_command(config: &mut temu_core::AppConfig) -> anyhow::Result<()> {
    let Some(profile) = &mut config.session_profile else {
        return Ok(());
    };
    if profile.refresh_command.is_empty() {
        return Ok(());
    }

    let program = &profile.refresh_command[0];
    let output = tokio::process::Command::new(program)
        .args(&profile.refresh_command[1..])
        .output()
        .await
        .with_context(|| format!("Failed to run session refresh command {program:?}"))?;
    if !output.status.success() {
        anyhow::bail!(
            "Session refresh command failed with status {}",
            output.status
        );
    }

    let token = String::from_utf8(output.stdout)
        .with_context(|| "Session refresh command returned non-UTF8 output")?
        .trim()
        .to_string();
    if token.is_empty() {
        anyhow::bail!("Session refresh command returned an empty token");
    }
    profile.bearer_token = Some(token);
    eprintln!("[+] Session token refreshed from command");
    Ok(())
}

async fn validate_session_profile(config: &temu_core::AppConfig) -> anyhow::Result<()> {
    let Some(profile) = &config.session_profile else {
        return Ok(());
    };
    let Some(validate_url) = profile.validate_url.as_deref() else {
        return Ok(());
    };

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(config.timeout_secs))
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::limited(3))
        .user_agent(&config.user_agent)
        .build()
        .with_context(|| "Failed to build session validation client")?;
    let mut request = client.get(validate_url);
    for (name, value) in config.session_headers_for_url(validate_url) {
        request = request.header(name, value);
    }

    let response = request
        .send()
        .await
        .with_context(|| format!("Session validation request failed: {validate_url}"))?;
    let status = response.status();
    if !status.is_success() {
        anyhow::bail!("Session validation failed for {validate_url}: HTTP {status}");
    }

    eprintln!("[+] Session validation succeeded: {validate_url}");
    Ok(())
}
