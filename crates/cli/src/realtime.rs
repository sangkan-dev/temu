use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::Context;
use discovery::{DiscoveryMode, default_top_ports, parse_ports};
use futures_util::{SinkExt, StreamExt};
use reporter::{generate_html, generate_json, generate_pdf};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use temu_core::{AppConfig, Severity};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tokio_tungstenite::tungstenite::http::StatusCode;
use tokio_tungstenite::tungstenite::protocol::Message;
use tracing::{info, warn};

use crate::orchestrator;

const EVENT_LOG_CAPACITY: usize = 512;
const DASHBOARD_HTML: &str = include_str!("realtime_dashboard.html");

/// Runtime options for the WebSocket dashboard server.
#[derive(Debug, Clone)]
pub struct RealtimeServerConfig {
    pub bind: SocketAddr,
    pub token: Option<String>,
    pub app_config: AppConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RealtimeEventKind {
    Queued,
    Progress,
    Finding,
    Log,
    Error,
    Artifact,
    WorkerStatus,
    Completed,
    Paused,
    Resumed,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealtimeEvent {
    pub id: u64,
    pub scan_id: Option<u64>,
    pub kind: RealtimeEventKind,
    pub stage: String,
    pub message: String,
    pub payload: Value,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ClientCommand {
    StartScan {
        url: String,
        #[serde(default = "default_mode")]
        mode: String,
        ports: Option<String>,
    },
    CancelScan {
        scan_id: u64,
    },
    PauseScan {
        scan_id: u64,
    },
    ResumeScan {
        scan_id: u64,
    },
    Ping,
}

#[derive(Debug)]
struct RunningScan {
    handle: JoinHandle<()>,
    paused: bool,
}

#[derive(Debug)]
struct RealtimeState {
    sender: broadcast::Sender<RealtimeEvent>,
    event_log: Mutex<VecDeque<RealtimeEvent>>,
    scans: Mutex<HashMap<u64, RunningScan>>,
    event_seq: AtomicU64,
    scan_seq: AtomicU64,
}

impl RealtimeState {
    fn new() -> Arc<Self> {
        let (sender, _) = broadcast::channel(EVENT_LOG_CAPACITY);
        Arc::new(Self {
            sender,
            event_log: Mutex::new(VecDeque::with_capacity(EVENT_LOG_CAPACITY)),
            scans: Mutex::new(HashMap::new()),
            event_seq: AtomicU64::new(1),
            scan_seq: AtomicU64::new(1),
        })
    }

    fn emit(
        &self,
        scan_id: Option<u64>,
        kind: RealtimeEventKind,
        stage: impl Into<String>,
        message: impl Into<String>,
        payload: Value,
    ) {
        let event = RealtimeEvent {
            id: self.event_seq.fetch_add(1, Ordering::Relaxed),
            scan_id,
            kind,
            stage: stage.into(),
            message: message.into(),
            payload,
            timestamp: chrono::Utc::now(),
        };

        if let Ok(mut log) = self.event_log.lock() {
            if log.len() == EVENT_LOG_CAPACITY {
                log.pop_front();
            }
            log.push_back(event.clone());
        }
        let _ = self.sender.send(event);
    }

    fn history(&self) -> Vec<RealtimeEvent> {
        self.event_log
            .lock()
            .map(|log| log.iter().cloned().collect())
            .unwrap_or_default()
    }
}

fn default_mode() -> String {
    "hybrid".to_string()
}

/// Runs the WebSocket and local dashboard server.
pub async fn run_realtime_server(config: RealtimeServerConfig) -> anyhow::Result<()> {
    ensure_bind_policy(&config)?;
    let listener = TcpListener::bind(config.bind)
        .await
        .with_context(|| format!("Failed to bind realtime server to {}", config.bind))?;
    let state = RealtimeState::new();

    eprintln!("[*] Realtime server listening on http://{}", config.bind);
    if config.token.is_some() {
        eprintln!("[*] WebSocket token authentication enabled");
    }
    info!("Realtime server listening on {}", config.bind);

    loop {
        let (stream, peer) = listener.accept().await?;
        let state = Arc::clone(&state);
        let server_config = config.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, peer, state, server_config).await {
                warn!("Realtime connection failed: {e}");
            }
        });
    }
}

fn ensure_bind_policy(config: &RealtimeServerConfig) -> anyhow::Result<()> {
    let is_local = match config.bind.ip() {
        IpAddr::V4(ip) => ip.is_loopback(),
        IpAddr::V6(ip) => ip.is_loopback(),
    };
    if !is_local && config.token.as_deref().unwrap_or_default().is_empty() {
        anyhow::bail!("Remote realtime bind requires --token or TEMU_SERVER_TOKEN");
    }
    Ok(())
}

async fn handle_connection(
    stream: TcpStream,
    peer: SocketAddr,
    state: Arc<RealtimeState>,
    config: RealtimeServerConfig,
) -> anyhow::Result<()> {
    let mut peek_buf = [0u8; 1024];
    let n = stream.peek(&mut peek_buf).await?;
    let request_head = String::from_utf8_lossy(&peek_buf[..n]).to_ascii_lowercase();

    if request_head.contains("upgrade: websocket") {
        handle_websocket(stream, peer, state, config).await
    } else {
        serve_dashboard(stream).await
    }
}

async fn serve_dashboard(stream: TcpStream) -> anyhow::Result<()> {
    let mut buf = [0u8; 2048];
    let _ = stream.readable().await;
    let _ = stream.try_read(&mut buf);

    let body = DASHBOARD_HTML.as_bytes();
    let response = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: text/html; charset=utf-8\r\ncontent-length: {}\r\ncache-control: no-store\r\nconnection: close\r\n\r\n",
        body.len()
    );
    stream.writable().await?;
    stream.try_write(response.as_bytes())?;
    stream.writable().await?;
    stream.try_write(body)?;
    Ok(())
}

async fn handle_websocket(
    stream: TcpStream,
    peer: SocketAddr,
    state: Arc<RealtimeState>,
    config: RealtimeServerConfig,
) -> anyhow::Result<()> {
    let expected_token = config.token.clone();
    let ws_stream = tokio_tungstenite::accept_hdr_async(
        stream,
        #[allow(clippy::result_large_err)]
        move |request: &Request, response: Response| {
            if token_allowed(request, expected_token.as_deref()) {
                Ok(response)
            } else {
                let mut response = ErrorResponse::new(Some("Unauthorized".to_string()));
                *response.status_mut() = StatusCode::UNAUTHORIZED;
                Err(response)
            }
        },
    )
    .await?;

    let (mut write, mut read) = ws_stream.split();

    for event in state.history() {
        write
            .send(Message::Text(serde_json::to_string(&event)?.into()))
            .await?;
    }

    state.emit(
        None,
        RealtimeEventKind::Log,
        "connection",
        format!("client connected: {peer}"),
        json!({"peer": peer.to_string()}),
    );

    let mut rx = state.sender.subscribe();
    loop {
        tokio::select! {
            received = rx.recv() => {
                let event = received?;
                write.send(Message::Text(serde_json::to_string(&event)?.into())).await?;
            }
            message = read.next() => {
                match message {
                    Some(Ok(Message::Text(text))) => {
                        handle_command(&text, Arc::clone(&state), config.clone()).await;
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Ok(Message::Ping(bytes))) => {
                        write.send(Message::Pong(bytes)).await?;
                    }
                    Some(Ok(_)) => {}
                    Some(Err(e)) => return Err(e.into()),
                }
            }
        }
    }

    Ok(())
}

fn token_allowed(request: &Request, expected_token: Option<&str>) -> bool {
    let Some(expected) = expected_token else {
        return true;
    };
    if expected.is_empty() {
        return true;
    }

    let query_token = request.uri().query().and_then(|query| {
        query
            .split('&')
            .filter_map(|part| part.split_once('='))
            .find_map(|(key, value)| (key == "token").then_some(value))
    });
    if query_token == Some(expected) {
        return true;
    }

    request
        .headers()
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        == Some(expected)
}

async fn handle_command(text: &str, state: Arc<RealtimeState>, config: RealtimeServerConfig) {
    let command = match serde_json::from_str::<ClientCommand>(text) {
        Ok(command) => command,
        Err(e) => {
            state.emit(
                None,
                RealtimeEventKind::Error,
                "command",
                format!("invalid command: {e}"),
                json!({}),
            );
            return;
        }
    };

    match command {
        ClientCommand::StartScan { url, mode, ports } => {
            start_scan(url, mode, ports, state, config).await;
        }
        ClientCommand::CancelScan { scan_id } => {
            cancel_scan(scan_id, &state);
        }
        ClientCommand::PauseScan { scan_id } => {
            set_paused(scan_id, true, &state);
        }
        ClientCommand::ResumeScan { scan_id } => {
            set_paused(scan_id, false, &state);
        }
        ClientCommand::Ping => {
            state.emit(None, RealtimeEventKind::Log, "ping", "pong", json!({}));
        }
    }
}

async fn start_scan(
    url: String,
    mode: String,
    ports: Option<String>,
    state: Arc<RealtimeState>,
    config: RealtimeServerConfig,
) {
    let scan_id = state.scan_seq.fetch_add(1, Ordering::Relaxed);
    state.emit(
        Some(scan_id),
        RealtimeEventKind::Queued,
        "queue",
        format!("queued scan for {url}"),
        json!({"target": url}),
    );

    let selected_ports = match ports {
        Some(ports) => match parse_ports(&ports) {
            Ok(ports) => ports,
            Err(e) => {
                state.emit(
                    Some(scan_id),
                    RealtimeEventKind::Error,
                    "ports",
                    format!("invalid ports: {e}"),
                    json!({}),
                );
                return;
            }
        },
        None => default_top_ports(),
    };
    let discovery_mode = match mode.as_str() {
        "bruteforce" => DiscoveryMode::ActiveBruteforce,
        "heuristic" => DiscoveryMode::SmartHeuristic,
        "passive" => DiscoveryMode::PassiveOnly,
        _ => DiscoveryMode::Hybrid,
    };

    let state_for_task = Arc::clone(&state);
    let app_config = config.app_config.clone();
    let handle = tokio::spawn(async move {
        state_for_task.emit(
            Some(scan_id),
            RealtimeEventKind::Progress,
            "scan",
            "scan started",
            json!({"target": url}),
        );
        match orchestrator::run_scan_with_ports(&url, &app_config, discovery_mode, &selected_ports)
            .await
        {
            Ok(result) => {
                let output_dir = app_config.output_dir.clone();
                let json_path = generate_json(&result, &output_dir);
                let html_path = generate_html(&result, &output_dir);
                let pdf_path = generate_pdf(&result, &output_dir);
                let artifacts = [json_path, html_path, pdf_path]
                    .into_iter()
                    .filter_map(Result::ok)
                    .map(|path| path.display().to_string())
                    .collect::<Vec<_>>();

                for vulnerability in &result.vulnerabilities {
                    state_for_task.emit(
                        Some(scan_id),
                        RealtimeEventKind::Finding,
                        "vulnerability",
                        vulnerability.name.clone(),
                        json!({
                            "id": vulnerability.id,
                            "url": vulnerability.url,
                            "severity": severity_name(&vulnerability.severity),
                            "verified": vulnerability.verified
                        }),
                    );
                }
                state_for_task.emit(
                    Some(scan_id),
                    RealtimeEventKind::Artifact,
                    "report",
                    "reports generated",
                    json!({"artifacts": artifacts}),
                );
                state_for_task.emit(
                    Some(scan_id),
                    RealtimeEventKind::Completed,
                    "scan",
                    "scan completed",
                    json!({
                        "assets": result.assets.len(),
                        "vulnerabilities": result.vulnerabilities.len(),
                        "duration_secs": result.stats.duration_secs
                    }),
                );
            }
            Err(e) => {
                state_for_task.emit(
                    Some(scan_id),
                    RealtimeEventKind::Error,
                    "scan",
                    e.to_string(),
                    json!({}),
                );
            }
        }

        if let Ok(mut scans) = state_for_task.scans.lock() {
            scans.remove(&scan_id);
        }
    });

    if let Ok(mut scans) = state.scans.lock() {
        scans.insert(
            scan_id,
            RunningScan {
                handle,
                paused: false,
            },
        );
    }
}

fn cancel_scan(scan_id: u64, state: &RealtimeState) {
    let removed = state
        .scans
        .lock()
        .ok()
        .and_then(|mut scans| scans.remove(&scan_id));
    if let Some(scan) = removed {
        scan.handle.abort();
        state.emit(
            Some(scan_id),
            RealtimeEventKind::Cancelled,
            "scan",
            "scan cancelled",
            json!({}),
        );
    }
}

fn set_paused(scan_id: u64, paused: bool, state: &RealtimeState) {
    let updated = state.scans.lock().ok().and_then(|mut scans| {
        let scan = scans.get_mut(&scan_id)?;
        scan.paused = paused;
        Some(())
    });
    if updated.is_some() {
        state.emit(
            Some(scan_id),
            if paused {
                RealtimeEventKind::Paused
            } else {
                RealtimeEventKind::Resumed
            },
            "scan",
            if paused {
                "pause requested"
            } else {
                "resume requested"
            },
            json!({"note": "running scans acknowledge pause/resume as control events"}),
        );
    }
}

fn severity_name(severity: &Severity) -> &'static str {
    match severity {
        Severity::Info => "info",
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_allowed_from_query() {
        let request = Request::builder()
            .uri("/ws?token=secret")
            .body(())
            .expect("request");
        assert!(token_allowed(&request, Some("secret")));
        assert!(!token_allowed(&request, Some("other")));
    }

    #[test]
    fn test_remote_bind_requires_token() {
        let config = RealtimeServerConfig {
            bind: "0.0.0.0:8787".parse().unwrap(),
            token: None,
            app_config: AppConfig::default(),
        };
        assert!(ensure_bind_policy(&config).is_err());
    }
}
