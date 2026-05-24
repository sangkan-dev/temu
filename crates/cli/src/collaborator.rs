use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use reporter::types::CallbackEvent;
use rusqlite::{Connection, params};
use tokio::net::{TcpListener, UdpSocket};
use tracing::warn;

/// Runtime configuration for the local OAST collaborator server.
#[derive(Debug, Clone)]
pub struct CollaboratorServerConfig {
    pub http_bind: SocketAddr,
    pub dns_bind: Option<SocketAddr>,
    pub dns_domain: Option<String>,
    pub public_url: Option<String>,
    pub database_path: std::path::PathBuf,
}

/// Initializes the callback evidence database.
pub fn init_callback_database(path: &Path) -> anyhow::Result<Connection> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let conn = Connection::open(path)?;
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS callback_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            correlation_id TEXT NOT NULL,
            protocol TEXT NOT NULL,
            method TEXT NOT NULL,
            path TEXT NOT NULL,
            remote_addr TEXT NOT NULL,
            user_agent TEXT,
            received_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_callback_correlation ON callback_events(correlation_id);
        "#,
    )?;
    Ok(conn)
}

/// Stores one callback event in the evidence database.
pub fn store_callback_event(conn: &Connection, event: &CallbackEvent) -> anyhow::Result<()> {
    conn.execute(
        r#"
        INSERT INTO callback_events (
            correlation_id, protocol, method, path, remote_addr, user_agent, received_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
        "#,
        params![
            event.correlation_id,
            event.protocol,
            event.method,
            event.path,
            event.remote_addr,
            event.user_agent,
            event.received_at.to_rfc3339(),
        ],
    )?;
    Ok(())
}

/// Loads callback events for one correlation ID.
pub fn load_callback_events(
    database_path: &Path,
    correlation_id: &str,
) -> anyhow::Result<Vec<CallbackEvent>> {
    let conn = init_callback_database(database_path)?;
    let mut stmt = conn.prepare(
        r#"
        SELECT correlation_id, protocol, method, path, remote_addr, user_agent, received_at
        FROM callback_events
        WHERE correlation_id = ?1
        ORDER BY received_at ASC, id ASC
        "#,
    )?;
    let rows = stmt.query_map([correlation_id], |row| {
        let received_at: String = row.get(6)?;
        Ok(CallbackEvent {
            correlation_id: row.get(0)?,
            protocol: row.get(1)?,
            method: row.get(2)?,
            path: row.get(3)?,
            remote_addr: row.get(4)?,
            user_agent: row.get(5)?,
            received_at: DateTime::parse_from_rfc3339(&received_at)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
        })
    })?;

    let mut events = Vec::new();
    for row in rows {
        events.push(row?);
    }
    Ok(events)
}

/// Runs the local HTTP and optional DNS collaborator listeners.
pub async fn run_collaborator_server(config: CollaboratorServerConfig) -> anyhow::Result<()> {
    let conn = init_callback_database(&config.database_path)?;
    let storage = Arc::new(Mutex::new(conn));
    eprintln!(
        "[*] Collaborator HTTP listening on http://{}",
        config.http_bind
    );
    eprintln!("[*] Callback database: {}", config.database_path.display());
    if let Some(public_url) = &config.public_url {
        eprintln!("[*] Public callback base URL: {public_url}");
        eprintln!(
            "[*] Example callback URL: {}/temu-test",
            public_url.trim_end_matches('/')
        );
    }
    if let Some(domain) = &config.dns_domain {
        eprintln!("[*] DNS callback domain: *.{domain}");
    }

    let http_task = tokio::spawn(run_http_listener(config.http_bind, Arc::clone(&storage)));
    let dns_task = if let (Some(bind), Some(domain)) = (config.dns_bind, config.dns_domain.clone())
    {
        Some(tokio::spawn(run_dns_listener(
            bind,
            domain,
            Arc::clone(&storage),
        )))
    } else {
        None
    };

    tokio::select! {
        result = http_task => result??,
        result = async {
            if let Some(task) = dns_task {
                task.await?
            } else {
                std::future::pending::<anyhow::Result<()>>().await
            }
        } => result?,
        _ = tokio::signal::ctrl_c() => {
            eprintln!("\n[!] Collaborator server stopped");
        }
    }
    Ok(())
}

async fn run_http_listener(
    bind: SocketAddr,
    storage: Arc<Mutex<Connection>>,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(bind).await?;
    loop {
        let (stream, peer) = listener.accept().await?;
        let storage = Arc::clone(&storage);
        tokio::spawn(async move {
            let mut buffer = vec![0u8; 8192];
            let Ok(read) = stream
                .readable()
                .await
                .and_then(|_| stream.try_read(&mut buffer))
            else {
                return;
            };
            let request = String::from_utf8_lossy(&buffer[..read]).to_string();
            let event = http_event_from_request(&request, peer);
            if let Ok(conn) = storage.lock()
                && let Err(error) = store_callback_event(&conn, &event)
            {
                warn!("Failed to store callback event: {error}");
            }
            let response =
                b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            let _ = stream
                .writable()
                .await
                .and_then(|_| stream.try_write(response));
        });
    }
}

fn http_event_from_request(request: &str, peer: SocketAddr) -> CallbackEvent {
    let mut lines = request.lines();
    let first = lines.next().unwrap_or_default();
    let mut parts = first.split_whitespace();
    let method = parts.next().unwrap_or("GET").to_string();
    let path = parts.next().unwrap_or("/").to_string();
    let headers = parse_headers(lines);
    let user_agent = headers.get("user-agent").cloned();
    let correlation_id = correlation_from_path(&path)
        .or_else(|| {
            headers
                .get("host")
                .and_then(|host| correlation_from_host(host))
        })
        .unwrap_or_else(|| "unknown".to_string());
    CallbackEvent {
        correlation_id,
        protocol: "http".to_string(),
        method,
        path,
        remote_addr: peer.to_string(),
        user_agent,
        received_at: Utc::now(),
    }
}

fn parse_headers<'a>(lines: impl Iterator<Item = &'a str>) -> HashMap<String, String> {
    let mut headers = HashMap::new();
    for line in lines {
        if line.trim().is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }
    headers
}

fn correlation_from_path(path: &str) -> Option<String> {
    let raw = path.split('?').next().unwrap_or(path);
    raw.trim_start_matches('/')
        .split('/')
        .find(|part| !part.is_empty() && *part != "cb" && *part != "callback")
        .map(|part| part.to_string())
}

fn correlation_from_host(host: &str) -> Option<String> {
    host.split('.')
        .next()
        .filter(|part| !part.is_empty())
        .map(str::to_string)
}

async fn run_dns_listener(
    bind: SocketAddr,
    domain: String,
    storage: Arc<Mutex<Connection>>,
) -> anyhow::Result<()> {
    let socket = UdpSocket::bind(bind).await?;
    eprintln!("[*] Collaborator DNS listening on udp://{bind}");
    let mut buffer = [0u8; 512];
    loop {
        let (len, peer) = socket.recv_from(&mut buffer).await?;
        let packet = &buffer[..len];
        let query_name = parse_dns_query_name(packet).unwrap_or_else(|| "unknown".to_string());
        let correlation_id = query_name
            .strip_suffix(&format!(".{}", domain.trim_end_matches('.')))
            .and_then(|value| value.trim_end_matches('.').split('.').next())
            .filter(|value| !value.is_empty())
            .unwrap_or("unknown")
            .to_string();
        let event = CallbackEvent {
            correlation_id,
            protocol: "dns".to_string(),
            method: "QUERY".to_string(),
            path: query_name,
            remote_addr: peer.to_string(),
            user_agent: None,
            received_at: Utc::now(),
        };
        if let Ok(conn) = storage.lock()
            && let Err(error) = store_callback_event(&conn, &event)
        {
            warn!("Failed to store DNS callback event: {error}");
        }
        let response = dns_response(packet);
        let _ = socket.send_to(&response, peer).await;
    }
}

fn parse_dns_query_name(packet: &[u8]) -> Option<String> {
    if packet.len() < 13 {
        return None;
    }
    let mut offset = 12usize;
    let mut labels = Vec::new();
    while offset < packet.len() {
        let len = *packet.get(offset)? as usize;
        offset += 1;
        if len == 0 {
            break;
        }
        if offset + len > packet.len() {
            return None;
        }
        labels.push(String::from_utf8_lossy(&packet[offset..offset + len]).to_string());
        offset += len;
    }
    (!labels.is_empty()).then(|| labels.join("."))
}

fn dns_response(packet: &[u8]) -> Vec<u8> {
    let mut response = packet.to_vec();
    if response.len() >= 4 {
        response[2] = 0x81;
        response[3] = 0x83;
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_event_extracts_correlation_from_path() {
        let event = http_event_from_request(
            "GET /cb/abc123 HTTP/1.1\r\nHost: localhost\r\nUser-Agent: test\r\n\r\n",
            "127.0.0.1:12345".parse().unwrap(),
        );
        assert_eq!(event.correlation_id, "abc123");
        assert_eq!(event.user_agent.as_deref(), Some("test"));
    }

    #[test]
    fn test_callback_database_roundtrip() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("callbacks.sqlite");
        let conn = init_callback_database(&path).unwrap();
        store_callback_event(
            &conn,
            &CallbackEvent {
                correlation_id: "cid".to_string(),
                protocol: "http".to_string(),
                method: "GET".to_string(),
                path: "/cid".to_string(),
                remote_addr: "127.0.0.1:1".to_string(),
                user_agent: None,
                received_at: Utc::now(),
            },
        )
        .unwrap();
        let events = load_callback_events(&path, "cid").unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].path, "/cid");
    }

    #[test]
    fn test_parse_dns_query_name() {
        let packet = [
            0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 3, b'a', b'b', b'c', 7, b'e', b'x', b'a', b'm',
            b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 0, 1, 0, 1,
        ];
        assert_eq!(
            parse_dns_query_name(&packet).as_deref(),
            Some("abc.example.com")
        );
    }
}
