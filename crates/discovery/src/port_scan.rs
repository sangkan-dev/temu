use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use temu_core::AppConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tracing::debug;

const CONNECT_TIMEOUT_SECS: u64 = 3;
const BANNER_TIMEOUT_SECS: u64 = 5;

/// TCP port state from a connect scan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PortState {
    Open,
    Closed,
    Filtered,
}

/// Result from scanning a single TCP port.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortResult {
    pub port: u16,
    pub state: PortState,
    pub service: Option<String>,
    pub banner: Option<String>,
}

/// Returns the default top 100 TCP ports used by the network scanner.
pub fn default_top_ports() -> Vec<u16> {
    vec![
        1, 3, 7, 9, 13, 17, 19, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113,
        119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514, 515, 543, 544,
        548, 554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1110, 1433,
        1720, 1723, 1755, 1900, 2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899,
        5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646,
        7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000, 32768, 49152, 49157,
    ]
}

/// Parses a port expression such as `80,443,8080` or `1-1024`.
pub fn parse_ports(input: &str) -> Result<Vec<u16>, String> {
    let mut ports = BTreeSet::new();

    for part in input.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        if let Some((start, end)) = part.split_once('-') {
            let start = parse_port(start)?;
            let end = parse_port(end)?;
            if start > end {
                return Err(format!("Invalid port range '{part}'"));
            }
            ports.extend(start..=end);
        } else {
            ports.insert(parse_port(part)?);
        }
    }

    if ports.is_empty() {
        return Err("No ports provided".to_string());
    }

    Ok(ports.into_iter().collect())
}

/// Scans TCP ports on `ip` and returns open ports with service and banner data.
pub async fn scan_ports(ip: IpAddr, ports: &[u16], config: &AppConfig) -> Vec<PortResult> {
    let semaphore = Arc::new(Semaphore::new(config.concurrency.max(1)));
    let mut handles = Vec::with_capacity(ports.len());

    for &port in ports {
        let sem = Arc::clone(&semaphore);
        handles.push(tokio::spawn(async move {
            let Ok(_permit) = sem.acquire().await else {
                return PortResult {
                    port,
                    state: PortState::Filtered,
                    service: None,
                    banner: None,
                };
            };
            scan_one_port(ip, port).await
        }));
    }

    let mut results = Vec::new();
    for handle in handles {
        if let Ok(result) = handle.await
            && result.state == PortState::Open
        {
            results.push(result);
        }
    }

    results.sort_by_key(|result| result.port);
    results
}

async fn scan_one_port(ip: IpAddr, port: u16) -> PortResult {
    let addr = SocketAddr::new(ip, port);
    debug!("Port scanning {addr}");

    match timeout(
        Duration::from_secs(CONNECT_TIMEOUT_SECS),
        TcpStream::connect(addr),
    )
    .await
    {
        Ok(Ok(_stream)) => {
            let banner = grab_banner(ip, port).await;
            let service = identify_service(port, banner.as_deref());
            PortResult {
                port,
                state: PortState::Open,
                service,
                banner,
            }
        }
        Ok(Err(_)) => PortResult {
            port,
            state: PortState::Closed,
            service: None,
            banner: None,
        },
        Err(_) => PortResult {
            port,
            state: PortState::Filtered,
            service: None,
            banner: None,
        },
    }
}

/// Connects to a TCP service and returns a lossy UTF-8 banner if one is received.
pub async fn grab_banner(ip: IpAddr, port: u16) -> Option<String> {
    let addr = SocketAddr::new(ip, port);
    let mut stream = timeout(
        Duration::from_secs(CONNECT_TIMEOUT_SECS),
        TcpStream::connect(addr),
    )
    .await
    .ok()?
    .ok()?;

    let probe = probe_bytes(port);
    if !probe.is_empty() {
        let _ = timeout(Duration::from_secs(1), stream.write_all(probe)).await;
    }

    let mut buf = vec![0_u8; 512];
    let n = timeout(
        Duration::from_secs(BANNER_TIMEOUT_SECS),
        stream.read(&mut buf),
    )
    .await
    .ok()?
    .ok()?;
    if n == 0 {
        return None;
    }

    Some(String::from_utf8_lossy(&buf[..n]).trim().to_string())
}

fn probe_bytes(port: u16) -> &'static [u8] {
    match port {
        80 | 81 | 8000 | 8008 | 8080 | 8081 | 8443 | 8888 => {
            b"HEAD / HTTP/1.0\r\nUser-Agent: Temu/1.1.1\r\n\r\n"
        }
        25 | 587 => b"EHLO temu.local\r\n",
        _ => b"",
    }
}

/// Identifies a likely service from a banner and known port.
pub fn identify_service(port: u16, banner: Option<&str>) -> Option<String> {
    let lower = banner.unwrap_or_default().to_ascii_lowercase();
    if lower.starts_with("ssh-") {
        Some("ssh".to_string())
    } else if lower.starts_with("220") && lower.contains("ftp") {
        Some("ftp".to_string())
    } else if lower.starts_with("220") && (lower.contains("smtp") || lower.contains("esmtp")) {
        Some("smtp".to_string())
    } else if lower.starts_with("http/") {
        Some("http".to_string())
    } else {
        service_from_port(port).map(str::to_string)
    }
}

fn service_from_port(port: u16) -> Option<&'static str> {
    match port {
        21 => Some("ftp"),
        22 => Some("ssh"),
        25 | 587 => Some("smtp"),
        53 => Some("dns"),
        80 | 8080 | 8081 | 8000 | 8008 => Some("http"),
        110 => Some("pop3"),
        143 => Some("imap"),
        443 | 8443 => Some("https"),
        445 => Some("smb"),
        3306 => Some("mysql"),
        3389 => Some("rdp"),
        5432 => Some("postgresql"),
        6379 => Some("redis"),
        9200 => Some("elasticsearch"),
        _ => None,
    }
}

fn parse_port(input: &str) -> Result<u16, String> {
    let port = input
        .parse::<u16>()
        .map_err(|_| format!("Invalid port '{input}'"))?;
    if port == 0 {
        return Err("Port 0 is not valid for TCP connect scanning".to_string());
    }
    Ok(port)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    fn test_config() -> AppConfig {
        AppConfig {
            rate_limit: 10,
            timeout_secs: 5,
            concurrency: 8,
            user_agent: "Temu-Test/1.0.0".to_string(),
            output_dir: PathBuf::from("/tmp"),
            rules_dir: PathBuf::from("/tmp"),
            dictionaries_dir: PathBuf::from("/tmp"),
            max_recursion_depth: 2,
            wordlist_override: None,
            allow_risky_rules: false,
        }
    }

    #[test]
    fn test_parse_ports_list_and_range() {
        assert_eq!(parse_ports("80,443,8080").unwrap(), vec![80, 443, 8080]);
        assert_eq!(parse_ports("22,80-82").unwrap(), vec![22, 80, 81, 82]);
        assert!(parse_ports("1024-1").is_err());
        assert!(parse_ports("0").is_err());
    }

    #[test]
    fn test_default_top_ports_has_100_entries() {
        let ports = default_top_ports();
        assert_eq!(ports.len(), 100);
        assert!(ports.contains(&80));
        assert!(ports.contains(&443));
    }

    #[test]
    fn test_identify_service_from_banner() {
        assert_eq!(
            identify_service(2222, Some("SSH-2.0-OpenSSH_8.9")),
            Some("ssh".to_string())
        );
        assert_eq!(
            identify_service(21, Some("220 ProFTPD")),
            Some("ftp".to_string())
        );
        assert_eq!(
            identify_service(25, Some("220 mail.example.com ESMTP")),
            Some("smtp".to_string())
        );
    }

    #[tokio::test]
    async fn test_scan_ports_finds_open_port_and_banner() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let _ = socket.write_all(b"SSH-2.0-OpenSSH_9.0\r\n").await;
            }
            if let Ok((mut socket, _)) = listener.accept().await {
                let _ = socket.write_all(b"SSH-2.0-OpenSSH_9.0\r\n").await;
            }
        });

        let results = scan_ports(IpAddr::from([127, 0, 0, 1]), &[port], &test_config()).await;

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].port, port);
        assert_eq!(results[0].state, PortState::Open);
        assert_eq!(results[0].service, Some("ssh".to_string()));
        assert!(
            results[0]
                .banner
                .as_deref()
                .unwrap_or_default()
                .contains("OpenSSH")
        );
    }
}
