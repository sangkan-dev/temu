use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use serde::{Deserialize, Serialize};
use temu_core::{AppConfig, ServiceEvidence, TlsEvidence};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::{Instant, timeout};
use tokio_rustls::TlsConnector;
use tracing::{debug, warn};
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::{FromDer, X509Certificate};

const CONNECT_TIMEOUT_SECS: u64 = 3;
const GREETING_TIMEOUT_MILLIS: u64 = 250;
const RESPONSE_TIMEOUT_SECS: u64 = 2;
const MAX_BANNER_BYTES: usize = 1024;

const TLS_CLIENT_HELLO: &[u8] = &[
    0x16, 0x03, 0x01, 0x00, 0x31, 0x01, 0x00, 0x00, 0x2d, 0x03, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x2f, 0x01,
    0x00, 0x00, 0x02, 0x00, 0x00,
];

/// TCP port state from a connect scan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PortState {
    Open,
    Closed,
    Filtered,
}

/// Result from scanning and safely profiling a single TCP port.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortResult {
    pub port: u16,
    pub state: PortState,
    pub service: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
    pub confidence: f32,
    pub banner: Option<String>,
    pub handshake: Option<String>,
    pub auth_required: Option<bool>,
    pub tls: Option<TlsEvidence>,
    #[serde(default)]
    pub signals: Vec<String>,
}

impl PortResult {
    /// Converts this open port profile into reportable network evidence.
    pub fn to_service_evidence(&self, ip: IpAddr) -> Option<ServiceEvidence> {
        if self.state != PortState::Open {
            return None;
        }
        Some(ServiceEvidence {
            endpoint: format!("tcp://{ip}:{}", self.port),
            port: self.port,
            protocol: self
                .service
                .clone()
                .unwrap_or_else(|| "unknown".to_string()),
            product: self.product.clone(),
            version: self.version.clone(),
            confidence: self.confidence,
            banner: self.banner.clone(),
            handshake: self.handshake.clone(),
            auth_required: self.auth_required,
            tls: self.tls.clone(),
            signals: self.signals.clone(),
        })
    }
}

#[derive(Debug, Clone, Default)]
struct ServiceProfile {
    protocol: Option<String>,
    product: Option<String>,
    version: Option<String>,
    confidence: f32,
    banner: Option<String>,
    handshake: Option<String>,
    auth_required: Option<bool>,
    signals: Vec<String>,
}

#[derive(Debug)]
struct ConnectionBudget {
    used: AtomicUsize,
    maximum: usize,
    deadline: Instant,
}

impl ConnectionBudget {
    fn new(config: &AppConfig) -> Self {
        Self {
            used: AtomicUsize::new(0),
            maximum: config.network_connection_budget.max(1),
            deadline: Instant::now() + Duration::from_secs(config.network_time_budget_secs.max(1)),
        }
    }

    fn reserve(&self) -> bool {
        if Instant::now() >= self.deadline {
            return false;
        }
        self.used
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
                (used < self.maximum).then_some(used + 1)
            })
            .is_ok()
    }
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

    for part in input
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
    {
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

/// Scans TCP ports and collects protocol evidence under per-host safety budgets.
pub async fn scan_ports(ip: IpAddr, ports: &[u16], config: &AppConfig) -> Vec<PortResult> {
    scan_ports_named(ip, ports, config, None).await
}

/// Scans TCP ports and uses an optional DNS name for certificate hostname checks.
pub async fn scan_ports_named(
    ip: IpAddr,
    ports: &[u16],
    config: &AppConfig,
    server_name: Option<&str>,
) -> Vec<PortResult> {
    let semaphore = Arc::new(Semaphore::new(config.concurrency.max(1)));
    let budget = Arc::new(ConnectionBudget::new(config));
    let allow_risky_probes = config.allow_risky_rules;
    let server_name = server_name.map(str::to_string);
    let mut handles = Vec::with_capacity(ports.len());

    for &port in ports {
        let sem = Arc::clone(&semaphore);
        let budget = Arc::clone(&budget);
        let server_name = server_name.clone();
        handles.push(tokio::spawn(async move {
            let Ok(_permit) = sem.acquire().await else {
                return filtered_result(port);
            };
            if !budget.reserve() {
                return filtered_result(port);
            }
            scan_one_port(ip, port, budget, allow_risky_probes, server_name.as_deref()).await
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

    if ports.len() > config.network_connection_budget {
        warn!(
            "Network connection budget exhausted or constrained: requested {} ports with budget {}",
            ports.len(),
            config.network_connection_budget
        );
    }
    results.sort_by_key(|result| result.port);
    results
}

async fn scan_one_port(
    ip: IpAddr,
    port: u16,
    budget: Arc<ConnectionBudget>,
    allow_risky_probes: bool,
    server_name: Option<&str>,
) -> PortResult {
    let addr = SocketAddr::new(ip, port);
    debug!("Port scanning {addr}");

    let Ok(Ok(mut stream)) = timeout(
        Duration::from_secs(CONNECT_TIMEOUT_SECS),
        TcpStream::connect(addr),
    )
    .await
    else {
        return closed_result(port);
    };

    let bytes = profile_response(&mut stream, port).await;
    let mut profile = parse_service_profile(port, &bytes);
    let mut tls = if budget.reserve() {
        probe_tls(ip, port).await
    } else {
        None
    };
    if (tls.is_some() || likely_tls_port(port))
        && budget.reserve()
        && let Some(certificate_evidence) = probe_tls_certificate(ip, port, server_name).await
    {
        tls = Some(certificate_evidence);
    }
    if let Some(evidence) = tls.as_mut() {
        for (name, minor) in [("TLS 1.0", 0x01), ("TLS 1.1", 0x02), ("TLS 1.2", 0x03)] {
            if budget.reserve()
                && probe_tls_version(ip, port, minor).await
                && !evidence
                    .supported_versions
                    .iter()
                    .any(|value| value == name)
            {
                evidence.supported_versions.push(name.to_string());
            }
        }
    }
    if tls.as_ref().is_some_and(|evidence| evidence.detected)
        && matches!(
            profile.protocol.as_deref(),
            None | Some("http") | Some("tls")
        )
    {
        profile.protocol = Some("https".to_string());
        profile
            .product
            .get_or_insert_with(|| "TLS service".to_string());
        profile.confidence = profile.confidence.max(0.90);
    }
    if tls.as_ref().is_some_and(|evidence| evidence.detected) {
        push_signal(&mut profile, "tls_detected");
        if tls.as_ref().is_some_and(|evidence| {
            evidence
                .supported_versions
                .iter()
                .any(|version| matches!(version.as_str(), "TLS 1.0" | "TLS 1.1"))
        }) {
            push_signal(&mut profile, "legacy_tls_accepted");
        }
        if tls.as_ref().and_then(|evidence| evidence.self_signed) == Some(true) {
            push_signal(&mut profile, "tls_self_signed");
        }
        if tls.as_ref().and_then(|evidence| evidence.hostname_mismatch) == Some(true) {
            push_signal(&mut profile, "tls_hostname_mismatch");
        }
        if tls
            .as_ref()
            .and_then(|evidence| evidence.signature_algorithm.as_deref())
            .is_some_and(weak_signature_algorithm)
        {
            push_signal(&mut profile, "tls_weak_signature");
        }
        if tls
            .as_ref()
            .and_then(|evidence| evidence.certificate_not_after.as_deref())
            .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
            .is_some_and(|expiry| expiry < chrono::Utc::now())
        {
            push_signal(&mut profile, "tls_certificate_expired");
        }
    }
    if profile.protocol.is_none() {
        profile = probe_unknown_service(ip, port, Arc::clone(&budget))
            .await
            .unwrap_or(profile);
    }
    if profile.protocol.is_none() {
        profile.protocol = service_from_port(port).map(str::to_string);
        profile.confidence = if profile.protocol.is_some() {
            0.35
        } else {
            0.10
        };
    }
    enrich_service_profile(ip, port, &mut profile, &budget, allow_risky_probes).await;
    push_signal(
        &mut profile,
        if is_publicly_routable(ip) {
            "publicly_routable"
        } else {
            "private_or_local"
        },
    );

    PortResult {
        port,
        state: PortState::Open,
        service: profile.protocol,
        product: profile.product,
        version: profile.version,
        confidence: profile.confidence,
        banner: profile.banner,
        handshake: profile.handshake,
        auth_required: profile.auth_required,
        tls,
        signals: profile.signals,
    }
}

async fn profile_response(stream: &mut TcpStream, port: u16) -> Vec<u8> {
    let mut buffer = vec![0_u8; MAX_BANNER_BYTES];
    if let Ok(Ok(size)) = timeout(
        Duration::from_millis(GREETING_TIMEOUT_MILLIS),
        stream.read(&mut buffer),
    )
    .await
        && size > 0
    {
        buffer.truncate(size);
        return buffer;
    }

    let probe = protocol_probe(port);
    if probe.is_empty()
        || timeout(Duration::from_secs(1), stream.write_all(probe))
            .await
            .is_err()
    {
        return Vec::new();
    }
    let Ok(Ok(size)) = timeout(
        Duration::from_secs(RESPONSE_TIMEOUT_SECS),
        stream.read(&mut buffer),
    )
    .await
    else {
        return Vec::new();
    };
    buffer.truncate(size);
    buffer
}

/// Connects to a TCP service and returns a sanitized greeting or probe response.
pub async fn grab_banner(ip: IpAddr, port: u16) -> Option<String> {
    let addr = SocketAddr::new(ip, port);
    let mut stream = timeout(
        Duration::from_secs(CONNECT_TIMEOUT_SECS),
        TcpStream::connect(addr),
    )
    .await
    .ok()?
    .ok()?;
    let bytes = profile_response(&mut stream, port).await;
    (!bytes.is_empty()).then(|| sanitize_banner(&bytes))
}

async fn probe_tls(ip: IpAddr, port: u16) -> Option<TlsEvidence> {
    let addr = SocketAddr::new(ip, port);
    let mut stream = timeout(
        Duration::from_secs(CONNECT_TIMEOUT_SECS),
        TcpStream::connect(addr),
    )
    .await
    .ok()?
    .ok()?;
    timeout(Duration::from_secs(1), stream.write_all(TLS_CLIENT_HELLO))
        .await
        .ok()?
        .ok()?;
    let mut response = [0_u8; 128];
    let size = timeout(
        Duration::from_secs(RESPONSE_TIMEOUT_SECS),
        stream.read(&mut response),
    )
    .await
    .ok()?
    .ok()?;
    parse_tls_response(&response[..size])
}

async fn probe_tls_version(ip: IpAddr, port: u16, minor_version: u8) -> bool {
    let mut hello = TLS_CLIENT_HELLO.to_vec();
    hello[2] = minor_version;
    hello[10] = minor_version;
    let Some(mut stream) = connect(ip, port).await else {
        return false;
    };
    if write_probe(&mut stream, &hello).await.is_none() {
        return false;
    }
    let response = read_response(&mut stream).await;
    response.first() == Some(&0x16)
}

#[derive(Debug)]
struct EvidenceOnlyCertificateVerifier;

impl ServerCertVerifier for EvidenceOnlyCertificateVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA1,
            SignatureScheme::ECDSA_SHA1_Legacy,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ]
    }
}

async fn probe_tls_certificate(
    ip: IpAddr,
    port: u16,
    expected_hostname: Option<&str>,
) -> Option<TlsEvidence> {
    let stream = connect(ip, port).await?;
    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(EvidenceOnlyCertificateVerifier))
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));
    let name =
        ServerName::try_from(expected_hostname.unwrap_or(&ip.to_string()).to_string()).ok()?;
    let tls_stream = timeout(
        Duration::from_secs(RESPONSE_TIMEOUT_SECS),
        connector.connect(name, stream),
    )
    .await
    .ok()?
    .ok()?;
    let connection = tls_stream.get_ref().1;
    let certificates = connection.peer_certificates()?;
    let leaf = certificates.first()?;
    let (_, certificate) = X509Certificate::from_der(leaf.as_ref()).ok()?;
    let subject = certificate.subject().to_string();
    let issuer = certificate.issuer().to_string();
    let signature_algorithm = certificate.signature_algorithm.algorithm.to_id_string();
    let subject_alt_names = certificate
        .subject_alternative_name()
        .ok()
        .flatten()
        .map(|extension| {
            extension
                .value
                .general_names
                .iter()
                .filter_map(|name| match name {
                    GeneralName::DNSName(name) => Some((*name).to_string()),
                    GeneralName::IPAddress(bytes) => Some(
                        bytes
                            .iter()
                            .map(|byte| byte.to_string())
                            .collect::<Vec<_>>()
                            .join("."),
                    ),
                    _ => None,
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let hostname_mismatch = expected_hostname.map(|hostname| {
        !subject_alt_names
            .iter()
            .any(|candidate| hostname_matches(hostname, candidate))
    });
    let protocol_version = connection.protocol_version().map(|version| match version {
        rustls::ProtocolVersion::TLSv1_2 => "TLS 1.2".to_string(),
        rustls::ProtocolVersion::TLSv1_3 => "TLS 1.3".to_string(),
        _ => format!("{version:?}"),
    });
    let cipher_suite = connection
        .negotiated_cipher_suite()
        .map(|suite| format!("{:?}", suite.suite()));

    Some(TlsEvidence {
        detected: true,
        supported_versions: protocol_version.clone().into_iter().collect(),
        protocol_version,
        cipher_suite,
        certificate_subject: Some(subject.clone()),
        certificate_issuer: Some(issuer.clone()),
        certificate_not_after: chrono::DateTime::from_timestamp(
            certificate.validity().not_after.timestamp(),
            0,
        )
        .map(|value| value.to_rfc3339()),
        signature_algorithm: Some(signature_algorithm),
        subject_alt_names,
        certificate_chain_length: certificates.len(),
        self_signed: Some(subject == issuer),
        hostname_mismatch,
    })
}

fn hostname_matches(hostname: &str, certificate_name: &str) -> bool {
    if hostname.eq_ignore_ascii_case(certificate_name) {
        return true;
    }
    let Some(suffix) = certificate_name.strip_prefix("*.") else {
        return false;
    };
    let hostname = hostname.to_ascii_lowercase();
    let suffix = suffix.to_ascii_lowercase();
    hostname.ends_with(&format!(".{suffix}"))
        && hostname
            .trim_end_matches(&format!(".{suffix}"))
            .split('.')
            .count()
            == 1
}

fn weak_signature_algorithm(algorithm: &str) -> bool {
    matches!(
        algorithm,
        "1.2.840.113549.1.1.4" | "1.2.840.113549.1.1.5" | "1.2.840.10045.4.1"
    )
}

async fn probe_unknown_service(
    ip: IpAddr,
    port: u16,
    budget: Arc<ConnectionBudget>,
) -> Option<ServiceProfile> {
    for probe in generic_protocol_probes() {
        if !budget.reserve() {
            return None;
        }
        let bytes = probe_once(ip, port, probe).await;
        let profile = parse_service_profile(port, &bytes);
        if profile.protocol.is_some() {
            return Some(profile);
        }
    }
    None
}

async fn probe_once(ip: IpAddr, port: u16, probe: &[u8]) -> Vec<u8> {
    let addr = SocketAddr::new(ip, port);
    let Ok(Ok(mut stream)) = timeout(
        Duration::from_secs(CONNECT_TIMEOUT_SECS),
        TcpStream::connect(addr),
    )
    .await
    else {
        return Vec::new();
    };
    if timeout(Duration::from_secs(1), stream.write_all(probe))
        .await
        .is_err()
    {
        return Vec::new();
    }
    let mut response = vec![0_u8; MAX_BANNER_BYTES];
    let Ok(Ok(size)) = timeout(
        Duration::from_secs(RESPONSE_TIMEOUT_SECS),
        stream.read(&mut response),
    )
    .await
    else {
        return Vec::new();
    };
    response.truncate(size);
    response
}

async fn enrich_service_profile(
    ip: IpAddr,
    port: u16,
    profile: &mut ServiceProfile,
    budget: &Arc<ConnectionBudget>,
    allow_risky_probes: bool,
) {
    match profile.protocol.as_deref() {
        Some("postgresql") if budget.reserve() => {
            let response = probe_once(ip, port, &postgres_startup_probe()).await;
            let text = sanitize_banner(&response);
            if response.first() == Some(&b'R') {
                profile.auth_required = Some(true);
                push_signal(profile, "auth_exchange_available");
            } else if response.first() == Some(&b'E') {
                if text.to_ascii_lowercase().contains("pg_hba.conf") {
                    push_signal(profile, "pg_hba_rejected");
                } else {
                    push_signal(profile, "startup_rejected");
                }
            }
            append_handshake(profile, &text);
        }
        Some("smtp") if budget.reserve() => {
            push_signal(profile, "smtp_banner_exposed");
            if let Some(summary) = probe_smtp(ip, port).await {
                if summary.to_ascii_lowercase().contains("starttls") {
                    push_signal(profile, "starttls_supported");
                } else {
                    push_signal(profile, "starttls_not_advertised");
                }
                if summary.contains("relay_probe=accepted") {
                    push_signal(profile, "open_relay_no_delivery_accepted");
                }
                append_handshake(profile, &summary);
            }
        }
        Some("ftp") if allow_risky_probes && budget.reserve() => {
            if let Some(summary) = probe_ftp_anonymous(ip, port).await {
                if summary.contains("anonymous_login=accepted") {
                    push_signal(profile, "anonymous_login_accepted");
                }
                append_handshake(profile, &summary);
            }
        }
        Some("elasticsearch")
            if profile
                .handshake
                .as_deref()
                .is_some_and(|value| value.to_ascii_lowercase().contains("200 ok")) =>
        {
            profile.auth_required = Some(false);
            push_signal(profile, "unauthenticated_api_response");
        }
        Some("mongodb") if budget.reserve() => {
            let response = probe_once(ip, port, &mongo_list_databases_probe()).await;
            let text = sanitize_banner(&response);
            let lower = text.to_ascii_lowercase();
            if lower.contains("databases") && !lower.contains("unauthorized") {
                profile.auth_required = Some(false);
                push_signal(profile, "unauthenticated_database_listing");
            } else if lower.contains("unauthorized") || lower.contains("requires authentication") {
                profile.auth_required = Some(true);
                push_signal(profile, "auth_required");
            }
            append_handshake(profile, &text);
        }
        Some("http") if port == 15672 => {
            profile.product = Some("RabbitMQ Management".to_string());
            push_signal(profile, "management_interface_exposed");
        }
        _ => {}
    }
}

async fn probe_smtp(ip: IpAddr, port: u16) -> Option<String> {
    let mut stream = connect(ip, port).await?;
    let greeting = read_response(&mut stream).await;
    write_probe(&mut stream, b"EHLO temu.invalid\r\n").await?;
    let ehlo = read_response(&mut stream).await;
    write_probe(&mut stream, b"MAIL FROM:<>\r\n").await?;
    let mail = read_response(&mut stream).await;
    write_probe(&mut stream, b"RCPT TO:<temu-probe@temu.invalid>\r\n").await?;
    let recipient = read_response(&mut stream).await;
    let _ = write_probe(&mut stream, b"RSET\r\nQUIT\r\n").await;
    let relay_accepted = smtp_success(&mail) && smtp_success(&recipient);
    Some(format!(
        "greeting={} ehlo={} relay_probe={}",
        sanitize_banner(&greeting),
        sanitize_banner(&ehlo),
        if relay_accepted {
            "accepted"
        } else {
            "rejected"
        }
    ))
}

async fn probe_ftp_anonymous(ip: IpAddr, port: u16) -> Option<String> {
    let mut stream = connect(ip, port).await?;
    let _ = read_response(&mut stream).await;
    write_probe(&mut stream, b"USER anonymous\r\n").await?;
    let user = read_response(&mut stream).await;
    write_probe(&mut stream, b"PASS temu@invalid\r\n").await?;
    let pass = read_response(&mut stream).await;
    let _ = write_probe(&mut stream, b"QUIT\r\n").await;
    Some(format!(
        "anonymous_login={} user_response={} pass_response={}",
        if pass.starts_with(b"230") {
            "accepted"
        } else {
            "rejected"
        },
        sanitize_banner(&user),
        sanitize_banner(&pass)
    ))
}

async fn connect(ip: IpAddr, port: u16) -> Option<TcpStream> {
    timeout(
        Duration::from_secs(CONNECT_TIMEOUT_SECS),
        TcpStream::connect(SocketAddr::new(ip, port)),
    )
    .await
    .ok()?
    .ok()
}

async fn write_probe(stream: &mut TcpStream, probe: &[u8]) -> Option<()> {
    timeout(Duration::from_secs(1), stream.write_all(probe))
        .await
        .ok()?
        .ok()
}

async fn read_response(stream: &mut TcpStream) -> Vec<u8> {
    let mut response = vec![0_u8; MAX_BANNER_BYTES];
    let Ok(Ok(size)) = timeout(
        Duration::from_secs(RESPONSE_TIMEOUT_SECS),
        stream.read(&mut response),
    )
    .await
    else {
        return Vec::new();
    };
    response.truncate(size);
    response
}

fn smtp_success(response: &[u8]) -> bool {
    matches!(response.first(), Some(b'2'))
}

fn postgres_startup_probe() -> Vec<u8> {
    let mut packet = vec![0, 0, 0, 0, 0, 3, 0, 0];
    packet.extend_from_slice(b"user\0temu_probe\0database\0temu_probe\0application_name\0temu\0\0");
    let length = (packet.len() as u32).to_be_bytes();
    packet[..4].copy_from_slice(&length);
    packet
}

fn mongo_list_databases_probe() -> Vec<u8> {
    let mut document = vec![0, 0, 0, 0];
    document.push(0x10);
    document.extend_from_slice(b"listDatabases\0");
    document.extend_from_slice(&1_i32.to_le_bytes());
    document.push(0x02);
    document.extend_from_slice(b"$db\0");
    document.extend_from_slice(&6_i32.to_le_bytes());
    document.extend_from_slice(b"admin\0");
    document.push(0);
    let document_length = (document.len() as i32).to_le_bytes();
    document[..4].copy_from_slice(&document_length);

    let mut message = vec![0, 0, 0, 0];
    message.extend_from_slice(&1_i32.to_le_bytes());
    message.extend_from_slice(&0_i32.to_le_bytes());
    message.extend_from_slice(&2013_i32.to_le_bytes());
    message.extend_from_slice(&0_u32.to_le_bytes());
    message.push(0);
    message.extend_from_slice(&document);
    let message_length = (message.len() as i32).to_le_bytes();
    message[..4].copy_from_slice(&message_length);
    message
}

fn append_handshake(profile: &mut ServiceProfile, evidence: &str) {
    if evidence.is_empty() {
        return;
    }
    profile.handshake = Some(match profile.handshake.take() {
        Some(existing) => format!("{existing}; {evidence}"),
        None => evidence.to_string(),
    });
}

fn push_signal(profile: &mut ServiceProfile, signal: &str) {
    if !profile.signals.iter().any(|value| value == signal) {
        profile.signals.push(signal.to_string());
    }
}

fn is_publicly_routable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            !(ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_broadcast()
                || ip.is_documentation()
                || ip.is_unspecified())
        }
        IpAddr::V6(ip) => !(ip.is_loopback() || ip.is_unspecified() || ip.is_unique_local()),
    }
}

fn likely_tls_port(port: u16) -> bool {
    matches!(
        port,
        443 | 465 | 636 | 853 | 990 | 993 | 995 | 5671 | 8443 | 8883
    )
}

fn parse_tls_response(response: &[u8]) -> Option<TlsEvidence> {
    if response.len() < 5 || !matches!(response[0], 0x15 | 0x16) || response[1] != 0x03 {
        return None;
    }
    let protocol_version = match response.get(2).copied() {
        Some(0x00) => "SSL 3.0",
        Some(0x01) => "TLS 1.0",
        Some(0x02) => "TLS 1.1",
        Some(0x03) => "TLS 1.2 or newer",
        _ => "TLS",
    };
    let cipher_suite =
        (response.len() > 44).then(|| format!("0x{:02x}{:02x}", response[43], response[44]));
    Some(TlsEvidence {
        detected: true,
        protocol_version: Some(protocol_version.to_string()),
        cipher_suite,
        supported_versions: vec![protocol_version.to_string()],
        certificate_subject: None,
        certificate_issuer: None,
        certificate_not_after: None,
        signature_algorithm: None,
        subject_alt_names: Vec::new(),
        certificate_chain_length: 0,
        self_signed: None,
        hostname_mismatch: None,
    })
}

fn protocol_probe(port: u16) -> &'static [u8] {
    match port {
        21 => b"FEAT\r\n",
        25 | 465 | 587 => b"EHLO temu.local\r\n",
        80 | 81 | 443 | 3000 | 8000 | 8008 | 8080 | 8081 | 8443 | 8888 | 15672 => {
            b"HEAD / HTTP/1.0\r\nUser-Agent: Temu/1.5.0\r\n\r\n"
        }
        9200 => b"GET / HTTP/1.0\r\nUser-Agent: Temu/1.5.0\r\n\r\n",
        110 | 995 => b"CAPA\r\n",
        143 | 993 => b"a001 CAPABILITY\r\n",
        445 => b"\x00\x00\x00\x54\xfeSMB@\x00",
        1433 => b"\x12\x01\x00\x12\x00\x00\x01\x00\x00\x00\x0f\x00\x01\xff",
        1883 | 8883 => b"\x10\x10\x00\x04MQTT\x04\x02\x00\x0a\x00\x04temu",
        27017 => b"\x25\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xdd\x07\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x10hello\x00\x01\x00\x00\x00\x00",
        3306 => b"",
        3389 => b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00",
        5432 => b"\x00\x00\x00\x08\x04\xd2\x16\x2f",
        5671 | 5672 => b"AMQP\x00\x00\x09\x01",
        6379 => b"*1\r\n$4\r\nPING\r\n",
        11211 => b"version\r\n",
        _ => b"HEAD / HTTP/1.0\r\nUser-Agent: Temu/1.5.0\r\n\r\n",
    }
}

fn generic_protocol_probes() -> &'static [&'static [u8]] {
    &[
        b"*1\r\n$4\r\nPING\r\n",
        b"version\r\n",
        b"\x00\x00\x00\x08\x04\xd2\x16\x2f",
        b"\x25\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xdd\x07\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x10hello\x00\x01\x00\x00\x00\x00",
        b"\x10\x10\x00\x04MQTT\x04\x02\x00\x0a\x00\x04temu",
        b"AMQP\x00\x00\x09\x01",
        b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00",
        b"\x00\x00\x00\x54\xfeSMB@\x00",
        b"\x12\x01\x00\x12\x00\x00\x01\x00\x00\x00\x0f\x00\x01\xff",
    ]
}

fn parse_service_profile(port: u16, bytes: &[u8]) -> ServiceProfile {
    if bytes.is_empty() {
        return ServiceProfile::default();
    }
    let banner = sanitize_banner(bytes);
    let lower = banner.to_ascii_lowercase();
    let mut profile = ServiceProfile {
        banner: Some(banner.clone()),
        handshake: Some(banner.clone()),
        ..ServiceProfile::default()
    };

    if lower.starts_with("ssh-") {
        profile.protocol = Some("ssh".to_string());
        profile.product = lower.contains("openssh").then(|| "OpenSSH".to_string());
        profile.version = substring_version(&banner, "OpenSSH_");
        profile.confidence = 0.99;
    } else if lower.starts_with("220") && lower.contains("ftp") {
        profile.protocol = Some("ftp".to_string());
        profile.product = product_token(&banner, &["proftpd", "vsftpd", "filezilla"]);
        profile.version = profile
            .product
            .as_deref()
            .and_then(|name| substring_version(&banner, name));
        profile.confidence = 0.95;
    } else if lower.starts_with("220") && (lower.contains("smtp") || lower.contains("esmtp")) {
        profile.protocol = Some("smtp".to_string());
        profile.product = Some("SMTP".to_string());
        profile.confidence = 0.92;
    } else if lower.starts_with("+ok") || lower.contains("pop3") {
        profile.protocol = Some("pop3".to_string());
        profile.product = Some("POP3".to_string());
        profile.confidence = 0.92;
    } else if lower.starts_with("* ok") || lower.contains("imap") {
        profile.protocol = Some("imap".to_string());
        profile.product = Some("IMAP".to_string());
        profile.confidence = 0.92;
    } else if lower.starts_with("+pong") || lower.contains("-noauth") || lower.contains("redis") {
        profile.protocol = Some("redis".to_string());
        profile.product = Some("Redis".to_string());
        profile.auth_required = Some(lower.contains("noauth"));
        if lower.starts_with("+pong") {
            push_signal(&mut profile, "unauthenticated_command_accepted");
        } else if lower.contains("noauth") {
            push_signal(&mut profile, "auth_required");
        }
        profile.confidence = 0.98;
    } else if lower.starts_with("version ") || lower.contains("memcached") {
        profile.protocol = Some("memcached".to_string());
        profile.product = Some("Memcached".to_string());
        profile.version = lower
            .strip_prefix("version ")
            .and_then(|rest| {
                rest.split(|character: char| character.is_ascii_whitespace() || character == '\\')
                    .next()
            })
            .map(str::to_string);
        push_signal(&mut profile, "unauthenticated_command_accepted");
        profile.confidence = 0.98;
    } else if mysql_protocol_offset(bytes).is_some() && port == 3306 {
        profile.protocol = Some("mysql".to_string());
        profile.product = Some("MySQL".to_string());
        profile.version = mysql_version(bytes);
        profile.auth_required = Some(true);
        push_signal(&mut profile, "auth_exchange_available");
        if mysql_supports_tls(bytes) {
            push_signal(&mut profile, "tls_supported");
        } else {
            push_signal(&mut profile, "tls_not_supported");
        }
        profile.confidence = 0.98;
    } else if matches!(bytes.first(), Some(b'S' | b'N' | b'E')) && bytes.len() <= 8 {
        profile.protocol = Some("postgresql".to_string());
        profile.product = Some("PostgreSQL".to_string());
        if bytes.first() == Some(&b'S') {
            push_signal(&mut profile, "tls_supported");
        } else if bytes.first() == Some(&b'N') {
            push_signal(&mut profile, "tls_not_supported");
        } else {
            push_signal(&mut profile, "startup_rejected");
        }
        profile.confidence = 0.92;
    } else if bytes.starts_with(b"AMQP") || lower.contains("rabbitmq") {
        profile.protocol = Some("amqp".to_string());
        profile.product = Some("RabbitMQ/AMQP".to_string());
        profile.confidence = 0.94;
    } else if bytes.starts_with(&[0x20, 0x02]) {
        profile.protocol = Some("mqtt".to_string());
        profile.product = Some("MQTT broker".to_string());
        profile.auth_required = bytes
            .get(3)
            .copied()
            .map(|code| code == 0x04 || code == 0x05);
        if profile.auth_required == Some(false) {
            push_signal(&mut profile, "anonymous_connection_accepted");
        }
        profile.confidence = 0.95;
    } else if bytes.starts_with(&[0x03, 0x00]) {
        profile.protocol = Some("rdp".to_string());
        profile.product = Some("RDP".to_string());
        match rdp_selected_protocol(bytes) {
            Some(0) => push_signal(&mut profile, "nla_not_required"),
            Some(2) | Some(8) => push_signal(&mut profile, "nla_required"),
            Some(_) => push_signal(&mut profile, "tls_transport_selected"),
            None => {}
        }
        profile.confidence = 0.93;
    } else if bytes
        .windows(4)
        .any(|part| part == b"SMB\x00" || part == b"\xfeSMB")
    {
        profile.protocol = Some("smb".to_string());
        profile.product = Some("SMB".to_string());
        match smb_signing_required(bytes) {
            Some(true) => push_signal(&mut profile, "smb_signing_required"),
            Some(false) => push_signal(&mut profile, "smb_signing_not_required"),
            None => {}
        }
        profile.confidence = 0.95;
    } else if bytes.first() == Some(&0x04) {
        profile.protocol = Some("mssql".to_string());
        profile.product = Some("Microsoft SQL Server".to_string());
        profile.auth_required = Some(true);
        push_signal(&mut profile, "auth_exchange_available");
        match mssql_encryption_mode(bytes) {
            Some(0) | Some(2) => push_signal(&mut profile, "tls_not_supported"),
            Some(1) | Some(3) => push_signal(&mut profile, "tls_supported"),
            _ => {}
        }
        profile.confidence = 0.90;
    } else if bytes
        .get(12..16)
        .and_then(|opcode| opcode.try_into().ok())
        .map(i32::from_le_bytes)
        .is_some_and(|opcode| matches!(opcode, 1 | 2013))
    {
        profile.protocol = Some("mongodb".to_string());
        profile.product = Some("MongoDB".to_string());
        profile.confidence = 0.92;
    } else if lower.starts_with("http/") {
        profile.protocol = Some(if port == 9200 && lower.contains("elastic") {
            "elasticsearch".to_string()
        } else {
            "http".to_string()
        });
        profile.product = http_product(&banner);
        profile.version = profile
            .product
            .as_deref()
            .and_then(|product| substring_version(&banner, &format!("{product}/")));
        profile.confidence = 0.90;
        if port == 9200 && lower.contains("200 ok") {
            profile.auth_required = Some(false);
            push_signal(&mut profile, "unauthenticated_api_response");
        } else if port == 9200 && lower.contains("401") {
            profile.auth_required = Some(true);
            push_signal(&mut profile, "auth_required");
        }
    }
    profile
}

/// Identifies a likely protocol from a banner and known port.
pub fn identify_service(port: u16, banner: Option<&str>) -> Option<String> {
    banner
        .and_then(|value| parse_service_profile(port, value.as_bytes()).protocol)
        .or_else(|| service_from_port(port).map(str::to_string))
}

fn service_from_port(port: u16) -> Option<&'static str> {
    match port {
        21 => Some("ftp"),
        22 => Some("ssh"),
        25 | 465 | 587 => Some("smtp"),
        80 | 81 | 3000 | 8000 | 8008 | 8080 | 8081 => Some("http"),
        110 | 995 => Some("pop3"),
        143 | 993 => Some("imap"),
        443 | 8443 => Some("https"),
        445 => Some("smb"),
        1433 => Some("mssql"),
        1883 | 8883 => Some("mqtt"),
        27017 => Some("mongodb"),
        3306 => Some("mysql"),
        3389 => Some("rdp"),
        5432 => Some("postgresql"),
        5671 | 5672 => Some("amqp"),
        6379 => Some("redis"),
        9200 => Some("elasticsearch"),
        11211 => Some("memcached"),
        _ => None,
    }
}

fn mysql_version(bytes: &[u8]) -> Option<String> {
    let offset = mysql_protocol_offset(bytes)?;
    let remaining = bytes.get(offset + 1..)?;
    let end = remaining.iter().position(|byte| *byte == 0)?;
    let value = sanitize_banner(&remaining[..end]);
    (!value.is_empty()).then_some(value)
}

fn mysql_protocol_offset(bytes: &[u8]) -> Option<usize> {
    if bytes.first() == Some(&0x0a) {
        Some(0)
    } else if bytes.get(4) == Some(&0x0a) {
        Some(4)
    } else {
        None
    }
}

fn mysql_supports_tls(bytes: &[u8]) -> bool {
    let Some(offset) = mysql_protocol_offset(bytes) else {
        return false;
    };
    let Some(version_end) = bytes
        .get(offset + 1..)
        .and_then(|value| value.iter().position(|byte| *byte == 0))
    else {
        return false;
    };
    let capability_offset = offset + 1 + version_end + 1 + 4 + 8 + 1;
    let Some(flags) = bytes.get(capability_offset..capability_offset + 2) else {
        return false;
    };
    u16::from_le_bytes([flags[0], flags[1]]) & 0x0800 != 0
}

fn rdp_selected_protocol(bytes: &[u8]) -> Option<u32> {
    let index = bytes.iter().position(|byte| *byte == 0x02)?;
    let selected = bytes.get(index + 4..index + 8)?;
    Some(u32::from_le_bytes(selected.try_into().ok()?))
}

fn smb_signing_required(bytes: &[u8]) -> Option<bool> {
    let smb = bytes.windows(4).position(|part| part == b"\xfeSMB")?;
    let security_mode = bytes.get(smb + 66..smb + 68)?;
    Some(u16::from_le_bytes(security_mode.try_into().ok()?) & 0x0002 != 0)
}

fn mssql_encryption_mode(bytes: &[u8]) -> Option<u8> {
    let payload = bytes.get(8..)?;
    for entry in payload.chunks_exact(5) {
        if entry[0] == 0xff {
            break;
        }
        if entry[0] != 0x01 {
            continue;
        }
        let offset = u16::from_be_bytes([entry[1], entry[2]]) as usize;
        return payload.get(offset).copied();
    }
    None
}

fn http_product(banner: &str) -> Option<String> {
    banner
        .split("\\n")
        .find_map(|line| {
            let (header, value) = line.split_once(':')?;
            header.eq_ignore_ascii_case("server").then(|| value.trim())
        })
        .and_then(|value| value.split('/').next())
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn product_token(banner: &str, products: &[&str]) -> Option<String> {
    let lower = banner.to_ascii_lowercase();
    products
        .iter()
        .find(|product| lower.contains(**product))
        .map(|product| product.to_string())
}

fn substring_version(value: &str, marker: &str) -> Option<String> {
    let marker_position = value
        .to_ascii_lowercase()
        .find(&marker.to_ascii_lowercase())?;
    let start = marker_position + marker.len();
    value
        .get(start..)?
        .split(|character: char| {
            character.is_ascii_whitespace()
                || character == '\\'
                || character == ')'
                || character == '-'
        })
        .next()
        .filter(|version| !version.is_empty())
        .map(str::to_string)
}

fn sanitize_banner(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .chars()
        .flat_map(|character| match character {
            '\r' => Vec::new(),
            '\n' => vec!['\\', 'n'],
            character if character.is_control() => {
                format!("\\x{:02x}", character as u32).chars().collect()
            }
            character => vec![character],
        })
        .take(512)
        .collect::<String>()
        .trim()
        .to_string()
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

fn filtered_result(port: u16) -> PortResult {
    empty_result(port, PortState::Filtered)
}

fn closed_result(port: u16) -> PortResult {
    empty_result(port, PortState::Closed)
}

fn empty_result(port: u16, state: PortState) -> PortResult {
    PortResult {
        port,
        state,
        service: None,
        product: None,
        version: None,
        confidence: 0.0,
        banner: None,
        handshake: None,
        auth_required: None,
        tls: None,
        signals: Vec::new(),
    }
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
            browser_crawl_enabled: true,
            browser_crawl_max_pages: 25,
            browser_crawl_max_depth: 2,
            browser_crawl_render_js: false,
            browser_crawl_browser_path: None,
            session_profile: None,
            oast_callback_url: None,
            oast_correlation_id: None,
            oast_database_path: None,
            oast_wait_secs: 0,
            network_connection_budget: 8,
            network_time_budget_secs: 5,
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
    fn test_identify_service_from_nonstandard_banner() {
        assert_eq!(
            identify_service(2222, Some("SSH-2.0-OpenSSH_8.9")),
            Some("ssh".to_string())
        );
        assert_eq!(
            identify_service(2121, Some("220 ProFTPD FTP Server")),
            Some("ftp".to_string())
        );
        assert_eq!(
            identify_service(2525, Some("220 mail.example.com ESMTP")),
            Some("smtp".to_string())
        );
    }

    #[test]
    fn test_parses_database_and_broker_responses() {
        let redis = parse_service_profile(16379, b"-NOAUTH Authentication required.\r\n");
        assert_eq!(redis.protocol.as_deref(), Some("redis"));
        assert_eq!(redis.auth_required, Some(true));
        assert!(redis.signals.contains(&"auth_required".to_string()));
        let memcached = parse_service_profile(11211, b"VERSION 1.6.22\r\n");
        assert_eq!(memcached.version.as_deref(), Some("1.6.22"));
        assert!(
            memcached
                .signals
                .contains(&"unauthenticated_command_accepted".to_string())
        );
        let mysql = parse_service_profile(3306, b"\x0a8.0.36\0fixture");
        assert_eq!(mysql.version.as_deref(), Some("8.0.36"));
        assert_eq!(mysql.auth_required, Some(true));
        let mqtt = parse_service_profile(1883, &[0x20, 0x02, 0x00, 0x05]);
        assert_eq!(mqtt.protocol.as_deref(), Some("mqtt"));
        let mut mongo = vec![0_u8; 16];
        mongo[12..16].copy_from_slice(&2013_i32.to_le_bytes());
        assert_eq!(
            parse_service_profile(27018, &mongo).protocol.as_deref(),
            Some("mongodb")
        );
    }

    #[test]
    fn test_postgres_startup_probe_is_well_formed() {
        let probe = postgres_startup_probe();
        assert_eq!(
            u32::from_be_bytes(probe[..4].try_into().unwrap()) as usize,
            probe.len()
        );
        assert_eq!(&probe[4..8], &[0, 3, 0, 0]);
        assert!(probe.windows(10).any(|value| value == b"temu_probe"));
    }

    #[test]
    fn test_public_routability_excludes_private_and_documentation_ranges() {
        assert!(!is_publicly_routable(IpAddr::from([127, 0, 0, 1])));
        assert!(!is_publicly_routable(IpAddr::from([10, 0, 0, 1])));
        assert!(!is_publicly_routable(IpAddr::from([192, 0, 2, 1])));
        assert!(is_publicly_routable(IpAddr::from([8, 8, 8, 8])));
    }

    #[test]
    fn test_hostname_matching_supports_single_label_wildcard() {
        assert!(hostname_matches("api.example.com", "*.example.com"));
        assert!(!hostname_matches("deep.api.example.com", "*.example.com"));
        assert!(!hostname_matches("example.net", "*.example.com"));
    }

    #[test]
    fn test_weak_signature_algorithm_identifies_sha1_and_md5_oids() {
        assert!(weak_signature_algorithm("1.2.840.113549.1.1.5"));
        assert!(weak_signature_algorithm("1.2.840.113549.1.1.4"));
        assert!(!weak_signature_algorithm("1.2.840.113549.1.1.11"));
    }

    #[test]
    fn test_parses_tls_server_hello_header() {
        let evidence = parse_tls_response(&[0x16, 0x03, 0x03, 0x00, 0x02, 0x02, 0x00]).unwrap();
        assert!(evidence.detected);
        assert_eq!(
            evidence.protocol_version.as_deref(),
            Some("TLS 1.2 or newer")
        );
        assert!(parse_tls_response(&[0x15, 0x03, 0x03, 0x00, 0x02]).is_some());
    }

    #[tokio::test]
    async fn test_scan_ports_finds_nonstandard_ssh_banner() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            for _ in 0..2 {
                if let Ok((mut socket, _)) = listener.accept().await {
                    let _ = socket.write_all(b"SSH-2.0-OpenSSH_9.0\r\n").await;
                }
            }
        });

        let results = scan_ports(IpAddr::from([127, 0, 0, 1]), &[port], &test_config()).await;

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].service.as_deref(), Some("ssh"));
        assert_eq!(results[0].product.as_deref(), Some("OpenSSH"));
        assert_eq!(results[0].version.as_deref(), Some("9.0"));
        assert!(results[0].confidence > 0.9);
    }

    #[tokio::test]
    async fn test_scan_ports_profiles_redis_on_nonstandard_port() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            for _ in 0..4 {
                if let Ok((mut socket, _)) = listener.accept().await {
                    let mut request = [0_u8; 64];
                    let size = socket.read(&mut request).await.unwrap_or_default();
                    if request[..size].windows(4).any(|part| part == b"PING") {
                        let _ = socket.write_all(b"+PONG\r\n").await;
                    }
                }
            }
        });

        let results = scan_ports(IpAddr::from([127, 0, 0, 1]), &[port], &test_config()).await;

        assert_eq!(results[0].service.as_deref(), Some("redis"));
        assert_eq!(results[0].auth_required, Some(false));
        assert!(
            results[0]
                .signals
                .contains(&"unauthenticated_command_accepted".to_string())
        );
        assert!(results[0].signals.contains(&"private_or_local".to_string()));
    }
}
