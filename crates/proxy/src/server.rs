use std::{
    collections::BTreeSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use tokio::{
    io::{
        AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt,
        BufReader,
    },
    net::{TcpListener, TcpStream, lookup_host},
    sync::{Semaphore, watch},
    task::JoinSet,
    time::{Instant, timeout, timeout_at},
};
use tracing::{debug, info, warn};

use crate::{allowlist::DomainAllowlist, error::ProxyError};

/// Resource and destination limits for the trusted local proxy.
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub max_request_line_bytes: usize,
    pub max_header_line_bytes: usize,
    pub max_header_bytes: usize,
    pub max_headers: usize,
    pub max_connections: usize,
    pub max_resolved_addresses: usize,
    pub header_timeout: Duration,
    pub dns_timeout: Duration,
    pub connect_timeout: Duration,
    pub idle_timeout: Duration,
    pub tunnel_timeout: Duration,
    pub allowed_ports: BTreeSet<u16>,
    /// Tests and explicitly trusted local-development profiles may opt in.
    pub allow_special_addresses: bool,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            max_request_line_bytes: 8 * 1024,
            max_header_line_bytes: 8 * 1024,
            max_header_bytes: 32 * 1024,
            max_headers: 64,
            max_connections: 64,
            max_resolved_addresses: 32,
            header_timeout: Duration::from_secs(10),
            dns_timeout: Duration::from_secs(10),
            connect_timeout: Duration::from_secs(15),
            idle_timeout: Duration::from_secs(60),
            tunnel_timeout: Duration::from_secs(30 * 60),
            allowed_ports: BTreeSet::from([443]),
            allow_special_addresses: false,
        }
    }
}

/// Per-run endpoint information injected into the sandbox environment.
#[derive(Clone)]
pub struct ProxyEndpoint {
    pub port: u16,
    token: String,
}

impl std::fmt::Debug for ProxyEndpoint {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProxyEndpoint")
            .field("port", &self.port)
            .field("token", &"<redacted>")
            .finish()
    }
}

impl ProxyEndpoint {
    pub fn url(&self) -> String {
        format!("http://sbe:{}@127.0.0.1:{}", self.token, self.port)
    }

    pub fn authorization_header(&self) -> String {
        format!(
            "Basic {}",
            BASE64_STANDARD.encode(format!("sbe:{}", self.token))
        )
    }

    fn java_tool_options(&self, agent_path: &str) -> String {
        format!(
            "-javaagent:{agent_path} \
             -Dhttp.proxyHost=127.0.0.1 -Dhttp.proxyPort={} \
             -Dhttp.proxyProtocol=http \
             -Dhttps.proxyHost=127.0.0.1 -Dhttps.proxyPort={} \
             -Dhttps.proxyProtocol=http \
             -Dhttp.nonProxyHosts= \
             -Djdk.http.auth.tunneling.disabledSchemes=",
            self.port, self.port
        )
    }

    /// Runtime variables for JVM clients. The one-time token stays outside
    /// `JAVA_TOOL_OPTIONS`, which the JVM prints to stderr on every launch.
    pub fn java_environment(&self, agent_path: &str) -> [(&'static str, String); 2] {
        [
            ("JAVA_TOOL_OPTIONS", self.java_tool_options(agent_path)),
            ("SBE_PROXY_TOKEN", self.token.clone()),
        ]
    }
}

/// A bounded, authenticated, domain-filtering HTTP CONNECT proxy.
pub struct ProxyServer {
    listener: TcpListener,
    allowlist: Arc<DomainAllowlist>,
    config: Arc<ProxyConfig>,
    authorization: Arc<str>,
    shutdown_rx: watch::Receiver<bool>,
}

impl ProxyServer {
    pub async fn bind(
        allowlist: DomainAllowlist,
        shutdown_rx: watch::Receiver<bool>,
    ) -> Result<(Self, ProxyEndpoint), ProxyError> {
        Self::bind_with_config(allowlist, shutdown_rx, ProxyConfig::default()).await
    }

    pub async fn bind_with_config(
        allowlist: DomainAllowlist,
        shutdown_rx: watch::Receiver<bool>,
        config: ProxyConfig,
    ) -> Result<(Self, ProxyEndpoint), ProxyError> {
        if config.max_connections == 0
            || config.max_request_line_bytes == 0
            || config.max_header_line_bytes == 0
            || config.max_header_bytes == 0
            || config.max_headers == 0
            || config.max_resolved_addresses == 0
            || config.allowed_ports.is_empty()
            || config.header_timeout.is_zero()
            || config.dns_timeout.is_zero()
            || config.connect_timeout.is_zero()
            || config.idle_timeout.is_zero()
            || config.tunnel_timeout.is_zero()
        {
            return Err(ProxyError::Config(
                "proxy limits and allowed ports must be non-zero".to_owned(),
            ));
        }
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(ProxyError::Bind)?;
        let port = listener.local_addr().map_err(ProxyError::Bind)?.port();
        let mut random = [0_u8; 32];
        getrandom::fill(&mut random)
            .map_err(|e| ProxyError::Config(format!("proxy authentication RNG failed: {e}")))?;
        let endpoint = ProxyEndpoint {
            port,
            token: hex(&random),
        };
        let authorization: Arc<str> = endpoint.authorization_header().into();
        info!(port, "sbe proxy listening");
        Ok((
            Self {
                listener,
                allowlist: Arc::new(allowlist),
                config: Arc::new(config),
                authorization,
                shutdown_rx,
            },
            endpoint,
        ))
    }

    /// Run until shutdown and keep every connection task inside this lifecycle.
    pub async fn run(self) -> Result<(), ProxyError> {
        let mut shutdown = self.shutdown_rx;
        let semaphore = Arc::new(Semaphore::new(self.config.max_connections));
        let mut tasks = JoinSet::new();
        loop {
            tokio::select! {
                result = self.listener.accept() => {
                    let (stream, addr) = result.map_err(ProxyError::Accept)?;
                    let Ok(permit) = Arc::clone(&semaphore).try_acquire_owned() else {
                        warn!(client = %addr, "proxy connection limit reached");
                        drop(stream);
                        continue;
                    };
                    let allowlist = Arc::clone(&self.allowlist);
                    let config = Arc::clone(&self.config);
                    let authorization = Arc::clone(&self.authorization);
                    tasks.spawn(async move {
                        let _permit = permit;
                        if let Err(error) = handle_connection(
                            stream, addr, &allowlist, &config, &authorization,
                        ).await {
                            debug!(%error, client = %addr, "proxy connection error");
                        }
                    });
                }
                Some(result) = tasks.join_next(), if !tasks.is_empty() => {
                    if let Err(error) = result {
                        warn!(%error, "proxy connection task failed");
                    }
                }
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
            }
        }
        tasks.shutdown().await;
        info!("sbe proxy shut down");
        Ok(())
    }
}

async fn handle_connection(
    client: TcpStream,
    addr: SocketAddr,
    allowlist: &DomainAllowlist,
    config: &ProxyConfig,
    expected_authorization: &str,
) -> Result<(), ProxyError> {
    let mut client = BufReader::new(client);
    let header_deadline = Instant::now() + config.header_timeout;
    let request_line = timeout_at(
        header_deadline,
        read_bounded_line(&mut client, config.max_request_line_bytes),
    )
    .await
    .map_err(|_| ProxyError::Timeout("request line"))??;
    if request_line.is_empty() {
        return Ok(());
    }
    let request = std::str::from_utf8(&request_line)
        .map_err(|_| ProxyError::Protocol("request line is not UTF-8".to_owned()))?
        .trim_end_matches(['\r', '\n']);
    let mut parts = request.split_ascii_whitespace();
    let method = parts.next().unwrap_or_default();
    let target = parts.next().unwrap_or_default();
    let version = parts.next().unwrap_or_default();
    if parts.next().is_some()
        || !method.eq_ignore_ascii_case("CONNECT")
        || target.is_empty()
        || !matches!(version, "HTTP/1.0" | "HTTP/1.1")
    {
        write_response(&mut client, 400, "Bad Request").await?;
        return Err(ProxyError::Protocol(
            "invalid CONNECT request line".to_owned(),
        ));
    }

    let mut header_bytes = 0_usize;
    let mut header_count = 0_usize;
    let mut authorized = false;
    loop {
        let remaining = config.max_header_bytes.saturating_sub(header_bytes);
        if remaining == 0 {
            write_response(&mut client, 431, "Request Header Fields Too Large").await?;
            return Err(ProxyError::Limit("total header bytes"));
        }
        let line = timeout_at(
            header_deadline,
            read_bounded_line(&mut client, remaining.min(config.max_header_line_bytes)),
        )
        .await
        .map_err(|_| ProxyError::Timeout("request headers"))??;
        header_bytes = header_bytes.saturating_add(line.len());
        if line == b"\r\n" || line == b"\n" || line.is_empty() {
            break;
        }
        header_count += 1;
        if header_count > config.max_headers {
            write_response(&mut client, 431, "Request Header Fields Too Large").await?;
            return Err(ProxyError::Limit("header count"));
        }
        let line = std::str::from_utf8(&line)
            .map_err(|_| ProxyError::Protocol("header is not UTF-8".to_owned()))?;
        let (name, value) = line
            .trim_end_matches(['\r', '\n'])
            .split_once(':')
            .ok_or_else(|| ProxyError::Protocol("malformed header".to_owned()))?;
        if name.eq_ignore_ascii_case("Proxy-Authorization")
            && constant_time_eq(value.trim().as_bytes(), expected_authorization.as_bytes())
        {
            authorized = true;
        }
    }
    if !authorized {
        client.write_all(
            b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"sbe\"\r\nConnection: close\r\n\r\n"
        ).await?;
        return Err(ProxyError::Unauthorized);
    }

    let (host, port) = parse_authority(target)?;
    if !config.allowed_ports.contains(&port) {
        write_response(&mut client, 403, "Forbidden").await?;
        return Err(ProxyError::Destination(format!(
            "port {port} is not authorized"
        )));
    }
    if !allowlist.is_allowed(&host) {
        write_response(&mut client, 403, "Forbidden").await?;
        warn!(%host, port, client = %addr, "blocked non-allowlisted domain");
        return Err(ProxyError::Destination(format!(
            "domain '{host}' is not authorized"
        )));
    }

    let resolved = timeout(config.dns_timeout, lookup_host((host.as_str(), port)))
        .await
        .map_err(|_| ProxyError::Timeout("DNS resolution"))??;
    let mut addresses = BTreeSet::new();
    for address in resolved {
        addresses.insert(address);
        if addresses.len() > config.max_resolved_addresses {
            write_response(&mut client, 502, "Bad Gateway").await?;
            return Err(ProxyError::Limit("resolved address count"));
        }
    }
    if addresses.is_empty() {
        return Err(ProxyError::Destination(format!(
            "domain '{host}' resolved to no addresses"
        )));
    }
    if !config.allow_special_addresses && addresses.iter().any(|a| !is_global(a.ip())) {
        write_response(&mut client, 403, "Forbidden").await?;
        return Err(ProxyError::Destination(format!(
            "domain '{host}' resolved to a special-use address"
        )));
    }
    let mut upstream = timeout(
        config.connect_timeout,
        connect_to_validated_address(&host, port, &addresses),
    )
    .await
    .map_err(|_| ProxyError::Timeout("upstream connection"))??;
    client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;
    client.flush().await?;
    debug!(%host, port, client = %addr, "proxy tunnel established");

    let buffered = client.buffer().to_vec();
    if !buffered.is_empty() {
        timeout(config.idle_timeout, upstream.write_all(&buffered))
            .await
            .map_err(|_| ProxyError::Timeout("initial tunnel write"))??;
    }
    let client = client.into_inner();
    let (client_read, client_write) = client.into_split();
    let (upstream_read, upstream_write) = upstream.into_split();
    let tunnel = async {
        tokio::try_join!(
            copy_with_idle_timeout(client_read, upstream_write, config.idle_timeout),
            copy_with_idle_timeout(upstream_read, client_write, config.idle_timeout),
        )
    };
    timeout(config.tunnel_timeout, tunnel)
        .await
        .map_err(|_| ProxyError::Timeout("maximum tunnel lifetime"))??;
    Ok(())
}

async fn connect_to_validated_address(
    host: &str,
    port: u16,
    addresses: &BTreeSet<SocketAddr>,
) -> Result<TcpStream, ProxyError> {
    let mut last_error = None;
    for &address in addresses {
        match TcpStream::connect(address).await {
            Ok(stream) => return Ok(stream),
            Err(error) => last_error = Some(error),
        }
    }
    Err(ProxyError::UpstreamConnect {
        host: host.to_owned(),
        port,
        source: last_error.unwrap_or_else(|| std::io::Error::other("no usable address")),
    })
}

async fn copy_with_idle_timeout<R, W>(
    mut reader: R,
    mut writer: W,
    idle_timeout: Duration,
) -> Result<u64, ProxyError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut copied = 0_u64;
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let count = timeout(idle_timeout, reader.read(&mut buffer))
            .await
            .map_err(|_| ProxyError::Timeout("tunnel idle period"))??;
        if count == 0 {
            writer.shutdown().await?;
            return Ok(copied);
        }
        writer.write_all(&buffer[..count]).await?;
        copied = copied.saturating_add(count as u64);
    }
}

async fn read_bounded_line<R>(reader: &mut R, maximum: usize) -> Result<Vec<u8>, ProxyError>
where
    R: AsyncBufRead + Unpin,
{
    let mut output = Vec::new();
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return Ok(output);
        }
        let consumed = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(available.len(), |index| index + 1);
        if output.len().saturating_add(consumed) > maximum {
            return Err(ProxyError::Limit("line bytes"));
        }
        output.extend_from_slice(&available[..consumed]);
        reader.consume(consumed);
        if output.last() == Some(&b'\n') {
            return Ok(output);
        }
    }
}

fn parse_authority(target: &str) -> Result<(String, u16), ProxyError> {
    if target.starts_with('[') || target.parse::<IpAddr>().is_ok() {
        return Err(ProxyError::Destination(
            "IP literals are not authorized".to_owned(),
        ));
    }
    let (raw_host, raw_port) = target
        .rsplit_once(':')
        .ok_or_else(|| ProxyError::Protocol("CONNECT target has no port".to_owned()))?;
    if raw_host.is_empty() || raw_host.contains(':') {
        return Err(ProxyError::Protocol(
            "CONNECT target has an invalid host".to_owned(),
        ));
    }
    let port = raw_port
        .parse::<u16>()
        .map_err(|_| ProxyError::Protocol("CONNECT target has an invalid port".to_owned()))?;
    if port == 0 {
        return Err(ProxyError::Protocol(
            "CONNECT target port must be non-zero".to_owned(),
        ));
    }
    let host = idna::domain_to_ascii(raw_host.trim_end_matches('.'))
        .map_err(|_| ProxyError::Protocol("CONNECT target has invalid IDNA".to_owned()))?
        .to_ascii_lowercase();
    validate_dns_name(&host)?;
    Ok((host, port))
}

fn validate_dns_name(host: &str) -> Result<(), ProxyError> {
    if host.is_empty() || host.len() > 253 || host.parse::<IpAddr>().is_ok() {
        return Err(ProxyError::Protocol("invalid DNS hostname".to_owned()));
    }
    for label in host.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err(ProxyError::Protocol("invalid DNS hostname".to_owned()));
        }
    }
    Ok(())
}

fn is_global(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_global_v4(ip),
        IpAddr::V6(ip) => is_global_v6(ip),
    }
}

fn is_global_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_unspecified()
        || ip.is_multicast()
        || a == 0
        || a >= 240
        || (a == 100 && (64..=127).contains(&b))
        || (a == 192 && b == 0 && c == 0)
        || (a == 192 && b == 88 && c == 99)
        || (a == 198 && (18..=19).contains(&b)))
}

fn is_global_v6(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();
    if let Some(mapped) = ip.to_ipv4_mapped() {
        return is_global_v4(mapped);
    }
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || (segments[0] & 0xfe00) == 0xfc00
        || (segments[0] & 0xffc0) == 0xfe80
        || (segments[0] & 0xffc0) == 0xfec0
        // Local-use translation, discard-only, and IETF protocol-assignment
        // blocks are not ordinary globally routable destinations.
        || (segments[0] == 0x0064 && segments[1] == 0xff9b && segments[2] == 1)
        || (segments[0] == 0x0100
            && segments[1] == 0
            && segments[2] == 0
            && segments[3] == 0)
        || (segments[0] == 0x2001 && segments[1] <= 0x01ff)
        || (segments[0] == 0x2001 && segments[1] == 0x0db8)
        || (segments[0] == 0x3fff && segments[1] < 0x1000)
        || segments[0] == 0x5f00)
}

async fn write_response<W: AsyncWrite + Unpin>(
    stream: &mut W,
    status: u16,
    reason: &str,
) -> Result<(), ProxyError> {
    stream
        .write_all(format!("HTTP/1.1 {status} {reason}\r\nConnection: close\r\n\r\n").as_bytes())
        .await?;
    Ok(())
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0_u8;
    for (&left, &right) in left.iter().zip(right) {
        difference |= left ^ right;
    }
    difference == 0
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_canonicalizes_authority() {
        assert_eq!(
            parse_authority("Registry.NPMJS.org.:443").unwrap(),
            ("registry.npmjs.org".to_owned(), 443)
        );
    }

    #[test]
    fn endpoint_debug_output_redacts_authentication_token() {
        let endpoint = ProxyEndpoint {
            port: 12345,
            token: "sentinel-token".to_owned(),
        };
        let output = format!("{endpoint:?}");
        assert!(output.contains("<redacted>"));
        assert!(!output.contains("sentinel-token"));
    }

    #[test]
    fn java_environment_uses_agent_without_logging_token() {
        let endpoint = ProxyEndpoint {
            port: 12345,
            token: "sentinel-token".to_owned(),
        };
        let environment = endpoint.java_environment("/private/sbe/proxy-agent.jar");
        let options = &environment[0].1;

        assert!(options.contains("-javaagent:/private/sbe/proxy-agent.jar"));
        assert!(options.contains("-Dhttp.proxyProtocol=http"));
        assert!(options.contains("-Dhttps.proxyProtocol=http"));
        assert!(options.contains("-Djdk.http.auth.tunneling.disabledSchemes="));
        assert!(!options.contains("sentinel-token"));
        assert_eq!(
            environment[1],
            ("SBE_PROXY_TOKEN", "sentinel-token".to_owned())
        );
    }

    #[test]
    fn malformed_or_literal_authorities_never_panic() {
        for target in ["]:443", "[::1]:443", "127.0.0.1:443", "a:b:443", "x:0", "x"] {
            assert!(parse_authority(target).is_err(), "accepted {target}");
        }
    }

    #[test]
    fn special_addresses_are_not_global() {
        for address in [
            "127.0.0.1",
            "10.0.0.1",
            "169.254.1.1",
            "192.0.2.1",
            "::1",
            "fe80::1",
            "fc00::1",
            "2001:db8::1",
            "64:ff9b:1::1",
            "100::1",
            "2001:20::1",
            "3fff::1",
            "5f00::1",
            "fec0::1",
        ] {
            assert!(!is_global(address.parse().unwrap()), "accepted {address}");
        }
        assert!(is_global("1.1.1.1".parse().unwrap()));
        assert!(is_global("2606:4700:4700::1111".parse().unwrap()));
    }

    #[tokio::test]
    async fn bounded_line_reader_rejects_oversized_input() {
        let (mut writer, reader) = tokio::io::duplex(128);
        tokio::spawn(async move {
            writer.write_all(&[b'a'; 65]).await.unwrap();
            writer.write_all(b"\n").await.unwrap();
        });
        let mut reader = BufReader::new(reader);
        assert!(matches!(
            read_bounded_line(&mut reader, 64).await,
            Err(ProxyError::Limit(_))
        ));
    }

    #[tokio::test]
    async fn tunnel_copy_enforces_idle_timeout() {
        let (_writer, reader) = tokio::io::duplex(64);
        let (_reader, output) = tokio::io::duplex(64);
        assert!(matches!(
            copy_with_idle_timeout(reader, output, Duration::from_millis(10)).await,
            Err(ProxyError::Timeout("tunnel idle period"))
        ));
    }
}
