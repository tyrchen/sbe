use std::collections::BTreeSet;

use sbe_proxy::{ProxyConfig, ProxyServer, allowlist::DomainAllowlist};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    sync::watch,
    time::{Duration, sleep, timeout},
};

#[tokio::test]
async fn test_should_reject_non_allowed_domain() {
    let allowlist = DomainAllowlist::new(&["registry.npmjs.org".to_owned()]).unwrap();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (server, endpoint) = ProxyServer::bind(allowlist, shutdown_rx).await.unwrap();

    let server_handle = tokio::spawn(async move { server.run().await });

    // Connect and send CONNECT to a blocked domain
    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", endpoint.port))
        .await
        .unwrap();
    stream
        .write_all(
            format!(
                "CONNECT evil.com:443 HTTP/1.1\r\nHost: evil.com\r\nProxy-Authorization: \
                 {}\r\n\r\n",
                endpoint.authorization_header()
            )
            .as_bytes(),
        )
        .await
        .unwrap();

    let reader = BufReader::new(&mut stream);
    let mut response_line = String::new();
    let mut lines = reader.lines();
    if let Some(line) = lines.next_line().await.unwrap() {
        response_line = line;
    }

    assert!(
        response_line.contains("403"),
        "expected 403 Forbidden, got: {response_line}"
    );

    let _ = shutdown_tx.send(true);
    let _ = server_handle.await;
}

#[tokio::test]
async fn test_should_reject_non_connect_methods() {
    let allowlist = DomainAllowlist::new(&["registry.npmjs.org".to_owned()]).unwrap();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (server, endpoint) = ProxyServer::bind(allowlist, shutdown_rx).await.unwrap();

    let server_handle = tokio::spawn(async move { server.run().await });

    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", endpoint.port))
        .await
        .unwrap();
    stream
        .write_all(b"GET http://evil.com/ HTTP/1.1\r\nHost: evil.com\r\n\r\n")
        .await
        .unwrap();

    let reader = BufReader::new(&mut stream);
    let mut response_line = String::new();
    let mut lines = reader.lines();
    if let Some(line) = lines.next_line().await.unwrap() {
        response_line = line;
    }

    assert!(
        response_line.contains("400"),
        "expected 400 Bad Request, got: {response_line}"
    );

    let _ = shutdown_tx.send(true);
    let _ = server_handle.await;
}

#[tokio::test]
async fn test_should_allow_permitted_domain() {
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_port = upstream.local_addr().unwrap().port();
    let upstream_task = tokio::spawn(async move {
        let _ = upstream.accept().await.unwrap();
    });
    let allowlist = DomainAllowlist::new(&["localhost".to_owned()]).unwrap();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let config = ProxyConfig {
        allowed_ports: BTreeSet::from([upstream_port]),
        allow_special_addresses: true,
        ..ProxyConfig::default()
    };
    let (server, endpoint) = ProxyServer::bind_with_config(allowlist, shutdown_rx, config)
        .await
        .unwrap();

    let server_handle = tokio::spawn(async move { server.run().await });

    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", endpoint.port))
        .await
        .unwrap();
    stream
        .write_all(
            format!(
                "CONNECT localhost:{upstream_port} HTTP/1.1\r\nHost: \
                 localhost\r\nProxy-Authorization: {}\r\n\r\n",
                endpoint.authorization_header()
            )
            .as_bytes(),
        )
        .await
        .unwrap();

    let reader = BufReader::new(&mut stream);
    let mut response_line = String::new();
    let mut lines = reader.lines();
    if let Some(line) = lines.next_line().await.unwrap() {
        response_line = line;
    }

    assert!(
        response_line.contains("200"),
        "expected 200 Connection Established, got: {response_line}"
    );

    let _ = shutdown_tx.send(true);
    let _ = server_handle.await;
    upstream_task.await.unwrap();
}

#[tokio::test]
async fn test_should_require_per_run_authentication() {
    let allowlist = DomainAllowlist::new(&["registry.npmjs.org".to_owned()]).unwrap();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (server, endpoint) = ProxyServer::bind(allowlist, shutdown_rx).await.unwrap();
    let server_handle = tokio::spawn(server.run());

    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", endpoint.port))
        .await
        .unwrap();
    stream
        .write_all(b"CONNECT registry.npmjs.org:443 HTTP/1.1\r\nHost: registry.npmjs.org\r\n\r\n")
        .await
        .unwrap();
    let mut response = String::new();
    BufReader::new(&mut stream)
        .read_line(&mut response)
        .await
        .unwrap();
    assert!(response.contains("407"));

    let _ = shutdown_tx.send(true);
    let _ = server_handle.await;
}

#[tokio::test]
async fn test_should_reject_unlisted_connect_port_before_dns() {
    let allowlist = DomainAllowlist::new(&["registry.npmjs.org".to_owned()]).unwrap();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (server, endpoint) = ProxyServer::bind(allowlist, shutdown_rx).await.unwrap();
    let server_handle = tokio::spawn(server.run());

    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", endpoint.port))
        .await
        .unwrap();
    stream
        .write_all(
            format!(
                "CONNECT registry.npmjs.org:8443 HTTP/1.1\r\nProxy-Authorization: {}\r\n\r\n",
                endpoint.authorization_header()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let mut response = String::new();
    BufReader::new(&mut stream)
        .read_line(&mut response)
        .await
        .unwrap();
    assert!(response.contains("403"));

    let _ = shutdown_tx.send(true);
    let _ = server_handle.await;
}

#[tokio::test]
async fn test_should_reject_special_use_resolution_before_connect() {
    let allowlist = DomainAllowlist::new(&["localhost".to_owned()]).unwrap();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (server, endpoint) = ProxyServer::bind(allowlist, shutdown_rx).await.unwrap();
    let server_handle = tokio::spawn(server.run());

    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", endpoint.port))
        .await
        .unwrap();
    stream
        .write_all(
            format!(
                "CONNECT localhost:443 HTTP/1.1\r\nProxy-Authorization: {}\r\n\r\n",
                endpoint.authorization_header()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let mut response = String::new();
    BufReader::new(&mut stream)
        .read_line(&mut response)
        .await
        .unwrap();
    assert!(response.contains("403"));

    let _ = shutdown_tx.send(true);
    let _ = server_handle.await;
}

#[tokio::test]
async fn test_should_enforce_header_count_limit() {
    let allowlist = DomainAllowlist::new(&["registry.npmjs.org".to_owned()]).unwrap();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let config = ProxyConfig {
        max_headers: 1,
        ..ProxyConfig::default()
    };
    let (server, endpoint) = ProxyServer::bind_with_config(allowlist, shutdown_rx, config)
        .await
        .unwrap();
    let server_handle = tokio::spawn(server.run());

    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", endpoint.port))
        .await
        .unwrap();
    stream
        .write_all(
            format!(
                "CONNECT registry.npmjs.org:443 HTTP/1.1\r\nProxy-Authorization: {}\r\nX-Extra: \
                 rejected\r\n\r\n",
                endpoint.authorization_header()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let mut response = String::new();
    BufReader::new(&mut stream)
        .read_line(&mut response)
        .await
        .unwrap();
    assert!(response.contains("431"));

    let _ = shutdown_tx.send(true);
    server_handle.await.unwrap().unwrap();
}

#[tokio::test]
async fn test_should_enforce_total_header_byte_limit() {
    let allowlist = DomainAllowlist::new(&["registry.npmjs.org".to_owned()]).unwrap();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let config = ProxyConfig {
        max_header_bytes: 8,
        ..ProxyConfig::default()
    };
    let (server, endpoint) = ProxyServer::bind_with_config(allowlist, shutdown_rx, config)
        .await
        .unwrap();
    let server_handle = tokio::spawn(server.run());

    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", endpoint.port))
        .await
        .unwrap();
    stream
        .write_all(b"CONNECT registry.npmjs.org:443 HTTP/1.1\r\nX-Oversized: value\r\n\r\n")
        .await
        .unwrap();
    let mut byte = [0_u8; 1];
    let result = timeout(Duration::from_secs(1), stream.read(&mut byte))
        .await
        .expect("proxy did not close an oversized header request");
    assert!(matches!(result, Ok(0) | Err(_)));

    let _ = shutdown_tx.send(true);
    server_handle.await.unwrap().unwrap();
}

#[tokio::test]
async fn test_should_enforce_one_deadline_for_slow_headers() {
    let allowlist = DomainAllowlist::new(&["registry.npmjs.org".to_owned()]).unwrap();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let config = ProxyConfig {
        header_timeout: Duration::from_millis(20),
        ..ProxyConfig::default()
    };
    let (server, endpoint) = ProxyServer::bind_with_config(allowlist, shutdown_rx, config)
        .await
        .unwrap();
    let server_handle = tokio::spawn(server.run());

    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", endpoint.port))
        .await
        .unwrap();
    stream
        .write_all(b"CONNECT registry.npmjs.org:443 HTTP/1.1\r\n")
        .await
        .unwrap();
    let mut byte = [0_u8; 1];
    let result = timeout(Duration::from_secs(1), stream.read(&mut byte))
        .await
        .expect("proxy did not enforce its header deadline");
    assert!(matches!(result, Ok(0) | Err(_)));

    let _ = shutdown_tx.send(true);
    server_handle.await.unwrap().unwrap();
}

#[tokio::test]
async fn test_should_drop_connections_above_the_concurrency_limit() {
    let allowlist = DomainAllowlist::new(&["registry.npmjs.org".to_owned()]).unwrap();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let config = ProxyConfig {
        max_connections: 1,
        header_timeout: Duration::from_secs(2),
        ..ProxyConfig::default()
    };
    let (server, endpoint) = ProxyServer::bind_with_config(allowlist, shutdown_rx, config)
        .await
        .unwrap();
    let server_handle = tokio::spawn(server.run());

    let mut held = TcpStream::connect(format!("127.0.0.1:{}", endpoint.port))
        .await
        .unwrap();
    held.write_all(b"partial request").await.unwrap();
    sleep(Duration::from_millis(20)).await;

    let mut rejected = TcpStream::connect(format!("127.0.0.1:{}", endpoint.port))
        .await
        .unwrap();
    let mut byte = [0_u8; 1];
    let result = timeout(Duration::from_secs(1), rejected.read(&mut byte))
        .await
        .expect("excess connection was not closed");
    assert!(matches!(result, Ok(0) | Err(_)));

    let _ = shutdown_tx.send(true);
    server_handle.await.unwrap().unwrap();
}
