use sbe_proxy::{ProxyServer, allowlist::DomainAllowlist};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
    sync::watch,
};

#[tokio::test]
async fn test_should_reject_non_allowed_domain() {
    let allowlist = DomainAllowlist::new(&["registry.npmjs.org".to_owned()]);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (server, port) = ProxyServer::bind(allowlist, shutdown_rx).await.unwrap();

    let server_handle = tokio::spawn(async move { server.run().await });

    // Connect and send CONNECT to a blocked domain
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap();
    stream
        .write_all(b"CONNECT evil.com:443 HTTP/1.1\r\nHost: evil.com\r\n\r\n")
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
    let allowlist = DomainAllowlist::new(&["registry.npmjs.org".to_owned()]);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (server, port) = ProxyServer::bind(allowlist, shutdown_rx).await.unwrap();

    let server_handle = tokio::spawn(async move { server.run().await });

    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
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
        response_line.contains("405"),
        "expected 405 Method Not Allowed, got: {response_line}"
    );

    let _ = shutdown_tx.send(true);
    let _ = server_handle.await;
}

#[tokio::test]
async fn test_should_allow_permitted_domain() {
    let allowlist = DomainAllowlist::new(&["registry.npmjs.org".to_owned()]);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (server, port) = ProxyServer::bind(allowlist, shutdown_rx).await.unwrap();

    let server_handle = tokio::spawn(async move { server.run().await });

    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap();
    stream
        .write_all(b"CONNECT registry.npmjs.org:443 HTTP/1.1\r\nHost: registry.npmjs.org\r\n\r\n")
        .await
        .unwrap();

    let reader = BufReader::new(&mut stream);
    let mut response_line = String::new();
    let mut lines = reader.lines();
    if let Some(line) = lines.next_line().await.unwrap() {
        response_line = line;
    }

    // Should get 200 Connection Established (upstream connects to real server)
    assert!(
        response_line.contains("200"),
        "expected 200 Connection Established, got: {response_line}"
    );

    let _ = shutdown_tx.send(true);
    let _ = server_handle.await;
}
