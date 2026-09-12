use anonguard::gateway::chain::{read_socks5_request, send_socks5_reply};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn test_socks5_handshake_and_reply_codes() {
    let (mut client, mut server) = tokio::io::duplex(4096);

    let server_task = tokio::spawn(async move {
        let (host, port) = read_socks5_request(&mut server).await.unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);

        // Simulate ruleset blocked (SSRF / exit policy reject)
        send_socks5_reply(&mut server, 0x02).await.unwrap();
    });

    let client_task = tokio::spawn(async move {
        // 1. Send SOCKS5 greeting (1 method: No Auth)
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();

        // 2. Read auth selection response
        let mut auth_resp = [0u8; 2];
        client.read_exact(&mut auth_resp).await.unwrap();
        assert_eq!(auth_resp, [0x05, 0x00]);

        // 3. Send CONNECT to domain example.com:443
        let mut req = vec![0x05, 0x01, 0x00, 0x03]; // SOCKS5, CONNECT, RSV, DOMAIN
        let domain = b"example.com";
        req.push(domain.len() as u8);
        req.extend_from_slice(domain);
        req.extend_from_slice(&443u16.to_be_bytes());
        client.write_all(&req).await.unwrap();

        // 4. Read CONNECT reply
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[0], 0x05); // SOCKS5
        assert_eq!(reply[1], 0x02); // Connection not allowed by ruleset (REP = 0x02)
    });

    server_task.await.unwrap();
    client_task.await.unwrap();
}

#[tokio::test]
async fn test_socks5_success_reply() {
    let (mut client, mut server) = tokio::io::duplex(4096);

    tokio::spawn(async move {
        let _ = read_socks5_request(&mut server).await.unwrap();
        send_socks5_reply(&mut server, 0x00).await.unwrap();
    });

    // 1. Send auth
    client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut auth_resp = [0u8; 2];
    client.read_exact(&mut auth_resp).await.unwrap();
    assert_eq!(auth_resp, [0x05, 0x00]);

    // 2. Send CONNECT IPv4 1.1.1.1:80
    let req = [0x05, 0x01, 0x00, 0x01, 1, 1, 1, 1, 0x00, 80];
    client.write_all(&req).await.unwrap();

    // 3. Read reply
    let mut reply = [0u8; 10];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[0], 0x05);
    assert_eq!(reply[1], 0x00); // Success (REP = 0x00)
}
