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

#[tokio::test]
async fn unoffered_authentication_is_rejected_before_connect() {
    for methods in [vec![], vec![2], vec![1, 2, 255]] {
        let (mut client, mut server) = tokio::io::duplex(128);
        let task = tokio::spawn(async move { read_socks5_request(&mut server).await });
        client.write_all(&[5, methods.len() as u8]).await.unwrap();
        client.write_all(&methods).await.unwrap();
        let mut reply = [0; 2];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [5, 255]);
        assert_eq!(
            task.await.unwrap().unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
    }
}

async fn parse_wire_request(request: &[u8]) -> std::io::Result<(String, u16)> {
    let (mut client, mut server) = tokio::io::duplex(1024);
    let task = tokio::spawn(async move { read_socks5_request(&mut server).await });
    client.write_all(&[5, 2, 2, 0]).await.unwrap();
    let mut selection = [0; 2];
    client.read_exact(&mut selection).await.unwrap();
    assert_eq!(selection, [5, 0]);
    client.write_all(request).await.unwrap();
    client.shutdown().await.unwrap();
    task.await.unwrap()
}

#[tokio::test]
async fn malformed_requests_fail_without_rewriting_destinations() {
    for wire in [
        vec![5, 1, 1, 1, 1, 1, 1, 1, 0, 80], // reserved byte
        vec![5, 2, 0, 1, 1, 1, 1, 1, 0, 80], // BIND unsupported
        vec![4, 1, 0, 1, 1, 1, 1, 1, 0, 80],
        vec![5, 1, 0, 7],
        vec![5, 1, 0, 3, 0, 0, 80],
        vec![5, 1, 0, 3, 1, 255, 0, 80],
        vec![5, 1, 0, 3, 3, b'a', 0, b'b', 0, 80],
        vec![5, 1, 0, 3, 3, b'a', b' ', b'b', 0, 80],
        vec![5, 1, 0, 1, 1, 1, 1, 1, 0, 0],
        vec![5, 1, 0, 1, 1, 1],    // truncated address
        vec![5, 1, 0, 3, 5, b'a'], // truncated domain
        vec![5, 1, 0, 4, 0],       // truncated IPv6
    ] {
        assert!(
            parse_wire_request(&wire).await.is_err(),
            "accepted {wire:?}"
        );
    }
}

#[tokio::test]
async fn incoming_ipv6_and_domain_keep_application_bytes_intact() {
    use anonguard::kernel::{build_socks5h_connect_frame, TargetAddress};
    for (target, expected) in [
        (
            TargetAddress::IPv6(std::net::Ipv6Addr::LOCALHOST.octets()),
            "::1",
        ),
        (TargetAddress::Domain("example.com".into()), "example.com"),
        (TargetAddress::IPv4([1, 2, 3, 4]), "1.2.3.4"),
    ] {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let wire = build_socks5h_connect_frame(&target, 443, false).unwrap();
        let task = tokio::spawn(async move {
            let parsed = read_socks5_request(&mut server).await.unwrap();
            let mut body = [0; 4];
            server.read_exact(&mut body).await.unwrap();
            assert_eq!(&body, b"DATA");
            parsed
        });
        client.write_all(&[5, 1, 0]).await.unwrap();
        let mut reply = [0; 2];
        client.read_exact(&mut reply).await.unwrap();
        client.write_all(&wire).await.unwrap();
        client.write_all(b"DATA").await.unwrap();
        assert_eq!(task.await.unwrap(), (expected.into(), 443));
    }
}

async fn upstream_exchange(reply: Vec<u8>, auth_method: u8) -> std::io::Result<Vec<u8>> {
    use anonguard::gateway::chain::socks5_connect_through;
    use tokio::net::{TcpListener, TcpStream};
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let peer = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut greeting = [0; 3];
        stream.read_exact(&mut greeting).await.unwrap();
        assert_eq!(greeting, [5, 1, 0]);
        stream.write_all(&[5, auth_method]).await.unwrap();
        if auth_method != 0 {
            return;
        }
        let mut request = [0; 18];
        stream.read_exact(&mut request).await.unwrap();
        assert_eq!(&request[..5], &[5, 1, 0, 3, 11]);
        assert_eq!(&request[5..16], b"example.com");
        assert_eq!(&request[16..], &443u16.to_be_bytes());
        stream.write_all(&reply).await.unwrap();
    });
    let result = async {
        let socket = TcpStream::connect(address).await?;
        let mut tunnel = socks5_connect_through(socket, "example.com", 443, false).await?;
        let mut body = Vec::new();
        tunnel.read_to_end(&mut body).await?;
        Ok(body)
    }
    .await;
    peer.await.unwrap();
    result
}

#[tokio::test]
async fn upstream_bound_addresses_leave_payload_in_the_tunnel() {
    for address in [
        vec![1, 0, 0, 0, 0, 0, 0],
        {
            let mut a = vec![4];
            a.extend_from_slice(&[0; 18]);
            a
        },
        vec![3, 3, b'f', b'o', b'o', 0, 0],
    ] {
        let mut response = vec![5, 0, 0];
        response.extend(address);
        response.extend(b"application response");
        assert_eq!(
            upstream_exchange(response, 0).await.unwrap(),
            b"application response"
        );
    }
}

#[tokio::test]
async fn upstream_unoffered_methods_and_malformed_replies_fail() {
    for method in [1, 2, 255] {
        assert!(upstream_exchange(vec![], method).await.is_err());
    }
    for response in [
        vec![4, 0, 0, 1],
        vec![5, 5, 0, 1],
        vec![5, 0, 1, 1],
        vec![5, 0, 0, 7],
        vec![5, 0, 0, 3, 0],
        vec![5, 0, 0, 1, 0],
    ] {
        assert!(upstream_exchange(response, 0).await.is_err());
    }
}

#[test]
fn outbound_invalid_destinations_and_ipv6_policy_fail_before_serialization() {
    use anonguard::kernel::{build_socks5h_connect_frame, TargetAddress};
    for host in ["", "a\0b", "a b", "é", &"a".repeat(256)] {
        assert!(
            build_socks5h_connect_frame(&TargetAddress::Domain(host.into()), 443, false).is_err()
        );
    }
    assert!(build_socks5h_connect_frame(&TargetAddress::IPv4([1; 4]), 0, false).is_err());
    assert_eq!(
        build_socks5h_connect_frame(&TargetAddress::IPv6([0; 16]), 443, true)
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::PermissionDenied
    );
}
