use anonguard::kernel::{build_socks5h_connect_frame, TargetAddress};

#[test]
fn test_socks5h_domain_frame_construction() {
    let target = TargetAddress::Domain("api.target.com".to_string());
    let frame = build_socks5h_connect_frame(&target, 443, true).unwrap();

    assert_eq!(frame[0], 0x05); // Version
    assert_eq!(frame[1], 0x01); // CMD_CONNECT
    assert_eq!(frame[2], 0x00); // Reserved
    assert_eq!(frame[3], 0x03); // ADDR_TYPE_DOMAIN (SOCKS5h)
    assert_eq!(frame[4], 14); // Length of "api.target.com"
    assert_eq!(&frame[5..19], b"api.target.com");

    // Big-endian port 443 -> [0x01, 0xbb]
    assert_eq!(&frame[19..21], &[0x01, 0xbb]);
}

#[test]
fn test_socks5h_ipv6_blocking_policy() {
    let target = TargetAddress::IPv6([0; 16]);
    let result = build_socks5h_connect_frame(&target, 80, true);
    assert!(
        result.is_err(),
        "IPv6 should be rejected when block_ipv6 is true"
    );
}
