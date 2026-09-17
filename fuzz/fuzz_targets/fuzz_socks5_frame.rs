#![no_main]

use libfuzzer_sys::fuzz_target;
use anonguard::kernel::dns::{build_socks5h_connect_frame, TargetAddress};

fuzz_target!(|data: &[u8]| {
    if data.len() < 3 {
        return;
    }

    let port = u16::from_be_bytes([data[0], data[1]]);
    let block_ipv6 = data[2] & 1 == 1;
    let rest = &data[3..];

    // Test Domain variant
    if let Ok(s) = std::str::from_utf8(rest) {
        let target = TargetAddress::Domain(s.to_string());
        let _ = build_socks5h_connect_frame(&target, port, block_ipv6);
    }

    // Test IPv4 variant
    if rest.len() >= 4 {
        let target = TargetAddress::IPv4([rest[0], rest[1], rest[2], rest[3]]);
        let _ = build_socks5h_connect_frame(&target, port, block_ipv6);
    }

    // Test IPv6 variant
    if rest.len() >= 16 {
        let mut ip = [0u8; 16];
        ip.copy_from_slice(&rest[..16]);
        let target = TargetAddress::IPv6(ip);
        let _ = build_socks5h_connect_frame(&target, port, block_ipv6);
    }
});
