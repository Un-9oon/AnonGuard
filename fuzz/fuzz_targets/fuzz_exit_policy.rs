#![no_main]

use libfuzzer_sys::fuzz_target;
use anonguard::kernel::exit_policy::ExitPolicy;

fuzz_target!(|data: &[u8]| {
    if data.len() < 3 {
        return;
    }

    let policy = ExitPolicy::default();
    let port = u16::from_be_bytes([data[0], data[1]]);
    let rest = &data[2..];

    // Test is_permitted with fuzz-derived hostname string — must never panic
    if let Ok(host_str) = std::str::from_utf8(rest) {
        if !host_str.is_empty() {
            let _ = policy.is_permitted(host_str, port);
        }
    }

    // Test is_ip_permitted with fuzz-derived IPv4 address
    if data.len() >= 6 {
        let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(data[2], data[3], data[4], data[5]));
        let _ = policy.is_ip_permitted(ip);
    }

    // Test is_ip_permitted with fuzz-derived IPv6 address
    if data.len() >= 18 {
        let mut octets = [0u8; 16];
        octets.copy_from_slice(&data[2..18]);
        let ip = std::net::IpAddr::V6(std::net::Ipv6Addr::from(octets));
        let _ = policy.is_ip_permitted(ip);
    }
});
