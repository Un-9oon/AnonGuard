//! Embedded IPv4 representations must not bypass circuit subnet diversity.
//! Address layouts: RFC 3056 (6to4), RFC 4380 (Teredo), RFC 6052 (NAT64).
use anonguard::mesh::sybil::{validate_circuit_diversity, SybilError};

#[test]
fn embedded_ipv4_aliases_collide_in_both_selection_orders() {
    // Every alias embeds 192.0.2.2, sharing /16 with 192.0.2.1.
    for alias in [
        "[::ffff:192.0.2.2]",
        "[::192.0.2.2]",
        "[2002:c000:0202::]",
        "[2001:0:0:0:0:0:3fff:fdfd]",
        "[64:ff9b::c000:202]",
    ] {
        for pair in [["192.0.2.1", alias], [alias, "192.0.2.1"]] {
            assert_eq!(
                validate_circuit_diversity(&pair),
                Err(SybilError::SubnetCollision([192, 0])),
                "IPv4 subnet policy was bypassed by {alias}"
            );
        }
        assert!(validate_circuit_diversity(&["198.51.100.1", alias]).is_ok());
    }
}

#[test]
fn native_ipv6_prefixes_and_non_ip_inputs_are_enforced() {
    assert_eq!(
        validate_circuit_diversity(&["2001:db8:1::1", "[2001:db8:ffff::2]"]),
        Err(SybilError::Ipv6SubnetCollision([0x20, 0x01, 0x0d, 0xb8]))
    );
    assert!(validate_circuit_diversity(&["2001:db8::1", "2001:db9::2"]).is_ok());
    assert_eq!(
        validate_circuit_diversity(&["relay.example"]),
        Err(SybilError::UnresolvableHost("relay.example".into()))
    );
}
