use anonguard::core::GuardConfig;

#[test]
fn mapped_relay_endpoint_is_distinct_from_local_bind() {
    let bound = "0.0.0.0:9443".parse().unwrap();
    let mapped = "203.0.113.12:443".parse().unwrap();
    let config = GuardConfig {
        relay_mode: true,
        relay_advertise_address: Some(mapped),
        ..GuardConfig::default()
    };
    assert_eq!(config.advertised_relay_address(bound).unwrap(), mapped);
    assert_eq!(
        GuardConfig::default()
            .advertised_relay_address(bound)
            .unwrap(),
        bound
    );
}

#[test]
fn invalid_advertisements_and_private_bridge_publication_are_refused() {
    let bound = "0.0.0.0:9443".parse().unwrap();
    for value in [
        "0.0.0.0:9443",
        "127.0.0.1:9443",
        "224.0.0.1:9443",
        "192.168.1.10:0",
    ] {
        let config = GuardConfig {
            relay_mode: true,
            relay_advertise_address: Some(value.parse().unwrap()),
            ..GuardConfig::default()
        };
        assert!(config.advertised_relay_address(bound).is_err());
    }
    for (relay_mode, unlisted_bridge) in [(false, false), (true, true)] {
        let config = GuardConfig {
            relay_mode,
            unlisted_bridge,
            relay_advertise_address: Some("192.168.1.10:9443".parse().unwrap()),
            ..GuardConfig::default()
        };
        assert!(config.advertised_relay_address(bound).is_err());
    }
}
