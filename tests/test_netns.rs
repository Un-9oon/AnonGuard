use anonguard::kernel::netns::NetnsConfig;

#[test]
fn test_nftables_rule_generation() {
    let config = NetnsConfig::new("anon_ns", "192.168.1.100", 9050);
    let rules = config.generate_nftables_rules();

    assert!(rules.as_ref().unwrap().contains("table inet anonguard_filter"));
    assert!(rules.as_ref().unwrap().contains("ip daddr 192.168.1.100 tcp dport 9050 accept"));
    assert!(rules.as_ref().unwrap().contains("policy drop"));
}
