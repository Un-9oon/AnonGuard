#![cfg(target_os = "linux")]

use anonguard::kernel::netns::NetnsConfig;

#[test]
fn test_nftables_rule_generation() {
    let config = NetnsConfig::new("anon_ns", "127.0.0.1", 9050);
    let rules = config.generate_nftables_rules();

    assert!(rules
        .as_ref()
        .unwrap()
        .contains("table inet anonguard_filter"));
    assert!(rules
        .as_ref()
        .unwrap()
        .contains("ip daddr 127.0.0.1 tcp dport 9050 accept"));
    assert!(rules.as_ref().unwrap().contains("policy drop"));
}

#[test]
fn namespace_policy_does_not_allow_external_or_existing_host_connections() {
    assert!(NetnsConfig::new("safe", "0.0.0.0", 9050)
        .generate_nftables_rules()
        .is_err());
    assert!(NetnsConfig::new("../bad", "127.0.0.1", 9050)
        .generate_nftables_rules()
        .is_err());
    let rules = NetnsConfig::new("safe", "::1", 9050)
        .generate_nftables_rules()
        .unwrap();
    assert!(rules.contains("ip6 daddr ::1"));
    assert!(!rules.contains("related accept"));
    assert!(!rules.contains("oif \"lo\" accept"));
}
