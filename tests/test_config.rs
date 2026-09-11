use anonguard::core::GuardConfig;

#[test]
fn test_guard_config_defaults() {
    let config = GuardConfig::default();
    
    assert!(config.strict_killswitch);
    assert!(config.enforce_remote_dns);
    assert!(config.disable_ipv6);
    assert!(!config.enable_jitter);
    assert_eq!(config.jitter_lambda, 0.05);
    assert_eq!(config.min_chain_length, 1);
    assert_eq!(config.max_chain_length, 3);
    assert_eq!(config.listen_addr, "127.0.0.1:9050");
}
